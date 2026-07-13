#import "RootHelperManager.h"
#import <spawn.h>
#import <sys/stat.h>
#import <fcntl.h>
#import <unistd.h>
#import <sys/sysctl.h>
#import <UIKit/UIKit.h>
#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);

@interface RootHelperManager ()

@property (atomic) pid_t helperPID;
@property (atomic) BOOL isRunning;

@property (assign) int stdinFD;
@property (assign) int stdoutFD;
@property (assign) int stderrFD;

@property (strong) NSString *shmName;
@property (assign) int shmFD;
@property (assign) size_t bufSize;

@property (strong) dispatch_source_t stdoutSource;
@property (strong) dispatch_source_t stderrSource;
@property (strong) dispatch_source_t procSource;

@property (strong) NSMutableData  *stdoutBuffer;
@property (strong) NSMutableData  *stderrBuffer;

// simple FIFO of pending completions
@property (strong) NSMutableArray<RHCommandCompletion> *pendingCompletions;

@end

@implementation RootHelperManager

+ (instancetype)sharedManager {
    static RootHelperManager *M;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        M = [self new];
    });
    return M;
}

- (instancetype)init {
    if ((self = [super init])) {
        _pendingCompletions = [NSMutableArray array];
        _stdoutBuffer = [NSMutableData data];
        _stderrBuffer = [NSMutableData data];
    }
    return self;
}

// Launch helper with a shared-memory process snapshot buffer.
- (BOOL)startHelperWithPath:(NSString*)helperPath
                      error:(NSError**)outError
{
    if (self.isRunning) return YES;
    int maxproc = 0;
    int mibMax[2] = { CTL_KERN, KERN_MAXPROC };
    size_t lenMax = sizeof(maxproc);
    if (sysctl(mibMax, 2, &maxproc, &lenMax, NULL, 0) < 0) {
        if (outError) *outError = [NSError errorWithDomain:NSPOSIXErrorDomain
                                                         code:errno
                                                     userInfo:nil];
        return NO;
    }
    self.bufSize = sizeof(*self.snapshot) + maxproc * sizeof(self.snapshot->records[0]);
    
    // 2. Create shared memory region
    self.shmName = [NSString stringWithFormat:@"/cocoatop_%d", getpid()];
    self.shmFD = shm_open(self.shmName.UTF8String, O_CREAT | O_RDWR , S_IRUSR | S_IWUSR);
    if (self.shmFD < 0) {
        if (outError) *outError = [NSError errorWithDomain:NSPOSIXErrorDomain
                                                      code:errno
                                                  userInfo:nil];
        return NO;
    }
    if (ftruncate(self.shmFD, self.bufSize) < 0) {
        if (outError) *outError = [NSError errorWithDomain:NSPOSIXErrorDomain
                                                      code:errno
                                                  userInfo:nil];
        return NO;
    }
    
    int inPipe[2], outPipe[2], errPipe[2];
    if (pipe(inPipe) || pipe(outPipe) || pipe(errPipe)) {
        if (outError) *outError = [NSError errorWithDomain:NSPOSIXErrorDomain
                                                      code:errno
                                                  userInfo:nil];
        return NO;
    }
    
    // 3. mmap local mapping for reads (optional)
    self.snapshot = mmap(NULL, self.bufSize,
                         PROT_READ | PROT_WRITE,
                         MAP_SHARED, self.shmFD, 0);
    if (self.snapshot == MAP_FAILED) {
        if (outError) *outError = [NSError errorWithDomain:NSPOSIXErrorDomain
                                                      code:errno
                                                  userInfo:nil];
        return NO;
    }
    
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, inPipe[0], STDIN_FILENO);
    posix_spawn_file_actions_addclose(&actions, inPipe[1]);
    posix_spawn_file_actions_adddup2(&actions, outPipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, outPipe[0]);
    posix_spawn_file_actions_adddup2(&actions, errPipe[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, errPipe[0]);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
    posix_spawnattr_set_persona_uid_np(&attr, 0);
    posix_spawnattr_set_persona_gid_np(&attr, 0);
    
    // 5. Pass shmFD to helper
    char bufArg[32];
    snprintf(bufArg, sizeof(bufArg), "%zu", self.bufSize);
    char *argv[] = { (char*)[helperPath UTF8String], bufArg ,NULL };
    pid_t pid;
    int err = posix_spawn(&pid,
                          [helperPath UTF8String],
                          &actions,
                          &attr,
                          argv,
                          NULL);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    
    if (err != 0) {
        if (outError) *outError = [NSError errorWithDomain:NSPOSIXErrorDomain
                                                      code:err
                                                  userInfo:nil];
        return NO;
    }
    
    // 6. Store fds & pid, close unused ends
    self.helperPID = pid;
    self.stdinFD   = inPipe[1];
    self.stdoutFD  = outPipe[0];
    self.stderrFD  = errPipe[0];
    self.isRunning = YES;
    
    // 7. Kick off I/O and proc watcher
    [self setupStdoutSource];
    [self setupStderrSource];
    [self setupProcWatcher];
    
    return YES;
}


- (void)setupStdoutSource {
    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    self.stdoutSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,
                                               self.stdoutFD, 0, q);
    dispatch_source_set_event_handler(self.stdoutSource, ^{
        size_t available = dispatch_source_get_data(self.stdoutSource);
        if (available == 0) return; // EOF?
        uint8_t buf[50];
        ssize_t r = read(self.stdoutFD, buf, MIN(sizeof(buf), available));
        NSLog(@"stdout: %s", buf);
        if (r > 0) {
            [self.stdoutBuffer appendBytes:buf length:r];
            [self checkForLineInBuffer:self.stdoutBuffer isStdout:YES];
        }
    });
    dispatch_resume(self.stdoutSource);
}

- (void)setupStderrSource {
    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    self.stderrSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,
                                               self.stderrFD, 0, q);
    dispatch_source_set_event_handler(self.stderrSource, ^{
        size_t available = dispatch_source_get_data(self.stderrSource);
        if (available == 0) return;
        uint8_t buf[100];
        ssize_t r = read(self.stderrFD, buf, MIN(sizeof(buf), available));
        NSLog(@"stderr: %s", buf);
        if (r > 0) {
            [self.stderrBuffer appendBytes:buf length:r];
            [self checkForLineInBuffer:self.stderrBuffer isStdout:NO];
        }
    });
    dispatch_resume(self.stderrSource);
}

- (void)setupProcWatcher {
    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0);
    self.procSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC,
                                             self.helperPID,
                                             DISPATCH_PROC_EXIT, q);
    dispatch_source_set_event_handler(self.procSource, ^{
        // helper died
        self.isRunning = NO;
        dispatch_source_cancel(self.stdoutSource);
        dispatch_source_cancel(self.stderrSource);
        // invoke any pending completions with an error
        for (RHCommandCompletion cb in self.pendingCompletions) {
            cb(nil, nil, -1);
        }
        [self.pendingCompletions removeAllObjects];
        // terminate app
        dispatch_async(dispatch_get_main_queue(), ^{
            NSLog(@"Helper has been terminated!!! Im leaving byee");
            [[UIApplication sharedApplication] performSelector:@selector(suspend)];
            sleep(1);
            exit(1);
        });
    });
    dispatch_resume(self.procSource);
}

/// Called whenever we see “\n” in the buffer
- (void)checkForLineInBuffer:(NSMutableData*)buf isStdout:(BOOL)isStdout {
    const void *bytes = buf.bytes;
    NSUInteger len = buf.length;
    for (NSUInteger i = 0; i < len; i++) {
        if (((char*)bytes)[i] == '\n') {
            // extract line up to i
            NSData *lineData = [buf subdataWithRange:NSMakeRange(0, i+1)];
            NSString *line = [[NSString alloc] initWithData:lineData
                                                   encoding:NSUTF8StringEncoding];
            // trim newline
            line = [line stringByTrimmingCharactersInSet:
                    [NSCharacterSet newlineCharacterSet]];
            // remove that chunk from buf
            [buf replaceBytesInRange:NSMakeRange(0, i+1)
                           withBytes:NULL length:0];
            
            // stderr is diagnostic output; command responses arrive on stdout.
            if (!isStdout)
                break;

            // fire the next pending completion
            RHCommandCompletion cb = nil;
            @synchronized(self.pendingCompletions) {
                if (self.pendingCompletions.count) {
                    cb = self.pendingCompletions.firstObject;
                    [self.pendingCompletions removeObjectAtIndex:0];
                }
            }
            if (cb)
                cb(line, nil, 0);
            break;
        }
    }
}

- (void)sendCommand:(NSString*)command
         completion:(RHCommandCompletion)completion
{
    if (! self.isRunning) {
        completion(nil, nil, -1);
        return;
    }
    // ensure newline
    NSString *cmd = command;
    if (![cmd hasSuffix:@"\n"]) cmd = [cmd stringByAppendingString:@"\n"];
    
    // enqueue callback
    @synchronized(self.pendingCompletions) {
        [self.pendingCompletions addObject:completion];
    }
    
    // write
    const char *utf8 = cmd.UTF8String;
    write(self.stdinFD, utf8, strlen(utf8));
}

- (void)stopHelper {
    if (! self.isRunning) return;
    self.isRunning = NO;
    kill(self.helperPID, SIGTERM);
    // cleanup
    dispatch_source_cancel(self.stdoutSource);
    dispatch_source_cancel(self.stderrSource);
    dispatch_source_cancel(self.procSource);
    close(self.stdinFD);
    close(self.stdoutFD);
    close(self.stderrFD);
    munmap(self.snapshot, self.bufSize);
    close(self.shmFD);
    shm_unlink(self.shmName.UTF8String);
    [[UIApplication sharedApplication] performSelector:@selector(suspend)];
}

@end
