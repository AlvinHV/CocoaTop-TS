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
@property (assign) int listRequestFD;
@property (assign) int listResponseFD;

@property (strong) NSString *shmName;
@property (assign) int shmFD;
@property (assign) size_t bufSize;
@property (strong) NSString *threadShmName;
@property (assign) int threadShmFD;
@property (assign) size_t threadBufSize;
@property (strong) NSString *portShmName;
@property (assign) int portShmFD;
@property (assign) size_t portBufSize;
@property (strong) NSString *detailShmName;
@property (assign) int detailShmFD;
@property (assign) size_t detailBufSize;

@property (strong) dispatch_source_t stdoutSource;
@property (strong) dispatch_source_t stderrSource;
@property (strong) dispatch_source_t procSource;
@property (strong) dispatch_source_t listResponseSource;

@property (strong) NSMutableData  *stdoutBuffer;
@property (strong) NSMutableData  *listResponseBuffer;

// simple FIFO of pending completions
@property (strong) NSMutableArray<RHCommandCompletion> *pendingCompletions;
@property (strong) NSMutableArray<RHCommandCompletion> *pendingProcessListCompletions;

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
        _listResponseBuffer = [NSMutableData data];
        _pendingProcessListCompletions = [NSMutableArray array];
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
    self.threadBufSize = 4 * 1024 * 1024;
    self.portBufSize = 4 * 1024 * 1024;
    self.detailBufSize = 4 * 1024 * 1024;
    
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

    self.threadShmName = [NSString stringWithFormat:@"/cocoatop_threads_%d", getpid()];
    self.threadShmFD = shm_open(self.threadShmName.UTF8String, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (self.threadShmFD < 0 || ftruncate(self.threadShmFD, self.threadBufSize) < 0) {
        if (outError) *outError = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        return NO;
    }

    self.portShmName = [NSString stringWithFormat:@"/cocoatop_ports_%d", getpid()];
    self.portShmFD = shm_open(self.portShmName.UTF8String, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (self.portShmFD < 0 || ftruncate(self.portShmFD, self.portBufSize) < 0) {
        if (outError) *outError = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        return NO;
    }

    self.detailShmName = [NSString stringWithFormat:@"/cocoatop_details_%d", getpid()];
    self.detailShmFD = shm_open(self.detailShmName.UTF8String, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (self.detailShmFD < 0 || ftruncate(self.detailShmFD, self.detailBufSize) < 0) {
        if (outError) *outError = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        return NO;
    }
    
    int inPipe[2], outPipe[2], errPipe[2], listRequestPipe[2], listResponsePipe[2];
    if (pipe(inPipe) || pipe(outPipe) || pipe(errPipe) ||
        pipe(listRequestPipe) || pipe(listResponsePipe)) {
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

    self.threadSnapshot = mmap(NULL, self.threadBufSize,
                               PROT_READ | PROT_WRITE,
                               MAP_SHARED, self.threadShmFD, 0);
    if (self.threadSnapshot == MAP_FAILED) {
        if (outError) *outError = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        return NO;
    }

    self.portSnapshot = mmap(NULL, self.portBufSize,
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED, self.portShmFD, 0);
    if (self.portSnapshot == MAP_FAILED) {
        if (outError) *outError = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        return NO;
    }

    self.detailSnapshot = mmap(NULL, self.detailBufSize,
                               PROT_READ | PROT_WRITE,
                               MAP_SHARED, self.detailShmFD, 0);
    if (self.detailSnapshot == MAP_FAILED) {
        if (outError) *outError = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
        return NO;
    }
    
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, inPipe[0], STDIN_FILENO);
    posix_spawn_file_actions_addclose(&actions, inPipe[0]);
    posix_spawn_file_actions_addclose(&actions, inPipe[1]);
    posix_spawn_file_actions_adddup2(&actions, outPipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, outPipe[1]);
    posix_spawn_file_actions_addclose(&actions, outPipe[0]);
    posix_spawn_file_actions_adddup2(&actions, errPipe[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, errPipe[1]);
    posix_spawn_file_actions_addclose(&actions, errPipe[0]);
    posix_spawn_file_actions_addclose(&actions, listRequestPipe[1]);
    posix_spawn_file_actions_addclose(&actions, listResponsePipe[0]);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
    posix_spawnattr_set_persona_uid_np(&attr, 0);
    posix_spawnattr_set_persona_gid_np(&attr, 0);
    
    // Pass shared-memory sizes and the dedicated process-list pipe descriptors.
    char bufArg[32], threadBufArg[32], portBufArg[32], detailBufArg[32], listRequestArg[16], listResponseArg[16];
    snprintf(bufArg, sizeof(bufArg), "%zu", self.bufSize);
    snprintf(threadBufArg, sizeof(threadBufArg), "%zu", self.threadBufSize);
    snprintf(portBufArg, sizeof(portBufArg), "%zu", self.portBufSize);
    snprintf(detailBufArg, sizeof(detailBufArg), "%zu", self.detailBufSize);
    snprintf(listRequestArg, sizeof(listRequestArg), "%d", listRequestPipe[0]);
    snprintf(listResponseArg, sizeof(listResponseArg), "%d", listResponsePipe[1]);
    char *argv[] = { (char*)helperPath.UTF8String, bufArg, threadBufArg, portBufArg, detailBufArg,
                     listRequestArg, listResponseArg, NULL };
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

    close(inPipe[0]);
    close(outPipe[1]);
    close(errPipe[1]);
    close(listRequestPipe[0]);
    close(listResponsePipe[1]);
    
    // 6. Store fds & pid, close unused ends
    self.helperPID = pid;
    self.stdinFD   = inPipe[1];
    self.stdoutFD  = outPipe[0];
    self.stderrFD  = errPipe[0];
    self.listRequestFD = listRequestPipe[1];
    self.listResponseFD = listResponsePipe[0];
    self.isRunning = YES;
    
    // 7. Kick off I/O and proc watcher
    [self setupStdoutSource];
    [self setupStderrSource];
    [self setupListResponseSource];
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
        if (r > 0) {
            [self.stdoutBuffer appendBytes:buf length:r];
            [self checkForLineInBuffer:self.stdoutBuffer completions:self.pendingCompletions];
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
        if (r > 0)
            NSLog(@"helper stderr: %.*s", (int)r, buf);
    });
    dispatch_resume(self.stderrSource);
}

- (void)setupListResponseSource {
    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    self.listResponseSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,
                                                      self.listResponseFD, 0, q);
    dispatch_source_set_event_handler(self.listResponseSource, ^{
        size_t available = dispatch_source_get_data(self.listResponseSource);
        if (available == 0) return;
        uint8_t buf[50];
        ssize_t r = read(self.listResponseFD, buf, MIN(sizeof(buf), available));
        if (r > 0) {
            [self.listResponseBuffer appendBytes:buf length:r];
            [self checkForLineInBuffer:self.listResponseBuffer
                           completions:self.pendingProcessListCompletions];
        }
    });
    dispatch_resume(self.listResponseSource);
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
        dispatch_source_cancel(self.listResponseSource);
        NSArray<RHCommandCompletion> *commandCompletions;
        @synchronized(self.pendingCompletions) {
            commandCompletions = [self.pendingCompletions copy];
            [self.pendingCompletions removeAllObjects];
        }
        for (RHCommandCompletion cb in commandCompletions) {
            cb(nil, nil, -1);
        }
        NSArray<RHCommandCompletion> *processListCompletions;
        @synchronized(self.pendingProcessListCompletions) {
            processListCompletions = [self.pendingProcessListCompletions copy];
            [self.pendingProcessListCompletions removeAllObjects];
        }
        for (RHCommandCompletion cb in processListCompletions) {
            cb(nil, nil, -1);
        }
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

/// Called whenever we see “\n” in a response buffer.
- (void)checkForLineInBuffer:(NSMutableData*)buf
                 completions:(NSMutableArray<RHCommandCompletion>*)completions {
    for (;;) {
        const char *bytes = buf.bytes;
        NSUInteger len = buf.length;
        NSUInteger newline = NSNotFound;
        for (NSUInteger i = 0; i < len; i++) {
            if (bytes[i] == '\n') {
                newline = i;
                break;
            }
        }
        if (newline == NSNotFound)
            break;

        NSData *lineData = [buf subdataWithRange:NSMakeRange(0, newline + 1)];
        NSString *line = [[NSString alloc] initWithData:lineData
                                               encoding:NSUTF8StringEncoding];
        line = [line stringByTrimmingCharactersInSet:[NSCharacterSet newlineCharacterSet]];
        [buf replaceBytesInRange:NSMakeRange(0, newline + 1) withBytes:NULL length:0];

        RHCommandCompletion cb = nil;
        @synchronized(completions) {
            if (completions.count) {
                cb = completions.firstObject;
                [completions removeObjectAtIndex:0];
            }
        }
        if (cb)
            cb(line, nil, 0);
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
    
    BOOL writeFailed = NO;
    @synchronized(self.pendingCompletions) {
        [self.pendingCompletions addObject:completion];
        const char *utf8 = cmd.UTF8String;
        size_t length = strlen(utf8);
        writeFailed = write(self.stdinFD, utf8, length) != (ssize_t)length;
        if (writeFailed)
            [self.pendingCompletions removeLastObject];
    }
    if (writeFailed)
        completion(nil, nil, -1);
}

- (void)requestProcessListWithCompletion:(RHCommandCompletion)completion
{
    if (!self.isRunning) {
        completion(nil, nil, -1);
        return;
    }
    uint8_t request = 1;
    BOOL writeFailed = NO;
    @synchronized(self.pendingProcessListCompletions) {
        [self.pendingProcessListCompletions addObject:completion];
        writeFailed = write(self.listRequestFD, &request, sizeof(request)) != sizeof(request);
        if (writeFailed)
            [self.pendingProcessListCompletions removeLastObject];
    }
    if (writeFailed)
        completion(nil, nil, -1);
}

- (void)requestThreadsForPID:(pid_t)pid completion:(RHCommandCompletion)completion
{
    [self sendCommand:[NSString stringWithFormat:@"getthreads %d", pid] completion:completion];
}

- (void)requestPortsForPID:(pid_t)pid completion:(RHCommandCompletion)completion
{
    [self sendCommand:[NSString stringWithFormat:@"getports %d", pid] completion:completion];
}

- (void)requestPortReferencesForPID:(pid_t)pid completion:(RHCommandCompletion)completion
{
    [self sendCommand:[NSString stringWithFormat:@"getportrefs %d", pid] completion:completion];
}

- (void)requestProcessInfoForPID:(pid_t)pid completion:(RHCommandCompletion)completion
{
    [self sendCommand:[NSString stringWithFormat:@"getproc %d", pid] completion:completion];
}

- (void)requestModulesForPID:(pid_t)pid completion:(RHCommandCompletion)completion
{
    [self sendCommand:[NSString stringWithFormat:@"getmodules %d", pid] completion:completion];
}

- (void)sendSignal:(int)signal toProcess:(pid_t)pid completion:(RHCommandCompletion)completion
{
    [self sendCommand:[NSString stringWithFormat:@"kill %d %d", pid, signal] completion:completion];
}

- (void)stopHelper {
    if (! self.isRunning) return;
    self.isRunning = NO;
    kill(self.helperPID, SIGTERM);
    // cleanup
    dispatch_source_cancel(self.stdoutSource);
    dispatch_source_cancel(self.stderrSource);
    dispatch_source_cancel(self.listResponseSource);
    dispatch_source_cancel(self.procSource);
    close(self.stdinFD);
    close(self.stdoutFD);
    close(self.stderrFD);
    close(self.listRequestFD);
    close(self.listResponseFD);
    munmap(self.snapshot, self.bufSize);
    munmap(self.threadSnapshot, self.threadBufSize);
    munmap(self.portSnapshot, self.portBufSize);
    munmap(self.detailSnapshot, self.detailBufSize);
    close(self.shmFD);
    close(self.threadShmFD);
    close(self.portShmFD);
    close(self.detailShmFD);
    shm_unlink(self.shmName.UTF8String);
    shm_unlink(self.threadShmName.UTF8String);
    shm_unlink(self.portShmName.UTF8String);
    shm_unlink(self.detailShmName.UTF8String);
    [[UIApplication sharedApplication] performSelector:@selector(suspend)];
}

@end
