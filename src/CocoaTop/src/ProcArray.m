#import <mach/mach_init.h>
#import <mach/mach_host.h>
#import <mach/host_info.h>
#import <pwd.h>
#import "ProcArray.h"
#import "NetArray.h"
#import "RootHelperManager.h"

@implementation PSProcInfo
int sort_procs_by_pid(const void *p1, const void *p2)
{
	pid_t kp1 = ((struct CocoaTopProcessRecord *)p1)->kinfo.kp_proc.p_pid;
	pid_t kp2 = ((struct CocoaTopProcessRecord *)p2)->kinfo.kp_proc.p_pid;
	return kp1 == kp2 ? 0 : kp1 > kp2 ? 1 : -1;
}

- (instancetype)initProcInfoSort:(BOOL)sort
{
	self = [super init];
	self->records = 0;
	self->count = 0;
	self->sampleTime = 0;
    
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    [[RootHelperManager sharedManager] sendCommand: @"getprocs" completion:^(NSString * _Nullable stdoutString,
                                                                             NSString * _Nullable stderrString,
                                                                             NSInteger exitCode) {
        struct CocoaTopProcessSnapshot *snapshot = [RootHelperManager sharedManager].snapshot;
        NSInteger value = [stdoutString integerValue];
        if (exitCode == 0 && value >= 0 &&
            snapshot->version == COCOATOP_PROCESS_SNAPSHOT_VERSION &&
            snapshot->count == (uint32_t)value) {
            self->count = snapshot->count;
            self->records = snapshot->records;
            self->sampleTime = snapshot->sample_time;
        }
        dispatch_semaphore_signal(sema);
    }];
    
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

	if (sort)
		qsort(self->records, self->count, sizeof(*self->records), sort_procs_by_pid);
	return self;
}

+ (instancetype)psProcInfoSort:(BOOL)sort
{
	return [[PSProcInfo alloc] initProcInfoSort:sort];
}
@end

@implementation PSProcArray

- (instancetype)initProcArrayWithIconSize:(CGFloat)size
{
	self = [super init];
	if (!self) return nil;
	self.iconSize = size;
	self.procs = [NSMutableArray arrayWithCapacity:300];
	self.nstats = [PSNetArray psNetArray];
	NSProcessInfo *procinfo = [NSProcessInfo processInfo];
	self.memTotal = procinfo.physicalMemory;
	self.coresCount = procinfo.processorCount;
	self.filterCount = 0;
	return self;
}

+ (instancetype)psProcArrayWithIconSize:(CGFloat)size
{
	return [[PSProcArray alloc] initProcArrayWithIconSize:size];
}

- (void)refreshMemStats
{
	mach_port_t host_port = mach_host_self();
	mach_msg_type_number_t host_size = HOST_VM_INFO64_COUNT;
	vm_statistics64_data_t vm_stat;
	vm_size_t pagesize;

	host_page_size(host_port, &pagesize);
	if (host_statistics64(host_port, HOST_VM_INFO64, (host_info_t)&vm_stat, &host_size) == KERN_SUCCESS) {
//		self.memUsed = (vm_stat.active_count + vm_stat.inactive_count + vm_stat.wire_count) * pagesize;
//#if __IPHONE_OS_VERSION_MAX_ALLOWED >= __IPHONE_7_0
//		self.memUsed += vm_stat.compressor_page_count * pagesize;
//#endif
		self.memFree = vm_stat.free_count * pagesize;
		self.memUsed = self.memTotal - self.memFree;
	}
/*
	host_cpu_load_info_data_t cpu_stat;
	host_size = HOST_CPU_LOAD_INFO_COUNT;
	if (host_statistics(host_port, HOST_CPU_LOAD_INFO, (host_info_t)&cpu_stat, &host_size) == KERN_SUCCESS) {
		cpu_stat.cpu_ticks[CPU_STATE_MAX]
	}
*/
}

- (int)refresh
{
	static uid_t mobileuid = 0;
	if (!mobileuid) {
		struct passwd *mobile = getpwnam("mobile");
        if (mobile) {
            mobileuid = mobile->pw_uid;
        }
	}
	// Reset totals
	self.totalCpu = self.threadCount = self.portCount = self.machCalls = self.unixCalls = self.switchCount = self.runningCount = self.mobileCount = self.guiCount = 0;
	// Remove terminated processes
	[self.procs filterUsingPredicate:[NSPredicate predicateWithBlock: ^BOOL(PSProc *obj, NSDictionary *bind) {
		return obj.display != ProcDisplayTerminated;
	}]];
	[self setAllDisplayed:ProcDisplayTerminated];
	// Get process list and update the procs array
	PSProcInfo *procs = [PSProcInfo psProcInfoSort:NO];

	for (int i = 0; i < procs->count; i++) {
		struct CocoaTopProcessRecord *record = &procs->records[i];
		PSProc *proc = [self procForPid:record->kinfo.kp_proc.p_pid];
		if (!proc) {
			proc = [PSProc psProcWithKinfo:&record->kinfo iconSize:self.iconSize];
			[self.procs addObject:proc];
		} else {
			[proc updateWithKinfo:&record->kinfo];
			proc.display = ProcDisplayUser;
		}
		if (record->taskinfo_valid)
			[proc updateWithTaskInfo:&record->taskinfo sampleTime:procs->sampleTime];
		// Compute totals
		if (proc.pid) self.totalCpu += proc.pcpu;	// Kernel gets all idle CPU time
		if (proc.uid == mobileuid) self.mobileCount++;
		if (proc.state == ProcStateRunning) self.runningCount++;
		if (proc.role != TASK_UNSPECIFIED) self.guiCount++;
		self.threadCount += proc.threads;
		self.portCount += proc.ports;
		self.machCalls += proc->events.syscalls_mach - proc->events_prev.syscalls_mach;
		self.unixCalls += proc->events.syscalls_unix - proc->events_prev.syscalls_unix;
		self.switchCount += proc->events.csw - proc->events_prev.csw;
	}
	[self refreshMemStats];
	[self.nstats refresh:self];
	self.procsFiltered = self.procs;
	return 0;
}

- (void)sortUsingComparator:(NSComparator)comp desc:(BOOL)desc
{
	if (desc) {
		[self.procs sortUsingComparator:^NSComparisonResult(id a, id b) { return comp(b, a); }];
	} else
		[self.procs sortUsingComparator:comp];
}

- (void)setAllDisplayed:(display_t)display
{
	for (PSProc *proc in self.procs)
		// Setting all items to "normal" is used only to hide "started"
		if (display != ProcDisplayNormal || proc.display == ProcDisplayStarted)
			proc.display = display;
}

- (NSUInteger)indexOfDisplayed:(display_t)display
{
	return [self.procsFiltered indexOfObjectPassingTest:^BOOL(PSProc *proc, NSUInteger idx, BOOL *stop) {
		return proc.display == display;
	}];
//	return [self.procs enumerateObjectsWithOptions:NSEnumerationReverse usingBlock:^void(PSProc *proc, NSUInteger idx, BOOL *stop) {
//		if (proc.display == display) *stop = YES;
//	}];
//	for (PSProc *proc in [self.procs reverseObjectEnumerator]) {
//		if (proc.display == display) return idx;
//	}
}

- (NSUInteger)totalCount
{
	return self.procs.count;
}

- (NSUInteger)count
{
	return self.procsFiltered.count;
}

- (PSProc *)objectAtIndexedSubscript:(NSUInteger)idx
{
	return (PSProc *)self.procsFiltered[idx];
}

- (NSUInteger)indexForPid:(pid_t)pid
{
	NSUInteger idx = [self.procsFiltered indexOfObjectPassingTest:^BOOL(id proc, NSUInteger idx, BOOL *stop) {
		return ((PSProc *)proc).pid == pid;
	}];
	return idx;
}

- (PSProc *)procForPid:(pid_t)pid
{
	NSUInteger idx = [self.procs indexOfObjectPassingTest:^BOOL(id proc, NSUInteger idx, BOOL *stop) {
		return ((PSProc *)proc).pid == pid;
	}];
	return idx == NSNotFound ? nil : (PSProc *)self.procs[idx];
}

- (void)filter:(NSString *)text column:(PSColumn *)col
{
	if (text && text.length) {
		self.procsFiltered = [self.procs mutableCopy];
		if (col.getFloatData != nil) {
			double minValue = [text doubleValue];
			switch([text characterAtIndex:text.length-1]) {
			case 'k': case 'K': minValue *= 1024; break;
			case 'm': case 'M': minValue *= 1024*1024; break;
			case 'g': case 'G': minValue *= 1024*1024*1024; break;
			}
			[self.procsFiltered filterUsingPredicate:[NSPredicate predicateWithBlock: ^BOOL(PSProc *proc, NSDictionary *bind) {
				return col.getFloatData(proc) >= minValue;
			}]];
		} else
			[self.procsFiltered filterUsingPredicate:[NSPredicate predicateWithBlock: ^BOOL(PSProc *proc, NSDictionary *bind) {
				return [col.getData(proc) rangeOfString:text options:NSCaseInsensitiveSearch].location != NSNotFound;
			}]];
	} else
		self.procsFiltered = self.procs;
}

@end
