#import "xpc/xpc.h"
#import "Sock.h"
#import "ProcArray.h"
#import <mach-o/dyld_images.h>
#import <mach/thread_info.h>
#import <arpa/inet.h>
#import <sys/syscall.h>
#import <netdb.h>
#import "sys/proc_info.h"
#import "sys/libproc.h"
#import "sys/dyld64.h"
#import "kern/debug.h"
#import "RootHelperManager.h"
#include <dlfcn.h>

#ifndef SYS_stack_snapshot 
#define SYS_stack_snapshot 365
#endif

static UIColor *_redColor(void) {
    if (@available(iOS 7, *)) {
        return [UIColor systemRedColor];
    } else {
        return [UIColor redColor];
    }
}

static UIColor *_orangeColor(void) {
    if (@available(iOS 7, *)) {
        return [UIColor systemOrangeColor];
    } else {
        return [UIColor orangeColor];
    }
}

static UIColor *_labelColor(void) {
    if (@available(iOS 13, *)) {
        return [UIColor labelColor];
    } else {
        return [UIColor blackColor];
    }
}

static UIColor *_blueColor(void) {
    if (@available(iOS 7, *)) {
        return [UIColor systemBlueColor];
    } else {
        return [UIColor blueColor];
    }
}

static UIColor *_grayColor(void) {
    if (@available(iOS 13, *)) {
        return [UIColor systemGrayColor];
    } else {
        return [UIColor grayColor];
    }
}

static UIColor *_greenColor(void) {
    if (@available(iOS 13, *)) {
        return [UIColor colorWithDynamicProvider:^(UITraitCollection *collection) {
            if (collection.userInterfaceStyle == UIUserInterfaceStyleDark) {
                return [UIColor colorWithRed:0.12 green:0.8 blue:0.12 alpha:1];
            } else {
                return [UIColor colorWithRed:0 green:0.5 blue:0 alpha:1];
            }
        }];
    } else {
        return [UIColor colorWithRed:.0 green:.5 blue:.0 alpha:1.0];
    }
}

kern_return_t
_task_for_pid(pid_t pid, task_port_t *target) {
    kern_return_t ret = task_for_pid(mach_task_self(), pid, target);
    if (ret != KERN_SUCCESS && pid == 0) {
        ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, target);
    }
    return ret;
}

NSString *psGetProcessName(struct extern_proc *ep)
{
	static pid_t pid = -1;
	static NSString *procname = 0;
	if (ep->p_pid == pid)
		return procname;
	char path[MAXPATHLEN];
	if (proc_pidpath(ep->p_pid, path, sizeof(path))) {
		char *last = strrchr(path, '/');
		procname = [NSString stringWithUTF8String:(last ? last + 1 : path)];
	} else {
		ep->p_comm[MAXCOMLEN] = 0;
		procname = [NSString stringWithUTF8String:ep->p_comm];
	}
	pid = ep->p_pid;
	return procname;
}

@implementation PSSock
+ (int)refreshArray:(PSSockArray *)socks { return 0; }
- (NSString *)description { return _name; }
@end

/////////////////////////////////////////////////////////////////////////////////////////////////////////
//  SUMMARY PAGE

@implementation PSSockSummary

- (instancetype)initWithProc:(PSProc *)proc column:(PSColumn *)col
{
	if (self = [super init]) {
		self.display = ProcDisplayNormal;
		self.proc = proc;
		self.col = col;
		self.name = col.fullname;
	}
	return self;
}

+ (instancetype)psSockWithProc:(PSProc *)proc column:(PSColumn *)col
{
	return [[PSSockSummary alloc] initWithProc:proc column:col];
}

+ (int)refreshArray:(PSSockArray *)socks
{
	[socks.socks removeAllObjects];
	for (PSColumn *col in [PSColumn psGetAllColumns]) if (!(col.style & ColumnStyleNoSummary)) {
		id sock = [PSSockSummary psSockWithProc:socks.proc column:col];
		if (sock) [socks.socks addObject:sock];
	}
	return 0;
}

@end

/////////////////////////////////////////////////////////////////////////////////////////////////////////
//  THREADS PAGE

int stack_snapshot(int pid, char *tracebuf, int bufsize, int options)
{
	return syscall(SYS_stack_snapshot, pid, tracebuf, bufsize, options);
}

@implementation PSSockThreads

- (instancetype)initWithId:(uint64_t)tid
{
	if (self = [super init]) {
		self.display = ProcDisplayStarted;
		self.name = [NSString stringWithFormat:@"TID: %llX", tid];
		self.tid = tid;
	}
	return self;
}

+ (instancetype)psSockWithId:(uint64_t)tid
{
	return [[PSSockThreads alloc] initWithId:tid];
}

/*
struct frame32 {
	uint32_t	retaddr;
	uint32_t	fp;
};

struct frame64 {
	uint64_t	retaddr;
	uint64_t	fp;
};
*/

void dump(unsigned char *b, int s)
{
	for (int i = 0; i < s/16; i++) {
		NSLog(@"%02X %02X %02X %02X - %02X %02X %02X %02X - %02X %02X %02X %02X - %02X %02X %02X %02X", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
		b += 16;
	}
}

+ (int)refreshArray:(PSSockArray *)socks
{
/*
	unsigned char buf[0x10000], *cur = buf;
	int size = stack_snapshot(socks.proc.pid, (char *)buf, sizeof(buf), 100);
	if (size > 0)
	while (cur < buf + size) {
		struct task_snapshot *ts = (struct task_snapshot *)cur;
		struct thread_snapshot *ths = (struct thread_snapshot *)cur;
		switch (ts->snapshot_magic) {
		case STACKSHOT_TASK_SNAPSHOT_MAGIC:
			NSLog(@"PID: %d (%s)", ts->pid, ts->p_comm);
			NSLog(@"Flags: %x, nloadinfos: %d", ts->ss_flags, ts->nloadinfos);
			dump(cur, sizeof(struct task_snapshot));
			cur += sizeof(struct task_snapshot);
			break;
		case STACKSHOT_THREAD_SNAPSHOT_MAGIC:
			NSLog(@"Thread ID: %llx, flags: %x, state: %x, Frames: %d kernel %d user", ths->thread_id, ths->ss_flags, ths->state, ths->nkern_frames, ths->nuser_frames);
			dump(cur, sizeof(struct thread_snapshot) + 246);
			//if (ths->wait_event) printf ("\tWaiting on: 0x%x ", ths->wait_event);
			//if (ths->continuation) printf ("\tContinuation: %p\n", ths->continuation);
		//if ( g_OsVer == 8 ) *voffs = 65;
		//if ( g_OsVer == 9 ) *voffs = 69;
		//if ( g_OsVer == 10 ) *voffs = 311;
			cur += sizeof(struct thread_snapshot) + 246;	//=311
			cur += ths->nuser_frames * (socks.proc.flags & P_LP64 ? sizeof(struct frame64) : sizeof(struct frame32));
			cur += ths->nkern_frames * sizeof(struct frame64);
			break;
		case STACKSHOT_MEM_AND_IO_SNAPSHOT_MAGIC:
			NSLog(@"Mem: %x", ts->snapshot_magic);
			dump(cur, sizeof(struct mem_and_io_snapshot) + 16);
			cur += sizeof(struct mem_and_io_snapshot) + 16;
			break;
		default:
			NSLog(@"%x Unk: %x", cur-buf, ts->snapshot_magic);
			cur++;
		}
	}
*/
	__block NSInteger result = -EIO;
	dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
	[[RootHelperManager sharedManager] requestThreadsForPID:socks.proc.pid
	                                           completion:^(NSString *stdoutString, NSString *stderrString, NSInteger exitCode) {
		if (exitCode == 0)
			result = stdoutString.integerValue;
		dispatch_semaphore_signal(semaphore);
	}];
	dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

	struct CocoaTopThreadSnapshot *snapshot = [RootHelperManager sharedManager].threadSnapshot;
	if (result < 0)
		return (int)-result;
	if (snapshot->error != 0 || snapshot->pid != socks.proc.pid ||
	    snapshot->count != (uint32_t)result)
		return EIO;

	for (uint32_t j = 0; j < snapshot->count; j++) {
		const struct CocoaTopThreadRecord *record = &snapshot->records[j];
		if (record->thread_id) {
			PSSockThreads *sock = (PSSockThreads *)[socks objectPassingTest:^BOOL(PSSockThreads *obj, NSUInteger idx, BOOL *stop) {
				return obj.tid == record->thread_id;
			}];
			if (!sock) {
				sock = [PSSockThreads psSockWithId:record->thread_id];
				if (sock) [socks.socks addObject:sock];
			} else if (sock.display != ProcDisplayStarted)
				sock.display = ProcDisplayUser;

			const struct proc_threadinfo *info = &record->info;
			memset(&sock->tbi, 0, sizeof(sock->tbi));
			sock->tbi.user_time.seconds = (integer_t)(info->pth_user_time / NSEC_PER_SEC);
			sock->tbi.user_time.microseconds = (integer_t)((info->pth_user_time % NSEC_PER_SEC) / NSEC_PER_USEC);
			sock->tbi.system_time.seconds = (integer_t)(info->pth_system_time / NSEC_PER_SEC);
			sock->tbi.system_time.microseconds = (integer_t)((info->pth_system_time % NSEC_PER_SEC) / NSEC_PER_USEC);
			sock->tbi.cpu_usage = info->pth_cpu_usage;
			sock->tbi.policy = info->pth_policy;
			sock->tbi.run_state = info->pth_run_state;
			sock->tbi.flags = info->pth_flags;
			sock->tbi.sleep_time = info->pth_sleep_time;
			// proc_threadinfo times are nanoseconds; ptime is hundredths of a second.
			sock.ptime = (info->pth_user_time + info->pth_system_time + 5000000) / 10000000;
			sock.prio = info->pth_curpri;
			switch (sock->tbi.run_state) {
            case TH_STATE_RUNNING:			sock.color = _redColor();break;//sock.color = [UIColor redColor]; break;
            case TH_STATE_UNINTERRUPTIBLE:	sock.color = _orangeColor(); break;//[UIColor orangeColor]; break;
            case TH_STATE_WAITING:			sock.color = sock->tbi.suspend_count ? _blueColor() : _labelColor();break;//[UIColor blueColor] : [UIColor blackColor]; break;
			case TH_STATE_STOPPED:
			case TH_STATE_HALTED:			sock.color = [UIColor brownColor]; break;
            default:						sock.color = _grayColor();//[UIColor grayColor];
			}
			size_t nameLength = strnlen(info->pth_name, sizeof(info->pth_name));
			sock.name = nameLength ? [[NSString alloc] initWithBytes:info->pth_name
			                                                  length:nameLength
			                                                encoding:NSUTF8StringEncoding] : @"-";
			if (!sock.name)
				sock.name = @"-";
		}
	}
	return 0;
}

@end

/////////////////////////////////////////////////////////////////////////////////////////////////////////
//  OPEN FILES PAGE

static NSInteger psFetchFDSnapshot(pid_t pid, BOOL includeDetails)
{
	__block NSInteger result = -EIO;
	dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
	RHCommandCompletion completion = ^(NSString *stdoutString, NSString *stderrString, NSInteger exitCode) {
		if (exitCode == 0)
			result = stdoutString.integerValue;
		dispatch_semaphore_signal(semaphore);
	};
	if (includeDetails)
		[[RootHelperManager sharedManager] requestFileDescriptorsForPID:pid completion:completion];
	else
		[[RootHelperManager sharedManager] requestFileDescriptorReferencesForPID:pid completion:completion];
	dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

	if (result < 0)
		return result;
	struct CocoaTopFDSnapshot *snapshot = [RootHelperManager sharedManager].fdSnapshot;
	size_t recordsEnd = sizeof(*snapshot) +
	                    (size_t)snapshot->count * sizeof(snapshot->records[0]);
	if (snapshot->error != 0 || snapshot->pid != pid ||
	    snapshot->count != (uint32_t)result || snapshot->data_size < recordsEnd)
		return -EIO;
	return result;
}

static const void *psFDRecordInfo(const struct CocoaTopFDSnapshot *snapshot,
	                              const struct CocoaTopFDRecord *record,
	                              size_t expectedSize)
{
	if (record->info_size != expectedSize)
		return NULL;
	size_t recordsEnd = sizeof(*snapshot) +
	                    (size_t)snapshot->count * sizeof(snapshot->records[0]);
	uint64_t infoEnd = (uint64_t)record->info_offset + record->info_size;
	if (record->info_offset < recordsEnd || infoEnd > snapshot->data_size)
		return NULL;
	return (const char *)snapshot + record->info_offset;
}

@implementation PSSockFiles

- (instancetype)initWithSocks:(PSSockArray *)socks
	                   snapshot:(const struct CocoaTopFDSnapshot *)snapshot
	                     record:(const struct CocoaTopFDRecord *)record
{
	int32_t fd = record->descriptor.proc_fd;
	uint32_t type = record->descriptor.proc_fdtype;
	NSMutableString *name = nil;
    UIColor *color = _labelColor();//[UIColor blackColor];
	uint32_t flags = record->flags;
	uint64_t node = record->node;
	char *stype = nil;
	size_t infoSize = type == PROX_FDTYPE_VNODE ? sizeof(struct vnode_fdinfowithpath) :
	                  type == PROX_FDTYPE_PIPE ? sizeof(struct pipe_fdinfo) :
	                  type == PROX_FDTYPE_KQUEUE ? sizeof(struct kqueue_fdinfo) :
	                  type == PROX_FDTYPE_SOCKET ? sizeof(struct socket_fdinfo) : 0;
	const void *infoData = infoSize ? psFDRecordInfo(snapshot, record, infoSize) : NULL;

	if (!infoData) {
		if (type == PROX_FDTYPE_VNODE) { name = [@"VNODE" mutableCopy]; stype = "VNODE"; }
		else if (type == PROX_FDTYPE_PIPE) { name = [@"PIPE" mutableCopy]; stype = "PIPE"; color = _blueColor(); }
		else if (type == PROX_FDTYPE_KQUEUE) { name = [@"KQUEUE" mutableCopy]; stype = "QUEUE"; color = _grayColor(); }
		else if (type == PROX_FDTYPE_SOCKET) { name = [@"SOCKET" mutableCopy]; stype = "SOCK"; }
	} else if (type == PROX_FDTYPE_VNODE) {
		struct vnode_fdinfowithpath info;
		memcpy(&info, infoData, sizeof(info));
		name = [[PSSymLink simplifyPathName:[NSString stringWithUTF8String:info.pvip.vip_path]] mutableCopy];
		stype = "VNODE";
		flags = info.pfi.fi_openflags;
		node = info.pvip.vip_vi.vi_stat.vst_ino;
	} else if (type == PROX_FDTYPE_PIPE) {
		struct pipe_fdinfo info;
		memcpy(&info, infoData, sizeof(info));
		NSString *partner = socks.objects[@(info.pipeinfo.pipe_peerhandle)];
		name = [NSMutableString stringWithFormat:@"\u2192 %@", partner ? partner : @"<Unknown>"];
		if (info.pipeinfo.pipe_status & PIPE_WANTR)			[name appendString:@" READ"];
		if (info.pipeinfo.pipe_status & PIPE_WANTW)			[name appendString:@" WRITE"];
		if (info.pipeinfo.pipe_status & PIPE_SEL)			[name appendString:@" SELECT"];
		if (info.pipeinfo.pipe_status & PIPE_EOF)			[name appendString:@" EOF"];
		if (info.pipeinfo.pipe_status & PIPE_KNOTE)			[name appendString:@" KNOTE"];
		if (info.pipeinfo.pipe_status & PIPE_DRAIN)			[name appendString:@" DRAIN"];
		if (info.pipeinfo.pipe_status & PIPE_DEAD)			[name appendString:@" DEAD"];
		stype = "PIPE";
        color = _blueColor();//[UIColor blueColor];
		flags = info.pfi.fi_openflags;
		node = info.pipeinfo.pipe_handle;
	} else if (type == PROX_FDTYPE_KQUEUE) {
		struct kqueue_fdinfo info;
		memcpy(&info, infoData, sizeof(info));
		name = [info.kqueueinfo.kq_state & PROC_KQUEUE_64 ? @"KQUEUE64:" : info.kqueueinfo.kq_state & PROC_KQUEUE_32 ? @"KQUEUE32:" : @"KQUEUE:" mutableCopy];
		if (info.kqueueinfo.kq_state & PROC_KQUEUE_SELECT)	[name appendString:@" SELECT"];
		if (info.kqueueinfo.kq_state & PROC_KQUEUE_SLEEP)	[name appendString:@" SLEEP"];
		if (info.kqueueinfo.kq_state & PROC_KQUEUE_QOS)		[name appendString:@" QOS"];
		if (!(info.kqueueinfo.kq_state & ~(PROC_KQUEUE_32 | PROC_KQUEUE_64))) [name appendString:@" SUSPENDED"];
		stype = "QUEUE";
        color = _grayColor();//[UIColor grayColor];
		flags = info.pfi.fi_openflags;
		node = info.kqueueinfo.kq_state;
	} else if (type == PROX_FDTYPE_SOCKET) {
		char lip[INET_ADDRSTRLEN] = "", fip[INET_ADDRSTRLEN] = "";
		struct in_sockinfo *s;
		struct socket_fdinfo info;
		memcpy(&info, infoData, sizeof(info));
		switch (info.psi.soi_kind) {
		case SOCKINFO_TCP:	// Type: TCP
		case SOCKINFO_IN:	// Type: UDP
			s = info.psi.soi_kind == SOCKINFO_TCP ? &info.psi.soi_proto.pri_tcp.tcpsi_ini : &info.psi.soi_proto.pri_in;
			if (info.psi.soi_family == AF_INET) {
				inet_ntop(info.psi.soi_family, &s->insi_faddr.ina_46.i46a_addr4, fip, INET_ADDRSTRLEN);
				inet_ntop(info.psi.soi_family, &s->insi_laddr.ina_46.i46a_addr4, lip, INET_ADDRSTRLEN);
			}
			if (info.psi.soi_family == AF_INET6) {
				inet_ntop(info.psi.soi_family, &s->insi_faddr.ina_6, fip, INET_ADDRSTRLEN);
				inet_ntop(info.psi.soi_family, &s->insi_laddr.ina_6, lip, INET_ADDRSTRLEN);
			}
			struct servent any = {"*"};	// \u2731
			struct servent *lsp = 0, *fsp = 0;
			lsp = s->insi_lport ? getservbyport(s->insi_lport, 0) : &any;
			fsp = s->insi_fport ? getservbyport(s->insi_fport, 0) : &any;
			if (info.psi.soi_family == AF_INET6) stype = (info.psi.soi_kind == SOCKINFO_TCP) ? "TCP6" : "UDP6";
											else stype = (info.psi.soi_kind == SOCKINFO_TCP) ? "TCP" : "UDP";
			if (lsp) name = [NSMutableString stringWithFormat:@"%s:%s \u2192 ", lip, lsp->s_name];
				else name = [NSMutableString stringWithFormat:@"%s:%d \u2192 ", lip, ntohs(s->insi_lport)];
			if (!s->insi_fport) [name appendString:@"Listening"]; else
			if (fsp) [name appendFormat:@"%s:%s", fip, fsp->s_name];
				else [name appendFormat:@"%s:%d", fip, ntohs(s->insi_fport)];
                
            color = _greenColor();//[UIColor colorWithRed:.0 green:.5 blue:.0 alpha:1.0];
			break;
		case SOCKINFO_UN: {
			stype = "UNIX";
			switch (info.psi.soi_type) {
			case SOCK_STREAM:	name = [@"STREAM" mutableCopy]; break;
			case SOCK_DGRAM:	name = [@"DGRAM" mutableCopy]; break;
			case SOCK_RAW:		name = [@"RAW" mutableCopy]; break;
			case SOCK_RDM:		name = [@"RDM" mutableCopy]; break;
			case SOCK_SEQPACKET:name = [@"SEQPACKET" mutableCopy]; break;
			default: 			name = [NSMutableString stringWithFormat:@"UNIX: %d", info.psi.soi_type];
			}
			NSString *client = [NSString stringWithUTF8String:info.psi.soi_proto.pri_un.unsi_caddr.ua_sun.sun_path],
					 *server = [NSString stringWithUTF8String:info.psi.soi_proto.pri_un.unsi_addr.ua_sun.sun_path],
					*partner = socks.objects[@(info.psi.soi_proto.pri_un.unsi_conn_so)];
			[name appendFormat:@": %@ \u2192 %@ %@", [PSSymLink simplifyPathName:client], [PSSymLink simplifyPathName:server], partner ? partner : @""];
			color = [UIColor brownColor];
			break; }
		case SOCKINFO_GENERIC:
			name = [NSMutableString stringWithFormat:@"GENERIC: %d", info.psi.soi_family];
			stype = "GEN";
			break;
		case SOCKINFO_NDRV:
			name = [NSMutableString stringWithFormat:@"NDRV: %d", info.psi.soi_family];
			stype = "NDRV";
			break;
		case SOCKINFO_KERN_CTL:
			name = [NSMutableString stringWithFormat:@"KEXT: %s", info.psi.soi_proto.pri_kern_ctl.kcsi_name];
			stype = "KCTL";
            color = _orangeColor();//[UIColor orangeColor];
			break;
		case SOCKINFO_KERN_EVENT: {
			struct kern_event_info *ki = &info.psi.soi_proto.pri_kern_event;
			NSString *kvendor = [NSString stringWithFormat:@"%d", ki->kesi_vendor_code_filter];
			NSString *kclass  = [NSString stringWithFormat:@"%d", ki->kesi_class_filter];
			NSString *ksubcls = [NSString stringWithFormat:@"%d", ki->kesi_subclass_filter];
			if (ki->kesi_vendor_code_filter == KEV_VENDOR_APPLE)	kvendor = @"APPLE";
			if (ki->kesi_vendor_code_filter == KEV_ANY_VENDOR)		kvendor = @"ANY";
			if (ki->kesi_class_filter == KEV_ANY_CLASS)				kclass  = @"ANY";
			if (ki->kesi_subclass_filter == KEV_ANY_SUBCLASS)		ksubcls = @"ANY";
			switch (ki->kesi_class_filter) {
			case KEV_NETWORK_CLASS:				kclass = @"NETWORK";
				switch (ki->kesi_subclass_filter) {
				case KEV_INET_SUBCLASS:			ksubcls = @"INET"; break;
				case KEV_DL_SUBCLASS:			ksubcls = @"DATALINK"; break;
				case KEV_NETPOLICY_SUBCLASS:	ksubcls = @"POLICY"; break;
				case KEV_SOCKET_SUBCLASS:		ksubcls = @"SOCKET"; break;
				case KEV_ATALK_SUBCLASS:		ksubcls = @"APPLETALK"; break;
				case KEV_INET6_SUBCLASS:		ksubcls = @"INET6"; break;
				case KEV_ND6_SUBCLASS:			ksubcls = @"ND6"; break;
				case KEV_NECP_SUBCLASS:			ksubcls = @"NECP"; break;
				case KEV_NETAGENT_SUBCLASS:		ksubcls = @"NETAGENT"; break;
				case KEV_LOG_SUBCLASS:			ksubcls = @"LOG"; break;
				} break;
			case KEV_IOKIT_CLASS:				kclass = @"IOKIT"; break;
			case KEV_SYSTEM_CLASS:				kclass = @"SYSTEM";
				switch (ki->kesi_subclass_filter) {
				case KEV_CTL_SUBCLASS:			ksubcls = @"CTL"; break;
				case KEV_MEMORYSTATUS_SUBCLASS:	ksubcls = @"MEMORYSTATUS"; break;
				} break;
			case KEV_APPLESHARE_CLASS:			kclass = @"APPLESHARE"; break;
			case KEV_FIREWALL_CLASS:			kclass = @"FIREWALL";
				switch (ki->kesi_subclass_filter) {
				case KEV_IPFW_SUBCLASS:			ksubcls = @"IPFW"; break;
				case KEV_IP6FW_SUBCLASS:		ksubcls = @"IP6FW"; break;
				} break;
			case KEV_IEEE80211_CLASS:			kclass = @"WIFI"; break;
				switch (ki->kesi_subclass_filter) {
				case KEV_APPLE80211_EVENT_SUBCLASS: kclass = @"EVENT"; break;
				} break;
			}
			name = [NSMutableString stringWithFormat:@"%@:%@:%@", kvendor, kclass, ksubcls];
			stype = "KEVNT";
            color = _redColor();//[UIColor redColor];
			break; }
		}
		flags = info.pfi.fi_openflags;
		node = info.psi.soi_so;
	}
	if (!name)
		return nil;
	switch (fd) {
	case 0: [name appendString:@" [stdin]"]; break;
	case 1: [name appendString:@" [stdout]"]; break;
	case 2: [name appendString:@" [stderr]"]; break;
	}
	if (self = [super init]) {
		self.display = ProcDisplayStarted;
		self.fd = fd;
		self.type = type;
		self.stype = stype;
		self.color = color;
		self.name = [name copy];
		self.flags = flags;
		self.node = node;
	}
	return self;
}

+ (instancetype)psSock:(PSSockArray *)socks
	           snapshot:(const struct CocoaTopFDSnapshot *)snapshot
	             record:(const struct CocoaTopFDRecord *)record
{
	return [[PSSockFiles alloc] initWithSocks:socks snapshot:snapshot record:record];
}

- (BOOL)updateWithFDRecord:(const struct CocoaTopFDRecord *)record
{
	if (self.display != ProcDisplayStarted)
		self.display = ProcDisplayUser;
	if (!self.node || !record->node)
		return YES;
	if (self.type != PROX_FDTYPE_KQUEUE)
		return self.node == record->node;
	if (self.node == record->node)
		return YES;
	self.node = record->node;
	uint32_t state = record->status;
	NSMutableString *name = [state & PROC_KQUEUE_64 ? @"KQUEUE64:" : state & PROC_KQUEUE_32 ? @"KQUEUE32:" : @"KQUEUE:" mutableCopy];
	if (state & PROC_KQUEUE_SELECT) [name appendString:@" SELECT"];
	if (state & PROC_KQUEUE_SLEEP) [name appendString:@" SLEEP"];
	if (state & PROC_KQUEUE_QOS) [name appendString:@" QOS"];
	if (!(state & ~(PROC_KQUEUE_32 | PROC_KQUEUE_64))) [name appendString:@" SUSPENDED"];
	self.name = name;
	return YES;
}

// Get system-wide fds that can potentially be used for IPC with this process
+ (int)getKernelObjects:(NSMutableDictionary *)objects
{
	PSProcInfo *procs = [PSProcInfo psProcInfoSort:NO];
	for (int i = 0; i < procs->count; i++) {
		struct extern_proc *ep = &procs->records[i].kinfo.kp_proc;
		NSInteger count = psFetchFDSnapshot(ep->p_pid, NO);
		if (count < 0)
			continue;
		struct CocoaTopFDSnapshot *snapshot = [RootHelperManager sharedManager].fdSnapshot;
		for (NSInteger j = 0; j < count; j++) {
			const struct CocoaTopFDRecord *record = &snapshot->records[j];
			BOOL isPipe = record->descriptor.proc_fdtype == PROX_FDTYPE_PIPE;
			BOOL isUnixSocket = record->descriptor.proc_fdtype == PROX_FDTYPE_SOCKET &&
			                    record->status == SOCKINFO_UN;
			if ((isPipe || isUnixSocket) && record->node)
				objects[@(record->node)] = [NSString stringWithFormat:@"[%@:%d]", psGetProcessName(ep), record->descriptor.proc_fd];
		}
	}
	return 0;
}

+ (int)refreshArray:(PSSockArray *)socks
{
	if (!socks.objects) {
		socks.objects = [NSMutableDictionary dictionaryWithCapacity:1000];
		[self getKernelObjects:socks.objects];
	}
	NSInteger totalfds = psFetchFDSnapshot(socks.proc.pid, YES);
	if (totalfds < 0)
		return (int)-totalfds;
	struct CocoaTopFDSnapshot *snapshot = [RootHelperManager sharedManager].fdSnapshot;
	for (NSInteger i = 0; i < totalfds; i++) {
		const struct CocoaTopFDRecord *record = &snapshot->records[i];
			PSSockFiles *sock = (PSSockFiles *)[socks objectPassingTest:^BOOL(PSSockFiles *obj, NSUInteger idx, BOOL *stop) {
				return obj.fd == record->descriptor.proc_fd && obj.type == record->descriptor.proc_fdtype;
			}];
			if (!sock) {
				sock = [PSSockFiles psSock:socks snapshot:snapshot record:record];
				if (sock) [socks.socks addObject:sock];
			} else if (![sock updateWithFDRecord:record]) {
				sock.display = ProcDisplayTerminated;
				PSSockFiles *newsock = [PSSockFiles psSock:socks snapshot:snapshot record:record];
				if (newsock) [socks.socks addObject:newsock];
			}
	}
	return 0;
}

@end

/////////////////////////////////////////////////////////////////////////////////////////////////////////
//  OPEN PORTS PAGE

static NSInteger psFetchPortSnapshot(pid_t pid, BOOL includeDetails)
{
	__block NSInteger result = -EIO;
	dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
	RHCommandCompletion completion = ^(NSString *stdoutString, NSString *stderrString, NSInteger exitCode) {
		if (exitCode == 0)
			result = stdoutString.integerValue;
		dispatch_semaphore_signal(semaphore);
	};
	if (includeDetails)
		[[RootHelperManager sharedManager] requestPortsForPID:pid completion:completion];
	else
		[[RootHelperManager sharedManager] requestPortReferencesForPID:pid completion:completion];
	dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

	if (result < 0)
		return result;
	struct CocoaTopPortSnapshot *snapshot = [RootHelperManager sharedManager].portSnapshot;
	size_t recordsEnd = sizeof(*snapshot) +
	                    (size_t)snapshot->count * sizeof(snapshot->records[0]);
	if (snapshot->error != 0 || snapshot->pid != pid ||
	    snapshot->count != (uint32_t)result ||
	    snapshot->data_size < recordsEnd)
		return -EIO;
	return result;
}

static NSString *psPortRecordDetails(const struct CocoaTopPortSnapshot *snapshot,
	                                  const struct CocoaTopPortRecord *record)
{
	if (!record->detail_length)
		return nil;
	uint64_t end = (uint64_t)record->detail_offset + record->detail_length;
	if (record->detail_offset < sizeof(*snapshot) || end > snapshot->data_size)
		return nil;
	return [[NSString alloc] initWithBytes:(const char *)snapshot + record->detail_offset
	                              length:record->detail_length
	                            encoding:NSUTF8StringEncoding];
}

@implementation PSSockPorts

+ (NSMutableDictionary *)getLaunchdPortNames
{
    static dispatch_queue_t launchd_pipe_queue;
    static dispatch_once_t once;
    static NSCharacterSet *MU_cset;
    static NSCharacterSet *AD_cset;
    dispatch_once(&once, ^{
        launchd_pipe_queue = dispatch_queue_create("com.sxx.queue.launchd_pipe", DISPATCH_QUEUE_SERIAL);
        MU_cset = [NSCharacterSet characterSetWithCharactersInString:@"MU"];
        AD_cset = [NSCharacterSet characterSetWithCharactersInString:@"AD"];
    });
	NSMutableDictionary *knownPorts = nil;
	int *hpipe = alloca(sizeof(int) * 2);
	pipe(hpipe);
	xpc_object_t xpc_out = 0, xpc_in = xpc_dictionary_create(0, 0, 0);
	xpc_dictionary_set_uint64(xpc_in, "handle", 0);
	xpc_dictionary_set_uint64(xpc_in, "routine", 828);
	xpc_dictionary_set_uint64(xpc_in, "subsystem", 3);
	xpc_dictionary_set_uint64(xpc_in, "type", 1);
	xpc_dictionary_set_fd(xpc_in, "fd", hpipe[1]);
	xpc_pipe_t xp = xpc_pipe_create_from_port(bootstrap_port, 0);
//	xpc_pipe_t xp = (xpc_pipe_t)_os_alloc_once_table[1].ptr[3];
//#if __IPHONE_OS_VERSION_MAX_ALLOWED >= __IPHONE_6_0
    if (@available(iOS 6, *)) {
        size_t buf_size;
        if (@available(iOS 12, *)) {
            buf_size = 0x800000u;
        } else {
            buf_size = 0x100000u;
        }
        char *buf = (char *)malloc(buf_size);
        
        dispatch_async(launchd_pipe_queue, ^{
            off_t done = 0;
            size_t remains = buf_size;
            int fd = hpipe[0];
            while (done < buf_size) {
                ssize_t once = read(fd, buf + done, remains);
                if (once <= 0) {
                    break;
                }
                done += once;
                remains -= once;
            }
        });
        
        if (xpc_pipe_routine(xp, xpc_in, &xpc_out) || !xpc_dictionary_get_int64(xpc_out, "error")) {
            #if !OS_OBJECT_USE_OBJC_RETAIN_RELEASE
            xpc_release(xpc_in);
            #endif
            xpc_in = nil;
            close(hpipe[1]);
            hpipe[1] = -1;
            dispatch_sync(launchd_pipe_queue, ^{});
        }
		char *endpoints_start = strstr(buf, "\tendpoints = {");
		if (endpoints_start) {
			endpoints_start += 14;
			char *endpoints_end = strchr(endpoints_start, '}');
			if (endpoints_end)
				*endpoints_end = 0;
			NSScanner *endpoints = [NSScanner scannerWithString:[NSString stringWithUTF8String:endpoints_start]];
			free(buf);
            buf = NULL;
			knownPorts = [NSMutableDictionary dictionaryWithCapacity:1000];
			NSInteger portCount = psFetchPortSnapshot(1, NO);
			struct CocoaTopPortSnapshot *ports = [RootHelperManager sharedManager].portSnapshot;
			while (!endpoints.isAtEnd) {
				mach_port_name_t port;
				NSString *name;
				if (![endpoints scanHexInt:&port]) break;
				[endpoints scanCharactersFromSet:MU_cset intoString:nil];
				[endpoints scanCharactersFromSet:AD_cset intoString:nil];
				if (![endpoints scanUpToCharactersFromSet:[NSCharacterSet newlineCharacterSet] intoString:&name]) break;
				for (NSInteger i = 0; i < portCount; i++)
					if (ports->records[i].info.iin_name == port) {
						knownPorts[@(ports->records[i].info.iin_object)] = name;
						break;
					}
			}
		}
        if (buf != NULL) {
            free(buf);
        }
    }
#if !OS_OBJECT_USE_OBJC_RETAIN_RELEASE
	if (xpc_in) xpc_release(xpc_in);
	if (xpc_out) xpc_release(xpc_out);
	xpc_release(xp);
#endif
    if (hpipe[0] != -1) {
        close(hpipe[0]);
    }
    if (hpipe[1] != -1) {
        close(hpipe[1]);
    }
//#endif
	return knownPorts;
}

static const char *port_types[] = {"","(thread)","(task)","(host)","(host priv)","(processor)","(pset)","(pset name)",
	"(timer)","(paging request)","(mig)","(memory object)","(xmm pager)","(xmm kernel)","(xmm reply)","(und reply)","(host notify)",
	"(host security)","(ledger)","(master device)","(task name)","(subsystem)","(io done queue)","(semaphore)","(lock set)",
	"(clock)","(clock ctrl)","(iokit spare)","(named entry)","(iokit connect)","(iokit object)","(upl)","(xmm ctrl)",
	"(audit session)","(file)","(label handle)","(task resume)","(voucher)","(voucher attr)","(work interval)",
	"(ux handler)","(user extension)","(arcade registration)","(eventlink)","(task inspect)","(task read)",
	"(thread inspect)","(thread read)","(suid credential)","(hypervisor)","(task id token)","(task fatal)",
	"(kcdata)","(exclaves resource)","(thread resume)"};

static NSString *psPortObjectTypeName(natural_t objectType)
{
	if (objectType < sizeof(port_types) / sizeof(port_types[0]))
		return [NSString stringWithUTF8String:port_types[objectType]];
	return objectType == IPC_OTYPE_UNKNOWN ? @"(unknown)" :
	       [NSString stringWithFormat:@"(type %u)", objectType];
}

- (NSString *)description
{
	if (!self.name) self.name = self.connect.length ? [self.connect copy] : @"-";
	return self.name;
}

- (instancetype)initWithPortRecord:(const struct CocoaTopPortRecord *)record
	                         name:(NSString *)name
	                      details:(NSString *)details
{
	if (self = [super init]) {
		self.display = ProcDisplayStarted;
		const ipc_info_name_t *iin = &record->info;
		self.port = iin->iin_name;
		self.object = iin->iin_object;
		self.type = iin->iin_type;
		mach_port_type_t send = iin->iin_type & MACH_PORT_TYPE_SEND_RIGHTS;
		mach_port_type_t recv = iin->iin_type & MACH_PORT_TYPE_RECEIVE;
		mach_port_type_t pset = iin->iin_type & MACH_PORT_TYPE_PORT_SET;

		self.connect = name ? [name mutableCopy] : [psPortObjectTypeName(record->object_type) mutableCopy];
		if (pset) {
			if (!self.connect.length)
				[self.connect appendString:@"(portset)"];
			if (details.length)
				[self.connect appendString:details];
		}
		self.color = pset ? _orangeColor()/*[UIColor orangeColor]*/ : send && recv ? _greenColor()/*[UIColor colorWithRed:.0 green:.5 blue:.0 alpha:1.0]*/ : recv ? _blueColor()/*[UIColor blueColor]*/ : /*[UIColor blackColor]*/_labelColor();
	}
	return self;
}

+ (instancetype)psSockWithPortRecord:(const struct CocoaTopPortRecord *)record
	                              name:(NSString *)name
	                           details:(NSString *)details
{
	return [[PSSockPorts alloc] initWithPortRecord:record name:name details:details];
}

+ (int)refreshArray:(PSSockArray *)socks
{
	if (!socks.objects) socks.objects = [self getLaunchdPortNames];
	NSInteger portCount = psFetchPortSnapshot(socks.proc.pid, YES);
	if (portCount < 0)
		return (int)-portCount;
	struct CocoaTopPortSnapshot *myports = [RootHelperManager sharedManager].portSnapshot;
	NSMutableDictionary *newPorts = [NSMutableDictionary dictionary];

	for (NSInteger i = 0; i < portCount; i++) {
		const struct CocoaTopPortRecord *record = &myports->records[i];
		natural_t object = record->info.iin_object;
		if (object) {
			PSSockPorts *sock = (PSSockPorts *)[socks objectPassingTest:^BOOL(PSSockPorts *obj, NSUInteger idx, BOOL *stop) {
				return obj.object == object;
			}];
			if (!sock) {
				sock = [PSSockPorts psSockWithPortRecord:record
				                                      name:socks.objects[@(object)]
				                                   details:psPortRecordDetails(myports, record)];
				if (sock) {
					[socks.socks addObject:sock];
					newPorts[@(object)] = sock;
				}
			} else if (sock.display != ProcDisplayStarted)
				sock.display = ProcDisplayUser;
		}
	}
	if (!newPorts.count)
		return 0;

	PSProcInfo *procs = [PSProcInfo psProcInfoSort:YES];
	for (int i = 0; i < procs->count; i++) {
		struct extern_proc *ep = &procs->records[i].kinfo.kp_proc;
		if (ep->p_pid != socks.proc.pid) {
			NSInteger otherPortCount = psFetchPortSnapshot(ep->p_pid, NO);
			if (otherPortCount < 0)
				continue;
			struct CocoaTopPortSnapshot *ports = [RootHelperManager sharedManager].portSnapshot;
			for (NSInteger j = 0; j < otherPortCount; j++) {
				const ipc_info_name_t *info = &ports->records[j].info;
				PSSockPorts *sock = newPorts[@(info->iin_object)];
				if (!sock)
					continue;
				if ((sock.type & MACH_PORT_TYPE_RECEIVE) && (info->iin_type & MACH_PORT_TYPE_SEND_RIGHTS))
					[sock.connect appendFormat:@" <%@:%X", psGetProcessName(ep), info->iin_name];
				else if ((sock.type & MACH_PORT_TYPE_SEND_RIGHTS) && (info->iin_type & MACH_PORT_TYPE_RECEIVE))
					[sock.connect appendFormat:@" >%@:%X", psGetProcessName(ep), info->iin_name];
			}
		}
	}
	return 0;
}

@end

/////////////////////////////////////////////////////////////////////////////////////////////////////////
//  MODULES PAGE

@implementation PSSockModules

- (instancetype)initWithRwpi:(struct proc_regionwithpathinfo *)rwpi
{
	if (!rwpi->prp_vip.vip_path[0] && !rwpi->prp_vip.vip_vi.vi_stat.vst_dev && !rwpi->prp_vip.vip_vi.vi_stat.vst_ino)
		return nil;
	if (self = [super init]) {
		self.display = ProcDisplayStarted;
		self.name = rwpi->prp_vip.vip_path[0] ? [PSSymLink simplifyPathName:[NSString stringWithUTF8String:rwpi->prp_vip.vip_path]] : @"<none>";
		self.bundle = [self.name lastPathComponent];
		self.addr = rwpi->prp_prinfo.pri_address;
		self.size = rwpi->prp_prinfo.pri_size;
		self.ref = rwpi->prp_prinfo.pri_ref_count;
		self.dev = rwpi->prp_vip.vip_vi.vi_stat.vst_dev;
		self.ino = rwpi->prp_vip.vip_vi.vi_stat.vst_ino;
		self.color = self.dev && self.ino ? _labelColor()/*[UIColor blackColor]*/ : _grayColor()/*[UIColor grayColor]*/;
	}
	return self;
}

+ (instancetype)psSockWithRwpi:(struct proc_regionwithpathinfo *)rwpi
{
	return [[PSSockModules alloc] initWithRwpi:rwpi];
}

- (instancetype)initWithDict:(NSDictionary *)dict 
{
	if (self = [super init]) {
		self.display = ProcDisplayUser;
		self.name = dict[@"OSBundleExecutablePath"];
		self.addr = [dict[@"OSBundleLoadAddress"] longLongValue] & 0xffffffffffffLL;
		self.size = [dict[@"OSBundleLoadSize"] longLongValue];
		self.ref = [dict[@"OSBundleRetainCount"] longValue];
//		self.dev = [dict[@"OSBundleLoadTag"] longValue];
		self.color = self.name ? _labelColor()/*[UIColor blackColor]*/ : _grayColor()/*[UIColor grayColor]*/;
		self.bundle = dict[@"CFBundleIdentifier"];
		if (!self.name) self.name = self.bundle;
	}
	return self;
}

+ (instancetype)psSockWithDict:(NSDictionary *)dict 
{
	return [[PSSockModules alloc] initWithDict:dict];
}

- (NSString *)description
{
	return self.bundle;
}

CFDictionaryRef (*OSKextCopyLoadedKextInfo)(CFArrayRef kextIdentifiers, CFArrayRef infoKeys);

+ (int)refreshArray:(PSSockArray *)socks
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        OSKextCopyLoadedKextInfo = dlsym(nil, "_OSKextCopyLoadedKextInfo");
    });
    
	// For the kernel task we will show loaded kernel extensions
	if (socks.proc.pid == 0) {
		if (!socks.objects) {
			// CFBundleVersion OSBundleStarted
			NSArray *infoKeys = @[@"CFBundleIdentifier", @"OSBundleExecutablePath", @"OSBundleLoadAddress", @"OSBundleLoadSize", @"OSBundleLoadTag", @"OSBundleRetainCount"];
			NSDictionary *kextDict = (__bridge NSDictionary*)OSKextCopyLoadedKextInfo(0, (__bridge CFArrayRef)infoKeys);
			[kextDict enumerateKeysAndObjectsUsingBlock: ^void(NSString *key, NSDictionary *kext, BOOL *stop) {
				[socks.socks addObject:[PSSockModules psSockWithDict:kext]];
			}];
			socks.objects = [NSMutableDictionary dictionaryWithCapacity:1];
		} else {
			[socks setAllDisplayed:ProcDisplayUser];
		}
		return 0;
	}

	__block NSInteger result = -EIO;
	dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
	[[RootHelperManager sharedManager] requestModulesForPID:socks.proc.pid
	                                           completion:^(NSString *stdoutString, NSString *stderrString, NSInteger exitCode) {
		if (exitCode == 0)
			result = stdoutString.integerValue;
		dispatch_semaphore_signal(semaphore);
	}];
	dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

	struct CocoaTopDetailSnapshot *snapshot = [RootHelperManager sharedManager].detailSnapshot;
	if (result < 0)
		return (int)-result;
	if (snapshot->error != 0 || snapshot->pid != socks.proc.pid ||
	    snapshot->module_count != (uint32_t)result)
		return EIO;

	for (uint32_t i = 0; i < snapshot->module_count; i++) {
		struct proc_regionwithpathinfo *region = &snapshot->modules[i].region;
		mach_vm_address_t address = region->prp_prinfo.pri_address;
		PSSockModules *sock = (PSSockModules *)[socks objectPassingTest:^BOOL(PSSockModules *obj, NSUInteger idx, BOOL *stop) {
			return obj.addr == address;
		}];
		PSSockModules *updated = [PSSockModules psSockWithRwpi:region];
		if (!updated)
			continue;
		if (!sock) {
			[socks.socks addObject:updated];
		} else {
			if (sock.display != ProcDisplayStarted)
				sock.display = ProcDisplayUser;
			sock.name = updated.name;
			sock.bundle = updated.bundle;
			sock.size = updated.size;
			sock.ref = updated.ref;
			sock.dev = updated.dev;
			sock.ino = updated.ino;
			sock.color = updated.color;
		}
	}
	return 0;
}

@end

/////////////////////////////////////////////////////////////////////////////////////////////////////////
//  PSSockArray

@implementation PSSockArray

- (instancetype)initSockArrayWithProc:(PSProc *)proc
{
	if (self = [super init]) {
		self.proc = proc;
		self.socks = [NSMutableArray arrayWithCapacity:300];
	}
	return self;
}

+ (instancetype)psSockArrayWithProc:(PSProc *)proc
{
	return [[PSSockArray alloc] initSockArrayWithProc:proc];
}

- (int)refreshWithMode:(column_mode_t)mode
{
	// Remove closed sockets
	[self.socks filterUsingPredicate:[NSPredicate predicateWithBlock: ^BOOL(PSSock *obj, NSDictionary *bind) {
		return obj.display != ProcDisplayTerminated;
	}]];
	[self setAllDisplayed:ProcDisplayTerminated];
	Class ModeClass[ColumnModes] = {[PSSockSummary class], [PSSockThreads class], [PSSockFiles class], [PSSockPorts class], [PSSockModules class]};
	return [ModeClass[mode] refreshArray:self];
}

- (void)sortUsingComparator:(NSComparator)comp desc:(BOOL)desc
{
	if (desc)
		[self.socks sortUsingComparator:^NSComparisonResult(id a, id b) { return comp(b, a); }];
	else
		[self.socks sortUsingComparator:comp];
}

- (void)setAllDisplayed:(display_t)display
{
	for (PSSock *sock in self.socks)
		// Setting all items to "normal" is used only to hide "started"
		if (display != ProcDisplayNormal || sock.display == ProcDisplayStarted)
			sock.display = display;
}

- (NSUInteger)indexOfDisplayed:(display_t)display
{
	return [self.socks indexOfObjectPassingTest:^BOOL(id obj, NSUInteger idx, BOOL *stop) {
		return ((PSSock *)obj).display == display;
	}];
}

- (NSUInteger)count
{
	return self.socks.count;
}

- (PSSock *)objectAtIndexedSubscript:(NSUInteger)idx
{
	return (PSSock *)self.socks[idx];
}

- (PSSock *)objectPassingTest:(BOOL (^)(id obj, NSUInteger idx, BOOL *stop))predicate
{
	NSUInteger idx = [self.socks indexOfObjectPassingTest:predicate];
	return idx == NSNotFound ? nil : (PSSock *)self.socks[idx];
}

@end
