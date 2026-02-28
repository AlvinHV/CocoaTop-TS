#import "Compat.h"
#import "Column.h"
#import "Proc.h"
#import "ProcArray.h"
#import "Sock.h"
#import <pwd.h>
#import <grp.h>
#import <sys/stat.h>
#import <sys/fcntl.h>
#import <mach/mach_time.h>

NSString *psProcessStateString(PSProc *proc)
{
	static const char states[] = PROC_STATE_CHARS;
	unichar st[8], *pst = st;

	*pst++ = states[proc.state];
	if (proc.nice < 0)
		*pst++ = L'\u25B2';	// up
	else if (proc.nice > 0)
		*pst++ = L'\u25BC';	// down
	if (proc.flags & P_TRACED)
		*pst++ = 't';
	if (proc.flags & P_WEXIT && proc.state != 1)
		*pst++ = 'z';
	if (proc.flags & P_PPWAIT)
		*pst++ = 'w';
	if (proc.flags & P_SYSTEM)
		*pst++ = 'K';
	if (proc->basic.suspend_count > 0)
		*pst++ = 'B';
	return [NSString stringWithCharacters:st length:(pst - st)];
}

NSString *psThreadStateString(PSSockThreads *sock)
{
	static const char states[] = PROC_STATE_CHARS;
	unichar st[8], *pst = st;

	*pst++ = states[mach_state_order(&sock->tbi)];
	if (sock->tbi.flags & TH_FLAGS_IDLE)
		*pst++ = L'i';
	if (sock->tbi.suspend_count)
		*pst++ = L'B';
	return [NSString stringWithCharacters:st length:(pst - st)];
}

NSString *psFdFlagsString(uint32_t openflags)
{
	unichar st[8], *pst = st;

	if (openflags & FREAD)
		*pst++ = L'R';
	if (openflags & FWRITE)
		*pst++ = L'W';
	if (openflags & O_APPEND)
		*pst++ = L'A';
	if (openflags & O_EXLOCK)
		*pst++ = L'L';
	if (openflags & O_NONBLOCK)
		*pst++ = L'N';
	if (openflags & O_EVTONLY)
		*pst++ = L'E';
	return [NSString stringWithCharacters:st length:(pst - st)];
}

NSString *psPortRightsString(uint32_t rights)
{
	unichar st[8], *pst = st;

	if (rights & MACH_PORT_TYPE_SEND_RIGHTS)
		*pst++ = L'S';
	if (rights & MACH_PORT_TYPE_SEND_ONCE)
		*pst++ = L'o';
	if (rights & MACH_PORT_TYPE_RECEIVE)
		*pst++ = L'R';
	if (rights & MACH_PORT_TYPE_PORT_SET)
		*pst++ = L'P';
	if (rights & MACH_PORT_TYPE_PORT_SET)
		*pst++ = L's';
	if (rights & MACH_PORT_TYPE_DEAD_NAME)
		*pst++ = L'D';
	return [NSString stringWithCharacters:st length:(pst - st)];
}

NSString *psTaskRoleString(PSProc *proc)
{
	switch (proc.role) {
	case TASK_RENICED:					return @"Reniced";
	case TASK_UNSPECIFIED:				return @"-";
	case TASK_FOREGROUND_APPLICATION:	return @"Foreground";
	case TASK_BACKGROUND_APPLICATION:	return @"Background";
	case TASK_CONTROL_APPLICATION:		return @"Controller";
	case TASK_GRAPHICS_SERVER:			return @"GfxServer";
	case TASK_THROTTLE_APPLICATION:		return @"Throttle";
	case TASK_NONUI_APPLICATION:		return @"Inactive";
	case TASK_DEFAULT_APPLICATION:		return @"Default";
	default:							return @"Unknown";
	}
}

NSString *psProcessTty(PSProc *proc)
{
	char *ttname = 0;
	if (proc.tdev != NODEV)
		ttname = devname(proc.tdev, S_IFCHR);
	return [NSString stringWithCString:(ttname ? ttname : "??") encoding:NSASCIIStringEncoding];
}

NSString *psSystemUptime(void)
{
	static struct timeval boottime = {0};
	if (boottime.tv_sec == 0) {
		int mib[2] = {CTL_KERN, KERN_BOOTTIME};
		size_t size = sizeof(boottime);
	    sysctl(mib, 2, &boottime, &size, NULL, 0);
	}
    if (boottime.tv_sec) {
		time_t uptime;
		time(&uptime);
		uptime -= boottime.tv_sec;
		time_t days = uptime/60/60/24;
		return days ? [NSString stringWithFormat:@"%ldd %02ld:%02ld:%02ld", days, (uptime/60/60) % 24, (uptime/60) % 60, uptime % 60]
					: [NSString stringWithFormat:@"%ld:%02ld:%02ld", uptime/60/60, (uptime/60) % 60, uptime % 60];
	} else
		return @"-";
}

NSString *psProcessUptime(uint64_t uptime, uint64_t exittime)
{
	if (!uptime)
		return @"-";
	if (!exittime) exittime = mach_absolute_time();
	uptime = mach_time_to_milliseconds(exittime - uptime) / 1000;
	uint64_t days = uptime/60/60/24;
	return days ? [NSString stringWithFormat:@"%llud %02llu:%02llu:%02llu", days, (uptime/60/60) % 24, (uptime/60) % 60, uptime % 60]
				: [NSString stringWithFormat:@"%llu:%02llu:%02llu", uptime/60/60, (uptime/60) % 60, uptime % 60];
}

NSString *psProcessCpuTime(unsigned int ptime)
{
	unsigned int hours = ptime/100/60/60;
	return hours ? [NSString stringWithFormat:@"%u:%02u:%02u.%02u", hours, (ptime / 6000) % 60, (ptime / 100) % 60, ptime % 100]
				 : [NSString stringWithFormat:@"%u:%02u.%02u", ptime / 6000, (ptime / 100) % 60, ptime % 100];
}

@implementation PSColumn

#define DELTA(ptr, field1, field2) ((ptr)->field1.field2 - (ptr)->field1 ## _prev.field2)
#define COMPARE_ORDER(a, b) ((a) == (b) ? NSOrderedSame : (a) > (b) ? NSOrderedDescending : NSOrderedAscending)
#define COMPARE(field) return COMPARE_ORDER(a.field, b.field);
#define COMPARE_VAR(field) return COMPARE_ORDER(a->field, b->field);
#define COMPARE_DELTA(field1, field2) return COMPARE_ORDER(DELTA(a,field1,field2), DELTA(b,field1,field2));
//#define DIFF_ORDER(a, b) ((a) == (b) ? [UIColor blackColor] : (a) > (b) ? [UIColor colorWithRed:.85 green:.0 blue:.0 alpha:1.0] : [UIColor blueColor])
//#define DIFF_ORDER(a, b) ((a) == (b) ? [UIColor blackColor] : (a) > (b) ? [UIColor systemRedColor] : [UIColor systemBlueColor])
#define DIFF_ORDER(a, b) ({ \
    UIColor *color; \
    if ((a) == (b)) { \
        if (@available(iOS 13, *)) { \
            color = UIColor.labelColor; \
        } else { \
            color = UIColor.blackColor; \
        } \
    } else if ((a) > (b)) { \
        if (@available(iOS 7, *)) { \
            color = UIColor.systemRedColor; \
        } else { \
            color = [UIColor colorWithRed:.85 green:.0 blue:.0 alpha:1.0]; \
        } \
    } else { \
        if (@available(iOS 7, *)) { \
            color = UIColor.systemBlueColor; \
        } else { \
            color = [UIColor blueColor]; \
        } \
    } \
    color; \
})
#define DIFF(field) return DIFF_ORDER(proc.field, proc.prev.field);
#define DIFF_VAR(field) return DIFF_ORDER(proc->field, proc.prev->field);
#define DIFF_DELTA(field1, field2) return DIFF_ORDER(DELTA(proc,field1,field2), DELTA(proc.prev,field1,field2));

+ (NSArray *)psGetAllColumns
{
	static NSArray *allColumns;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
        allColumns = @[
        #if TARGET_IPHONE_SIMULATOR
            #include "Column_simulator.h"
        #else
            #include "Column_ios.h"
        #endif
        ];
	});
	return allColumns;
}

+ (NSMutableArray *)psGetShownColumnsWithWidth:(NSUInteger)width
{
	NSArray *columnOrder = [[NSUserDefaults standardUserDefaults] arrayForKey:@"Columns"];
	NSMutableArray *shownCols = [NSMutableArray array];
	PSColumn *extendedcol = nil;
	// Sanity check
	if (columnOrder.count == 0)
		columnOrder = @[@0, @1, @3, @5, @7, @20];
	for (NSNumber* order in columnOrder) {
		PSColumn *col = [PSColumn psColumnWithTag:order.unsignedIntegerValue];
		if (!col) continue;
		if (width < col.minwidth) break;
		[shownCols addObject:col];
		col.width = col.minwidth;
		width -= col.width;
		if (col.style & ColumnStyleExtend)
			extendedcol = col;
	}
	if (extendedcol)
		extendedcol.width = extendedcol.minwidth + width;
	return shownCols;
}

+ (NSArray *)psGetTaskColumns:(column_mode_t)mode
{
	static NSArray *sockColumns[ColumnModes];
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		sockColumns[ColumnModeSummary] = @[
		[PSColumn psColumnWithName:@"Column" fullname:@"Information Column" align:NSTextAlignmentLeft width:180 tag:1000 style:ColumnStyleEllipsis
			data:^NSString*(PSSockSummary *sock) { return sock.name; }
			sort:^NSComparisonResult(PSSock *a, PSSock *b) { return [a.name caseInsensitiveCompare:b.name]; } summary:nil],
		[PSColumn psColumnWithName:@"Value" fullname:@"Column Value" align:NSTextAlignmentLeft width:140 tag:1001 style:ColumnStyleExtend | ColumnStyleEllipsis
			data:^NSString*(PSSockSummary *sock) { return sock.col.getData(sock.proc); }
			sort:^NSComparisonResult(PSSock *a, PSSock *b) { return 0; } summary:nil],
		];
		sockColumns[ColumnModeThreads] = @[
		[PSColumn psColumnWithName:@"TID" fullname:@"Thread ID" align:NSTextAlignmentRight width:53 tag:2000 style:0
			data:^NSString*(PSSockThreads *sock) { return [NSString stringWithFormat:@"%llX", sock.tid]; }
			sort:^NSComparisonResult(PSSockThreads *a, PSSockThreads *b) { COMPARE(tid); } summary:nil],
		[PSColumn psColumnWithName:@"%" fullname:@"%CPU Usage" align:NSTextAlignmentRight width:42 tag:2001 style:ColumnStyleSortDesc
			data:^NSString*(PSSockThreads *sock) { return !sock->tbi.cpu_usage ? @"-" : [NSString stringWithFormat:@"%.1f", (float)sock->tbi.cpu_usage / 10]; }
			sort:^NSComparisonResult(PSSockThreads *a, PSSockThreads *b) { COMPARE_VAR(tbi.cpu_usage); } summary:nil],
		[PSColumn psColumnWithName:@"Time" fullname:@"Thread Time" align:NSTextAlignmentRight width:60 tag:2002 style:ColumnStyleSortDesc | ColumnStyleLowSpace
			data:^NSString*(PSSockThreads *sock) { return psProcessCpuTime(sock.ptime); }
			sort:^NSComparisonResult(PSSockThreads *a, PSSockThreads *b) { COMPARE(ptime); } summary:nil],
		[PSColumn psColumnWithName:@"S" fullname:@"Mach Thread State" align:NSTextAlignmentLeft width:33 tag:2003 style:ColumnStyleLowSpace
			data:^NSString*(PSSockThreads *sock) { return psThreadStateString(sock); }
			sort:^NSComparisonResult(PSSockThreads *a, PSSockThreads *b) { COMPARE_VAR(tbi.run_state); } summary:nil],
		[PSColumn psColumnWithName:@"Pri" fullname:@"Thread Priority" align:NSTextAlignmentRight width:37 tag:2004 style:ColumnStyleSortDesc | ColumnStyleLowSpace
			data:^NSString*(PSSockThreads *sock) { return [NSString stringWithFormat:@"%@%u", sock->tbi.policy == POLICY_RR ? @"R:" : sock->tbi.policy == POLICY_FIFO ? @"F:" : @"", sock.prio]; }
			sort:^NSComparisonResult(PSSockThreads *a, PSSockThreads *b) { COMPARE(prio); } summary:nil],
		[PSColumn psColumnWithName:@"Name / Dispatch Queue" fullname:@"Thread Name & Dispatch Queue" align:NSTextAlignmentLeft width:95 tag:2005 style:ColumnStyleExtend | ColumnStyleEllipsis
			data:^NSString*(PSSockThreads *sock) { return sock.name; }
			sort:^NSComparisonResult(PSSockThreads *a, PSSockThreads *b) { return [a.name caseInsensitiveCompare:b.name]; } summary:nil],
		];
		sockColumns[ColumnModeFiles] = @[
		[PSColumn psColumnWithName:@"FD" fullname:@"File Descriptor" align:NSTextAlignmentRight width:40 tag:3000 style:0
			data:^NSString*(PSSockFiles *sock) { return [NSString stringWithFormat:@"%d", sock.fd]; }
			sort:^NSComparisonResult(PSSockFiles *a, PSSockFiles *b) { COMPARE(fd); } summary:nil],
		[PSColumn psColumnWithName:@"Open file/socket" fullname:@"Filename or Socket Address" align:NSTextAlignmentLeft width:220 tag:3001 style:ColumnStylePathTrunc
			data:^NSString*(PSSockFiles *sock) { return sock.name; }
			sort:^NSComparisonResult(PSSockFiles *a, PSSockFiles *b) { return [a.name caseInsensitiveCompare:b.name]; } summary:nil],
		[PSColumn psColumnWithName:@"Type" fullname:@"Descriptor Type" align:NSTextAlignmentLeft width:50 tag:3002 style:ColumnStyleLowSpace
			data:^NSString*(PSSockFiles *sock) { return [NSString stringWithUTF8String:sock.stype]; }
			sort:^NSComparisonResult(PSSockFiles *a, PSSockFiles *b) { int res = strcmp(a.stype, b.stype); return COMPARE_ORDER(res, 0); } summary:nil],
		[PSColumn psColumnWithName:@"F" fullname:@"Open Flags" align:NSTextAlignmentLeft width:40 tag:3003 style:ColumnStyleLowSpace
			data:^NSString*(PSSockFiles *sock) { return psFdFlagsString(sock.flags); }
			sort:^NSComparisonResult(PSSockFiles *a, PSSockFiles *b) { COMPARE(flags); } summary:nil],
		];
		sockColumns[ColumnModePorts] = @[
		[PSColumn psColumnWithName:@"Name" fullname:@"Port Name" align:NSTextAlignmentRight width:53 tag:5000 style:0
			data:^NSString*(PSSockPorts *sock) { return [NSString stringWithFormat:@"%X", sock.port]; }
			sort:^NSComparisonResult(PSSockPorts *a, PSSockPorts *b) { COMPARE(port); } summary:nil],
		[PSColumn psColumnWithName:@"Connection" fullname:@"Port Connection" align:NSTextAlignmentLeft width:220 tag:5002 style:ColumnStylePathTrunc
			data:^NSString*(PSSockPorts *sock) { return sock.description; }
			sort:^NSComparisonResult(PSSockPorts *a, PSSockPorts *b) { return [a.description caseInsensitiveCompare:b.description]; } summary:nil],
		[PSColumn psColumnWithName:@"R" fullname:@"Rights" align:NSTextAlignmentLeft width:30 tag:5003 style:0
			data:^NSString*(PSSockPorts *sock) { return psPortRightsString(sock.type); }
			sort:^NSComparisonResult(PSSockPorts *a, PSSockPorts *b) { COMPARE(type & MACH_PORT_TYPE_ALL_RIGHTS); } summary:nil],
		];
		sockColumns[ColumnModeModules] = @[
		[PSColumn psColumnWithName:@"Mapped module" fullname:@"Module Filename" align:NSTextAlignmentLeft width:220 tag:4000 style:ColumnStylePathTrunc | ColumnStyleTooLong
			data:^NSString*(PSSockModules *sock) { return sock.name; }
			sort:^NSComparisonResult(PSSockModules *a, PSSockModules *b) { return [a.bundle caseInsensitiveCompare:b.bundle]; } summary:nil],
		[PSColumn psColumnWithName:@"Address" fullname:@"Loaded Virtual Address" align:NSTextAlignmentRight width:90 tag:4001 style:ColumnStyleMonoFont | ColumnStyleLowSpace
			data:^NSString*(PSSockModules *sock) { return [NSString stringWithFormat:@"%llX", sock.addr]; }
			sort:^NSComparisonResult(PSSockModules *a, PSSockModules *b) { COMPARE(addr); } summary:nil],
		[PSColumn psColumnWithName:@"Size" fullname:@"Mapped size" align:NSTextAlignmentRight width:60 tag:4002 style:ColumnStyleSortDesc
			data:^NSString*(PSSockModules *sock) { return !sock.size ? @"-" : [NSByteCountFormatter stringFromByteCount:sock.size countStyle:NSByteCountFormatterCountStyleMemory]; }
			sort:^NSComparisonResult(PSSockModules *a, PSSockModules *b) { COMPARE(size); } summary:nil],
//		[PSColumn psColumnWithName:@"iNode" fullname:@"Device and iNode of Module on Disk" align:NSTextAlignmentLeft width:80 tag:4003 style:0
//			data:^NSString*(PSSockModules *sock) { return sock.dev || sock.ino ? [NSString stringWithFormat:@"%u,%u %u", sock.dev >> 24, sock.dev & ((1<<24)-1), sock.ino] : @"  cache"; }
//			sort:^NSComparisonResult(PSSockModules *a, PSSockModules *b) { return a.dev == b.dev ? a.ino - b.ino : a.dev - b.dev; } summary:nil],
		[PSColumn psColumnWithName:@"Ref" fullname:@"Reference count" align:NSTextAlignmentRight width:40 tag:4004 style:ColumnStyleSortDesc | ColumnStyleLowSpace
			data:^NSString*(PSSockModules *sock) { return [NSString stringWithFormat:@"%d", sock.ref]; }
			sort:^NSComparisonResult(PSSockModules *a, PSSockModules *b) { COMPARE(ref); } summary:nil],
		];
	});
	return sockColumns[mode];
}

+ (NSArray *)psGetTaskColumnsWithWidth:(NSUInteger)fullwidth mode:(column_mode_t)mode
{
	NSMutableArray *cols = [[PSColumn psGetTaskColumns:mode] mutableCopy];
	PSColumn *extendedcol = nil;
	NSUInteger width = fullwidth;
	for (PSColumn *col in cols) {
		if ((col.style & ColumnStyleLowSpace) && UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPhone && fullwidth < 400)
			col.width = 0;
		else
			col.width = col.minwidth;
		width -= col.width;
		if (col.style & ColumnStyleExtend)
			extendedcol = col;
	}
	if (extendedcol)
		extendedcol.width = extendedcol.minwidth + width;
	if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPhone)
		[cols filterUsingPredicate:[NSPredicate predicateWithBlock: ^BOOL(PSColumn *obj, NSDictionary *bind) {
			return obj.width != 0;
		}]];
	return cols;
}

+ (PSColumn *)psColumnWithTag:(NSInteger)tag
{
	NSArray *columns = [PSColumn psGetAllColumns];
	NSUInteger idx = [columns indexOfObjectPassingTest:^BOOL(PSColumn *col, NSUInteger idx, BOOL *stop) {
		return col.tag == tag;
	}];
	return idx == NSNotFound ? nil : (PSColumn *)columns[idx];
}

+ (PSColumn *)psTaskColumnWithTag:(NSInteger)tag forMode:(column_mode_t)mode
{
	NSArray *columns = [PSColumn psGetTaskColumns:mode];
	NSUInteger idx = [columns indexOfObjectPassingTest:^BOOL(PSColumn *col, NSUInteger idx, BOOL *stop) {
		return col.tag == tag;
	}];
	return idx == NSNotFound ? nil : (PSColumn *)columns[idx];
}

- (instancetype)initWithName:(NSString *)name fullname:(NSString *)fullname align:(NSTextAlignment)align width:(NSInteger)width tag:(NSInteger)tag
	style:(column_style_t)style data:(PSColumnData)data floatData:(PSColumnFloat)floatData sort:(NSComparator)sort summary:(PSColumnData)summary color:(PSColumnColor)color descr:(NSString *)descr
{
	if (self = [super init]) {
		self.name = name;
		self.fullname = fullname;
		self.descr = descr;
		self.align = align;
		self.minwidth = self.width = width;
		self.getData = data;
		self.getFloatData = floatData;
		self.getSummary = summary;
		self.getColor = color;
		self.sort = sort;
		self.tag = tag;
		self.style = style;
	}
	return self;
}

+ (instancetype)psColumnWithName:(NSString *)name fullname:(NSString *)fullname align:(NSTextAlignment)align width:(NSInteger)width tag:(NSInteger)tag
	style:(column_style_t)style data:(PSColumnData)data floatData:(PSColumnFloat)floatData sort:(NSComparator)sort summary:(PSColumnData)summary color:(PSColumnColor)color descr:(NSString *)descr
{
	return [[PSColumn alloc] initWithName:name fullname:fullname align:align width:width tag:tag style:style data:data floatData:floatData sort:sort summary:summary color:color descr:descr];
}

+ (instancetype)psColumnWithName:(NSString *)name fullname:(NSString *)fullname align:(NSTextAlignment)align width:(NSInteger)width tag:(NSInteger)tag
	style:(column_style_t)style data:(PSColumnData)data sort:(NSComparator)sort summary:(PSColumnData)summary color:(PSColumnColor)color descr:(NSString *)descr
{
	return [[PSColumn alloc] initWithName:name fullname:fullname align:align width:width tag:tag style:style data:data floatData:nil sort:sort summary:summary color:color descr:descr];
}

+ (instancetype)psColumnWithName:(NSString *)name fullname:(NSString *)fullname align:(NSTextAlignment)align width:(NSInteger)width tag:(NSInteger)tag
	style:(column_style_t)style data:(PSColumnData)data sort:(NSComparator)sort summary:(PSColumnData)summary descr:(NSString *)descr
{
	return [[PSColumn alloc] initWithName:name fullname:fullname align:align width:width tag:tag style:style data:data floatData:nil sort:sort summary:summary color:nil descr:descr];
}

+ (instancetype)psColumnWithName:(NSString *)name fullname:(NSString *)fullname align:(NSTextAlignment)align width:(NSInteger)width tag:(NSInteger)tag
	style:(column_style_t)style data:(PSColumnData)data floatData:(PSColumnFloat)floatData sort:(NSComparator)sort summary:(PSColumnData)summary descr:(NSString *)descr
{
	return [[PSColumn alloc] initWithName:name fullname:fullname align:align width:width tag:tag style:style data:data floatData:nil sort:sort summary:summary color:nil descr:descr];
}

+ (instancetype)psColumnWithName:(NSString *)name fullname:(NSString *)fullname align:(NSTextAlignment)align width:(NSInteger)width tag:(NSInteger)tag
	style:(column_style_t)style data:(PSColumnData)data sort:(NSComparator)sort summary:(PSColumnData)summary
{
	return [[PSColumn alloc] initWithName:name fullname:fullname align:align width:width tag:tag style:style data:data floatData:nil sort:sort summary:summary color:nil descr:nil];
}

@end
