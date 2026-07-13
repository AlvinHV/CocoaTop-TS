#ifndef ProcessSnapshot_h
#define ProcessSnapshot_h

#include <stdint.h>
#include <sys/sysctl.h>

#include "sys/proc_info.h"

struct CocoaTopProcessRecord {
	struct kinfo_proc kinfo;
	struct proc_taskinfo taskinfo;
	uint8_t taskinfo_valid;
};

struct CocoaTopProcessSnapshot {
	uint32_t count;
	uint64_t sample_time;
	struct CocoaTopProcessRecord records[];
};

struct CocoaTopThreadRecord {
	uint64_t thread_id;
	struct proc_threadinfo info;
};

struct CocoaTopThreadSnapshot {
	int32_t error;
	pid_t pid;
	uint32_t count;
	struct CocoaTopThreadRecord records[];
};

#endif /* ProcessSnapshot_h */
