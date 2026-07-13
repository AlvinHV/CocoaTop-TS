#ifndef ProcessSnapshot_h
#define ProcessSnapshot_h

#include <stdint.h>
#include <sys/sysctl.h>

#include "sys/proc_info.h"

#define COCOATOP_PROCESS_SNAPSHOT_VERSION 1

struct CocoaTopProcessRecord {
	struct kinfo_proc kinfo;
	struct proc_taskinfo taskinfo;
	uint8_t taskinfo_valid;
};

struct CocoaTopProcessSnapshot {
	uint32_t version;
	uint32_t count;
	uint64_t sample_time;
	struct CocoaTopProcessRecord records[];
};

#endif /* ProcessSnapshot_h */
