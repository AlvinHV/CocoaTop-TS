#ifndef ProcessSnapshot_h
#define ProcessSnapshot_h

#include <stdint.h>
#include <sys/sysctl.h>
#include <mach_debug/ipc_info.h>

#include "sys/proc_info.h"
#include "sys/resource.h"

struct CocoaTopProcessMetrics {
	struct proc_taskinfo taskinfo;
	struct rusage_info_v2 rusage;
	uint32_t port_count;
	uint32_t file_count;
	uint32_t socket_count;
	uint8_t taskinfo_valid;
	uint8_t rusage_valid;
	uint8_t port_count_valid;
	uint8_t fd_count_valid;
};

struct CocoaTopProcessRecord {
	struct kinfo_proc kinfo;
	struct CocoaTopProcessMetrics metrics;
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

struct CocoaTopPortRecord {
	ipc_info_name_t info;
	natural_t object_type;
	uint32_t detail_offset;
	uint32_t detail_length;
};

struct CocoaTopPortSnapshot {
	int32_t error;
	pid_t pid;
	uint32_t count;
	uint32_t data_size;
	struct CocoaTopPortRecord records[];
};

struct CocoaTopModuleRecord {
	struct proc_regionwithpathinfo region;
	uint8_t executable;
};

struct CocoaTopDetailSnapshot {
	int32_t error;
	pid_t pid;
	uint32_t module_count;
	uint64_t sample_time;
	struct CocoaTopProcessMetrics process;
	struct CocoaTopModuleRecord modules[];
};

#endif /* ProcessSnapshot_h */
