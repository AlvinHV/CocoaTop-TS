#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <signal.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/task_info.h>
#include <mach/vm_prot.h>

#include "../CocoaTop/src/ProcessSnapshot.h"

extern int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
extern int proc_pid_rusage(int pid, int flavor, struct rusage_info_v2 *rusage);
extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task,
                                             mach_vm_address_t address,
                                             mach_vm_size_t size,
                                             mach_vm_address_t data,
                                             mach_vm_size_t *outsize);

// Private on older SDKs, but implemented by XNU alongside PROC_PIDLISTTHREADS.
#ifndef PROC_PIDLISTTHREADIDS
#define PROC_PIDLISTTHREADIDS 28
#endif

#ifndef PROC_PIDIPCTABLEINFO
#define PROC_PIDIPCTABLEINFO 32
#endif

struct CocoaTopIPCTableInfo {
    uint32_t table_size;
    uint32_t table_free;
};

// Comparator to sort kinfo_proc by PID
static int sort_procs_by_pid(const void *a, const void *b) {
    const struct kinfo_proc *p1 = a;
    const struct kinfo_proc *p2 = b;
    if (p1->kp_proc.p_pid < p2->kp_proc.p_pid) return -1;
    if (p1->kp_proc.p_pid > p2->kp_proc.p_pid) return 1;
    return 0;
}

static struct kinfo_proc *get_kinfo_procs(size_t *count) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    struct kinfo_proc *processes = NULL;

    for (unsigned int retry = 0; retry < 4; retry++) {
        size_t size = 0;
        if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0 || size == 0) {
            free(processes);
            return NULL;
        }

        size += 16 * retry * retry * sizeof(struct kinfo_proc);
        struct kinfo_proc *resized = realloc(processes, size);
        if (!resized) {
            free(processes);
            errno = ENOMEM;
            return NULL;
        }
        processes = resized;

        if (sysctl(mib, 4, processes, &size, NULL, 0) == 0) {
            *count = size / sizeof(struct kinfo_proc);
            return processes;
        }

        if (errno != ENOMEM) {
            break;
        }
    }

    free(processes);
    return NULL;
}

static int get_fd_counts(pid_t pid, uint32_t *file_count, uint32_t *socket_count) {
    int required = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (required <= 0 || required > INT_MAX / 2)
        return -1;

    int buffer_size = required * 2;
    struct proc_fdinfo *fdinfo = malloc((size_t)buffer_size);
    if (!fdinfo) {
        errno = ENOMEM;
        return -1;
    }

    int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo, buffer_size);
    if (bytes <= 0) {
        free(fdinfo);
        return -1;
    }

    uint32_t files = 0;
    uint32_t sockets = 0;
    size_t count = (size_t)bytes / sizeof(*fdinfo);
    for (size_t i = 0; i < count; i++) {
        switch (fdinfo[i].proc_fdtype) {
        case PROX_FDTYPE_SOCKET:
            sockets++;
            files++;
            break;
        case PROX_FDTYPE_VNODE:
        case PROX_FDTYPE_PIPE:
        case PROX_FDTYPE_KQUEUE:
            files++;
            break;
        }
    }

    free(fdinfo);
    *file_count = files;
    *socket_count = sockets;
    return 0;
}

static int get_process_metrics(pid_t pid, struct CocoaTopProcessMetrics *metrics) {
    memset(metrics, 0, sizeof(*metrics));
    int first_error = 0;

    if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &metrics->taskinfo,
                     sizeof(metrics->taskinfo)) == sizeof(metrics->taskinfo)) {
        metrics->taskinfo_valid = 1;
    } else {
        first_error = errno;
    }

    if (proc_pid_rusage(pid, RUSAGE_INFO_V2, &metrics->rusage) == 0) {
        metrics->rusage_valid = 1;
    } else if (!first_error) {
        first_error = errno;
    }

    struct CocoaTopIPCTableInfo ipc_info = {0};
    if (proc_pidinfo(pid, PROC_PIDIPCTABLEINFO, 0, &ipc_info,
                     sizeof(ipc_info)) == sizeof(ipc_info) &&
        ipc_info.table_size >= ipc_info.table_free) {
        metrics->port_count = ipc_info.table_size - ipc_info.table_free;
        metrics->port_count_valid = 1;
    } else if (!first_error) {
        first_error = errno;
    }

    if (get_fd_counts(pid, &metrics->file_count, &metrics->socket_count) == 0) {
        metrics->fd_count_valid = 1;
    } else if (!first_error) {
        first_error = errno;
    }

    if (metrics->taskinfo_valid || metrics->rusage_valid ||
        metrics->port_count_valid || metrics->fd_count_valid)
        return 0;

    errno = first_error ? first_error : ESRCH;
    return -1;
}

// Fill the shared buffer with the same kinfo + PROC_PIDTASKINFO data used by htop.
static ssize_t get_process_list(struct CocoaTopProcessSnapshot *snapshot, size_t bufSize) {
    if (bufSize < sizeof(*snapshot)) {
        errno = ENOSPC;
        return -1;
    }

    snapshot->count = 0;
    snapshot->sample_time = 0;

    size_t count = 0;
    struct kinfo_proc *processes = get_kinfo_procs(&count);
    if (!processes) {
        return -1;
    }

    size_t capacity = (bufSize - sizeof(*snapshot)) / sizeof(snapshot->records[0]);
    if (count > capacity) {
        free(processes);
        errno = ENOSPC;
        return -1;
    }

    qsort(processes, count, sizeof(*processes), sort_procs_by_pid);
    uint64_t sample_time = mach_absolute_time();

    for (size_t i = 0; i < count; i++) {
        struct CocoaTopProcessRecord *record = &snapshot->records[i];
        memset(record, 0, sizeof(*record));
        record->kinfo = processes[i];
        get_process_metrics(processes[i].kp_proc.p_pid, &record->metrics);
    }

    free(processes);
    snapshot->sample_time = sample_time;
    snapshot->count = (uint32_t)count;
    return (ssize_t)count;
}

static ssize_t get_process_detail(struct CocoaTopDetailSnapshot *snapshot, size_t bufSize, pid_t pid) {
    if (bufSize < sizeof(*snapshot)) {
        errno = ENOSPC;
        return -1;
    }

    snapshot->error = 0;
    snapshot->pid = pid;
    snapshot->module_count = 0;
    snapshot->sample_time = mach_absolute_time();
    if (get_process_metrics(pid, &snapshot->process) < 0) {
        snapshot->error = errno;
        return -1;
    }
    return 1;
}

static ssize_t get_thread_list(struct CocoaTopThreadSnapshot *snapshot, size_t bufSize, pid_t pid) {
    if (bufSize < sizeof(*snapshot)) {
        errno = ENOSPC;
        return -1;
    }

    snapshot->error = 0;
    snapshot->pid = pid;
    snapshot->count = 0;

    size_t capacity = (bufSize - sizeof(*snapshot)) / sizeof(snapshot->records[0]);
    if (capacity == 0 || capacity > INT_MAX / sizeof(uint64_t)) {
        snapshot->error = ENOSPC;
        errno = ENOSPC;
        return -1;
    }

    uint64_t *thread_ids = calloc(capacity, sizeof(*thread_ids));
    if (!thread_ids) {
        snapshot->error = ENOMEM;
        errno = ENOMEM;
        return -1;
    }

    int list_size = (int)(capacity * sizeof(*thread_ids));
    int list_bytes = proc_pidinfo(pid, PROC_PIDLISTTHREADIDS, 0, thread_ids, list_size);
    int thread_info_flavor = PROC_PIDTHREADID64INFO;
    if (list_bytes <= 0) {
        memset(thread_ids, 0, (size_t)list_size);
        list_bytes = proc_pidinfo(pid, PROC_PIDLISTTHREADS, 0, thread_ids, list_size);
        thread_info_flavor = PROC_PIDTHREADINFO;
    }
    if (list_bytes <= 0) {
        int error = errno ? errno : ESRCH;
        free(thread_ids);
        snapshot->error = error;
        errno = error;
        return -1;
    }

    size_t thread_count = (size_t)list_bytes / sizeof(*thread_ids);
    if (thread_count > capacity)
        thread_count = capacity;

    uint32_t count = 0;
    for (size_t i = 0; i < thread_count; i++) {
        if (!thread_ids[i])
            continue;

        struct proc_threadinfo info = {0};
        if (proc_pidinfo(pid, thread_info_flavor, thread_ids[i], &info, sizeof(info)) != sizeof(info))
            continue;

        struct CocoaTopThreadRecord *record = &snapshot->records[count++];
        record->thread_id = thread_ids[i];
        record->info = info;
        record->info.pth_name[sizeof(record->info.pth_name) - 1] = '\0';
    }

    free(thread_ids);

    snapshot->count = count;
    return count;
}

static int same_module(const struct CocoaTopModuleRecord *record,
                       const struct proc_regionwithpathinfo *region) {
    uint32_t record_dev = record->region.prp_vip.vip_vi.vi_stat.vst_dev;
    uint64_t record_ino = record->region.prp_vip.vip_vi.vi_stat.vst_ino;
    uint32_t region_dev = region->prp_vip.vip_vi.vi_stat.vst_dev;
    uint64_t region_ino = region->prp_vip.vip_vi.vi_stat.vst_ino;
    if (record_dev && record_ino && region_dev && region_ino)
        return record_dev == region_dev && record_ino == region_ino;
    return region->prp_vip.vip_path[0] &&
           strcmp(record->region.prp_vip.vip_path, region->prp_vip.vip_path) == 0;
}

struct CocoaTopDyldAllImageInfos32 {
    uint32_t version;
    uint32_t info_array_count;
    uint32_t info_array;
};

struct CocoaTopDyldAllImageInfos64 {
    uint32_t version;
    uint32_t info_array_count;
    uint64_t info_array;
};

struct CocoaTopDyldImageInfo32 {
    uint32_t image_load_address;
    uint32_t image_file_path;
    uint32_t image_file_mod_date;
};

struct CocoaTopDyldImageInfo64 {
    uint64_t image_load_address;
    uint64_t image_file_path;
    uint64_t image_file_mod_date;
};

typedef kern_return_t (*task_read_for_pid_fn)(mach_port_t, int, mach_port_t *);
typedef kern_return_t (*mach_port_kobject_fn)(ipc_space_read_t, mach_port_name_t,
                                               ipc_info_object_type_t *,
                                               mach_vm_address_t *);
typedef kern_return_t (*mach_port_kernel_object_fn)(ipc_space_read_t,
                                                     mach_port_name_t,
                                                     unsigned *, unsigned *);

static int get_task_read_port(pid_t pid, mach_port_t *task) {
    task_read_for_pid_fn task_read =
        (task_read_for_pid_fn)dlsym(RTLD_DEFAULT, "task_read_for_pid");
    if (!task_read) {
        errno = ENOTSUP;
        return -1;
    }
    *task = MACH_PORT_NULL;
    if (task_read(mach_task_self(), pid, task) != KERN_SUCCESS ||
        !MACH_PORT_VALID(*task)) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static natural_t get_port_object_type(mach_port_t task, mach_port_name_t name) {
    mach_port_kobject_fn port_kobject =
        (mach_port_kobject_fn)dlsym(RTLD_DEFAULT, "mach_port_kobject");
    if (port_kobject) {
        ipc_info_object_type_t object_type = IPC_OTYPE_NONE;
        mach_vm_address_t object_address = 0;
        if (port_kobject(task, name, &object_type, &object_address) == KERN_SUCCESS)
            return (natural_t)object_type;
    }

    mach_port_kernel_object_fn legacy_port_kobject =
        (mach_port_kernel_object_fn)dlsym(RTLD_DEFAULT, "mach_port_kernel_object");
    if (legacy_port_kobject) {
        unsigned object_type = 0;
        unsigned object_address = 0;
        if (legacy_port_kobject(task, name, &object_type,
                                &object_address) == KERN_SUCCESS)
            return (natural_t)object_type;
    }
    return 0;
}

static ssize_t get_port_list(struct CocoaTopPortSnapshot *snapshot,
                             size_t bufSize, pid_t pid, int include_details) {
    if (bufSize < sizeof(*snapshot)) {
        errno = ENOSPC;
        return -1;
    }

    snapshot->error = 0;
    snapshot->pid = pid;
    snapshot->count = 0;
    snapshot->data_size = sizeof(*snapshot);

    mach_port_t task = MACH_PORT_NULL;
    if (get_task_read_port(pid, &task) < 0) {
        snapshot->error = errno;
        return -1;
    }

    ipc_info_space_t space_info = {0};
    ipc_info_name_array_t table = NULL;
    mach_msg_type_number_t table_count = 0;
    ipc_info_tree_name_array_t tree = NULL;
    mach_msg_type_number_t tree_count = 0;
    kern_return_t result = mach_port_space_info(task, &space_info, &table,
                                                 &table_count, &tree,
                                                 &tree_count);
    if (result != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), task);
        snapshot->error = EPERM;
        errno = EPERM;
        return -1;
    }

    size_t records_size = (size_t)table_count * sizeof(snapshot->records[0]);
    size_t data_offset = sizeof(*snapshot) + records_size;
    if (table_count > UINT32_MAX || records_size > bufSize - sizeof(*snapshot)) {
        if (table)
            vm_deallocate(mach_task_self(), (vm_address_t)table,
                          table_count * sizeof(*table));
        if (tree)
            vm_deallocate(mach_task_self(), (vm_address_t)tree,
                          tree_count * sizeof(*tree));
        mach_port_deallocate(mach_task_self(), task);
        snapshot->error = ENOSPC;
        errno = ENOSPC;
        return -1;
    }

    for (mach_msg_type_number_t i = 0; i < table_count; i++) {
        struct CocoaTopPortRecord *record = &snapshot->records[i];
        memset(record, 0, sizeof(*record));
        record->info = table[i];
        if (include_details)
            record->object_type = get_port_object_type(task, table[i].iin_name);

        if (include_details && (table[i].iin_type & MACH_PORT_TYPE_PORT_SET)) {
            mach_port_name_array_t members = NULL;
            mach_msg_type_number_t member_count = 0;
            if (mach_port_get_set_status(task, table[i].iin_name, &members,
                                         &member_count) == KERN_SUCCESS) {
                char details[4096];
                size_t length = 0;
                for (mach_msg_type_number_t j = 0; j < member_count; j++) {
                    int written = snprintf(details + length,
                                           sizeof(details) - length,
                                           " %X", members[j]);
                    if (written < 0 || (size_t)written >= sizeof(details) - length)
                        break;
                    length += (size_t)written;
                }
                if (length && data_offset + length + 1 <= bufSize) {
                    memcpy((char *)snapshot + data_offset, details, length + 1);
                    record->detail_offset = (uint32_t)data_offset;
                    record->detail_length = (uint32_t)length;
                    data_offset += length + 1;
                }
            }
            if (members)
                vm_deallocate(mach_task_self(), (vm_address_t)members,
                              member_count * sizeof(*members));
        }
    }

    if (table)
        vm_deallocate(mach_task_self(), (vm_address_t)table,
                      table_count * sizeof(*table));
    if (tree)
        vm_deallocate(mach_task_self(), (vm_address_t)tree,
                      tree_count * sizeof(*tree));
    mach_port_deallocate(mach_task_self(), task);

    snapshot->count = table_count;
    snapshot->data_size = (uint32_t)data_offset;
    return table_count;
}

static int read_task_memory(mach_port_t task, mach_vm_address_t address,
                            void *buffer, mach_vm_size_t size) {
    mach_vm_size_t bytes_read = 0;
    kern_return_t result = mach_vm_read_overwrite(task, address, size,
                                                   (mach_vm_address_t)buffer,
                                                   &bytes_read);
    return result == KERN_SUCCESS && bytes_read == size ? 0 : -1;
}

static int read_task_path(mach_port_t task, mach_vm_address_t address,
                          char path[MAXPATHLEN]) {
    if (!address)
        return -1;

    memset(path, 0, MAXPATHLEN);
    size_t offset = 0;
    size_t page_size = (size_t)getpagesize();
    while (offset < MAXPATHLEN - 1) {
        size_t page_remaining = page_size - (size_t)((address + offset) % page_size);
        mach_vm_size_t chunk = (mach_vm_size_t)(MAXPATHLEN - 1 - offset);
        if (chunk > page_remaining)
            chunk = (mach_vm_size_t)page_remaining;
        if (chunk > 256)
            chunk = 256;

        while (chunk && read_task_memory(task, address + offset,
                                         path + offset, chunk) < 0)
            chunk /= 2;
        if (!chunk)
            return -1;
        if (memchr(path + offset, '\0', (size_t)chunk))
            return 0;
        offset += (size_t)chunk;
    }
    path[MAXPATHLEN - 1] = '\0';
    return 0;
}

static void fill_dyld_module(pid_t pid, mach_port_t task,
                             mach_vm_address_t address,
                             mach_vm_address_t path_address,
                             struct CocoaTopModuleRecord *record) {
    memset(record, 0, sizeof(*record));
    struct proc_regionwithpathinfo *region = &record->region;
    if (proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, address, region,
                     sizeof(*region)) != sizeof(*region)) {
        memset(region, 0, sizeof(*region));
    }
    region->prp_vip.vip_path[sizeof(region->prp_vip.vip_path) - 1] = '\0';

    // proc_pidinfo can report only the shared-cache file here. dyld's image
    // array has the authoritative per-image path, so prefer it for every image.
    int shared_cache_mapping = strstr(region->prp_vip.vip_path,
                                      "dyld_shared_cache") != NULL;
    char dyld_path[MAXPATHLEN];
    if (read_task_path(task, path_address, dyld_path) == 0 && dyld_path[0]) {
        strlcpy(region->prp_vip.vip_path, dyld_path,
                sizeof(region->prp_vip.vip_path));
    } else if (!region->prp_vip.vip_path[0]) {
        strlcpy(region->prp_vip.vip_path, "<Unknown>",
                sizeof(region->prp_vip.vip_path));
    }

    uint32_t dev = region->prp_vip.vip_vi.vi_stat.vst_dev;
    uint64_t ino = region->prp_vip.vip_vi.vi_stat.vst_ino;
    if (shared_cache_mapping || !dev || !ino) {
        if (shared_cache_mapping) {
            region->prp_vip.vip_vi.vi_stat.vst_dev = 0;
            region->prp_vip.vip_vi.vi_stat.vst_ino = 0;
        }
        region->prp_prinfo.pri_address = address;
        region->prp_prinfo.pri_size = 0;
    } else {
        // Sum the adjacent mappings belonging to this file, matching the
        // behavior of CocoaTop's original task-port module enumerator.
        uint64_t next = region->prp_prinfo.pri_address + region->prp_prinfo.pri_size;
        while (region->prp_prinfo.pri_size && next > region->prp_prinfo.pri_address) {
            struct proc_regionwithpathinfo following = {0};
            if (proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, next, &following,
                             sizeof(following)) != sizeof(following))
                break;
            if (following.prp_vip.vip_vi.vi_stat.vst_dev != dev ||
                following.prp_vip.vip_vi.vi_stat.vst_ino != ino)
                break;
            uint64_t following_size = following.prp_prinfo.pri_size;
            if (!following_size || UINT64_MAX - region->prp_prinfo.pri_size < following_size)
                break;
            region->prp_prinfo.pri_size += following_size;
            next = following.prp_prinfo.pri_address + following_size;
        }
    }
    record->executable = 1;
}

static ssize_t get_dyld_module_list(struct CocoaTopDetailSnapshot *snapshot,
                                    size_t bufSize, pid_t pid) {
    if (bufSize < sizeof(*snapshot)) {
        errno = ENOSPC;
        return -1;
    }

    mach_port_t task = MACH_PORT_NULL;
    if (get_task_read_port(pid, &task) < 0)
        return -1;

    task_dyld_info_data_t dyld_info = {0};
    mach_msg_type_number_t task_info_count = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info,
                  &task_info_count) != KERN_SUCCESS ||
        !dyld_info.all_image_info_addr) {
        mach_port_deallocate(mach_task_self(), task);
        errno = ENODATA;
        return -1;
    }

    uint32_t image_count = 0;
    mach_vm_address_t image_array = 0;
    size_t image_info_size = 0;
    if (dyld_info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_64) {
        struct CocoaTopDyldAllImageInfos64 infos = {0};
        if (read_task_memory(task, dyld_info.all_image_info_addr,
                             &infos, sizeof(infos)) < 0) {
            mach_port_deallocate(mach_task_self(), task);
            errno = EIO;
            return -1;
        }
        image_count = infos.info_array_count;
        image_array = infos.info_array;
        image_info_size = sizeof(struct CocoaTopDyldImageInfo64);
    } else {
        struct CocoaTopDyldAllImageInfos32 infos = {0};
        if (read_task_memory(task, dyld_info.all_image_info_addr,
                             &infos, sizeof(infos)) < 0) {
            mach_port_deallocate(mach_task_self(), task);
            errno = EIO;
            return -1;
        }
        image_count = infos.info_array_count;
        image_array = infos.info_array;
        image_info_size = sizeof(struct CocoaTopDyldImageInfo32);
    }

    size_t capacity = (bufSize - sizeof(*snapshot)) / sizeof(snapshot->modules[0]);
    if (!image_array || image_count > capacity ||
        image_count > SIZE_MAX / image_info_size) {
        mach_port_deallocate(mach_task_self(), task);
        errno = !image_array ? EAGAIN : ENOSPC;
        return -1;
    }

    size_t image_bytes = (size_t)image_count * image_info_size;
    void *images = malloc(image_bytes ? image_bytes : 1);
    if (!images) {
        mach_port_deallocate(mach_task_self(), task);
        errno = ENOMEM;
        return -1;
    }
    if (image_bytes && read_task_memory(task, image_array, images, image_bytes) < 0) {
        free(images);
        mach_port_deallocate(mach_task_self(), task);
        errno = EIO;
        return -1;
    }

    snapshot->error = 0;
    snapshot->pid = pid;
    snapshot->module_count = image_count;
    for (uint32_t i = 0; i < image_count; i++) {
        mach_vm_address_t address;
        mach_vm_address_t path_address;
        if (dyld_info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_64) {
            const struct CocoaTopDyldImageInfo64 *info =
                &((const struct CocoaTopDyldImageInfo64 *)images)[i];
            address = info->image_load_address;
            path_address = info->image_file_path;
        } else {
            const struct CocoaTopDyldImageInfo32 *info =
                &((const struct CocoaTopDyldImageInfo32 *)images)[i];
            address = info->image_load_address;
            path_address = info->image_file_path;
        }
        fill_dyld_module(pid, task, address, path_address, &snapshot->modules[i]);
    }

    free(images);
    mach_port_deallocate(mach_task_self(), task);
    return image_count;
}

static ssize_t get_region_module_list(struct CocoaTopDetailSnapshot *snapshot, size_t bufSize, pid_t pid) {
    if (bufSize < sizeof(*snapshot)) {
        errno = ENOSPC;
        return -1;
    }

    snapshot->error = 0;
    snapshot->pid = pid;
    snapshot->module_count = 0;

    size_t capacity = (bufSize - sizeof(*snapshot)) / sizeof(snapshot->modules[0]);
    if (capacity == 0) {
        snapshot->error = ENOSPC;
        errno = ENOSPC;
        return -1;
    }

    uint64_t address = 0;
    int saw_region = 0;
    for (;;) {
        struct proc_regionwithpathinfo region = {0};
        int bytes = proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, address,
                                 &region, sizeof(region));
        if (bytes != sizeof(region))
            break;

        saw_region = 1;
        region.prp_vip.vip_path[sizeof(region.prp_vip.vip_path) - 1] = '\0';
        uint64_t region_address = region.prp_prinfo.pri_address;
        uint64_t region_size = region.prp_prinfo.pri_size;
        uint64_t next_address = region_address + region_size;
        if (!region_size || next_address <= address || next_address < region_address)
            break;

        uint32_t dev = region.prp_vip.vip_vi.vi_stat.vst_dev;
        uint64_t ino = region.prp_vip.vip_vi.vi_stat.vst_ino;
        if (region.prp_vip.vip_path[0] || dev || ino) {
            size_t index = 0;
            while (index < snapshot->module_count &&
                   !same_module(&snapshot->modules[index], &region))
                index++;

            if (index == snapshot->module_count) {
                if (snapshot->module_count >= capacity) {
                    snapshot->error = ENOSPC;
                    errno = ENOSPC;
                    return -1;
                }
                snapshot->modules[index].region = region;
                snapshot->modules[index].executable = 0;
                snapshot->module_count++;
            } else {
                struct proc_regioninfo *combined = &snapshot->modules[index].region.prp_prinfo;
                if (region_address < combined->pri_address)
                    combined->pri_address = region_address;
                if (UINT64_MAX - combined->pri_size >= region_size)
                    combined->pri_size += region_size;
                if (region.prp_prinfo.pri_ref_count > combined->pri_ref_count)
                    combined->pri_ref_count = region.prp_prinfo.pri_ref_count;
            }

            if ((region.prp_prinfo.pri_protection | region.prp_prinfo.pri_max_protection) & VM_PROT_EXECUTE)
                snapshot->modules[index].executable = 1;
        }
        address = next_address;
    }

    if (!saw_region) {
        int error = errno ? errno : ESRCH;
        snapshot->error = error;
        errno = error;
        return -1;
    }

    uint32_t output_count = 0;
    for (uint32_t i = 0; i < snapshot->module_count; i++) {
        if (!snapshot->modules[i].executable)
            continue;
        if (output_count != i)
            snapshot->modules[output_count] = snapshot->modules[i];
        output_count++;
    }
    snapshot->module_count = output_count;
    return output_count;
}

static ssize_t get_module_list(struct CocoaTopDetailSnapshot *snapshot, size_t bufSize, pid_t pid) {
    ssize_t count = get_dyld_module_list(snapshot, bufSize, pid);
    if (count >= 0)
        return count;

    // Older kernels or processes that deny the read-only task right still get
    // the coarser file-backed executable-region list.
    return get_region_module_list(snapshot, bufSize, pid);
}

int main(int argc, char *argv[]) {
    if (argc < 7) {
        fprintf(stderr, "Usage: %s <process_buf_size> <thread_buf_size> <port_buf_size> <detail_buf_size> <list_request_fd> <list_response_fd>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    char shm_name[50], thread_shm_name[50], port_shm_name[50], detail_shm_name[50];
    int parent_pid = getppid();
    snprintf(shm_name, sizeof(shm_name), "/cocoatop_%d", parent_pid);
    snprintf(thread_shm_name, sizeof(thread_shm_name), "/cocoatop_threads_%d", parent_pid);
    snprintf(port_shm_name, sizeof(port_shm_name), "/cocoatop_ports_%d", parent_pid);
    snprintf(detail_shm_name, sizeof(detail_shm_name), "/cocoatop_details_%d", parent_pid);
    
    int shm_fd = shm_open(shm_name, O_RDWR , S_IRUSR | S_IWUSR);
    if (shm_fd < 0) {
        perror("helper: shm_open");
        return 1;
    }

    int thread_shm_fd = shm_open(thread_shm_name, O_RDWR, S_IRUSR | S_IWUSR);
    if (thread_shm_fd < 0) {
        perror("helper: thread shm_open");
        return EXIT_FAILURE;
    }

    int port_shm_fd = shm_open(port_shm_name, O_RDWR, S_IRUSR | S_IWUSR);
    if (port_shm_fd < 0) {
        perror("helper: port shm_open");
        return EXIT_FAILURE;
    }

    int detail_shm_fd = shm_open(detail_shm_name, O_RDWR, S_IRUSR | S_IWUSR);
    if (detail_shm_fd < 0) {
        perror("helper: detail shm_open");
        return EXIT_FAILURE;
    }

    size_t bufSize = (size_t)strtoull(argv[1], NULL, 10);
    size_t threadBufSize = (size_t)strtoull(argv[2], NULL, 10);
    size_t portBufSize = (size_t)strtoull(argv[3], NULL, 10);
    size_t detailBufSize = (size_t)strtoull(argv[4], NULL, 10);
    int listRequestFD = (int)strtol(argv[5], NULL, 10);
    int listResponseFD = (int)strtol(argv[6], NULL, 10);
    
    // mmap the shared memory region
    struct CocoaTopProcessSnapshot *snapshot = mmap(NULL, bufSize,
                                                    PROT_READ | PROT_WRITE,
                                                    MAP_SHARED, shm_fd, 0);
    if (snapshot == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    struct CocoaTopThreadSnapshot *thread_snapshot = mmap(NULL, threadBufSize,
                                                           PROT_READ | PROT_WRITE,
                                                           MAP_SHARED, thread_shm_fd, 0);
    if (thread_snapshot == MAP_FAILED) {
        perror("thread mmap");
        munmap(snapshot, bufSize);
        return EXIT_FAILURE;
    }

    struct CocoaTopPortSnapshot *port_snapshot = mmap(NULL, portBufSize,
                                                       PROT_READ | PROT_WRITE,
                                                       MAP_SHARED, port_shm_fd, 0);
    if (port_snapshot == MAP_FAILED) {
        perror("port mmap");
        munmap(snapshot, bufSize);
        munmap(thread_snapshot, threadBufSize);
        return EXIT_FAILURE;
    }

    struct CocoaTopDetailSnapshot *detail_snapshot = mmap(NULL, detailBufSize,
                                                           PROT_READ | PROT_WRITE,
                                                           MAP_SHARED, detail_shm_fd, 0);
    if (detail_snapshot == MAP_FAILED) {
        perror("detail mmap");
        munmap(snapshot, bufSize);
        munmap(thread_snapshot, threadBufSize);
        munmap(port_snapshot, portBufSize);
        return EXIT_FAILURE;
    }
    
    char line[128];
    for (;;) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(listRequestFD, &readfds);
        int maxfd = listRequestFD > STDIN_FILENO ? listRequestFD : STDIN_FILENO;
        if (select(maxfd + 1, &readfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (FD_ISSET(listRequestFD, &readfds)) {
            char request;
            if (read(listRequestFD, &request, 1) <= 0)
                break;
            ssize_t count = get_process_list(snapshot, bufSize);
            if (count < 0) {
                fprintf(stderr, "Failed to get process list: %s\n", strerror(errno));
                dprintf(listResponseFD, "-%d\n", errno);
            } else {
                dprintf(listResponseFD, "%zd\n", count);
            }
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (!fgets(line, sizeof(line), stdin))
                break;
            size_t len = strlen(line);
            if (len > 0 && line[len - 1] == '\n')
                line[len - 1] = '\0';

            pid_t pid;
            int sig;
            if (sscanf(line, "getproc %d", &pid) == 1) {
                ssize_t count = get_process_detail(detail_snapshot, detailBufSize, pid);
                printf("%zd\n", count >= 0 ? count : -(ssize_t)errno);
            } else if (sscanf(line, "getthreads %d", &pid) == 1) {
                ssize_t count = get_thread_list(thread_snapshot, threadBufSize, pid);
                printf("%zd\n", count >= 0 ? count : -(ssize_t)errno);
            } else if (sscanf(line, "getports %d", &pid) == 1) {
                ssize_t count = get_port_list(port_snapshot, portBufSize, pid, 1);
                printf("%zd\n", count >= 0 ? count : -(ssize_t)errno);
            } else if (sscanf(line, "getportrefs %d", &pid) == 1) {
                ssize_t count = get_port_list(port_snapshot, portBufSize, pid, 0);
                printf("%zd\n", count >= 0 ? count : -(ssize_t)errno);
            } else if (sscanf(line, "getmodules %d", &pid) == 1) {
                ssize_t count = get_module_list(detail_snapshot, detailBufSize, pid);
                printf("%zd\n", count >= 0 ? count : -(ssize_t)errno);
            } else if (sscanf(line, "kill %d %d", &pid, &sig) == 2) {
                int error = 0;
                if (pid <= 0 || sig <= 0 || sig >= NSIG)
                    error = EINVAL;
                else if (kill(pid, sig) < 0)
                    error = errno;
                printf("%d\n", error);
            } else if (strcmp(line, "quit") == 0) {
                break;
            } else {
                printf("-%d\n", EINVAL);
            }
            fflush(stdout);
        }
    }
    
    munmap(snapshot, bufSize);
    munmap(thread_snapshot, threadBufSize);
    munmap(port_snapshot, portBufSize);
    munmap(detail_snapshot, detailBufSize);
    close(shm_fd);
    close(thread_shm_fd);
    close(port_shm_fd);
    close(detail_shm_fd);
    return EXIT_SUCCESS;
}
