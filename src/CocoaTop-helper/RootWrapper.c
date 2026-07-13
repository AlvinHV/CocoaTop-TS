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
#include <mach/mach_time.h>

#include "../CocoaTop/src/ProcessSnapshot.h"

extern int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);

// Private on older SDKs, but implemented by XNU alongside PROC_PIDLISTTHREADS.
#ifndef PROC_PIDLISTTHREADIDS
#define PROC_PIDLISTTHREADIDS 28
#endif

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
        record->taskinfo_valid = proc_pidinfo(processes[i].kp_proc.p_pid,
                                              PROC_PIDTASKINFO,
                                              0,
                                              &record->taskinfo,
                                              PROC_PIDTASKINFO_SIZE) == PROC_PIDTASKINFO_SIZE;
    }

    free(processes);
    snapshot->sample_time = sample_time;
    snapshot->count = (uint32_t)count;
    return (ssize_t)count;
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

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <process_buf_size> <thread_buf_size> <list_request_fd> <list_response_fd>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    char shm_name[50], thread_shm_name[50];
    int parent_pid = getppid();
    snprintf(shm_name, sizeof(shm_name), "/cocoatop_%d", parent_pid);
    snprintf(thread_shm_name, sizeof(thread_shm_name), "/cocoatop_threads_%d", parent_pid);
    
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

    size_t bufSize = (size_t)strtoull(argv[1], NULL, 10);
    size_t threadBufSize = (size_t)strtoull(argv[2], NULL, 10);
    int listRequestFD = (int)strtol(argv[3], NULL, 10);
    int listResponseFD = (int)strtol(argv[4], NULL, 10);
    
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
            if (sscanf(line, "getthreads %d", &pid) == 1) {
                ssize_t count = get_thread_list(thread_snapshot, threadBufSize, pid);
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
    close(shm_fd);
    close(thread_shm_fd);
    return EXIT_SUCCESS;
}
