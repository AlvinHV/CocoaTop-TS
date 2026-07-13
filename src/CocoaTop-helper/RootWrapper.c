#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <signal.h>
#include <mach/mach_time.h>

#include "../CocoaTop/src/ProcessSnapshot.h"

extern int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);

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

    snapshot->version = COCOATOP_PROCESS_SNAPSHOT_VERSION;
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

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <buf_size>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    char shm_name[50];
    int parent_pid = getppid();
    snprintf(shm_name, sizeof(shm_name), "/cocoatop_%d", parent_pid);
    
    int shm_fd = shm_open(shm_name, O_RDWR , S_IRUSR | S_IWUSR);
    if (shm_fd < 0) {
        perror("helper: shm_open");
        return 1;
    }

    size_t bufSize = (size_t)strtoull(argv[1], NULL, 10);
    
    // mmap the shared memory region
    struct CocoaTopProcessSnapshot *snapshot = mmap(NULL, bufSize,
                                                    PROT_READ | PROT_WRITE,
                                                    MAP_SHARED, shm_fd, 0);
    if (snapshot == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }
    
    char line[128];
    while (fgets(line, sizeof(line), stdin)) {
        // Strip newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        if (strcmp(line, "getprocs") == 0) {
            ssize_t count = get_process_list(snapshot, bufSize);
            if (count < 0) {
                fprintf(stderr, "Failed to get process list: %s\n", strerror(errno));
                printf("-1\n");
            } else {
                printf("%zd\n", count);
            }
            fflush(stdout);
        }
        else if (strcmp(line, "quit") == 0) {
            break;
        }
        else {
            fprintf(stderr, "Unknown command: %s\n", line);
            fflush(stderr);
        }
    }
    
    munmap(snapshot, bufSize);
    return EXIT_SUCCESS;
}
