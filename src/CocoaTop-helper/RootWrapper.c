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

// Comparator to sort kinfo_proc by PID
static int sort_procs_by_pid(const void *a, const void *b) {
    const struct kinfo_proc *p1 = a;
    const struct kinfo_proc *p2 = b;
    if (p1->kp_proc.p_pid < p2->kp_proc.p_pid) return -1;
    if (p1->kp_proc.p_pid > p2->kp_proc.p_pid) return 1;
    return 0;
}

// Fill the shared buffer with process info, return count or -1 on error
static ssize_t get_process_list(struct kinfo_proc *kp, size_t bufSize) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t size = bufSize;
    if (sysctl(mib, 4, kp, &size, NULL, 0) < 0) {
        return -1;
    }
    ssize_t count = size / sizeof(struct kinfo_proc);
    qsort(kp, count, sizeof(struct kinfo_proc), sort_procs_by_pid);
    return count;
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
    struct kinfo_proc *kp = mmap(NULL, bufSize,
                                 PROT_READ | PROT_WRITE,
                                 MAP_SHARED, shm_fd, 0);
    if (kp == MAP_FAILED) {
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
            ssize_t count = get_process_list(kp, bufSize);
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
    
    munmap(kp, bufSize);
    return EXIT_SUCCESS;
}
