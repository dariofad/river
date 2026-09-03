// go:build ignore
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

// todo: turn this program into a daemon to reduce latency

#define MAX_NOF_SIGNALS 16

struct model_record {
        __u32 time;
        __u32 filler;
        double values[MAX_NOF_SIGNALS];
};

int main(int argc, char **argv) {

        struct user_ring_buffer *rb = NULL;
        int input_fd                = -1;
        int fd                      = -1;
        int EXIT_STATUS             = 0;
        bool VERBOSE                = false;

        // get params
        if (argc != 4) {
                printf("Error: missing required input argument\n");
                EXIT_STATUS = 1;
                goto exitRoutine;
        }
        // get nof_signals
        int nof_signals = atoi(argv[1]);
        if (nof_signals < 0 || nof_signals > MAX_NOF_SIGNALS) {
                fprintf(stderr, "Invalid number of signals %d; expected 0-%d\n", nof_signals,
                        MAX_NOF_SIGNALS);
                EXIT_STATUS = 1;
                goto exitRoutine;
        }
        if (VERBOSE) {
                printf("Nof signals to be injected: %d\n", nof_signals);
        }
        // get input file
        input_fd = open(argv[2], O_RDONLY);
        if (input_fd < 0) {
                printf("Cannot get fd for temporary record file %s\n", argv[2]);
                EXIT_STATUS = 1;
                goto exitRoutine;
        }
        // set verbosity
        VERBOSE = atoi(argv[3]) == 0 ? false : true;
        // get user ringbuf
        fd = bpf_obj_get("/sys/fs/bpf/pertbuf");
        if (fd < 0) {
                fprintf(stderr, "Perturbuf open failed: %s (errno %d)\n", strerror(errno), errno);
                EXIT_STATUS = 1;
                goto exitRoutine;
        }
        rb = user_ring_buffer__new(fd, NULL);
        if (!rb) {
                perror("user_ring_buffer__new");
                EXIT_STATUS = 1;
                goto exitRoutine;
        }

        // read perturbations and inject
        uint record_size      = sizeof(struct model_record);
        uint record_real_size = sizeof(uint) + sizeof(uint) + nof_signals * sizeof(double);
        struct model_record rec;
        memset(&rec, 0, sizeof(rec));
        while (read(input_fd, &rec, record_real_size) == record_real_size) {
                // inject
                void *p = user_ring_buffer__reserve(rb, record_size);
                if (!p) {
                        fprintf(stderr, "ring full or error %d\n", errno);
                        continue;
                }
                // copy data to the reserved memory area (todo: avoid 2nd copy)
                struct model_record *rec_p = p;
                rec_p->time                = rec.time;
                rec_p->filler              = 0;
                memcpy(rec_p->values, &(rec.values), sizeof(double) * nof_signals);
                user_ring_buffer__submit(rb, p);
                if (VERBOSE) {
                        printf("record injected\n");
                }
                // zero signal memory
                rec.time = 0;
                memset(&rec, 0, sizeof(rec));
        }

exitRoutine:
        if (rb != NULL)
                user_ring_buffer__free(rb);
        if (fd >= 0)
                close(fd);
        if (input_fd >= 0)
                close(input_fd);
        return EXIT_STATUS;
}
