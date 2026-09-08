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

struct state_record {
        __u32 time;
        __u32 value_size;
        __u64 addr;
        __u64 value;
};

int main(int argc, char **argv) {

        struct user_ring_buffer *rb = NULL;
        int input_fd                = -1;
        int fd                      = -1;
        int EXIT_STATUS             = 0;
        bool VERBOSE                = false;

        // get params
        if (argc != 3) {
                printf("Error: missing required input argument\n");
                EXIT_STATUS = 1;
                goto exitRoutine;
        }
        // get input file
        input_fd = open(argv[1], O_RDONLY);
        if (input_fd < 0) {
                printf("Cannot get fd for temporary record file %s\n", argv[2]);
                EXIT_STATUS = 1;
                goto exitRoutine;
        }
        // set verbosity
        VERBOSE = atoi(argv[2]) == 0 ? false : true;

        // get user ringbuf
        fd = bpf_obj_get("/sys/fs/bpf/state_pertbuf");
        if (fd < 0) {
                fprintf(stderr, "State perturbuf open failed: %s (errno %d)\n", strerror(errno),
                        errno);
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
        uint state_record_size = sizeof(struct state_record);
        struct state_record rec;
        while (read(input_fd, &rec, state_record_size) == state_record_size) {
                // inject
                void *p = user_ring_buffer__reserve(rb, state_record_size);
                if (!p) {
                        fprintf(stderr, "ring full or error %d\n", errno);
                        continue;
                }
                // copy data to the reserved memory area (todo: avoid 2nd copy)
                struct state_record *rec_p = p;
                rec_p->time                = rec.time;
                rec_p->value_size          = rec.value_size;
                rec_p->addr                = rec.addr;
                rec_p->value               = rec.value;
                user_ring_buffer__submit(rb, p);
                if (VERBOSE) {
                        printf("state record injected\n");
                }
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
