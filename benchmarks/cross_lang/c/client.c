/*
 * C echo client using liburing. Opens N connections, arms a
 * multishot recv on each, ping-pongs through one ring.
 *
 * Build: cc -O2 -o client client.c -luring
 * Run:   ./client <port> <conns> <rounds> <payload>
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <liburing.h>

#define BUF_SIZE 16384
#define BUF_COUNT 256
#define BGID 0

enum kind { K_RECV, K_SEND };
struct op { enum kind kind; int fd; };

static long long now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: client <port> <conns> <rounds> <payload>\n"); return 2; }
    int port = atoi(argv[1]);
    int conns = atoi(argv[2]);
    int rounds = atoi(argv[3]);
    int payload = atoi(argv[4]);

    struct io_uring ring;
    if (io_uring_queue_init(conns * 4 + 256, &ring, 0) < 0) {
        perror("io_uring_queue_init"); return 1;
    }

    /* Buffer ring. */
    int ret;
    struct io_uring_buf_ring *br = io_uring_setup_buf_ring(
        &ring, BUF_COUNT, BGID, 0, &ret);
    if (!br) { fprintf(stderr, "buf_ring_setup: %s\n", strerror(-ret)); return 1; }
    char *backing = aligned_alloc(4096, (size_t)BUF_COUNT * BUF_SIZE);
    for (int i = 0; i < BUF_COUNT; i++) {
        io_uring_buf_ring_add(br, backing + (size_t)i * BUF_SIZE, BUF_SIZE,
                              i, io_uring_buf_ring_mask(BUF_COUNT), i);
    }
    io_uring_buf_ring_advance(br, BUF_COUNT);

    /* Blocking-connect all sockets (cleaner than dance with OP_CONNECT). */
    int *fds = malloc(sizeof(int) * conns);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for (int i = 0; i < conns; i++) {
        fds[i] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fds[i] < 0) { perror("socket"); return 1; }
        if (connect(fds[i], (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("connect"); return 1;
        }
    }

    /* Arm multishot recv on every conn. */
    struct op *recv_ops = calloc(conns, sizeof(*recv_ops));
    char *msg = malloc(payload);
    memset(msg, 0x42, payload);
    for (int i = 0; i < conns; i++) {
        recv_ops[i].kind = K_RECV;
        recv_ops[i].fd = fds[i];
        struct io_uring_sqe *s = io_uring_get_sqe(&ring);
        io_uring_prep_recv_multishot(s, fds[i], NULL, 0, 0);
        s->buf_group = BGID;
        s->flags |= IOSQE_BUFFER_SELECT;
        io_uring_sqe_set_data(s, &recv_ops[i]);
    }
    /* Prime the first ping on every conn. */
    for (int i = 0; i < conns; i++) {
        struct op *s_op = malloc(sizeof(*s_op));
        s_op->kind = K_SEND;
        s_op->fd = fds[i];
        struct io_uring_sqe *s = io_uring_get_sqe(&ring);
        io_uring_prep_send(s, fds[i], msg, payload, MSG_NOSIGNAL);
        io_uring_sqe_set_data(s, s_op);
    }

    int target = rounds * conns;
    int pings = 0;
    long long t0 = now_ns();
    while (pings < target) {
        ret = io_uring_submit_and_wait(&ring, 1);
        if (ret < 0 && ret != -EINTR) { perror("submit_and_wait"); break; }
        struct io_uring_cqe *cqe;
        unsigned head;
        unsigned reaped = 0;
        io_uring_for_each_cqe(&ring, head, cqe) {
            struct op *op = io_uring_cqe_get_data(cqe);
            if (op->kind == K_RECV) {
                if (cqe->res > 0 && (cqe->flags & IORING_CQE_F_BUFFER)) {
                    int bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
                    char *buf = backing + (size_t)bid * BUF_SIZE;
                    pings++;
                    if (pings < target) {
                        struct op *s_op = malloc(sizeof(*s_op));
                        s_op->kind = K_SEND;
                        s_op->fd = op->fd;
                        struct io_uring_sqe *s = io_uring_get_sqe(&ring);
                        io_uring_prep_send(s, op->fd, msg, payload, MSG_NOSIGNAL);
                        io_uring_sqe_set_data(s, s_op);
                    }
                    io_uring_buf_ring_add(br, buf, BUF_SIZE, bid,
                                          io_uring_buf_ring_mask(BUF_COUNT), 0);
                    io_uring_buf_ring_advance(br, 1);
                }
            } else if (op->kind == K_SEND) {
                free(op);
            }
            reaped++;
        }
        io_uring_cq_advance(&ring, reaped);
    }
    long long t1 = now_ns();
    double secs = (double)(t1 - t0) / 1e9;
    double rate = (double)target / secs;
    printf("c-liburing: %d conns x %d rounds @ %d B → %d rt/s\n",
           conns, rounds, payload, (int)rate);

    for (int i = 0; i < conns; i++) close(fds[i]);
    free(fds);
    free(recv_ops);
    free(msg);
    free(backing);
    io_uring_queue_exit(&ring);
    return 0;
}
