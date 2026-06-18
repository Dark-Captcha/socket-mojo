/*
 * C echo server using liburing. Mirrors the Mojo Ring-based server:
 * multishot accept + multishot recv + provided buffer ring. The
 * "speed of light" comparison for io_uring on the same kernel /
 * machine.
 *
 * Build:   cc -O2 -o server server.c -luring
 * Run:     ./server <port> <conns>
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <liburing.h>

#define BUF_SIZE 16384
#define BUF_COUNT 256
#define BGID 0

enum kind { K_ACCEPT, K_RECV, K_SEND };

struct op {
    enum kind kind;
    int fd;
};

static int closed_conns = 0;
static int target_conns = 0;

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: server <port> <conns>\n"); return 2; }
    int port = atoi(argv[1]);
    target_conns = atoi(argv[2]);

    int lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (lfd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }
    if (listen(lfd, 256) < 0) { perror("listen"); return 1; }

    struct io_uring ring;
    struct io_uring_params p = {0};
    if (io_uring_queue_init_params(target_conns * 4 + 256, &ring, &p) < 0) {
        perror("io_uring_queue_init"); return 1;
    }

    /* Provided buffer ring (multishot recv pool). */
    struct io_uring_buf_ring *br;
    int ret;
    br = io_uring_setup_buf_ring(&ring, BUF_COUNT, BGID, 0, &ret);
    if (!br) { fprintf(stderr, "buf_ring_setup: %s\n", strerror(-ret)); return 1; }
    char *backing = aligned_alloc(4096, (size_t)BUF_COUNT * BUF_SIZE);
    for (int i = 0; i < BUF_COUNT; i++) {
        io_uring_buf_ring_add(br, backing + (size_t)i * BUF_SIZE, BUF_SIZE,
                              i, io_uring_buf_ring_mask(BUF_COUNT), i);
    }
    io_uring_buf_ring_advance(br, BUF_COUNT);

    /* Arm multishot accept. */
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    static struct op accept_op = { .kind = K_ACCEPT, .fd = -1 };
    io_uring_prep_multishot_accept(sqe, lfd, NULL, NULL, 0);
    io_uring_sqe_set_data(sqe, &accept_op);

    while (closed_conns < target_conns) {
        ret = io_uring_submit_and_wait(&ring, 1);
        if (ret < 0 && ret != -EINTR) { perror("submit_and_wait"); break; }

        struct io_uring_cqe *cqe;
        unsigned head;
        unsigned reaped = 0;
        io_uring_for_each_cqe(&ring, head, cqe) {
            struct op *op = io_uring_cqe_get_data(cqe);
            if (op->kind == K_ACCEPT) {
                if (cqe->res > 0) {
                    /* Arm multishot recv on the new conn. */
                    struct op *r = malloc(sizeof(*r));
                    r->kind = K_RECV;
                    r->fd = cqe->res;
                    struct io_uring_sqe *s = io_uring_get_sqe(&ring);
                    io_uring_prep_recv_multishot(s, r->fd, NULL, 0, 0);
                    s->buf_group = BGID;
                    s->flags |= IOSQE_BUFFER_SELECT;
                    io_uring_sqe_set_data(s, r);
                }
            } else if (op->kind == K_RECV) {
                if (cqe->res > 0 && (cqe->flags & IORING_CQE_F_BUFFER)) {
                    int bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
                    char *buf = backing + (size_t)bid * BUF_SIZE;
                    /* Echo back. */
                    struct op *s_op = malloc(sizeof(*s_op));
                    s_op->kind = K_SEND;
                    s_op->fd = op->fd;
                    struct io_uring_sqe *s = io_uring_get_sqe(&ring);
                    io_uring_prep_send(s, op->fd, buf, cqe->res, MSG_NOSIGNAL);
                    io_uring_sqe_set_data(s, s_op);
                    /* Recycle the buffer immediately — we copy in send. */
                    io_uring_buf_ring_add(br, buf, BUF_SIZE, bid,
                                          io_uring_buf_ring_mask(BUF_COUNT), 0);
                    io_uring_buf_ring_advance(br, 1);
                } else if (cqe->res <= 0) {
                    closed_conns++;
                    if (!(cqe->flags & IORING_CQE_F_MORE)) {
                        free(op);
                    }
                }
            } else if (op->kind == K_SEND) {
                free(op);
            }
            reaped++;
        }
        io_uring_cq_advance(&ring, reaped);
    }

    io_uring_queue_exit(&ring);
    free(backing);
    close(lfd);
    return 0;
}
