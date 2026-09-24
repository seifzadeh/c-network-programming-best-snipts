#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <liburing.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_PORT 9000
#define RING_ENTRIES 1024
#define ACCEPT_DEPTH 32
#define MAX_CLIENTS 768
#define BUFFER_SIZE 4096

enum operation {
    OP_ACCEPT,
    OP_RECV,
    OP_SEND,
};

struct request {
    enum operation op;
    int fd;
    size_t length;
    size_t offset;
    socklen_t peer_len;
    struct sockaddr_storage peer;
    char buffer[BUFFER_SIZE];
};

static volatile sig_atomic_t stop_requested = 0;
static size_t active_clients = 0;

static void handle_signal(int signo)
{
    (void)signo;
    stop_requested = 1;
}

static void print_error(const char *what, int error)
{
    fprintf(stderr, "%s: %s\n", what, strerror(error));
}

static struct request *request_new(enum operation op, int fd)
{
    struct request *req = calloc(1, sizeof(*req));

    if (req == NULL) {
        perror("calloc");
        return NULL;
    }

    req->op = op;
    req->fd = fd;
    req->peer_len = sizeof(req->peer);
    return req;
}

static struct io_uring_sqe *get_sqe(struct io_uring *ring)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

    if (sqe != NULL) {
        return sqe;
    }

    int ret = io_uring_submit(ring);
    if (ret < 0) {
        print_error("io_uring_submit", -ret);
        return NULL;
    }

    return io_uring_get_sqe(ring);
}

static int queue_accept(struct io_uring *ring, int listen_fd)
{
    struct request *req = request_new(OP_ACCEPT, listen_fd);
    if (req == NULL) {
        return -1;
    }

    struct io_uring_sqe *sqe = get_sqe(ring);
    if (sqe == NULL) {
        free(req);
        return -1;
    }

    io_uring_prep_accept(
        sqe,
        listen_fd,
        (struct sockaddr *)&req->peer,
        &req->peer_len,
        SOCK_CLOEXEC);
    io_uring_sqe_set_data(sqe, req);
    return 0;
}

static int queue_recv(struct io_uring *ring, int client_fd)
{
    struct request *req = request_new(OP_RECV, client_fd);
    if (req == NULL) {
        return -1;
    }

    struct io_uring_sqe *sqe = get_sqe(ring);
    if (sqe == NULL) {
        free(req);
        return -1;
    }

    io_uring_prep_recv(sqe, client_fd, req->buffer, sizeof(req->buffer), 0);
    io_uring_sqe_set_data(sqe, req);
    return 0;
}

static int queue_send(struct io_uring *ring, struct request *req)
{
    struct io_uring_sqe *sqe = get_sqe(ring);
    if (sqe == NULL) {
        return -1;
    }

    req->op = OP_SEND;
    io_uring_prep_send(
        sqe,
        req->fd,
        req->buffer + req->offset,
        req->length - req->offset,
        MSG_NOSIGNAL);
    io_uring_sqe_set_data(sqe, req);
    return 0;
}

static void close_client(int fd)
{
    if (fd >= 0) {
        close(fd);
    }

    if (active_clients > 0) {
        --active_clients;
    }
}

static void log_peer(const struct request *req)
{
    const struct sockaddr_in *peer = (const struct sockaddr_in *)&req->peer;
    char address[INET_ADDRSTRLEN];

    if (req->peer.ss_family != AF_INET ||
        inet_ntop(AF_INET, &peer->sin_addr, address, sizeof(address)) == NULL) {
        printf("accepted fd=%d\n", req->fd);
        return;
    }

    printf("accepted %s:%u fd=%d\n",
           address,
           (unsigned)ntohs(peer->sin_port),
           req->fd);
}

static int create_listener(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(fd);
        return -1;
    }

    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, SOMAXCONN) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

static int parse_port(const char *text, uint16_t *port)
{
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);

    if (errno != 0 || end == text || *end != '\0' || value < 1 || value > 65535) {
        return -1;
    }

    *port = (uint16_t)value;
    return 0;
}

int main(int argc, char **argv)
{
    uint16_t port = DEFAULT_PORT;

    if (argc > 2) {
        fprintf(stderr, "usage: %s [port]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (argc == 2 && parse_port(argv[1], &port) != 0) {
        fprintf(stderr, "invalid port: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    struct sigaction sa = {
        .sa_handler = handle_signal,
    };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int listen_fd = create_listener(port);
    if (listen_fd < 0) {
        return EXIT_FAILURE;
    }

    struct io_uring ring;
    int ret = io_uring_queue_init(RING_ENTRIES, &ring, 0);
    if (ret < 0) {
        print_error("io_uring_queue_init", -ret);
        close(listen_fd);
        return EXIT_FAILURE;
    }

    for (unsigned i = 0; i < ACCEPT_DEPTH; ++i) {
        if (queue_accept(&ring, listen_fd) != 0) {
            fprintf(stderr, "failed to queue initial accept\n");
            io_uring_queue_exit(&ring);
            close(listen_fd);
            return EXIT_FAILURE;
        }
    }

    ret = io_uring_submit(&ring);
    if (ret < 0) {
        print_error("io_uring_submit", -ret);
        io_uring_queue_exit(&ring);
        close(listen_fd);
        return EXIT_FAILURE;
    }

    printf("io_uring echo server listening on 0.0.0.0:%u\n", (unsigned)port);

    while (!stop_requested) {
        struct io_uring_cqe *cqe = NULL;
        ret = io_uring_wait_cqe(&ring, &cqe);

        if (ret == -EINTR) {
            continue;
        }
        if (ret < 0) {
            print_error("io_uring_wait_cqe", -ret);
            break;
        }

        struct request *req = io_uring_cqe_get_data(cqe);
        int result = cqe->res;
        io_uring_cqe_seen(&ring, cqe);

        if (req == NULL) {
            fprintf(stderr, "completion without request context\n");
            continue;
        }

        switch (req->op) {
        case OP_ACCEPT: {
            int client_fd = result;

            if (!stop_requested && queue_accept(&ring, listen_fd) != 0) {
                fprintf(stderr, "failed to replenish accept queue\n");
                free(req);
                stop_requested = 1;
                break;
            }

            if (result < 0) {
                if (result != -ECANCELED && result != -EINTR) {
                    print_error("accept", -result);
                }
                free(req);
                break;
            }

            req->fd = client_fd;
            log_peer(req);

            if (active_clients >= MAX_CLIENTS) {
                fprintf(stderr, "client limit reached; closing fd=%d\n", client_fd);
                close(client_fd);
                free(req);
                break;
            }

            ++active_clients;
            if (queue_recv(&ring, client_fd) != 0) {
                close_client(client_fd);
                stop_requested = 1;
            }
            free(req);
            break;
        }

        case OP_RECV:
            if (result == 0) {
                close_client(req->fd);
                free(req);
                break;
            }

            if (result < 0) {
                if (result != -ECANCELED) {
                    print_error("recv", -result);
                }
                close_client(req->fd);
                free(req);
                break;
            }

            req->length = (size_t)result;
            req->offset = 0;

            if (queue_send(&ring, req) != 0) {
                close_client(req->fd);
                free(req);
                stop_requested = 1;
            }
            break;

        case OP_SEND:
            if (result <= 0) {
                if (result < 0 && result != -ECANCELED) {
                    print_error("send", -result);
                }
                close_client(req->fd);
                free(req);
                break;
            }

            req->offset += (size_t)result;

            if (req->offset < req->length) {
                if (queue_send(&ring, req) != 0) {
                    close_client(req->fd);
                    free(req);
                    stop_requested = 1;
                }
                break;
            }

            int client_fd = req->fd;
            free(req);

            if (queue_recv(&ring, client_fd) != 0) {
                close_client(client_fd);
                stop_requested = 1;
            }
            break;
        }

        ret = io_uring_submit(&ring);
        if (ret < 0) {
            print_error("io_uring_submit", -ret);
            break;
        }
    }

    printf("shutting down\n");
    io_uring_queue_exit(&ring);
    close(listen_fd);
    return EXIT_SUCCESS;
}
