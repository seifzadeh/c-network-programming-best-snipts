#define _GNU_SOURCE

#include <errno.h>
#include <liburing.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT "9000"
#define DEFAULT_MESSAGE "hello from io_uring client\n"
#define RING_ENTRIES 8

static void print_error(const char *what, int error)
{
    fprintf(stderr, "%s: %s\n", what, strerror(error));
}

static struct io_uring_sqe *get_sqe(struct io_uring *ring)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

    if (sqe == NULL) {
        fprintf(stderr, "submission queue is full\n");
    }

    return sqe;
}

static int submit_and_wait(struct io_uring *ring)
{
    int ret = io_uring_submit(ring);
    if (ret < 0) {
        print_error("io_uring_submit", -ret);
        return ret;
    }

    struct io_uring_cqe *cqe = NULL;
    ret = io_uring_wait_cqe(ring, &cqe);
    if (ret < 0) {
        print_error("io_uring_wait_cqe", -ret);
        return ret;
    }

    int result = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    return result;
}

static int connect_with_uring(struct io_uring *ring,
                              int fd,
                              const struct sockaddr *address,
                              socklen_t address_len)
{
    struct io_uring_sqe *sqe = get_sqe(ring);
    if (sqe == NULL) {
        return -ENOSPC;
    }

    io_uring_prep_connect(sqe, fd, address, address_len);
    return submit_and_wait(ring);
}

static int send_all(struct io_uring *ring, int fd, const char *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        struct io_uring_sqe *sqe = get_sqe(ring);
        if (sqe == NULL) {
            return -ENOSPC;
        }

        io_uring_prep_send(
            sqe,
            fd,
            data + sent,
            length - sent,
            MSG_NOSIGNAL);

        int result = submit_and_wait(ring);
        if (result < 0) {
            return result;
        }
        if (result == 0) {
            return -EPIPE;
        }

        sent += (size_t)result;
    }

    return 0;
}

static int recv_exact(struct io_uring *ring, int fd, char *buffer, size_t length)
{
    size_t received = 0;

    while (received < length) {
        struct io_uring_sqe *sqe = get_sqe(ring);
        if (sqe == NULL) {
            return -ENOSPC;
        }

        io_uring_prep_recv(sqe, fd, buffer + received, length - received, 0);

        int result = submit_and_wait(ring);
        if (result < 0) {
            return result;
        }
        if (result == 0) {
            break;
        }

        received += (size_t)result;
    }

    return (int)received;
}

int main(int argc, char **argv)
{
    if (argc > 4) {
        fprintf(stderr, "usage: %s [host] [port] [message]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *host = argc > 1 ? argv[1] : DEFAULT_HOST;
    const char *port = argc > 2 ? argv[2] : DEFAULT_PORT;
    const char *message = argc > 3 ? argv[3] : DEFAULT_MESSAGE;
    size_t message_len = strlen(message);

    if (message_len == 0) {
        fprintf(stderr, "message must not be empty\n");
        return EXIT_FAILURE;
    }

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *addresses = NULL;

    int gai_ret = getaddrinfo(host, port, &hints, &addresses);
    if (gai_ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai_ret));
        return EXIT_FAILURE;
    }

    struct io_uring ring;
    int ret = io_uring_queue_init(RING_ENTRIES, &ring, 0);
    if (ret < 0) {
        print_error("io_uring_queue_init", -ret);
        freeaddrinfo(addresses);
        return EXIT_FAILURE;
    }

    int fd = -1;
    int connect_error = -ECONNREFUSED;

    for (const struct addrinfo *it = addresses; it != NULL; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype | SOCK_CLOEXEC, it->ai_protocol);
        if (fd < 0) {
            continue;
        }

        ret = connect_with_uring(&ring, fd, it->ai_addr, (socklen_t)it->ai_addrlen);
        if (ret == 0) {
            connect_error = 0;
            break;
        }

        connect_error = ret;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(addresses);

    if (fd < 0) {
        print_error("connect", -connect_error);
        io_uring_queue_exit(&ring);
        return EXIT_FAILURE;
    }

    ret = send_all(&ring, fd, message, message_len);
    if (ret < 0) {
        print_error("send", -ret);
        close(fd);
        io_uring_queue_exit(&ring);
        return EXIT_FAILURE;
    }

    char *response = calloc(message_len + 1, 1);
    if (response == NULL) {
        perror("calloc");
        close(fd);
        io_uring_queue_exit(&ring);
        return EXIT_FAILURE;
    }

    ret = recv_exact(&ring, fd, response, message_len);
    if (ret < 0) {
        print_error("recv", -ret);
        free(response);
        close(fd);
        io_uring_queue_exit(&ring);
        return EXIT_FAILURE;
    }

    printf("server echoed %d byte(s): ", ret);
    fwrite(response, 1, (size_t)ret, stdout);
    if (ret == 0 || response[ret - 1] != '\n') {
        putchar('\n');
    }

    free(response);
    close(fd);
    io_uring_queue_exit(&ring);
    return EXIT_SUCCESS;
}
