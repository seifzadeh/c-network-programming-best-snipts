# io_uring TCP networking example

A small, self-contained Linux networking example that uses **io_uring** through
`liburing`.

The example intentionally uses the basic single-shot networking operations
instead of newer multishot or zero-copy features, so the control flow remains
easy to study:

- server: `accept -> recv -> send -> recv ...`
- client: `connect -> send -> recv`

The server is a concurrent TCP echo server. Each active connection has one
in-flight request at a time, while several accept requests are kept queued so
new clients can arrive without serializing the accept path.

## Directory layout

```text
io_uring-networking/
├── Makefile
├── README.md
├── client/
│   └── client.c
└── server/
    └── server.c
```

## How io_uring maps to networking

Traditional synchronous socket code enters the kernel for calls such as
`accept()`, `recv()`, and `send()` and may block the calling thread.

With io_uring, the application prepares **submission queue entries (SQEs)** and
submits them to the kernel. Completion results arrive as **completion queue
entries (CQEs)**. A CQE carries the result directly in `cqe->res`; failures are
negative errno values such as `-ECONNRESET`.

This example stores a pointer to a small request structure in the SQE
`user_data`. When a completion arrives, the server can identify whether it was
an accept, receive, or send operation and queue the next operation for that
connection.

Important details demonstrated by the server:

1. Multiple accepts are kept in flight.
2. A connection owns only one recv/send operation at a time.
3. Partial sends are handled correctly.
4. `recv == 0` is treated as an orderly peer shutdown.
5. CQE errors are decoded from negative errno values.
6. The server limits active clients so the number of in-flight requests stays
   below the ring size.
7. Accepted sockets use `SOCK_CLOEXEC`; the socket I/O itself is driven by io_uring.

## Requirements

You need Linux, a C compiler, and the `liburing` development package.

On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install build-essential pkg-config liburing-dev
```

A modern Linux kernel is recommended. io_uring has evolved across kernel
releases, so production software should check the features it depends on.
This example uses long-established basic operations only:
`IORING_OP_ACCEPT`, `IORING_OP_CONNECT`, `IORING_OP_RECV`, and
`IORING_OP_SEND`.

## Build

From this directory:

```bash
make
```

The binaries are written to:

```text
bin/uring-server
bin/uring-client
```

To remove generated files:

```bash
make clean
```

## Run

Start the server:

```bash
./bin/uring-server
```

or choose another port:

```bash
./bin/uring-server 8080
```

In another terminal, run the client:

```bash
./bin/uring-client
```

The defaults are `127.0.0.1:9000` and the message:

```text
hello from io_uring client
```

You can provide host, port, and a message:

```bash
./bin/uring-client 127.0.0.1 9000 "hello io_uring"
```

You can also use the convenience Make targets:

```bash
make run-server
make run-client
```

## Expected output

Server:

```text
io_uring echo server listening on 0.0.0.0:9000
accepted 127.0.0.1:54321 fd=7
```

Client:

```text
server echoed 14 byte(s): hello io_uring
```

## Server design

The ring is created with 1024 entries. The program initially queues 32 accept
requests. After each accept completion it immediately replenishes the accept
queue.

For an accepted client, the state machine is:

```text
ACCEPT completion
      |
      v
    RECV
      |
      v
    SEND  -- partial send --> SEND
      |
      v
    RECV
```

The request object is attached to the SQE with
`io_uring_sqe_set_data()`. It remains available when the CQE is consumed with
`io_uring_cqe_get_data()`.

This is intentionally a compact teaching example. A production server may add
multishot accept/recv, provided buffers, registered files, fixed buffers,
timeouts, cancellation, connection objects, protocol framing, backpressure,
and zero-copy techniques where the target kernel and workload justify them.

## Why use liburing?

The io_uring kernel interface can be used directly with system calls and shared
ring mappings, but `liburing` provides small helpers for queue setup, SQE
preparation, submission, and CQE handling. It keeps this example focused on the
networking state machine instead of ring setup internals.

## References

Primary references:

- liburing source, examples, and documentation:
  https://github.com/axboe/liburing
- Jens Axboe, "Efficient IO with io_uring":
  https://kernel.dk/io_uring.pdf
- `io_uring_prep_accept(3)`:
  https://man7.org/linux/man-pages/man3/io_uring_prep_accept.3.html
- `io_uring_prep_connect(3)`:
  https://man7.org/linux/man-pages/man3/io_uring_prep_connect.3.html
- `io_uring_prep_recv(3)`:
  https://man7.org/linux/man-pages/man3/io_uring_prep_recv.3.html
- `io_uring_prep_send(3)`:
  https://man7.org/linux/man-pages/man3/io_uring_prep_send.3.html
- Jens Axboe, "io_uring and networking in 2023":
  https://github.com/axboe/liburing/wiki/io_uring-and-networking-in-2023
- Linux kernel zero-copy receive documentation (advanced):
  https://docs.kernel.org/networking/iou-zcrx.html

For newer high-performance networking features, also see the current kernel
and liburing documentation for multishot operations, provided buffer rings,
registered files, zero-copy send, and zero-copy receive.

## Notes for experiments

Useful next steps when benchmarking or extending this code:

```bash
strace -f ./bin/uring-server
perf stat ./bin/uring-server
```

For load testing, use a tool that matches the protocol and concurrency pattern
you want to measure. Compare against an equivalent `epoll` implementation
before drawing performance conclusions: io_uring reduces and reorganizes
kernel/userspace interaction, but the best design depends on workload,
buffering, batching, kernel version, and socket behavior.
