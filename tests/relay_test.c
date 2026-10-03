#define _GNU_SOURCE
/* Include the relay so this test exercises the worker's actual byte pump. */
#include "../guest/relay.c"

#include <pthread.h>
#include <time.h>

struct endpoint {
    int fd;
    unsigned char *send_data, *expect_data;
    size_t send_size, expect_size, sent, received;
    bool write_closed, read_closed;
};

struct pump_args {
    int client, remote;
};

static void fail(const char *message)
{
    fprintf(stderr, "relay test: %s (errno=%d)\n", message, errno);
    exit(1);
}

static void require_test(bool condition, const char *message)
{
    if (!condition)
        fail(message);
}

static void nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    require_test(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
                 "set nonblocking");
}

static void *run_pump(void *argument)
{
    struct pump_args *args = argument;
    pump_streams(args->client, args->remote);
    return NULL;
}

static int64_t monotonic_ms(void)
{
    struct timespec now;
    require_test(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "read clock");
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void transfer(struct endpoint *endpoint, short events)
{
    if ((events & (POLLIN | POLLHUP | POLLERR)) && !endpoint->read_closed) {
        unsigned char data[8192];
        ssize_t count = recv(endpoint->fd, data, sizeof(data), 0);
        if (count > 0) {
            require_test((size_t)count <= endpoint->expect_size - endpoint->received,
                         "unexpected response bytes");
            require_test(memcmp(data, endpoint->expect_data + endpoint->received,
                                (size_t)count) == 0, "response bytes changed");
            endpoint->received += (size_t)count;
        } else if (count == 0) {
            require_test(endpoint->received == endpoint->expect_size,
                         "response truncated before EOF");
            endpoint->read_closed = true;
        } else {
            require_test(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR,
                         "read response");
        }
    }
    if ((events & POLLOUT) && endpoint->sent < endpoint->send_size) {
        size_t left = endpoint->send_size - endpoint->sent;
        if (left > 8192)
            left = 8192;
        ssize_t count = send(endpoint->fd, endpoint->send_data + endpoint->sent,
                             left, MSG_NOSIGNAL);
        if (count > 0)
            endpoint->sent += (size_t)count;
        else
            require_test(count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                                       errno == EINTR), "send request");
    }
    if (endpoint->sent == endpoint->send_size && !endpoint->write_closed) {
        require_test(shutdown(endpoint->fd, SHUT_WR) == 0, "half-close sender");
        endpoint->write_closed = true;
    }
}

static void exercise(size_t client_size, size_t remote_size, bool wait_for_client_eof)
{
    int client[2], remote[2];
    require_test(socketpair(AF_UNIX, SOCK_STREAM, 0, client) == 0,
                 "create client socketpair");
    require_test(socketpair(AF_UNIX, SOCK_STREAM, 0, remote) == 0,
                 "create remote socketpair");
    for (size_t i = 0; i < 2; ++i) {
        nonblocking(client[i]);
        nonblocking(remote[i]);
    }
    int small_buffer = 4096;
    require_test(setsockopt(client[0], SOL_SOCKET, SO_SNDBUF, &small_buffer,
                            sizeof(small_buffer)) == 0, "limit client buffer");
    require_test(setsockopt(remote[0], SOL_SOCKET, SO_SNDBUF, &small_buffer,
                            sizeof(small_buffer)) == 0, "limit remote buffer");

    unsigned char *request = malloc(client_size ? client_size : 1);
    unsigned char *response = malloc(remote_size ? remote_size : 1);
    require_test(request && response, "allocate payloads");
    for (size_t i = 0; i < client_size; ++i)
        request[i] = (unsigned char)((i * 37u + 17u) & 255u);
    for (size_t i = 0; i < remote_size; ++i)
        response[i] = (unsigned char)((i * 53u + 231u) & 255u);
    struct endpoint ends[2] = {
        {.fd = client[0], .send_data = request, .expect_data = response,
         .send_size = client_size, .expect_size = remote_size},
        {.fd = remote[0], .send_data = response, .expect_data = request,
         .send_size = remote_size, .expect_size = client_size}
    };
    struct pump_args args = {.client = client[1], .remote = remote[1]};
    worker_stopping = 0;
    pthread_t worker;
    require_test(pthread_create(&worker, NULL, run_pump, &args) == 0,
                 "start pump");

    int64_t deadline = monotonic_ms() + 20000;
    while (!ends[0].read_closed || !ends[1].read_closed) {
        require_test(monotonic_ms() < deadline, "pump timed out");
        struct pollfd fds[2];
        for (size_t i = 0; i < 2; ++i) {
            bool may_send = !wait_for_client_eof || i == 0 || ends[1].read_closed;
            fds[i] = (struct pollfd){.fd = ends[i].fd,
                .events = (short)((!ends[i].read_closed ? POLLIN : 0) |
                                  (may_send && !ends[i].write_closed ? POLLOUT : 0))};
        }
        int result = poll(fds, 2, 100);
        if (result < 0 && errno == EINTR)
            continue;
        require_test(result >= 0, "poll endpoints");
        for (size_t i = 0; i < 2; ++i) {
            require_test(!(fds[i].revents & POLLNVAL), "endpoint invalid");
            if (!wait_for_client_eof || i == 0 || ends[1].read_closed)
                transfer(&ends[i], fds[i].revents);
            else if (fds[i].revents & (POLLIN | POLLHUP | POLLERR))
                transfer(&ends[i], (short)(fds[i].revents & ~POLLOUT));
        }
    }
    require_test(ends[0].write_closed && ends[1].write_closed,
                 "both senders half-closed");
    require_test(pthread_join(worker, NULL) == 0, "join pump");
    close(client[0]);
    close(client[1]);
    close(remote[0]);
    close(remote[1]);
    free(request);
    free(response);
}

int main(void)
{
    exercise(2u * 1024u * 1024u + 19u, 7u, true);
    exercise(1024u * 1024u + 3u, 2u * 1024u * 1024u + 5u, false);
    puts("relay tests passed: raw bytes, backpressure, bidirectional flow and half-close");
    return 0;
}
