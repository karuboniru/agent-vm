#define _GNU_SOURCE
#include "relay.h"
#include "agent_vm/protocol.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/vm_sockets.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_WORKERS 64u
#define BUFFER_SIZE (64u * 1024u)

static volatile sig_atomic_t worker_stopping;

static void stop_worker(int signal_number)
{
    (void)signal_number;
    worker_stopping = 1;
}

/* The guest supervisor may have control sockets and executable/spec FDs open.
 * None of those descriptors belong in a socket relay. */
static void close_inherited_fds(int keep)
{
#ifdef SYS_close_range
    int failed = 0;
    if (keep > 3 && syscall(SYS_close_range, 3u, (unsigned int)keep - 1u, 0u) < 0)
        failed = 1;
    unsigned int first = keep >= 3 ? (unsigned int)keep + 1u : 3u;
    if (syscall(SYS_close_range, first, UINT_MAX, 0u) < 0)
        failed = 1;
    if (!failed)
        return;
#endif
    DIR *directory = opendir("/proc/self/fd");
    if (directory) {
        struct dirent *entry;
        int directory_fd = dirfd(directory);
        while ((entry = readdir(directory))) {
            char *end;
            long fd = strtol(entry->d_name, &end, 10);
            if (*end == '\0' && fd >= 3 && fd <= INT_MAX &&
                fd != keep && fd != directory_fd)
                close((int)fd);
        }
        closedir(directory);
        return;
    }
    struct rlimit limit;
    rlim_t maximum = 1048576;
    if (getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY)
        maximum = limit.rlim_cur;
    if (maximum > INT_MAX)
        maximum = INT_MAX;
    for (int fd = 3; (rlim_t)fd < maximum; ++fd)
        if (fd != keep)
            close(fd);
}

static int report_ready(int fd, int error)
{
    const unsigned char *data = (const unsigned char *)&error;
    size_t left = sizeof(error);
    while (left) {
        ssize_t written = write(fd, data, left);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return -1;
        data += written;
        left -= (size_t)written;
    }
    return 0;
}

struct stream_buffer {
    unsigned char data[BUFFER_SIZE + sizeof(uint32_t)];
    size_t begin, end;
};

static void compact_buffer(struct stream_buffer *buffer)
{
    if (buffer->begin && buffer->end == sizeof(buffer->data)) {
        memmove(buffer->data, buffer->data + buffer->begin,
                buffer->end - buffer->begin);
        buffer->end -= buffer->begin;
        buffer->begin = 0;
    }
}

static int send_bytes(int fd, struct stream_buffer *buffer)
{
    if (buffer->begin == buffer->end)
        return 0;
    ssize_t count = send(fd, buffer->data + buffer->begin,
                         buffer->end - buffer->begin, MSG_NOSIGNAL);
    if (count > 0) {
        buffer->begin += (size_t)count;
        if (buffer->begin == buffer->end)
            buffer->begin = buffer->end = 0;
    } else if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        return -1;
    }
    return 0;
}

struct frame_reader {
    unsigned char header[sizeof(uint32_t)];
    size_t header_used;
    uint32_t remaining;
    bool eof, acknowledgement;
};

static int receive_frame(int fd, struct stream_buffer *output, struct frame_reader *reader)
{
    if (!reader->remaining) {
        ssize_t count = read(fd, reader->header + reader->header_used,
                             sizeof(reader->header) - reader->header_used);
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            return 0;
        if (count <= 0)
            return -1;
        reader->header_used += (size_t)count;
        if (reader->header_used < sizeof(reader->header))
            return 0;
        uint32_t length;
        memcpy(&length, reader->header, sizeof(length));
        length = ntohl(length);
        reader->header_used = 0;
        if (length == AVM_STREAM_EOF && !reader->eof) {
            reader->eof = true;
            return 0;
        }
        if (length == AVM_STREAM_ACK && reader->eof && !reader->acknowledgement) {
            reader->acknowledgement = true;
            return 0;
        }
        if (reader->eof || !length || length > AVM_STREAM_MAX) {
            errno = EPROTO;
            return -1;
        }
        reader->remaining = length;
    }
    size_t space = sizeof(output->data) - output->end;
    if (space > reader->remaining)
        space = reader->remaining;
    if (!space)
        return 0;
    ssize_t count = read(fd, output->data + output->end, space);
    if (count > 0) {
        output->end += (size_t)count;
        reader->remaining -= (uint32_t)count;
    } else if (count == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
        return -1;
    }
    return 0;
}

static int receive_client(int client, struct stream_buffer *packet, bool *eof)
{
    ssize_t count = read(client, packet->data + sizeof(uint32_t), BUFFER_SIZE);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return 0;
    if (count < 0)
        return -1;
    uint32_t length = htonl((uint32_t)count);
    memcpy(packet->data, &length, sizeof(length));
    packet->begin = 0;
    packet->end = sizeof(length) + (size_t)count;
    if (!count)
        *eof = true;
    return 0;
}

static void pump_streams(int client, int remote)
{
    struct stream_buffer to_remote = {0};
    struct stream_buffer to_client = {0};
    struct frame_reader incoming = {0};
    bool client_eof = false, eof_sent = false, client_shutdown = false;
    while (!worker_stopping) {
        compact_buffer(&to_client);
        if (incoming.eof && to_client.begin == to_client.end && !client_shutdown) {
            if (shutdown(client, SHUT_WR) < 0 && errno != ENOTCONN)
                return;
            client_shutdown = true;
        }
        /* libkrun 1.19 drops unread data on transport HUP. EOF is therefore a
         * protocol frame, not shutdown(remote). The broker acknowledges that
         * it consumed our final request and keeps its side open until we have
         * consumed its response and close this connection. */
        if (eof_sent && incoming.acknowledgement && client_shutdown)
            return;

        struct pollfd sockets[2] = {
            {.fd = client}, {.fd = remote}
        };
        if (!client_eof && to_remote.begin == to_remote.end)
            sockets[0].events |= POLLIN;
        if (to_client.begin != to_client.end)
            sockets[0].events |= POLLOUT;
        if (!incoming.acknowledgement &&
            (!incoming.remaining || to_client.end < sizeof(to_client.data)))
            sockets[1].events |= POLLIN;
        if (to_remote.begin != to_remote.end)
            sockets[1].events |= POLLOUT;

        /* Do not poll an entirely drained half-closed endpoint: POLLHUP is
         * otherwise returned continuously while waiting for the other side. */
        if (!sockets[0].events)
            sockets[0].fd = -1;
        if (!sockets[1].events)
            sockets[1].fd = -1;
        int result = poll(sockets, 2, -1);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            return;
        }
        if ((sockets[0].revents | sockets[1].revents) & POLLNVAL)
            return;
        if ((sockets[0].revents & POLLOUT) && send_bytes(client, &to_client) < 0)
            return;
        if (sockets[1].revents & POLLOUT) {
            if (send_bytes(remote, &to_remote) < 0)
                return;
            if (client_eof && to_remote.begin == to_remote.end)
                eof_sent = true;
        }
        if (!client_eof && to_remote.begin == to_remote.end &&
            (sockets[0].revents & (POLLIN | POLLHUP | POLLERR)) &&
            receive_client(client, &to_remote, &client_eof) < 0)
            return;
        if ((sockets[1].revents & (POLLIN | POLLHUP | POLLERR)) &&
            receive_frame(remote, &to_client, &incoming) < 0)
            return;
        if (incoming.acknowledgement && !eof_sent)
            return; /* An ACK before our EOF is a malformed broker response. */
        if ((sockets[0].revents & (POLLHUP | POLLERR)) &&
            to_client.begin != to_client.end && send_bytes(client, &to_client) < 0)
            return;
    }
}

static void run_worker(int client, pid_t parent, uint32_t port)
{
    struct sigaction action = {.sa_handler = stop_worker};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) < 0 ||
        sigaction(SIGINT, &action, NULL) < 0 ||
        sigaction(SIGHUP, &action, NULL) < 0 ||
        sigaction(SIGQUIT, &action, NULL) < 0 ||
        prctl(PR_SET_PDEATHSIG, SIGTERM) < 0 || getppid() != parent)
        _exit(1);
    worker_stopping = 0;
    sigset_t empty;
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, NULL) < 0)
        _exit(1);

    int remote = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (remote < 0)
        _exit(1);
    struct sockaddr_vm address = {
        .svm_family = AF_VSOCK,
        .svm_port = port,
        .svm_cid = VMADDR_CID_HOST
    };
    if (connect(remote, (const struct sockaddr *)&address, sizeof(address)) < 0) {
        if (errno != EINPROGRESS)
            _exit(1);
        struct pollfd pending = {.fd = remote, .events = POLLOUT};
        while (!worker_stopping) {
            int result = poll(&pending, 1, 30000);
            if (result < 0 && errno == EINTR)
                continue;
            if (result <= 0)
                _exit(1);
            int error = 0;
            socklen_t size = sizeof(error);
            if (getsockopt(remote, SOL_SOCKET, SO_ERROR, &error, &size) < 0 || error)
                _exit(1);
            break;
        }
    }
    if (!worker_stopping)
        pump_streams(client, remote);
    close(remote);
    close(client);
    _exit(0);
}

static void reap_workers(pid_t workers[MAX_WORKERS], size_t *count)
{
    for (size_t i = 0; i < *count;) {
        pid_t result = waitpid(workers[i], NULL, WNOHANG);
        if (result == workers[i] || (result < 0 && errno == ECHILD))
            workers[i] = workers[--*count];
        else
            ++i;
    }
}

static int socket_parent(const char *path, bool create, uid_t uid, gid_t gid)
{
    if (!path || path[0] != '/' || !path[1]) {
        errno = EINVAL;
        return -1;
    }
    char copy[sizeof(((struct sockaddr_un *)0)->sun_path)];
    if (strlen(path) >= sizeof(copy)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(copy, path, strlen(path) + 1);
    /* Validate all components before creating any directory. */
    for (const char *part = path + 1;;) {
        const char *end = strchr(part, '/');
        size_t length = end ? (size_t)(end - part) : strlen(part);
        if (!length || (length == 1 && part[0] == '.') ||
            (length == 2 && part[0] == '.' && part[1] == '.')) {
            errno = EINVAL;
            return -1;
        }
        if (!end)
            break;
        part = end + 1;
    }
    int directory = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0)
        return -1;
    char *part = copy + 1, *end;
    while ((end = strchr(part, '/'))) {
        *end = '\0';
        bool created = false;
        if (create) {
            if (mkdirat(directory, part, 0700) == 0)
                created = true;
            else if (errno != EEXIST)
                goto failed;
        }
        int next = openat(directory, part, (created ? O_RDONLY : O_PATH) |
                          O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0)
            goto failed;
        if (created && (fchown(next, uid, gid) < 0 || fchmod(next, 0700) < 0)) {
            int error = errno;
            close(next);
            errno = error;
            goto failed;
        }
        close(directory);
        directory = next;
        part = end + 1;
    }
    return directory;

failed: {
    int error = errno;
    close(directory);
    errno = error;
    return -1;
}
}

int avm_relay_prepare(const char *socket_path, uid_t uid, gid_t gid)
{
    int directory = socket_parent(socket_path, true, uid, gid);
    if (directory < 0)
        return -1;
    close(directory);
    return 0;
}

static void relay_supervisor(const char *path, uint32_t port, int ready_fd, pid_t parent)
{
    int listener = -1, signal_fd = -1, parent_fd = -1, error = 0;
    bool bound = false;
    struct stat bound_status;
    const char *name = strrchr(path, '/') + 1;
    pid_t workers[MAX_WORKERS];
    size_t count = 0;
    close_inherited_fds(ready_fd);

    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGTERM);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGHUP);
    sigaddset(&signals, SIGQUIT);
    sigaddset(&signals, SIGCHLD);
    if (sigprocmask(SIG_SETMASK, &signals, NULL) < 0)
        goto failed;
    struct sigaction action = {.sa_handler = SIG_DFL};
    sigemptyset(&action.sa_mask);
    const int watched[] = {SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGCHLD};
    for (size_t i = 0; i < sizeof(watched) / sizeof(watched[0]); ++i)
        if (sigaction(watched[i], &action, NULL) < 0)
            goto failed;
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, NULL) < 0 ||
        prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
        goto failed;
    if (getppid() != parent) {
        errno = ECANCELED;
        goto failed;
    }
    signal_fd = signalfd(-1, &signals, SFD_CLOEXEC | SFD_NONBLOCK);
    if (signal_fd < 0)
        goto failed;
    parent_fd = socket_parent(path, false, 0, 0);
    if (parent_fd < 0 || fchdir(parent_fd) < 0)
        goto failed;
    listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (listener < 0)
        goto failed;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t length = strlen(name);
    memcpy(address.sun_path, name, length + 1);
    /* The isolated relay's cwd anchors bind to the verified parent inode.
     * This also avoids following replacement symlinks in the original path. */
    umask(0177);
    if (bind(listener, (const struct sockaddr *)&address,
             (socklen_t)(offsetof(struct sockaddr_un, sun_path) + length + 1)) < 0)
        goto failed;
    if (fstatat(parent_fd, name, &bound_status, AT_SYMLINK_NOFOLLOW) < 0)
        goto failed;
    bound = true;
    if (listen(listener, (int)MAX_WORKERS) < 0)
        goto failed;
    if (report_ready(ready_fd, 0) < 0)
        goto finished;
    close(ready_fd);
    ready_fd = -1;

    for (;;) {
        reap_workers(workers, &count);
        struct pollfd fds[2] = {
            {.fd = signal_fd, .events = POLLIN},
            {.fd = listener, .events = count < MAX_WORKERS ? POLLIN : 0}
        };
        int result = poll(fds, 2, -1);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (fds[0].revents & POLLIN) {
            struct signalfd_siginfo info;
            while (read(signal_fd, &info, sizeof(info)) == sizeof(info))
                if (info.ssi_signo != SIGCHLD)
                    goto finished;
            reap_workers(workers, &count);
        }
        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL))
            break;
        if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL))
            break;
        if (fds[1].revents & POLLIN) {
            while (count < MAX_WORKERS) {
                int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
                if (client < 0) {
                    if (errno == EINTR)
                        continue;
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                        goto finished;
                    break;
                }
                pid_t supervisor = getpid();
                pid_t child = fork();
                if (child == 0) {
                    close(listener);
                    close(signal_fd);
                    close(parent_fd);
                    run_worker(client, supervisor, port);
                }
                close(client);
                if (child < 0)
                    goto finished;
                workers[count++] = child;
            }
        }
    }
    goto finished;

failed:
    error = errno;
    (void)report_ready(ready_fd, error ? error : EIO);
finished:
    if (ready_fd >= 0)
        close(ready_fd);
    if (listener >= 0)
        close(listener);
    if (signal_fd >= 0)
        close(signal_fd);
    for (size_t i = 0; i < count; ++i)
        (void)kill(workers[i], SIGTERM);
    for (size_t i = 0; i < count; ++i)
        while (waitpid(workers[i], NULL, 0) < 0 && errno == EINTR) {}
    if (bound) {
        struct stat current;
        if (fstatat(parent_fd, name, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISSOCK(current.st_mode) && current.st_dev == bound_status.st_dev &&
            current.st_ino == bound_status.st_ino)
            (void)unlinkat(parent_fd, name, 0);
    }
    if (parent_fd >= 0)
        close(parent_fd);
    _exit(error ? 1 : 0);
}

pid_t avm_relay_start(const char *socket_path, uint32_t port)
{
    if (!socket_path || socket_path[0] != '/' ||
        port < AVM_SOCKET_PORT_BASE || port - AVM_SOCKET_PORT_BASE >= AVM_SOCKET_MAX) {
        errno = EINVAL;
        return -1;
    }
    int readiness[2];
    if (pipe2(readiness, O_CLOEXEC) < 0)
        return -1;
    pid_t parent = getpid();
    pid_t child = fork();
    if (child == 0) {
        close(readiness[0]);
        relay_supervisor(socket_path, port, readiness[1], parent);
    }
    int saved = errno;
    close(readiness[1]);
    if (child < 0) {
        close(readiness[0]);
        errno = saved;
        return -1;
    }
    int error = 0;
    unsigned char *destination = (unsigned char *)&error;
    size_t left = sizeof(error);
    while (left) {
        ssize_t result = read(readiness[0], destination, left);
        if (result < 0 && errno == EINTR)
            continue;
        if (result <= 0) {
            error = result == 0 ? EIO : errno;
            break;
        }
        destination += result;
        left -= (size_t)result;
    }
    close(readiness[0]);
    if (error) {
        (void)kill(child, SIGTERM);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        errno = error;
        return -1;
    }
    return child;
}
