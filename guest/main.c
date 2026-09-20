#define _GNU_SOURCE
#include "agent_vm/protocol.h"
#include "relay.h"
#include "filesystem.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <ifaddrs.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/vm_sockets.h>
#include <net/if.h>
#include <net/route.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define CONTROL_CLIENTS 32

extern char **environ;

struct run_spec {
    struct avm_spec_header header;
    char *home, *cwd;
    char **argv, **env, **sockets;
};

static pid_t relay_pids[AVM_SOCKET_MAX];
static uint32_t relay_count;
static pid_t relay_owner;

struct cursor {
    const unsigned char *data;
    size_t size, offset;
};

struct control_client {
    int fd;
    size_t used;
    unsigned char data[sizeof(struct avm_control_message) + 1];
    bool processed;
    size_t acknowledgement_written;
    int64_t deadline;
};

static void fail(const char *what)
{
    fprintf(stderr, "agent-vm guest: %s: %s\n", what, strerror(errno));
    exit(125);
}

static void invalid_spec(const char *what)
{
    fprintf(stderr, "agent-vm guest: invalid launch specification: %s\n", what);
    exit(125);
}

static int64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        fail("clock_gettime");
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static char *read_string(struct cursor *cursor)
{
    uint32_t length;
    if (cursor->size - cursor->offset < sizeof(length))
        invalid_spec("truncated string length");
    memcpy(&length, cursor->data + cursor->offset, sizeof(length));
    cursor->offset += sizeof(length);
    if (length > cursor->size - cursor->offset)
        invalid_spec("truncated string");
    if (memchr(cursor->data + cursor->offset, '\0', length))
        invalid_spec("embedded NUL");
    char *result = malloc((size_t)length + 1);
    if (!result)
        fail("allocate launch string");
    memcpy(result, cursor->data + cursor->offset, length);
    result[length] = '\0';
    cursor->offset += length;
    return result;
}

static bool absolute_path(const char *path)
{
    if (path[0] != '/' || strlen(path) >= PATH_MAX)
        return false;
    const char *part = path + 1;
    while (*part) {
        const char *slash = strchr(part, '/');
        size_t length = slash ? (size_t)(slash - part) : strlen(part);
        if ((length == 1 && part[0] == '.') ||
            (length == 2 && part[0] == '.' && part[1] == '.'))
            return false;
        if (!slash)
            break;
        part = slash + 1;
    }
    return true;
}

static bool environment_key(const char *entry)
{
    const unsigned char *p = (const unsigned char *)entry;
    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || *p == '_'))
        return false;
    for (++p; *p && *p != '='; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '_'))
            return false;
    return *p == '=';
}

static int compare_environment_keys(const void *left, const void *right)
{
    const char *a = *(const char *const *)left;
    const char *b = *(const char *const *)right;
    size_t a_length = (size_t)(strchr(a, '=') - a);
    size_t b_length = (size_t)(strchr(b, '=') - b);
    size_t shorter = a_length < b_length ? a_length : b_length;
    int result = memcmp(a, b, shorter);
    if (result)
        return result;
    return (a_length > b_length) - (a_length < b_length);
}

static struct run_spec read_spec(void)
{
    struct run_spec spec = {0};
    int fd = open(AVM_GUEST_SPEC, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        fail("open launch specification");
    struct stat status;
    if (fstat(fd, &status) < 0)
        fail("stat launch specification");
    if (!S_ISREG(status.st_mode) || status.st_size < (off_t)sizeof(spec.header) ||
        status.st_size > AVM_SPEC_MAX)
        invalid_spec("expected regular file between header size and 1 MiB");
    size_t size = (size_t)status.st_size;
    unsigned char *data = malloc(size);
    if (!data)
        fail("allocate launch specification");
    size_t used = 0;
    while (used < size) {
        ssize_t count = read(fd, data + used, size - used);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0)
            fail("read launch specification");
        if (!count)
            invalid_spec("file shortened during read");
        used += (size_t)count;
    }
    unsigned char extra;
    ssize_t count;
    do {
        count = read(fd, &extra, 1);
    } while (count < 0 && errno == EINTR);
    if (count < 0)
        fail("read launch specification end");
    if (count)
        invalid_spec("file grew during read");
    close(fd);
    memcpy(&spec.header, data, sizeof(spec.header));
    const struct avm_spec_header *header = &spec.header;
    if (header->magic != AVM_SPEC_MAGIC || header->version != AVM_SPEC_VERSION ||
        (header->flags & ~AVM_FLAG_NETWORK))
        invalid_spec("unsupported header");
    if (header->uid == UINT32_MAX || header->gid == UINT32_MAX)
        invalid_spec("invalid user or group ID");
    if (!header->argc || header->argc > 65535 || header->envc > 65535 ||
        header->socket_count > AVM_SOCKET_MAX ||
        (uint64_t)header->argc + header->envc + header->socket_count + 2 >
            (size - sizeof(*header)) / sizeof(uint32_t))
        invalid_spec("invalid argument, environment, or socket count");
    struct cursor cursor = {data, size, sizeof(*header)};
    spec.home = read_string(&cursor);
    spec.cwd = read_string(&cursor);
    if (!absolute_path(spec.home) || !absolute_path(spec.cwd))
        invalid_spec("HOME and working directory must be absolute normalized paths");
    spec.argv = calloc((size_t)header->argc + 1, sizeof(char *));
    spec.env = calloc((size_t)header->envc + 1, sizeof(char *));
    spec.sockets = calloc((size_t)header->socket_count + 1, sizeof(char *));
    if (!spec.argv || !spec.env || !spec.sockets)
        fail("allocate argument vectors");
    for (uint32_t i = 0; i < header->argc; ++i)
        spec.argv[i] = read_string(&cursor);
    if (!spec.argv[0][0])
        invalid_spec("empty executable name");
    for (uint32_t i = 0; i < header->envc; ++i) {
        spec.env[i] = read_string(&cursor);
        if (!environment_key(spec.env[i]))
            invalid_spec("invalid environment key");
    }
    for (uint32_t i = 0; i < header->socket_count; ++i) {
        const char *target = spec.sockets[i] = read_string(&cursor);
        size_t length = strlen(target);
        if (!absolute_path(target) || length < 2 ||
            length >= sizeof(((struct sockaddr_un *)0)->sun_path) ||
            target[length - 1] == '/' || strstr(target, "//"))
            invalid_spec("socket target must be an absolute normalized Unix socket path");
        for (uint32_t j = 0; j < i; ++j)
            if (!strcmp(target, spec.sockets[j]))
                invalid_spec("duplicate socket target");
    }
    if (cursor.offset != cursor.size)
        invalid_spec("unexpected trailing data");
    qsort(spec.env, header->envc, sizeof(char *), compare_environment_keys);
    for (uint32_t i = 1; i < header->envc; ++i)
        if (!compare_environment_keys(&spec.env[i - 1], &spec.env[i]))
            invalid_spec("duplicate environment key");
    free(data);
    return spec;
}

static void check_network(void)
{
    struct ifaddrs *addresses = NULL;
    if (getifaddrs(&addresses) < 0)
        fail("inspect guest network interfaces");
    bool address_ready = false;
    for (const struct ifaddrs *entry = addresses; entry; entry = entry->ifa_next) {
        if (entry->ifa_addr && entry->ifa_addr->sa_family == AF_INET &&
            !strcmp(entry->ifa_name, "eth0") && (entry->ifa_flags & IFF_UP)) {
            const struct sockaddr_in *address = (const void *)entry->ifa_addr;
            uint32_t host_address = ntohl(address->sin_addr.s_addr);
            address_ready |= host_address && ((host_address >> 24) != 127);
        }
    }
    freeifaddrs(addresses);
    FILE *routes = fopen("/proc/net/route", "re");
    if (!routes)
        fail("inspect guest network routes");
    char line[1024];
    bool route_ready = false;
    while (fgets(line, sizeof(line), routes)) {
        char device[IFNAMSIZ];
        unsigned long destination, gateway, flags;
        if (sscanf(line, "%15s %lx %lx %lx", device, &destination, &gateway, &flags) == 4 &&
            !strcmp(device, "eth0") && !destination && (flags & RTF_UP))
            route_ready = true;
    }
    bool route_error = ferror(routes);
    fclose(routes);
    if (route_error)
        fail("read guest network routes");
    int dns = open("/etc/resolv.conf", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (dns < 0)
        fail("open guest DNS configuration");
    struct stat status;
    if (fstat(dns, &status) < 0)
        fail("stat guest DNS configuration");
    bool dns_ready = S_ISREG(status.st_mode) && status.st_size > 0;
    close(dns);
    if (!address_ready || !route_ready || !dns_ready) {
        fprintf(stderr, "agent-vm guest: network not ready: eth0 IPv4=%s, default route=%s, DNS=%s\n",
                address_ready ? "yes" : "no", route_ready ? "yes" : "no", dns_ready ? "yes" : "no");
        exit(125);
    }
}

/* Only /run/user is changed here. HOME, CWD, and arbitrary shared mounts are
 * deliberately never chmod/chown targets, even while this helper is root. */
static void prepare_runtime(uid_t uid, gid_t gid)
{
    int run = open("/run", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (run < 0)
        fail("open private /run");
    if (mkdirat(run, "user", 0755) < 0 && errno != EEXIST)
        fail("create /run/user");
    int user = openat(run, "user", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (user < 0)
        fail("open /run/user");
    close(run);
    char name[32];
    snprintf(name, sizeof(name), "%u", (unsigned)uid);
    if (mkdirat(user, name, 0700) < 0 && errno != EEXIST)
        fail("create private user runtime directory");
    int runtime = openat(user, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (runtime < 0)
        fail("open private user runtime directory");
    close(user);
    if (fchown(runtime, uid, gid) < 0 || fchmod(runtime, 0700) < 0)
        fail("set private user runtime directory permissions");
    close(runtime);
    const char *temporary[] = {"/tmp", "/var/tmp"};
    for (size_t i = 0; i < sizeof(temporary) / sizeof(temporary[0]); ++i) {
        struct stat status;
        if (lstat(temporary[i], &status) < 0)
            fail("stat private temporary directory");
        if (!S_ISDIR(status.st_mode) || (status.st_mode & 01777) != 01777) {
            fprintf(stderr, "agent-vm guest: %s must be a private directory with mode 1777\n", temporary[i]);
            exit(125);
        }
    }
}

static void drop_privileges(uid_t uid, gid_t gid)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        fail("set no_new_privs");
    /* Also prevents uid 0 workloads from regaining capabilities on exec. */
    if (prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED, 0, 0, 0) < 0)
        fail("disable root capability fixup");
    for (int capability = 0; capability < 1024; ++capability) {
        int present = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);
        if (present < 0 && errno == EINVAL)
            break;
        if (present < 0 || prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) < 0)
            fail("clear capability bounding set");
    }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0)
        fail("clear ambient capabilities");
    if (setgroups(0, NULL) < 0 || setresgid(gid, gid, gid) < 0 || setresuid(uid, uid, uid) < 0)
        fail("drop guest user and group privileges");
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    if (syscall(SYS_capset, &header, data) < 0)
        fail("clear guest capabilities");
}

static int control_listener(void)
{
    int fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        fail("create guest control socket");
    struct sockaddr_vm address = {0};
    address.svm_family = AF_VSOCK;
    address.svm_cid = VMADDR_CID_ANY;
    address.svm_port = AVM_CONTROL_PORT;
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0 || listen(fd, 32) < 0)
        fail("listen on guest control socket");
    return fd;
}

static bool allowed_signal(uint32_t signal_number)
{
    return signal_number == SIGINT || signal_number == SIGTERM ||
           signal_number == SIGHUP || signal_number == SIGQUIT || signal_number == SIGWINCH;
}

static void forward_signal(pid_t workload, int signal_number)
{
    if (kill(-workload, signal_number) < 0 && errno != ESRCH)
        fprintf(stderr, "agent-vm guest: forward signal: %s\n", strerror(errno));
}

static bool dispatch_control(const unsigned char *data, pid_t workload)
{
    struct avm_control_message message;
    memcpy(&message, data, sizeof(message));
    if (message.magic != AVM_CONTROL_MAGIC)
        return false;
    if (message.operation == AVM_CONTROL_SIGNAL && allowed_signal(message.signal) &&
        !message.rows && !message.columns) {
        forward_signal(workload, (int)message.signal);
        return true;
    } else if (message.operation == AVM_CONTROL_RESIZE && !message.signal &&
               message.rows && message.rows <= USHRT_MAX &&
               message.columns && message.columns <= USHRT_MAX) {
        struct winsize size = {0};
        size.ws_row = (unsigned short)message.rows;
        size.ws_col = (unsigned short)message.columns;
        /* stdin may be redirected while stdout remains the console. */
        for (int fd = 0; fd <= 2; ++fd)
            if (isatty(fd))
                (void)ioctl(fd, TIOCSWINSZ, &size);
        forward_signal(workload, SIGWINCH);
        return true;
    }
    return false;
}

static void close_client(struct control_client *client)
{
    close(client->fd);
    client->fd = -1;
}

static void acknowledge_control(struct control_client *client)
{
    const uint32_t acknowledgement = AVM_CONTROL_ACK_MAGIC;
    const unsigned char *bytes = (const void *)&acknowledgement;
    while (client->acknowledgement_written < sizeof(acknowledgement)) {
        ssize_t count = send(client->fd, bytes + client->acknowledgement_written,
                             sizeof(acknowledgement) - client->acknowledgement_written, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        if (count <= 0) {
            close_client(client);
            return;
        }
        client->acknowledgement_written += (size_t)count;
    }
}

static void receive_control(struct control_client *client, pid_t workload)
{
    for (;;) {
        if (client->processed) {
            /* Keep the transport open until the sender consumes our ACK.
             * libkrun 1.19 may otherwise discard pending data on HUP. A
             * second message on the same connection is never executed. */
            unsigned char trailing;
            ssize_t count = read(client->fd, &trailing, 1);
            if (count < 0 && errno == EINTR)
                continue;
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                return;
            close_client(client);
            return;
        }
        ssize_t count = read(client->fd, client->data + client->used,
                             sizeof(client->data) - client->used);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        if (count <= 0) {
            close_client(client);
            return;
        }
        client->used += (size_t)count;
        if (client->used > sizeof(struct avm_control_message)) {
            close_client(client);
            return;
        }
        if (client->used == sizeof(struct avm_control_message)) {
            if (!dispatch_control(client->data, workload)) {
                close_client(client);
                return;
            }
            client->processed = true;
            acknowledge_control(client);
            return;
        }
    }
}

static void accept_controls(int listener, struct control_client *clients)
{
    /* Bound each batch, so a connection flood cannot starve signals/reaping. */
    for (size_t attempt = 0; attempt < CONTROL_CLIENTS; ++attempt) {
        struct sockaddr_vm address = {0};
        socklen_t length = sizeof(address);
        int fd = accept4(listener, (struct sockaddr *)&address, &length,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0 && errno == EINTR)
            continue;
        if (fd < 0)
            return;
        bool stored = false;
        if (length >= sizeof(address) && address.svm_family == AF_VSOCK &&
            address.svm_cid == VMADDR_CID_HOST) {
            for (size_t i = 0; i < CONTROL_CLIENTS; ++i) {
                if (clients[i].fd >= 0)
                    continue;
                clients[i] = (struct control_client){.fd = fd, .deadline = monotonic_ms() + 5000};
                stored = true;
                break;
            }
        }
        if (!stored)
            close(fd);
    }
}

static void reset_workload_signals(void)
{
    const int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGWINCH, SIGCHLD,
                           SIGPIPE, SIGTTOU, SIGTTIN, SIGTSTP, SIGCONT};
    struct sigaction action = {.sa_handler = SIG_DFL};
    sigemptyset(&action.sa_mask);
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i)
        if (sigaction(signals[i], &action, NULL) < 0)
            fail("reset command signals");
    sigset_t empty;
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, NULL) < 0)
        fail("unblock command signals");
}

static pid_t start_workload(struct run_spec *spec, int listener, int signal_fd,
                            pid_t *previous_foreground)
{
    int barrier[2];
    if (pipe2(barrier, O_CLOEXEC) < 0)
        fail("create command startup pipe");
    pid_t child = fork();
    if (child < 0)
        fail("fork command");
    if (!child) {
        close(barrier[1]);
        close(listener);
        close(signal_fd);
        if (setpgid(0, 0) < 0)
            fail("set command process group");
        unsigned char ready;
        ssize_t count;
        do {
            count = read(barrier[0], &ready, 1);
        } while (count < 0 && errno == EINTR);
        if (count != 1)
            _exit(125);
        close(barrier[0]);
        reset_workload_signals();
        if (chdir(spec->cwd) < 0)
            fail("enter command working directory");
        /* execvp searches environ's PATH; execvpe would search bootstrap PATH. */
        environ = spec->env;
        execvp(spec->argv[0], spec->argv);
        int error = errno;
        fprintf(stderr, "agent-vm guest: execute %s: %s\n", spec->argv[0], strerror(error));
        _exit(error == ENOENT ? 127 : 126);
    }
    close(barrier[0]);
    if (setpgid(child, child) < 0 && errno != EACCES && errno != ESRCH)
        fail("set command process group");
    *previous_foreground = -1;
    if (isatty(STDIN_FILENO)) {
        pid_t foreground = tcgetpgrp(STDIN_FILENO);
        if (foreground > 0 && tcsetpgrp(STDIN_FILENO, child) == 0)
            *previous_foreground = foreground;
    }
    unsigned char ready = 1;
    ssize_t count;
    do {
        count = write(barrier[1], &ready, 1);
    } while (count < 0 && errno == EINTR);
    close(barrier[1]);
    if (count != 1)
        fail("release command startup pipe");
    return child;
}

static void stop_relays(void)
{
    if (getpid() != relay_owner)
        return;
    relay_owner = 0;
    for (uint32_t i = 0; i < relay_count; ++i)
        if (relay_pids[i] > 0)
            (void)kill(relay_pids[i], SIGTERM);
    int64_t deadline = monotonic_ms() + 2000;
    for (;;) {
        bool remaining = false;
        for (uint32_t i = 0; i < relay_count; ++i) {
            if (relay_pids[i] <= 0)
                continue;
            pid_t result = waitpid(relay_pids[i], NULL, WNOHANG);
            if (result == relay_pids[i] || (result < 0 && errno == ECHILD))
                relay_pids[i] = 0;
            else
                remaining = true;
        }
        if (!remaining)
            return;
        if (monotonic_ms() >= deadline)
            break;
        struct timespec pause = {.tv_nsec = 10000000};
        (void)nanosleep(&pause, NULL);
    }
    for (uint32_t i = 0; i < relay_count; ++i)
        if (relay_pids[i] > 0)
            (void)kill(relay_pids[i], SIGKILL);
    for (uint32_t i = 0; i < relay_count; ++i) {
        if (relay_pids[i] <= 0)
            continue;
        while (waitpid(relay_pids[i], NULL, 0) < 0 && errno == EINTR)
            ;
        relay_pids[i] = 0;
    }
}

static int supervise(pid_t workload, const struct run_spec *spec, int listener, int signal_fd)
{
    struct control_client clients[CONTROL_CLIENTS];
    for (size_t i = 0; i < CONTROL_CLIENTS; ++i)
        clients[i].fd = -1;
    bool done = false, relay_failed = false;
    int workload_status = 0;
    int64_t relay_failure_deadline = 0;
    while (!done) {
        for (;;) {
            int status;
            pid_t child = waitpid(-1, &status, WNOHANG);
            if (child == 0 || (child < 0 && errno == ECHILD))
                break;
            if (child < 0 && errno == EINTR)
                continue;
            if (child < 0)
                fail("reap guest children");
            if (child == workload) {
                workload_status = status;
                done = true;
            } else {
                for (uint32_t i = 0; i < relay_count; ++i) {
                    if (child != relay_pids[i])
                        continue;
                    relay_pids[i] = 0;
                    if (!relay_failed)
                        relay_failure_deadline = monotonic_ms() + 2000;
                    relay_failed = true;
                    fprintf(stderr, "agent-vm guest: socket relay for %s exited unexpectedly\n",
                            spec->sockets[i]);
                    if (!done)
                        forward_signal(workload, SIGTERM);
                    break;
                }
            }
        }
        if (done)
            break;
        int64_t now = monotonic_ms();
        if (relay_failed && now >= relay_failure_deadline)
            forward_signal(workload, SIGKILL);
        struct pollfd poll_fds[CONTROL_CLIENTS + 2] = {
            {.fd = signal_fd, .events = POLLIN}, {.fd = listener, .events = POLLIN}};
        int timeout = relay_failed ? 100 : -1;
        for (size_t i = 0; i < CONTROL_CLIENTS; ++i) {
            if (clients[i].fd >= 0) {
                int64_t remaining = clients[i].deadline - now;
                if (remaining <= 0)
                    close_client(&clients[i]);
                else if (timeout < 0 || remaining < timeout)
                    timeout = (int)remaining;
            }
            poll_fds[i + 2] = (struct pollfd){.fd = clients[i].fd, .events = POLLIN};
            if (clients[i].processed && clients[i].acknowledgement_written < sizeof(uint32_t))
                poll_fds[i + 2].events |= POLLOUT;
        }
        int result = poll(poll_fds, CONTROL_CLIENTS + 2, timeout);
        if (result < 0 && errno == EINTR)
            continue;
        if (result < 0)
            fail("poll guest control and signals");
        if (poll_fds[0].revents & POLLIN) {
            struct signalfd_siginfo event;
            while (read(signal_fd, &event, sizeof(event)) == sizeof(event))
                if (allowed_signal(event.ssi_signo))
                    forward_signal(workload, (int)event.ssi_signo);
        }
        for (size_t i = 0; i < CONTROL_CLIENTS; ++i) {
            if (clients[i].fd >= 0 && (poll_fds[i + 2].revents & POLLOUT))
                acknowledge_control(&clients[i]);
            if (clients[i].fd >= 0 && (poll_fds[i + 2].revents & (POLLIN | POLLHUP | POLLERR)))
                receive_control(&clients[i], workload);
        }
        if (poll_fds[1].revents & POLLIN)
            accept_controls(listener, clients);
    }
    for (size_t i = 0; i < CONTROL_CLIENTS; ++i)
        if (clients[i].fd >= 0)
            close_client(&clients[i]);
    if (relay_failed)
        return 125;
    if (WIFEXITED(workload_status))
        return WEXITSTATUS(workload_status);
    if (WIFSIGNALED(workload_status))
        return 128 + WTERMSIG(workload_status);
    return 125;
}

int main(void)
{
    struct run_spec spec = read_spec();
    if (geteuid() != 0) {
        fprintf(stderr, "agent-vm guest: helper must start as guest root\n");
        return 125;
    }
    avm_mount_filesystems();
    if (spec.header.flags & AVM_FLAG_NETWORK)
        check_network();
    prepare_runtime((uid_t)spec.header.uid, (gid_t)spec.header.gid);
    for (uint32_t i = 0; i < spec.header.socket_count; ++i)
        if (avm_relay_prepare(spec.sockets[i], (uid_t)spec.header.uid,
                              (gid_t)spec.header.gid) < 0)
            fail(spec.sockets[i]);
    int listener = control_listener();
    sigset_t blocked;
    sigemptyset(&blocked);
    const int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGCHLD, SIGWINCH};
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i)
        sigaddset(&blocked, signals[i]);
    if (sigprocmask(SIG_BLOCK, &blocked, NULL) < 0)
        fail("block supervisor signals");
    struct sigaction defaults = {.sa_handler = SIG_DFL};
    sigemptyset(&defaults.sa_mask);
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i)
        if (sigaction(signals[i], &defaults, NULL) < 0)
            fail("reset supervisor signal dispositions");
    struct sigaction ignored = {.sa_handler = SIG_IGN};
    sigemptyset(&ignored.sa_mask);
    if (sigaction(SIGTTOU, &ignored, NULL) < 0 || sigaction(SIGPIPE, &ignored, NULL) < 0)
        fail("configure supervisor signals");
    int signal_fd = signalfd(-1, &blocked, SFD_NONBLOCK | SFD_CLOEXEC);
    if (signal_fd < 0)
        fail("create supervisor signal descriptor");
    drop_privileges((uid_t)spec.header.uid, (gid_t)spec.header.gid);
    relay_owner = getpid();
    if (atexit(stop_relays) != 0) {
        errno = ENOMEM;
        fail("register socket relay cleanup");
    }
    relay_count = spec.header.socket_count;
    for (uint32_t i = 0; i < relay_count; ++i) {
        relay_pids[i] = avm_relay_start(spec.sockets[i], AVM_SOCKET_PORT_BASE + i);
        if (relay_pids[i] < 0)
            fail(spec.sockets[i]);
    }
    int ready = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (ready < 0)
        fail("create readiness socket");
    struct sockaddr_vm ready_address = {0};
    ready_address.svm_family = AF_VSOCK;
    ready_address.svm_cid = VMADDR_CID_HOST;
    ready_address.svm_port = AVM_READY_PORT;
    if (connect(ready, (struct sockaddr *)&ready_address, sizeof(ready_address)) < 0)
        fail("publish guest readiness");
    close(ready);
    pid_t previous_foreground;
    pid_t workload = start_workload(&spec, listener, signal_fd, &previous_foreground);
    int result = supervise(workload, &spec, listener, signal_fd);
    if (previous_foreground > 0)
        (void)tcsetpgrp(STDIN_FILENO, previous_foreground);
    /* Any remaining processes in the workload group must not outlive its main
     * command. libkrun's PID 1 tears down the rest when this helper exits. */
    forward_signal(workload, SIGTERM);
    forward_signal(workload, SIGKILL);
    stop_relays();
    close(listener);
    close(signal_fd);
    return result;
}
