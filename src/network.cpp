#include "agent_vm/runtime.hpp"
#include "agent_vm/protocol.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace avm {
namespace {
class Fd {
public:
    explicit Fd(int value = -1) : value_(value) {}
    ~Fd() { if (value_ >= 0) close(value_); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    int get() const { return value_; }
    int release() { int value = value_; value_ = -1; return value; }
    void reset(int value = -1) { if (value_ >= 0) close(value_); value_ = value; }
private:
    int value_;
};

[[noreturn]] void fail(const std::string& message, int error = errno) {
    throw std::runtime_error(message + ": " + std::strerror(error));
}

enum class Stage : int { Ready, Signals, ProcessGroup, ParentDeath, Descriptors, Privileges,
                         Stdin, Output, Exec, Socket, Bind, Listen };
struct Status { Stage stage; int error; };
const char* stage_name(Stage stage) {
    switch (stage) {
    case Stage::Ready: return "ready";
    case Stage::Signals: return "reset signals";
    case Stage::ProcessGroup: return "separate helper process group";
    case Stage::ParentDeath: return "set parent-death signal";
    case Stage::Descriptors: return "close unrelated descriptors";
    case Stage::Privileges: return "drop helper privileges";
    case Stage::Stdin: return "redirect helper stdin";
    case Stage::Output: return "redirect helper output";
    case Stage::Exec: return "execute helper";
    case Stage::Socket: return "create broker socket";
    case Stage::Bind: return "bind broker socket";
    case Stage::Listen: return "listen on broker socket";
    }
    return "initialize helper";
}

void write_status(int fd, Status value) {
    const char* data = reinterpret_cast<const char*>(&value);
    size_t left = sizeof(value);
    while (left) {
        ssize_t count = write(fd, data, left);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        data += count;
        left -= static_cast<size_t>(count);
    }
}
[[noreturn]] void child_fail(int fd, Stage stage) {
    write_status(fd, {stage, errno});
    _exit(125);
}

// All callers fork before introducing threads. close_range avoids an inherited
// directory FD or an arbitrary RLIMIT_NOFILE-sized /proc traversal.
bool close_except(std::vector<int> keep) {
    keep.insert(keep.end(), {0, 1, 2});
    std::sort(keep.begin(), keep.end());
    keep.erase(std::unique(keep.begin(), keep.end()), keep.end());
    unsigned int first = 3;
    bool fallback = false;
    for (int fd : keep) {
        if (fd < 3) continue;
        if (first < static_cast<unsigned int>(fd) &&
            syscall(SYS_close_range, first, static_cast<unsigned int>(fd - 1), 0) < 0) {
            if (errno != ENOSYS && errno != EINVAL) return false;
            fallback = true;
            break;
        }
        first = static_cast<unsigned int>(fd) + 1;
    }
    if (!fallback && syscall(SYS_close_range, first, UINT_MAX, 0) == 0) return true;
    if (!fallback && errno != ENOSYS && errno != EINVAL) return false;
    struct rlimit limit {};
    if (getrlimit(RLIMIT_NOFILE, &limit) < 0) return false;
    const rlim_t end = std::min<rlim_t>(limit.rlim_max, INT_MAX);
    for (int fd = 3; static_cast<rlim_t>(fd) < end; ++fd)
        if (!std::binary_search(keep.begin(), keep.end(), fd)) close(fd);
    return true;
}

bool reset_signals() {
    sigset_t empty;
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, nullptr) < 0) return false;
    struct sigaction action {};
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    for (int signal = 1; signal < NSIG; ++signal) {
        if (signal == SIGKILL || signal == SIGSTOP) continue;
        if (sigaction(signal, &action, nullptr) < 0 && errno != EINVAL) return false;
    }
    return true;
}

bool ignore_terminal_signals() {
    // Helpers use /dev/null for input and may still log to the caller's stderr.
    // Their separate process group must not stop on background-terminal I/O.
    struct sigaction action {};
    action.sa_handler = SIG_IGN;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGTTIN, &action, nullptr) == 0 &&
           sigaction(SIGTTOU, &action, nullptr) == 0;
}

bool parent_death(pid_t expected_parent, int signal) {
    if (prctl(PR_SET_PDEATHSIG, signal) < 0) return false;
    if (getppid() != expected_parent) { errno = ECHILD; return false; }
    return true;
}

bool drop_privileges() {
    cap_t empty = cap_init();
    if (!empty) return false;
    int result = cap_set_proc(empty);
    int error = errno;
    cap_free(empty);
    if (result < 0) { errno = error; return false; }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) return false;
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0;
}

bool null_stream(int target, int mode) {
    Fd stream(open("/dev/null", mode | O_CLOEXEC));
    if (stream.get() < 0) return false;
    if (stream.get() == target) {
        if (fcntl(stream.get(), F_SETFD, 0) < 0) return false;
        stream.release();
        return true;
    }
    return dup2(stream.get(), target) >= 0;
}

void move_above_stdio(Fd& fd) {
    // Keep passt IPC out of standard-stream slots even if the caller closed them.
    if (fd.get() >= 3) return;
    int moved = fcntl(fd.get(), F_DUPFD_CLOEXEC, 3);
    if (moved < 0) fail("move passt IPC descriptor above standard streams");
    fd.reset(moved);
}

void wait_startup(int fd, pid_t child, bool exec_helper, const char* name) {
    Status status {};
    char* output = reinterpret_cast<char*>(&status);
    size_t used = 0;
    while (used < sizeof(status)) {
        ssize_t count = read(fd, output + used, sizeof(status) - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { int error = errno; stop_child(child); fail(std::string(name) + " startup pipe", error); }
        if (count == 0) break;
        used += static_cast<size_t>(count);
    }
    if (used == 0 && exec_helper) return; // CLOEXEC acknowledges successful exec.
    if (used != sizeof(status)) {
        stop_child(child);
        fail(std::string(name) + " exited before reporting readiness", EPROTO);
    }
    if (status.stage != Stage::Ready) {
        stop_child(child);
        fail(std::string(name) + ": " + stage_name(status.stage), status.error);
    }
}

sockaddr_un socket_address(const std::string& path) {
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    if (path.empty() || path.front() != '/' || path.find('\0') != std::string::npos)
        throw std::runtime_error("Unix socket path must be an absolute pathname");
    if (path.size() >= sizeof(address.sun_path))
        throw std::runtime_error("Unix socket path exceeds sockaddr_un limit: " + path);
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    return address;
}

volatile sig_atomic_t broker_stopping = 0;
void broker_signal(int) { broker_stopping = 1; }

struct Buffer {
    std::array<char, 65536> data {};
    size_t begin = 0;
    size_t end = 0;
    bool eof = false;
    bool sent_eof = false;
    bool empty() const { return begin == end; }
    void compact() {
        if (begin == 0) return;
        std::memmove(data.data(), data.data() + begin, end - begin);
        end -= begin;
        begin = 0;
    }
};

bool write_buffer(int fd, Buffer& buffer) {
    ssize_t count = send(fd, buffer.data.data() + buffer.begin,
                         buffer.end - buffer.begin, MSG_NOSIGNAL);
    if (count > 0) { buffer.begin += static_cast<size_t>(count); return true; }
    if (count == 0) return false;
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}

int relay(int client, int upstream) {
    // The vsock-facing Unix socket carries framing, not the raw upstream stream.
    // libkrun 1.19 processes host HUP before readable data, so half-closing or
    // closing that endpoint can discard its final reply. Logical EOF plus ACK
    // lets the guest consume the complete reply before it closes the transport.
    Buffer requests;
    std::array<unsigned char, 4> header {};
    size_t header_used = 0;
    uint32_t request_remaining = 0;
    std::array<char, AVM_STREAM_MAX + 4> outgoing {};
    size_t output_begin = 0, output_end = 0;
    uint32_t output_type = 0;
    bool remote_eof = false, response_eof_sent = false, ack_sent = false;
    auto queue_frame = [&](uint32_t size) {
        const uint32_t encoded = htonl(size);
        std::memcpy(outgoing.data(), &encoded, sizeof(encoded));
        output_begin = 0;
        output_end = 4 + (size <= AVM_STREAM_MAX ? size : 0);
        output_type = size;
    };
    while (true) {
        if (requests.eof && requests.empty() && !requests.sent_eof) {
            if (shutdown(upstream, SHUT_WR) < 0 && errno != ENOTCONN) return 1;
            requests.sent_eof = true;
        }
        if (output_begin == output_end && remote_eof && !response_eof_sent) queue_frame(AVM_STREAM_EOF);
        if (output_begin == output_end && response_eof_sent && requests.sent_eof && !ack_sent) queue_frame(AVM_STREAM_ACK);
        requests.compact();
        pollfd fds[2] {{client, 0, 0}, {upstream, 0, 0}};
        if (requests.eof || !request_remaining || requests.end < requests.data.size()) fds[0].events |= POLLIN;
        if (output_begin != output_end) fds[0].events |= POLLOUT;
        if (!remote_eof && output_begin == output_end) fds[1].events |= POLLIN;
        if (!requests.empty()) fds[1].events |= POLLOUT;
        // poll reports HUP even with events == 0. Disable a completed endpoint
        // until data in the opposite direction makes it relevant again.
        if (!fds[0].events) fds[0].fd = -1;
        if (!fds[1].events) fds[1].fd = -1;
        int result = poll(fds, 2, -1);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return 1;
        if ((fds[0].revents | fds[1].revents) & POLLNVAL) return 1;
        if ((fds[0].revents & (POLLIN | POLLHUP | POLLERR)) && (fds[0].events & POLLIN)) {
            if (requests.eof) {
                char extra;
                ssize_t count = recv(client, &extra, 1, 0);
                if (count == 0) return ack_sent ? 0 : 1;
                if (count > 0) return 1; // No request frames after logical EOF.
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return 1;
            } else if (!request_remaining) {
                ssize_t count = recv(client, header.data() + header_used, header.size() - header_used, 0);
                if (count == 0) return 1;
                if (count < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return 1;
                } else {
                    header_used += static_cast<size_t>(count);
                    if (header_used == header.size()) {
                        uint32_t encoded;
                        std::memcpy(&encoded, header.data(), sizeof(encoded));
                        request_remaining = ntohl(encoded);
                        header_used = 0;
                        if (request_remaining > AVM_STREAM_MAX) return 1;
                        if (request_remaining == AVM_STREAM_EOF) requests.eof = true;
                    }
                }
            } else {
                ssize_t count = recv(client, requests.data.data() + requests.end,
                    std::min<size_t>(request_remaining, requests.data.size() - requests.end), 0);
                if (count == 0) return 1;
                if (count < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return 1;
                } else {
                    requests.end += static_cast<size_t>(count);
                    request_remaining -= static_cast<uint32_t>(count);
                }
            }
        }
        if ((fds[1].revents & (POLLIN | POLLHUP | POLLERR)) && !remote_eof && output_begin == output_end) {
            ssize_t count = recv(upstream, outgoing.data() + 4, AVM_STREAM_MAX, 0);
            if (count == 0) remote_eof = true;
            else if (count > 0) queue_frame(static_cast<uint32_t>(count));
            else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return 1;
        }
        if ((fds[0].revents & POLLOUT) && output_begin != output_end) {
            ssize_t count = send(client, outgoing.data() + output_begin, output_end - output_begin, MSG_NOSIGNAL);
            if (count == 0) return 1;
            if (count < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return 1;
            } else {
                output_begin += static_cast<size_t>(count);
                if (output_begin == output_end) {
                    if (output_type == AVM_STREAM_EOF) response_eof_sent = true;
                    else if (output_type == AVM_STREAM_ACK) ack_sent = true;
                }
            }
        }
        if ((fds[1].revents & POLLOUT) && !requests.empty() && !write_buffer(upstream, requests)) return 1;
    }
}

[[noreturn]] void broker_worker(int client, const sockaddr_un& upstream, pid_t broker) {
    // Keep the broker's process group, but restore its terminal-I/O policy after
    // resetting any signal handlers inherited from the broker supervisor.
    if (!reset_signals() || !ignore_terminal_signals() ||
        !parent_death(broker, SIGKILL) || !close_except({client})) _exit(125);
    Fd remote(socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (remote.get() < 0) _exit(125);
    if (connect(remote.get(), reinterpret_cast<const sockaddr*>(&upstream), sizeof(upstream)) < 0) {
        if (errno != EINPROGRESS) _exit(1);
        pollfd pending {remote.get(), POLLOUT, 0};
        int result;
        do { result = poll(&pending, 1, 10000); } while (result < 0 && errno == EINTR);
        int error = 0;
        socklen_t size = sizeof(error);
        if (result <= 0 || getsockopt(remote.get(), SOL_SOCKET, SO_ERROR, &error, &size) < 0 || error) _exit(1);
    }
    _exit(relay(client, remote.get()));
}

void reap_workers(std::vector<pid_t>& workers) {
    workers.erase(std::remove_if(workers.begin(), workers.end(), [](pid_t worker) {
        int status;
        pid_t result = waitpid(worker, &status, WNOHANG);
        return result == worker || (result < 0 && errno == ECHILD);
    }), workers.end());
}

void finish_workers(std::vector<pid_t>& workers) {
    for (pid_t worker : workers) kill(worker, SIGTERM);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    while (!workers.empty() && std::chrono::steady_clock::now() < deadline) {
        reap_workers(workers);
        if (!workers.empty()) { timespec delay {0, 10000000}; nanosleep(&delay, nullptr); }
    }
    for (pid_t worker : workers) kill(worker, SIGKILL);
    for (pid_t worker : workers) {
        while (waitpid(worker, nullptr, 0) < 0 && errno == EINTR) {}
    }
}

[[noreturn]] void broker_main(const std::string& listen_path, const sockaddr_un& listen_address,
                            const sockaddr_un& upstream_address, int status_fd, pid_t parent) {
    if (!reset_signals()) child_fail(status_fd, Stage::Signals);
    if (setpgid(0, 0) < 0) child_fail(status_fd, Stage::ProcessGroup);
    if (!ignore_terminal_signals()) child_fail(status_fd, Stage::Signals);
    struct sigaction action {};
    action.sa_handler = broker_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, nullptr) < 0 || sigaction(SIGINT, &action, nullptr) < 0 ||
        sigaction(SIGHUP, &action, nullptr) < 0) child_fail(status_fd, Stage::Signals);
    broker_stopping = 0;
    if (!parent_death(parent, SIGTERM)) child_fail(status_fd, Stage::ParentDeath);
    if (!close_except({status_fd})) child_fail(status_fd, Stage::Descriptors);
    if (!null_stream(STDIN_FILENO, O_RDONLY)) child_fail(status_fd, Stage::Stdin);
    clearenv();
    if (!drop_privileges()) child_fail(status_fd, Stage::Privileges);
    umask(0077);
    Fd listener(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    if (listener.get() < 0) child_fail(status_fd, Stage::Socket);
    if (bind(listener.get(), reinterpret_cast<const sockaddr*>(&listen_address), sizeof(listen_address)) < 0)
        child_fail(status_fd, Stage::Bind);
    if (chmod(listen_path.c_str(), 0600) < 0 || listen(listener.get(), 64) < 0) {
        int error = errno;
        unlink(listen_path.c_str());
        errno = error;
        child_fail(status_fd, Stage::Listen);
    }
    write_status(status_fd, {Stage::Ready, 0});
    close(status_fd);
    std::vector<pid_t> workers;
    int exit_code = 0;
    while (!broker_stopping) {
        reap_workers(workers);
        pollfd pending {listener.get(), POLLIN, 0};
        int result = poll(&pending, 1, 100);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0 || (pending.revents & (POLLERR | POLLHUP | POLLNVAL))) { exit_code = 125; break; }
        if (!result || !(pending.revents & POLLIN)) continue;
        Fd client(accept4(listener.get(), nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK));
        if (client.get() < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            exit_code = 125;
            break;
        }
        if (workers.size() >= 64) continue;
        pid_t own_pid = getpid();
        pid_t child = fork();
        if (child < 0) { exit_code = 125; break; }
        if (child == 0) broker_worker(client.get(), upstream_address, own_pid);
        workers.push_back(child);
    }
    listener.reset();
    finish_workers(workers);
    unlink(listen_path.c_str());
    _exit(exit_code);
}
}

void stop_child(pid_t pid) {
    if (pid <= 0) return;
    int status;
    pid_t result;
    do { result = waitpid(pid, &status, WNOHANG); } while (result < 0 && errno == EINTR);
    // Do not signal a PID that has already been reaped and could be reused.
    if (result == pid || (result < 0 && errno == ECHILD)) return;
    kill(pid, SIGTERM);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline) {
        result = waitpid(pid, &status, WNOHANG);
        if (result == pid || (result < 0 && errno == ECHILD)) return;
        if (result < 0 && errno != EINTR) break;
        timespec delay {0, 10000000};
        nanosleep(&delay, nullptr);
    }
    kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
}

NetworkProcess start_dbus_proxy(const DbusSpec& spec, const std::string& path) {
    socket_address(path);
    int pair[2];
    if (pipe2(pair, O_CLOEXEC) < 0) fail("create D-Bus readiness pipe");
    Fd ready_read(pair[0]), ready_write(pair[1]);
    move_above_stdio(ready_read); move_above_stdio(ready_write);
    int status[2];
    if (pipe2(status, O_CLOEXEC) < 0) fail("create D-Bus startup pipe");
    Fd status_read(status[0]), status_write(status[1]);
    move_above_stdio(status_read); move_above_stdio(status_write);
    std::vector<std::string> args {"/usr/bin/xdg-dbus-proxy", "--fd=" + std::to_string(ready_write.get()),
                                   spec.address, path, "--filter"};
    args.insert(args.end(), spec.args.begin(), spec.args.end());
    std::vector<char*> argv;
    for (auto& arg : args) argv.push_back(arg.data());
    argv.push_back(nullptr);
    pid_t parent = getpid(), child = fork();
    if (child < 0) fail("fork xdg-dbus-proxy");
    if (child == 0) {
        if (!reset_signals() || !ignore_terminal_signals()) child_fail(status_write.get(), Stage::Signals);
        if (setpgid(0, 0) < 0) child_fail(status_write.get(), Stage::ProcessGroup);
        if (!parent_death(parent, SIGKILL)) child_fail(status_write.get(), Stage::ParentDeath);
        if (!close_except({ready_write.get(), status_write.get()})) child_fail(status_write.get(), Stage::Descriptors);
        if (!null_stream(STDIN_FILENO, O_RDONLY)) child_fail(status_write.get(), Stage::Stdin);
        // Keep --log diagnostics off workload stdout.
        if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0) child_fail(status_write.get(), Stage::Output);
        if (!drop_privileges()) child_fail(status_write.get(), Stage::Privileges);
        if (fcntl(ready_write.get(), F_SETFD, 0) < 0) child_fail(status_write.get(), Stage::Descriptors);
        char path_env[] = "PATH=/usr/bin:/bin", locale[] = "LC_ALL=C";
        char* environment[] = {path_env, locale, nullptr};
        execve(argv[0], argv.data(), environment);
        child_fail(status_write.get(), Stage::Exec);
    }
    status_write.reset(); ready_write.reset();
    wait_startup(status_read.get(), child, true, "xdg-dbus-proxy");
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    for (;;) {
        pollfd event{ready_read.get(), POLLIN, 0};
        int result = poll(&event, 1, 100);
        if (result < 0 && errno == EINTR) continue;
        char byte;
        if (result > 0 && (event.revents & POLLIN) && read(ready_read.get(), &byte, 1) == 1)
            return {ready_read.release(), child};
        if (result < 0 || (result > 0 && (event.revents & (POLLHUP | POLLERR))) ||
            std::chrono::steady_clock::now() >= deadline) {
            stop_child(child);
            throw std::runtime_error("xdg-dbus-proxy exited or timed out before readiness");
        }
    }
}

NetworkProcess start_passt(const RunSpec& spec) {
    std::vector<std::string> args {"/usr/bin/passt", "--foreground", "--fd"};
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0) fail("create passt socketpair");
    Fd parent_socket(pair[0]), child_socket(pair[1]);
    move_above_stdio(parent_socket);
    move_above_stdio(child_socket);
    args.push_back(std::to_string(child_socket.get()));
    if (spec.debug) args.push_back("--debug");
    for (bool udp : {false, true}) {
        bool any = false;
        for (const auto& port : spec.ports) {
            if (port.udp != udp) continue;
            in_addr address {};
            if (!port.host_port || !port.guest_port || inet_pton(AF_INET, port.address.c_str(), &address) != 1)
                throw std::runtime_error("passt requires valid IPv4 addresses and nonzero port numbers");
            args.push_back(udp ? "--udp-ports" : "--tcp-ports");
            args.push_back(port.address + "/" + std::to_string(port.host_port) + ":" + std::to_string(port.guest_port));
            any = true;
        }
        if (!any) { args.push_back(udp ? "--udp-ports" : "--tcp-ports"); args.push_back("none"); }
    }
    std::vector<char*> argv;
    for (auto& arg : args) argv.push_back(arg.data());
    argv.push_back(nullptr);
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC) < 0) fail("create passt startup pipe");
    Fd status_read(pipe_fds[0]), status_write(pipe_fds[1]);
    move_above_stdio(status_read);
    move_above_stdio(status_write);
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) fail("fork passt");
    if (child == 0) {
        if (!reset_signals()) child_fail(status_write.get(), Stage::Signals);
        if (setpgid(0, 0) < 0) child_fail(status_write.get(), Stage::ProcessGroup);
        if (!ignore_terminal_signals()) child_fail(status_write.get(), Stage::Signals);
        if (!parent_death(parent, SIGKILL)) child_fail(status_write.get(), Stage::ParentDeath);
        if (!close_except({child_socket.get(), status_write.get()})) child_fail(status_write.get(), Stage::Descriptors);
        if (!null_stream(STDIN_FILENO, O_RDONLY)) child_fail(status_write.get(), Stage::Stdin);
        if (!null_stream(STDOUT_FILENO, O_WRONLY) || !null_stream(STDERR_FILENO, O_WRONLY))
            child_fail(status_write.get(), Stage::Output);
        if (!drop_privileges()) child_fail(status_write.get(), Stage::Privileges);
        if (fcntl(child_socket.get(), F_SETFD, 0) < 0) child_fail(status_write.get(), Stage::Descriptors);
        char path[] = "PATH=/usr/bin:/bin";
        char locale[] = "LC_ALL=C";
        char* environment[] = {path, locale, nullptr};
        execve(argv[0], argv.data(), environment);
        child_fail(status_write.get(), Stage::Exec);
    }
    child_socket.reset();
    status_write.reset();
    wait_startup(status_read.get(), child, true, "passt");
    // Catch common immediate failures (unsupported flags, unavailable interface,
    // occupied published port); the supervisor monitors later helper exits.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    do {
        int status;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            std::string reason = WIFEXITED(status) ? "exit status " + std::to_string(WEXITSTATUS(status))
                : "signal " + std::to_string(WTERMSIG(status));
            throw std::runtime_error("passt failed during startup (" + reason + ")");
        }
        if (result < 0 && errno != EINTR) { int error = errno; stop_child(child); fail("wait for passt startup", error); }
        timespec delay {0, 10000000};
        nanosleep(&delay, nullptr);
    } while (std::chrono::steady_clock::now() < deadline);
    return {parent_socket.release(), child};
}

pid_t start_socket_broker(const std::string& listen_path, const std::string& upstream_path) {
    sockaddr_un listen_address = socket_address(listen_path);
    sockaddr_un upstream_address = socket_address(upstream_path);
    struct stat info {};
    if (lstat(upstream_path.c_str(), &info) < 0) fail("inspect upstream Unix socket " + upstream_path);
    if (!S_ISSOCK(info.st_mode)) throw std::runtime_error("upstream endpoint is not a Unix socket: " + upstream_path);
    const std::string parent_dir = std::filesystem::path(listen_path).parent_path().string();
    if (lstat(parent_dir.c_str(), &info) < 0) fail("inspect socket broker directory");
    if (!S_ISDIR(info.st_mode) || info.st_uid != geteuid() || (info.st_mode & 0777) != 0700)
        throw std::runtime_error("socket broker directory must be owned by the caller and have mode 0700");
    if (lstat(listen_path.c_str(), &info) == 0) throw std::runtime_error("broker socket path already exists: " + listen_path);
    if (errno != ENOENT) fail("inspect broker socket path");
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC) < 0) fail("create socket broker startup pipe");
    Fd status_read(pipe_fds[0]), status_write(pipe_fds[1]);
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) fail("fork socket broker");
    if (child == 0) broker_main(listen_path, listen_address, upstream_address, status_write.get(), parent);
    status_write.reset();
    wait_startup(status_read.get(), child, false, "socket broker");
    return child;
}
}
