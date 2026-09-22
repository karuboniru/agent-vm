#include "agent_vm/runtime.hpp"
#include "agent_vm/protocol.h"
#include "agent_vm/process_title.h"
#include "socket_sandbox.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
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
                         Stdin, Output, Exec, Socket, Bind, Listen, Sandbox };
struct Status { Stage stage; int error; char detail[256]{}; };
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
    case Stage::Sandbox: return "confine socket broker";
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
[[noreturn]] void child_fail(int fd, Stage stage, const char* detail = nullptr) {
    Status status{stage, errno};
    if (detail) std::strncpy(status.detail, detail, sizeof(status.detail) - 1);
    write_status(fd, status);
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
        if (status.detail[0])
            throw std::runtime_error(std::string(name) + ": " + stage_name(status.stage) + ": " +
                                     std::string(status.detail, strnlen(status.detail, sizeof(status.detail))));
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

// One persistent data process owns a fixed pool of sessions. No allocations,
// socket creation, forks or filesystem operations occur after confinement.
// Logical EOF + ACK keep the transport open until the guest consumes the final
// reply: libkrun 1.19's Unix backend handles HUP before remaining readable data.
constexpr size_t max_sessions = 64;
struct Relay {
    int client = -1, upstream = -1;
    Buffer requests;
    std::array<unsigned char, 4> header {};
    size_t header_used = 0;
    uint32_t request_remaining = 0;
    std::array<char, AVM_STREAM_MAX + 4> outgoing {};
    size_t output_begin = 0, output_end = 0;
    uint32_t output_type = 0;
    bool remote_eof = false, response_eof_sent = false, ack_sent = false;
    void queue_frame(uint32_t size) {
        const uint32_t encoded = htonl(size);
        std::memcpy(outgoing.data(), &encoded, sizeof(encoded));
        output_begin = 0;
        output_end = 4 + (size <= AVM_STREAM_MAX ? size : 0);
        output_type = size;
    }

    bool active() const { return client >= 0; }
    void close_session() {
        if (client >= 0) close(client);
        if (upstream >= 0) close(upstream);
        client = upstream = -1;
    }
    void attach(int guest, int remote) {
        client = guest; upstream = remote;
        requests.begin = requests.end = header_used = request_remaining = 0;
        requests.eof = requests.sent_eof = false;
        output_begin = output_end = output_type = 0;
        remote_eof = response_eof_sent = ack_sent = false;
    }
    bool prepare(pollfd* fds) {
        if (requests.eof && requests.empty() && !requests.sent_eof) {
            if (shutdown(upstream, SHUT_WR) < 0 && errno != ENOTCONN) return false;
            requests.sent_eof = true;
        }
        if (output_begin == output_end && remote_eof && !response_eof_sent) queue_frame(AVM_STREAM_EOF);
        if (output_begin == output_end && response_eof_sent && requests.sent_eof && !ack_sent) queue_frame(AVM_STREAM_ACK);
        requests.compact();
        fds[0] = {client, 0, 0};
        fds[1] = {upstream, 0, 0};
        if (requests.eof || !request_remaining || requests.end < requests.data.size()) fds[0].events |= POLLIN;
        if (output_begin != output_end) fds[0].events |= POLLOUT;
        if (!remote_eof && output_begin == output_end) fds[1].events |= POLLIN;
        if (!requests.empty()) fds[1].events |= POLLOUT;
        // poll reports HUP even with events == 0. Disable a completed endpoint
        // until data in the opposite direction makes it relevant again.
        if (!fds[0].events) fds[0].fd = -1;
        if (!fds[1].events) fds[1].fd = -1;

        return true;
    }
    bool step(const pollfd* fds) {
        if ((fds[0].revents | fds[1].revents) & POLLNVAL) return false;
        if ((fds[0].revents & (POLLIN | POLLHUP | POLLERR)) && (fds[0].events & POLLIN)) {
            if (requests.eof) {
                char extra;
                ssize_t count = recv(client, &extra, 1, 0);
                if (count >= 0) return false; // Transport closed, or data after logical EOF.
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
            } else if (!request_remaining) {
                ssize_t count = recv(client, header.data() + header_used, header.size() - header_used, 0);
                if (count == 0) return false;
                if (count < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
                } else {
                    header_used += static_cast<size_t>(count);
                    if (header_used == header.size()) {
                        uint32_t encoded;
                        std::memcpy(&encoded, header.data(), sizeof(encoded));
                        request_remaining = ntohl(encoded);
                        header_used = 0;
                        if (request_remaining > AVM_STREAM_MAX) return false;
                        if (request_remaining == AVM_STREAM_EOF) requests.eof = true;
                    }
                }
            } else {
                ssize_t count = recv(client, requests.data.data() + requests.end,
                    std::min<size_t>(request_remaining, requests.data.size() - requests.end), 0);
                if (count == 0) return false;
                if (count < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
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
            else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
        }
        if ((fds[0].revents & POLLOUT) && output_begin != output_end) {
            ssize_t count = send(client, outgoing.data() + output_begin, output_end - output_begin, MSG_NOSIGNAL);
            if (count == 0) return false;
            if (count < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
            } else {
                output_begin += static_cast<size_t>(count);
                if (output_begin == output_end) {
                    if (output_type == AVM_STREAM_EOF) response_eof_sent = true;
                    else if (output_type == AVM_STREAM_ACK) ack_sent = true;
                }
            }
        }
        if ((fds[1].revents & POLLOUT) && !requests.empty() && !write_buffer(upstream, requests)) return false;

        return true;
    }
};

// Only the controller writes to this private SOCK_SEQPACKET channel. No guest
// framing, path, command, length or response is ever interpreted by it.
bool send_pair(int channel, int guest, int upstream) {
    char version = 1;
    iovec payload{&version, 1};
    alignas(cmsghdr) char ancillary[CMSG_SPACE(2 * sizeof(int))]{};
    msghdr message{};
    message.msg_iov = &payload; message.msg_iovlen = 1;
    message.msg_control = ancillary; message.msg_controllen = sizeof(ancillary);
    cmsghdr* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(2 * sizeof(int));
    int descriptors[2]{guest, upstream};
    std::memcpy(CMSG_DATA(header), descriptors, sizeof(descriptors));
    ssize_t result;
    do { result = sendmsg(channel, &message, MSG_NOSIGNAL); } while (result < 0 && errno == EINTR && !broker_stopping);
    return result == 1;
}

bool receive_pair(int channel, Relay* sessions) {
    char version = 0;
    iovec payload{&version, 1};
    alignas(cmsghdr) char ancillary[CMSG_SPACE(2 * sizeof(int))]{};
    msghdr message{};
    message.msg_iov = &payload; message.msg_iovlen = 1;
    message.msg_control = ancillary; message.msg_controllen = sizeof(ancillary);
    ssize_t result = recvmsg(channel, &message, MSG_CMSG_CLOEXEC);
    if (result < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
    if (!result) return false;
    int descriptors[2]{-1, -1};
    size_t count = 0;
    bool valid = result == 1 && version == 1 && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    for (cmsghdr* header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
            header->cmsg_len < CMSG_LEN(0)) { valid = false; continue; }
        size_t bytes = header->cmsg_len - CMSG_LEN(0);
        if (bytes % sizeof(int)) valid = false;
        for (size_t at = 0; at + sizeof(int) <= bytes; at += sizeof(int)) {
            int fd;
            std::memcpy(&fd, CMSG_DATA(header) + at, sizeof(fd));
            if (count < 2) descriptors[count++] = fd;
            else { close(fd); valid = false; }
        }
    }
    if (valid && count == 2) {
        for (size_t i = 0; i < max_sessions; ++i) {
            if (!sessions[i].active()) {
                sessions[i].attach(descriptors[0], descriptors[1]);
                return true;
            }
        }
    }
    for (int fd : descriptors) if (fd >= 0) close(fd);
    return valid && count == 2; // A full pool rejects this pair, not existing streams.
}

[[noreturn]] void data_main(int channel, int status_fd, size_t index, const SocketBrokerSpec& spec) {
    try {
        const auto name = "avm-sock-" + std::to_string(index);
        const auto title = "agent-vm: socket[" + std::to_string(index) + "] " + spec.upstream_path +
                           (spec.guest_path.empty() ? "" : " -> guest:" + spec.guest_path);
        if (avm_process_title(name.c_str(), title.c_str())) fail("name socket data process");
        // The channel's HUP also covers parent death before PDEATHSIG is set:
        // getppid() is zero here because the controller is outside this pidns.
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || !close_except({channel, status_fd}))
            child_fail(status_fd, Stage::Descriptors);
        for (int fd : {0, 1, 2}) close(fd);
        detail::enter_socket_data_namespace();
        auto sessions = std::make_unique<Relay[]>(max_sessions);
        std::array<pollfd, 1 + 2 * max_sessions> events{};
        detail::seal_socket_data(channel, status_fd);
        write_status(status_fd, {Stage::Ready, 0});
        close(status_fd);
        while (!broker_stopping) {
            events[0] = {channel, POLLIN, 0};
            for (size_t i = 0; i < max_sessions; ++i) {
                auto* pair = &events[1 + 2 * i];
                pair[0] = pair[1] = {-1, 0, 0};
                if (sessions[i].active() && !sessions[i].prepare(pair)) {
                    sessions[i].close_session();
                    pair[0] = pair[1] = {-1, 0, 0};
                }
            }
            int result = poll(events.data(), events.size(), -1);
            if (result < 0 && errno == EINTR) continue;
            if (result < 0 || (events[0].revents & (POLLHUP | POLLERR | POLLNVAL))) _exit(125);
            for (size_t i = 0; i < max_sessions; ++i)
                if (sessions[i].active() && !sessions[i].step(&events[1 + 2 * i])) sessions[i].close_session();
            if ((events[0].revents & POLLIN) && !receive_pair(channel, sessions.get())) _exit(125);
        }
        _exit(0);
    } catch (const std::exception& error) { child_fail(status_fd, Stage::Sandbox, error.what()); }
}

// The host caller owns pathname cleanup. The controller loses access to its
// listening path when it pivots, and never retains a host directory descriptor.
std::map<pid_t, std::vector<std::string>> broker_paths;
void cleanup_broker(pid_t pid) {
    auto entry = broker_paths.find(pid);
    if (entry == broker_paths.end()) return;
    for (const auto& path : entry->second) unlink(path.c_str());
    broker_paths.erase(entry);
}

struct DataLaunch {
    int channel, status;
    size_t index;
    const SocketBrokerSpec* spec;
};
int data_entry(void* pointer) {
    const auto& launch = *static_cast<DataLaunch*>(pointer);
    data_main(launch.channel, launch.status, launch.index, *launch.spec);
}

struct PendingConnection {
    int client = -1, remote = -1;
    size_t route = 0;
    std::chrono::steady_clock::time_point deadline;
    void reset() {
        if (client >= 0) close(client);
        if (remote >= 0) close(remote);
        client = remote = -1;
    }
};

[[noreturn]] void broker_main(const std::vector<SocketBrokerSpec>& sockets, int status_fd, pid_t parent) {
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
    clearenv();
    umask(0077);
    std::vector<pid_t> children;
    try {
        const size_t count = sockets.size();
        const auto title = "agent-vm: socket controller (" + std::to_string(count) + " forwards)";
        if (avm_process_title("avm-sock-ctl", title.c_str())) fail("name socket controller");
        std::vector<int> listeners, channels, directory_fds;
        std::vector<detail::SocketDirectory> directories;
        std::vector<size_t> directory_indices;
        std::vector<sockaddr_un> upstreams;
        listeners.reserve(count); channels.reserve(count); children.reserve(count);
        directory_fds.reserve(count); directories.reserve(count);
        directory_indices.reserve(count); upstreams.reserve(count);
        for (const auto& socket_spec : sockets) {
            auto address = socket_address(socket_spec.listen_path);
            Fd listener(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
            if (listener.get() < 0) fail("create broker listener");
            move_above_stdio(listener);
            if (bind(listener.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) ||
                chmod(socket_spec.listen_path.c_str(), 0600) || listen(listener.get(), 64))
                fail("bind/listen broker socket " + socket_spec.listen_path);
            listeners.push_back(listener.release());
            const auto source = std::filesystem::path(socket_spec.upstream_path);
            const auto directory = source.parent_path().string(), name = source.filename().string();
            auto found = std::find_if(directories.begin(), directories.end(), [&](const auto& item) {
                return item.source == directory;
            });
            size_t index = static_cast<size_t>(found - directories.begin());
            if (found == directories.end()) directories.push_back({directory, {name}});
            else found->names.push_back(name);
            directory_indices.push_back(index);
            sockaddr_un upstream{};
            upstream.sun_family = AF_UNIX;
            if (name.size() >= sizeof(upstream.sun_path)) fail("socket upstream name too long", ENAMETOOLONG);
            std::memcpy(upstream.sun_path, name.c_str(), name.size() + 1);
            upstreams.push_back(upstream);
        }
        for (int fd : {0, 1, 2}) close(fd);
        detail::enter_socket_control_namespace(std::filesystem::path(sockets.front().listen_path).parent_path().string(), directories);
        if (!parent_death(parent, SIGTERM)) child_fail(status_fd, Stage::ParentDeath);
        for (size_t i = 0; i < directories.size(); ++i) {
            int fd = open(("/upstream/" + std::to_string(i)).c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
            if (fd < 0) fail("open confined socket directory");
            directory_fds.push_back(fd);
        }
        // clone(), rather than repeated unshare(CLONE_NEWPID), gives every
        // data child its own sibling PID namespace with no extra wait process.
        constexpr size_t stack_size = 1024 * 1024;
        auto stack = std::make_unique<unsigned char[]>(stack_size);
        for (size_t i = 0; i < count; ++i) {
            int pair[2], readiness[2];
            if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, pair))
                fail("create socket broker FD channel");
            Fd control_channel(pair[0]), data_channel(pair[1]);
            move_above_stdio(control_channel); move_above_stdio(data_channel);
            if (shutdown(control_channel.get(), SHUT_RD) || shutdown(data_channel.get(), SHUT_WR))
                fail("make socket broker FD channel one-way");
            if (pipe2(readiness, O_CLOEXEC)) fail("create socket data readiness pipe");
            Fd ready_read(readiness[0]), ready_write(readiness[1]);
            move_above_stdio(ready_read); move_above_stdio(ready_write);
            DataLaunch launch{data_channel.get(), ready_write.get(), i, &sockets[i]};
            pid_t child = clone(data_entry, stack.get() + stack_size, CLONE_NEWPID | SIGCHLD, &launch);
            if (child < 0) fail("clone socket data process");
            children.push_back(child);
            data_channel.reset(); ready_write.reset();
            wait_startup(ready_read.get(), child, false, "socket data process");
            channels.push_back(control_channel.release());
        }
        stack.reset();
        // Everything needed by the event loop is allocated before seccomp.
        std::vector<PendingConnection> pending(count * max_sessions);
        std::vector<pollfd> events(2 * count + pending.size());
        detail::seal_socket_control(listeners, channels, directory_fds, status_fd, children);
        write_status(status_fd, {Stage::Ready, 0});
        close(status_fd);
        int exit_code = 0;
        auto handoff = [&](size_t route, int client, int remote) {
            if (!send_pair(channels[route], client, remote) &&
                errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) exit_code = 125;
        };
        while (!broker_stopping && !exit_code) {
            int timeout = -1;
            const auto now = std::chrono::steady_clock::now();
            for (size_t i = 0; i < count; ++i) {
                events[2 * i] = {listeners[i], POLLIN, 0};
                events[2 * i + 1] = {channels[i], 0, 0};
            }
            for (size_t i = 0; i < pending.size(); ++i) {
                auto& connection = pending[i];
                if (connection.client >= 0 && now >= connection.deadline) connection.reset();
                events[2 * count + i] = {connection.remote, POLLOUT, 0};
                if (connection.client >= 0) {
                    int remaining = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(connection.deadline - now).count()) + 1;
                    timeout = timeout < 0 ? remaining : std::min(timeout, remaining);
                }
            }
            int result = poll(events.data(), events.size(), timeout);
            if (result < 0 && errno == EINTR) continue;
            if (result < 0) { exit_code = 125; break; }
            for (size_t i = 0; i < pending.size(); ++i) {
                auto& connection = pending[i];
                if (connection.client < 0 || !events[2 * count + i].revents) continue;
                int error = 0;
                socklen_t size = sizeof(error);
                if (!(events[2 * count + i].revents & POLLNVAL) &&
                    getsockopt(connection.remote, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && !error)
                    handoff(connection.route, connection.client, connection.remote);
                connection.reset();
            }
            for (size_t i = 0; i < count && !exit_code; ++i) {
                if ((events[2 * i].revents | events[2 * i + 1].revents) & (POLLERR | POLLHUP | POLLNVAL)) {
                    exit_code = 125; break;
                }
                if (!(events[2 * i].revents & POLLIN)) continue;
                Fd client(accept4(listeners[i], nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK));
                if (client.get() < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
                    exit_code = 125; break;
                }
                Fd remote(socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
                if (remote.get() < 0) continue;
                if (fchdir(directory_fds[directory_indices[i]])) { exit_code = 125; break; }
                if (connect(remote.get(), reinterpret_cast<const sockaddr*>(&upstreams[i]), sizeof(sockaddr_un)) == 0) {
                    handoff(i, client.get(), remote.get());
                } else if (errno == EINPROGRESS) {
                    auto slot = std::find_if(pending.begin(), pending.end(), [](const auto& item) { return item.client < 0; });
                    if (slot != pending.end()) {
                        slot->client = client.release(); slot->remote = remote.release(); slot->route = i;
                        slot->deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
                    }
                }
                // AF_UNIX backlog-full EAGAIN rejects just this connection.
            }
        }
        for (pid_t child : children) kill(child, SIGKILL);
        for (pid_t child : children) while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {}
        _exit(exit_code);
    } catch (const std::exception& error) {
        for (pid_t child : children) stop_child(child);
        child_fail(status_fd, Stage::Sandbox, error.what());
    }
}

}

void stop_child(pid_t pid) {
    if (pid <= 0) return;
    int status;
    pid_t result;
    do { result = waitpid(pid, &status, WNOHANG); } while (result < 0 && errno == EINTR);
    // Do not signal a PID that has already been reaped and could be reused.
    if (result == pid || (result < 0 && errno == ECHILD)) { cleanup_broker(pid); return; }
    kill(pid, SIGTERM);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline) {
        result = waitpid(pid, &status, WNOHANG);
        if (result == pid || (result < 0 && errno == ECHILD)) { cleanup_broker(pid); return; }
        if (result < 0 && errno != EINTR) break;
        timespec delay {0, 10000000};
        nanosleep(&delay, nullptr);
    }
    kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    cleanup_broker(pid);
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

pid_t start_socket_brokers(const std::vector<SocketBrokerSpec>& sockets) {
    if (sockets.empty()) return -1;
    if (sockets.size() > AVM_SOCKET_MAX) throw std::runtime_error("too many socket brokers");
    std::vector<std::string> paths;
    paths.reserve(sockets.size());
    for (const auto& spec : sockets) {
        socket_address(spec.listen_path);
        socket_address(spec.upstream_path);
        struct stat info{};
        if (lstat(spec.upstream_path.c_str(), &info) < 0) fail("inspect upstream Unix socket " + spec.upstream_path);
        if (!S_ISSOCK(info.st_mode)) throw std::runtime_error("upstream endpoint is not a Unix socket: " + spec.upstream_path);
        const auto parent_dir = std::filesystem::path(spec.listen_path).parent_path().string();
        if (lstat(parent_dir.c_str(), &info) < 0) fail("inspect socket broker directory");
        if (!S_ISDIR(info.st_mode) || info.st_uid != geteuid() || (info.st_mode & 0777) != 0700)
            throw std::runtime_error("socket broker directory must be owned by the caller and have mode 0700");
        if (lstat(spec.listen_path.c_str(), &info) == 0) throw std::runtime_error("broker socket path already exists: " + spec.listen_path);
        if (errno != ENOENT) fail("inspect broker socket path");
        if (std::find(paths.begin(), paths.end(), spec.listen_path) != paths.end())
            throw std::runtime_error("duplicate broker listen path");
        paths.push_back(spec.listen_path);
    }
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC) < 0) fail("create socket broker startup pipe");
    Fd status_read(pipe_fds[0]), status_write(pipe_fds[1]);
    move_above_stdio(status_read); move_above_stdio(status_write);
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) fail("fork socket controller");
    if (child == 0) broker_main(sockets, status_write.get(), parent);
    status_write.reset();
    try {
        broker_paths.emplace(child, std::move(paths));
        wait_startup(status_read.get(), child, false, "socket controller");
    } catch (...) {
        stop_child(child);
        throw;
    }
    return child;
}

pid_t start_socket_broker(const std::string& listen_path, const std::string& upstream_path) {
    return start_socket_brokers({{listen_path, upstream_path, ""}});
}
}
