#include "agent_vm/runtime.hpp"
#include "agent_vm/protocol.h"
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
namespace avm {
namespace {
struct Fd {
    int value;
    explicit Fd(int fd) : value(fd) {}
    ~Fd() { if (value >= 0) close(value); }
};
}
bool send_control(int directory, const avm_control_message& message) {
    Fd endpoint(openat(directory, "control.sock", O_PATH | O_NOFOLLOW | O_CLOEXEC));
    struct stat st{};
    if (endpoint.value < 0 || fstat(endpoint.value, &st) || !S_ISSOCK(st.st_mode)) return false;
    // Keep the inode pinned through connect. Never re-resolve a mutable name.
    const std::string path = "/proc/self/fd/" + std::to_string(endpoint.value);
    Fd fd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    if (fd.value < 0) return false;
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    int result = connect(fd.value, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    if (result && errno != EINPROGRESS) return false;
    pollfd p{fd.value, POLLOUT, 0};
    if (poll(&p, 1, 100) <= 0) return false;
    int error = 0; socklen_t size = sizeof(error);
    if (getsockopt(fd.value, SOL_SOCKET, SO_ERROR, &error, &size) || error) return false;
    if (send(fd.value, &message, sizeof(message), MSG_NOSIGNAL) != sizeof(message)) return false;
    // Do not close the Unix transport until the guest has consumed this message.
    // libkrun 1.19 handles HUP before pending IN and can drop data on early close.
    uint32_t acknowledgement = 0;
    size_t used = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    while (used < sizeof(acknowledgement)) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) return false;
        pollfd incoming{fd.value, POLLIN, 0};
        int ready = poll(&incoming, 1, static_cast<int>(remaining));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return false;
        ssize_t n = recv(fd.value, reinterpret_cast<char*>(&acknowledgement) + used, sizeof(acknowledgement) - used, 0);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (n <= 0) return false;
        used += static_cast<size_t>(n);
    }
    return acknowledgement == AVM_CONTROL_ACK_MAGIC;
}
}
