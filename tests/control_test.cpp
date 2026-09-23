#include "agent_vm/runtime.hpp"
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
namespace fs = std::filesystem;
static void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
struct Directory {
    fs::path path;
    Directory() { char name[] = "/tmp/avm-control-test-XXXXXX"; auto p = mkdtemp(name); require(p, "mkdtemp"); path = p; }
    ~Directory() { std::error_code ec; fs::remove_all(path, ec); }
};
struct Fd {
    int fd;
    explicit Fd(int value) : fd(value) { require(fd >= 0, "open descriptor"); }
    ~Fd() { close(fd); }
};
static int listen_at(const fs::path& path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    require(path.string().size() < sizeof(address.sun_path), "socket path length");
    std::strcpy(address.sun_path, path.c_str());
    require(bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 && listen(fd, 16) == 0, "listen");
    return fd;
}
int main() {
    try {
        Directory fixture;
        fs::create_directory(fixture.path / "ipc");
        Fd directory(open((fixture.path / "ipc").c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC));
        Fd outside(listen_at(fixture.path / "outside.sock"));
        auto endpoint = fixture.path / "ipc/control.sock";
        const avm_control_message message{AVM_CONTROL_MAGIC, AVM_CONTROL_SIGNAL, 2, 0, 0};
        require(!avm::send_control(directory.fd, message), "missing socket accepted");
        fs::create_symlink(fixture.path / "outside.sock", endpoint);
        require(!avm::send_control(directory.fd, message), "absolute symlink accepted");
        fs::remove(endpoint);
        fs::create_symlink("../outside.sock", endpoint);
        require(!avm::send_control(directory.fd, message), "relative symlink accepted");
        fs::remove(endpoint);
        { Fd regular(open(endpoint.c_str(), O_CREAT | O_WRONLY, 0600)); }
        require(!avm::send_control(directory.fd, message), "regular file accepted");
        fs::remove(endpoint);
        fs::create_directory(endpoint);
        require(!avm::send_control(directory.fd, message), "directory accepted");
        fs::remove(endpoint);
        Fd listener(listen_at(endpoint));
        std::atomic<unsigned> received{0};
        std::atomic<bool> bad{false};
        std::jthread server([&](std::stop_token stop) {
            while (!stop.stop_requested()) {
                pollfd p{listener.fd, POLLIN, 0};
                if (poll(&p, 1, 10) <= 0) continue;
                int client = accept4(listener.fd, nullptr, nullptr, SOCK_CLOEXEC);
                if (client < 0) continue;
                avm_control_message input{};
                pollfd incoming{client, POLLIN, 0};
                if (poll(&incoming, 1, 1000) > 0 && recv(client, &input, sizeof(input), MSG_WAITALL) == sizeof(input)) {
                    if (std::memcmp(&input, &message, sizeof(input))) bad = true;
                    ++received;
                    uint32_t ack = AVM_CONTROL_ACK_MAGIC;
                    (void)send(client, &ack, sizeof(ack), MSG_NOSIGNAL);
                }
                close(client);
            }
        });
        require(avm::send_control(directory.fd, message), "valid endpoint failed");
        // Replacing the parent name must not redirect the saved directory FD.
        fs::rename(fixture.path / "ipc", fixture.path / "pinned");
        fs::create_directory(fixture.path / "ipc");
        fs::create_symlink(fixture.path / "outside.sock", endpoint);
        require(avm::send_control(directory.fd, message), "directory pin lost after rename");
        fs::create_symlink(fixture.path / "outside.sock", fixture.path / "pinned/swap");
        std::atomic<bool> rename_failed{false};
        std::jthread racer([&](std::stop_token stop) {
            while (!stop.stop_requested())
                if (syscall(SYS_renameat2, directory.fd, "control.sock", directory.fd, "swap", RENAME_EXCHANGE)) {
                    rename_failed = true; break;
                }
        });
        for (unsigned i = 0; i < 300; ++i) (void)avm::send_control(directory.fd, message);
        racer.request_stop(); racer.join();
        server.request_stop(); server.join();
        require(!rename_failed && !bad && received >= 2, "race fixture or message failed");
        pollfd leaked{outside.fd, POLLIN, 0};
        require(poll(&leaked, 1, 0) == 0, "control connection escaped pinned endpoint");
        std::cout << "control inode pinning and replacement race passed\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
