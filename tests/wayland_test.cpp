#include "agent_vm/runtime.hpp"
#include "../src/landlock.hpp"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <system_error>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<class Function> void expect_failure(Function function, const char* message) {
    try { function(); } catch (const std::exception&) { return; }
    throw std::runtime_error(message);
}

std::string read_file(const std::string& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("cannot read " + path);
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

std::string namespace_id(const std::string& path) {
    char buffer[128];
    ssize_t length = readlink(path.c_str(), buffer, sizeof(buffer));
    if (length < 0) throw std::runtime_error("cannot inspect network namespace");
    return {buffer, static_cast<size_t>(length)};
}

int bind_socket(const std::string& path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) throw std::runtime_error("create compositor socket");
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    if (path.size() >= sizeof(address.sun_path)) {
        close(fd);
        throw std::runtime_error("test compositor socket path too long");
    }
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) || listen(fd, 4)) {
        close(fd);
        throw std::runtime_error("bind compositor socket");
    }
    return fd;
}

bool render_node_available() {
    if (!std::filesystem::exists("/dev/dri")) return false;
    for (const auto& entry : std::filesystem::directory_iterator("/dev/dri")) {
        struct stat info {};
        if (lstat(entry.path().c_str(), &info) == 0 && S_ISCHR(info.st_mode) &&
            major(info.st_rdev) == 226 && minor(info.st_rdev) >= 128 &&
            entry.path().filename() == ("renderD" + std::to_string(minor(info.st_rdev))))
            return true;
    }
    return false;
}

} // namespace

int main() {
    if (access("/usr/bin/waypipe", X_OK)) {
        std::cout << "SKIP: waypipe not installed\n";
        return 77;
    }
    if (avm::detail::landlock_abi() < 3) {
        std::cout << "SKIP: Landlock ABI 3 unavailable\n";
        return 77;
    }
    char pattern[] = "/tmp/avm-waypipe-test-XXXXXX";
    char* created = mkdtemp(pattern);
    if (!created) return 1;
    const std::filesystem::path root(created);
    const auto private_dir = root / "private";
    const auto shared_dir = root / "shared";
    std::filesystem::create_directory(private_dir);
    std::filesystem::create_directory(shared_dir);
    std::filesystem::permissions(private_dir, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    std::filesystem::permissions(shared_dir,
                                 std::filesystem::perms::owner_all |
                                 std::filesystem::perms::group_read |
                                 std::filesystem::perms::group_exec,
                                 std::filesystem::perm_options::replace);
    const std::string display = (root / "display").string();
    const std::string transport = (private_dir / "transport").string();
    int compositor = -1;
    pid_t helper = -1;
    try {
        compositor = bind_socket(display);
        expect_failure([&] { avm::start_waypipe("relative-display", transport); },
                       "accepted relative compositor path");
        expect_failure([&] { avm::start_waypipe(display, (shared_dir / "transport").string()); },
                       "accepted shared transport directory");
        expect_failure([&] { avm::start_waypipe(display, (root / "missing/transport").string()); },
                       "accepted missing transport directory");
        std::filesystem::create_directory(private_dir / "regular");
        expect_failure([&] { avm::start_waypipe(display, (private_dir / "regular").string()); },
                       "accepted occupied transport path");

        try { helper = avm::start_waypipe(display, transport); }
        catch (const std::system_error& error) {
            if (error.code() == std::errc::operation_not_permitted &&
                std::string(error.what()).find("waypipe user namespace") != std::string::npos) {
                close(compositor);
                std::filesystem::remove_all(root);
                std::cout << "SKIP: user namespaces unavailable\n";
                return 77;
            }
            throw;
        }
        require(std::filesystem::is_socket(transport), "waypipe returned before binding transport socket");
        const auto argv = read_file("/proc/" + std::to_string(helper) + "/cmdline");
        require(argv.find("--no-gpu") != std::string::npos,
                "waypipe without GPU did not disable DMABUF forwarding");
        const auto status = read_file("/proc/" + std::to_string(helper) + "/status");
        require(status.find("NoNewPrivs:\t1") != std::string::npos,
                "waypipe lacks no_new_privs");
        require(status.find("CapEff:\t0000000000000000") != std::string::npos,
                "waypipe kept effective capabilities");
        require(namespace_id("/proc/self/ns/net") !=
                namespace_id("/proc/" + std::to_string(helper) + "/ns/net"),
                "waypipe did not enter an isolated network namespace");
        const auto environment = read_file("/proc/" + std::to_string(helper) + "/environ");
        require(environment.find("WAYLAND_DISPLAY=" + display + '\0') != std::string::npos,
                "waypipe did not receive the selected display");
        require(environment.find("XDG_RUNTIME_DIR=" + private_dir.string() + '\0') != std::string::npos,
                "waypipe runtime directory is not private");
        require(environment.find("HOME=") == std::string::npos,
                "waypipe inherited the caller environment");
        avm::stop_child(helper);
        helper = -1;
        if (render_node_available()) {
            const std::string gpu_transport = (private_dir / "gpu-transport").string();
            helper = avm::start_waypipe(display, gpu_transport, true);
            require(std::filesystem::is_socket(gpu_transport),
                    "GPU waypipe returned before binding transport socket");
            const auto gpu_argv = read_file("/proc/" + std::to_string(helper) + "/cmdline");
            require(gpu_argv.find("--no-gpu") == std::string::npos,
                    "GPU waypipe still blocks DMABUF forwarding");
            avm::stop_child(helper);
            helper = -1;
        }
        require(waitpid(-1, nullptr, WNOHANG) == -1 && errno == ECHILD,
                "waypipe stop left a child process");
        close(compositor);
        std::filesystem::remove_all(root);
        std::cout << "Waypipe helper tests passed: validation, readiness, confinement and lifecycle\n";
        return 0;
    } catch (const std::exception& error) {
        avm::stop_child(helper);
        if (compositor >= 0) close(compositor);
        std::filesystem::remove_all(root);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
