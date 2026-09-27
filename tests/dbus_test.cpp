#include "agent_vm/runtime.hpp"
#include "../src/landlock.hpp"
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {

bool denied(int result) { return result < 0 && (errno == EACCES || errno == EPERM); }

int bind_socket(const std::filesystem::path& path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    const std::string name = path.string();
    if (name.size() >= sizeof(address.sun_path)) { close(fd); errno = ENAMETOOLONG; return -1; }
    std::memcpy(address.sun_path, name.c_str(), name.size() + 1);
    if (bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0) return fd;
    const int error = errno;
    close(fd);
    errno = error;
    return -1;
}

void check_proxy_profile(const std::filesystem::path& root,
                         const std::filesystem::path& private_dir) {
    if (avm::detail::landlock_abi() < 3) return;
    const auto outside = root / "outside";
    int fixture = open(outside.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fixture < 0) throw std::runtime_error("create D-Bus profile fixture");
    close(fixture);
    pid_t child = fork();
    if (child < 0) throw std::runtime_error("fork D-Bus profile check");
    if (child == 0) {
        try {
            int directory = open(private_dir.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
            if (directory < 0) _exit(2);
            if (!avm::confine_dbus_proxy_filesystem(directory)) _exit(3);
            close(directory);
            int fd = open("/usr/bin/xdg-dbus-proxy", O_RDONLY | O_CLOEXEC);
            if (fd < 0) _exit(4);
            close(fd);
            if (!denied(open(outside.c_str(), O_RDONLY | O_CLOEXEC))) _exit(5);
            if (!denied(open(outside.c_str(), O_WRONLY | O_CLOEXEC))) _exit(6);
            if (!denied(open((private_dir / "regular").c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600)))
                _exit(7);
            const auto allowed_socket = private_dir / "profile.sock";
            fd = bind_socket(allowed_socket);
            if (fd < 0) _exit(8);
            close(fd);
            if (unlink(allowed_socket.c_str()) < 0) _exit(9);
            if (!denied(bind_socket(root / "forbidden.sock"))) _exit(10);
            _exit(0);
        } catch (...) { _exit(11); }
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
        throw std::runtime_error("D-Bus filesystem profile check failed at step " +
                                 std::to_string(WIFEXITED(status) ? WEXITSTATUS(status) : -1));
}

} // namespace

int main() {
    if (access("/usr/bin/xdg-dbus-proxy", X_OK)) {
        std::cout << "SKIP: xdg-dbus-proxy not installed\n";
        return 77;
    }
    char pattern[] = "/tmp/avm-dbus-test-XXXXXX";
    char* directory = mkdtemp(pattern);
    if (!directory) return 1;
    std::filesystem::path root(directory);
    avm::NetworkProcess proxy;
    try {
        const auto private_dir = root / "dbus-user";
        std::filesystem::create_directory(private_dir);
        std::filesystem::permissions(private_dir, std::filesystem::perms::owner_all,
                                     std::filesystem::perm_options::replace);
        const auto socket_path = private_dir / "bus";
        avm::DbusSpec spec;
        spec.address = "unix:path=" + (root / "missing-upstream").string();
        proxy = avm::start_dbus_proxy(spec, socket_path.string());
        if (!std::filesystem::is_socket(socket_path)) throw std::runtime_error("readiness before socket creation");
        close(proxy.fd); proxy.fd = -1;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        int status;
        for (;;) {
            if (waitpid(proxy.pid, &status, WNOHANG) == proxy.pid) { proxy.pid = -1; break; }
            if (std::chrono::steady_clock::now() >= deadline) throw std::runtime_error("proxy did not exit when lifetime FD closed");
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status)) throw std::runtime_error("proxy lifetime shutdown failed");
        spec.args = {"--not-a-real-option"};
        bool rejected = false;
        try { proxy = avm::start_dbus_proxy(spec, (private_dir / "invalid").string()); }
        catch (const std::exception&) { rejected = true; }
        if (!rejected) throw std::runtime_error("invalid proxy argument did not fail startup");
        if (waitpid(-1, nullptr, WNOHANG) != -1 || errno != ECHILD) throw std::runtime_error("startup failure left a child");

        // A shared output directory must never become a Landlock write grant.
        spec.args.clear();
        const auto shared_dir = root / "shared";
        std::filesystem::create_directory(shared_dir);
        std::filesystem::permissions(shared_dir,
                                     std::filesystem::perms::owner_all |
                                     std::filesystem::perms::group_read |
                                     std::filesystem::perms::group_exec,
                                     std::filesystem::perm_options::replace);
        rejected = false;
        try { proxy = avm::start_dbus_proxy(spec, (shared_dir / "bus").string()); }
        catch (const std::exception&) { rejected = true; }
        if (!rejected) throw std::runtime_error("proxy accepted a shared output directory");

        check_proxy_profile(root, private_dir);

        std::filesystem::remove_all(root);
        std::cout << "D-Bus helper tests passed: readiness, lifetime FD, startup failure and filesystem profile\n";
        return 0;
    } catch (const std::exception& error) {
        avm::stop_child(proxy.pid);
        if (proxy.fd >= 0) close(proxy.fd);
        std::filesystem::remove_all(root);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
