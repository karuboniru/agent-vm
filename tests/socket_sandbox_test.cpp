#include "../src/socket_sandbox.hpp"

#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include <dirent.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(std::string(message) + ": " + std::to_string(errno));
}
bool denied(long result) { return result == -1 && errno == EPERM; }
bool common_denials(const char* outside) {
    return denied(open(outside, O_RDONLY)) && denied(open("/upstream/0/secret", O_RDONLY)) &&
        denied(syscall(SYS_execve, outside, nullptr, nullptr)) &&
        denied(syscall(SYS_ptrace, PTRACE_TRACEME, 0, nullptr, nullptr)) &&
        denied(unshare(0)) && denied(setns(-1, 0)) &&
        denied(mount(nullptr, "/", nullptr, 0, nullptr)) && denied(chdir("/")) &&
        denied(syscall(SYS_clone, SIGCHLD, nullptr, nullptr, nullptr, 0)) &&
        denied(syscall(SYS_mmap, nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) &&
        denied(syscall(SYS_mprotect, nullptr, 0, PROT_READ | PROT_WRITE | PROT_EXEC)) &&
        denied(syscall(SYS_io_uring_setup, 0, nullptr)) &&
        denied(socket(AF_INET, SOCK_STREAM, 0));
}
int status_of(pid_t child) {
    int status = 0;
    while (waitpid(child, &status, 0) < 0) require(errno == EINTR, "wait child");
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
void inherited_mounts(const std::string& upstream, const std::string& outside) {
    const auto uid = getuid(), gid = getgid();
    require(unshare(CLONE_NEWUSER) == 0, "create fixture user namespace");
    auto mapping = [](const char* path, const std::string& value) {
        std::ofstream file(path);
        file << value;
        file.close();
        require(bool(file), "write fixture identity map");
    };
    mapping("/proc/self/uid_map", std::to_string(uid) + " " + std::to_string(uid) + " 1\n");
    mapping("/proc/self/setgroups", "deny\n");
    mapping("/proc/self/gid_map", std::to_string(gid) + " " + std::to_string(gid) + " 1\n");
    require(unshare(CLONE_NEWNS) == 0 && mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == 0,
            "create fixture mount namespace");
    // These mounts become locked in the helper's nested user namespace, just
    // like doc/gvfs beneath a desktop session's /run/user/UID directory.
    require(mount("tmpfs", (upstream + "/nested mount").c_str(), "tmpfs", 0, "size=64k") == 0,
            "mount inherited directory fixture");
    std::ofstream(upstream + "/nested mount/hidden") << "must not be exposed";
    require(mount(outside.c_str(), (upstream + "/file-mount").c_str(), nullptr, MS_BIND, nullptr) == 0,
            "mount inherited file fixture");
    require(mount((upstream + "/service").c_str(), (upstream + "/service").c_str(), nullptr, MS_BIND, nullptr) == 0,
            "mount authorized socket fixture");
}
}

int main() {
    alarm(20);
    char pattern[] = "/tmp/avm-socket-sandbox-XXXXXX";
    char* temp = mkdtemp(pattern);
    if (!temp) return 1;
    const std::string base = temp, upstream = base + "/source", root = upstream + "/runtime";
    const std::string outside = base + "/outside";
    std::filesystem::create_directory(upstream);
    std::filesystem::create_directory(root);
    std::filesystem::create_directory(upstream + "/nested mount");
    std::ofstream(upstream + "/file-mount") << "underlying file";
    std::ofstream(outside) << "host secret";
    std::ofstream(upstream + "/secret") << "sibling file";
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::snprintf(address.sun_path, sizeof(address.sun_path), "%s/service", upstream.c_str());
    int pair[2];
    try {
        require(listener >= 0 && bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
                listen(listener, 8) == 0, "prepare upstream socket");
        require(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) == 0, "prepare FD channel");
        require(shutdown(pair[0], SHUT_RD) == 0 && shutdown(pair[1], SHUT_WR) == 0, "one-way FD channel");
        pid_t controller = fork();
        require(controller >= 0, "fork controller test");
        if (!controller) {
            try {
                const uid_t uid = getuid(); const gid_t gid = getgid();
                const char* names[]{"user", "mnt", "net", "ipc", "uts"};
                int original[5];
                for (size_t i = 0; i < 5; ++i) {
                    original[i] = open((std::string("/proc/self/ns/") + names[i]).c_str(), O_RDONLY | O_CLOEXEC);
                    require(original[i] >= 0, "pin original namespace");
                }
                inherited_mounts(upstream, outside);
                avm::detail::enter_socket_control_namespace(root, {{upstream, {"service"}}});
                require(getuid() == uid && getgid() == gid, "helper identity changed");
                require(access(outside.c_str(), F_OK) == -1 && errno == ENOENT, "host file remained visible");
                require(access("/proc", F_OK) == -1 && errno == ENOENT, "host proc remained visible");
                require(access("/upstream/0/service", F_OK) == 0, "authorized endpoint missing");
                struct stat masked{};
                require(lstat("/upstream/0/nested mount/hidden", &masked) == -1 && errno == ENOENT,
                        "inherited directory submount leaked");
                require(stat("/upstream/0/file-mount", &masked) == 0 && masked.st_size == 0,
                        "inherited file submount leaked");
                require(access("/upstream/0/runtime/upstream", F_OK) == -1 && errno == ENOENT,
                        "recursive staging mount leaked");
                require(open("/upstream/0/created", O_WRONLY | O_CREAT, 0600) == -1 && errno == EROFS,
                        "upstream parent is writable");
                require(open("/created", O_WRONLY | O_CREAT, 0600) == -1 && errno == EROFS,
                        "helper root is writable");
                // Namespace FDs cannot restore the host view after sealing.
                require(unshare(CLONE_NEWPID) == 0, "create data test PID namespace");
                pid_t data = fork();
                require(data >= 0, "fork data test");
                if (!data) {
                    require(getpid() == 1, "data process is not isolated in PID namespace");
                    avm::detail::enter_socket_data_namespace();
                    DIR* directory = opendir("/");
                    require(directory != nullptr, "open empty root");
                    size_t entries = 0;
                    while (auto* entry = readdir(directory))
                        if (std::string(entry->d_name) != "." && std::string(entry->d_name) != "..") ++entries;
                    closedir(directory);
                    require(entries == 0, "data root is not empty");
                    require(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "set test nnp");
                    avm::detail::seal_socket_data(pair[1], STDERR_FILENO);
                    if (!common_denials(outside.c_str())) _exit(10);
                    if (!denied(socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) ||
                        !denied(connect(listener, nullptr, 0)) || !denied(accept4(listener, nullptr, nullptr, 0)) ||
                        !denied(sendmsg(pair[1], nullptr, MSG_NOSIGNAL)) ||
                        !denied(recvmsg(listener, nullptr, MSG_CMSG_CLOEXEC)) ||
                        !denied(kill(1, 0)) || !denied(setns(original[0], CLONE_NEWUSER))) _exit(11);
                    // Even the control channel rejects specifying a destination.
                    if (!denied(syscall(SYS_sendto, pair[1], nullptr, 0, MSG_NOSIGNAL, &address, sizeof(address)))) _exit(12);
                    // Direction is enforced on the socket itself, not by a
                    // potentially bypassable 64-bit comparison of an int FD.
                    if (send(pair[1], "x", 1, MSG_NOSIGNAL) != -1 || errno != EPIPE) _exit(13);
                    if (syscall(SYS_sendto, (1ULL << 32) | static_cast<unsigned>(pair[1]), "x", 1,
                                MSG_NOSIGNAL, nullptr, 0) != -1 || errno != EPIPE) _exit(14);
                    _exit(0);
                }
                require(status_of(data) == 0, "data isolation policy failed");
                // The controller can still connect to the authorized pathname.
                int remote = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                require(remote >= 0, "create authorized connection");
                std::snprintf(address.sun_path, sizeof(address.sun_path), "/upstream/0/service");
                avm::detail::seal_socket_control({listener}, {pair[0]}, {}, STDERR_FILENO, {data});
                if (!common_denials(outside.c_str())) _exit(20);
                if (connect(remote, reinterpret_cast<sockaddr*>(&address), sizeof(address))) _exit(21);
                if (!denied(recv(remote, nullptr, 0, 0)) || !denied(read(remote, nullptr, 0)) ||
                    !denied(recvmsg(pair[0], nullptr, MSG_CMSG_CLOEXEC)) ||
                    !denied(sendmsg(remote, nullptr, MSG_NOSIGNAL)) || !denied(kill(1, SIGKILL))) _exit(22);
                for (int fd : original) if (!denied(setns(fd, 0))) _exit(23);
                _exit(0);
            } catch (const std::exception& error) { dprintf(2, "%s\n", error.what()); _exit(1); }
        }
        int code = status_of(controller);
        require(code == 0, ("socket sandbox child status " + std::to_string(code)).c_str());
        close(listener); close(pair[0]); close(pair[1]);
        std::filesystem::remove_all(base);
        std::puts("socket sandbox tests passed: empty data root, read-only upstream, PID namespace, syscall boundaries");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        std::filesystem::remove_all(base);
        return 1;
    }
}
