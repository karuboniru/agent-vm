#include "../src/landlock.hpp"
#include "agent_vm/runtime.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <stdexcept>
#include <string>
#include <system_error>

#include <fcntl.h>
#include <seccomp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

void require(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}

void write_file(const fs::path& path, const char* contents) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    require(fd >= 0, "create fixture file");
    ssize_t size = static_cast<ssize_t>(std::strlen(contents));
    require(write(fd, contents, size) == size, "write fixture file");
    require(close(fd) == 0, "close fixture file");
}

void in_child(const char* name, const std::function<void()>& test) {
    pid_t child = fork();
    require(child >= 0, "fork Landlock test");
    if (child == 0) {
        try {
            test();
            _exit(0);
        } catch (const std::exception& error) {
            std::fprintf(stderr, "%s: %s\n", name, error.what());
            _exit(1);
        }
    }
    int status = 0;
    require(waitpid(child, &status, 0) == child, "wait Landlock test");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0, name);
}

bool denied(int result) {
    return result < 0 && (errno == EACCES || errno == EPERM);
}

int listener(const fs::path& path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "create Unix listener");
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    require(path.string().size() < sizeof(address.sun_path), "Unix socket fixture path length");
    std::strcpy(address.sun_path, path.c_str());
    require(bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0,
            "bind Unix listener");
    require(listen(fd, 2) == 0, "listen Unix socket");
    return fd;
}

int connect_to(const fs::path& path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "create Unix client");
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::strcpy(address.sun_path, path.c_str());
    int result = connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    int error = errno;
    close(fd);
    errno = error;
    return result;
}

} // namespace

int main() {
    try {
        for (int error : {ENOSYS, EOPNOTSUPP, EPERM}) {
            in_child("Landlock availability and error handling", [=] {
                scmp_filter_ctx filter = seccomp_init(SCMP_ACT_ALLOW);
                require(filter != nullptr, "allocate Landlock error injection filter");
                require(seccomp_rule_add(filter, SCMP_ACT_ERRNO(error),
                                        SCMP_SYS(landlock_create_ruleset), 0) == 0 &&
                        seccomp_load(filter) == 0, "install Landlock error injection filter");
                seccomp_release(filter);
                bool threw = false;
                try {
                    require(avm::detail::landlock_abi() == 0, "unavailable Landlock reported supported");
                    require(!avm::detail::enforce_unix_socket_allowlist({}),
                            "unavailable socket policy reported enforced");
                    require(!avm::confine_supervisor_filesystem("/tmp/unused"),
                            "unavailable filesystem policy reported enforced");
                } catch (const std::system_error& failure) {
                    require(failure.code().value() == error, "Landlock query lost errno");
                    threw = true;
                }
                require(threw == (error == EPERM), "unexpected Landlock error silently downgraded");
            });
        }
        const int abi = avm::detail::landlock_abi();
        if (abi < 3) {
            std::puts("SKIP: Landlock ABI 3 unavailable");
            return 77;
        }
        require((avm::detail::fs_rights_for_abi(1) & LANDLOCK_ACCESS_FS_TRUNCATE) == 0,
                "ABI 1 includes unsupported truncate right");
        require((avm::detail::fs_rights_for_abi(2) & LANDLOCK_ACCESS_FS_REFER) != 0,
                "ABI 2 omits refer right");
        require((avm::detail::fs_rights_for_abi(3) & LANDLOCK_ACCESS_FS_TRUNCATE) != 0,
                "ABI 3 omits truncate right");
        require((avm::detail::fs_rights_for_abi(abi) & LANDLOCK_ACCESS_FS_IOCTL_DEV) == 0,
                "terminal ioctl right unexpectedly handled");

        char pattern[] = "/tmp/avm-landlock-XXXXXX";
        char* directory = mkdtemp(pattern);
        require(directory != nullptr, "create Landlock fixture directory");
        const fs::path root(directory);
        try {
            fs::create_directories(root / "allowed");
            fs::create_directories(root / "outside");
            write_file(root / "allowed" / "read", "inside");
            write_file(root / "outside" / "read", "outside");

            in_child("basic filesystem confinement", [&] {
                int inherited = open((root / "outside" / "read").c_str(), O_RDWR | O_CLOEXEC);
                require(inherited >= 0, "preopen outside file");
                avm::detail::LandlockRuleset rules(avm::detail::fs_rights_for_abi(abi));
                rules.add_path((root / "allowed").string(), avm::detail::fs_rights_for_abi(abi));
                rules.enforce();

                int fd = open((root / "allowed" / "read").c_str(), O_RDONLY | O_CLOEXEC);
                require(fd >= 0, "allowed file read");
                close(fd);
                fd = open((root / "allowed" / "created").c_str(),
                          O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
                require(fd >= 0, "allowed file create");
                close(fd);
                require(unlink((root / "allowed" / "created").c_str()) == 0,
                        "allowed file removal");

                require(denied(open((root / "outside" / "read").c_str(), O_RDONLY | O_CLOEXEC)),
                        "outside read allowed");
                require(denied(open((root / "outside" / "read").c_str(), O_WRONLY | O_CLOEXEC)),
                        "outside write allowed");
                require(denied(open((root / "outside" / "created").c_str(),
                                    O_WRONLY | O_CREAT | O_CLOEXEC, 0600)),
                        "outside create allowed");
                char byte = 0;
                require(read(inherited, &byte, 1) == 1 && byte == 'o',
                        "preopened file read lost after confinement");
                require(write(inherited, "!", 1) == 1 && ftruncate(inherited, 1) == 0,
                        "preopened file write/truncate lost after confinement");
                close(inherited);
            });

            in_child("truncate right on newly opened file", [&] {
                avm::detail::LandlockRuleset rules(LANDLOCK_ACCESS_FS_WRITE_FILE |
                                                   LANDLOCK_ACCESS_FS_TRUNCATE);
                rules.add_path((root / "allowed" / "read").string(), LANDLOCK_ACCESS_FS_WRITE_FILE);
                rules.enforce();
                int fd = open((root / "allowed" / "read").c_str(), O_WRONLY | O_CLOEXEC);
                require(fd >= 0, "open write-only file without truncate right");
                require(denied(ftruncate(fd, 0)), "new file descriptor bypassed truncate right");
                close(fd);
            });

            fs::create_directories(root / "runtime" / "nested");
            write_file(root / "runtime" / "nested" / "stale", "cleanup");
            write_file(root / "outside" / "keep", "secret");
            in_child("supervisor cleanup policy", [&] {
                require(avm::confine_supervisor_filesystem((root / "runtime").string()),
                        "supervisor policy not installed");
                require(denied(open((root / "outside" / "keep").c_str(), O_RDONLY | O_CLOEXEC)),
                        "supervisor read outside runtime");
                require(denied(open((root / "outside" / "keep").c_str(), O_WRONLY | O_CLOEXEC)),
                        "supervisor write outside runtime");
                require(denied(unlink((root / "outside" / "keep").c_str())),
                        "supervisor removed sibling file");
                require(denied(mkdir((root / "outside" / "new").c_str(), 0700)),
                        "supervisor created sibling directory");
                char* const args[] = {const_cast<char*>("/bin/true"), nullptr};
                char* const environment[] = {nullptr};
                require(denied(execve("/bin/true", args, environment)),
                        "supervisor executed a new program");
                avm::cleanup_runtime_directory((root / "runtime").string());
                require(!fs::exists(root / "runtime"),
                        "supervisor could not recursively clean runtime directory");
            });

            if (abi >= 9) {
                const fs::path allowed_socket = root / "allowed.sock";
                const fs::path denied_socket = root / "denied.sock";
                int allowed_listener = listener(allowed_socket);
                int denied_listener = listener(denied_socket);
                in_child("ABI 9 pathname Unix socket whitelist", [&] {
                    require(avm::detail::enforce_unix_socket_allowlist({allowed_socket.string()}),
                            "socket whitelist unavailable on ABI 9");
                    require(connect_to(allowed_socket) == 0, "whitelisted Unix socket denied");
                    require(denied(connect_to(denied_socket)), "other Unix socket reachable");
                    // This ruleset only handles socket lookup and REFER; it
                    // must not quietly turn into a filesystem access policy.
                    int fd = open((root / "outside" / "keep").c_str(), O_RDONLY | O_CLOEXEC);
                    require(fd >= 0, "socket policy blocked ordinary file read");
                    close(fd);
                    require(rename((root / "outside" / "keep").c_str(),
                                   (root / "allowed" / "renamed").c_str()) == 0,
                            "socket policy blocked cross-directory rename");
                });
                close(allowed_listener);
                close(denied_listener);
            }
        } catch (...) {
            fs::remove_all(root);
            throw;
        }
        fs::remove_all(root);
        std::puts("Landlock filesystem, supervisor and Unix socket tests passed");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "Landlock test: %s\n", error.what());
        return 1;
    }
}
