#include "agent_vm/runtime.hpp"
#include "landlock.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cctype>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <fcntl.h>
#include <linux/capability.h>
#include <poll.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace avm {
namespace {

constexpr char waypipe_binary[] = "/usr/bin/waypipe";

class Fd {
public:
    explicit Fd(int fd = -1) : fd_(fd) {}
    ~Fd() { if (fd_ >= 0) close(fd_); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    int get() const { return fd_; }
    void reset(int next = -1) { if (fd_ >= 0) close(fd_); fd_ = next; }
private:
    int fd_;
};

[[noreturn]] void fail(const std::string& operation, int error = errno) {
    throw std::system_error(error, std::generic_category(), operation);
}

struct StartupError { int error; char operation[96]; };

[[noreturn]] void child_fail(int status_fd, const char* operation) {
    StartupError status{errno, {}};
    std::strncpy(status.operation, operation, sizeof(status.operation) - 1);
    const char* data = reinterpret_cast<const char*>(&status);
    size_t remaining = sizeof(status);
    while (remaining) {
        ssize_t written = write(status_fd, data, remaining);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) break;
        data += written;
        remaining -= static_cast<size_t>(written);
    }
    _exit(125);
}

bool reset_signals() {
    sigset_t empty;
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, nullptr)) return false;
    struct sigaction action {};
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    for (int signal = 1; signal < NSIG; ++signal) {
        if (signal == SIGKILL || signal == SIGSTOP) continue;
        if (sigaction(signal, &action, nullptr) && errno != EINVAL) return false;
    }
    action.sa_handler = SIG_IGN;
    return sigaction(SIGTTIN, &action, nullptr) == 0 &&
           sigaction(SIGTTOU, &action, nullptr) == 0;
}

bool close_except(int status_fd, int directory_fd) {
    const int first = std::min(status_fd, directory_fd);
    const int second = std::max(status_fd, directory_fd);
    bool fallback = false;
    unsigned int start = 3;
    for (int fd : {first, second}) {
        if (fd < 3) continue;
        if (start < static_cast<unsigned int>(fd) &&
            syscall(SYS_close_range, start, static_cast<unsigned int>(fd - 1), 0)) {
            if (errno != ENOSYS && errno != EINVAL) return false;
            fallback = true;
            break;
        }
        start = static_cast<unsigned int>(fd) + 1;
    }
    if (!fallback && syscall(SYS_close_range, start, UINT_MAX, 0) == 0) return true;
    if (!fallback && errno != ENOSYS && errno != EINVAL) return false;
    struct rlimit limit {};
    if (getrlimit(RLIMIT_NOFILE, &limit)) return false;
    for (int fd = 3; static_cast<rlim_t>(fd) < std::min<rlim_t>(limit.rlim_max, INT_MAX); ++fd)
        if (fd != status_fd && fd != directory_fd) close(fd);
    return true;
}

bool write_map(const char* path, const std::string& value) {
    Fd fd(open(path, O_WRONLY | O_CLOEXEC));
    if (fd.get() < 0) return false;
    const char* data = value.data();
    size_t remaining = value.size();
    while (remaining) {
        ssize_t count = write(fd.get(), data, remaining);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        data += count;
        remaining -= static_cast<size_t>(count);
    }
    return true;
}

void isolate_network(int status_fd) {
    const uid_t uid = getuid();
    const gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER)) child_fail(status_fd, "create waypipe user namespace");
    if (!write_map("/proc/self/uid_map", std::to_string(uid) + " " + std::to_string(uid) + " 1\n"))
        child_fail(status_fd, "map waypipe user ID");
    if (!write_map("/proc/self/setgroups", "deny\n")) child_fail(status_fd, "disable waypipe setgroups");
    if (!write_map("/proc/self/gid_map", std::to_string(gid) + " " + std::to_string(gid) + " 1\n"))
        child_fail(status_fd, "map waypipe group ID");
    if (unshare(CLONE_NEWNET)) child_fail(status_fd, "isolate waypipe network");
}

void drop_privileges(int status_fd) {
    for (int cap = 0; ; ++cap) {
        int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (present < 0 && errno == EINVAL) break;
        if (present < 0 || (present && prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)))
            child_fail(status_fd, "clear waypipe capability bounding set");
    }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))
        child_fail(status_fd, "clear waypipe ambient capabilities");
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    __user_cap_data_struct data[2]{};
    if (syscall(SYS_capset, &header, data) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        child_fail(status_fd, "drop waypipe capabilities");
}

void confine_gpu(detail::LandlockRuleset& rules) {
    constexpr std::uint64_t read = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    namespace fs = std::filesystem;
    // The directory grants enumeration only. Every device grant is pinned to
    // an O_PATH FD after checking both its name and kernel device number.
    rules.add_path("/dev/dri", LANDLOCK_ACCESS_FS_READ_DIR);
    size_t count = 0;
    for (const auto& entry : fs::directory_iterator("/dev/dri")) {
        const std::string name = entry.path().filename().string();
        constexpr std::string_view prefix = "renderD";
        if (!name.starts_with(prefix)) continue;
        const std::string digits = name.substr(prefix.size());
        if (digits.empty() || !std::all_of(digits.begin(), digits.end(), [](unsigned char ch) {
                return std::isdigit(ch);
            }))
            throw std::runtime_error("invalid DRM render node name: " + name);
        Fd node(open(entry.path().c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
        if (node.get() < 0) fail("pin DRM render node " + name);
        struct stat info {};
        if (fstat(node.get(), &info)) fail("inspect DRM render node " + name);
        if (!S_ISCHR(info.st_mode) || major(info.st_rdev) != 226 || minor(info.st_rdev) < 128 ||
            digits != std::to_string(minor(info.st_rdev)))
            throw std::runtime_error("invalid DRM render node: " + name);
        rules.add_fd(node.get(), LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE);
        ++count;

        // libdrm and Mesa follow these sysfs links to identify the driver.
        // Resolve them before confinement, and grant read rights only to the
        // selected device, its driver, and its module metadata.
        const fs::path device_link = "/sys/dev/char/226:" + digits + "/device";
        const fs::path device = fs::canonical(device_link);
        auto within = [](const fs::path& path, const fs::path& root) {
            return path != root && path.string().starts_with(root.string() + "/");
        };
        if (!within(device, "/sys/devices"))
            throw std::runtime_error("DRM sysfs device leaves /sys/devices: " + device.string());
        rules.add_path(device.string(), read);
        const fs::path driver_link = device_link / "driver";
        if (fs::exists(driver_link)) {
            const fs::path driver = fs::canonical(driver_link);
            if (!within(driver, "/sys/bus") || driver.string().find("/drivers/") == std::string::npos)
                throw std::runtime_error("DRM driver metadata has an unexpected location");
            rules.add_path(driver.string(), read);
            const fs::path module_link = driver_link / "module";
            if (fs::exists(module_link)) {
                const fs::path module = fs::canonical(module_link);
                if (!within(module, "/sys/module"))
                    throw std::runtime_error("DRM driver module has an unexpected location");
                rules.add_path(module.string(), read);
            }
        }
    }
    if (!count) throw std::runtime_error("GPU forwarding requires a DRM render node under /dev/dri");
}

void confine_filesystem(int directory_fd, const std::string& display, bool gpu, int status_fd) {
    try {
        const int abi = detail::landlock_abi();
        if (abi < 3) throw std::runtime_error("Landlock ABI 3 is required for waypipe confinement");
        detail::LandlockRuleset rules(detail::fs_rights_for_abi(abi));
        const std::uint64_t read = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
        auto add = [&](const char* path, std::uint64_t rights, bool optional) {
            try { rules.add_path(path, rights); }
            catch (const std::system_error& error) {
                if (optional && error.code() == std::errc::no_such_file_or_directory) return;
                throw;
            }
        };
        add("/usr", read, false);
        add("/lib", read, true);
        add("/lib64", read, true);
        add(waypipe_binary, LANDLOCK_ACCESS_FS_EXECUTE, false);
        for (const char* loader : {
                 "/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-x86-64.so.2",
                 "/lib/ld-linux-aarch64.so.1", "/lib64/ld-linux-aarch64.so.1"})
            add(loader, LANDLOCK_ACCESS_FS_EXECUTE, true);
        for (const char* path : {
                 "/etc/ld.so.cache", "/etc/nsswitch.conf", "/etc/passwd", "/etc/group",
                 "/etc/hosts", "/etc/host.conf", "/etc/gai.conf", "/etc/resolv.conf",
                 "/etc/services", "/etc/protocols", "/etc/machine-id", "/etc/localtime",
                 "/sys/devices/system/cpu/online"})
            add(path, LANDLOCK_ACCESS_FS_READ_FILE, true);
        add("/dev/null", LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE, false);
        add("/dev/urandom", LANDLOCK_ACCESS_FS_READ_FILE, true);
        if (gpu) confine_gpu(rules);
        rules.add_fd(directory_fd, LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                                    LANDLOCK_ACCESS_FS_REMOVE_FILE);
        rules.enforce();
        // ABI 9 limits pathname Unix connects to the chosen compositor. The
        // first layer above already limits filesystem writes on older kernels.
        detail::enforce_unix_socket_allowlist({display});
    } catch (const std::exception& error) {
        // A descriptive message fits in the fixed startup record.
        StartupError status{EACCES, {}};
        std::strncpy(status.operation, error.what(), sizeof(status.operation) - 1);
        (void)write(status_fd, &status, sizeof(status));
        _exit(125);
    }
}

void child_main(int status_fd, int directory_fd, pid_t parent,
                const std::string& display, const std::string& path,
                const std::string& directory, bool gpu) {
    if (!reset_signals()) child_fail(status_fd, "reset waypipe signals");
    if (setpgid(0, 0)) child_fail(status_fd, "separate waypipe process group");
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent)
        child_fail(status_fd, "set waypipe parent-death signal");
    if (!close_except(status_fd, directory_fd)) child_fail(status_fd, "close waypipe descriptors");
    if (fchdir(directory_fd)) child_fail(status_fd, "enter private waypipe directory");
    Fd input(open("/dev/null", O_RDONLY | O_CLOEXEC));
    if (input.get() < 0 || dup2(input.get(), STDIN_FILENO) < 0) child_fail(status_fd, "redirect waypipe stdin");
    if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0) child_fail(status_fd, "redirect waypipe output");
    isolate_network(status_fd);
    // A credential transition can clear PDEATHSIG. Reassert it after entering
    // the user namespace, then close the race with a parent PID check.
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent)
        child_fail(status_fd, "restore waypipe parent-death signal");
    drop_privileges(status_fd);
    umask(0077);
    confine_filesystem(directory_fd, display, gpu, status_fd);
    close(directory_fd);
    std::string socket_option = "--socket=" + path;
    char* argv[] = {const_cast<char*>(waypipe_binary),
                    const_cast<char*>("--compress"), const_cast<char*>("none"),
                    gpu ? socket_option.data() : const_cast<char*>("--no-gpu"),
                    gpu ? const_cast<char*>("client") : socket_option.data(),
                    gpu ? nullptr : const_cast<char*>("client"), nullptr};
    std::string display_env = "WAYLAND_DISPLAY=" + display;
    std::string runtime_env = "XDG_RUNTIME_DIR=" + directory;
    char path_env[] = "PATH=/usr/bin:/bin", locale_env[] = "LC_ALL=C";
    char* environment[] = {display_env.data(), runtime_env.data(), path_env, locale_env, nullptr};
    execve(waypipe_binary, argv, environment);
    child_fail(status_fd, "execute /usr/bin/waypipe");
}

void validate_socket_path(const std::string& path, const char* name) {
    if (path.empty() || path.front() != '/' || path.find('\0') != std::string::npos)
        throw std::runtime_error(std::string(name) + " must be an absolute Unix socket path");
    sockaddr_un address {};
    if (path.size() >= sizeof(address.sun_path))
        throw std::runtime_error(std::string(name) + " exceeds the Unix socket path limit");
}

} // namespace

pid_t start_waypipe(const std::string& display, const std::string& path, bool gpu) {
    validate_socket_path(display, "Wayland display");
    validate_socket_path(path, "waypipe transport");
    if (access(waypipe_binary, X_OK)) fail("waypipe requires /usr/bin/waypipe");
    struct stat info {};
    if (lstat(display.c_str(), &info)) fail("inspect Wayland compositor socket");
    if (!S_ISSOCK(info.st_mode) || info.st_uid != geteuid())
        throw std::runtime_error("Wayland display must be a socket owned by this user");
    const auto directory = std::filesystem::path(path).parent_path().string();
    Fd directory_fd(open(directory.c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (directory_fd.get() < 0) fail("open private waypipe directory");
    if (fstat(directory_fd.get(), &info)) fail("inspect private waypipe directory");
    if (info.st_uid != geteuid() || (info.st_mode & 07777) != 0700)
        throw std::runtime_error("waypipe socket parent must be owned by this user and mode 0700");
    if (lstat(path.c_str(), &info) == 0)
        throw std::runtime_error("waypipe transport socket already exists: " + path);
    if (errno != ENOENT) fail("inspect waypipe transport path");
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC | O_NONBLOCK)) fail("create waypipe startup pipe");
    Fd status_read(pipe_fds[0]), status_write(pipe_fds[1]);
    // Keep the report pipe out of stdio even when the caller closed a stream.
    for (Fd* fd : {&status_read, &status_write, &directory_fd}) {
        if (fd->get() >= 3) continue;
        int moved = fcntl(fd->get(), F_DUPFD_CLOEXEC, 3);
        if (moved < 0) fail("move waypipe startup descriptor");
        fd->reset(moved);
    }
    const pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) fail("fork waypipe");
    if (child == 0) child_main(status_write.get(), directory_fd.get(), parent, display, path, directory, gpu);
    status_write.reset();
    directory_fd.reset();
    try {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        bool execed = false;
        StartupError startup {};
        size_t used = 0;
        while (std::chrono::steady_clock::now() < deadline) {
            if (!execed) {
                pollfd event {status_read.get(), POLLIN, 0};
                int result = poll(&event, 1, 25);
                if (result < 0 && errno != EINTR) fail("wait for waypipe startup");
                if (result > 0 && (event.revents & (POLLIN | POLLHUP))) {
                    ssize_t count = read(status_read.get(), reinterpret_cast<char*>(&startup) + used,
                                         sizeof(startup) - used);
                    if (count > 0) used += static_cast<size_t>(count);
                    else if (count == 0) {
                        if (used) throw std::runtime_error("incomplete waypipe startup report");
                        execed = true;
                        status_read.reset();
                    } else if (errno != EAGAIN && errno != EINTR) fail("read waypipe startup report");
                    if (used == sizeof(startup))
                        fail(std::string("waypipe: ") + startup.operation, startup.error);
                }
            } else {
                (void)poll(nullptr, 0, 25);
            }
            int status = 0;
            pid_t result = waitpid(child, &status, WNOHANG);
            if (result == child) {
                child = -1;
                const std::string reason = WIFEXITED(status)
                    ? "exit status " + std::to_string(WEXITSTATUS(status))
                    : "signal " + std::to_string(WTERMSIG(status));
                throw std::runtime_error("waypipe exited before readiness (" + reason + ")");
            }
            if (result < 0 && errno != EINTR) fail("wait for waypipe readiness");
            if (execed && lstat(path.c_str(), &info) == 0) {
                if (!S_ISSOCK(info.st_mode) || info.st_uid != geteuid())
                    throw std::runtime_error("waypipe transport path is not an owned socket");
                return child;
            }
            if (execed && errno != ENOENT) fail("inspect waypipe readiness socket");
        }
        throw std::runtime_error("waypipe timed out before creating its transport socket");
    } catch (...) {
        stop_child(child);
        // Only a new path can have appeared after the initial ENOENT check.
        unlink(path.c_str());
        throw;
    }
}

} // namespace avm
