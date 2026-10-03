#include "agent_vm/runtime.hpp"
#include "landlock.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>
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
                         Stdin, Output, Exec, DbusSandbox };
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
    case Stage::DbusSandbox: return "confine D-Bus proxy";
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
    // Keep helper descriptors out of standard-stream slots even if the caller closed them.
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

bool confine_dbus_proxy_filesystem(int private_directory) {
    struct stat directory_stat {};
    if (fstat(private_directory, &directory_stat) < 0)
        fail("inspect private D-Bus proxy directory");
    if (!S_ISDIR(directory_stat.st_mode) || directory_stat.st_uid != geteuid() ||
        (directory_stat.st_mode & 07777) != 0700)
        throw std::runtime_error("D-Bus proxy socket parent must be owned by this user and mode 0700");
    // ABI 3 handles TRUNCATE. Earlier ABIs cannot deny truncation through a
    // newly opened file, so they are treated as unavailable for this profile.
    const int abi = detail::landlock_abi();
    if (abi < 3) return false;
    const std::uint64_t handled = detail::fs_rights_for_abi(abi);
    detail::LandlockRuleset rules(handled);
    const std::uint64_t read = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    const auto add = [&](const char* name, std::uint64_t rights, bool optional) {
        try {
            rules.add_path(name, rights);
        } catch (const std::system_error& error) {
            if (optional && error.code() == std::errc::no_such_file_or_directory) return;
            throw std::system_error(error.code(), std::string("D-Bus Landlock path ") + name);
        }
    };
    add("/usr", read, false);
    add("/lib", read, true);
    add("/lib64", read, true);
    add("/usr/bin/xdg-dbus-proxy", LANDLOCK_ACCESS_FS_EXECUTE, false);
    // The kernel also checks EXECUTE on the ELF interpreter named by PT_INTERP.
    // Keep this to known loader files for the supported x86_64 and aarch64 hosts.
    for (const char* loader : {
             "/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-x86-64.so.2",
             "/lib/ld-linux-aarch64.so.1", "/lib64/ld-linux-aarch64.so.1"})
        add(loader, LANDLOCK_ACCESS_FS_EXECUTE, true);
    for (const char* name : {
             "/etc/ld.so.cache", "/etc/nsswitch.conf", "/etc/passwd", "/etc/group",
             "/etc/hosts", "/etc/host.conf", "/etc/gai.conf", "/etc/resolv.conf",
             "/etc/services", "/etc/protocols", "/etc/machine-id", "/etc/localtime"})
        add(name, LANDLOCK_ACCESS_FS_READ_FILE, true);
    add("/dev/null", LANDLOCK_ACCESS_FS_READ_FILE, false);
    add("/dev/urandom", LANDLOCK_ACCESS_FS_READ_FILE, true);
    rules.add_fd(private_directory, LANDLOCK_ACCESS_FS_READ_DIR |
                                    LANDLOCK_ACCESS_FS_MAKE_SOCK |
                                    LANDLOCK_ACCESS_FS_REMOVE_FILE);
    rules.enforce();
    return true;
}

NetworkProcess start_dbus_proxy(const DbusSpec& spec, const std::string& path) {
    socket_address(path);
    // Landlock rules apply to every entry beneath the directory. The trusted
    // caller must supply a dedicated parent (the CLI creates a fresh one per
    // proxy); here we additionally verify its owner and private permissions.
    const std::string directory = std::filesystem::path(path).parent_path().string();
    Fd proxy_directory(open(directory.c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (proxy_directory.get() < 0) fail("open private D-Bus proxy directory");
    move_above_stdio(proxy_directory);
    struct stat directory_stat {};
    if (fstat(proxy_directory.get(), &directory_stat) < 0)
        fail("inspect private D-Bus proxy directory");
    if (directory_stat.st_uid != geteuid() || (directory_stat.st_mode & 07777) != 0700)
        throw std::runtime_error("D-Bus proxy socket parent must be owned by this user and mode 0700");
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
        if (!close_except({ready_write.get(), status_write.get(), proxy_directory.get()}))
            child_fail(status_write.get(), Stage::Descriptors);
        if (!null_stream(STDIN_FILENO, O_RDONLY)) child_fail(status_write.get(), Stage::Stdin);
        // Keep --log diagnostics off workload stdout.
        if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0) child_fail(status_write.get(), Stage::Output);
        if (!drop_privileges()) child_fail(status_write.get(), Stage::Privileges);
        try {
            if (!confine_dbus_proxy_filesystem(proxy_directory.get())) {
                constexpr char warning[] = "agent-vm: warning: Landlock ABI 3 unavailable; D-Bus proxy filesystem is not confined\n";
                (void)write(STDERR_FILENO, warning, sizeof(warning) - 1);
            }
        } catch (const std::exception& error) {
            child_fail(status_write.get(), Stage::DbusSandbox, error.what());
        }
        proxy_directory.reset();
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

}
