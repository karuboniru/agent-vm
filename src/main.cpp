#include "agent_vm/runtime.hpp"
#include "agent_vm/protocol.h"
#include <libkrun.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
namespace {
[[noreturn]] void system_error(const std::string& what) {
    throw std::runtime_error(what + ": " + std::strerror(errno));
}
void check_krun(int result, const char* what) {
    if (result < 0) { errno = -result; system_error(what); }
}
void maximize_nofile() {
    rlimit limit{};
    if (getrlimit(RLIMIT_NOFILE, &limit)) system_error("read host RLIMIT_NOFILE");
    if (limit.rlim_cur == limit.rlim_max) return;
    // Do this before forking helpers or entering userns: every host process
    // inherits the largest soft limit permitted by the caller's hard limit.
    limit.rlim_cur = limit.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &limit)) system_error("raise host RLIMIT_NOFILE to its hard limit");
}
struct Fd {
    int value = -1;
    explicit Fd(int fd = -1) : value(fd) {}
    ~Fd() { if (value >= 0) close(value); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};
struct Terminal {
    termios saved{};
    bool active = tcgetattr(STDIN_FILENO, &saved) == 0;
    ~Terminal() { if (active) tcsetattr(STDIN_FILENO, TCSANOW, &saved); }
};
struct RuntimeDirectory {
    fs::path path;
    explicit RuntimeDirectory(const avm::RunSpec& spec) {
        std::string socket_suffix = "/ipc/control.sock";
        if (!spec.sockets.empty()) {
            auto broker_suffix = "/ipc/socket-" + std::to_string(spec.sockets.size() - 1) + ".sock";
            if (broker_suffix.size() > socket_suffix.size()) socket_suffix = std::move(broker_suffix);
        }
        std::vector<fs::path> candidates;
        if (const char* x = getenv("XDG_RUNTIME_DIR"); x && *x) candidates.emplace_back(x);
        candidates.emplace_back("/run/user/" + std::to_string(spec.uid));
        candidates.emplace_back("/tmp");
        for (auto candidate : candidates) {
            std::error_code ec;
            candidate = fs::canonical(candidate, ec);
            if (ec) continue;
            struct stat st{};
            if (stat(candidate.c_str(), &st) || !S_ISDIR(st.st_mode)) continue;
            if (candidate != "/tmp" && (st.st_uid != spec.uid || (st.st_mode & 0022))) continue;
            bool exposed = false;
            for (const auto& m : spec.mounts)
                if (avm::path_within(candidate.string(), m.source)) exposed = true;
            if (exposed) continue;
            std::string pattern = (candidate / "agent-vm.XXXXXX").string();
            if (pattern.size() + socket_suffix.size() >= sizeof(sockaddr_un::sun_path)) continue;
            std::vector<char> name(pattern.begin(), pattern.end()); name.push_back(0);
            if (char* made = mkdtemp(name.data())) {
                path = made;
                fs::create_directory(path / "root");
                fs::create_directory(path / "ipc");
                chmod((path / "ipc").c_str(), 0700);
                return;
            }
        }
        throw std::runtime_error("cannot create private runtime directory outside shared source trees; set XDG_RUNTIME_DIR to an unshared, user-owned private directory");
    }
    ~RuntimeDirectory() {
        if (!path.empty()) {
            std::error_code ec;
            fs::remove_all(path, ec);
            if (ec) std::cerr << "agent-vm: cleanup " << path << ": " << ec.message() << '\n';
        }
    }
};
void write_all(int fd, const void* data, size_t length) {
    const auto* bytes = static_cast<const char*>(data);
    while (length) {
        ssize_t n = write(fd, bytes, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) system_error("write guest specification");
        bytes += n; length -= static_cast<size_t>(n);
    }
}
void write_spec(const avm::RunSpec& spec, const fs::path& path) {
    std::vector<unsigned char> bytes;
    auto append = [&](const void* p, size_t n) {
        if (bytes.size() + n > AVM_SPEC_MAX) throw std::runtime_error("command and environment exceed 1 MiB");
        const auto* first = static_cast<const unsigned char*>(p);
        bytes.insert(bytes.end(), first, first + n);
    };
    auto string = [&](const std::string& s) {
        if (s.find('\0') != std::string::npos || s.size() > AVM_SPEC_MAX)
            throw std::runtime_error("invalid guest configuration string");
        uint32_t n = static_cast<uint32_t>(s.size()); append(&n, sizeof(n)); append(s.data(), s.size());
    };
    avm_spec_header header{AVM_SPEC_MAGIC, AVM_SPEC_VERSION, spec.uid, spec.gid,
        spec.network ? AVM_FLAG_NETWORK : 0u,
        static_cast<uint32_t>(spec.command.size()), static_cast<uint32_t>(spec.environment.size()),
        static_cast<uint32_t>(spec.sockets.size())};
    static_assert(sizeof(header) == 32);
    append(&header, sizeof(header)); string(spec.home); string(spec.cwd);
    for (const auto& arg : spec.command) string(arg);
    for (const auto& [key, value] : spec.environment) string(key + "=" + value);
    for (const auto& socket : spec.sockets) string(socket.target);
    Fd fd(open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600));
    if (fd.value < 0) system_error("create guest specification");
    write_all(fd.value, bytes.data(), bytes.size());
}
// Re-exec the VMM with a clean address space: clearenv() alone leaves the original
// environment and parser heap reachable through the VMM's proc/memory interfaces.
void write_worker_spec(const avm::RunSpec& s, const fs::path& path) {
    Fd fd(open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600));
    if (fd.value < 0) system_error("create worker specification");
    auto number = [&](uint32_t n) { write_all(fd.value, &n, sizeof(n)); };
    auto string = [&](const std::string& v) {
        if (v.size() > AVM_SPEC_MAX) throw std::runtime_error("worker string too large");
        number(static_cast<uint32_t>(v.size())); write_all(fd.value, v.data(), v.size());
    };
    auto strings = [&](const auto& list) { number(static_cast<uint32_t>(list.size())); for (const auto& v : list) string(v); };
    number(AVM_SPEC_MAGIC); number(s.uid); number(s.gid); number(s.cpus); number(s.memory_mib); number(s.tmp_mib);
    number(s.network); number(s.ssh_agent); number(s.debug);
    string(s.username); string(s.home); string(s.cwd);
    number(static_cast<uint32_t>(s.mounts.size()));
    for (const auto& m : s.mounts) { string(m.source); string(m.target); number(m.read_only); }
    number(static_cast<uint32_t>(s.sockets.size()));
    for (const auto& socket : s.sockets) { string(socket.source); string(socket.target); }
    number(static_cast<uint32_t>(s.tmpfs.size()));
    for (const auto& mount : s.tmpfs) {
        string(mount.target); number(mount.uid); number(mount.gid); number(mount.mode);
    }
    strings(s.mask_sources); strings(s.mask_targets);
    number(static_cast<uint32_t>(s.ports.size()));
    for (const auto& p : s.ports) { string(p.address); number(p.host_port); number(p.guest_port); number(p.udp); }
    strings(s.command); number(static_cast<uint32_t>(s.environment.size()));
    for (const auto& [key, value] : s.environment) { string(key); string(value); }
}
avm::RunSpec read_worker_spec(const fs::path& path) {
    Fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (fd.value < 0) system_error("open worker specification");
    struct stat st{};
    if (fstat(fd.value, &st) || !S_ISREG(st.st_mode) || st.st_uid != getuid() ||
        (st.st_mode & 0077) || st.st_size < 0 || st.st_size > 2 * AVM_SPEC_MAX)
        throw std::runtime_error("invalid worker specification file");
    auto read_exact = [&](void* p, size_t n) {
        auto* b = static_cast<char*>(p);
        while (n) { ssize_t got = read(fd.value, b, n); if (got < 0 && errno == EINTR) continue;
            if (got <= 0) throw std::runtime_error("truncated worker specification");
            b += got; n -= static_cast<size_t>(got); }
    };
    auto number = [&] { uint32_t n; read_exact(&n, sizeof(n)); return n; };
    auto count = [&] { uint32_t n = number(); if (n > 65536) throw std::runtime_error("worker array too large"); return n; };
    auto string = [&] { uint32_t n = number(); if (n > AVM_SPEC_MAX) throw std::runtime_error("worker string too large");
        std::string v(n, '\0'); read_exact(v.data(), n); if (v.find('\0') != std::string::npos) throw std::runtime_error("NUL in worker specification"); return v; };
    auto strings = [&](auto& list) { uint32_t n = count(); while (n--) list.push_back(string()); };
    if (number() != AVM_SPEC_MAGIC) throw std::runtime_error("invalid worker specification version");
    avm::RunSpec s;
    s.uid = number(); s.gid = number(); uint32_t cpus = number();
    if (cpus == 0 || cpus > 255 || s.uid != getuid() || s.gid != getgid()) throw std::runtime_error("invalid worker identity or CPU count");
    s.cpus = static_cast<uint8_t>(cpus); s.memory_mib = number(); s.tmp_mib = number();
    s.network = number(); s.ssh_agent = number(); s.debug = number();
    s.username = string(); s.home = string(); s.cwd = string();
    for (uint32_t n = count(); n; --n) { avm::MountSpec m; m.source = string(); m.target = string(); m.read_only = number(); s.mounts.push_back(std::move(m)); }
    uint32_t sockets = count();
    if (sockets > AVM_SOCKET_MAX) throw std::runtime_error("too many forwarded sockets");
    for (uint32_t n = 0; n < sockets; ++n) {
        avm::SocketSpec socket; socket.source = string(); socket.target = string();
        s.sockets.push_back(std::move(socket));
    }
    for (uint32_t n = count(); n; --n) {
        avm::TmpfsSpec mount; mount.target = string();
        mount.uid = number(); mount.gid = number(); mount.mode = number();
        s.tmpfs.push_back(std::move(mount));
    }
    strings(s.mask_sources); strings(s.mask_targets);
    for (uint32_t n = count(); n; --n) {
        avm::PortSpec p; p.address = string(); uint32_t hp = number(), gp = number();
        if (hp == 0 || hp > 65535 || gp == 0 || gp > 65535) throw std::runtime_error("invalid worker port");
        p.host_port = static_cast<uint16_t>(hp); p.guest_port = static_cast<uint16_t>(gp); p.udp = number(); s.ports.push_back(std::move(p));
    }
    strings(s.command);
    for (uint32_t n = count(); n; --n) { auto key = string(); auto value = string(); s.environment.emplace(std::move(key), std::move(value)); }
    char trailing;
    if (read(fd.value, &trailing, 1) != 0) throw std::runtime_error("trailing worker specification data");
    avm::validate_spec(s); return s;
}
std::string find_guest_helper() {
    std::array<char, 4096> buffer{};
    ssize_t n = readlink("/proc/self/exe", buffer.data(), buffer.size() - 1);
    std::vector<fs::path> choices;
    if (n > 0) {
        const auto executable_dir = fs::path(std::string(buffer.data(), n)).parent_path();
        choices.push_back(executable_dir / "agent-vm-guest");
        choices.push_back(executable_dir / AVM_RELATIVE_HELPER);
    }
    choices.emplace_back(AVM_INSTALLED_HELPER);
    for (const auto& p : choices) {
        struct stat st{};
        if (!stat(p.c_str(), &st) && S_ISREG(st.st_mode) && !access(p.c_str(), R_OK | X_OK))
            return fs::canonical(p).string();
    }
    throw std::runtime_error("agent-vm-guest is missing; build both executables or install the project");
}
bool send_control(const fs::path& path, const avm_control_message& message) {
    if (path.string().size() >= sizeof(sockaddr_un::sun_path)) return false;
    Fd fd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    if (fd.value < 0) return false;
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.string().size() + 1);
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
int status_code(int status) {
    return WIFEXITED(status) ? WEXITSTATUS(status) : WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 125;
}
int doctor() {
    bool good = true;
    utsname uts{}; uname(&uts);
    std::cout << "agent-vm " << AVM_VERSION << "; " << uts.sysname << ' ' << uts.release << ' ' << uts.machine << '\n';
    std::cout << "Caller: " << getuid() << ':' << getgid() << " (IDs in the current outer namespace)\n";
    Fd kvm(open("/dev/kvm", O_RDWR | O_CLOEXEC));
    if (kvm.value < 0) {
        std::cout << "FAIL KVM: " << std::strerror(errno) << "; check device visibility and permissions in this execution environment\n";
        good = false;
    } else {
        int version = ioctl(kvm.value, KVM_GET_API_VERSION, 0);
        Fd vm(ioctl(kvm.value, KVM_CREATE_VM, 0));
        if (version != 12 || vm.value < 0) { std::cout << "FAIL KVM ioctls: " << std::strerror(errno) << '\n'; good = false; }
        else std::cout << "OK KVM API 12; empty VM created and closed\n";
    }
    for (auto [name, feature] : std::array<std::pair<const char*, uint64_t>, 2>{{{"NET", KRUN_FEATURE_NET}, {"INIT_BLOB", KRUN_FEATURE_INIT_BLOB}}}) {
        int result = krun_has_feature(feature);
        std::cout << (result == 1 ? "OK " : "FAIL ") << "libkrun " << name << '\n';
        if (result != 1) good = false;
    }
    try { std::cout << "OK guest helper: " << find_guest_helper() << '\n'; }
    catch (const std::exception& e) { std::cout << "FAIL " << e.what() << '\n'; good = false; }
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC)) system_error("doctor pipe");
    Fd read_end(pipefd[0]), write_end(pipefd[1]);
    pid_t child = fork();
    if (child < 0) system_error("doctor fork");
    if (child == 0) {
        close(read_end.value);
        int result = unshare(CLONE_NEWUSER | CLONE_NEWNS) ? errno : 0;
        (void)!write(write_end.value, &result, sizeof(result)); _exit(0);
    }
    close(write_end.value); write_end.value = -1;
    int error = 0; ssize_t received = read(read_end.value, &error, sizeof(error));
    int status = 0; while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    if (received != sizeof(error) || error) {
        std::cout << "FAIL user/mount namespace: " << (error ? std::strerror(error) : "probe failed") << "; check sandbox, LSM and container restrictions\n"; good = false;
    } else std::cout << "OK unprivileged user/mount namespaces\n";
    std::cout << (!access("/usr/bin/xdg-dbus-proxy", X_OK) ? "OK" : "OPTIONAL MISSING") << " /usr/bin/xdg-dbus-proxy (required for D-Bus forwarding)\n";
    std::cout << (!access("/usr/bin/passt", X_OK) ? "OK" : "OPTIONAL MISSING") << " /usr/bin/passt (required for --network passt)\n";
    return good ? 0 : 1;
}
[[noreturn]] void vmm(const avm::RunSpec& spec, const fs::path& runtime,
                      const std::string& helper, int net_fd, pid_t parent) {
    try {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(125);
        sigset_t empty; sigemptyset(&empty); sigprocmask(SIG_SETMASK, &empty, nullptr);
        for (int sig : {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGPIPE, SIGCHLD, SIGWINCH}) signal(sig, SIG_DFL);
        auto exports = avm::enter_sandbox(spec, (runtime / "root").string(), (runtime / "ipc").string(),
                           (runtime / "spec.bin").string(), helper, net_fd >= 0 ? std::vector<int>{net_fd} : std::vector<int>{});
        clearenv(); setenv("PATH", "/usr/bin:/bin", 1);
        check_krun(krun_set_log_level(spec.debug ? 4 : 1), "libkrun log");
        int context = krun_create_ctx(); check_krun(context, "libkrun context");
        check_krun(krun_set_vm_config(context, spec.cpus, spec.memory_mib), "VM resources");
        check_krun(krun_disable_implicit_vsock(context), "disable implicit vsock");
        check_krun(krun_add_vsock(context, 0), "explicit control vsock");
        check_krun(krun_add_vsock_port2(context, AVM_CONTROL_PORT, AVM_CONTROL_SOCKET, true), "control socket");
        check_krun(krun_add_vsock_port2(context, AVM_READY_PORT, AVM_READY_SOCKET, false), "readiness socket");
        for (size_t i = 0; i < spec.sockets.size(); ++i) {
            auto path = std::string(AVM_SOCKET_PREFIX) + std::to_string(i) + ".sock";
            check_krun(krun_add_vsock_port2(context, AVM_SOCKET_PORT_BASE + static_cast<uint32_t>(i),
                                          path.c_str(), false), "forwarded Unix socket");
        }
        if (spec.network) {
            uint8_t mac[] = {0x02, 0x61, 0x76, 0x6d, 0x00, 0x01};
            check_krun(krun_add_net_unixstream(context, nullptr, net_fd, mac, COMPAT_NET_FEATURES, NET_FLAG_DHCP_CLIENT), "passt NIC");
        }
        check_krun(krun_add_virtiofs3(context, KRUN_FS_ROOT_TAG, AVM_BOOTSTRAP, 0, false), "virtio-fs bootstrap");
        for (const auto& object : exports)
            check_krun(krun_add_virtiofs3(context, object.tag.c_str(), object.path.c_str(), 0, false), "virtio-fs object");
        const char* args[] = {nullptr};
        const char* environment[] = {"PATH=/usr/bin:/bin", "HOME=/", "HOSTNAME=agent-vm", nullptr};
        check_krun(krun_set_workdir(context, "/"), "bootstrap cwd");
        check_krun(krun_set_exec(context, AVM_GUEST_HELPER, args, environment), "guest helper");
        avm::install_vmm_seccomp();
        check_krun(krun_start_enter(context), "start VM");
        _exit(125);
    } catch (const std::exception& e) {
        std::cerr << "agent-vm: sandbox/VM: " << e.what() << '\n'; _exit(125);
    }
}
int run(avm::RunSpec spec) {
    maximize_nofile();
    avm::validate_spec(spec);
    if (access("/dev/kvm", R_OK | W_OK)) system_error("/dev/kvm unavailable in this execution environment; run agent-vm doctor");
    const auto helper = find_guest_helper();
    sigset_t blocked, previous;
    sigemptyset(&blocked);
    for (int sig : {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGCHLD, SIGWINCH}) sigaddset(&blocked, sig);
    if (sigprocmask(SIG_BLOCK, &blocked, &previous)) system_error("block supervisor signals");
    struct RestoreSignals { sigset_t mask; ~RestoreSignals() { sigprocmask(SIG_SETMASK, &mask, nullptr); } } restore{previous};
    // Restore the caller's signal mask last, after terminal and directory cleanup.
    RuntimeDirectory runtime(spec);
    // Bind before starting the VMM; CLOEXEC keeps the host listener out of it.
    Fd readiness(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    if (readiness.value < 0) system_error("create readiness listener");
    sockaddr_un ready_address{};
    ready_address.sun_family = AF_UNIX;
    const auto ready_path = (runtime.path / "ipc/ready.sock").string();
    if (ready_path.size() >= sizeof(ready_address.sun_path))
        throw std::runtime_error("readiness socket path too long");
    std::memcpy(ready_address.sun_path, ready_path.c_str(), ready_path.size() + 1);
    if (bind(readiness.value, reinterpret_cast<sockaddr*>(&ready_address), sizeof(ready_address)) ||
        chmod(ready_path.c_str(), 0600) || listen(readiness.value, 1))
        system_error("listen for guest readiness");
    Terminal terminal;
    Fd signals(signalfd(-1, &blocked, SFD_CLOEXEC | SFD_NONBLOCK));
    if (signals.value < 0) system_error("signalfd");
    avm::NetworkProcess network;
    pid_t vm = -1;
    std::vector<avm::NetworkProcess> proxies;
    proxies.reserve(2);
    std::vector<pid_t> brokers;
    brokers.reserve(spec.sockets.size());
    auto cleanup = [&] {
        if (vm > 0) { avm::stop_child(vm); vm = -1; }
        if (network.fd >= 0) { close(network.fd); network.fd = -1; }
        if (network.pid > 0) { avm::stop_child(network.pid); network.pid = -1; }
        for (auto& broker : brokers)
            if (broker > 0) { avm::stop_child(broker); broker = -1; }
        for (auto& proxy : proxies) {
            avm::stop_child(proxy.pid); proxy.pid = -1;
            if (proxy.fd >= 0) { close(proxy.fd); proxy.fd = -1; }
        }
    };
    try {
        for (bool system : {false, true}) {
            const auto& bus = system ? spec.dbus_system : spec.dbus_user;
            if (!bus.enabled) continue;
            auto path = (runtime.path / (system ? "dbus-system.sock" : "dbus-user.sock")).string();
            proxies.push_back(avm::start_dbus_proxy(bus, path));
            auto target = "/run/user/" + std::to_string(spec.uid) + (system ? "/dbus-system.socket" : "/dbus-user.socket");
            for (auto& socket : spec.sockets) if (socket.target == target && socket.source.empty()) socket.source = path;
        }
        avm::validate_spec(spec);
        write_spec(spec, runtime.path / "spec.bin");
        write_worker_spec(spec, runtime.path / "worker.bin");
        if (spec.network) network = avm::start_passt(spec);
        for (size_t i = 0; i < spec.sockets.size(); ++i) {
            auto path = runtime.path / "ipc" / ("socket-" + std::to_string(i) + ".sock");
            brokers.push_back(avm::start_socket_broker(path.string(), spec.sockets[i].source));
        }
        pid_t parent = getpid();
        vm = fork(); if (vm < 0) system_error("fork VM");
        if (vm == 0) {
            if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(125);
            if (network.fd >= 0 && fcntl(network.fd, F_SETFD, 0) < 0) _exit(125);
            const auto job = (runtime.path / "worker.bin").string();
            const auto net = std::to_string(network.fd), owner = std::to_string(parent);
            const char* args[] = {"agent-vm", "--internal-worker", job.c_str(), net.c_str(), owner.c_str(), helper.c_str(), nullptr};
            const char* env[] = {"PATH=/usr/bin:/bin", "LANG=C.UTF-8", nullptr};
            execve("/proc/self/exe", const_cast<char* const*>(args), const_cast<char* const*>(env));
            perror("agent-vm: exec isolated worker"); _exit(125);
        }
        if (network.fd >= 0) { close(network.fd); network.fd = -1; }
        if (spec.debug) std::cerr << "agent-vm: runtime " << runtime.path << "; VM supervisor pid " << vm << '\n';
        auto deadline = std::chrono::steady_clock::time_point::max();
        int requested_signal = 0;
        bool resize_pending = true, helper_failed = false, guest_ready = false;
        int result = 125;
        for (;;) {
            int status;
            pid_t reaped = waitpid(vm, &status, WNOHANG);
            if (reaped == vm) { result = helper_failed ? 125 : status_code(status); vm = -1; break; }
            if (reaped < 0 && errno != EINTR) system_error("wait VM");
            auto check_helper = [&](pid_t& pid, const std::string& name) {
                if (pid > 0 && waitpid(pid, &status, WNOHANG) == pid) {
                    std::cerr << "agent-vm: " << name << " exited before the VM (status " << status_code(status) << ")\n";
                    pid = -1; helper_failed = true; requested_signal = SIGTERM;
                    deadline = std::min(deadline, std::chrono::steady_clock::now() + std::chrono::seconds(3));
                }
            };
            check_helper(network.pid, "passt");
            for (auto& proxy : proxies) check_helper(proxy.pid, "xdg-dbus-proxy");
            for (size_t i = 0; i < brokers.size(); ++i)
                check_helper(brokers[i], "socket broker for " + spec.sockets[i].target);
            if (!guest_ready) {
                Fd notification(accept4(readiness.value, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK));
                if (notification.value >= 0) {
                    guest_ready = true;
                    close(readiness.value); readiness.value = -1;
                } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    system_error("accept guest readiness");
                }
            }
            if (guest_ready) {
                if (requested_signal && send_control(runtime.path / "ipc/control.sock",
                    {AVM_CONTROL_MAGIC, AVM_CONTROL_SIGNAL, static_cast<uint32_t>(requested_signal), 0, 0})) requested_signal = 0;
                if (resize_pending) {
                    winsize size{};
                    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size)) resize_pending = false;
                    else if (send_control(runtime.path / "ipc/control.sock", {AVM_CONTROL_MAGIC, AVM_CONTROL_RESIZE, 0, size.ws_row, size.ws_col})) resize_pending = false;
                }
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                kill(vm, SIGKILL);
                while (waitpid(vm, &status, 0) < 0 && errno == EINTR) {}
                vm = -1; result = helper_failed ? 125 : 137; break;
            }
            pollfd p{signals.value, POLLIN, 0};
            if (poll(&p, 1, 100) < 0 && errno != EINTR) system_error("supervisor poll");
            signalfd_siginfo info{};
            while (read(signals.value, &info, sizeof(info)) == sizeof(info)) {
                if (info.ssi_signo == SIGWINCH) { resize_pending = true; continue; }
                if (info.ssi_signo == SIGCHLD) continue;
                requested_signal = static_cast<int>(info.ssi_signo);
                auto grace = std::chrono::steady_clock::now() + std::chrono::seconds(5);
                deadline = std::min(deadline, grace);
            }
        }
        cleanup(); return result;
    } catch (...) { cleanup(); throw; }
}
}

int main(int argc, char** argv) {
    try {
        if (argc == 6 && std::string(argv[1]) == "--internal-worker") {
            auto spec = read_worker_spec(argv[2]);
            vmm(spec, fs::path(argv[2]).parent_path(), argv[5], std::stoi(argv[3]), static_cast<pid_t>(std::stol(argv[4])));
        }
        auto options = avm::parse_options(argc, argv);
        switch (options.action) {
        case avm::Options::Action::Help: avm::print_help(); return 0;
        case avm::Options::Action::Version: std::cout << "agent-vm " << AVM_VERSION << '\n'; return 0;
        case avm::Options::Action::Doctor: return doctor();
        case avm::Options::Action::Plan: avm::print_plan(options.spec); return 0;
        case avm::Options::Action::Run: return run(options.spec);
        }
    } catch (const std::exception& e) { std::cerr << "agent-vm: " << e.what() << '\n'; return 125; }
    return 125;
}
