#include "agent_vm/runtime.hpp"
#include "agent_vm/protocol.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <set>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>
#include <dirent.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/mount.h>
#include <linux/openat2.h>
#include <poll.h>
#include <sched.h>
#include <seccomp.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace avm {
namespace {
[[noreturn]] void fail(const std::string& operation) {
    throw std::system_error(errno, std::generic_category(), operation);
}
struct Fd {
    int fd = -1;
    explicit Fd(int value = -1) : fd(value) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : fd(std::exchange(other.fd, -1)) {}
    Fd& operator=(Fd&& other) noexcept {
        if (fd >= 0) close(fd);
        fd = std::exchange(other.fd, -1);
        return *this;
    }
    ~Fd() { if (fd >= 0) close(fd); }
};
std::string fd_path(int fd) { return "/proc/self/fd/" + std::to_string(fd); }
bool within(const std::string& path, const std::string& parent) {
    return path == parent || (parent == "/" && path.starts_with('/')) ||
           (path.size() > parent.size() && path.starts_with(parent) && path[parent.size()] == '/');
}
void check_absolute(const std::string& path) {
    if (path.empty() || path[0] != '/' || path.find('\0') != std::string::npos ||
        std::filesystem::path(path).lexically_normal().string() != path ||
        (path.size() > 1 && path.back() == '/'))
        throw std::runtime_error("sandbox path must be absolute and normalized: " + path);
}
Fd open_source(const std::string& path, int flags = O_PATH) {
    // Sources are canonicalized by the policy layer. Do not follow replacements
    // with symlinks, including a changed ancestor, during sandbox setup.
    open_how how{};
    how.flags = static_cast<unsigned long long>(flags | O_CLOEXEC);
    how.resolve = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS;
    int fd = static_cast<int>(syscall(SYS_openat2, AT_FDCWD, path.c_str(), &how, sizeof(how)));
    if (fd < 0) fail("pin source " + path);
    return Fd(fd);
}
struct stat info(int fd) {
    struct stat st{};
    if (fstat(fd, &st)) fail("fstat source");
    return st;
}
void repin(Fd& original, const std::string& path) {
    Fd current = open_source(path);
    const auto before = info(original.fd), after = info(current.fd);
    if (before.st_dev != after.st_dev || before.st_ino != after.st_ino)
        throw std::runtime_error("source changed while entering mount namespace: " + path);
    original = std::move(current);
}
Fd target_fd(int root, const std::string& path) {
    check_absolute(path);
    open_how how{};
    how.flags = O_PATH | O_CLOEXEC;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS;
    const auto relative = path == "/" ? "." : path.substr(1);
    int fd = static_cast<int>(syscall(SYS_openat2, root, relative.c_str(), &how, sizeof(how)));
    if (fd < 0) fail("resolve confined target " + path);
    return Fd(fd);
}
void write_all(int fd, const char* data, size_t size) {
    while (size) {
        ssize_t n = write(fd, data, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fail("write sandbox file");
        data += n;
        size -= static_cast<size_t>(n);
    }
}
void proc_write(const char* path, const std::string& value) {
    Fd fd(open(path, O_WRONLY | O_CLOEXEC));
    if (fd.fd < 0) fail(path);
    write_all(fd.fd, value.data(), value.size());
}
// Resolve every component without symlinks, including when creating mountpoints
// inside an explicitly writable shared tree.
void make_dirs(int root, const std::string& path, mode_t final_mode = 0755) {
    check_absolute(path);
    std::string accumulated;
    for (const auto& part : std::filesystem::path(path).relative_path()) {
        const auto parent = accumulated.empty() ? "/" : accumulated;
        Fd parentfd = target_fd(root, parent);
        const std::string name = part.string();
        accumulated += "/" + name;
        const mode_t mode = accumulated == path ? final_mode : 0755;
        if (mkdirat(parentfd.fd, name.c_str(), mode) && errno != EEXIST)
            fail("mkdir " + accumulated);
        Fd check = target_fd(root, accumulated);
        if (!S_ISDIR(info(check.fd).st_mode))
            throw std::runtime_error("directory target is not a directory: " + accumulated);
    }
}
void create_file(int root, const std::string& path, const std::string& data, mode_t mode = 0644) {
    auto p = std::filesystem::path(path);
    make_dirs(root, p.parent_path().string());
    Fd parent = target_fd(root, p.parent_path().string());
    Fd fd(openat(parent.fd, p.filename().c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode));
    if (fd.fd < 0) fail("create private file " + path);
    write_all(fd.fd, data.data(), data.size());
}
void placeholder(int root, const std::string& path, bool directory) {
    if (directory) { make_dirs(root, path); return; }
    const auto p = std::filesystem::path(path);
    make_dirs(root, p.parent_path().string());
    Fd parent = target_fd(root, p.parent_path().string());
    Fd fd(openat(parent.fd, p.filename().c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644));
    if (fd.fd < 0 && errno != EEXIST) fail("create mount placeholder " + path);
    // Explicit binds may cover generated /etc files. Never truncate an existing
    // target or follow a symlink, and require a matching regular-file target.
    Fd target = target_fd(root, path);
    if (!S_ISREG(info(target.fd).st_mode))
        throw std::runtime_error("file target is not a regular file: " + path);
}
void attributes(int root, const std::string& path, uint64_t attrs, bool recursive) {
    Fd fd = target_fd(root, path);
    mount_attr attr{};
    attr.attr_set = attrs;
    if (syscall(SYS_mount_setattr, fd.fd, "", AT_EMPTY_PATH | (recursive ? AT_RECURSIVE : 0), &attr, sizeof(attr)))
        fail("mount attributes " + path);
}
void bind_fd(int root, int source, const std::string& target, bool recursive, bool read_only,
             bool nodev = true, const struct stat* expected_target = nullptr) {
    Fd dest = target_fd(root, target);
    const auto source_stat = info(source);
    const auto dest_stat = info(dest.fd);
    if (expected_target && (dest_stat.st_dev != expected_target->st_dev || dest_stat.st_ino != expected_target->st_ino))
        throw std::runtime_error("mask target changed since its source was pinned: " + target);
    if (S_ISDIR(source_stat.st_mode) != S_ISDIR(dest_stat.st_mode))
        throw std::runtime_error("mount target type mismatch: " + target);
    if (mount(fd_path(source).c_str(), fd_path(dest.fd).c_str(), nullptr,
              MS_BIND | (recursive ? static_cast<unsigned long>(MS_REC) : 0ul), nullptr)) fail("bind " + target);
    uint64_t attrs = MOUNT_ATTR_NOSUID | (nodev ? MOUNT_ATTR_NODEV : 0) |
                     (read_only ? MOUNT_ATTR_RDONLY : 0);
    attributes(root, target, attrs, true);
}
void copy_file(int root, int source, const std::string& target, mode_t mode, size_t limit) {
    const auto st = info(source);
    if (!S_ISREG(st.st_mode) || st.st_size < 0 || static_cast<uint64_t>(st.st_size) > limit)
        throw std::runtime_error("invalid private input for " + target);
    std::string bytes;
    std::array<char, 65536> buffer{};
    for (;;) {
        const ssize_t n = read(source, buffer.data(), buffer.size());
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) fail("read private input " + target);
        if (n == 0) break;
        if (bytes.size() + static_cast<size_t>(n) > limit)
            throw std::runtime_error("private input exceeded size limit: " + target);
        bytes.append(buffer.data(), static_cast<size_t>(n));
    }
    create_file(root, target, bytes, mode);
}
std::filesystem::path runtime_data_path(const std::string& source) {
    std::error_code ec;
    auto canonical = std::filesystem::canonical(source, ec);
    if (ec) {
        if (ec == std::errc::no_such_file_or_directory) return {};
        throw std::system_error(ec, "resolve runtime data " + source);
    }
    // Toolbx can point localtime through /run/host. Use the same zone from
    // our shared /usr rather than exposing any of that host filesystem.
    if (source == "/etc/localtime" && within(canonical.string(), "/run/host/usr/share/zoneinfo"))
        canonical = std::filesystem::canonical(canonical.string().substr(9));
    // Only fixed system configuration is imported, never caller-selected data.
    if (!within(canonical.string(), "/usr") && !within(canonical.string(), "/etc"))
        throw std::runtime_error("system runtime data points outside /usr or /etc: " + source);
    return canonical;
}
void copy_optional(int root, const std::string& source, const std::string& target, size_t limit) {
    const auto canonical = runtime_data_path(source);
    if (canonical.empty()) return;
    Fd src = open_source(canonical.string(), O_RDONLY | O_NONBLOCK);
    copy_file(root, src.fd, target, 0644, limit);
}
void copy_optional_directory(int root, const std::string& source, const std::string& target, size_t limit) {
    const auto canonical = runtime_data_path(source);
    if (canonical.empty()) return;
    make_dirs(root, target);
    size_t entries = 0;
    // Preserve nested include layouts without following directory symlinks.
    // File symlinks are materialized through the same system-data checks.
    for (std::filesystem::recursive_directory_iterator entry(canonical), end; entry != end; ++entry) {
        if (++entries > 1024 || entry.depth() > 16)
            throw std::runtime_error("system configuration directory exceeds copy limits: " + source);
        const auto destination = (std::filesystem::path(target) /
                                  entry->path().lexically_relative(canonical)).string();
        if (std::filesystem::is_directory(entry->symlink_status()))
            make_dirs(root, destination);
        else
            copy_optional(root, entry->path().string(), destination, limit);
    }
}
void close_unlisted(const std::vector<int>& keep) {
    DIR* dir = opendir("/proc/self/fd");
    if (!dir) fail("enumerate inherited descriptors");
    std::vector<int> close_fds;
    while (auto* entry = readdir(dir)) {
        char* end = nullptr;
        long number = strtol(entry->d_name, &end, 10);
        if (!end || *end || number < 3 || number > INT_MAX || number == dirfd(dir)) continue;
        int fd = static_cast<int>(number);
        if (std::find(keep.begin(), keep.end(), fd) == keep.end()) close_fds.push_back(fd);
    }
    closedir(dir);
    for (int fd : close_fds) close(fd);
}
void drop_capabilities() {
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)) fail("clear ambient capabilities");
    // The bounding set must be emptied while CAP_SETPCAP is still effective.
    for (int capability = 0; ; ++capability) {
        int exists = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);
        if (exists < 0 && errno == EINVAL) break;
        if (exists < 0) fail("read capability bounding set");
        if (exists && prctl(PR_CAPBSET_DROP, capability, 0, 0, 0)) fail("clear capability bounding set");
    }
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    __user_cap_data_struct data[2]{};
    if (syscall(SYS_capset, &header, data)) fail("clear process capabilities");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) fail("set no_new_privs");
}
struct PinnedMount { MountSpec spec; Fd fd; bool directory; };
struct Mask {
    std::string path;
    bool directory;
    dev_t device = 0;
    ino_t inode = 0;
    bool check_identity = false;
};
struct MountRegion { std::string device, filesystem_path, visible_path; };
struct MountRecord { std::string device, root, target; };
std::string unescape_mount_path(const std::string& input) {
    std::string result;
    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '\\' && i + 3 < input.size() &&
            input[i + 1] >= '0' && input[i + 1] <= '7' &&
            input[i + 2] >= '0' && input[i + 2] <= '7' &&
            input[i + 3] >= '0' && input[i + 3] <= '7') {
            result += static_cast<char>((input[i + 1] - '0') * 64 + (input[i + 2] - '0') * 8 + input[i + 3] - '0');
            i += 3;
        } else result += input[i];
    }
    return result;
}
std::string append_path(const std::string& parent, const std::string& suffix) {
    return parent == "/" ? (suffix.empty() ? "/" : suffix) : parent + suffix;
}
std::vector<MountRecord> mount_records() {
    std::ifstream input("/proc/self/mountinfo");
    if (!input) throw std::runtime_error("cannot inspect mount aliases in /proc/self/mountinfo");
    std::vector<MountRecord> records;
    std::string line;
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::string id, parent, device, root, target;
        if (!(fields >> id >> parent >> device >> root >> target))
            throw std::runtime_error("malformed mountinfo while inspecting aliases");
        records.push_back({device, unescape_mount_path(root), unescape_mount_path(target)});
    }
    return records;
}
std::vector<MountRegion> mount_regions(const std::string& path, const std::vector<MountRecord>& records) {
    const MountRecord* containing = nullptr;
    for (const auto& record : records)
        if (within(path, record.target) && (!containing || record.target.size() >= containing->target.size()))
            containing = &record;
    if (!containing) throw std::runtime_error("cannot determine mount identity for " + path);
    const auto suffix = path.substr(containing->target == "/" ? 0 : containing->target.size());
    std::vector<MountRegion> regions{{containing->device, append_path(containing->root, suffix), path}};
    // Recursive exports also expose bind aliases nested below their source.
    // Keeping hidden stacked mount records can cause conservative rejection,
    // but cannot silently omit a potential sensitive alias.
    for (const auto& record : records)
        if (record.target != path && within(record.target, path))
            regions.push_back({record.device, record.root, record.target});
    return regions;
}
bool overlaps(const MountRegion& a, const MountRegion& b) {
    return a.device == b.device && (within(a.filesystem_path, b.filesystem_path) || within(b.filesystem_path, a.filesystem_path));
}
void reject_mount_alias_conflicts(const RunSpec& spec, const std::vector<std::string>& private_paths) {
    const auto records = mount_records();
    const auto usr_regions = mount_regions("/usr", records);
    std::vector<MountRegion> sensitive;
    for (const auto& mask : spec.mask_sources) {
        auto regions = mount_regions(mask, records);
        sensitive.insert(sensitive.end(), regions.begin(), regions.end());
    }
    std::vector<MountRegion> private_regions;
    for (const auto& path : private_paths) {
        auto regions = mount_regions(path, records);
        private_regions.insert(private_regions.end(), regions.begin(), regions.end());
    }
    for (const auto& mount : spec.mounts) {
        for (const auto& exported : mount_regions(mount.source, records)) {
            for (const auto& private_region : private_regions)
                if (overlaps(exported, private_region))
                    throw std::runtime_error("shared source aliases private runtime data: " + exported.visible_path);
            for (const auto& usr : usr_regions)
                if (!mount.read_only && overlaps(exported, usr))
                    throw std::runtime_error("writable source contains a filesystem alias of /usr: " + exported.visible_path);
            for (const auto& mask : sensitive) {
                if (!overlaps(exported, mask)) continue;
                // The ordinary masking pass only reasons about visible source
                // paths. A second mount route to the same filesystem subtree
                // is rejected rather than pretending that pass covers it.
                const bool source_contains_mask = within(mask.visible_path, exported.visible_path) &&
                    within(mask.filesystem_path, exported.filesystem_path) &&
                    mask.visible_path.substr(exported.visible_path == "/" ? 0 : exported.visible_path.size()) ==
                    mask.filesystem_path.substr(exported.filesystem_path == "/" ? 0 : exported.filesystem_path.size());
                const bool mask_contains_source = within(exported.visible_path, mask.visible_path) &&
                    within(exported.filesystem_path, mask.filesystem_path);
                const bool explicit_child = mount.source != mask.visible_path &&
                    within(mount.source, mask.visible_path) && mask_contains_source &&
                    exported.visible_path.substr(mask.visible_path.size()) ==
                    exported.filesystem_path.substr(mask.filesystem_path.size());
                if ((!source_contains_mask || mask_contains_source) && !explicit_child)
                    throw std::runtime_error("source mask conflicts with a filesystem mount alias: " + exported.visible_path);
            }
        }
    }
    for (const auto& usr : usr_regions)
        for (const auto& mask : sensitive)
            if (overlaps(usr, mask))
                throw std::runtime_error("source mask overlaps an implicit /usr filesystem alias");
}
bool forbidden_target(const std::string& path, bool bind = false) {
    if (bind && ((path != "/run" && within(path, "/run")) ||
                 (path != "/usr" && within(path, "/usr")))) return false;
    if (bind && path != "/etc" && within(path, "/etc") &&
        !within(path, "/etc/resolv.conf")) return false;
    for (const char* protected_path : {"/usr", "/etc", "/proc", "/sys", "/dev", "/.agent-vm",
                                       "/bin", "/sbin", "/lib", "/lib64", "/run", "/ipc"})
        if (within(path, protected_path) || within(protected_path, path)) return true;
    return false;
}
void verify_identity_text(const std::string& text) {
    if (text.empty() || text.find_first_of(":\n\r") != std::string::npos || text.find('\0') != std::string::npos)
        throw std::runtime_error("identity text contains passwd delimiters");
}
} // namespace

std::vector<FilesystemExport> enter_sandbox(const RunSpec& spec, const std::string& root_dir,
                   const std::string& ipc_dir, const std::string& spec_file,
                   const std::string& helper, const std::vector<int>& keep_fds) {
    if (getuid() != spec.uid || getgid() != spec.gid || geteuid() != spec.uid || getegid() != spec.gid)
        throw std::runtime_error("sandbox identity must match the invoking real/effective UID and GID");
    for (int fd : {0, 1, 2}) {
        struct stat st{};
        if (fstat(fd, &st) == -1 && errno == EBADF) continue;
        if (S_ISDIR(st.st_mode) || (fcntl(fd, F_GETFL) & O_PATH))
            throw std::runtime_error("standard descriptors cannot retain directories or O_PATH handles");
    }
    check_absolute(root_dir);
    check_absolute(ipc_dir);
    check_absolute(spec.home);
    if (forbidden_target(spec.home) || spec.home == "/tmp" || spec.home == "/var" || spec.home == "/var/tmp")
        throw std::runtime_error("home overlaps a sandbox runtime directory");
    verify_identity_text(spec.username);
    verify_identity_text(spec.home);
    if (!spec.tmp_mib) throw std::runtime_error("private tmpfs size must be positive");

    Fd usr = open_source("/usr");
    Fd kvm = open_source("/dev/kvm");
    if (!S_ISCHR(info(kvm.fd).st_mode)) throw std::runtime_error("/dev/kvm is not a character device");
    Fd ipc = open_source(ipc_dir);
    Fd configuration = open_source(spec_file, O_RDONLY | O_NONBLOCK);
    Fd executable = open_source(helper, O_RDONLY | O_NONBLOCK);
    if (!S_ISDIR(info(ipc.fd).st_mode)) throw std::runtime_error("IPC source is not a directory");

    std::vector<PinnedMount> mounts;
    for (const auto& m : spec.mounts) {
        check_absolute(m.source);
        check_absolute(m.target);
        if (forbidden_target(m.target, true)) throw std::runtime_error("mount overlaps protected target: " + m.target);
        if (within("/run/user/" + std::to_string(spec.uid), m.target))
            throw std::runtime_error("mount overlaps required guest directory: " + m.target);
        if (!m.read_only && (within(m.source, "/usr") || within("/usr", m.source)))
            throw std::runtime_error("host /usr must remain read-only through every mount alias");
        if (within(root_dir, m.source) || within(ipc_dir, m.source) || within(spec_file, m.source))
            throw std::runtime_error("shared source contains private runtime data: " + m.source);
        Fd fd = open_source(m.source);
        auto st = info(fd.fd);
        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
            throw std::runtime_error("only regular files and directories can be shared: " + m.source);
        mounts.push_back({m, std::move(fd), S_ISDIR(st.st_mode)});
    }
    std::sort(mounts.begin(), mounts.end(), [](const auto& a, const auto& b) {
        return a.spec.target.size() < b.spec.target.size();
    });
    auto tmpfs = spec.tmpfs;
    for (const auto& mount : tmpfs) {
        check_absolute(mount.target);
        if (mount.uid == UINT32_MAX || mount.gid == UINT32_MAX || (mount.mode & ~07777u))
            throw std::runtime_error("invalid tmpfs ownership or mode: " + mount.target);
    }
    std::sort(tmpfs.begin(), tmpfs.end(), [](const auto& a, const auto& b) {
        return a.target.size() < b.target.size();
    });
    struct Layer {
        std::string target;
        const PinnedMount* bind;
        const TmpfsSpec* tmpfs;
    };
    std::vector<Layer> layers;
    for (const auto& mount : mounts) layers.push_back({mount.spec.target, &mount, nullptr});
    for (const auto& mount : tmpfs) layers.push_back({mount.target, nullptr, &mount});
    std::sort(layers.begin(), layers.end(), [](const auto& a, const auto& b) {
        return a.target.size() < b.target.size();
    });
    std::vector<Mask> masks;
    std::vector<Fd> mask_pins;
    for (const auto& path : spec.mask_sources) {
        check_absolute(path);
        if (within(path, "/usr") || within("/usr", path))
            throw std::runtime_error("source masks overlapping /usr are unsupported");
        bool needed = false;
        for (const auto& m : mounts) {
            if (m.spec.source == path)
                throw std::runtime_error("shared source is denied by source mask: " + m.spec.source);
            needed |= within(path, m.spec.source);
        }
        if (!needed) continue;
        Fd masked = open_source(path);
        const auto st = info(masked.fd);
        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
            throw std::runtime_error("mask source must be a regular file or directory: " + path);
        for (const auto& m : mounts) {
            if (within(path, m.spec.source)) {
                const auto suffix = path.substr(m.spec.source == "/" ? 0 : m.spec.source.size());
                masks.push_back({m.spec.target + suffix, S_ISDIR(st.st_mode), st.st_dev, st.st_ino, true});
            }
        }
        mask_pins.push_back(std::move(masked));
    }
    for (const auto& path : spec.mask_targets) {
        check_absolute(path);
        if (forbidden_target(path)) throw std::runtime_error("mask overlaps protected target: " + path);
    }

    // A parent-death signal is cleared by fork. Set it for both generations;
    // pidfds close the race even where getppid() is 0 across PID namespaces.
    const pid_t original_parent = getppid();
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) fail("set setup parent-death signal");
    if (getppid() != original_parent) _exit(125);
    if (unshare(CLONE_NEWUSER)) fail("create user namespace");
    proc_write("/proc/self/uid_map", std::to_string(spec.uid) + " " + std::to_string(spec.uid) + " 1\n");
    proc_write("/proc/self/setgroups", "deny\n");
    proc_write("/proc/self/gid_map", std::to_string(spec.gid) + " " + std::to_string(spec.gid) + " 1\n");
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) fail("restore setup parent-death signal");
    if (getppid() != original_parent) _exit(125);
    if (unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET))
        fail("create mount/pid/ipc/uts/net namespaces");
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr)) fail("make mount propagation private");
    Fd parentfd(static_cast<int>(syscall(SYS_pidfd_open, getpid(), 0)));
    if (parentfd.fd < 0) fail("pin namespace parent");
    sigset_t forwarded_signals, previous_mask;
    sigemptyset(&forwarded_signals);
    for (int signal : {SIGINT, SIGTERM, SIGHUP, SIGQUIT}) sigaddset(&forwarded_signals, signal);
    if (sigprocmask(SIG_BLOCK, &forwarded_signals, &previous_mask)) fail("block namespace-parent control signals");
    pid_t child = fork();
    if (child < 0) fail("fork PID namespace init");
    if (child) {
        int status = 0;
        while (waitpid(child, &status, 0) < 0) {
            if (errno != EINTR) _exit(125);
        }
        _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status));
    }
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) fail("set VMM parent-death signal");
    // The supervisor forwards these over the guest control channel. Do not let
    // terminal process-group delivery kill the waiting parent or VMM first.
    struct sigaction ignore{};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    for (int signal : {SIGINT, SIGTERM, SIGHUP, SIGQUIT})
        if (sigaction(signal, &ignore, nullptr)) fail("ignore host process-group control signal in VMM");
    if (sigprocmask(SIG_SETMASK, &previous_mask, nullptr)) fail("restore VMM signal mask");
    pollfd parent_poll{parentfd.fd, POLLIN, 0};
    int alive = poll(&parent_poll, 1, 0);
    if (alive < 0) fail("check namespace parent");
    if (alive != 0) _exit(125);
    parentfd = Fd();
    if (sethostname("agent-vm", 8)) fail("set private hostname");
    // Bind sources must refer to the cloned mount tree owned by this userns.
    // An O_PATH FD into the previous mount namespace cannot be recursively
    // bound here. Reopen in the private namespace and verify inode identity.
    repin(usr, "/usr");
    repin(kvm, "/dev/kvm");
    repin(ipc, ipc_dir);
    for (auto& mount : mounts) repin(mount.fd, mount.spec.source);
    std::vector<std::string> private_paths{root_dir, ipc_dir, spec_file};
    const auto runtime_parent = std::filesystem::path(root_dir).parent_path();
    if (runtime_parent == std::filesystem::path(ipc_dir).parent_path() &&
        runtime_parent == std::filesystem::path(spec_file).parent_path())
        private_paths.push_back(runtime_parent.string());
    reject_mount_alias_conflicts(spec, private_paths);

    Fd root_mountpoint = open_source(root_dir);
    if (!S_ISDIR(info(root_mountpoint.fd).st_mode)) throw std::runtime_error("root source is not a directory");
    if (mount("tmpfs", fd_path(root_mountpoint.fd).c_str(), "tmpfs", MS_NOSUID | MS_NODEV,
              "size=64m,nr_inodes=65536,mode=0755")) fail("mount private root");
    root_mountpoint = Fd();
    Fd root = open_source(root_dir);
    for (const char* path : {"/usr", "/etc", "/proc", "/sys", "/dev", "/dev/pts", "/dev/shm",
                             "/tmp", "/run", "/var", "/var/tmp", "/home", "/opt", "/srv",
                             "/mnt", "/media", "/root", "/.agent-vm", "/.agent-vm/ipc", "/.oldroot"})
        make_dirs(root.fd, path);
    // Private writable filesystems belong to the guest. These host directories
    // are only policy-tree placeholders, sealed read-only before VM launch.
    make_dirs(root.fd, spec.home, 0700);
    make_dirs(root.fd, "/run/user/" + std::to_string(spec.uid), 0700);

    // Masks outside shares have private placeholders. Shared mask targets must
    // already exist; user mount placeholders are prepared per layer below.
    for (const auto& path : spec.mask_targets) {
        bool shared = false;
        for (const auto& m : mounts) shared |= within(path, m.spec.target);
        if (!shared) make_dirs(root.fd, path);
    }
    create_file(root.fd, "/dev/kvm", "", 0600);
    create_file(root.fd, "/.agent-vm/resolv.conf", "", 0644);
    create_file(root.fd, "/etc/resolv.conf", "", 0644);
    create_file(root.fd, "/.agent-vm/empty-file", "", 0444);
    make_dirs(root.fd, "/.agent-vm/empty-dir", 0555);
    const auto uid = std::to_string(spec.uid), gid = std::to_string(spec.gid);
    std::string passwd = "root:x:0:0:root:/root:/bin/sh\n";
    std::string group = "root:x:0:\n";
    if (spec.uid != 0) passwd += spec.username + ":x:" + uid + ":" + gid + ":agent-vm:" + spec.home + ":/bin/sh\n";
    if (spec.gid != 0) group += spec.username + ":x:" + gid + ":\n";
    create_file(root.fd, "/etc/passwd", passwd);
    create_file(root.fd, "/etc/group", group);
    create_file(root.fd, "/etc/nsswitch.conf", "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\nnetworks: files\n");
    create_file(root.fd, "/etc/hosts", "127.0.0.1 localhost agent-vm\n::1 localhost agent-vm\n");
    create_file(root.fd, "/etc/hostname", "agent-vm\n");
    copy_optional(root.fd, "/etc/ld.so.conf", "/etc/ld.so.conf", 1024u * 1024u);
    copy_optional_directory(root.fd, "/etc/ld.so.conf.d", "/etc/ld.so.conf.d", 1024u * 1024u);
    copy_optional(root.fd, "/etc/ld.so.cache", "/etc/ld.so.cache", 16u * 1024u * 1024u);
    copy_optional(root.fd, "/etc/localtime", "/etc/localtime", 16u * 1024u * 1024u);
    copy_optional(root.fd, "/etc/locale.conf", "/etc/locale.conf", 65536);
    std::string ca_source;
    for (const char* path : {"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"}) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(path, ec)) { ca_source = path; break; }
    }
    if (!ca_source.empty()) {
        // Fedora curl also uses the extracted bundle path directly.
        for (const char* target : {"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                                   "/etc/pki/tls/certs/ca-bundle.crt", "/etc/pki/tls/cert.pem",
                                   "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"})
            copy_optional(root.fd, ca_source, target, 16u * 1024u * 1024u);
    }
    for (const auto& [link, target] : std::array<std::pair<const char*, const char*>, 4>{
             {{"bin", "usr/bin"}, {"sbin", "usr/sbin"}, {"lib", "usr/lib"}, {"lib64", "usr/lib64"}}}) {
        struct stat st{};
        const std::string host = std::string("/") + target;
        if (stat(host.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
            if (symlinkat(target, root.fd, link)) fail("create FHS symlink");
        } else if (errno != ENOENT) fail("inspect host FHS layout");
    }

    bind_fd(root.fd, usr.fd, "/usr", true, true);
    // Private tmpfs staging provides mountpoints for explicit bind children.
    // Writable shares also permit missing mountpoints; read-only shares require
    // existing targets. The kernel enforces the backing filesystem permissions.
    for (size_t i = 0; i < layers.size(); ++i) {
        const auto& layer = layers[i];
        const Layer* parent = nullptr;
        for (size_t j = 0; j < i; ++j)
            if (within(layer.target, layers[j].target)) parent = &layers[j];
        if (!parent) {
            placeholder(root.fd, layer.target, layer.tmpfs || layer.bind->directory);
        } else if (parent->tmpfs || !parent->bind->spec.read_only) {
            Fd writable_parent = target_fd(root.fd, parent->target);
            placeholder(writable_parent.fd, layer.target.substr(parent->target.size()),
                        layer.tmpfs || layer.bind->directory);
        }
        if (layer.bind) {
            bind_fd(root.fd, layer.bind->fd.fd, layer.target, layer.bind->directory, layer.bind->spec.read_only);
        } else {
            Fd target = target_fd(root.fd, layer.target);
            if (!S_ISDIR(info(target.fd).st_mode))
                throw std::runtime_error("tmpfs target is not a directory: " + layer.target);
            if (mount("tmpfs", fd_path(target.fd).c_str(), "tmpfs", MS_NOSUID | MS_NODEV,
                      "size=64m,nr_inodes=65536,mode=0755")) fail("stage private tmpfs " + layer.target);
        }
    }
    // Seal only the staging roots; separately authorized writable bind children
    // retain their own policy. Guest ownership applies to the guest tmpfs only.
    for (const auto& mount : tmpfs) attributes(root.fd, mount.target, MOUNT_ATTR_RDONLY, false);
    // DNS is a separate private bind so guest DHCP can write it after the root
    // filesystem containing /etc becomes read-only.
    Fd resolv = target_fd(root.fd, "/.agent-vm/resolv.conf");
    bind_fd(root.fd, resolv.fd, "/etc/resolv.conf", false, false);
    bind_fd(root.fd, ipc.fd, "/.agent-vm/ipc", true, false);
    bind_fd(root.fd, kvm.fd, "/dev/kvm", false, false, false);
    Fd proc = target_fd(root.fd, "/proc");
    if (mount("proc", fd_path(proc.fd).c_str(), "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr))
        fail("mount PID-namespace proc");
    for (const auto& path : spec.mask_targets) {
        Fd target = target_fd(root.fd, path);
        const auto st = info(target.fd);
        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
            throw std::runtime_error("mask target must be a regular file or directory: " + path);
        masks.push_back({path, S_ISDIR(st.st_mode)});
    }
    std::sort(masks.begin(), masks.end(), [](const auto& a, const auto& b) { return a.path.size() < b.path.size(); });
    Fd empty_directory = target_fd(root.fd, "/.agent-vm/empty-dir");
    Fd empty_file = target_fd(root.fd, "/.agent-vm/empty-file");
    std::vector<std::string> masked_ancestors;
    std::vector<std::string> restored;
    for (const auto& mask : masks) {
        bool covered = false;
        for (const auto& ancestor : masked_ancestors) {
            if (!within(mask.path, ancestor)) continue;
            bool exposed = false;
            for (const auto& child : restored)
                exposed |= within(mask.path, child) && within(child, ancestor) && child != ancestor;
            covered |= !exposed;
        }
        if (covered) continue;
        // Preserve the composed child view, never the original source: it may
        // itself contain child binds. Target masks do not create new exceptions;
        // the coverage check above preserves existing descendant exceptions.
        struct Child { const PinnedMount* mount; Fd view; };
        std::vector<Child> children;
        if (mask.check_identity && mask.directory) {
            for (const auto& m : mounts) {
                if (m.spec.target == mask.path || !within(m.spec.target, mask.path)) continue;
                bool nested = false;
                for (const auto& child : children) nested |= within(m.spec.target, child.mount->spec.target);
                if (!nested) children.push_back({&m, target_fd(root.fd, m.spec.target)});
            }
        }
        struct stat expected{};
        expected.st_dev = mask.device;
        expected.st_ino = mask.inode;
        if (children.empty()) {
            bind_fd(root.fd, mask.directory ? empty_directory.fd : empty_file.fd, mask.path, false, true,
                    true, mask.check_identity ? &expected : nullptr);
        } else {
            const auto staging = "/.agent-vm/mask-" + std::to_string(masked_ancestors.size());
            make_dirs(root.fd, staging);
            Fd directory = target_fd(root.fd, staging);
            for (const auto& child : children)
                placeholder(directory.fd, child.mount->spec.target.substr(mask.path.size()), child.mount->directory);
            bind_fd(root.fd, directory.fd, mask.path, false, false, true, &expected);
            for (const auto& child : children) {
                bind_fd(root.fd, child.view.fd, child.mount->spec.target, child.mount->directory, false);
                restored.push_back(child.mount->spec.target);
            }
            attributes(root.fd, mask.path, MOUNT_ATTR_RDONLY, false);
        }
        masked_ancestors.push_back(mask.path);
    }

    // Only the final, masked tree may supply export objects. In particular,
    // never export a pinned original source: it bypasses masks and child binds.
    struct Object { std::string target, path; };
    std::vector<Object> objects;
    struct GuestMount {
        uint32_t kind, mode, uid, gid;
        std::string target, object;
    };
    std::vector<GuestMount> guest_mounts;
    std::string manifest(sizeof(avm_mount_header), '\0');
    auto number = [&](uint32_t value) { manifest.append(reinterpret_cast<const char*>(&value), sizeof(value)); };
    auto string = [&](const std::string& value) { number(static_cast<uint32_t>(value.size())); manifest += value; };
    auto entry = [&](uint32_t kind, const std::string& target, const std::string& object,
                     uint32_t mode = 0, uint32_t uid = 0, uint32_t gid = 0) {
        guest_mounts.push_back({kind, mode, uid, gid, target, object});
    };
    entry(AVM_MOUNT_TMPFS, "/tmp", "", 01777);
    entry(AVM_MOUNT_TMPFS, "/var/tmp", "", 01777);
    entry(AVM_MOUNT_TMPFS, "/run", "", 0755);
    entry(AVM_MOUNT_TMPFS, spec.home, "", 0700, spec.uid, spec.gid);
    const auto builtin_mounts = guest_mounts.size();
    auto export_object = [&](const std::string& target, bool readonly_root = false) {
        Fd source = target_fd(root.fd, target);
        bool directory = S_ISDIR(info(source.fd).st_mode);
        const auto container = std::string(AVM_EXPORT_TAG) + "/" + std::to_string(objects.size());
        make_dirs(root.fd, container);
        const auto object = directory ? container + "/root" : container + "/file";
        placeholder(root.fd, object, directory);
        bind_fd(root.fd, source.fd, object, directory, false);
        // Generated /etc is read-only, except for its private DHCP file mount.
        if (readonly_root) attributes(root.fd, object, MOUNT_ATTR_RDONLY, false);
        objects.push_back({target, object});
        entry(directory ? AVM_MOUNT_DIRECTORY : AVM_MOUNT_FILE, target,
              object.substr(std::strlen(AVM_EXPORT_TAG)));
    };
    export_object("/usr");
    export_object("/etc", true);
    // IPC is VMM-private: never add it to the virtio-fs object catalog.
    for (const auto& m : mounts) {
        bool hidden = false;
        for (const auto& path : masked_ancestors) {
            bool exposed = false;
            for (const auto& child : restored)
                exposed |= within(m.spec.target, child) && within(child, path) && child != path;
            hidden |= within(m.spec.target, path) && !exposed;
        }
        if (!hidden) export_object(m.spec.target);
    }
    // Masks within a share are already part of that share's host view. Masks
    // on private guest paths still need an empty, host-enforced RO object.
    for (const auto& path : masked_ancestors) {
        bool shared = false;
        for (const auto& m : mounts) shared |= within(path, m.spec.target) && path != m.spec.target;
        if (!shared) export_object(path);
    }
    for (const auto& mount : tmpfs)
        entry(AVM_MOUNT_USER_TMPFS, mount.target, "", mount.mode, mount.uid, mount.gid);
    std::stable_sort(guest_mounts.begin() + builtin_mounts, guest_mounts.end(), [](const auto& a, const auto& b) {
        return a.target.size() < b.target.size();
    });
    for (const auto& mount : guest_mounts) {
        number(mount.kind); number(mount.mode); number(mount.uid); number(mount.gid);
        string(mount.target); string(mount.object);
        if (manifest.size() > AVM_SPEC_MAX) throw std::runtime_error("mount specification exceeds 1 MiB");
    }
    avm_mount_header mount_header{AVM_MOUNT_MAGIC, AVM_MOUNT_VERSION,
                                 static_cast<uint32_t>(guest_mounts.size()), spec.tmp_mib};
    std::memcpy(manifest.data(), &mount_header, sizeof(mount_header));

    // The boot export contains only what libkrun's init and our helper need.
    // The VMM's proc, KVM node, policy tree and object registry are not its root.
    const std::string boot = AVM_BOOTSTRAP;
    for (const char* path : {"/usr", "/etc", "/dev", "/dev/pts", "/dev/shm", "/proc", "/sys",
                             "/run", "/tmp", "/.agent-vm", AVM_NEW_ROOT})
        make_dirs(root.fd, boot + path);
    for (const auto& object : objects) {
        if (object.target != "/usr" && object.target != "/etc") continue;
        Fd source = target_fd(root.fd, object.path);
        bind_fd(root.fd, source.fd, boot + object.target, true, false);
    }
    copy_file(root.fd, configuration.fd, boot + AVM_GUEST_SPEC, 0400, AVM_SPEC_MAX);
    copy_file(root.fd, executable.fd, boot + AVM_GUEST_HELPER, 0555, 32u * 1024u * 1024u);
    create_file(root.fd, boot + AVM_MOUNT_SPEC, manifest, 0400);
    Fd boot_fd = target_fd(root.fd, boot);
    for (const char* name : {"bin", "sbin", "lib", "lib64"}) {
        struct stat st{};
        if (fstatat(root.fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode))
            if (symlinkat((std::string("usr/") + name).c_str(), boot_fd.fd, name)) fail("bootstrap FHS symlink");
    }
    boot_fd = Fd();
    if (fchdir(root.fd)) fail("chdir private root");
    if (syscall(SYS_pivot_root, ".", ".oldroot")) fail("pivot_root");
    if (chdir("/")) fail("chdir new root");
    if (umount2("/.oldroot", MNT_DETACH)) fail("detach old root");
    if (rmdir("/.oldroot")) fail("remove old-root mountpoint");
    attributes(root.fd, "/", MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, false);
    // Release every source reference before returning to libkrun. The final
    // descriptor sweep also removes caller inheritance not explicitly allowed.
    mounts.clear();
    mask_pins.clear();
    usr = Fd(); kvm = Fd(); ipc = Fd(); configuration = Fd(); executable = Fd();
    resolv = Fd(); proc = Fd(); empty_directory = Fd(); empty_file = Fd(); root = Fd();
    close_unlisted(keep_fds);
    drop_capabilities();
    return {{AVM_EXPORT_TAG, AVM_EXPORT_TAG}};
}

void install_vmm_seccomp() {
    scmp_filter_ctx filter = seccomp_init(SCMP_ACT_ALLOW);
    if (!filter) throw std::runtime_error("cannot allocate VMM seccomp filter");
    try {
        for (const char* name : {"mount", "umount", "umount2", "pivot_root", "chroot", "setns", "unshare", "execve", "execveat",
                                 "ptrace", "process_vm_readv", "process_vm_writev", "open_by_handle_at", "name_to_handle_at",
                                 "bpf", "perf_event_open", "init_module", "finit_module", "delete_module", "reboot",
                                 "kexec_load", "kexec_file_load", "swapon", "swapoff", "syslog", "iopl", "ioperm",
                                 "keyctl", "add_key", "request_key", "acct", "quotactl", "fsopen", "fsconfig",
                                 "fsmount", "fspick", "open_tree", "move_mount", "mount_setattr"}) {
            int number = seccomp_syscall_resolve_name(name);
            if (number == __NR_SCMP_ERROR) continue;
            int rc = seccomp_rule_add(filter, SCMP_ACT_ERRNO(EPERM), number, 0);
            if (rc < 0) throw std::system_error(-rc, std::generic_category(), "seccomp deny " + std::string(name));
        }
        // clone3 carries flags behind a userspace pointer, which seccomp cannot
        // inspect. ENOSYS makes pthread implementations fall back to clone.
        int clone3 = seccomp_syscall_resolve_name("clone3");
        if (clone3 != __NR_SCMP_ERROR) {
            int rc = seccomp_rule_add(filter, SCMP_ACT_ERRNO(ENOSYS), clone3, 0);
            if (rc < 0) throw std::system_error(-rc, std::generic_category(), "seccomp clone3");
        }
        for (uint64_t flag : {uint64_t(CLONE_NEWUSER), uint64_t(CLONE_NEWNS), uint64_t(CLONE_NEWPID),
                              uint64_t(CLONE_NEWNET), uint64_t(CLONE_NEWIPC), uint64_t(CLONE_NEWUTS), uint64_t(CLONE_NEWCGROUP)}) {
            int rc = seccomp_rule_add(filter, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1,
                                      SCMP_A0(SCMP_CMP_MASKED_EQ, flag, flag));
            if (rc < 0) throw std::system_error(-rc, std::generic_category(), "seccomp namespace clone");
        }
        int rc = seccomp_load(filter);
        if (rc < 0) throw std::system_error(-rc, std::generic_category(), "load VMM seccomp");
    } catch (...) { seccomp_release(filter); throw; }
    seccomp_release(filter);
}
} // namespace avm
