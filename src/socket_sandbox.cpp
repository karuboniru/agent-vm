#include "socket_sandbox.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <linux/capability.h>
#include <linux/mount.h>
#include <sched.h>
#include <seccomp.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>

namespace avm::detail {
namespace {
[[noreturn]] void fail(const char* message) {
    throw std::runtime_error(std::string(message) + ": " + std::strerror(errno));
}
void mapping(const char* path, const std::string& value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) fail("open socket helper identity map");
    ssize_t result;
    do { result = write(fd, value.data(), value.size()); } while (result < 0 && errno == EINTR);
    int error = result < 0 ? errno : EIO;
    close(fd);
    if (result != static_cast<ssize_t>(value.size())) { errno = error; fail("write socket helper identity map"); }
}
void make_directory(const std::string& path) {
    if (mkdir(path.c_str(), 0700)) fail("create socket helper mountpoint");
}
void new_root(const char* path) {
    if (mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=64k,mode=0700"))
        fail("mount socket helper root");
}
std::string mount_path(const std::string& escaped) {
    std::string path;
    for (size_t i = 0; i < escaped.size(); ++i) {
        if (escaped[i] == '\\' && i + 3 < escaped.size() &&
            escaped[i + 1] >= '0' && escaped[i + 1] <= '7' &&
            escaped[i + 2] >= '0' && escaped[i + 2] <= '7' &&
            escaped[i + 3] >= '0' && escaped[i + 3] <= '7') {
            path += static_cast<char>((escaped[i + 1] - '0') * 64 +
                                      (escaped[i + 2] - '0') * 8 + escaped[i + 3] - '0');
            i += 3;
        } else path += escaped[i];
    }
    return path;
}
void hide_submounts(const std::string& root, const std::string& target, const std::vector<std::string>& names) {
    const auto prefix = target + "/";
    std::ifstream mounts("/proc/self/mountinfo");
    if (!mounts) fail("read socket helper mount table");
    std::vector<std::string> paths;
    std::string line;
    while (std::getline(mounts, line)) {
        std::istringstream fields(line);
        std::string id, parent, device, source, escaped;
        if (!(fields >> id >> parent >> device >> source >> escaped))
            throw std::runtime_error("invalid socket helper mount table");
        auto path = mount_path(escaped);
        if (path.starts_with(prefix) && std::find(names.begin(), names.end(), path.substr(prefix.size())) == names.end())
            paths.push_back(std::move(path));
    }
    if (!mounts.eof()) fail("read socket helper mount table");
    // Cover topmost descendants only. Locked inherited mounts cannot be
    // detached individually, but can be hidden beneath new private mounts.
    std::sort(paths.begin(), paths.end());
    std::vector<std::string> covered;
    const auto empty_file = root + "/.empty-file";
    bool have_file = false;
    for (const auto& path : paths) {
        if (std::any_of(covered.begin(), covered.end(), [&](const auto& parent) {
            return path == parent || path.starts_with(parent + "/");
        })) continue;
        struct stat info{};
        if (lstat(path.c_str(), &info)) fail("inspect socket upstream submount");
        if (S_ISDIR(info.st_mode)) {
            if (mount("tmpfs", path.c_str(), "tmpfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                      "size=4k,mode=000")) fail("hide socket upstream directory submount");
        } else {
            if (!have_file) {
                int fd = open(empty_file.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0000);
                if (fd < 0) fail("create socket upstream file mask");
                close(fd);
                have_file = true;
            }
            if (mount(empty_file.c_str(), path.c_str(), nullptr, MS_BIND, nullptr))
                fail("hide socket upstream file submount");
        }
        covered.push_back(path);
    }
    if (have_file && unlink(empty_file.c_str())) fail("remove socket upstream mask staging file");
}
void pivot(const std::string& root) {
    make_directory(root + "/.oldroot");
    if (chdir(root.c_str()) || syscall(SYS_pivot_root, ".", ".oldroot") || chdir("/") ||
        umount2("/.oldroot", MNT_DETACH) || rmdir("/.oldroot")) fail("pivot socket helper root");
    mount_attr attributes{};
    attributes.attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC;
    // Seal this mount, not the entire superblock: an unlinked file mask can
    // still be pinned by a bind mount, making a superblock remount return EBUSY.
    if (syscall(SYS_mount_setattr, AT_FDCWD, "/", 0, &attributes, sizeof(attributes)))
        fail("seal socket helper root");
}
void drop_capabilities() {
    for (int cap = 0; ; ++cap) {
        int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (present < 0 && errno == EINVAL) break;
        if (present < 0 || (present && prctl(PR_CAPBSET_DROP, cap, 0, 0, 0))) fail("clear socket helper bounding set");
    }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)) fail("clear socket helper ambient capabilities");
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    __user_cap_data_struct data[2]{};
    if (syscall(SYS_capset, &header, data) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        fail("drop socket helper capabilities");
}
class Filter {
public:
    Filter() : context(seccomp_init(SCMP_ACT_ERRNO(EPERM))) {
        if (!context) fail("create socket helper seccomp");
    }
    ~Filter() { if (context) seccomp_release(context); }
    template<class... Conditions> void allow(int syscall, Conditions... conditions) {
        int error = seccomp_rule_add(context, SCMP_ACT_ALLOW, syscall, sizeof...(conditions), conditions...);
        if (error) { errno = -error; fail("add socket helper seccomp rule"); }
    }
    void load() {
        int error = seccomp_load(context);
        if (error) { errno = -error; fail("install socket helper seccomp"); }
        // Keep libseccomp's setup allocation until exit. The steady-state filter
        // intentionally denies allocator and memory-mapping system calls.
        context = nullptr;
    }
private:
    scmp_filter_ctx context;
};
void common(Filter& filter, int status) {
    for (int call : {SCMP_SYS(close), SCMP_SYS(poll), SCMP_SYS(ppoll), SCMP_SYS(exit),
                     SCMP_SYS(exit_group), SCMP_SYS(rt_sigreturn), SCMP_SYS(clock_gettime)})
        filter.allow(call);
    filter.allow(SCMP_SYS(write), SCMP_A0(SCMP_CMP_EQ, static_cast<scmp_datum_t>(status)));
}
}

void enter_socket_control_namespace(const std::string& root, const std::vector<SocketDirectory>& directories) {
    const auto uid = getuid(), gid = getgid();
    if (unshare(CLONE_NEWUSER)) fail("create socket helper user namespace");
    mapping("/proc/self/uid_map", std::to_string(uid) + " " + std::to_string(uid) + " 1\n");
    mapping("/proc/self/setgroups", "deny\n");
    mapping("/proc/self/gid_map", std::to_string(gid) + " " + std::to_string(gid) + " 1\n");
    if (unshare(CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET))
        fail("create socket helper namespaces");
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr)) fail("make socket helper mounts private");
    if (sethostname("socket-broker", 13)) fail("set socket helper hostname");
    // Clone every source before mounting staging: sources can overlap each
    // other or contain staging. No clone may capture our newly created root.
    std::vector<int> trees;
    trees.reserve(directories.size());
    for (const auto& directory : directories) {
        int source = open(directory.source.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (source < 0) fail("pin socket upstream directory");
        int tree = static_cast<int>(syscall(SYS_open_tree, source, "",
            OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH | AT_RECURSIVE));
        close(source);
        if (tree < 0) fail("clone socket upstream mount tree");
        trees.push_back(tree);
    }
    new_root(root.c_str());
    make_directory(root + "/upstream");
    make_directory(root + "/empty");
    for (size_t i = 0; i < trees.size(); ++i) {
        const auto target = root + "/upstream/" + std::to_string(i);
        make_directory(target);
        if (syscall(SYS_move_mount, trees[i], "", AT_FDCWD, target.c_str(), MOVE_MOUNT_F_EMPTY_PATH))
            fail("attach socket upstream mount tree");
        close(trees[i]);
        hide_submounts(root, target, directories[i].names);
        mount_attr attributes{};
        attributes.attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC;
        if (syscall(SYS_mount_setattr, AT_FDCWD, target.c_str(), AT_RECURSIVE, &attributes, sizeof(attributes)))
            fail("seal socket upstream directory");
    }
    pivot(root);
}

void enter_socket_data_namespace() {
    // The FD channel and connected streams survive. No proc, device nodes,
    // libraries, directory handles, or upstream mount survive this pivot.
    if (unshare(CLONE_NEWNS)) fail("create socket data mount namespace");
    new_root("/empty");
    pivot("/empty");
}

void seal_socket_control(const std::vector<int>& listeners, const std::vector<int>& channels,
                         const std::vector<int>& directories, int status, const std::vector<pid_t>& data_pids) {
    drop_capabilities();
    Filter filter;
    common(filter, status);
    filter.allow(SCMP_SYS(socket), SCMP_A0(SCMP_CMP_EQ, AF_UNIX),
                 SCMP_A1(SCMP_CMP_EQ, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC), SCMP_A2(SCMP_CMP_EQ, 0));
    for (int fd : listeners)
        filter.allow(SCMP_SYS(accept4), SCMP_A0(SCMP_CMP_EQ, static_cast<scmp_datum_t>(fd)),
                     SCMP_A3(SCMP_CMP_EQ, SOCK_CLOEXEC | SOCK_NONBLOCK));
    for (int fd : channels)
        filter.allow(SCMP_SYS(sendmsg), SCMP_A0(SCMP_CMP_EQ, static_cast<scmp_datum_t>(fd)), SCMP_A2(SCMP_CMP_EQ, MSG_NOSIGNAL));
    for (int fd : directories)
        filter.allow(SCMP_SYS(fchdir), SCMP_A0(SCMP_CMP_EQ, static_cast<scmp_datum_t>(fd)));
    for (pid_t pid : data_pids) {
        filter.allow(SCMP_SYS(kill), SCMP_A0(SCMP_CMP_EQ, static_cast<scmp_datum_t>(pid)), SCMP_A1(SCMP_CMP_EQ, SIGKILL));
        filter.allow(SCMP_SYS(wait4), SCMP_A0(SCMP_CMP_EQ, static_cast<scmp_datum_t>(pid)));
    }
    filter.allow(SCMP_SYS(connect));
    filter.allow(SCMP_SYS(getsockopt), SCMP_A1(SCMP_CMP_EQ, SOL_SOCKET), SCMP_A2(SCMP_CMP_EQ, SO_ERROR));
    filter.load();
}

void seal_socket_data(int channel, int status) {
    drop_capabilities();
    Filter filter;
    common(filter, status);
    filter.allow(SCMP_SYS(recvmsg), SCMP_A0(SCMP_CMP_EQ, static_cast<scmp_datum_t>(channel)), SCMP_A2(SCMP_CMP_EQ, MSG_CMSG_CLOEXEC));
    filter.allow(SCMP_SYS(recvfrom), SCMP_A4(SCMP_CMP_EQ, 0), SCMP_A5(SCMP_CMP_EQ, 0));
    filter.allow(SCMP_SYS(sendto), SCMP_A4(SCMP_CMP_EQ, 0), SCMP_A5(SCMP_CMP_EQ, 0));
    filter.allow(SCMP_SYS(shutdown));
    filter.load();
}
}
