#include "agent_vm/runtime.hpp"
#include "agent_vm/protocol.h"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <dirent.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <seccomp.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;
static void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
static void write_file(const fs::path& path, const std::string& data) {
    std::ofstream out(path); out << data;
    require(bool(out), "write fixture failed");
}
static std::string read_file(const char* path) {
    std::ifstream in(path);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
template<class F> static int child_status(F function) {
    pid_t child = fork(); require(child >= 0, "fork failed");
    if (child == 0) {
        try { function(); _exit(0); }
        catch (const std::exception& error) { dprintf(2, "sandbox test: %s\n", error.what()); _exit(1); }
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) require(errno == EINTR, "waitpid failed");
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
static bool namespace_changes_denied() {
    // unshare(0) needs no capabilities: EPERM proves the filter is active.
    errno = 0;
    if (unshare(0) != -1 || errno != EPERM) return false;
    errno = 0;
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != -1 || errno != EPERM) return false;
    errno = 0;
    return umount2("/work/.ssh", MNT_DETACH) == -1 && errno == EPERM;
}
static void seccomp_test() {
    require(child_status([] {
        require(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "no_new_privs failed");
        std::atomic<bool> installed{false};
        bool synchronized = false;
        std::jthread existing([&](std::stop_token stop) {
            while (!installed.load()) {
                if (stop.stop_requested()) return;
                std::this_thread::yield();
            }
            synchronized = namespace_changes_denied();
        });
        avm::install_vmm_seccomp();
        installed.store(true);
        existing.join();
        require(synchronized, "existing thread did not receive VMM filter");
        errno = 0;
        require(syscall(SYS_mount, nullptr, nullptr, nullptr, 0, nullptr) == -1 && errno == EPERM, "mount was not denied");
        errno = 0;
        require(unshare(CLONE_NEWUSER) == -1 && errno == EPERM, "unshare was not denied");
        errno = 0;
        require(syscall(SYS_execve, "/nonexistent", nullptr, nullptr) == -1 && errno == EPERM, "exec was not denied");
#ifdef SYS_clone3
        errno = 0;
        require(syscall(SYS_clone3, nullptr, 0) == -1 && errno == ENOSYS, "clone3 did not request fallback");
#endif
        for (const char* name : {"io_uring_setup", "io_uring_register", "io_uring_enter", "userfaultfd", "quotactl_fd", "kcmp"}) {
            int call = seccomp_syscall_resolve_name(name);
            require(call != __NR_SCMP_ERROR, "missing syscall definition");
            errno = 0;
            require(syscall(call, -1, 0, 0, 0, 0, 0) == -1 && errno == EPERM, name);
        }
        for (int family : {AF_VSOCK, AF_INET, AF_INET6, AF_NETLINK, AF_PACKET}) {
            errno = 0;
            require(socket(family, SOCK_STREAM, 0) == -1 && errno == EPERM, "host socket family escaped filter");
            int pair[2];
            require(socketpair(family, SOCK_STREAM, 0, pair) == -1 && errno == EPERM, "socketpair family escaped filter");
        }
        int pair[2];
        require(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "Unix stream backend denied");
        close(pair[0]); close(pair[1]);
        bool ran = false;
        std::thread thread([&] { ran = namespace_changes_denied(); }); thread.join();
        require(ran, "new thread did not inherit VMM filter");
        require(child_status([] {
            require(namespace_changes_denied(), "fork child did not inherit VMM filter");
        }) == 0, "seccomp fork inheritance failed");
    }) == 0, "seccomp regression failed");
}
static void supervisor_network_test() {
    require(child_status([] {
        const auto uid = getuid(), gid = getgid();
        int original = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
        require(original >= 0, "open original network namespace failed");
        struct stat before{}, after{};
        require(fstat(original, &before) == 0, "stat original network namespace failed");
        avm::isolate_supervisor_network();
        require(stat("/proc/self/ns/net", &after) == 0, "stat supervisor network namespace failed");
        require(before.st_ino != after.st_ino, "supervisor retained host network namespace");
        require(getuid() == uid && geteuid() == uid && getgid() == gid && getegid() == gid,
                "supervisor identity changed");
        require(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "supervisor lacks no_new_privs");
        __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
        __user_cap_data_struct caps[2]{};
        require(syscall(SYS_capget, &header, caps) == 0, "supervisor capget failed");
        for (const auto& cap : caps)
            require(!(cap.effective | cap.permitted | cap.inheritable), "supervisor capabilities remain");
        errno = 0;
        require(setns(original, CLONE_NEWNET) == -1 && errno == EPERM, "supervisor can rejoin host network");
        close(original);
    }) == 0, "supervisor network isolation failed");
}
static void outer_mount_namespace() {
    const uid_t uid = getuid(); const gid_t gid = getgid();
    require(unshare(CLONE_NEWUSER) == 0, "test outer userns failed");
    auto map = [](const char* path, const std::string& text) {
        int fd = open(path, O_WRONLY | O_CLOEXEC);
        require(fd >= 0, "test map open failed");
        require(write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size()), "test map write failed");
        close(fd);
    };
    map("/proc/self/uid_map", std::to_string(uid) + " " + std::to_string(uid) + " 1\n");
    map("/proc/self/setgroups", "deny\n");
    map("/proc/self/gid_map", std::to_string(gid) + " " + std::to_string(gid) + " 1\n");
    require(unshare(CLONE_NEWNS) == 0, "test outer mountns failed");
    require(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == 0, "test private propagation failed");
}

struct Fixture {
    fs::path base, source, root, ipc, helper, spec;
    Fixture() {
        char path[] = "/tmp/agent-vm-sandbox-test-XXXXXX";
        char* made = mkdtemp(path); require(made, "mkdtemp failed"); base = made;
        source = base / "source"; root = base / "runtime/root"; ipc = base / "runtime/ipc";
        helper = base / "helper"; spec = base / "runtime/spec.bin";
        fs::create_directories(source / ".ssh");
        fs::create_directories(source / "nested");
        fs::create_directories(root); fs::create_directory(ipc);
        write_file(source / ".ssh/key", "never expose");
        write_file(source / "public", "public data");
        int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        sockaddr_un address{}; address.sun_family = AF_UNIX;
        auto ready = (ipc / "ready.sock").string();
        std::strcpy(address.sun_path, ready.c_str());
        require(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "bind fixture readiness");
        close(listener);
        write_file(helper, "helper fixture"); write_file(spec, "config fixture");
    }
    ~Fixture() { std::error_code ec; fs::remove_all(base, ec); }
    avm::RunSpec run_spec() const {
        avm::RunSpec s; s.uid = getuid(); s.gid = getgid(); s.username = "testuser";
        s.home = "/tmp/testuser-home"; s.cwd = "/work"; s.tmp_mib = 8;
        s.mounts = {{source.string(), "/work", false}, {source.string(), "/copy", false},
                    {(source / "nested").string(), "/work/nested", false}};
        s.mask_sources = {(source / ".ssh").string()};
        return s;
    }
    std::vector<avm::FilesystemExport> enter(avm::RunSpec s, const std::vector<int>& keep = {}) const {
        int control = avm::isolate_supervisor_network(true);
        return avm::enter_sandbox(s, root.string(), ipc.string(), spec.string(), helper.string(), keep, control);
    }
};
static void masked_child_test() {
    Fixture fixture;
    write_file(fixture.source / ".ssh/known_hosts", "public hosts");
    auto spec = fixture.run_spec();
    spec.mounts.push_back({(fixture.source / ".ssh/known_hosts").string(), "/work/.ssh/known_hosts", true});
    spec.mounts.push_back({(fixture.source / ".ssh/known_hosts").string(), "/hosts", true});
    require(child_status([&] {
        fixture.enter(spec);
        require(read_file("/work/.ssh/known_hosts") == "public hosts", "masked child not restored");
        require(read_file("/hosts") == "public hosts", "masked child alias not shared");
        require(!fs::exists("/work/.ssh/key"), "masked sibling exposed");
        require(fs::is_empty("/copy/.ssh"), "exception leaked into another alias");
        int fd = open("/work/.ssh/known_hosts", O_WRONLY);
        require(fd < 0 && errno == EROFS, "child lost read-only policy");
    }) == 0, "masked child regression failed");
    require(read_file((fixture.source / ".ssh/key").c_str()) == "never expose", "host mask changed");
}
// A shared directory authorizes its contents only up to more specific masks.
// Exercise both the assembled tree and every exported view of that directory.
static void masked_descendant_test() {
    for (int shape : {0, 1, 2}) for (bool target_mask : {false, true})
    for (bool read_only : {false, true}) for (bool reverse : {false, true}) {
        Fixture fixture;
        fs::create_directories(fixture.source / ".ssh/allowed/secret");
        write_file(fixture.source / ".ssh/allowed/visible", "allowed data");
        write_file(fixture.source / ".ssh/allowed/secret/token", "private token");
        write_file(fixture.source / ".ssh/allowed/secret-file", "private file");
        auto spec = fixture.run_spec();
        spec.mounts = {{fixture.source.string(), "/work", read_only},
                       {fixture.source.string(), "/copy", read_only}};
        spec.mask_sources.clear();
        if (shape != 0)
            spec.mounts.push_back({(fixture.source / ".ssh/allowed").string(), "/work/.ssh/allowed", !read_only});
        if (shape == 2) spec.mask_sources.push_back((fixture.source / ".ssh").string());
        const std::vector<std::string> hidden = shape == 0 ? std::vector<std::string>{".ssh"} :
            std::vector<std::string>{".ssh/allowed/secret", ".ssh/allowed/secret-file"};
        for (const auto& path : hidden) {
            if (target_mask) {
                spec.mask_targets.push_back("/work/" + path);
                spec.mask_targets.push_back("/copy/" + path);
            } else spec.mask_sources.push_back((fixture.source / path).string());
        }
        if (reverse) {
            std::reverse(spec.mounts.begin(), spec.mounts.end());
            std::reverse(spec.mask_sources.begin(), spec.mask_sources.end());
            std::reverse(spec.mask_targets.begin(), spec.mask_targets.end());
        }
        avm::validate_spec(spec);
        require(child_status([&] {
            fixture.enter(spec);
            for (const auto& parent : {std::string("/work"), std::string("/copy")}) {
                require(!fs::exists(parent + "/.ssh/allowed/secret/token"), "parent share exposed masked child");
                require(read_file((parent + "/.ssh/allowed/secret-file").c_str()).empty(), "parent share exposed masked file");
            }
            if (shape != 0)
                require(read_file("/work/.ssh/allowed/visible") == "allowed data", "child mask hid allowed sibling");
            unsigned checked = 0;
            for (const auto& object : fs::directory_iterator(AVM_EXPORT_TAG)) {
                const auto tree = object.path() / "root";
                if (fs::exists(tree / "public")) {
                    ++checked;
                    require(!fs::exists(tree / ".ssh/allowed/secret/token"), "parent export bypassed child mask");
                    require(read_file((tree / ".ssh/allowed/secret-file").c_str()).empty(), "parent export bypassed file mask");
                }
                if (fs::exists(tree / "visible")) {
                    ++checked;
                    require(!fs::exists(tree / "secret/token"), "restored directory export bypassed child mask");
                    require(read_file((tree / "secret-file").c_str()).empty(), "restored directory export bypassed file mask");
                    int fd = open((tree / "secret/new").c_str(), O_WRONLY | O_CREAT, 0600);
                    require(fd < 0 && errno == EROFS, "restored directory permits writes inside child mask");
                }
            }
            require(checked >= 2, "expected shared exports missing");
        }) == 0, "masked descendant regression failed");
        require(read_file((fixture.source / ".ssh/allowed/secret/token").c_str()) == "private token",
                "mask modified host contents");
    }
    std::cout << "masked descendants passed (24 combinations)\n";
}
static void nested_mount_modes_test() {
    Fixture fixture;
    const auto child = fixture.base / "child";
    const auto grandchild = fixture.base / "grandchild";
    const auto leaf = fixture.base / "leaf";
    fs::create_directories(child / "locked");
    fs::create_directories(grandchild / "writable");
    fs::create_directory(leaf);
    write_file(fixture.base / "file", "original");
    auto s = fixture.run_spec();
    // Deliberately reverse depth order, and use distinct sources so each
    // mountpoint must be resolved against its nearest mounted ancestor.
    s.mounts = {{leaf.string(), "/work/nested/locked/writable", false},
                {grandchild.string(), "/work/nested/locked", true},
                {child.string(), "/work/nested", false},
                {(fixture.base / "file").string(), "/work/public", false},
                {fixture.source.string(), "/work", true}};
    require(child_status([&] {
        auto exports = fixture.enter(s);
        require(exports.size() == 1 && exports[0].tag == AVM_EXPORT_TAG,
                "object exports must use a bounded number of devices");
        for (const char* path : {"/work/denied", "/work/nested/locked/denied"}) {
            const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
            require(fd == -1 && errno == EROFS, "read-only parent accepted a write");
        }
        write_file("/work/nested/created", "child");
        write_file("/work/nested/locked/writable/created", "leaf");
        write_file("/work/public", "file child");
        for (const auto& object : fs::directory_iterator(AVM_EXPORT_TAG)) {
            auto tree = object.path() / "root";
            if (fs::exists(tree / "nested/locked")) {
                int fd = open((tree / "denied").c_str(), O_WRONLY | O_CREAT, 0600);
                require(fd == -1 && errno == EROFS, "export registry bypassed parent read-only policy");
                fd = open((tree / "nested/locked/denied").c_str(), O_WRONLY | O_CREAT, 0600);
                require(fd == -1 && errno == EROFS, "export registry bypassed nested read-only policy");
                write_file(tree / "nested/locked/writable/exported", "allowed");
            }
        }
    }) == 0, "alternating nested mount modes failed");
    require(read_file((child / "created").c_str()) == "child", "rw child write missing on host");
    require(read_file((leaf / "created").c_str()) == "leaf", "rw leaf write missing on host");
    require(read_file((fixture.base / "file").c_str()) == "file child", "rw file mount write missing on host");
    require(read_file((fixture.source / "public").c_str()) == "public data", "covered parent file changed");
    require(!fs::exists(fixture.source / "denied") && !fs::exists(grandchild / "denied"), "read-only source changed");
    require(fs::is_empty(fixture.root), "nested mounts leaked to supervisor");

    for (bool parent_ro : {true, false}) {
        s.mounts = {{fixture.source.string(), "/work", parent_ro},
                    {child.string(), "/work/absent", !parent_ro}};
        const int status = child_status([&] {
            fixture.enter(s);
            require(read_file("/work/absent/created") == "child", "new target did not mount child");
        });
        require(parent_ro ? status != 0 : status == 0, "missing target did not respect parent mode");
        require(fs::exists(fixture.source / "absent") == !parent_ro, "mountpoint creation did not respect parent mode");
    }
    std::cout << "nested mount modes passed\n";
}
static void tmpfs_export_test() {
    Fixture fixture;
    fs::create_directory(fixture.source / "cache");
    write_file(fixture.source / "cache/host-only", "host content");
    auto s = fixture.run_spec();
    s.mounts = {{fixture.source.string(), "/work", true}};
    write_file(fixture.base / "selected", "selected data");
    write_file(fixture.base / "output", "initial");
    s.mounts.push_back({(fixture.base / "selected").string(), "/work/cache/selected", true});
    s.mounts.push_back({(fixture.base / "output").string(), "/work/cache/output", false});
    s.tmpfs = {{"/work/cache/nested", s.uid, s.gid, 0700},
               {"/work/cache", s.uid, s.gid, 0750}};
    struct stat before{};
    require(stat((fixture.source / "cache").c_str(), &before) == 0, "stat tmpfs fixture failed");
    require(child_status([&] {
        fixture.enter(s);
        require(!fs::exists("/work/cache/host-only") && fs::is_empty("/work/cache/nested"),
                "covered host tmpfs target remains visible to VMM");
        bool found = false;
        for (const auto& object : fs::directory_iterator(AVM_EXPORT_TAG)) {
            const auto tree = object.path() / "root";
            if (!fs::exists(tree / "public")) continue;
            found = true;
            require(!fs::exists(tree / "cache/host-only") && fs::is_empty(tree / "cache/nested"),
                    "object catalog exposes tmpfs-covered host content");
            require(read_file((tree / "cache/selected").c_str()) == "selected data",
                    "tmpfs staging hid an authorized child bind");
            int selected = open((tree / "cache/selected").c_str(), O_WRONLY);
            require(selected == -1 && errno == EROFS, "read-only tmpfs child bind became writable");
            write_file(tree / "cache/output", "authorized output");
            int fd = open((tree / "cache/new").c_str(), O_WRONLY | O_CREAT, 0600);
            require(fd == -1 && (errno == EROFS || errno == EACCES), "VMM can write tmpfs placeholder");
        }
        require(found, "tmpfs containing share not exported");
    }) == 0, "tmpfs export isolation failed");
    struct stat after{};
    require(stat((fixture.source / "cache").c_str(), &after) == 0, "stat tmpfs source after run failed");
    require(before.st_ino == after.st_ino && before.st_uid == after.st_uid &&
            before.st_gid == after.st_gid && before.st_mode == after.st_mode,
            "tmpfs preparation modified host target metadata");
    require(read_file((fixture.source / "cache/host-only").c_str()) == "host content",
            "tmpfs preparation changed host contents");
    require(!fs::exists(fixture.source / "cache/nested"), "nested tmpfs created a host mountpoint");
    require(!fs::exists(fixture.source / "cache/selected") && !fs::exists(fixture.source / "cache/output"),
            "bind children created host mountpoints below tmpfs");
    require(read_file((fixture.base / "output").c_str()) == "authorized output",
            "sealing tmpfs staging broke an authorized writable child");
    std::cout << "tmpfs export isolation passed\n";
}
static void integration_test() {
    Fixture fixture;
    auto s = fixture.run_spec();
    const std::string removable_target = "/run/media/test-user/test-volume/project";
    s.mounts.push_back({fixture.source.string(), removable_target, false});
    write_file(fixture.ipc / "private-marker", "host IPC");
    int leaked = open(fixture.source.c_str(), O_PATH | O_CLOEXEC);
    require(leaked >= 0, "open inherited fixture descriptor failed");
    require(child_status([&] {
        fixture.enter(s);
        require(read_file((removable_target + "/public").c_str()) == "public data",
                "bind below /run missing from host staging tree");
        require(read_file((std::string(AVM_BOOTSTRAP) + AVM_MOUNT_SPEC).c_str()).find(removable_target) != std::string::npos,
                "bind below /run missing from guest mount manifest");
        // Inspect the actual host export roots, independent of guest mounts
        // or guest privilege. The IPC bind must remain available only to VMM.
        require(!fs::exists("/.agent-vm/ipc/private-marker"), "VMM retains host IPC directory");
        require(unlink(AVM_READY_SOCKET) == -1, "VMM can replace readiness inode");
        require(symlink("/work/other.sock", AVM_READY_SOCKET) == -1, "VMM can redirect readiness");
        require(open("/.agent-vm/ipc/new", O_CREAT | O_WRONLY, 0600) == -1, "IPC parent is writable");
        struct statvfs control_fs{};
        require(statvfs("/.agent-vm/ipc/control", &control_fs) == 0, "stat control tmpfs");
        require(control_fs.f_blocks * control_fs.f_frsize <= 65536 && control_fs.f_files <= 16,
                "control storage lacks byte/inode bounds");
        int quota = open("/.agent-vm/ipc/control/quota", O_CREAT | O_WRONLY, 0600);
        require(quota >= 0, "control tmpfs not writable");
        std::string bytes(128 * 1024, 'x');
        ssize_t written = write(quota, bytes.data(), bytes.size());
        require(written > 0 && written <= 65536, "control tmpfs exceeded byte quota");
        require(write(quota, bytes.data(), 1) == -1 && errno == ENOSPC, "control byte quota not enforced");
        close(quota);
        require(unlink("/.agent-vm/ipc/control/quota") == 0, "remove quota fixture");
        unsigned created = 0;
        for (; created < 32; ++created) {
            auto path = "/.agent-vm/ipc/control/inode-" + std::to_string(created);
            if (mkdir(path.c_str(), 0700)) break;
        }
        require(created < 16 && errno == ENOSPC, "control inode quota not enforced");
        require(socket(AF_VSOCK, SOCK_STREAM, 0) == -1 && errno == EPERM,
                "isolated VMM can create a host vsock socket");
        struct stat ipc_info{};
        require(stat("/.agent-vm/ipc", &ipc_info) == 0, "stat private IPC failed");
        for (const auto& object : fs::directory_iterator(AVM_EXPORT_TAG)) {
            struct stat exported{};
            if (stat((object.path() / "root").c_str(), &exported) != 0) continue;
            require(exported.st_dev != ipc_info.st_dev || exported.st_ino != ipc_info.st_ino,
                    "private IPC directory entered the virtio-fs catalog");
            require(!fs::exists(object.path() / "root/.agent-vm/ipc"), "export contains private IPC");
        }
        require(!fs::exists(std::string(AVM_BOOTSTRAP) + "/.agent-vm/ipc"), "bootstrap exposes IPC");
        require(read_file((std::string(AVM_BOOTSTRAP) + AVM_MOUNT_SPEC).c_str()).find("/.agent-vm/ipc") == std::string::npos,
                "guest mount manifest includes IPC");
        require(getpid() == 1, "VMM did not become PID namespace init");
        require(getuid() == s.uid && getgid() == s.gid, "identity changed");
        require(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "no_new_privs absent");
        __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
        __user_cap_data_struct caps[2]{};
        require(syscall(SYS_capget, &header, caps) == 0, "capget failed");
        for (const auto& cap : caps) require(!(cap.effective | cap.permitted | cap.inheritable), "capabilities remain");
        require(fcntl(leaked, F_GETFD) == -1 && errno == EBADF, "source FD leaked");
        require(read_file("/work/public") == "public data", "shared public data unavailable");
        require(access("/work/.ssh/key", F_OK) == -1 && errno == ENOENT, "source mask leaked primary alias");
        require(access("/copy/.ssh/key", F_OK) == -1 && errno == ENOENT, "source mask leaked secondary alias");
        unsigned shared_objects = 0;
        for (const auto& object : fs::directory_iterator(AVM_EXPORT_TAG)) {
            const auto tree = object.path() / "root";
            if (!fs::exists(tree / "public")) continue;
            ++shared_objects;
            require(read_file((tree / "public").c_str()) == "public data", "export lost allowed data");
            require(!fs::exists(tree / ".ssh/key"), "VMM export registry bypassed a source mask");
            const int fd = open((tree / ".ssh/new").c_str(), O_WRONLY | O_CREAT, 0600);
            require(fd == -1 && (errno == EROFS || errno == EACCES), "VMM can write through export mask");
        }
        require(shared_objects == 3, "shared aliases missing from object registry");
        require(read_file(AVM_BOOTSTRAP AVM_GUEST_HELPER) == "helper fixture", "bootstrap helper truncated");
        require(read_file(AVM_BOOTSTRAP AVM_GUEST_SPEC) == "config fixture", "bootstrap spec truncated");
        require(!fs::exists(AVM_BOOTSTRAP "/dev/kvm"), "bootstrap exports host KVM node");
        require(!fs::exists(AVM_BOOTSTRAP "/proc/self"), "bootstrap exports host proc");
        require(!fs::exists(AVM_BOOTSTRAP "/work"), "bootstrap contains workload shares");
        int fd = open("/work/.ssh/new", O_WRONLY | O_CREAT, 0600);
        require(fd == -1 && (errno == EROFS || errno == EACCES), "masked directory is writable");
        fd = open("/etc/hostname", O_WRONLY);
        require(fd == -1 && errno == EROFS, "root skeleton is writable");
        fd = open("/etc/resolv.conf", O_WRONLY);
        require(fd >= 0, "private DHCP resolver is not writable"); close(fd);
        for (const auto& path : {s.home + "/ephemeral", std::string("/tmp/ephemeral"),
                                "/run/user/" + std::to_string(s.uid) + "/ephemeral"}) {
            fd = open(path.c_str(), O_WRONLY | O_CREAT, 0600);
            require(fd == -1 && errno == EROFS, "host retains writable guest-private tmpfs");
        }
        write_file("/work/created", "shared");
        struct statvfs usr_mount{}, shared_mount{};
        require(statvfs("/usr", &usr_mount) == 0 && (usr_mount.f_flag & ST_RDONLY), "/usr lacks read-only mount attribute");
        require(statvfs("/work", &shared_mount) == 0 && !(shared_mount.f_flag & ST_RDONLY), "shared writable mount became read-only");
        require(access(fixture.base.c_str(), F_OK) == -1, "old root remains visible");
        require(access("/.oldroot", F_OK) == -1, "old-root mountpoint remains");
        require(read_file("/proc/self/uid_map").find(std::to_string(s.uid)) != std::string::npos, "private proc lacks namespace process");
        require(namespace_changes_denied(), "sandbox returned without VMM filter");
    }) == 0, "sandbox integration failed");
    close(leaked);
    require(fs::exists(fixture.source / "created"), "shared output not visible on host");
    require(!fs::exists(fixture.ipc / "control"), "control data leaked to host runtime storage");
    require(fs::is_empty(fixture.root), "namespace mount leaked to supervisor");
    require(read_file((fixture.source / ".ssh/key").c_str()) == "never expose", "host secret changed");
    require(!fs::exists(fixture.source / ".ssh/new"), "mask modified source");

    // A mask above a share must suppress its standalone export as well.
    const auto hidden_source = fixture.base / "hidden-source";
    fs::create_directory(hidden_source);
    write_file(hidden_source / "secret", "not exported");
    auto hidden = fixture.run_spec();
    hidden.mounts.push_back({hidden_source.string(), "/hidden/child", false});
    hidden.mask_targets.push_back("/hidden");
    require(child_status([&] {
        fixture.enter(hidden);
        require(!fs::exists("/hidden/child"), "VMM can reach child beneath target mask");
        require(!fs::exists(hidden_source), "VMM retains original hidden source path");
        for (const auto& object : fs::directory_iterator(AVM_EXPORT_TAG)) {
            const auto tree = object.path() / "root";
            require(!fs::exists(tree / "secret") && !fs::exists(tree / "child/secret"),
                    "masked child remains accessible as a standalone export");
        }
    }) == 0, "target mask above an exported child failed");

    // Writable shared parents create missing mountpoints during launch.
    s = fixture.run_spec();
    s.mounts.push_back({(fixture.source / "nested").string(), "/work/absent", false});
    require(child_status([&] { fixture.enter(s); }) == 0, "missing writable nested target was rejected");
    require(fs::is_directory(fixture.source / "absent"), "nested target not created on host");
    s = fixture.run_spec();
    s.mask_sources = {(fixture.source / "future-secret").string()};
    require(child_status([&] { fixture.enter(s); }) != 0, "nonexistent shared mask was accepted");
    require(!fs::exists(fixture.source / "future-secret"), "missing mask created on host");
    fs::create_directory_symlink("nested", fixture.source / "alias");
    s = fixture.run_spec();
    s.mounts.push_back({(fixture.source / "nested").string(), "/work/alias", false});
    require(child_status([&] { fixture.enter(s); }) != 0, "symlink nested target was accepted");

    // Mount aliases need filesystem-root identity checks: canonical pathname
    // comparisons alone do not recognize either of these alternate entrances.
    fs::create_directory(fixture.base / "mounted-alias");
    require(child_status([&] {
        outer_mount_namespace();
        const auto alias = fixture.base / "mounted-alias";
        require(mount((fixture.source / ".ssh").c_str(), alias.c_str(), nullptr, MS_BIND, nullptr) == 0, "test secret alias mount failed");
        auto spec = fixture.run_spec();
        spec.mounts.push_back({alias.string(), "/keys", false});
        require(child_status([&] { fixture.enter(spec); }) != 0, "source mask accepted a bind alias");
    }) == 0, "source alias rejection failed");
    require(child_status([&] {
        outer_mount_namespace();
        const auto alias = fixture.base / "mounted-alias";
        require(mount("/usr", alias.c_str(), nullptr, MS_BIND | MS_REC, nullptr) == 0, "test usr alias mount failed");
        auto spec = fixture.run_spec();
        spec.mounts.push_back({alias.string(), "/writable-usr", false});
        require(child_status([&] { fixture.enter(spec); }) != 0, "writable /usr bind alias was accepted");
    }) == 0, "usr alias rejection failed");
    require(child_status([&] {
        outer_mount_namespace();
        const auto alias = fixture.base / "mounted-alias";
        require(mount((fixture.base / "runtime").c_str(), alias.c_str(), nullptr, MS_BIND, nullptr) == 0, "test runtime alias mount failed");
        auto spec = fixture.run_spec();
        spec.mounts.push_back({alias.string(), "/leaked-runtime", false});
        require(child_status([&] { fixture.enter(spec); }) != 0, "private runtime bind alias was accepted");
    }) == 0, "private runtime alias rejection failed");
    fs::create_directory(fixture.source / "nested-alias");
    require(child_status([&] {
        outer_mount_namespace();
        require(mount((fixture.source / ".ssh").c_str(), (fixture.source / "nested-alias").c_str(), nullptr, MS_BIND, nullptr) == 0, "test recursive secret alias mount failed");
        auto spec = fixture.run_spec();
        require(child_status([&] { fixture.enter(spec); }) != 0, "recursive source mask bind alias was accepted");
    }) == 0, "recursive source alias rejection failed");
    std::cout << "sandbox integration passed\n";
}
int main(int argc, char** argv) {
    try {
        seccomp_test();
        if (argc == 2 && std::string(argv[1]) == "--integration") {
            supervisor_network_test();
            integration_test();
            masked_child_test();
            masked_descendant_test();
            nested_mount_modes_test();
            tmpfs_export_test();
        }
        std::cout << "sandbox tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
