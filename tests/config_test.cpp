#include "agent_vm/spec.hpp"
#include "agent_vm/protocol.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
namespace {
int failures = 0, checks = 0;
void check(bool condition, const std::string& description) {
    ++checks;
    if (!condition) { ++failures; std::cerr << "FAIL: " << description << '\n'; }
}
avm::Options parse(std::vector<std::string> args) {
    args.insert(args.begin(), "agent-vm");
    std::vector<char*> ptrs;
    for (auto& arg : args) ptrs.push_back(arg.data());
    return avm::parse_options(static_cast<int>(ptrs.size()), ptrs.data());
}
void reject(const std::vector<std::string>& args, const std::string& reason) {
    try { parse(args); check(false, reason + " (accepted)"); }
    catch (const std::exception&) { check(true, reason); }
}
void reject_spec(const avm::RunSpec& spec, const std::string& reason) {
    try { avm::validate_spec(spec); check(false, reason + " (accepted)"); }
    catch (const std::exception&) { check(true, reason); }
}
class SocketFixture {
    int fd_ = -1;
public:
    explicit SocketFixture(const fs::path& path) {
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        auto name = path.string();
        if (name.size() >= sizeof(address.sun_path)) throw std::runtime_error("test socket path too long");
        std::memcpy(address.sun_path, name.c_str(), name.size() + 1);
        fd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd_ < 0) throw std::runtime_error("cannot create test socket");
        if (bind(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
            close(fd_);
            throw std::runtime_error("cannot bind test socket");
        }
    }
    ~SocketFixture() { close(fd_); }
    SocketFixture(const SocketFixture&) = delete;
    SocketFixture& operator=(const SocketFixture&) = delete;
};
void write(const fs::path& path, const std::string& content) {
    std::ofstream file(path); file << content;
    if (!file) throw std::runtime_error("cannot write test fixture");
}
} // namespace

int main() {
    auto old_cwd = fs::current_path();
    char pattern[] = "/tmp/agent-vm-config-test-XXXXXX";
    char* directory = mkdtemp(pattern);
    if (!directory) return 2;
    fs::path root(directory);
    try {
        fs::create_directories(root / "home/work");
        fs::create_directories(root / "home/.ssh");
        fs::create_directories(root / "home/.gnupg");
        fs::create_directories(root / "home/existing/outer-only");
        fs::create_directories(root / "data/nested");
        write(root / "home/file", "parent file\n");
        write(root / "data/file", "child file\n");
        write(root / "home/.gnupg/pubring.kbx", "public key fixture\n");
        fs::create_directory_symlink(root / "home/existing", root / "home/link");
        fs::create_directories(root / "config/agent-vm");
        setenv("HOME", (root / "home").c_str(), 1);
        setenv("XDG_CONFIG_HOME", (root / "config").c_str(), 1);
        unsetenv("SSH_AUTH_SOCK");
        unsetenv("AVM_UNSET_TEST_VARIABLE");
        fs::current_path(root / "home/work");
        const std::string cwd = fs::current_path();
        const std::string home = (root / "home").string();
        auto options = parse({"--no-config"});
        check(options.spec.uid == getuid() && options.spec.gid == getgid(), "identity uses caller IDs");
        check(options.spec.home == home && options.spec.cwd == cwd, "default canonical home/cwd");
        check(options.spec.mounts.size() == 1 && !options.spec.mounts[0].read_only, "default only shares cwd rw");
        check(!options.spec.network && !options.spec.ssh_agent, "network and SSH disabled by default");
        check(options.spec.command == std::vector<std::string>{"/bin/sh"}, "default shell");
        check(!options.spec.environment.contains("SSH_AUTH_SOCK"), "host SSH socket does not leak to environment");
        auto dbus_config = root / "dbus.toml";
        write(dbus_config, "[dbus.user]\nenabled = true\naddress = 'unix:path=/nonexistent/test-bus'\nargs = ['--talk=org.example.Service', '--call=org.example.Other=org.example.API.Read@/obj']\n[dbus.system]\nenabled = true\naddress = 'unix:path=/nonexistent/system-bus'\nargs = []\n");
        auto dbus = parse({"--config", dbus_config.string()}).spec;
        check(dbus.dbus_user.enabled && dbus.dbus_system.enabled && dbus.sockets.size() == 2,
              "both D-Bus buses independently materialize socket channels without launching proxies in plan");
        auto bus_target = "/run/user/" + std::to_string(getuid()) + "/dbus-user.socket";
        check(dbus.environment.at("DBUS_SESSION_BUS_ADDRESS") == "unix:path=" + bus_target &&
              dbus.environment.at("DBUS_SYSTEM_BUS_ADDRESS").ends_with("/dbus-system.socket"), "D-Bus guest addresses generated");
        reject({"--config", dbus_config.string(), "-e", "DBUS_SESSION_BUS_ADDRESS=unix:path=/wrong"}, "D-Bus environment conflict");
        for (auto arg : {"--fd=3", "--args=3", "unix:path=/extra", "--unknown", "--talk="}) {
            write(dbus_config, std::string("[dbus.user]\nargs = ['") + arg + "']\n");
            reject({"--config", dbus_config.string()}, "reject proxy control arguments and empty rules");
        }
        write(dbus_config, "[dbus.user]\nenabled = false\n[dbus.system]\nenabled = true\naddress = 'unix:path=/nonexistent/system-bus'\n");
        auto system_bus = parse({"--config", dbus_config.string()}).spec;
        check(system_bus.sockets.size() == 1 && !system_bus.environment.contains("DBUS_SESSION_BUS_ADDRESS"), "system bus independent of user bus");
        write(dbus_config, "[dbus.user]\nenabeld = true\n");
        reject({"--config", dbus_config.string()}, "unknown D-Bus fields rejected");
        check(avm::path_within("/a/b", "/a") && !avm::path_within("/ab", "/a"), "path component containment");
        check(avm::path_within("/a/b/../c", "/a/") && avm::path_within("/a", "/"), "normalized path containment");

        options = parse({"plan", "--no-config", "--home", "shared", "--mask", "~/.ssh", "--mount", "src=" + home + ",dst=/backup,ro"});
        check(options.action == avm::Options::Action::Plan && options.spec.mounts.size() == 3, "home, cwd and alias mounts accepted together");
        check(options.spec.mask_sources == std::vector<std::string>{home + "/.ssh"}, "mask canonicalized for all source aliases");
        reject({"--no-config", "--mask", cwd}, "CWD inside mask refused");
        reject({"--no-config", "--home", "shared", "--mask", "~/.missing"}, "missing mask under writable shared parent refused");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/backup,ro", "--mask", "~/.missing"}, "missing mask under read-only shared parent refused");
        reject({"--no-config", "--mask", "~/.ssh", "--mount", "src=" + home + "/.ssh,dst=/keys"}, "direct source mask bypass refused");
        write(root / "home/.ssh/known_hosts", "public hosts");
        options = parse({"--no-config", "--home", "shared", "--mask", "~/.ssh", "--mount",
                         "src=" + home + "/.ssh/known_hosts,dst=" + home + "/.ssh/known_hosts"});
        check(options.spec.mounts.size() == 3, "explicit child of source mask accepted");
        fs::current_path("/usr/bin");
        options = parse({"--no-config"});
        check(options.spec.mounts.empty() && options.spec.cwd == fs::canonical("/usr/bin"),
              "runtime CWD reuses usr mount");
        fs::current_path(home);
        options = parse({"--no-config", "--mount", "src=" + cwd + ",dst=" + home});
        check(options.spec.mounts.size() == 1 && options.spec.mounts[0].source == home,
              "home CWD overrides conflicting mount");
        fs::current_path(cwd);
        fs::create_directory_symlink(root / "home/.ssh", root / "alias");
        reject({"--no-config", "--mask", "~/.ssh", "--mount", "src=" + (root / "alias").string() + ",dst=/keys"}, "symlink alias bypass refused");
        parse({"--no-config", "--mask", "~/.missing"});
        check(true, "missing mask without shared ancestor is safe");
        reject({"--no-config", "--mask", "/usr/bin"}, "implicit /usr source masks fail explicitly");
        reject({"--no-config", "--mask-target", cwd}, "target mask on cwd refused");
        reject({"--no-config", "--mask-target", cwd + "/missing"}, "target mask missing beneath shared source refused");
        parse({"--no-config", "--mask-target", "/private/missing"});
        check(true, "private target mask can be created in generated root");

        for (const auto& mode : {"ro", "rw"}) {
            auto etc = parse({"--no-config", "--cwd-mode", "none", "--mount",
                              "src=" + home + ",dst=/etc/custom," + mode});
            check(etc.spec.mounts.size() == 1, "explicit /etc subtree bind accepted");
        }
        for (const auto& target : {"/etc", "/etc/resolv.conf", "/etc/resolv.conf/child"})
            reject({"--no-config", "--mount", "src=" + home + ",dst=" + target}, "generated etc root and DHCP resolver protected");
        reject({"--no-config", "--mount", "src=/usr,dst=/system,rw"}, "writable alias of /usr refused");
        parse({"--no-config", "--mount", "src=" + home + ",dst=/usr/share/misc"});
        parse({"--no-config", "--tmpfs", "target=/usr/share/misc", "--mount", "src=" + home + ",dst=/usr/share/misc/custom"});
        parse({"--no-config", "--tmpfs", "target=/etc/custom"});
        reject({"--no-config", "--mount", "src=" + home + ",dst=/usr/agent-vm-missing-test-target"}, "implicit read-only usr requires existing mountpoints");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/"}, "reserved system ancestors protected");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/var/../etc"}, "target normalization prevents traversal bypass");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/run"}, "runtime path protected");
        for (const auto& target : {"/run/media/test-user/test-volume/project", "/run/custom", "/tmp/custom", "/var/tmp/custom", "/mnt/custom", "/media/custom"}) {
            for (const auto& mode : {"ro", "rw"}) {
                auto mounted = parse({"--no-config", "--cwd-mode", "none", "--mount",
                                      "src=" + cwd + ",dst=" + target + "," + mode, "--workdir", target});
                check(mounted.spec.cwd == target && mounted.spec.mounts.size() == 1,
                      "workdir bind beneath a built-in filesystem accepted");
            }
        }
        for (const auto& target : {std::string("/run/user"), "/run/user/" + std::to_string(getuid())})
            reject({"--no-config", "--mount", "src=" + home + ",dst=" + target}, "managed runtime directory protected");
        parse({"--no-config", "--mount", "src=" + home + ",dst=/run/user/" + std::to_string(getuid()) + "/custom"});

        options = parse({"--no-config", "--mount", "src=" + home + ",dst=" + cwd});
        check(options.spec.mounts.size() == 1 && options.spec.mounts[0].source == cwd,
              "CWD wins over a conflicting source");
        for (const auto& mode : {"ro", "rw"}) {
            options = parse({"--no-config", "--cwd-mode", std::string(mode) == "ro" ? "rw" : "ro",
                             "--mount", "src=" + cwd + ",dst=" + cwd + "," + mode});
            check(options.spec.mounts.size() == 1 && options.spec.mounts[0].read_only == (std::string(mode) == "ro"),
                  "reused CWD mount retains its explicit mode");
        }
        parse({"--no-config", "--mount", "src=" + home + ",dst=/data,rw", "--mount", "src=" + home + ",dst=/data/new,ro"});
        parse({"--no-config", "--mount", "src=" + home + "/file,dst=/data/new/deep/file,ro", "--mount", "src=" + home + ",dst=/data,rw"});
        parse({"--no-config", "--mount", "src=" + home + ",dst=/data,rw", "--tmpfs", "target=/data/new/cache"});
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,rw", "--mount", "src=" + home + ",dst=/data/link/new"}, "creation cannot traverse symlinks");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,rw", "--mount", "src=" + home + ",dst=/data/file/new"}, "creation cannot traverse files");
        check(!fs::exists(root / "home/new"), "validation never creates a host mount point");
        parse({"--no-config", "--mount", "src=" + home + ",dst=/data", "--mount", "src=" + home + ",dst=/data/existing"});
        check(true, "existing nested target accepted");
        options = parse({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + home + ",dst=/data/existing,rw"});
        check(options.spec.mounts[0].read_only && !options.spec.mounts[1].read_only, "rw child below ro mount accepted with independent modes");
        options = parse({"--no-config", "--mount", "src=" + home + ",dst=/data/existing,rw", "--mount", "src=" + home + ",dst=/data,ro"});
        check(!options.spec.mounts[0].read_only && options.spec.mounts[1].read_only, "rw child below ro mount accepted before its parent in CLI order");
        options = parse({"--no-config", "--mount", "src=" + home + ",dst=" + home + ",ro"});
        check(options.spec.mounts.size() == 2 && options.spec.mounts[0].read_only && !options.spec.mounts[1].read_only, "default rw CWD allowed below explicit ro home");
        options = parse({"--no-config", "--mount", "src=" + home + ",dst=" + home + ",ro", "--cwd-mode", "ro"});
        check(options.spec.mounts.size() == 2 && options.spec.mounts[1].read_only, "cwd-mode ro keeps CWD read-only below ro home");
        options = parse({"--no-config", "--mount", "src=" + home + ",dst=/data,rw", "--mount", "src=" + home + ",dst=/data/existing,ro"});
        check(!options.spec.mounts[0].read_only && options.spec.mounts[1].read_only, "ro child below rw ancestor remains supported");
        parse({"--no-config", "--mount", "src=" + home + ",dst=/data,rw", "--mount", "src=" + home + ",dst=/data/existing,rw"});
        check(true, "rw child below rw ancestor remains supported");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + home + ",dst=/data/new,rw"}, "rw child under ro parent still requires an existing target");
        check(!fs::exists(root / "home/new"), "missing rw child target does not create a host path");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + home + ",dst=/data/file,rw"}, "directory child cannot cover a regular file target");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + (root / "data/file").string() + ",dst=/data/existing,rw"}, "file child cannot cover a directory target");
        parse({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + (root / "data/file").string() + ",dst=/data/file,rw"});
        check(true, "writable file child below ro directory accepted");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + home + ",dst=/data/link,rw"}, "rw child cannot use a symlink target");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + home + ",dst=/data/link/outer-only,rw"}, "rw child target cannot traverse an intermediate symlink");
        parse({"--no-config", "--mount", "src=" + cwd + ",dst=/data/existing/nested,rw", "--mount", "src=" + (root / "data").string() + ",dst=/data/existing,ro", "--mount", "src=" + home + ",dst=/data,ro"});
        check(true, "nested target is resolved in nearest shared parent regardless of CLI order");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,ro", "--mount", "src=" + (root / "data").string() + ",dst=/data/existing,ro", "--mount", "src=" + cwd + ",dst=/data/existing/outer-only,rw"}, "target existing only in a hidden ancestor source is rejected");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/data,ro,rw"}, "ambiguous mount flags refused");

        options = parse({"--no-config", "--tmpfs", "target=/cache/unused/../work"});
        check(options.spec.tmpfs.size() == 1 && options.spec.tmpfs[0].target == "/cache/work" &&
              options.spec.tmpfs[0].uid == getuid() && options.spec.tmpfs[0].gid == getgid() &&
              options.spec.tmpfs[0].mode == 0700, "tmpfs target normalization and caller ownership defaults");
        options = parse({"--no-config", "--tmpfs", "dst=~/scratch", "--tmpfs", "destination=/run/custom/deep,uid=0,gid=4294967294,mode=1777"});
        check(options.spec.tmpfs.size() == 2 && options.spec.tmpfs[0].target == home + "/scratch" &&
              options.spec.tmpfs[1].uid == 0 && options.spec.tmpfs[1].gid == UINT32_MAX - 1 &&
              options.spec.tmpfs[1].mode == 01777, "tmpfs target aliases, home expansion and explicit IDs/mode");
        options = parse({"--no-config", "--tmpfs", "target=/cache,uid=0,gid=0,mode=0000"});
        check(options.spec.tmpfs[0].uid == 0 && options.spec.tmpfs[0].gid == 0 && options.spec.tmpfs[0].mode == 0,
              "tmpfs root IDs and empty permissions accepted");
        std::ostringstream tmpfs_plan;
        auto previous_output = std::cout.rdbuf(tmpfs_plan.rdbuf());
        avm::print_plan(options.spec); std::cout.rdbuf(previous_output);
        check(tmpfs_plan.str().find("Tmpfs: /cache (uid=0, gid=0, mode=0o0)") != std::string::npos,
              "plan includes tmpfs target, ownership and octal permissions");
        for (const auto& fields : {"uid=1000", "target=", "target=/cache,target=/other", "target=/cache,dst=/other",
                                   "target=/cache,uid=1,uid=2", "target=/cache,gid=1,gid=2", "target=/cache,mode=700,mode=755",
                                   "target=/cache,source=/host", "target=/cache,ro", "target=/cache,uid", "target=/cache,"})
            reject({"--no-config", "--tmpfs", fields}, "invalid or duplicate tmpfs fields rejected: " + std::string(fields));
        for (const auto& value : {"-1", "+1", "", "4294967295", "4294967296", "1.5", "0x10", " 1"}) {
            reject({"--no-config", "--tmpfs", "target=/cache,uid=" + std::string(value)}, "invalid tmpfs uid rejected");
            reject({"--no-config", "--tmpfs", "target=/cache,gid=" + std::string(value)}, "invalid tmpfs gid rejected");
        }
        for (const auto& value : {"-1", "+700", "", "888", "10000", "0o700", "700 ", "7.0"})
            reject({"--no-config", "--tmpfs", "target=/cache,mode=" + std::string(value)}, "invalid tmpfs octal mode rejected");
        for (const auto& target : {"/", "/proc/cache", "/sys/cache", "/dev/cache",
                                   "/.agent-vm/cache", "/.oldroot/cache", "/ipc/cache", "/run", "/run/user", "/tmp", "/var", "/var/tmp"})
            reject({"--no-config", "--tmpfs", "target=" + std::string(target)}, "protected tmpfs target rejected: " + std::string(target));
        reject({"--no-config", "--tmpfs", "target=/run/user/" + std::to_string(getuid())}, "tmpfs cannot replace runtime user directory");
        reject({"--no-config", "--cwd-mode", "none", "--tmpfs", "target=" + home}, "tmpfs cannot replace private home");
        reject({"--no-config", "--tmpfs", "target=/cache", "--tmpfs", "target=/cache/sub/.."}, "normalized duplicate tmpfs targets rejected");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/cache", "--tmpfs", "target=/cache"}, "tmpfs and bind cannot share the same mount point");
        parse({"--no-config", "--mount", "src=" + home + ",dst=/cache/data", "--tmpfs", "target=/cache"});
        check(true, "shared directory can mount inside a custom tmpfs");
        parse({"--no-config", "--tmpfs", "target=/cache", "--mount", "src=" + home + "/file,dst=/cache/parent/file", "--workdir", "/cache/parent"});
        check(true, "file bind inside tmpfs creates private parent usable as workdir");
        parse({"--no-config", "--tmpfs", "target=/cache", "--mount", "src=" + (root / "data").string() + ",dst=/cache/data", "--workdir", "/cache/data/nested"});
        check(true, "workdir resolves in child bind contents beneath tmpfs");
        reject({"--no-config", "--tmpfs", "target=/cache", "--mount", "src=" + (root / "data").string() + ",dst=/cache/data", "--workdir", "/cache/data/missing"},
               "missing workdir in child bind beneath tmpfs rejected");
        reject({"--no-config", "--tmpfs", "target=/cache", "--mount", "src=" + home + "/file,dst=/cache/file", "--workdir", "/cache/file"},
               "file bind beneath tmpfs cannot be workdir");
        options = parse({"--no-config", "--tmpfs", "target=" + cwd});
        check(options.spec.tmpfs.empty(), "CWD wins over conflicting tmpfs");
        options = parse({"--no-config", "--tmpfs", "target=/cache/parent/child", "--tmpfs", "target=/cache", "--workdir", "/cache/parent"});
        check(options.spec.tmpfs.size() == 2 && options.spec.cwd == "/cache/parent", "nested tmpfs parents created regardless of CLI order");
        parse({"--no-config", "--tmpfs", "target=/cache", "--workdir", "/cache"});
        check(true, "tmpfs root can be the workdir");
        parse({"--no-config", "--tmpfs", "target=/cache/parent/child", "--workdir", "/cache/parent"});
        check(true, "ancestor directory created for tmpfs can be the workdir");
        reject({"--no-config", "--tmpfs", "target=/cache", "--workdir", "/cache/missing"}, "missing workdir under tmpfs rejected");
        parse({"--no-config", "--mount", "src=" + home + ",dst=/shared,ro", "--tmpfs", "target=/shared/existing"});
        check(true, "tmpfs can cover an existing directory in read-only shared mount");
        parse({"--no-config", "--mount", "src=" + home + ",dst=/shared,ro",
               "--tmpfs", "target=/shared/existing/new/deep", "--tmpfs", "target=/shared/existing", "--workdir", "/shared/existing/new"});
        check(!fs::exists(root / "home/existing/new"), "nested tmpfs creates paths only in private parent without host writes");
        const std::vector<std::vector<std::string>> mixed_layers = {
            {"--mount", "src=" + home + ",dst=/shared,ro"},
            {"--tmpfs", "target=/shared/existing"},
            {"--mount", "src=" + (root / "data").string() + ",dst=/shared/existing/private/new,ro"},
            {"--tmpfs", "target=/shared/existing/private/new/nested"},
            {"--mount", "src=" + home + "/file,dst=/shared/existing/private/new/nested/files/key,ro"}
        };
        for (bool reverse : {false, true}) {
            std::vector<std::string> args = {"--no-config", "--workdir", "/shared/existing/private/new/nested/files"};
            for (size_t i = 0; i < mixed_layers.size(); ++i) {
                const auto& layer = mixed_layers[reverse ? mixed_layers.size() - i - 1 : i];
                args.insert(args.end(), layer.begin(), layer.end());
            }
            options = parse(args);
            check(options.spec.tmpfs.size() == 2 && options.spec.mounts.size() == 4,
                  "alternating bind/tmpfs layers work in either declaration order");
        }
        check(!fs::exists(root / "home/existing/private") && !fs::exists(root / "data/nested/files"),
              "mixed layer validation never creates private placeholders in host sources");
        reject({"--no-config", "--tmpfs", "target=/cache", "--mount", "src=" + home + ",dst=/cache/data,ro",
                "--mount", "src=" + (root / "data").string() + ",dst=/cache/data/missing,ro"},
               "bind below child shared mount still requires existing source target");
        reject({"--no-config", "--tmpfs", "target=/cache", "--mount", "src=" + home + ",dst=/cache/data,ro",
                "--tmpfs", "target=/cache/data/missing"}, "tmpfs below child shared mount still requires existing source target");
        reject({"--no-config", "--tmpfs", "target=/cache", "--mount", "src=" + home + ",dst=/cache/data,ro",
                "--tmpfs", "target=/cache/data/link"}, "tmpfs below child shared mount cannot traverse source symlink");
        reject({"--no-config", "--tmpfs", "target=/cache", "--mount", "src=" + home + "/file,dst=/cache/file,ro",
                "--tmpfs", "target=/cache/file/child"}, "tmpfs cannot descend through child regular-file bind");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/shared,ro", "--tmpfs", "target=/shared/missing"}, "tmpfs cannot create mountpoint in shared source");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/shared,ro", "--tmpfs", "target=/shared/file"}, "tmpfs cannot cover regular file");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/shared,ro", "--tmpfs", "target=/shared/link"}, "tmpfs cannot cover source symlink");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/shared,ro", "--tmpfs", "target=/shared/link/outer-only"}, "tmpfs cannot traverse source symlink");
        parse({"--no-config", "--mount", "src=" + home + ",dst=/shared,ro", "--mount", "src=" + (root / "data").string() + ",dst=/shared/existing,ro",
               "--tmpfs", "target=/shared/existing/nested"});
        check(true, "tmpfs validates target in the nearest shared mount");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/shared,ro", "--mount", "src=" + (root / "data").string() + ",dst=/shared/existing,ro",
                "--tmpfs", "target=/shared/existing/outer-only"}, "tmpfs target hidden by nearest shared mount rejected");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/shared,ro", "--tmpfs", "target=/shared/existing", "--workdir", "/shared/existing/outer-only"},
               "workdir hidden by empty tmpfs rejected despite existing source directory");
        reject({"--no-config", "--tmpfs", "target=/cache", "--mask-target", "/cache/secrets"}, "tmpfs cannot contain masked target");
        reject({"--no-config", "--tmpfs", "target=/cache/data", "--mask-target", "/cache"}, "tmpfs cannot descend into masked target");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/shared,ro", "--tmpfs", "target=/shared/existing", "--mask", home + "/existing/outer-only"},
               "tmpfs cannot hide translated source mask");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/shared,ro", "--tmpfs", "target=/shared/existing/outer-only", "--mask", home + "/existing"},
               "tmpfs cannot bypass translated source mask");
        options = parse({"--no-config", "--tmpfs", "target=/cache"});
        auto invalid_tmpfs = options.spec;
        invalid_tmpfs.tmpfs[0].target += '\0';
        reject_spec(invalid_tmpfs, "re-exec tmpfs target rejects NUL");
        invalid_tmpfs = options.spec;
        invalid_tmpfs.tmpfs[0].target = "/run/custom/../other";
        reject_spec(invalid_tmpfs, "re-exec runtime tmpfs target must be normalized");
        invalid_tmpfs = options.spec;
        invalid_tmpfs.tmpfs[0].uid = UINT32_MAX;
        reject_spec(invalid_tmpfs, "re-exec tmpfs uid rejects sentinel");
        invalid_tmpfs = options.spec;
        invalid_tmpfs.tmpfs[0].gid = UINT32_MAX;
        reject_spec(invalid_tmpfs, "re-exec tmpfs gid rejects sentinel");
        invalid_tmpfs = options.spec;
        invalid_tmpfs.tmpfs[0].mode = 010000;
        reject_spec(invalid_tmpfs, "re-exec tmpfs mode rejects non-permission bits");
        invalid_tmpfs = options.spec;
        invalid_tmpfs.tmpfs.resize(65537, invalid_tmpfs.tmpfs[0]);
        reject_spec(invalid_tmpfs, "tmpfs mount count bounded by worker protocol");

        options = parse({"--no-config", "--cwd-mode", "none"});
        check(options.spec.mounts.empty() && options.spec.cwd == home, "disabled cwd sharing defaults workdir to private home");
        options = parse({"--no-config", "--workdir", "/tmp"});
        check(options.spec.cwd == "/tmp" && options.spec.mounts[0].source == cwd, "workdir leaves source cwd sharing intact");
        reject({"--no-config", "--workdir", "/not/provided"}, "inaccessible workdir rejected");
        reject({"--no-config", "--workdir", "/.agent-vm"}, "private bootstrap workdir rejected");
        fs::current_path(home);
        options = parse({"--no-config", "--home", "shared", "--cwd-mode", "ro"});
        check(options.spec.mounts.size() == 1 && options.spec.mounts[0].read_only, "home equal to cwd merges with cwd mode");
        fs::current_path(cwd);

        setenv("AVM_INHERIT", "secret-value", 1);
        options = parse({"--no-config", "-e", "AVM_INHERIT", "--env", "EMPTY=", "-eLITERAL=$(touch /must-not-run)", "--", "echo", "$(literal)", "--help"});
        check(options.spec.environment.at("AVM_INHERIT") == "secret-value" && options.spec.environment.at("EMPTY").empty(), "env inheritance and empty values");
        check(options.spec.environment.at("LITERAL") == "$(touch /must-not-run)", "values remain literal");
        check(options.spec.command == std::vector<std::string>{"echo", "$(literal)", "--help"}, "command argv preserved");
        std::ostringstream output;
        auto old = std::cout.rdbuf(output.rdbuf()); avm::print_plan(options.spec); std::cout.rdbuf(old);
        check(output.str().find("secret-value") == std::string::npos && output.str().find("AVM_INHERIT") != std::string::npos, "plan hides environment values");
        check(output.str().find("Network: none") != std::string::npos &&
              output.str().find("fixed control channel enabled") != std::string::npos &&
              output.str().find("implicit vsock/TSI disabled") != std::string::npos,
              "network-none plan accurately declares the fixed control vsock");
        reject({"--no-config", "-e", "AVM_UNSET_TEST_VARIABLE"}, "undefined inherited variable rejected");
        reject({"--no-config", "-e", "A-B=bad"}, "invalid env name rejected");
        reject({"--no-config", "-e", "KRUN_INIT=/bad"}, "reserved bootstrap env rejected");
        options = parse({"--no-config", "-e", "SSH_AUTH_SOCK=/tmp/manual.sock"});
        check(options.spec.environment.at("SSH_AUTH_SOCK") == "/tmp/manual.sock", "SSH env can name a manually forwarded socket");
        reject({"--no-config", "--ssh-agent"}, "missing host SSH socket rejected");
        parse({"--no-config", "--ssh-agent", "--no-ssh-agent"});
        check(true, "later CLI SSH disable overrides enable");

        const auto host_socket = (root / "agent.sock").string();
        SocketFixture socket_fixture(host_socket);
        fs::create_symlink(host_socket, root / "agent-link.sock");
        options = parse({"--no-config", "--socket", "source=../../agent-link.sock,destination=~/service/../sockets/api.sock"});
        check(options.spec.sockets.size() == 1 && options.spec.sockets[0].source == host_socket &&
              options.spec.sockets[0].target == home + "/sockets/api.sock", "socket source canonicalization, home expansion and CLI aliases");
        check(!options.spec.network && !options.spec.ssh_agent && !options.spec.environment.contains("SSH_AUTH_SOCK"),
              "generic socket forwarding requires neither network nor SSH settings");
        options = parse({"--no-config", "--socket", "src=" + host_socket + ",target=/run/custom/deep/service.sock",
                         "--socket", "src=" + host_socket + ",dst=/var/tmp/other.sock"});
        check(options.spec.sockets.size() == 2, "repeated sockets can share a source with distinct guest paths");
        output.str(""); output.clear();
        old = std::cout.rdbuf(output.rdbuf()); avm::print_plan(options.spec); std::cout.rdbuf(old);
        check(output.str().find(host_socket + " -> /run/custom/deep/service.sock") != std::string::npos &&
              output.str().find("2 authorized socket channels") != std::string::npos, "plan lists generic socket mappings");
        for (const auto& fields : std::vector<std::string>{"src=" + host_socket, "dst=/tmp/test.sock", "src=" + host_socket + ",dst=/tmp/test.sock,ro",
                                   "src=" + host_socket + ",source=" + host_socket + ",dst=/tmp/test.sock",
                                   "src=" + host_socket + ",dst=/tmp/a.sock,target=/tmp/b.sock"})
            reject({"--no-config", "--socket", fields}, "invalid or duplicate socket fields rejected");
        reject({"--no-config", "--socket", "src=" + home + "/file,dst=/tmp/test.sock"}, "regular file socket source rejected");
        reject({"--no-config", "--socket", "src=" + home + ",dst=/tmp/test.sock"}, "directory socket source rejected");
        reject({"--no-config", "--socket", "src=" + home + "/missing.sock,dst=/tmp/test.sock"}, "missing socket source rejected");
        for (const auto& target : {"/", "/etc/service.sock", "/proc/service.sock",
                                    "/dev/service.sock", "/.agent-vm/service.sock", "/ipc/service.sock",
                                    "/opt/new/service.sock", "/run", "/run/user", "/tmp", "/var/tmp"})
            reject({"--no-config", "--socket", "src=" + host_socket + ",dst=" + target}, "unavailable or protected socket target rejected: " + std::string(target));
        options = parse({"--no-config", "--socket", "src=" + host_socket + ",dst=/tmp/" + std::string(102, 's')});
        check(options.spec.sockets[0].target.size() == sizeof(sockaddr_un{}.sun_path) - 1, "maximum socket pathname accepted");
        reject({"--no-config", "--socket", "src=" + host_socket + ",dst=/tmp/" + std::string(103, 's')}, "overlong socket target rejected");
        reject({"--no-config", "--socket", "src=" + host_socket + ",dst=/tmp/test.sock",
                "--socket", "src=" + host_socket + ",dst=/tmp/sub/../test.sock"}, "normalized duplicate socket targets rejected");
        reject({"--no-config", "--socket", "src=" + host_socket + ",dst=/tmp/test.sock",
                "--socket", "src=" + host_socket + ",dst=/tmp/test.sock/child"}, "socket target ancestor conflicts rejected");
        options = parse({"--no-config", "--socket", "src=" + host_socket + ",dst=" + cwd + "/new/deep/api.sock"});
        check(options.spec.sockets.size() == 1 && !fs::exists(fs::path(cwd) / "new"), "socket parent may be created in writable shared mount without plan writes");
        reject({"--no-config", "--cwd-mode", "ro", "--socket", "src=" + host_socket + ",dst=" + cwd + "/new/api.sock"}, "socket in read-only mount rejected");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/shared,rw",
                "--socket", "src=" + host_socket + ",dst=/shared/file"}, "socket cannot replace existing shared file");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/shared,rw",
                "--socket", "src=" + host_socket + ",dst=/shared/link/api.sock"}, "socket parent cannot traverse shared symlink");
        reject({"--no-config", "--mount", "src=" + home + "/file,dst=/shared,rw",
                "--socket", "src=" + host_socket + ",dst=/shared/api.sock"}, "socket cannot descend through regular-file mount");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/tmp/service.sock/child,rw",
                "--socket", "src=" + host_socket + ",dst=/tmp/service.sock"}, "socket cannot contain a mount point");
        reject({"--no-config", "--mask-target", "/tmp/masked", "--socket", "src=" + host_socket + ",dst=/tmp/masked/api.sock"}, "socket target cannot bypass target mask");
        options = parse({"--no-config", "--mask", host_socket, "--socket", "src=" + host_socket + ",dst=/tmp/api.sock"});
        check(options.spec.sockets.size() == 1 && options.spec.sockets[0].source == host_socket,
              "explicit socket forwarding may expose a service from a masked source");
        reject({"--no-config", "--mount", "src=" + home + ",dst=/shared,rw", "--mask", home + "/.ssh",
                "--socket", "src=" + host_socket + ",dst=/shared/.ssh/api.sock"}, "socket target cannot bypass translated source mask");
        options = parse({"--no-config", "--tmpfs", "target=/cache", "--socket", "src=" + host_socket + ",dst=/cache/service/api.sock"});
        check(options.spec.sockets.size() == 1, "socket can listen under a custom writable tmpfs");
        options = parse({"--no-config", "--mount", "src=" + home + ",dst=/shared,ro", "--tmpfs", "target=/shared/existing",
                         "--socket", "src=" + host_socket + ",dst=/shared/existing/outer-only"});
        check(options.spec.sockets.size() == 1, "tmpfs socket ignores underlying read-only mount and hidden source leaf");
        options = parse({"--no-config", "--tmpfs", "target=/cache", "--mount", "src=" + (root / "data").string() + ",dst=/cache/data,rw",
                         "--socket", "src=" + host_socket + ",dst=/cache/data/new.sock"});
        check(options.spec.sockets.size() == 1, "socket can listen in writable child bind beneath tmpfs");
        reject({"--no-config", "--tmpfs", "target=/cache", "--mount", "src=" + (root / "data").string() + ",dst=/cache/data,ro",
                "--socket", "src=" + host_socket + ",dst=/cache/data/new.sock"}, "socket uses read-only policy of nearest child bind beneath tmpfs");
        reject({"--no-config", "--tmpfs", "target=/cache", "--mount", "src=" + (root / "data").string() + ",dst=/cache/data,rw",
                "--socket", "src=" + host_socket + ",dst=/cache/data/file"}, "socket checks existing leaf in nearest child bind beneath tmpfs");
        options = parse({"--no-config", "--tmpfs", "target=/cache", "--mount", "src=" + (root / "data").string() + ",dst=/cache/data,ro",
                         "--tmpfs", "target=/cache/data/nested", "--socket", "src=" + host_socket + ",dst=/cache/data/nested/api.sock"});
        check(options.spec.sockets.size() == 1, "socket resolves deepest tmpfs in alternating mount layers");
        reject({"--no-config", "--tmpfs", "target=/tmp/service.sock/child", "--socket", "src=" + host_socket + ",dst=/tmp/service.sock"},
               "socket cannot contain a tmpfs mount point");
        reject({"--no-config", "--tmpfs", "target=/tmp/service.sock", "--socket", "src=" + host_socket + ",dst=/tmp/service.sock"},
               "socket cannot replace a tmpfs mount point");

        setenv("SSH_AUTH_SOCK", host_socket.c_str(), 1);
        const auto ssh_target = "/run/user/" + std::to_string(getuid()) + "/ssh-agent.socket";
        options = parse({"--no-config", "--ssh-agent", "--socket", "src=" + host_socket + ",dst=/tmp/manual.sock"});
        check(options.spec.ssh_agent && options.spec.sockets.size() == 2 && options.spec.sockets[1].source == host_socket &&
              options.spec.sockets[1].target == ssh_target && options.spec.environment.at("SSH_AUTH_SOCK") == ssh_target,
              "SSH alias appends generic mapping and workload environment");
        auto invalid_spec = options.spec;
        invalid_spec.sockets.pop_back();
        reject_spec(invalid_spec, "re-exec SSH alias requires its mapping");
        invalid_spec = options.spec;
        invalid_spec.environment["SSH_AUTH_SOCK"] = "/tmp/incorrect.sock";
        reject_spec(invalid_spec, "re-exec SSH alias requires matching environment");
        reject({"--no-config", "--ssh-agent", "--socket", "src=" + host_socket + ",dst=" + ssh_target}, "SSH alias target conflicts with explicit socket");
        reject({"--no-config", "--ssh-agent", "-e", "SSH_AUTH_SOCK=/tmp/manual.sock"}, "SSH alias rejects conflicting explicit environment");
        options = parse({"--no-config", "--ssh-agent", "--no-ssh-agent", "--socket", "src=" + host_socket + ",dst=" + ssh_target,
                         "-e", "SSH_AUTH_SOCK=" + ssh_target});
        check(!options.spec.ssh_agent && options.spec.sockets.size() == 1 && options.spec.environment.at("SSH_AUTH_SOCK") == ssh_target,
              "disabling SSH alias preserves explicit generic mapping and environment");
        const auto masked_ssh_socket = (root / "home/.ssh/agent.sock").string();
        SocketFixture masked_ssh_fixture(masked_ssh_socket);
        setenv("SSH_AUTH_SOCK", masked_ssh_socket.c_str(), 1);
        auto masked_ssh = parse({"--no-config", "--home", "shared", "--mask", home + "/.ssh", "--ssh-agent"});
        check(masked_ssh.spec.ssh_agent && masked_ssh.spec.sockets.size() == 1 &&
              masked_ssh.spec.sockets[0].source == masked_ssh_socket && masked_ssh.spec.sockets[0].target == ssh_target,
              "SSH alias may expose agent service while its shared source directory remains masked");
        invalid_spec = options.spec;
        invalid_spec.sockets[0].source += '\0';
        reject_spec(invalid_spec, "re-exec rejects NUL in socket source");
        invalid_spec = options.spec;
        invalid_spec.sockets[0].target += '\0';
        reject_spec(invalid_spec, "re-exec rejects NUL in socket target");
        invalid_spec = options.spec;
        invalid_spec.sockets[0].source = (root / "agent-link.sock").string();
        reject_spec(invalid_spec, "re-exec rejects socket source changed to symlink");
        invalid_spec = options.spec;
        invalid_spec.sockets.clear();
        for (size_t i = 0; i <= AVM_SOCKET_MAX; ++i)
            invalid_spec.sockets.push_back({host_socket, "/tmp/socket-" + std::to_string(i)});
        reject_spec(invalid_spec, "socket forwarding count bounded by protocol");
        unsetenv("SSH_AUTH_SOCK");

        options = parse({"--no-config", "--network=passt", "-p8080:80", "--publish", "0.0.0.0:5353:53/udp"});
        check(options.spec.ports.size() == 2 && options.spec.ports[0].address == "127.0.0.1" && options.spec.ports[1].udp, "IPv4 publication and loopback default");
        for (const std::string bad : {"80", "localhost:80:80", "127.0.0.1:0:80", "65536:80", "80:80/sctp", "80-81:80", "::1:80:80", " 80:80"})
            reject({"--no-config", "--network", "passt", "-p", bad}, "invalid publication " + bad);
        reject({"--no-config", "-p", "8080:80"}, "network none rejects publication");
        reject({"--no-config", "--network", "passt", "-p", "8080:80", "-p", "0.0.0.0:8080:81"}, "overlapping bind address publication rejected");
        reject({"--no-config", "--cpus", "256"}, "CPU count overflow rejected");
        reject({"--no-config", "--memory", "-1"}, "negative memory rejected");
        reject({"--no-config", "--tmp-size", "0"}, "empty temporary size rejected");
        reject({"--no-config", "--typo"}, "unknown option rejected");
        reject({"--no-config", "--config", "anything"}, "conflicting config controls rejected");

        const fs::path config = root / "config/agent-vm/config.toml";
        write(config, "version = 1\n[vm]\ncpus = 3\nmemory_mib = 1024\n[filesystem]\ncwd = 'ro'\n[environment.set]\nOVERRIDE = 'config'\n[network]\nmode = 'passt'\n");
        options = parse({"--cpus", "4", "-e", "OVERRIDE=cli"});
        check(options.spec.cpus == 4 && options.spec.memory_mib == 1024 && options.spec.network, "config loaded and CLI scalar precedence");
        check(options.spec.environment.at("OVERRIDE") == "cli" && options.spec.mounts[0].read_only, "config env and cwd defaults");
        options = parse({"--no-config"});
        check(options.spec.cpus == 2 && !options.spec.network, "no-config ignores user file");
        write(root / "config/agent-vm/test.toml", "[vm]\ncpus = 5\n");
        write(root / "home/work/test.toml", "[vm]\ncpus = 9\n");
        options = parse({"--profile", "test"});
        check(options.spec.cpus == 5 && options.spec.memory_mib == 2048 && !options.spec.network,
              "profile selects XDG filename without loading default or project config");
        options = parse({"plan", "--profile=test", "--cpus", "6"});
        check(options.action == avm::Options::Action::Plan && options.spec.cpus == 6,
              "inline profile works with plan and CLI overrides");
        options = parse({"--no-config", "--", "echo", "--profile", "test"});
        check(options.spec.command == std::vector<std::string>{"echo", "--profile", "test"},
              "profile after command separator is preserved");
        reject({"--profile"}, "profile requires a value");
        reject({"--profile="}, "empty profile rejected");
        for (const auto& name : {".", "..", "../test", "/tmp/test", "nested/test"})
            reject({"--profile", name}, "profile path components rejected");
        reject({"--profile", "test", "--profile=test"}, "duplicate profile rejected");
        reject({"--profile", "test", "--config", config.string()}, "profile and config conflict");
        reject({"--no-config", "--profile", "test"}, "profile and no-config conflict");
        reject({"--profile", "missing"}, "missing explicit profile rejected");
        fs::create_symlink(root / "missing.toml", root / "config/agent-vm/dangling.toml");
        reject({"--profile", "dangling"}, "dangling profile symlink rejected");
        fs::create_directories(root / "home/.config/agent-vm");
        write(root / "home/.config/agent-vm/test.toml", "[vm]\ncpus = 7\n");
        unsetenv("XDG_CONFIG_HOME");
        check(parse({"--profile", "test"}).spec.cpus == 7, "profile uses home fallback when XDG is unset");
        for (const auto& xdg : {"", "relative"}) {
            setenv("XDG_CONFIG_HOME", xdg, 1);
            check(parse({"--profile", "test"}).spec.cpus == 7,
                  "profile uses home fallback when XDG is empty or relative");
        }
        setenv("XDG_CONFIG_HOME", (root / "config").c_str(), 1);
        write(config, "unknown = 1\n");
        reject({}, "unknown top-level config field rejected");
        write(config, "[filesystem]\nunknown = 1\n");
        reject({}, "unknown nested config field rejected");
        write(config, "[vm]\ncpus = 1.5\n");
        reject({}, "wrong TOML scalar type rejected");
        write(config, "[environment]\ninherit = [1]\n");
        reject({}, "wrong TOML array type rejected");
        write(config, "[environment]\ninherit = ['ASSIGNMENT=value']\n");
        reject({}, "config inherit accepts variable names only");
        write(config, "invalid toml !");
        check(parse({"doctor"}).action == avm::Options::Action::Doctor, "doctor ignores invalid user config");
        check(parse({"--help"}).action == avm::Options::Action::Help, "help ignores invalid user config");
        check(parse({"--version"}).action == avm::Options::Action::Version, "version ignores invalid user config");
        fs::remove(config);
        fs::create_symlink(root / "missing.toml", config);
        reject({}, "dangling default config symlink does not drop policy silently");
        fs::remove(config);
        write(root / "machine-id", "fixture-machine-id");
        write(root / "relative.toml", "[[mounts]]\nsource = '../../machine-id'\ntarget = '/etc/machine-id'\nmode = 'ro'\n");
        options = parse({"--config", (root / "relative.toml").string()});
        check(options.spec.mounts[0].target == "/etc/machine-id" && options.spec.mounts[0].read_only,
              "TOML accepts read-only machine-id bind");
        fs::create_directories(fs::path(cwd) / "data");
        write(root / "relative.toml", "[[mounts]]\nsource = 'data'\ntarget = '/dataset'\n");
        options = parse({"--config", (root / "relative.toml").string()});
        check(options.spec.mounts[0].source == (fs::path(cwd) / "data").string(), "config-relative source uses invoking working directory");
        fs::create_directories(fs::path(cwd) / ".git");
        const std::string mask_config = "[filesystem]\nmask_sources = ['.git']\nworkdir = '/tmp'\n";
        write(root / "relative.toml", mask_config);
        write(config, mask_config);
        write(root / "config/agent-vm/mask.toml", mask_config);
        for (const auto& args : std::vector<std::vector<std::string>>{
                 {"--config", "../../relative.toml"}, {}, {"--profile", "mask"}}) {
            options = parse(args);
            check(options.spec.mask_sources == std::vector<std::string>{cwd + "/.git"} &&
                  options.spec.cwd == "/tmp", "config mask uses invoking CWD independently of guest workdir and config selection");
        }
        fs::create_directories(fs::path(cwd) / "mount-here");
        fs::create_directories(fs::path(cwd) / "cache-here");
        fs::create_symlink("missing", fs::path(cwd) / "dangling");
        fs::create_symlink("loop", fs::path(cwd) / "loop");
        write(root / "relative.toml",
              "[filesystem]\nworkdir = '.'\nmask_try_sources = ['.git', 'missing', 'dangling', '../../home/file/child']\n"
              "mask_targets = ['data']\n"
              "[[mounts]]\nsource = '../../data'\ntarget = 'mount-here'\n"
              "[[tmpfs]]\ntarget = 'cache-here'\n"
              "[[sockets]]\nsource = '../../agent.sock'\ntarget = 'service.sock'\n");
        options = parse({"--config", "../../relative.toml", "--mask-try", ".git", "--mask-try", "missing"});
        check(options.spec.cwd == cwd && options.spec.mounts[0].target == cwd + "/mount-here" &&
              options.spec.tmpfs[0].target == cwd + "/cache-here" &&
              options.spec.sockets[0].target == cwd + "/service.sock" &&
              options.spec.mask_targets == std::vector<std::string>{cwd + "/data"},
              "all TOML filesystem targets resolve against invoking CWD");
        check(options.spec.mask_sources == std::vector<std::string>{cwd + "/.git"},
              "optional masks include existing paths, skip missing paths and deduplicate with CLI");
        options = parse({"--no-config", "--workdir", ".", "--mount", "src=../../data,dst=mount-here",
                         "--tmpfs", "target=cache-here", "--socket", "src=../../agent.sock,dst=service.sock",
                         "--mask-target", "data", "--mask-try", ".git"});
        check(options.spec.cwd == cwd && options.spec.mounts[0].target == cwd + "/mount-here" &&
              options.spec.tmpfs[0].target == cwd + "/cache-here" &&
              options.spec.sockets[0].target == cwd + "/service.sock" &&
              options.spec.mask_targets == std::vector<std::string>{cwd + "/data"},
              "CLI filesystem targets use the same invoking CWD");
        reject({"--no-config", "--mask-try", "loop"}, "optional mask does not ignore symlink loop errors");
        reject({"--no-config", "--mask-try", ""}, "optional mask rejects empty source");
        reject({"--no-config", "--mask-try", "."}, "optional mask retains shared source conflict validation");
        for (const auto& content : {"[filesystem]\nmask_try_sources = 'wrong'\n",
                                   "[filesystem]\nmask_try_sources = [1]\n"}) {
            write(root / "relative.toml", content);
            reject({"--config", "../../relative.toml"}, "optional mask rejects invalid TOML types");
        }
        fs::remove(config);
        write(root / "relative.toml", "[[tmpfs]]\ntarget = '~/.gnupg'\nuid = 1000\ngid = 1000\n"
                                     "[[mounts]]\nsource = '../.gnupg/pubring.kbx'\ntarget = '~/.gnupg/pubring.kbx'\nmode = 'ro'\n");
        options = parse({"--config", (root / "relative.toml").string()});
        check(options.spec.tmpfs[0].target == home + "/.gnupg" && options.spec.tmpfs[0].uid == 1000 &&
              options.spec.mounts[0].target == home + "/.gnupg/pubring.kbx" && options.spec.mounts[0].read_only,
              "TOML GnuPG tmpfs can expose selected read-only keyring file");
        write(root / "relative.toml", "[[tmpfs]]\ntarget = '~/scratch'\nuid = 0\ngid = 42\nmode = 0o750\n"
                                     "[[tmpfs]]\ntarget = '/cache'\n");
        options = parse({"--config", (root / "relative.toml").string(), "--tmpfs", "target=/run/services,uid=4294967294,gid=0,mode=7777"});
        check(options.spec.tmpfs.size() == 3 && options.spec.tmpfs[0].target == home + "/scratch" &&
              options.spec.tmpfs[0].uid == 0 && options.spec.tmpfs[0].gid == 42 && options.spec.tmpfs[0].mode == 0750,
              "TOML tmpfs parses ownership and octal mode and appends CLI entries");
        check(options.spec.tmpfs[1].uid == getuid() && options.spec.tmpfs[1].gid == getgid() && options.spec.tmpfs[1].mode == 0700 &&
              options.spec.tmpfs[2].uid == UINT32_MAX - 1 && options.spec.tmpfs[2].gid == 0 && options.spec.tmpfs[2].mode == 07777,
              "TOML tmpfs defaults and CLI numeric upper bounds preserved");
        reject({"--config", (root / "relative.toml").string(), "--tmpfs", "target=/cache"}, "duplicate config and CLI tmpfs targets rejected");
        for (const auto& content : {"tmpfs = 'wrong'\n", "tmpfs = [1]\n", "[[tmpfs]]\nuid = 0\n",
                                   "[[tmpfs]]\ntarget = 123\n", "[[tmpfs]]\ntarget = '/cache'\nsource = '/host'\n"}) {
            write(root / "relative.toml", content);
            reject({"--config", (root / "relative.toml").string()}, "invalid TOML tmpfs structure rejected");
        }
        for (const auto& field : {"uid = -1", "uid = 4294967295", "uid = '1000'", "uid = 1.5", "uid = true",
                                 "gid = -1", "gid = 4294967295", "gid = '1000'", "gid = 1.5",
                                 "mode = -1", "mode = 0o10000", "mode = '0700'", "mode = 1.5", "mode = true"}) {
            write(root / "relative.toml", "[[tmpfs]]\ntarget = '/cache'\n" + std::string(field) + "\n");
            reject({"--config", (root / "relative.toml").string()}, "invalid TOML tmpfs numeric property rejected");
        }
        write(root / "relative.toml", "[[sockets]]\nsource = '../../agent.sock'\ntarget = '/tmp/config.sock'\n"
                                     "[[sockets]]\nsource = '../../agent-link.sock'\ntarget = '/tmp/config-other.sock'\n"
                                     "[ssh_agent]\nenabled = true\n");
        setenv("SSH_AUTH_SOCK", host_socket.c_str(), 1);
        options = parse({"--config", (root / "relative.toml").string(), "--socket", "src=" + host_socket + ",dst=/tmp/cli.sock"});
        check(options.spec.sockets.size() == 4 && options.spec.sockets[0].source == host_socket &&
              options.spec.sockets[1].source == host_socket && options.spec.sockets[2].target == "/tmp/cli.sock" &&
              options.spec.sockets[3].target == ssh_target, "config sockets resolve relative sources and append CLI sockets and SSH alias");
        options = parse({"--config", (root / "relative.toml").string(), "--no-ssh-agent"});
        check(options.spec.sockets.size() == 2 && !options.spec.ssh_agent && !options.spec.environment.contains("SSH_AUTH_SOCK"),
              "CLI SSH disable preserves configured generic sockets");
        unsetenv("SSH_AUTH_SOCK");
        write(root / "relative.toml", "sockets = 'wrong'\n");
        reject({"--config", (root / "relative.toml").string()}, "wrong TOML sockets type rejected");
        write(root / "relative.toml", "sockets = [1]\n");
        reject({"--config", (root / "relative.toml").string()}, "non-table TOML socket rejected");
        write(root / "relative.toml", "[[sockets]]\nsource = '../../agent.sock'\n");
        reject({"--config", (root / "relative.toml").string()}, "incomplete TOML socket rejected");
        write(root / "relative.toml", "[[sockets]]\nsource = '../../agent.sock'\ntarget = '/tmp/config.sock'\nmode = 'rw'\n");
        reject({"--config", (root / "relative.toml").string()}, "unknown TOML socket fields rejected");
        write(root / "relative.toml", "[environment]\ninherit = ['KRUN_INIT']\n");
        reject({"--config", (root / "relative.toml").string()}, "config cannot inherit bootstrap settings");
    } catch (const std::exception& error) {
        ++failures;
        std::cerr << "UNEXPECTED: " << error.what() << '\n';
    }
    fs::current_path(old_cwd);
    fs::remove_all(root);
    std::cout << checks << " policy/parser checks, " << failures << " failures\n";
    return failures ? 1 : 0;
}
