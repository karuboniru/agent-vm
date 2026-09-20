#include "agent_vm/spec.hpp"
#include "agent_vm/protocol.h"

#include <toml++/toml.hpp>
#include <arpa/inet.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <optional>
#include <set>
#include <stdexcept>
#include <string_view>

namespace avm {
namespace {
namespace fs = std::filesystem;
[[noreturn]] void fail(const std::string& message) { throw std::runtime_error(message); }
std::string env(const char* name) { const char* v = std::getenv(name); return v ? v : ""; }
std::string normalize(const fs::path& path) {
    auto s = path.lexically_normal().string();
    while (s.size() > 1 && s.back() == '/') s.pop_back();
    return s;
}
std::string expand(const std::string& value, const std::string& home) {
    if (value == "~") return home;
    if (value.starts_with("~/")) return home + value.substr(1);
    if (value.starts_with('~')) fail("only ~ and ~/... home expansion are supported: " + value);
    return value;
}
std::string source_path(const std::string& value, const fs::path& base,
                        const std::string& home, bool must_exist) {
    if (value.empty() || value.find('\0') != std::string::npos) fail("source path must be nonempty and contain no NUL bytes");
    fs::path p(expand(value, home));
    if (p.is_relative()) p = base / p;
    std::error_code error;
    auto result = must_exist ? fs::canonical(p, error) : fs::weakly_canonical(p, error);
    if (error) fail("cannot resolve source '" + p.string() + "': " + error.message());
    return normalize(result);
}
std::string target_path(const std::string& value, const std::string& home) {
    if (value.empty() || value.find('\0') != std::string::npos) fail("target path must be nonempty and contain no NUL bytes");
    fs::path p(expand(value, home));
    if (!p.is_absolute()) fail("guest target must be absolute: " + value);
    return normalize(p);
}
bool env_key(const std::string& key) {
    if (key.empty() || !(std::isalpha(static_cast<unsigned char>(key[0])) || key[0] == '_')) return false;
    return std::all_of(key.begin() + 1, key.end(), [](unsigned char c) { return std::isalnum(c) || c == '_'; });
}
void check_env_key(const std::string& key) {
    if (!env_key(key)) fail("invalid environment variable name: " + key);
    if (key.starts_with("KRUN_")) fail("KRUN_* variables are reserved for the VM bootstrap: " + key);
}
void set_env(RunSpec& spec, const std::string& item) {
    auto split = item.find('=');
    const auto key = item.substr(0, split);
    check_env_key(key);
    if (split != std::string::npos) spec.environment[key] = item.substr(split + 1);
    else {
        const char* value = std::getenv(key.c_str());
        if (!value) fail("cannot inherit undefined environment variable: " + key);
        spec.environment[key] = value;
    }
}
uint32_t number(std::string_view value, uint32_t maximum, const std::string& label) {
    uint32_t n = 0;
    auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), n);
    if (ec != std::errc() || end != value.data() + value.size() || n == 0 || n > maximum)
        fail(label + " must be an integer between 1 and " + std::to_string(maximum));
    return n;
}
uint32_t unsigned_number(std::string_view value, uint32_t maximum, const std::string& label, int base = 10) {
    uint32_t n = 0;
    auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), n, base);
    if (ec != std::errc() || end != value.data() + value.size() || n > maximum)
        fail(label + " must be " + (base == 8 ? "an octal" : "a decimal") + " integer between 0 and " + std::to_string(maximum));
    return n;
}
std::vector<std::string> split(const std::string& value, char delimiter) {
    std::vector<std::string> result;
    size_t begin = 0;
    for (;;) {
        auto end = value.find(delimiter, begin);
        result.push_back(value.substr(begin, end - begin));
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    return result;
}
PortSpec port_spec(const std::string& value) {
    PortSpec port;
    auto slash = value.find('/');
    std::string ports = value.substr(0, slash);
    if (slash != std::string::npos) {
        auto protocol = value.substr(slash + 1);
        if (protocol != "tcp" && protocol != "udp") fail("publish protocol must be tcp or udp: " + value);
        port.udp = protocol == "udp";
    }
    auto parts = split(ports, ':');
    if (parts.size() == 3) port.address = parts[0];
    else if (parts.size() != 2) fail("publish expects [IPv4:]HOST_PORT:GUEST_PORT[/tcp|udp]: " + value);
    in_addr address{};
    if (inet_pton(AF_INET, port.address.c_str(), &address) != 1)
        fail("publish address must be an IPv4 literal: " + port.address);
    port.host_port = static_cast<uint16_t>(number(parts[parts.size() - 2], 65535, "host port"));
    port.guest_port = static_cast<uint16_t>(number(parts.back(), 65535, "guest port"));
    return port;
}
MountSpec mount_spec(const std::string& value, const fs::path& base, const std::string& home) {
    std::optional<std::string> source, target;
    std::optional<bool> read_only;
    bool type_seen = false;
    for (const auto& token : split(value, ',')) {
        auto eq = token.find('=');
        auto key = token.substr(0, eq);
        auto v = eq == std::string::npos ? std::string{} : token.substr(eq + 1);
        if (key == "type") {
            if (type_seen || v != "bind") fail("mount accepts type=bind exactly once");
            type_seen = true;
        } else if (key == "src" || key == "source") {
            if (source || eq == std::string::npos) fail("mount requires one source");
            source = v;
        } else if (key == "dst" || key == "target" || key == "destination") {
            if (target || eq == std::string::npos) fail("mount requires one target");
            target = v;
        } else if (key == "ro" || key == "rw" || key == "readonly") {
            if (read_only) fail("mount has conflicting or duplicate modes");
            if (key == "rw") {
                if (eq != std::string::npos) fail("mount rw does not accept a value");
                read_only = false;
            } else {
                if (eq == std::string::npos || v == "true") read_only = true;
                else if (v == "false") read_only = false;
                else fail("mount readonly value must be true or false");
            }
        } else fail("unknown mount field: " + key);
    }
    if (!source || !target) fail("mount requires src=SOURCE,dst=TARGET");
    return {source_path(*source, base, home, true), target_path(*target, home), read_only.value_or(true)};
}
TmpfsSpec tmpfs_spec(const std::string& value, const RunSpec& spec) {
    TmpfsSpec result{"", spec.uid, spec.gid, 0700};
    std::optional<std::string> target;
    std::set<std::string> fields;
    for (const auto& token : split(value, ',')) {
        auto eq = token.find('=');
        auto key = token.substr(0, eq);
        auto v = eq == std::string::npos ? std::string{} : token.substr(eq + 1);
        if (key == "dst" || key == "destination") key = "target";
        if (eq == std::string::npos || !fields.insert(key).second)
            fail("tmpfs fields require unique key=value pairs");
        if (key == "target") target = v;
        else if (key == "uid") result.uid = unsigned_number(v, UINT32_MAX - 1, "tmpfs uid");
        else if (key == "gid") result.gid = unsigned_number(v, UINT32_MAX - 1, "tmpfs gid");
        else if (key == "mode") result.mode = unsigned_number(v, 07777, "tmpfs mode", 8);
        else fail("unknown tmpfs field: " + key);
    }
    if (!target) fail("tmpfs requires target=PATH");
    result.target = target_path(*target, spec.home);
    return result;
}
SocketSpec socket_spec(const std::string& value, const fs::path& base, const std::string& home) {
    std::optional<std::string> source, target;
    for (const auto& token : split(value, ',')) {
        auto eq = token.find('=');
        auto key = token.substr(0, eq);
        auto v = eq == std::string::npos ? std::string{} : token.substr(eq + 1);
        if (key == "src" || key == "source") {
            if (source || eq == std::string::npos) fail("socket requires one source");
            source = v;
        } else if (key == "dst" || key == "target" || key == "destination") {
            if (target || eq == std::string::npos) fail("socket requires one target");
            target = v;
        } else fail("unknown socket field: " + key);
    }
    if (!source || !target) fail("socket requires src=SOURCE,dst=TARGET");
    return {source_path(*source, base, home, true), target_path(*target, home)};
}
void keys(const toml::table& table, std::initializer_list<std::string_view> allowed, const std::string& context) {
    for (const auto& [key, value] : table) {
        (void)value;
        if (std::find(allowed.begin(), allowed.end(), key.str()) == allowed.end())
            fail("unknown configuration field: " + context + std::string(key.str()));
    }
}
const toml::table* table_at(const toml::table& table, const char* key) {
    auto n = table.get(key);
    if (!n) return nullptr;
    auto result = n->as_table();
    if (!result) fail(std::string(key) + " must be a TOML table");
    return result;
}
std::optional<std::string> string_at(const toml::table& table, const char* key) {
    auto n = table.get(key);
    if (!n) return {};
    auto result = n->value<std::string>();
    if (!result) fail(std::string(key) + " must be a string");
    return result;
}
std::optional<bool> bool_at(const toml::table& table, const char* key) {
    auto n = table.get(key);
    if (!n) return {};
    auto result = n->value<bool>();
    if (!result) fail(std::string(key) + " must be a boolean");
    return result;
}
std::optional<uint32_t> int_at(const toml::table& table, const char* key, uint32_t maximum) {
    auto n = table.get(key);
    if (!n) return {};
    auto result = n->value<int64_t>();
    if (!n->is_integer() || !result || *result <= 0 || static_cast<uint64_t>(*result) > maximum)
        fail(std::string(key) + " must be an integer between 1 and " + std::to_string(maximum));
    return static_cast<uint32_t>(*result);
}
std::optional<uint32_t> unsigned_int_at(const toml::table& table, const char* key, uint32_t maximum) {
    auto n = table.get(key);
    if (!n) return {};
    auto result = n->value<int64_t>();
    if (!n->is_integer() || !result || *result < 0 || static_cast<uint64_t>(*result) > maximum)
        fail(std::string(key) + " must be an integer between 0 and " + std::to_string(maximum));
    return static_cast<uint32_t>(*result);
}
std::vector<std::string> array_at(const toml::table& table, const char* key) {
    auto n = table.get(key);
    if (!n) return {};
    auto array = n->as_array();
    if (!array) fail(std::string(key) + " must be an array of strings");
    std::vector<std::string> result;
    for (const auto& element : *array) {
        auto v = element.value<std::string>();
        if (!v) fail(std::string(key) + " must contain strings only");
        result.push_back(*v);
    }
    return result;
}
void network_mode(RunSpec& spec, const std::string& value) {
    if (value != "none" && value != "passt") fail("network must be none or passt");
    spec.network = value == "passt";
}
void home_mode(std::string& mode, const std::string& value) {
    if (value != "ephemeral" && value != "shared") fail("home must be ephemeral or shared");
    mode = value;
}
void cwd_mode(std::string& mode, const std::string& value) {
    if (value != "ro" && value != "rw" && value != "none") fail("cwd mode must be ro, rw or none");
    mode = value;
}
void load_config(const fs::path& file, RunSpec& spec, std::string& home,
                 std::string& cwd, std::optional<std::string>& workdir) {
    toml::table root;
    try { root = toml::parse_file(file.string()); }
    catch (const toml::parse_error& e) { fail("configuration '" + file.string() + "': " + std::string(e.description())); }
    keys(root, {"version", "vm", "filesystem", "mounts", "tmpfs", "sockets", "environment", "network", "ssh_agent"}, "");
    if (auto n = root.get("version")) {
        if (!n->is_integer() || n->value<int64_t>() != 1) fail("configuration version must be 1");
    }
    if (auto t = table_at(root, "vm")) {
        keys(*t, {"cpus", "memory_mib", "tmp_mib"}, "vm.");
        if (auto v = int_at(*t, "cpus", 255)) spec.cpus = static_cast<uint8_t>(*v);
        if (auto v = int_at(*t, "memory_mib", UINT32_MAX)) spec.memory_mib = *v;
        if (auto v = int_at(*t, "tmp_mib", UINT32_MAX)) spec.tmp_mib = *v;
    }
    if (auto t = table_at(root, "filesystem")) {
        keys(*t, {"cwd", "home", "workdir", "mask_sources", "mask_targets"}, "filesystem.");
        if (auto v = string_at(*t, "cwd")) cwd_mode(cwd, *v);
        if (auto v = string_at(*t, "home")) home_mode(home, *v);
        if (auto v = string_at(*t, "workdir")) workdir = target_path(*v, spec.home);
        for (const auto& v : array_at(*t, "mask_sources"))
            spec.mask_sources.push_back(source_path(v, file.parent_path(), spec.home, false));
        for (const auto& v : array_at(*t, "mask_targets")) spec.mask_targets.push_back(target_path(v, spec.home));
    }
    if (auto n = root.get("mounts")) {
        auto array = n->as_array();
        if (!array) fail("mounts must be an array of tables");
        for (const auto& v : *array) {
            auto t = v.as_table();
            if (!t) fail("mounts must contain tables only");
            keys(*t, {"source", "target", "mode"}, "mounts.");
            auto source = string_at(*t, "source"), target = string_at(*t, "target");
            if (!source || !target) fail("each mount requires source and target");
            auto mode = string_at(*t, "mode").value_or("ro");
            if (mode != "ro" && mode != "rw") fail("mount mode must be ro or rw");
            spec.mounts.push_back({source_path(*source, file.parent_path(), spec.home, true),
                                   target_path(*target, spec.home), mode == "ro"});
        }
    }
    if (auto n = root.get("tmpfs")) {
        auto array = n->as_array();
        if (!array) fail("tmpfs must be an array of tables");
        for (const auto& v : *array) {
            auto t = v.as_table();
            if (!t) fail("tmpfs must contain tables only");
            keys(*t, {"target", "uid", "gid", "mode"}, "tmpfs.");
            auto target = string_at(*t, "target");
            if (!target) fail("each tmpfs requires target");
            spec.tmpfs.push_back({target_path(*target, spec.home),
                                 unsigned_int_at(*t, "uid", UINT32_MAX - 1).value_or(spec.uid),
                                 unsigned_int_at(*t, "gid", UINT32_MAX - 1).value_or(spec.gid),
                                 unsigned_int_at(*t, "mode", 07777).value_or(0700)});
        }
    }
    if (auto n = root.get("sockets")) {
        auto array = n->as_array();
        if (!array) fail("sockets must be an array of tables");
        for (const auto& v : *array) {
            auto t = v.as_table();
            if (!t) fail("sockets must contain tables only");
            keys(*t, {"source", "target"}, "sockets.");
            auto source = string_at(*t, "source"), target = string_at(*t, "target");
            if (!source || !target) fail("each socket requires source and target");
            spec.sockets.push_back({source_path(*source, file.parent_path(), spec.home, true),
                                    target_path(*target, spec.home)});
        }
    }
    if (auto t = table_at(root, "environment")) {
        keys(*t, {"inherit", "set"}, "environment.");
        for (const auto& v : array_at(*t, "inherit")) {
            check_env_key(v);
            set_env(spec, v);
        }
        if (auto set = table_at(*t, "set")) {
            for (const auto& [key, n] : *set) {
                auto v = n.value<std::string>();
                if (!v) fail("environment.set values must be strings");
                check_env_key(std::string(key.str()));
                spec.environment[std::string(key.str())] = *v;
            }
        }
    }
    if (auto t = table_at(root, "network")) {
        keys(*t, {"mode", "publish"}, "network.");
        if (auto v = string_at(*t, "mode")) network_mode(spec, *v);
        for (const auto& v : array_at(*t, "publish")) spec.ports.push_back(port_spec(v));
    }
    if (auto t = table_at(root, "ssh_agent")) {
        keys(*t, {"enabled"}, "ssh_agent.");
        if (auto v = bool_at(*t, "enabled")) spec.ssh_agent = *v;
    }
}
const std::vector<std::string> reserved = {"/usr", "/etc", "/proc", "/sys", "/dev", "/.agent-vm",
                                         "/bin", "/sbin", "/lib", "/lib64", "/run", "/ipc"};
void check_target(const std::string& target, const char* kind) {
    if (target.empty() || target[0] != '/' || normalize(target) != target)
        fail(std::string(kind) + " target must be a normalized absolute path: " + target);
    for (const auto& path : reserved) {
        if (path_within(target, path) || path_within(path, target))
            fail(std::string(kind) + " target overlaps a reserved guest path: " + target);
    }
}
void check_existing_target(const MountSpec& parent, const std::string& target, bool want_directory) {
    fs::path relative = fs::path(target).lexically_relative(parent.target);
    fs::path physical(parent.source);
    for (const auto& component : relative) {
        if (component == ".") continue;
        physical /= component;
        std::error_code error;
        auto status = fs::symlink_status(physical, error);
        if (error || status.type() == fs::file_type::not_found)
            fail("nested mount/mask target does not exist in shared source; refusing to create host path: " + physical.string());
        if (fs::is_symlink(status)) fail("nested mount/mask target traverses a source symlink: " + physical.string());
    }
    std::error_code error;
    bool directory = fs::is_directory(physical, error);
    if (error || directory != want_directory)
        fail("nested mount target type differs from source: " + target);
}
const MountSpec* nearest_mount(const RunSpec& spec, const std::string& target, bool equal) {
    const MountSpec* result = nullptr;
    for (const auto& mount : spec.mounts)
        if ((equal || target != mount.target) && path_within(target, mount.target) &&
            (!result || mount.target.size() > result->target.size())) result = &mount;
    return result;
}
const TmpfsSpec* nearest_tmpfs(const RunSpec& spec, const std::string& target, bool equal) {
    const TmpfsSpec* result = nullptr;
    for (const auto& tmpfs : spec.tmpfs)
        if ((equal || target != tmpfs.target) && path_within(target, tmpfs.target) &&
            (!result || tmpfs.target.size() > result->target.size())) result = &tmpfs;
    return result;
}
bool covered_by_tmpfs(const RunSpec& spec, const std::string& target) {
    auto tmpfs = nearest_tmpfs(spec, target, true);
    auto mount = nearest_mount(spec, target, true);
    return tmpfs && (!mount || tmpfs->target.size() > mount->target.size());
}
void check_socket_path(const std::string& path, const char* kind) {
    if (path.empty() || path[0] != '/' || path.find('\0') != std::string::npos || normalize(path) != path)
        fail(std::string("socket ") + kind + " must be a normalized absolute pathname: " + path);
    if (path.size() >= sizeof(sockaddr_un{}.sun_path))
        fail(std::string("socket ") + kind + " exceeds the Unix socket pathname limit: " + path);
}
void check_socket_mount(const MountSpec& mount, const std::string& target) {
    if (mount.read_only) fail("socket target is inside a read-only shared mount: " + target);
    fs::path physical(mount.source);
    std::error_code error;
    if (!fs::is_directory(physical, error) || error)
        fail("socket target is inside a regular-file mount: " + target);
    auto relative = fs::path(target).lexically_relative(mount.target);
    for (const auto& component : relative) {
        physical /= component;
        auto status = fs::symlink_status(physical, error);
        if (status.type() == fs::file_type::not_found || error == std::errc::no_such_file_or_directory) return;
        if (error) fail("cannot inspect shared socket target: " + physical.string() + ": " + error.message());
        if (fs::is_symlink(status)) fail("socket target traverses a shared source symlink: " + physical.string());
        if (!fs::is_directory(status)) fail("socket target already exists or has a non-directory parent: " + physical.string());
    }
    fail("socket target already exists in a shared source: " + target);
}
bool paths_overlap(const std::string& a, const std::string& b) {
    return path_within(a, b) || path_within(b, a);
}
void deduplicate(std::vector<std::string>& values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
}
} // namespace

bool path_within(const std::string& path, const std::string& parent) {
    if (path.empty() || parent.empty()) return false;
    auto p = normalize(path), base = normalize(parent);
    return p == base || (base == "/" && p.starts_with('/')) ||
           (p.size() > base.size() && p.starts_with(base) && p[base.size()] == '/');
}

Options parse_options(int argc, char** argv) {
    Options options;
    int start = 1;
    if (argc > 1) {
        std::string action(argv[1]);
        if (action == "run") ++start;
        else if (action == "plan") { options.action = Options::Action::Plan; ++start; }
        else if (action == "doctor") { options.action = Options::Action::Doctor; ++start; }
        else if (action == "help") { options.action = Options::Action::Help; return options; }
        else if (action == "version") { options.action = Options::Action::Version; return options; }
    }
    for (int i = start; i < argc && std::string_view(argv[i]) != "--"; ++i) {
        if (std::string_view(argv[i]) == "--help" || std::string_view(argv[i]) == "-h") {
            options.action = Options::Action::Help; return options;
        }
        if (std::string_view(argv[i]) == "--version") {
            options.action = Options::Action::Version; return options;
        }
    }
    if (options.action == Options::Action::Doctor) {
        if (argc > start) fail("doctor does not accept run options");
        return options;
    }
    std::optional<std::string> config;
    bool no_config = false;
    std::vector<std::string> args;
    for (int i = start; i < argc; ++i) {
        std::string a(argv[i]);
        if (a == "--") {
            args.push_back(a);
            for (++i; i < argc; ++i) args.emplace_back(argv[i]);
            break;
        }
        if (a == "--no-config") no_config = true;
        else if (a == "--config" || a.starts_with("--config=")) {
            if (config) fail("--config can only be specified once");
            if (a == "--config") {
                if (++i == argc) fail("--config requires a file");
                config = argv[i];
            } else config = a.substr(9);
        } else args.push_back(a);
    }
    if (no_config && config) fail("--config and --no-config cannot be combined");
    auto& spec = options.spec;
    spec.uid = getuid(); spec.gid = getgid();
    if (getuid() != geteuid() || getgid() != getegid()) fail("agent-vm must not run as a setuid/setgid executable");
    errno = 0;
    passwd* user = getpwuid(spec.uid);
    if (!user) fail("cannot find the invoking user's passwd entry");
    spec.username = user->pw_name;
    std::string home = env("HOME");
    if (home.empty()) home = user->pw_dir;
    if (!fs::path(home).is_absolute()) fail("HOME must be absolute");
    const fs::path host_cwd = fs::canonical(fs::current_path());
    spec.home = source_path(home, host_cwd, home, false);
    spec.cwd = host_cwd.string();
    spec.environment = {{"PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
                        {"HOME", spec.home}, {"USER", spec.username}, {"LOGNAME", spec.username},
                        {"XDG_RUNTIME_DIR", "/run/user/" + std::to_string(spec.uid)}};
    for (const char* name : {"TERM", "LANG", "LC_ALL"})
        if (const char* v = std::getenv(name)) spec.environment[name] = v;
    std::string home_setting = "ephemeral", cwd_setting = "rw";
    std::optional<std::string> workdir;
    if (!no_config) {
        fs::path file;
        if (config) file = source_path(*config, host_cwd, spec.home, true);
        else {
            auto xdg = env("XDG_CONFIG_HOME");
            fs::path base = xdg.empty() || !fs::path(xdg).is_absolute() ? fs::path(spec.home) / ".config" : fs::path(xdg);
            file = base / "agent-vm/config.toml";
        }
        std::error_code error;
        bool exists = fs::exists(file, error);
        if (!error && !exists && fs::is_symlink(fs::symlink_status(file)))
            fail("configuration is a dangling symlink: " + file.string());
        if (error) fail("cannot inspect configuration: " + error.message());
        if (exists) load_config(file, spec, home_setting, cwd_setting, workdir);
        else if (config) fail("configuration file does not exist: " + file.string());
    }
    for (size_t i = 0; i < args.size(); ++i) {
        std::string token = args[i];
        if (token == "--") {
            spec.command.assign(args.begin() + static_cast<std::ptrdiff_t>(i + 1), args.end());
            break;
        }
        auto equal = token.find('=');
        std::string option = token.substr(0, equal);
        std::optional<std::string> inline_value;
        if (equal != std::string::npos) inline_value = token.substr(equal + 1);
        if (token.size() > 2 && token[0] == '-' && (token[1] == 'e' || token[1] == 'p') && token[2] != '-') {
            option = token.substr(0, 2); inline_value = token.substr(2);
        }
        auto value = [&]() -> std::string {
            if (inline_value) return *inline_value;
            if (++i == args.size()) fail(option + " requires a value");
            return args[i];
        };
        auto flag = [&]() { if (inline_value) fail(option + " does not accept a value"); };
        if (option == "--cpus") spec.cpus = static_cast<uint8_t>(number(value(), 255, "cpus"));
        else if (option == "--memory") spec.memory_mib = number(value(), UINT32_MAX, "memory (MiB)");
        else if (option == "--tmp-size") spec.tmp_mib = number(value(), UINT32_MAX, "tmp size (MiB)");
        else if (option == "--network") network_mode(spec, value());
        else if (option == "--home") home_mode(home_setting, value());
        else if (option == "--cwd-mode") cwd_mode(cwd_setting, value());
        else if (option == "--workdir") workdir = target_path(value(), spec.home);
        else if (option == "--mount") spec.mounts.push_back(mount_spec(value(), host_cwd, spec.home));
        else if (option == "--tmpfs") spec.tmpfs.push_back(tmpfs_spec(value(), spec));
        else if (option == "--socket") spec.sockets.push_back(socket_spec(value(), host_cwd, spec.home));
        else if (option == "--mask") spec.mask_sources.push_back(source_path(value(), host_cwd, spec.home, false));
        else if (option == "--mask-target") spec.mask_targets.push_back(target_path(value(), spec.home));
        else if (option == "--env" || option == "-e") set_env(spec, value());
        else if (option == "--publish" || option == "-p") spec.ports.push_back(port_spec(value()));
        else if (option == "--ssh-agent") { flag(); spec.ssh_agent = true; }
        else if (option == "--no-ssh-agent") { flag(); spec.ssh_agent = false; }
        else if (option == "--debug") { flag(); spec.debug = true; }
        else fail("unknown argument '" + token + "' (place workload arguments after --)");
    }
    if (home_setting == "shared") {
        bool ro = host_cwd == fs::path(spec.home) && cwd_setting == "ro";
        spec.mounts.push_back({source_path(spec.home, host_cwd, spec.home, true), spec.home, ro});
    }
    if (cwd_setting != "none" && !(home_setting == "shared" && host_cwd == fs::path(spec.home)))
        spec.mounts.push_back({host_cwd.string(), host_cwd.string(), cwd_setting == "ro"});
    if (workdir) spec.cwd = *workdir;
    else if (cwd_setting == "none") spec.cwd = spec.home;
    if (spec.ssh_agent) {
        auto socket = env("SSH_AUTH_SOCK");
        if (socket.empty()) fail("--ssh-agent requires SSH_AUTH_SOCK in the host environment");
        auto target = "/run/user/" + std::to_string(spec.uid) + "/ssh-agent.socket";
        if (spec.environment.contains("SSH_AUTH_SOCK") && spec.environment.at("SSH_AUTH_SOCK") != target)
            fail("SSH_AUTH_SOCK conflicts with the --ssh-agent target: " + target);
        spec.sockets.push_back({source_path(socket, host_cwd, spec.home, true), target});
        spec.environment["SSH_AUTH_SOCK"] = target;
    }
    if (spec.command.empty()) spec.command = {"/bin/sh"};
    deduplicate(spec.mask_sources); deduplicate(spec.mask_targets);
    validate_spec(spec);
    return options;
}

void validate_spec(const RunSpec& spec) {
    if (spec.cpus == 0 || spec.memory_mib == 0 || spec.tmp_mib == 0) fail("VM resources must be positive");
    if (!spec.network && !spec.ports.empty()) fail("port publishing requires --network passt");
    if (spec.home.empty() || spec.home[0] != '/' || normalize(spec.home) != spec.home) fail("home must be a normalized absolute path");
    if (spec.cwd.empty() || spec.cwd[0] != '/' || normalize(spec.cwd) != spec.cwd) fail("workdir must be a normalized absolute path");
    check_target(spec.home, "home");
    if (path_within(spec.cwd, "/.agent-vm") || path_within(spec.cwd, "/ipc"))
        fail("workdir overlaps a private runtime path: " + spec.cwd);
    std::set<std::string> targets;
    for (const auto& mount : spec.mounts) {
        check_target(mount.target, "mount");
        if (!targets.insert(mount.target).second) fail("duplicate mount target: " + mount.target + "; remove one mount or disable the default CWD/home mount");
        if (mount.source.empty() || mount.source[0] != '/' || normalize(mount.source) != mount.source)
            fail("mount source must be a normalized absolute path: " + mount.source);
        if (!mount.read_only && (path_within(mount.source, "/usr") || path_within("/usr", mount.source)))
            fail("writable shared source overlaps the read-only runtime /usr tree: " + mount.source);
        std::error_code error;
        auto canonical = fs::canonical(mount.source, error);
        if (error || normalize(canonical) != mount.source) fail("mount source is missing or no longer canonical: " + mount.source);
        auto status = fs::status(mount.source, error);
        if (error || (!fs::is_directory(status) && !fs::is_regular_file(status)))
            fail("shared sources must be regular files or directories: " + mount.source);
        if (auto parent = nearest_mount(spec, mount.target, false)) {
            auto tmpfs = nearest_tmpfs(spec, mount.target, false);
            if (!tmpfs || tmpfs->target.size() < parent->target.size())
                check_existing_target(*parent, mount.target, fs::is_directory(status));
        }
    }
    if (spec.tmpfs.size() > 65536) fail("too many tmpfs mounts");
    std::set<std::string> tmpfs_targets;
    for (const auto& tmpfs : spec.tmpfs) {
        if (tmpfs.target.find('\0') != std::string::npos) fail("tmpfs target cannot contain NUL bytes");
        if (tmpfs.target == "/run" || !path_within(tmpfs.target, "/run")) check_target(tmpfs.target, "tmpfs");
        else if (normalize(tmpfs.target) != tmpfs.target) fail("tmpfs target must be a normalized absolute path: " + tmpfs.target);
        if (paths_overlap(tmpfs.target, "/.oldroot")) fail("tmpfs target overlaps a private runtime path: " + tmpfs.target);
        for (const auto& required : {std::string("/tmp"), std::string("/var/tmp"), spec.home,
                                     "/run/user/" + std::to_string(spec.uid)})
            if (path_within(required, tmpfs.target)) fail("tmpfs target overlaps a required guest directory: " + tmpfs.target);
        if (!tmpfs_targets.insert(tmpfs.target).second) fail("duplicate tmpfs target: " + tmpfs.target);
        if (tmpfs.uid == UINT32_MAX || tmpfs.gid == UINT32_MAX) fail("tmpfs uid and gid cannot be UINT32_MAX");
        if (tmpfs.mode > 07777) fail("tmpfs mode must fit in permission bits (0000 through 7777)");
        if (targets.contains(tmpfs.target)) fail("duplicate mount/tmpfs target: " + tmpfs.target);
        if (auto mount = nearest_mount(spec, tmpfs.target, true)) {
            auto parent = nearest_tmpfs(spec, tmpfs.target, false);
            if (!parent || parent->target.size() < mount->target.size())
                check_existing_target(*mount, tmpfs.target, true);
        }
        for (const auto& mask : spec.mask_targets)
            if (paths_overlap(tmpfs.target, mask)) fail("tmpfs target overlaps a masked target: " + tmpfs.target);
        for (const auto& mask : spec.mask_sources) {
            for (const auto& mount : spec.mounts) {
                if (!path_within(mask, mount.source)) continue;
                auto target = normalize(fs::path(mount.target) / fs::path(mask).lexically_relative(mount.source));
                if (paths_overlap(tmpfs.target, target)) fail("tmpfs target overlaps a masked subtree: " + tmpfs.target);
            }
        }
    }
    for (const auto& mask : spec.mask_sources) {
        if (mask.empty() || mask[0] != '/' || normalize(mask) != mask) fail("source masks must be normalized absolute paths");
        if (path_within(mask, "/usr") || path_within("/usr", mask))
            fail("source mask overlaps the runtime /usr tree: " + mask);
        for (const auto& mount : spec.mounts) {
            if (path_within(mount.source, mask)) fail("a shared source is inside a masked subtree: " + mount.source);
            if (path_within(mask, mount.source)) {
                std::error_code error;
                auto status = fs::status(mask, error);
                if (error || !fs::exists(status))
                    fail("mask does not exist beneath a shared source; refusing an ineffective mask: " + mask);
                if (!fs::is_directory(status) && !fs::is_regular_file(status))
                    fail("masked sources must be regular files or directories: " + mask);
                auto target = normalize(fs::path(mount.target) / fs::path(mask).lexically_relative(mount.source));
                if (path_within(spec.cwd, target)) fail("workdir is inside a masked subtree: " + spec.cwd);
                // A target beneath a later child mount must still be maskable without host writes.
                if (auto covering = nearest_mount(spec, target, true))
                    check_existing_target(*covering, target, fs::is_directory(status));
            }
        }
    }
    for (const auto& target : spec.mask_targets) {
        check_target(target, "mask");
        if (path_within(spec.cwd, target)) fail("workdir is inside a masked target: " + spec.cwd);
        if (auto parent = nearest_mount(spec, target, true)) {
            auto path = fs::path(parent->source);
            if (target != parent->target) path /= fs::path(target).lexically_relative(parent->target);
            std::error_code error;
            auto status = fs::status(path, error);
            if (error || !fs::exists(status)) fail("mask target does not exist in a shared source: " + target);
            check_existing_target(*parent, target, fs::is_directory(status));
        }
    }
    if (spec.sockets.size() > AVM_SOCKET_MAX) fail("too many forwarded sockets");
    std::vector<std::string> socket_targets;
    for (const auto& socket : spec.sockets) {
        check_socket_path(socket.source, "source");
        check_socket_path(socket.target, "target");
        std::error_code error;
        auto canonical = fs::canonical(socket.source, error);
        if (error || normalize(canonical) != socket.source)
            fail("socket source is missing or no longer canonical: " + socket.source);
        if (!fs::is_socket(socket.source, error) || error)
            fail("socket source is not an existing Unix socket: " + socket.source);
        if (socket.target == "/run" || !path_within(socket.target, "/run")) check_target(socket.target, "socket");
        if (path_within(spec.home, socket.target) || path_within(spec.cwd, socket.target) ||
            path_within("/run/user/" + std::to_string(spec.uid), socket.target))
            fail("socket target overlaps a required guest directory: " + socket.target);
        for (const auto& target : socket_targets)
            if (paths_overlap(socket.target, target)) fail("conflicting socket targets: " + socket.target + " and " + target);
        socket_targets.push_back(socket.target);
        for (const auto& mount : spec.mounts)
            if (path_within(mount.target, socket.target)) fail("socket target overlaps a mount point: " + socket.target);
        for (const auto& tmpfs : spec.tmpfs)
            if (path_within(tmpfs.target, socket.target)) fail("socket target overlaps a tmpfs mount point: " + socket.target);
        if (!covered_by_tmpfs(spec, socket.target)) {
            if (auto parent = nearest_mount(spec, socket.target, true)) check_socket_mount(*parent, socket.target);
            else if (!(path_within(socket.target, spec.home) || path_within(socket.target, "/tmp") ||
                       path_within(socket.target, "/var/tmp") || path_within(socket.target, "/run")))
                fail("socket target is outside the guest's writable filesystems: " + socket.target);
        }
        if (socket.target == "/tmp" || socket.target == "/var/tmp")
            fail("socket target overlaps a required guest directory: " + socket.target);
        for (const auto& mask : spec.mask_targets)
            if (paths_overlap(socket.target, mask)) fail("socket target overlaps a masked target: " + socket.target);
        for (const auto& mask : spec.mask_sources) {
            for (const auto& mount : spec.mounts) {
                if (!path_within(mask, mount.source)) continue;
                auto target = normalize(fs::path(mount.target) / fs::path(mask).lexically_relative(mount.source));
                if (paths_overlap(socket.target, target)) fail("socket target overlaps a masked subtree: " + socket.target);
            }
        }
    }
    // Empty private filesystems contain only their roots and paths created
    // to reach nested mounts; a deeper shared mount supplies its own contents.
    bool created_directory = std::any_of(spec.tmpfs.begin(), spec.tmpfs.end(), [&](const auto& tmpfs) {
        return path_within(tmpfs.target, spec.cwd);
    }) || std::any_of(spec.mounts.begin(), spec.mounts.end(), [&](const auto& mount) {
        return mount.target != spec.cwd && path_within(mount.target, spec.cwd);
    });
    if (covered_by_tmpfs(spec, spec.cwd)) {
        if (!created_directory) fail("workdir does not exist in the empty tmpfs: " + spec.cwd);
    } else if (auto mount = nearest_mount(spec, spec.cwd, true)) {
        auto physical = fs::path(mount->source) / fs::path(spec.cwd).lexically_relative(mount->target);
        std::error_code error;
        if (!fs::is_directory(physical, error) || error)
            fail("workdir is not an existing directory in the shared source: " + spec.cwd);
        check_existing_target(*mount, spec.cwd, true);
    } else {
        bool private_directory = spec.cwd == spec.home || spec.cwd == "/" ||
            spec.cwd == "/tmp" || spec.cwd == "/var/tmp" || spec.cwd == "/opt" ||
            spec.cwd == "/srv" || spec.cwd == "/mnt" || spec.cwd == "/media" ||
            spec.cwd == "/var" || spec.cwd == "/home" || spec.cwd == "/root" ||
            spec.cwd == "/run/user/" + std::to_string(spec.uid);
        bool system_directory = false;
        if (path_within(spec.cwd, "/usr")) {
            std::error_code error;
            system_directory = fs::is_directory(spec.cwd, error) && !error;
        }
        if (!private_directory && !system_directory && !created_directory)
            fail("workdir is not provided by the guest filesystem: " + spec.cwd);
    }
    for (size_t i = 0; i < spec.ports.size(); ++i) {
        const auto& p = spec.ports[i];
        in_addr address{};
        if (!p.host_port || !p.guest_port || inet_pton(AF_INET, p.address.c_str(), &address) != 1)
            fail("invalid IPv4 port publication");
        for (size_t j = 0; j < i; ++j) {
            const auto& other = spec.ports[j];
            if (p.udp == other.udp && p.host_port == other.host_port &&
                (p.address == other.address || p.address == "0.0.0.0" || other.address == "0.0.0.0"))
                fail("conflicting published host port: " + std::to_string(p.host_port));
        }
    }
    if (spec.ssh_agent) {
        auto target = "/run/user/" + std::to_string(spec.uid) + "/ssh-agent.socket";
        if (std::none_of(spec.sockets.begin(), spec.sockets.end(), [&](const auto& socket) { return socket.target == target; }))
            fail("SSH agent forwarding requires its socket mapping");
        auto value = spec.environment.find("SSH_AUTH_SOCK");
        if (value == spec.environment.end() || value->second != target)
            fail("SSH_AUTH_SOCK must match the SSH agent forwarding target");
    }
    for (const auto& [key, value] : spec.environment) {
        check_env_key(key);
        if (value.find('\0') != std::string::npos) fail("environment values cannot contain NUL bytes");
    }
    for (const auto& argument : spec.command)
        if (argument.find('\0') != std::string::npos) fail("command arguments cannot contain NUL bytes");
}

void print_plan(const RunSpec& spec) {
    std::cout << "Identity: " << spec.uid << ':' << spec.gid << " (" << spec.username << ")\n"
              << "VM: " << unsigned(spec.cpus) << " CPUs, " << spec.memory_mib << " MiB RAM, " << spec.tmp_mib << " MiB temporary storage\n"
              << "Home: " << spec.home << "\nWorkdir: " << spec.cwd << "\n"
              << "Mounts:\n  /usr -> /usr (recursive ro; runtime)\n";
    for (const auto& mount : spec.mounts)
        std::cout << "  " << mount.source << " -> " << mount.target << (mount.read_only ? " (ro)\n" : " (rw)\n");
    for (const auto& tmpfs : spec.tmpfs)
        std::cout << "Tmpfs: " << tmpfs.target << " (uid=" << tmpfs.uid << ", gid=" << tmpfs.gid
                  << ", mode=0o" << std::oct << tmpfs.mode << std::dec << ")\n";
    for (const auto& mask : spec.mask_sources) std::cout << "Source mask: " << mask << '\n';
    for (const auto& mask : spec.mask_targets) std::cout << "Target mask: " << mask << '\n';
    std::cout << "Network: " << (spec.network ? "passt (IPv4)" : "none") << '\n'
              << "Vsock: fixed control channel enabled; implicit vsock/TSI disabled; "
              << spec.sockets.size() << " authorized socket channels\n";
    for (const auto& socket : spec.sockets)
        std::cout << "Socket: " << socket.source << " -> " << socket.target << '\n';
    for (const auto& port : spec.ports)
        std::cout << "Publish: " << port.address << ':' << port.host_port << ':' << port.guest_port << (port.udp ? "/udp\n" : "/tcp\n");
    std::cout << "SSH agent: " << (spec.ssh_agent ? "enabled (socket alias)" : "disabled") << "\nEnvironment names:";
    for (const auto& [key, value] : spec.environment) { (void)value; std::cout << ' ' << key; }
    std::cout << "\nCommand arguments: " << spec.command.size() << " (values omitted)\n";
}

void print_help() {
    std::cout << R"(Usage: agent-vm [run|plan] [OPTIONS] [-- COMMAND [ARG...]]
       agent-vm doctor | --help | --version

  --config FILE          Read an explicit TOML configuration
  --no-config            Ignore the per-user configuration
  --cpus N               Virtual CPUs (default 2)
  --memory MiB           Guest RAM (default 2048)
  --tmp-size MiB         Private temporary filesystem capacity (default 256)
  --network none|passt   Network policy (default none)
  --home ephemeral|shared  Home policy (default ephemeral)
  --cwd-mode ro|rw|none  Share the invoking directory (default rw)
  --workdir PATH         Absolute guest working directory
  --mount SPEC           type=bind,src=SOURCE,dst=TARGET[,ro|rw] (default ro)
  --tmpfs SPEC           target=PATH[,uid=UID,gid=GID,mode=0700] (caller IDs)
  --socket SPEC          Forward a Unix stream socket: src=SOURCE,dst=TARGET
  --mask SOURCE          Hide a host source subtree through every shared mount
  --mask-target TARGET   Hide one absolute guest target
  -e, --env KEY[=VALUE]   Set a workload variable, or inherit it from the host
  -p, --publish SPEC     [IPv4:]HOST:GUEST[/tcp|udp] (default 127.0.0.1, TCP)
  --ssh-agent            Forward SSH_AUTH_SOCK to /run/user/UID/ssh-agent.socket
  --no-ssh-agent         Disable configured SSH agent forwarding
  --debug               Enable runtime diagnostic output

Default configuration: $XDG_CONFIG_HOME/agent-vm/config.toml, otherwise
$HOME/.config/agent-vm/config.toml. Project configuration is never read.
CLI scalars and environment keys override configuration; mounts, tmpfs, sockets
and masks are combined. Conflicting filesystem targets are errors.
Disable default mounts with --cwd-mode none
or --home ephemeral when replacing them. All values are literal, without shell
execution. Command defaults to /bin/sh. plan prints environment names, not values.
)";
}
} // namespace avm
