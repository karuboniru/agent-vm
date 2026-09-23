#pragma once
#include <array>
#include <filesystem>
#include <stdexcept>
#include <string>

namespace avm::paths {
inline constexpr std::array reserved = {"/usr", "/etc", "/proc", "/sys", "/dev", "/.agent-vm",
    "/.oldroot", "/bin", "/sbin", "/lib", "/lib64", "/run", "/ipc"};
inline std::string normalize(const std::filesystem::path& path) {
    auto value = path.lexically_normal().string();
    while (value.size() > 1 && value.back() == '/') value.pop_back();
    return value;
}
// All callers share lexical normalization; this does not resolve host symlinks.
inline bool within(const std::string& path, const std::string& parent) {
    if (path.empty() || parent.empty()) return false;
    const auto p = normalize(path), base = normalize(parent);
    return p == base || (base == "/" && p.starts_with('/')) ||
        (p.size() > base.size() && p.starts_with(base) && p[base.size()] == '/');
}
inline void check_absolute(const std::string& path) {
    if (path.empty() || path[0] != '/' || path.find('\0') != std::string::npos || normalize(path) != path)
        throw std::runtime_error("path must be absolute and normalized: " + path);
}
inline bool forbidden_target(const std::string& path, bool custom_mount = false) {
    if (custom_mount && ((path != "/run" && within(path, "/run")) ||
                         (path != "/usr" && within(path, "/usr")))) return false;
    if (custom_mount && path != "/etc" && within(path, "/etc") &&
        !within(path, "/etc/resolv.conf")) return false;
    for (const auto* parent : reserved)
        if (within(path, parent) || within(parent, path)) return true;
    return false;
}
}
