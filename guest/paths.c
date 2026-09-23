#include "paths.h"
#include <string.h>
bool avm_path_valid(const char *path)
{
    if (path[0] != '/') return false;
    if (!path[1]) return true;
    for (const char *p = path + 1; ; ) {
        const char *end = strchr(p, '/');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (!n || (n == 1 && *p == '.') || (n == 2 && !memcmp(p, "..", 2))) return false;
        if (!end) return true;
        p = end + 1;
    }
}
bool avm_path_within(const char *path, const char *parent)
{
    if (!strcmp(parent, "/")) return path[0] == '/';
    size_t size = strlen(parent);
    return !strncmp(path, parent, size) && (!path[size] || path[size] == '/');
}
bool avm_protected_target(const char *path, bool custom_mount)
{
    if (custom_mount && ((strcmp(path, "/run") && avm_path_within(path, "/run")) ||
                         (strcmp(path, "/usr") && avm_path_within(path, "/usr")))) return false;
    if (custom_mount && strcmp(path, "/etc") && avm_path_within(path, "/etc") &&
        !avm_path_within(path, "/etc/resolv.conf")) return false;
    const char *protected[] = {"/usr", "/etc", "/proc", "/sys", "/dev", "/.agent-vm",
        "/.oldroot", "/bin", "/sbin", "/lib", "/lib64", "/run", "/ipc"};
    for (size_t i = 0; i < sizeof(protected) / sizeof(protected[0]); ++i)
        if (avm_path_within(path, protected[i]) || avm_path_within(protected[i], path)) return true;
    return false;
}
