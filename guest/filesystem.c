#define _GNU_SOURCE
#include "filesystem.h"
#include "agent_vm/protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/openat2.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

struct entry {
    uint32_t kind, mode, uid, gid;
    char *target, *object;
};
struct reader { unsigned char *data; size_t size, offset; };

static void fail(const char *operation)
{
    fprintf(stderr, "agent-vm guest: filesystem %s: %s\n", operation, strerror(errno));
    exit(125);
}
static void invalid(void)
{
    errno = EINVAL;
    fail("invalid mount description");
}
static uint32_t number(struct reader *r)
{
    uint32_t value;
    if (r->size - r->offset < sizeof(value)) invalid();
    memcpy(&value, r->data + r->offset, sizeof(value));
    r->offset += sizeof(value);
    return value;
}
static char *string(struct reader *r)
{
    uint32_t size = number(r);
    if (size >= PATH_MAX || size > r->size - r->offset || memchr(r->data + r->offset, 0, size)) invalid();
    char *value = strndup((const char *)r->data + r->offset, size);
    if (!value) fail("allocate string");
    r->offset += size;
    return value;
}
static bool path_valid(const char *path)
{
    if (path[0] != '/' || !path[1]) return false;
    for (const char *p = path + 1; ; ) {
        const char *end = strchr(p, '/');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (!n || (n == 1 && *p == '.') || (n == 2 && !memcmp(p, "..", 2))) return false;
        if (!end) return true;
        p = end + 1;
    }
}
static bool within(const char *path, const char *parent)
{
    size_t size = strlen(parent);
    return !strncmp(path, parent, size) && (!path[size] || path[size] == '/');
}
static bool protected_target(const char *path)
{
    if (strcmp(path, "/usr") && within(path, "/usr")) return false;
    if (strcmp(path, "/etc") && within(path, "/etc") && !within(path, "/etc/resolv.conf")) return false;
    const char *protected[] = {"/usr", "/etc", "/proc", "/sys", "/dev", "/.agent-vm",
        "/.oldroot", "/bin", "/sbin", "/lib", "/lib64", "/ipc"};
    for (size_t i = 0; i < sizeof(protected) / sizeof(protected[0]); ++i)
        if (within(path, protected[i]) || within(protected[i], path)) return true;
    return false;
}
static int target_fd(int root, const char *path)
{
    struct open_how how = {.flags = O_PATH | O_CLOEXEC,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS};
    int fd = (int)syscall(SYS_openat2, root, path + 1, &how, sizeof(how));
    if (fd < 0) fail(path);
    return fd;
}
static void fd_path(int fd, char path[64])
{
    snprintf(path, 64, "/proc/self/fd/%d", fd);
}
/* Create placeholders only on guest-native filesystems. Targets within a host
 * share must already exist and are opened without creating anything. */
static void placeholder(int root, const char *path, bool directory)
{
    char *copy = strdup(path + 1), *save = NULL;
    if (!copy) fail("allocate path");
    int parent = dup(root);
    if (parent < 0) fail("duplicate root fd");
    char *part = strtok_r(copy, "/", &save);
    while (part) {
        char *next = strtok_r(NULL, "/", &save);
        bool dir = next || directory;
        if (dir && mkdirat(parent, part, 0755) < 0 && errno != EEXIST) fail(path);
        int fd = openat(parent, part, O_CLOEXEC | O_NOFOLLOW |
                        (dir ? O_RDONLY | O_DIRECTORY : O_WRONLY | O_CREAT), 0600);
        if (fd < 0) fail(path);
        struct stat st;
        if (fstat(fd, &st) < 0 || (dir ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode))) invalid();
        close(parent);
        parent = fd;
        part = next;
    }
    close(parent);
    free(copy);
}
static void mount_at(int root, const char *path, const char *source, const char *type,
                     unsigned long flags, const char *options)
{
    int fd = target_fd(root, path);
    char destination[64];
    fd_path(fd, destination);
    if (mount(source, destination, type, flags, options) < 0) fail(path);
    close(fd);
}
static void mount_tmpfs(int root, const struct entry *e, uint32_t tmp_mib)
{
    char options[160];
    snprintf(options, sizeof(options), "size=%um,nr_inodes=65536,mode=%o,uid=%u,gid=%u",
             tmp_mib, e->mode, e->uid, e->gid);
    mount_at(root, e->target, "tmpfs", "tmpfs", MS_NOSUID | MS_NODEV, options);
}

void avm_mount_filesystems(void)
{
    int input = open(AVM_MOUNT_SPEC, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) fail("open description");
    struct stat st;
    if (fstat(input, &st) < 0) fail("stat description");
    if (!S_ISREG(st.st_mode) || st.st_size < (off_t)sizeof(struct avm_mount_header) || st.st_size > AVM_SPEC_MAX) invalid();
    struct reader r = {.size = (size_t)st.st_size};
    r.data = malloc(r.size);
    if (!r.data) fail("allocate description");
    size_t used = 0;
    while (used < r.size) {
        ssize_t n = read(input, r.data + used, r.size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) invalid();
        used += (size_t)n;
    }
    close(input);
    if (number(&r) != AVM_MOUNT_MAGIC || number(&r) != AVM_MOUNT_VERSION) invalid();
    uint32_t count = number(&r), tmp_mib = number(&r);
    if (!count || count > (r.size - r.offset) / 24 || !tmp_mib) invalid();
    struct entry *entries = calloc(count, sizeof(*entries));
    if (!entries) fail("allocate entries");
    bool layers_started = false;
    for (uint32_t i = 0; i < count; ++i) {
        struct entry *e = &entries[i];
        e->kind = number(&r); e->mode = number(&r); e->uid = number(&r); e->gid = number(&r);
        e->target = string(&r); e->object = string(&r);
        if (!path_valid(e->target) || e->uid == UINT32_MAX || e->gid == UINT32_MAX) invalid();
        if (e->kind == AVM_MOUNT_TMPFS) {
            if (layers_started || e->object[0] || (e->mode & ~07777u)) invalid();
            continue;
        } else if (e->kind == AVM_MOUNT_DIRECTORY || e->kind == AVM_MOUNT_FILE) {
            if (!path_valid(e->object) || e->mode || e->uid || e->gid) invalid();
        } else if (e->kind == AVM_MOUNT_USER_TMPFS) {
            if (e->object[0] || (e->mode & ~07777u) || protected_target(e->target)) invalid();
        } else invalid();
        layers_started = true;
        for (uint32_t j = 0; j < i; ++j) {
            const struct entry *prior = &entries[j];
            // Layers must install parents first. Only shared mounts may cover
            // built-in tmpfs, as happens when sharing the user's home.
            if (((prior->kind != AVM_MOUNT_TMPFS || e->kind == AVM_MOUNT_USER_TMPFS) &&
                 within(prior->target, e->target)) ||
                (prior->kind == AVM_MOUNT_FILE && within(e->target, prior->target))) invalid();
        }
    }
    if (r.offset != r.size) invalid();
    free(r.data);

    // libkrun PID 1 retains its bootstrap namespace (including DHCP's resolver).
    if (unshare(CLONE_NEWNS) < 0 || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        fail("private mount namespace");
    if (mount("tmpfs", AVM_NEW_ROOT, "tmpfs", MS_NOSUID | MS_NODEV,
              "size=64m,nr_inodes=65536,mode=0755") < 0) fail("new root tmpfs");
    int root = open(AVM_NEW_ROOT, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) fail("open new root");
    const char *dirs[] = {"/usr", "/etc", "/proc", "/sys", "/dev", "/tmp", "/run", "/var/tmp",
        "/home", "/opt", "/srv", "/mnt", "/media", "/root", "/.oldroot", "/.agent-vm/objects"};
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); ++i) placeholder(root, dirs[i], true);
    for (uint32_t i = 0; i < count; ++i) {
        struct entry *e = &entries[i];
        if (e->kind != AVM_MOUNT_TMPFS) continue;
        placeholder(root, e->target, true);
        mount_tmpfs(root, e, tmp_mib);
    }
    mount_at(root, "/.agent-vm/objects", AVM_EXPORT_TAG, "virtiofs", MS_NOSUID | MS_NODEV, NULL);
    int objects = target_fd(root, "/.agent-vm/objects");
    for (uint32_t i = 0; i < count; ++i) {
        const struct entry *e = &entries[i], *parent = NULL;
        if (e->kind == AVM_MOUNT_TMPFS) continue;
        for (uint32_t j = 0; j < i; ++j) {
            const struct entry *prior = &entries[j];
            // Later containing mounts hide earlier ones, including an export
            // replacing or covering the built-in private home filesystem.
            if (within(e->target, prior->target)) parent = prior;
        }
        if (!parent) placeholder(root, e->target, e->kind != AVM_MOUNT_FILE);
        else if (parent->kind == AVM_MOUNT_TMPFS || parent->kind == AVM_MOUNT_USER_TMPFS) {
            const char *relative = e->target + strlen(parent->target);
            if (*relative) {
                int native = target_fd(root, parent->target);
                placeholder(native, relative, e->kind != AVM_MOUNT_FILE);
                close(native);
            }
        }
        if (e->kind == AVM_MOUNT_USER_TMPFS) {
            mount_tmpfs(root, e, tmp_mib);
            continue;
        }
        int source = target_fd(objects, e->object);
        char source_path[64];
        fd_path(source, source_path);
        mount_at(root, e->target, source_path, NULL, MS_BIND, NULL);
        close(source);
    }
    close(objects);
    // Each selected object now has its own guest mount. The catalog itself is
    // only staging, and need not remain in the workload's filesystem layout.
    if (umount2(AVM_NEW_ROOT "/.agent-vm/objects", MNT_DETACH) < 0 ||
        unlinkat(root, ".agent-vm/objects", AT_REMOVEDIR) < 0) fail("detach object catalog");
    // These are already guest-native mounts made by libkrun's init. Preserve
    // devpts, shm, cgroups and the console, without exporting host counterparts.
    for (size_t i = 0; i < 3; ++i) {
        const char *path = (const char *[]){"/proc", "/sys", "/dev"}[i];
        mount_at(root, path, path, NULL, MS_BIND | MS_REC, NULL);
    }
    const char *links[] = {"bin", "sbin", "lib", "lib64"};
    for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); ++i) {
        char path[32], destination[32];
        snprintf(path, sizeof(path), "/%s", links[i]);
        if (lstat(path, &st) == 0 && S_ISLNK(st.st_mode)) {
            snprintf(destination, sizeof(destination), "usr/%s", links[i]);
            if (symlinkat(destination, root, links[i]) < 0) fail("FHS symlink");
        }
    }
    if (fchdir(root) < 0 || syscall(SYS_pivot_root, ".", ".oldroot") < 0 || chdir("/") < 0)
        fail("pivot to guest root");
    close(root);
    if (umount2("/.oldroot", MNT_DETACH) < 0 || rmdir("/.oldroot") < 0) fail("detach bootstrap");
    if (mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL) < 0)
        fail("read-only root skeleton");
    for (uint32_t i = 0; i < count; ++i) { free(entries[i].target); free(entries[i].object); }
    free(entries);
}
