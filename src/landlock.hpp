#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <linux/landlock.h>

// The build headers can be older than the running kernel.
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif
// Older userspace headers may predate ABI 9, even on a newer kernel.
#ifndef LANDLOCK_ACCESS_FS_RESOLVE_UNIX
#define LANDLOCK_ACCESS_FS_RESOLVE_UNIX (1ULL << 16)
#endif

namespace avm::detail {

// Returns zero only when the kernel has no enabled Landlock support. Other
// failures are reported as std::system_error so callers cannot silently run
// without a policy after an unexpected setup failure.
int landlock_abi();

// Filesystem rights through ABI 3. ABI 5's IOCTL_DEV is intentionally omitted:
// some users need to reopen and operate on terminal devices after confinement.
std::uint64_t fs_rights_for_abi(int abi);

class LandlockRuleset {
public:
    explicit LandlockRuleset(std::uint64_t handled_fs);
    ~LandlockRuleset();
    LandlockRuleset(const LandlockRuleset&) = delete;
    LandlockRuleset& operator=(const LandlockRuleset&) = delete;
    LandlockRuleset(LandlockRuleset&& other) noexcept;
    LandlockRuleset& operator=(LandlockRuleset&& other) noexcept;

    // A file rule applies only to that file; a directory rule to its tree.
    // The path is opened before enforcement. The fd overload accepts O_PATH.
    // Failures throw std::system_error carrying the original errno.
    void add_path(std::string_view path, std::uint64_t allowed_fs);
    void add_fd(int path_fd, std::uint64_t allowed_fs);
    void enforce();

private:
    int fd_ = -1;
    std::uint64_t handled_fs_ = 0;
};

// Restrict connections to pre-existing pathname Unix servers to exactly these
// paths. Returns false when ABI 9 is unavailable. The caller chooses whether
// to continue without this optional protection.
bool enforce_unix_socket_allowlist(const std::vector<std::string>& sockets);

} // namespace avm::detail
