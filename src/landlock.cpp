#include "landlock.hpp"

#include <cerrno>
#include <cstring>
#include <system_error>
#include <utility>

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace avm::detail {
namespace {

[[noreturn]] void fail(const char* operation, int error = errno) {
    throw std::system_error(error, std::generic_category(), operation);
}

constexpr std::uint64_t abi1_rights =
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
    LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
    LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
    LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
    LANDLOCK_ACCESS_FS_MAKE_SYM;

} // namespace

int landlock_abi() {
    int abi = static_cast<int>(syscall(SYS_landlock_create_ruleset, nullptr, 0,
                                       LANDLOCK_CREATE_RULESET_VERSION));
    if (abi >= 1) return abi;
    if (abi < 0 && (errno == ENOSYS || errno == EOPNOTSUPP)) return 0;
    if (abi < 0) fail("query Landlock ABI");
    throw std::system_error(EINVAL, std::generic_category(), "invalid Landlock ABI");
}

std::uint64_t fs_rights_for_abi(int abi) {
    if (abi < 1) return 0;
    std::uint64_t rights = abi1_rights;
    if (abi >= 2) rights |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
    return rights;
}

LandlockRuleset::LandlockRuleset(std::uint64_t handled_fs) : handled_fs_(handled_fs) {
    landlock_ruleset_attr attr{};
    attr.handled_access_fs = handled_fs;
    // Only pass the ABI 1 field. All policies here use filesystem rights;
    // this keeps the struct accepted on old kernels and old userspace headers.
    fd_ = static_cast<int>(syscall(SYS_landlock_create_ruleset, &attr,
                                   sizeof(attr.handled_access_fs), 0));
    if (fd_ < 0) fail("create Landlock ruleset");
}

LandlockRuleset::~LandlockRuleset() {
    if (fd_ >= 0) close(fd_);
}

LandlockRuleset::LandlockRuleset(LandlockRuleset&& other) noexcept
    : fd_(std::exchange(other.fd_, -1)), handled_fs_(other.handled_fs_) {}

LandlockRuleset& LandlockRuleset::operator=(LandlockRuleset&& other) noexcept {
    if (this != &other) {
        if (fd_ >= 0) close(fd_);
        fd_ = std::exchange(other.fd_, -1);
        handled_fs_ = other.handled_fs_;
    }
    return *this;
}

void LandlockRuleset::add_path(std::string_view path, std::uint64_t allowed_fs) {
    if (path.empty() || path.find('\0') != std::string_view::npos)
        throw std::system_error(EINVAL, std::generic_category(), "invalid Landlock path");
    std::string name(path);
    int path_fd = open(name.c_str(), O_PATH | O_CLOEXEC);
    if (path_fd < 0) fail("open Landlock path");
    try {
        add_fd(path_fd, allowed_fs);
    } catch (...) {
        close(path_fd);
        throw;
    }
    close(path_fd);
}

void LandlockRuleset::add_fd(int path_fd, std::uint64_t allowed_fs) {
    if (fd_ < 0 || (allowed_fs & ~handled_fs_) != 0)
        throw std::system_error(EINVAL, std::generic_category(), "invalid Landlock rule");
    landlock_path_beneath_attr attr{};
    attr.allowed_access = allowed_fs;
    attr.parent_fd = path_fd;
    if (syscall(SYS_landlock_add_rule, fd_, LANDLOCK_RULE_PATH_BENEATH, &attr, 0) < 0)
        fail("add Landlock path rule");
}

void LandlockRuleset::enforce() {
    if (fd_ < 0)
        throw std::system_error(EINVAL, std::generic_category(), "invalid Landlock ruleset");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        fail("set no_new_privs for Landlock");
    if (syscall(SYS_landlock_restrict_self, fd_, 0) < 0)
        fail("enforce Landlock ruleset");
}

bool enforce_unix_socket_allowlist(const std::vector<std::string>& sockets) {
    if (landlock_abi() < 9) return false;
    LandlockRuleset rules(LANDLOCK_ACCESS_FS_RESOLVE_UNIX | LANDLOCK_ACCESS_FS_REFER);
    // REFER is implicitly denied by each Landlock layer, even if omitted from
    // handled_access_fs. A root grant preserves the caller's rename/link policy.
    rules.add_path("/", LANDLOCK_ACCESS_FS_REFER);
    for (const auto& socket : sockets)
        rules.add_path(socket, LANDLOCK_ACCESS_FS_RESOLVE_UNIX);
    rules.enforce();
    return true;
}

} // namespace avm::detail
