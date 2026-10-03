#pragma once
#include "spec.hpp"
#include "protocol.h"
#include <string>
#include <sys/types.h>

namespace avm {
struct FilesystemExport {
    std::string tag, path;
};
// Called in a dedicated child, before any libkrun threads exist. This starts a
// new session (no shared process group or controlling terminal with the
// supervisor), enters a userns, mountns, pidns, ipcns, utsns and netns, forks
// the namespace init, and builds the confined policy tree, bootstrap and export
// catalog. The intermediate parent waits and _exit's with the child status.
// Returns the export devices only in the fully confined VMM process, after cap
// clearing and seccomp installation.
// Guest-private writable filesystems and the final guest root are assembled
// by the guest helper.
// root_dir is empty; ipc_dir contains already-listening broker/readiness sockets.
// control_directory pins the supervisor's bounded detached tmpfs.
// spec_file and helper are trusted regular files to copy before guest launch.
// keep_fds is the complete explicit allowlist in addition to 0, 1, 2.
std::vector<FilesystemExport> enter_sandbox(const RunSpec& spec, const std::string& root_dir,
                   const std::string& ipc_dir, const std::string& spec_file,
                   const std::string& helper, const std::vector<int>& keep_fds, int control_directory);
// Render-server mode permits execve only under an exact ELF/loader Landlock
// execute allowlist. All other profiles continue to deny execution outright.
void install_vmm_seccomp(bool render_server = false);
// Resolve only a socket inode relative to a pinned directory; never follow symlinks.
bool send_control(int directory, const avm_control_message& message);
// Call after starting host helpers, before forking the VMM. Preserves UID/GID
// in a new user namespace, creates an empty netns, then drops capabilities.
// With control_directory, also creates a private mount namespace and tmpfs.
// When requested, returns a CLOEXEC mount FD for a 64 KiB / 16 inode control tmpfs.
int isolate_supervisor_network(bool control_directory = false);
// Parent only, after the worker fork: file access is limited to runtime
// directory enumeration and cleanup. Removing runtime itself also requires
// REMOVE_DIR on its parent, permitting removal of empty sibling directories.
// Returns false if Landlock ABI 3 is unavailable; other failures throw.
bool confine_supervisor_filesystem(const std::string& runtime);
// Remove children, then rmdir the runtime itself without first trying unlink.
// This avoids needing REMOVE_FILE permission on the runtime's parent.
void cleanup_runtime_directory(const std::string& runtime);

struct NetworkProcess { int fd = -1; pid_t pid = -1; };
// Internal helper profile, before exec: read-only system dependencies and
// socket creation/removal in the pinned private directory. False below ABI 3.
bool confine_dbus_proxy_filesystem(int private_directory);
// Returned fd is the readiness/lifetime pipe and must remain open while in use.
// The listening path's parent must be a dedicated caller-owned 0700 directory.
NetworkProcess start_dbus_proxy(const DbusSpec& spec, const std::string& path);
// display is the host compositor socket; path carries serialized waypipe bytes.
// The socket parent must be a dedicated caller-owned mode 0700 directory.
pid_t start_waypipe(const std::string& display, const std::string& path, bool gpu = false);
NetworkProcess start_passt(const RunSpec& spec);
struct SocketBrokerSpec {
    std::string listen_path, upstream_path, guest_path;
};
// One confined controller for all forwards, one empty-root data process each.
// stop_child also removes the listener pathname, even after the caller reaps it.
pid_t start_socket_brokers(const std::vector<SocketBrokerSpec>& sockets);
pid_t start_socket_broker(const std::string& listen_path, const std::string& upstream_path);
// Helpers must exit when their parent dies and close all unrelated FDs.
void stop_child(pid_t pid);
}
