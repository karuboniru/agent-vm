#pragma once
#include "spec.hpp"
#include <string>
#include <sys/types.h>

namespace avm {
struct FilesystemExport {
    std::string tag, path;
};
// Called in a dedicated child, before any libkrun threads exist. This enters a
// userns, mountns, pidns, ipcns, utsns and netns, forks the namespace init, and
// builds the confined policy tree, bootstrap and export catalog. The intermediate
// parent waits and _exit's with the child status. Returns the export devices only
// in the fully confined VMM process, after cap clearing and seccomp installation.
// Guest-private writable filesystems and the final guest root are assembled
// by the guest helper.
// root_dir and ipc_dir are empty private directories owned by supervisor.
// spec_file and helper are trusted regular files to copy before guest launch.
// keep_fds is the complete explicit allowlist in addition to 0, 1, 2.
std::vector<FilesystemExport> enter_sandbox(const RunSpec& spec, const std::string& root_dir,
                   const std::string& ipc_dir, const std::string& spec_file,
                   const std::string& helper, const std::vector<int>& keep_fds);
void install_vmm_seccomp();
// Call after starting host helpers, before forking the VMM. Preserves UID/GID
// in a new user namespace, creates an empty netns, then drops capabilities.
void isolate_supervisor_network();

struct NetworkProcess { int fd = -1; pid_t pid = -1; };
// Returned fd is the readiness/lifetime pipe and must remain open while in use.
NetworkProcess start_dbus_proxy(const DbusSpec& spec, const std::string& path);
NetworkProcess start_passt(const RunSpec& spec);
pid_t start_socket_broker(const std::string& listen_path, const std::string& upstream_path);
// Helpers must exit when their parent dies and close all unrelated FDs.
void stop_child(pid_t pid);
}
