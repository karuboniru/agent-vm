#pragma once
#include "spec.hpp"
#include <string>
#include <sys/types.h>

namespace avm {
// Called in a dedicated child, before any libkrun threads exist. This enters a
// userns, mountns, pidns, ipcns, utsns and netns, forks the namespace init, and
// builds the root. The intermediate parent waits and _exit's with the child status.
// Returns only in the fully confined VMM process, after cap clearing.
// root_dir and ipc_dir are empty private directories owned by supervisor.
// spec_file and helper are trusted regular files to copy before guest launch.
// keep_fds is the complete explicit allowlist in addition to 0, 1, 2.
void enter_sandbox(const RunSpec& spec, const std::string& root_dir,
                   const std::string& ipc_dir, const std::string& spec_file,
                   const std::string& helper, const std::vector<int>& keep_fds);
void install_vmm_seccomp();

struct NetworkProcess { int fd = -1; pid_t pid = -1; };
NetworkProcess start_passt(const RunSpec& spec);
pid_t start_ssh_broker(const std::string& listen_path, const std::string& upstream_path);
// Both helpers must exit when their parent dies and close all unrelated FDs.
void stop_child(pid_t pid);
}
