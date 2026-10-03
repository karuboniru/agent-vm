[中文](ARCHITECTURE.zh.md) · [README](../README.md)

# Architecture and security boundaries

## Components and lifecycle

```text
agent-vm supervisor
  ├─ passt                         optional, host networking
  ├─ xdg-dbus-proxy                 one per enabled bus
  ├─ waypipe client                 optional, host compositor access
  ├─ socket controller             shared by all forwards
  │    └─ socket data processes     one per forward
  └─ clean re-exec → VMM worker     libkrun + namespaces + mount jail
       └─ guest init
            └─ agent-vm-guest
                 ├─ socket relays
                 └─ waypipe server  optional, wraps workload
                      ├─ xwayland-satellite → Xwayland  optional, on demand
                      └─ workload   caller UID/GID
```

The supervisor parses TOML/CLI into `RunSpec` and prepares a private runtime directory, launch configuration, and fixed communication endpoints. D-Bus proxies become ready before socket brokers start. When enabled, a confined host waypipe client connects to the selected compositor and listens on a private Unix transport for the socket broker. After starting passt and brokers, the supervisor enters a single-ID user namespace and an empty network namespace, clears capabilities, and sets `no_new_privs`, then forks/re-execs the VMM worker. Supervisor isolation also applies with networking disabled.

The worker re-execs with a minimal environment, separating its address space from configuration parsing and the original host environment. It starts a new session, so the VMM shares neither a process group nor a controlling terminal with the supervisor: process groups span PID namespaces, and `kill(0, sig)` from the confined VMM would otherwise reach the supervisor. It then establishes user, mount, PID, IPC, UTS, and network namespaces, assembles its restricted root, closes unapproved FDs, clears capabilities, and installs a seccomp denylist before starting libkrun. The supervisor manages signals, TTY state, exit status, and helper cleanup; unexpected helper exit ends the VM. Terminal signals reach only the supervisor, which forwards them over the control channel; it ignores SIGTTOU so it can restore terminal settings from a background process group.

## Authorization boundary

The security boundary is **the set of host resources accessible to the guest and the entire VMM**. A virtio-fs export path is not an independent containment boundary; guest mount permissions do not isolate host resources. Host read-only attributes, masks, root switching, and FD cleanup are established before creating the filesystem backend.

The VMM jail retains the exact `/dev/kvm` node and a private PID-namespace proc, which provides `/proc/self/fd` for libkrun. These are authorized VMM resources, without a claim that malicious raw guest filesystem requests cannot reach them. The outer host proc and the whole host `/dev` are not shared by default. When GPU is enabled, the VMM also receives selected host render nodes and corresponding read-only sysfs entries; these are VMM capabilities, not direct guest mounts. VMM seccomp uses a denylist, including all three io_uring calls, userfaultfd, quotactl_fd and kcmp, plus the terminal input-injection ioctls TIOCSTI and TIOCLINUX on the inherited console descriptors (the separate session already leaves the VMM without a controlling terminal). Host socket/socketpair creation is restricted to AF_UNIX; guest AF_VSOCK uses libkrun’s Unix backend and passt uses an inherited Unix stream. Socket helpers use allowlists. There is no independent security audit or exhaustive validation of malicious raw virtio-fs requests.

The host is trusted. Host-side renaming, replacement, or recreation of masked paths during a run is outside the guarantee. Masks protect shared entry points, without hiding hardlinks, copies elsewhere, or already-granted FDs. Writable shares authorize direct modification of their host sources.

With Landlock ABI 9, the VMM may connect only to the fixed readiness/broker pathname Unix sockets; other host sockets reachable through shares, including read-only shares and export aliases, are denied. Sockets created inside the confined domain, including the control listener, remain usable. Below ABI 9, a warning reports the original boundary: reachable host sockets inside shares remain service capabilities. Explicit guest relays carry only bytes. For Wayland, waypipe serializes protocol traffic, including FD-backed resources, before the relay. Authorized services and inherited FDs can still grant capabilities; Landlock does not revoke them.

## Landlock confinement

The kernel ABI is probed at runtime. Supervisor and D-Bus proxy filesystem profiles require ABI 3, including truncate restrictions; the VMM pathname Unix socket allowlist requires ABI 9. Missing ABI support or disabled Landlock produces an explicit warning and retains the existing isolation for those profiles. Wayland forwarding requires its host helper's ABI 3 confinement and fails startup without it. On supported kernels, rule creation or enforcement errors fail startup. `doctor` reports both capabilities.

The supervisor installs its filesystem policy only in the parent branch after the worker fork, so the worker can still mount and pivot. It retains runtime cleanup permissions. Removing runtime itself requires `REMOVE_DIR` on its parent, which also permits removal of other empty directories beneath that parent, without granting file reads, writes, or regular-file removal there. Existing terminal and communication FDs remain usable.

Before exec, each D-Bus proxy gets a built-in file allowlist: read-only `/usr` and existing `/lib` and `/lib64`; execution of the proxy binary and known x86_64/aarch64 ELF loaders; individual `/etc` loader-cache, NSS, account, resolver, machine-id and timezone files; and read-only `/dev/null` and `/dev/urandom`. Each bus has a separate caller-owned 0700 private directory, with only enumeration, socket creation and entry removal allowed, without regular-file writes. The whole home, `/etc`, and host runtime directory are not granted. The upstream address remains a D-Bus configuration choice: this profile does not filter proxy socket connections, and addresses requiring home authentication files are outside its filesystem grants.

The VMM socket policy is installed after mounts, pivot and FD cleanup, before libkrun creates threads. It does not further restrict ordinary file access and explicitly preserves cross-directory rename/link behavior. The VMM normally denies `execve` and always denies `execveat`. When GPU flag bit 9 selects render-server mode, the VMM permits `execve` under a mandatory, separate Landlock rule that grants execution only of `/usr/libexec/virgl_render_server` and the ELF `PT_INTERP` loader named by that binary. Other executable targets remain denied; missing Landlock or a missing/invalid render server fails startup. This narrow exception lets virglrenderer start its Venus server without opening general VMM execution. Landlock does not replace host read-only mounts, masks, FD cleanup or seccomp, and does not cover all metadata operations. Socket controller/data processes and passt receive no additional Landlock policy.

## UID/GID and privilege dropping

Only the caller's numeric U/G is mapped. For a caller with `1000:1000`:

```text
uid_map: 1000 1000 1
gid_map: 1000 1000 1
```

Mappings are relative to the immediate outer user namespace, which need not be the physical host's initial namespace inside a container. Unprivileged GID mapping uses `setgroups=deny`; no subordinate IDs or root daemon are required. Unmapped host owners may appear as overflow IDs. Host `/usr` ownership is unchanged, and supplementary group/ACL behavior is not guaranteed to match the host.

Setup uses namespace capabilities for mounts and root switching, clearing them and setting `no_new_privs` before VMM startup. The guest helper assembles the filesystem as guest root, then sets groups, GID, and UID, locks securebits, clears capabilities, and sets `no_new_privs` before executing the command. There is no guest sudo or elevated workload mode.

## Host policy tree and guest filesystem

Host mount propagation is recursive private. Source objects are pinned with FDs; targets use restricted `openat2` resolution. Mounts are assembled in ancestor order, applying child mounts, read-only attributes, and masks. Host `mount_setattr` enforces read-only policy independently of guest mount flags. Explicit child mounts retain their own permissions.

All exported objects come from the final confined policy tree, never directly from original source FDs. Masks overlay empty read-only files/directories, retaining configured descendant exceptions. Mountinfo checks reject bind aliases that could bypass masks, read-only `/usr`, or private runtime restrictions. `plan` checks configuration and filesystem paths; launch additionally checks pinned FDs and mount identities.

Two fixed virtio-fs devices provide guest bootstrap material:

| Device | Contents |
| --- | --- |
| `/dev/root` | Minimal bootstrap: helper, launch/mount descriptions, read-only `/usr`, private `/etc`, and boot directories |
| `/.agent-vm/exports` | Confined object catalog, addressed through `/N/root` or `/N/file` |

Full target paths live in a bounded mount description, so additional mounts and long paths need no extra device tags. The guest helper creates a native tmpfs root in a separate mount namespace, installs built-in filesystems, then interleaves bind and custom tmpfs mounts in ancestor order. It preserves guest kernel/init proc/sys/dev mounts, removes catalog staging, pivots root, detaches the old bootstrap, and seals the root skeleton read-only. Guest PID 1's bootstrap view and the final view share the same private resolver file.

| Guest path | Source |
| --- | --- |
| `/usr` | Host read-only share, executable with suid disabled |
| `/bin`, `/sbin`, `/lib`, `/lib64` | Links into `/usr` according to host layout |
| `/etc` | Minimal generated accounts, NSS, hosts, hostname; CA, timezone, loader cache/config imported from fixed locations |
| `/etc/alternatives` | Read-only bind when present, preserving symlinks |
| `/etc/resolv.conf` | Separate private writable file for DHCP |
| Home | Guest tmpfs by default, host share when explicitly configured |
| CWD | Writable share at the same absolute path by default |
| `/tmp`, `/var/tmp`, `/run` | Guest tmpfs; `/run/user/U` belongs to U with mode 0700 |
| Custom tmpfs | Guest-local temporary storage with explicit bind/tmpfs children |
| `/proc`, `/sys`, `/dev` and their built-in mounts | Guest kernel/init; enabled GPU render nodes are native virtio devices owned by the workload user with mode 0666 |
| Other root directories | Minimal placeholders and explicit mounts |

Host `/etc/ld.so.conf` and `ld.so.conf.d/`, when present, are copied into private read-only `/etc`; symlinks to regular configuration files are copied as files. The entire host `/etc` is not shared automatically. Reusing `/usr` does not provide every host command's external configuration, services, or symlink targets, or a consistent software snapshot during a run.

Each custom tmpfs has a private host staging skeleton that hides the covered source subtree, prepares children, and exports the final policy. The skeleton is read-only while explicit writable bind children remain writable. Actual tmpfs contents live in guest RAM, without writes to host staging. `--tmp-size` limits each tmpfs separately; VM memory does not impose a total host cgroup limit or shared-disk quota.

## GPU

GPU is an independent opt-in. An absent mask disables it; `--gpu=0` enables it with raw flags zero, without guaranteeing successful startup. CLI decimal or hexadecimal unsigned 32-bit masks and TOML `[vm].gpu_flags` are passed unchanged to `krun_set_gpu_options`; the runner checks the libkrun GPU feature, while libkrun and its renderer determine whether the mask works. The VMM's host access is limited to selected render nodes and their matching read-only sysfs entries. Guest GPU device nodes are created by its own kernel and owned by the workload user, with mode 0666 for render nodes and 0660 for `/dev/dri/card0`; host node permissions are unchanged. This does not grant the guest a bind of host `/dev/dri` or the host sysfs tree. `963` (`0x3c3`) selects EGL, thread synchronization, Venus, no VirGL, asynchronous fence callbacks, and render-server mode. Driver and device support remain host- and libkrun-dependent. On libkrun 1.19, unimplemented `TransferFromHost3d`/`transfer_read` can panic the host VMM GPU worker and stall an accelerated VirGL Wayland workload even when offscreen VirGL works; this is not a general guarantee for all accelerated Wayland workloads.

## Networking, vsock, and protocols

Passt remains in the host network namespace, exchanging Ethernet frames with libkrun through a preconnected Unix stream FD, without a host TAP device. The VMM has an empty network namespace. Implicit vsock/TSI is disabled; only explicit mappings remain:

| Vsock port | Purpose |
| --- | --- |
| 1024 | Fixed signal and terminal-resize control messages |
| 1025–1280 | Up to 256 authorized socket forwards |
| 1281 | One-shot guest readiness connection |

IPC is absent from the bootstrap and export catalog. The VMM receives individual read-only inode binds for the already-listening broker and readiness sockets, beneath a read-only parent; replacing a broker upstream socket still reconnects through the broker. The host runtime IPC directory is not mounted into the VMM. For libkrun’s late-created control listener, the supervisor creates a detached tmpfs (64 KiB, 16 inodes), retains its directory FD and gives the VMM a bind of that filesystem. It has no path in the host runtime filesystem and is released when the VM and supervisor close their references. Control sends open `control.sock` relative to the retained dirfd with `O_PATH | O_NOFOLLOW`, require a socket via `fstat`, and connect through `/proc/self/fd/<fd>` while retaining that inode pin. Symlink replacement cannot redirect a connection outside the control filesystem. A compromised VMM can still deny service to its own control channel; the supervisor’s five-second forced termination remains in effect. Readiness has no payload or shared-file marker; it is a lifecycle hint, not proof of guest trustworthiness. The control protocol accepts neither host paths nor arbitrary commands.

`include/agent_vm/protocol.h` defines launch format version 2 and mount format version 3. They use native endianness, require matching host/guest architectures, limit configuration size to 1 MiB, and use length-prefixed strings. Stream relays use network-byte-order lengths and DATA/EOF/ACK frames, with at most 65536 data bytes per frame. EOF and acknowledgements preserve half-close semantics and drain trailing data before transport closure.

Wayland forwarding consumes one authorized socket-forward slot. The host resolves `WAYLAND_DISPLAY` as an absolute path or relative to `XDG_RUNTIME_DIR` (default `wayland-0`) and validates the selected Unix socket. The confined host `/usr/bin/waypipe client` connects to that compositor; this helper requires Landlock ABI 3 and fails startup if unavailable. The guest command is wrapped by `/usr/bin/waypipe --socket /run/user/<uid>/waypipe.sock server --`. Both waypipe processes use `--no-gpu` by default; when GPU is enabled, they omit it and the host helper's Landlock policy admits selected render nodes for decoding. The host client listens on a private Unix transport, which the existing broker and framed vsock relay connect to the guest server. The compositor socket itself is not mounted or forwarded into the VM. Waypipe handles FD-bearing Wayland messages, including shared-memory buffers, on its respective sides of the byte-only transport. The base path uses neither passt nor X11, and GPU remains optional. Enabling it grants the workload the selected compositor's protocol capabilities.

Optional Xwayland satellite support adds `--xwls` to the guest waypipe server. Waypipe sets the guest `DISPLAY` and starts `xwayland-satellite` on demand, using `Xwayland` from the guest's shared `/usr`. It requires Wayland forwarding and waypipe 0.11 or newer with `--xwls`. The host continues to expose only the selected Wayland compositor through the confined host waypipe client; no host X11 socket or Xauthority file crosses the boundary. A user-supplied guest `DISPLAY` conflicts with waypipe's display assignment and is rejected. X11 clients receive the guest Xwayland service capability and ultimately the selected compositor's display capability through the Wayland transport.

With networking enabled, the guest helper checks addresses, routes, and DNS before launching the workload. Guest kernel arguments include `oops=panic panic=-1`. The helper seeds failure status 125 before assembly; libkrun init writes the normal status after helper exit completes. This makes guest kernel exceptions terminate promptly, without repairing firmware kernel bugs.

## Socket broker confinement

N forwards share one controller and N persistent data processes, allowing up to 64 concurrent connections per forward. The controller connects only configured basenames inside preauthorized parent directories; it provides no arbitrary-path RPC.

The controller has private user, mount, network, IPC, and UTS namespaces. Its root contains read-only authorized upstream parent directories, deduplicated by directory, with unrelated submounts masked. Retaining parents allows reconnection after socket replacement within a directory, without tracking replacement of the parent itself. Sibling sockets are inside the controller's filesystem boundary, although normal operation connects only configured targets. Its seccomp allowlist permits accept, selection of preopened directories, Unix stream connection, and FD-pair handoff, but no stream reads, file opens, or execution.

Each data process is PID 1 in its own PID namespace, with an empty read-only root and no proc/dev, standard streams, host directory FDs, or listener FDs. It receives connected FD pairs through a private one-way channel and relays bytes. Its allowlist denies file opens, socket creation/connection, exec, fork, ptrace, and namespace changes. Both controller and data processes clear all capabilities, including the bounding set, and set `no_new_privs` before readiness. Data-process failure triggers cleanup of the whole broker.

Internal FD handoff uses `SCM_RIGHTS`; this is not guest FD forwarding. There are no additional idle timeouts or aggregate host resource quotas. Broker confinement does not change passt's own sandbox; the separate `xdg-dbus-proxy` uses the Landlock filesystem profile described above. Each enabled D-Bus uses an independent filtering proxy; its policy and upstream address are not serialized to the clean VMM worker, which receives resolved socket mappings only. Waypipe's private transport is an authorized upstream for one broker slot, and the host waypipe process is confined separately.

## Process observability

`ps -eo pid,ppid,comm,args` shows `avm-supervisor`, `avm-sock-ctl`, `avm-sock-N`, and `avm-vmm-wait`; data titles include host sources and guest targets. The VMM title is `agent-vm: virtual machine`, while libkrun sets its own main-thread name. Guest processes use `avm-guest`, `avm-relay-N`, and `avm-stream-N`; workloads, passt, and D-Bus proxies retain their executable names.

Titles are set before confinement, escape control characters, and are bounded by original argv/environment storage. Original argv/environment strings are saved separately before storage reuse; small launch environments can truncate long titles. See the [development guide](DEVELOPMENT.md) and [testing guide](TESTING.md) for source responsibilities and test entry points.
