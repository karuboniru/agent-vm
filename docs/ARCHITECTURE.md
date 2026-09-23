[中文](ARCHITECTURE.zh.md) · [README](../README.md)

# Architecture and security boundaries

## Components and lifecycle

```text
agent-vm supervisor
  ├─ passt                         optional, host networking
  ├─ xdg-dbus-proxy                 one per enabled bus
  ├─ socket controller             shared by all forwards
  │    └─ socket data processes     one per forward
  └─ clean re-exec → VMM worker     libkrun + namespaces + mount jail
       └─ guest init
            └─ agent-vm-guest
                 ├─ socket relays
                 └─ workload       caller UID/GID
```

The supervisor parses TOML/CLI into `RunSpec` and prepares a private runtime directory, launch configuration, and fixed communication endpoints. D-Bus proxies become ready before socket brokers start. After starting passt and brokers, the supervisor enters a single-ID user namespace and an empty network namespace, clears capabilities, and sets `no_new_privs`, then forks/re-execs the VMM worker. Supervisor isolation also applies with networking disabled.

The worker re-execs with a minimal environment, separating its address space from configuration parsing and the original host environment. It establishes user, mount, PID, IPC, UTS, and network namespaces, assembles its restricted root, closes unapproved FDs, clears capabilities, and installs a seccomp denylist before starting libkrun. The supervisor manages signals, TTY state, exit status, and helper cleanup; unexpected helper exit ends the VM.

## Authorization boundary

The security boundary is **the set of host resources accessible to the guest and the entire VMM**. A virtio-fs export path is not an independent containment boundary; guest mount permissions do not isolate host resources. Host read-only attributes, masks, root switching, and FD cleanup are established before creating the filesystem backend.

The VMM jail retains the exact `/dev/kvm` node and a private PID-namespace proc, which provides `/proc/self/fd` for libkrun. These are authorized VMM resources, without a claim that malicious raw guest filesystem requests cannot reach them. The outer host proc and the whole host `/dev` are not shared by default. VMM seccomp uses a denylist; socket helpers use allowlists. There is no independent security audit or exhaustive validation of malicious raw virtio-fs requests.

The host is trusted. Host-side renaming, replacement, or recreation of masked paths during a run is outside the guarantee. Masks protect shared entry points, without hiding hardlinks, copies elsewhere, or already-granted FDs. Writable shares authorize direct modification of their host sources.

Reachable host Unix sockets inside shares are also service capabilities, even when the directory is read-only. Explicit guest relays carry only bytes. A compromised VMM that can connect directly to a reachable service can use capabilities granted by that service, including FDs it sends voluntarily. Thus `--network none`, read-only binds, and path masks do not restrict permissions separately granted by services over authorized connections.

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
| `/proc`, `/sys`, `/dev` and their built-in mounts | Guest kernel/init |
| Other root directories | Minimal placeholders and explicit mounts |

Host `/etc/ld.so.conf` and `ld.so.conf.d/`, when present, are copied into private read-only `/etc`; symlinks to regular configuration files are copied as files. The entire host `/etc` is not shared automatically. Reusing `/usr` does not provide every host command's external configuration, services, or symlink targets, or a consistent software snapshot during a run.

Each custom tmpfs has a private host staging skeleton that hides the covered source subtree, prepares children, and exports the final policy. The skeleton is read-only while explicit writable bind children remain writable. Actual tmpfs contents live in guest RAM, without writes to host staging. `--tmp-size` limits each tmpfs separately; VM memory does not impose a total host cgroup limit or shared-disk quota.

## Networking, vsock, and protocols

Passt remains in the host network namespace, exchanging Ethernet frames with libkrun through a preconnected Unix stream FD, without a host TAP device. The VMM has an empty network namespace. Implicit vsock/TSI is disabled; only explicit mappings remain:

| Vsock port | Purpose |
| --- | --- |
| 1024 | Fixed signal and terminal-resize control messages |
| 1025–1280 | Up to 256 authorized socket forwards |
| 1281 | One-shot guest readiness connection |

The IPC directory is host/VMM-private and absent from the bootstrap and export catalog. Readiness has no payload or shared-file marker; it is a lifecycle hint, not proof of guest trustworthiness. The control protocol accepts neither host paths nor arbitrary commands.

`include/agent_vm/protocol.h` defines launch format version 2 and mount format version 3. They use native endianness, require matching host/guest architectures, limit configuration size to 1 MiB, and use length-prefixed strings. Stream relays use network-byte-order lengths and DATA/EOF/ACK frames, with at most 65536 data bytes per frame. EOF and acknowledgements preserve half-close semantics and drain trailing data before transport closure.

With networking enabled, the guest helper checks addresses, routes, and DNS before launching the workload. Guest kernel arguments include `oops=panic panic=-1`. The helper seeds failure status 125 before assembly; libkrun init writes the normal status after helper exit completes. This makes guest kernel exceptions terminate promptly, without repairing firmware kernel bugs.

## Socket broker confinement

N forwards share one controller and N persistent data processes, allowing up to 64 concurrent connections per forward. The controller connects only configured basenames inside preauthorized parent directories; it provides no arbitrary-path RPC.

The controller has private user, mount, network, IPC, and UTS namespaces. Its root contains read-only authorized upstream parent directories, deduplicated by directory, with unrelated submounts masked. Retaining parents allows reconnection after socket replacement within a directory, without tracking replacement of the parent itself. Sibling sockets are inside the controller's filesystem boundary, although normal operation connects only configured targets. Its seccomp allowlist permits accept, selection of preopened directories, Unix stream connection, and FD-pair handoff, but no stream reads, file opens, or execution.

Each data process is PID 1 in its own PID namespace, with an empty read-only root and no proc/dev, standard streams, host directory FDs, or listener FDs. It receives connected FD pairs through a private one-way channel and relays bytes. Its allowlist denies file opens, socket creation/connection, exec, fork, ptrace, and namespace changes. Both controller and data processes clear all capabilities, including the bounding set, and set `no_new_privs` before readiness. Data-process failure triggers cleanup of the whole broker.

Internal FD handoff uses `SCM_RIGHTS`; this is not guest FD forwarding. There are no additional idle timeouts or aggregate host resource quotas. Broker confinement does not sandbox the separate `xdg-dbus-proxy` executable or change passt's own sandbox. Each enabled D-Bus uses an independent filtering proxy; its policy and upstream address are not serialized to the clean VMM worker, which receives resolved socket mappings only.

## Process observability

`ps -eo pid,ppid,comm,args` shows `avm-supervisor`, `avm-sock-ctl`, `avm-sock-N`, and `avm-vmm-wait`; data titles include host sources and guest targets. The VMM title is `agent-vm: virtual machine`, while libkrun sets its own main-thread name. Guest processes use `avm-guest`, `avm-relay-N`, and `avm-stream-N`; workloads, passt, and D-Bus proxies retain their executable names.

Titles are set before confinement, escape control characters, and are bounded by original argv/environment storage. Original argv/environment strings are saved separately before storage reuse; small launch environments can truncate long titles. See the [development guide](DEVELOPMENT.md) and [testing guide](TESTING.md) for source responsibilities and test entry points.
