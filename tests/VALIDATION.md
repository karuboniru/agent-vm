# Validation record — 0.1.0

Validated on 2026-09-20 with Fedora 45 x86_64, Linux 7.2.6, libkrun 1.19.0,
libkrunfw 5.5.0 and passt 20260728. KVM and namespace tests ran outside the
tool sandbox as the ordinary invoking user; no sudo was needed.

| Check | Result |
| --- | --- |
| CMake/Ninja RelWithDebInfo build | Passed, no compiler warnings |
| `config-test` | 272 parser and policy checks passed |
| `network-test` | Concurrent framed streams, 8 × 2 MiB, backpressure, half-close, reconnect, invalid frames, FD/worker/process-group cleanup passed |
| `sandbox-test` | Seccomp denies dangerous operations while allowing threads |
| `sandbox-test --integration` | Single-ID mapping, PID namespace, capabilities, read-only host policy placeholders, writable DNS, export-object masks and nested ro/rw, tmpfs-covered export isolation, bootstrap contents, FD cleanup, bind-alias negative tests passed |
| `integration_core.py` | 47 real-VM checks passed |
| `integration_network.py` | Outbound TCP/UDP, published TCP/UDP, SSH alias, and generic Unix socket bridge cases passed |
| Relocated installation | `cmake --install --prefix /tmp/...`; installed executable found its libexec helper, started a VM, and read generated loader configuration |

Core VM coverage includes literal argv/environment transport, non-inheritance
of unselected environment values, numeric UID/GID and persistent CWD file
ownership, ephemeral home, a mask through two home aliases, invalid policy
rejection, read-only mounts, network-none with working guest loopback,
exit statuses, pipe EOF, separate stdout/stderr, SIGTERM and process-group
SIGTERM, PTY operation, window resize, and host terminal restoration. Filesystem
assembly coverage includes guest-native tmpfs for the root, home and temporary
directories, per-filesystem ENOSPC limits, one path-tagged export catalog,
single-file ro/rw aliases, long target paths, whole-file and private-path masks,
and detachment of the guest's bootstrap root and catalog staging mount.
Custom tmpfs coverage includes default and explicit UID/GID/mode, nested
mount ordering, independent capacity limits, empty filesystems on each run,
configuration and CLI combination, working directories, and writable tmpfs
over read-only shares without modifying the covered host directory.
Mixed-layer tests cover a temporary GnuPG directory with a read-only keyring
bind under both ephemeral and shared home, plus alternating bind/tmpfs layers
in both declaration orders. Only explicitly writable bind children persist
writes; temporary files, directories and sockets do not change the host tree.

Network tests use temporary local TCP/UDP/Unix echo services. The SSH test uses
six concurrent 256 KiB streams and checks final data after half-close; it does
not use real SSH credentials or a public network endpoint. Generic forwarding
tests exercise independent routes, concurrent streams, upstream socket
replacement, root-created user-owned parent directories, shared-directory
permissions, custom tmpfs socket destinations (including over read-only shares),
and refusal to replace existing targets. Unpublished UDP
ports remain unbound even when a matching TCP port is published.

Integration findings affected the implementation:

1. libkrun 1.19's Unix backend can process HUP before pending input. Internal
   DATA/EOF/ACK framing and control acknowledgements avoid closing the transport
   until the receiver has consumed its data.
2. Network helpers need separate host process groups; otherwise a terminal group
   signal can kill them before the supervisor forwards it to the guest.
3. A virtio-fs device per mounted object exhausts libkrun 1.19's IRQ allocation
   in the nested-mount test. The implementation uses two fixed devices: a
   bootstrap root and a confined object catalog, with guest bind mounts selecting
   objects according to the host-generated description.
4. On 2026-09-21, libkrunfw 5.5.0's Linux 6.12.91 reproduced an exit-time
   virtiofs submount crash (`generic_shutdown_super`, busy inodes), matching
   upstream fix `06b41351779e9289e8785694ade9042ae85e41ea`, included in
   Linux 6.12.95. Before mitigation the core test timed out after 20 seconds;
   with `oops=panic panic=-1` and a seeded failure status, two subsequent
   occurrences exited with status 125 and a fatal-exception panic instead.
   The added core check verifies the command line and effective panic sysctls.
   Ordinary statuses 0, 37, 127 and forwarded SIGTERM status 143 were also
   verified. The toolbox build and config/network/seccomp tests passed; D-Bus
   was skipped. The full core suite still fails when the underlying race fires;
   fixing that race requires a patched guest kernel in libkrunfw.

This record does not constitute an independent security audit. In particular,
host-side mutation of masked paths is outside the agreed trusted-host boundary;
raw malicious virtio-fs protocol behavior and a complete host syscall allowlist
have not been exhaustively audited. See README.md for resource and networking
limits.
