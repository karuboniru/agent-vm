# Validation record — 0.1.0

Validated on 2026-09-20 with Fedora 45 x86_64, Linux 7.2.6, libkrun 1.19.0,
libkrunfw 5.5.0 and passt 20260728. KVM and namespace tests ran outside the
tool sandbox as the ordinary invoking user; no sudo was needed.

| Check | Result |
| --- | --- |
| CMake/Ninja RelWithDebInfo build | Passed, no compiler warnings |
| `config-test` | 82 parser and policy checks passed |
| `network-test` | Concurrent framed streams, 8 × 2 MiB, backpressure, half-close, reconnect, invalid frames, FD/worker/process-group cleanup passed |
| `sandbox-test` | Seccomp denies dangerous operations while allowing threads |
| `sandbox-test --integration` | Single-ID mapping, PID namespace, capabilities, read-only host policy placeholders, writable DNS, export-object masks and nested ro/rw, bootstrap contents, FD cleanup, bind-alias negative tests passed |
| `integration_core.py` | 33 real-VM checks passed |
| `integration_network.py` | Outbound TCP/UDP, published TCP/UDP, and SSH bridge cases passed |
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

Network tests use temporary local TCP/UDP/Unix echo services. The SSH test uses
six concurrent 256 KiB streams and checks final data after half-close; it does
not use real SSH credentials or a public network endpoint. Unpublished UDP
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

This record does not constitute an independent security audit. In particular,
host-side mutation of masked paths is outside the agreed trusted-host boundary;
raw malicious virtio-fs protocol behavior and a complete host syscall allowlist
have not been exhaustively audited. See README.md for resource and networking
limits.
