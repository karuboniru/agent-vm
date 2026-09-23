[中文](TESTING.zh.md) · [README](../README.md)

# Testing guide

This guide lists repository test entry points and coverage, not the results of a particular run. See the [development guide](DEVELOPMENT.md) for builds and dependencies. Run commands from the repository root.

## CTest and host confinement tests

```sh
toolbox run cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
toolbox run cmake --build build
ctest --test-dir build --output-on-failure
./build/sandbox-test --integration
```

CTest does not start real VMs, but network/socket-sandbox tests create namespaces, so a restricted sandbox may still prevent execution. Sandbox integration also needs access to `/dev/kvm`. Run in an environment with dependencies and permissions; use prefixes such as `toolbox run ctest ...` when dependencies reside there.

| CTest name | Coverage |
| --- | --- |
| `config` | CLI/TOML, profiles, merge precedence, mounts/tmpfs/masks, environment, socket/D-Bus policy |
| `process-title` | Short names/full titles, preserved argv/environment, fork isolation, escaping, truncation |
| `dbus` | Proxy readiness, lifetime FD, startup failure, reaping; missing xdg-dbus-proxy returns 77 and CTest marks it skipped |
| `network` | Concurrent streams, backpressure, half-close, frame validation, reconnection, shared controller, data-process reuse and failure cleanup |
| `socket-sandbox` | Controller/data filesystem and syscall boundaries, independent PID namespace, locked submounts, socket binds |
| `sandbox-seccomp` | Dangerous-syscall rejection and thread compatibility |

`sandbox-test --integration` additionally checks single-ID mappings, namespaces, capabilities, read-only and nested ro/rw mounts, masks/alias rejection, tmpfs coverage, bootstrap contents, and FD cleanup.

## Real VM tests

The execution environment needs KVM, namespace permissions, and feature-specific dependencies. Python scripts default to `build/agent-vm`; override with `--binary /absolute/path/to/agent-vm`.

```sh
python3 tests/integration_core.py
python3 tests/integration_network.py
python3 tests/integration_dbus.py
```

| Script | Coverage |
| --- | --- |
| `integration_core.py` | Argv/env, identity/file ownership, home, mounts/masks/tmpfs, read-only policy, loopback, exit status, pipes/PTY, signals, resizing, terminal restoration, panic settings |
| `integration_network.py` | TCP/UDP outbound, IPv6 outbound, publications, SSH agent alias, generic sockets, concurrent streams/reconnection, tmpfs targets, existing-target rejection |
| `integration_dbus.py` | Bus filtering, independent user/system switches, guest addresses, proxy lifecycle |

Run individual network cases with:

```sh
python3 tests/integration_network.py --case sockets
python3 tests/integration_network.py --case ssh
```

Other cases are `outbound`, `outbound6`, and `publish`. The D-Bus script needs `dbus-daemon`; if only that program resides in toolbox:

```sh
python3 tests/integration_dbus.py --daemon-prefix toolbox run
```

Tests use temporary homes/workspaces and local TCP/UDP/Unix services. SSH stream tests use neither real credentials nor public services. Network tests retain temporary logs on failure.

## Installation checks and troubleshooting

Check a relocated installation in a private directory:

```sh
toolbox run cmake --install build --prefix "$PWD/build/install-smoke"
./build/install-smoke/bin/agent-vm --version
./build/install-smoke/bin/agent-vm doctor
./build/install-smoke/bin/agent-vm run --no-config -- id
```

`doctor` reports KVM visibility, device permissions, and namespace restrictions. A tool-sandbox denial does not establish that the physical host lacks KVM; check in an environment permitting those capabilities. For missing shared libraries, distinguish the build container from the execution environment.

For guest panics mentioning `VFS: Busy inodes after unmount` or `generic_shutdown_super`, check the virtiofs unmount path in the guest kernel bundled by libkrunfw. `oops=panic panic=-1` and the seeded failure status make exceptions terminate promptly without repairing kernel defects. Status 125 or prompt termination is not a test pass.

Record commands, dependency/kernel environment, failures, and skips when validating. This suite is not a complete security audit or exhaustive coverage of malicious raw virtio-fs requests, host syscalls, or resource exhaustion. See the [packaging guide](PACKAGING.md) for RPM checks.
