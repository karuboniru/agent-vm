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

CTest does not start real VMs, but some confinement tests create namespaces, so a restricted sandbox may still prevent execution. Sandbox integration also needs access to `/dev/kvm`. Run in an environment with dependencies and permissions; use prefixes such as `toolbox run ctest ...` when dependencies reside there.

| CTest name | Coverage |
| --- | --- |
| `landlock` | Unavailable-support fallback/error handling, file read/write/truncate denial, existing FDs, supervisor cleanup and ABI 9 Unix socket allowlist; returns 77 without ABI 3 |
| `config` | CLI/TOML, profiles, merge precedence, mounts/tmpfs/masks, environment, socket/D-Bus policy |
| `process-title` | Short names/full titles, preserved argv/environment, fork isolation, escaping, truncation |
| `dbus` | Proxy readiness, lifetime FD, startup failure, reaping; missing xdg-dbus-proxy returns 77 and CTest marks it skipped |
| `wayland` | Host waypipe input validation, transport readiness, confinement, GPU mode selection, and lifecycle; missing waypipe or Landlock ABI 3 returns 77 |
| `network` | Passt input validation and helper lifecycle |
| `relay` | Raw-byte relay pump with socketpairs, including half-close |
| `control` | Pinned control inode, symlink rejection, parent replacement and rename races |
| `paths` | C/C++ reserved-path, normalization and containment parity |
| `sandbox-seccomp` | Dangerous-syscall and host socket-family rejection; thread compatibility |

Some real VM socket-forwarding cases may expose a known data-loss issue in libkrun 1.x path mapping; current testing has observed truncation of a terminal EOF sentinel in the test payload. The fix in upstream PR 885 is planned for cherry-pick into a future 1.x build; no fixed release version is identified here. Current Wayland validation has also reached several surface commits before a virtiofs panic caused exit status 125. Record these failures rather than treating the affected cases as passing coverage.

`sandbox-test --integration` additionally checks single-ID mappings, namespaces, capabilities, read-only and nested ro/rw mounts, masks/alias rejection, tmpfs coverage, bootstrap contents, FD cleanup, pinned socket endpoints, and the direct/Waypipe IPC allowlist.

## Real VM tests

The execution environment needs KVM, namespace permissions, and feature-specific dependencies. Python scripts default to `build/agent-vm`; override with `--binary /absolute/path/to/agent-vm`.

```sh
python3 tests/integration_core.py
python3 tests/integration_network.py
python3 tests/integration_dbus.py
python3 tests/integration_wayland.py
python3 tests/integration_wayland.py --xwayland-satellite
python3 tests/integration_wayland.py --gpu-flags 963
python3 tests/integration_gpu.py --gpu-flags 0x10b
```

| Script | Coverage |
| --- | --- |
| `integration_core.py` | Argv/env, identity/file ownership, home, mounts/masks/tmpfs, read-only policy, loopback, exit status, pipes/PTY, signals, resizing, terminal restoration, panic settings |
| `integration_network.py` | TCP/UDP outbound, IPv6 outbound, publications, SSH agent alias, generic sockets with pinned endpoint identity and multiple connections, tmpfs targets, existing-target rejection |
| `integration_dbus.py` | Bus filtering, independent user/system switches, guest addresses, proxy lifecycle |
| `integration_wayland.py` | Headless Weston compositor; repeated Wayland registry connections and mapped `xdg_toplevel` windows with 256×256 `wl_shm` FD-backed buffers and frame callbacks through waypipe; exit status and SIGTERM. With `--xwayland-satellite`, also checks guest `DISPLAY` and three X11 connections that create and map windows through Xwayland. With `--gpu-flags 963`, also checks hardware Venus and 30 Wayland `vkcube` frames through DMA-BUF |
| `integration_gpu.py` | Guest virtio DRM render-node ownership and mode 0666, GBM/EGL OpenGL pixel readback through VirGL, rejecting software renderers; GPU flag mask can be selected with `--gpu-flags` |

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

The default Wayland case starts a disposable Weston headless compositor, so it does not need a desktop session, X11, GPU, or external network. It needs `weston` with its headless backend, `/usr/bin/waypipe`, `libwayland-client.so.0`, guest `/usr/bin/python3`, KVM, Landlock ABI 3, and the normal VM namespace permissions in the execution environment. The optional `--xwayland-satellite` case also needs `xwayland-satellite`, `Xwayland`, and `libX11.so.6` in the execution environment and shared guest `/usr`; it verifies three X11 window maps and reconnections alongside the usual exit and signal cases. The optional `--gpu-flags 963` case additionally needs a host render node, GPU-capable libkrun, Weston GL renderer, and `vkcube` and `vulkaninfo` from `vulkan-tools` in the execution environment and shared guest `/usr`. It checks hardware Venus and 30 DMA-BUF Wayland frames; other hardware and flag masks can behave differently. The script exits 77 when a checked optional prerequisite is unavailable; startup or protocol failures after prerequisites are present fail the test. When these packages and the built binary are inside toolbox, run:

```sh
toolbox run python3 tests/integration_wayland.py
toolbox run python3 tests/integration_wayland.py --xwayland-satellite
toolbox run python3 tests/integration_wayland.py --gpu-flags 963
```

The GPU script does not need a compositor. It needs an accessible host `/dev/dri/renderD*`, GPU-capable libkrun, guest `/usr/bin/python3`, Mesa GBM/EGL/OpenGL libraries, KVM, and VM namespace permissions. It defaults to raw mask `0x10b`; use another decimal/hexadecimal uint32 mask to test a different libkrun configuration. `--gpu-flags 0` is accepted as an enable request but may fail during VM startup or rendering. Missing checked host prerequisites exit 77; VM or rendering failures fail. For dependencies installed in toolbox:

```sh
toolbox run python3 tests/integration_gpu.py --gpu-flags 0x10b
```

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
