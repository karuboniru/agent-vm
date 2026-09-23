[中文](DEVELOPMENT.zh.md) · [README](../README.md)

# Development guide

## Dependencies and environment

Host code uses C++20; the guest helper uses C17. Builds require CMake >= 3.20, Ninja, pkg-config, libkrun >= 1.19 and < 2, toml++, libcap, libseccomp, and C/C++ compilers. Runtime requires libkrun firmware; optional features require passt and `/usr/bin/xdg-dbus-proxy`.

Local configuration and compilation must run inside a `toolbox` container. Install development dependencies in a Fedora container with:

```sh
toolbox run sudo dnf install gcc gcc-c++ cmake ninja-build pkgconf-pkg-config \
  libkrun-devel libkrunfw tomlplusplus-devel libcap-devel libseccomp-devel \
  passt xdg-dbus-proxy
```

The VM execution environment needs a visible `/dev/kvm` with caller read/write access, permission for unprivileged user namespaces and mounts, and Linux interfaces including `openat2`, `pidfd_open`, and `mount_setattr`. LSM, container, and tool-sandbox policies must allow these operations. A successful build does not establish permission to run a VM in the current environment.

## Build and install

From the repository root:

```sh
toolbox run cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
toolbox run cmake --build build
./build/agent-vm doctor
./build/agent-vm run --no-config -- id
```

Select a container with `toolbox run --container <name> ...`. Run `doctor` and VM commands where runtime dependencies, KVM, and namespace permissions are available; add the same toolbox prefix if that environment is the container.

Optional user installation:

```sh
toolbox run cmake --install build --prefix "$HOME/.local"
"$HOME/.local/bin/agent-vm" doctor
```

Both `agent-vm` and `libexec/agent-vm-guest` must be installed. The executable can locate its helper relative to the installation. The example installs as `share/agent-vm/config.toml` without automatically becoming user configuration. See the [packaging guide](PACKAGING.md) for RPM layout and builds.

## Source responsibilities

| File | Responsibility |
| --- | --- |
| `src/config.cpp` | TOML/CLI, path and policy validation, plan output |
| `include/agent_vm/spec.hpp` | Configuration and runtime specifications |
| `src/main.cpp` | Doctor, worker re-exec, libkrun setup, process/TTY/signal lifecycle |
| `src/sandbox.cpp` | Namespaces, UID mapping, mounts, masks, VMM seccomp |
| `src/network.cpp` | Passt, D-Bus proxies, socket controller, stream forwarding |
| `src/socket_sandbox.cpp` | Socket controller/data namespace and seccomp confinement |
| `src/process_title.c` | Host/guest process names and titles |
| `guest/main.c` | Launch protocol, privilege dropping, command supervision, control channel |
| `guest/filesystem.c` | Mount descriptions, tmpfs, shared objects, guest root switch |
| `guest/relay.c` | Guest Unix stream listeners and relays |
| `include/agent_vm/protocol.h` | Host/guest launch, mount, control, and stream protocols |

## Conventions

- Use toolbox for local builds, retaining CMake language standards and warning settings. Host code uses RAII for FDs, child processes, and cleanup; the guest helper keeps a C interface and small dependency surface.
- Pass arguments and environment through structured formats, without shell concatenation. Validate configuration fields explicitly and reject unknown fields. `plan` performs no mounts and omits environment values.
- Enforce filesystem authorization through host confinement. Mount, mask, FD, namespace, or seccomp changes require checking rejection paths and resource cleanup alongside successful operation.
- Keep shared host/guest formats in `protocol.h`. Update producers, consumers, size bounds, and version checks together.
- Run checks from the [testing guide](TESTING.md) appropriate to the change. Report the actual scope of VM, namespace, and packaging validation separately; skips and environment denials are not passes.
- Documentation describes only the current implementation and limitations. `.md` is English and the matching `.zh.md` is Chinese; keep both synchronized and mutually linked. README covers purpose, usage entry points, and overall design; topic guides hold details.
