# agent-vm

A rootless Linux command runner using libkrun. It shares the host's `/usr` read-only, builds a temporary FHS filesystem, and runs a command in a microVM with the invoking user's numeric UID/GID.

The host supervisor and policy code use C++20; the guest helper uses C17. Tested with libkrun 1.19.0 and libkrunfw 5.5.0 on x86_64 Fedora. The [architecture document](ARCHITECTURE.md) records the design and its trust boundaries.

## Build

Required: a C/C++ compiler, CMake, Ninja, pkg-config, libkrun 1.19 development files and firmware, toml++, libcap and libseccomp. `passt` is required only for networking. Linux must support unprivileged user namespaces, `openat2`, `pidfd_open` and `mount_setattr` (Linux 5.12 or newer); container/LSM policy must allow the namespace and mount operations. `/dev/kvm` must be visible and accessible.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
./build/agent-vm doctor
./build/agent-vm run --no-config -- id
```

Fedora development packages:

```sh
sudo dnf install gcc-c++ cmake ninja-build pkgconf-pkg-config \
  libkrun-devel libkrunfw passt tomlplusplus-devel libcap-devel libseccomp-devel
```

Optional user installation:

```sh
cmake --install build --prefix "$HOME/.local"
```

Both `agent-vm` and its installed `libexec/agent-vm-guest` helper are needed. The current backend uses the libkrun 1.x API; libkrun 2.x is not supported.

## Fedora RPM

`agent-vm.spec` builds from a source tarball using Fedora's CMake macros,
compiler hardening flags, and automatic ELF dependencies. `passt` is an explicit
runtime dependency; the `libkrun` package pulls in its own firmware dependency.
The internal core library is linked statically into the executable. Tests are
disabled so build services do not need KVM or unprivileged user namespaces.

The spec uses the Fedora SourceURL forge macros and defaults to the `master`
branch. This is a moving development snapshot; pin a commit or release tag for
reproducible distribution builds. With `mock` installed and configured for your
user, build on Fedora 45:

```sh
mkdir -p build-rpm/{sources,srpm,result}
curl -fL https://github.com/karuboniru/agent-vm/archive/master/agent-vm-master.tar.gz \
  -o build-rpm/sources/agent-vm-master.tar.gz
mock -r fedora-45-x86_64 --uniqueext=agent-vm --buildsrpm \
  --spec "$PWD/agent-vm.spec" --sources "$PWD/build-rpm/sources" \
  --resultdir "$PWD/build-rpm/srpm"
mock -r fedora-45-x86_64 --uniqueext=agent-vm --rebuild \
  "$PWD"/build-rpm/srpm/agent-vm-*.src.rpm \
  --resultdir "$PWD/build-rpm/result"
rpmlint agent-vm.spec build-rpm/result/*.rpm
```

Use an empty SRPM output directory so the rebuild selects only the current
snapshot. Forge macros include the snapshot date and branch in the RPM release.

For a committed local checkout, replace the download with
`git archive --format=tar.gz --prefix=agent-vm-master/ HEAD > build-rpm/sources/agent-vm-master.tar.gz`.
The archive must contain the matching version's sources and `LICENSE`.
Other Fedora targets need libkrun >= 1.19 and < 2 in their repositories.
The package installs the command in `/usr/bin`, the guest helper in
`/usr/libexec`, and the example configuration in `/usr/share/agent-vm`.
User configuration remains opt-in; the example is not a system configuration file.

## Run commands

```sh
# Default: writable CWD, temporary home, no external networking.
./build/agent-vm run -- bash

# Inspect the effective configuration; environment values are omitted.
./build/agent-vm plan --network passt -e LANG

# Networking and a TCP port published on host loopback.
./build/agent-vm run --network passt -p 127.0.0.1:8080:8000/tcp \
  -- python3 -m http.server 8000 --bind 0.0.0.0

# Extra read-only data, a literal environment value, and SSH agent forwarding.
./build/agent-vm run --network passt \
  --mount "type=bind,src=$HOME/datasets,dst=/data,ro" \
  -e EDITOR=vi --ssh-agent -- bash

# Share home while hiding an existing .ssh subtree at every shared alias.
./build/agent-vm run --home shared --mask "$HOME/.ssh" -- bash
```

Use `--` before the command. Arguments, including spaces, quotes, empty strings and newlines, are passed literally. `-e NAME` inherits one defined host variable; `-e NAME=VALUE` assigns a value. Only `TERM`, `LANG` and `LC_ALL` are inherited by default. The guest receives generated `HOME`, `USER`, `LOGNAME`, `PATH` and `XDG_RUNTIME_DIR` values. Secrets are not printed by `plan`.

CWD is shared at its canonical absolute path. `--workdir` changes the guest working directory; `--cwd-mode ro|rw|none` changes the default CWD sharing policy. Additional mounts default to read-only. Duplicate mount targets are errors. Use TOML for source paths containing commas, which are separators in `--mount` syntax.

Nested mounts have independent modes: a writable child can sit under a read-only parent, and a read-only child under a writable parent. A parent's read-only setting covers its tree except for separately declared child mounts. Parents are installed before children regardless of configuration or CLI order. Each nested target must already exist in the nearest shared parent's source, match the child source's file/directory type, and contain no symlink components. Missing targets are errors; the runner never creates mountpoints inside host shares. For example, a read-only home mount can contain the default writable CWD mount.

Passt stdout and stderr are redirected to `/dev/null`, including in debug mode. Startup and unexpected-exit errors are reported by the supervisor.

`--network none` disables external networking and TSI. Guest-local loopback remains available. A fixed, explicit vsock control channel remains enabled for signals and terminal resizing. `--ssh-agent` separately authorizes a connection to the host SSH agent and sets a guest-local `SSH_AUTH_SOCK`; it works with either network mode.

The workload's exit status is returned. SIGINT, SIGTERM, SIGHUP and SIGQUIT sent to the supervisor are forwarded to the guest process group; SIGWINCH updates the guest terminal size. Unresponsive shutdown is forcibly terminated after five seconds. Terminal state is restored on normal supervisor exit and handled signals. No process can restore terminal state after an uncatchable SIGKILL; use `stty sane` if an external kill leaves a terminal in raw mode.

Before starting the VM and host helpers, `run` raises the host process's `RLIMIT_NOFILE` soft limit to its inherited hard limit. The VMM and helpers inherit it; this does not change the invoking shell's limits or the guest's limits.

## Configuration

The default file is `$XDG_CONFIG_HOME/agent-vm/config.toml`, or `~/.config/agent-vm/config.toml`. Project-local configuration is never loaded automatically. `--config FILE` selects a file; `--no-config` disables configuration loading.

See [examples/config.toml](examples/config.toml). CLI scalar settings and environment keys override the file; mounts and port publications are appended; masks are combined. Unknown fields are errors. Relative source paths in configuration are relative to that file; CLI source paths are relative to the invoking CWD. `~` expands to the invoking user's home. No shell expansion or command substitution is performed.

The generated `/etc` contains minimal account/NSS/host configuration. Timezone, CA certificates and the loader cache are imported from fixed system locations. Host `/etc/ld.so.conf` and the contents of `/etc/ld.so.conf.d/` are copied into the private root when present; symlinks to regular configuration files are copied as files. These are read-only private files. `/etc/resolv.conf` is a separate private writable mount for guest DHCP. The whole host `/etc` is never shared automatically.

## Isolation and supported boundaries

- The VMM enters its own user, mount, PID, IPC, UTS and network namespaces. It switches to the assembled root, closes unapproved file descriptors, clears all capabilities and uses a seccomp denylist. The supervisor re-execs the VMM with a clean environment/address space before confinement.
- UID/GID mapping contains only the invoking U/G. Guest initialization starts as guest root; the helper drops to U/G before running the command. Host root-owned files may display as an overflow UID. Supplementary group/ACL behavior is not promised to match the host; no subordinate UID ranges or root daemon are needed.
- `/usr`, the root skeleton and generated configuration are read-only on the host side. Home, `/tmp`, `/var/tmp` and `/run` are temporary filesystems; explicit writable shares modify host files. `--tmp-size` is a **per-filesystem** limit, not an aggregate memory or disk quota. VM vCPU/RAM settings do not impose a total host cgroup limit or shared-storage quota.
- A source `--mask` covers that subtree through each declared shared path. Existing filesystem bind aliases that could bypass the policy are conservatively rejected, including aliases of `/usr` and the private runtime. Target symlinks, missing mask paths under shared trees, and nested mounts requiring host directory creation are rejected. `--mask-target` applies to one guest target. `plan` previews configuration; mount identity and pinned-FD checks also run during actual launch.
- The **host is trusted**, as agreed in the design. Host-side renaming/replacing masked directories during a run is outside the guarantee. Masks do not hide copies or hardlinks already placed elsewhere. The guest cannot unmount host masks, and mountpoint-changing guest operations are constrained by the host mount namespace.
- Treat guest and VMM as one resource boundary. libkrun's export path is not a separate containment boundary. This version retains the VMM's private PID-namespace proc and exact KVM device inside its jail for libkrun. It does not claim they are inaccessible to a malicious guest using raw virtio-fs requests. It never shares the outer host proc or whole host `/dev` by default.
- Passt uses a connected socket, without a host TAP device. The first version supports one IPv4 NIC and TCP/UDP publications; IPv6, multiple NICs, full DHCP lease management and destination allowlists are not implemented. Passt networking can access host/LAN destinations available to its host context.
- SSH forwarding grants use of agent signing operations even when `.ssh` is masked. The bridge targets only the authorized socket; it does not provide arbitrary host-path RPC or transport `SCM_RIGHTS`. An internal bounded framing protocol preserves EOF and drains data across libkrun's vsock backend.

The runner is an initial implementation with integration coverage, not an independently audited sandbox. Run guest code only with the writable paths, environment variables, network access and SSH capability it should have.

## Tests

Unit and helper tests:

```sh
ctest --test-dir build --output-on-failure
```

Namespace and real VM acceptance tests, in an environment with KVM and namespace access:

```sh
./build/sandbox-test --integration
python3 tests/integration_core.py
python3 tests/integration_network.py
```

The integration tests use temporary homes/workspaces and local echo services. They do not use real SSH credentials or public services. The network tests retain their temporary logs on failure. A tool sandbox denial is an execution-environment restriction; run these tests outside that sandbox, rather than assuming the physical host lacks KVM.

The initial validation results and exact coverage are recorded in [tests/VALIDATION.md](tests/VALIDATION.md).

## Source map

| File | Responsibility |
| --- | --- |
| `src/config.cpp` | TOML, CLI, configuration validation and plan output |
| `src/sandbox.cpp` | Mount plan execution, namespace setup, UID mapping, mask and seccomp |
| `src/main.cpp` | Doctor, clean worker re-exec, libkrun configuration and lifecycle |
| `src/network.cpp` | Passt process and fixed-target host SSH broker |
| `guest/main.c` | Launch specification, guest identity, command supervision and control channel |
| `guest/relay.c` | Guest SSH agent socket bridge |
| `include/agent_vm/protocol.h` | Bounded launch/control/bridge formats |

## License

MIT; see [LICENSE](LICENSE).
