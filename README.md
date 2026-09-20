# agent-vm

A rootless Linux command runner using libkrun. It shares the host's `/usr` read-only, assembles an FHS filesystem inside the guest, and runs a command in a microVM with the invoking user's numeric UID/GID.

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

# Add an empty, temporary filesystem owned by the invoking guest user.
./build/agent-vm run --tmpfs target=/cache --workdir /cache -- bash

# Forward a host Unix stream socket to a guest-local listener.
./build/agent-vm run \
  --socket "src=$XDG_RUNTIME_DIR/service.sock,dst=/run/service/client.sock" \
  -- bash
```

Use `--` before the command. Arguments, including spaces, quotes, empty strings and newlines, are passed literally. `-e NAME` inherits one defined host variable; `-e NAME=VALUE` assigns a value. Only `TERM`, `LANG` and `LC_ALL` are inherited by default. The guest receives generated `HOME`, `USER`, `LOGNAME`, `PATH` and `XDG_RUNTIME_DIR` values. Secrets are not printed by `plan`.

CWD is shared at its canonical absolute path. `--workdir` changes the guest working directory; `--cwd-mode ro|rw|none` changes the default CWD sharing policy. Additional bind mounts default to read-only. Duplicate mount targets are errors. Use TOML for source paths containing commas, which are separators in `--mount` syntax.

Nested bind mounts have independent modes: a writable child can sit under a read-only parent, and a read-only child under a writable parent. A parent's read-only setting covers its tree except for separately declared child mounts. Bind mounts and custom tmpfs mounts may be nested together, with parents installed before children regardless of configuration or CLI order. When the nearest enclosing mount is a bind mount, the nested target must match the child source's file/directory type and contain no symlink components. Missing targets are created at launch in writable bind sources; read-only bind sources require existing targets. When the nearest enclosing mount is a tmpfs, child mountpoints can be created privately. Created mountpoints in writable host shares persist after exit; configuration validation and `plan` do not create them. For example, a read-only home mount can contain the default writable CWD mount.

Repeat `--tmpfs target=/cache`, or add `[[tmpfs]]` entries with `target`, to mount additional guest-native tmpfs filesystems at absolute guest paths. Optional `uid` and `gid` default to the invoking user's numeric IDs; optional `mode` defaults to 0700. An explicit CLI entry is `--tmpfs target=/cache,uid=1000,gid=1000,mode=0750`; `dst` and `destination` are aliases for `target`, and CLI modes are octal. TOML uses integer values, for example `mode = 0o750`.

UID/GID values may range from 0 through 4294967294; 4294967295 (`UINT32_MAX`) is invalid. These are guest IDs: mount options set the tmpfs root's ownership and permissions without changing host ownership or the workload's identity. Explicit root ownership with mode 0700 makes the filesystem inaccessible to a non-root workload. Each tmpfs uses the existing `--tmp-size` / `[vm].tmp_mib` capacity limit and starts empty apart from child mountpoints and explicit child mounts. Its own contents disappear with the VM; writable bind children still write to their host sources.

Built-in guest filesystems are installed first, then bind mounts and custom tmpfs mounts are installed together from ancestors to descendants. A tmpfs can cover an existing directory inside a read-only share, provided no path component is a symlink. The host prepares a private staging tree for each custom tmpfs, creates child mountpoints there, installs explicit child mounts, and seals the staging skeleton read-only before export while preserving writable bind children. This hides the original covered subtree without modifying host source directories. The guest mounts its writable tmpfs and installs its children in the same order. `--workdir` can select a tmpfs root or a parent directory created to reach a child mount; other paths inside the empty filesystem are not created automatically.

Duplicate targets, including a bind and tmpfs at the same target, are errors. A tmpfs cannot replace or contain a built-in mount (`/tmp`, `/var/tmp`, `/run`, or home), or `/run/user/<uid>`. Protected system paths, `/.oldroot`, and overlap with masks are rejected. Descendants such as `/run/myapp` are allowed. Socket listeners may use a custom tmpfs, including one covering part of a read-only share. For a temporary GnuPG home with only the host public keyring exposed, combine a tmpfs at `~/.gnupg` with a read-only bind of `~/.gnupg/pubring.kbx`; [examples/config.toml](examples/config.toml) includes this optional configuration.

Passt stdout and stderr are redirected to `/dev/null`, including in debug mode. Startup and unexpected-exit errors are reported by the supervisor.

`--network none` disables external networking and TSI. Guest-local loopback remains available. A fixed, explicit vsock control channel remains enabled for signals and terminal resizing. Explicit socket forwarding works with either network mode.

Repeat `--socket src=SOURCE,dst=TARGET`, or add `[[sockets]]` entries with `source` and `target`, to forward filesystem Unix stream sockets. Sources must resolve to existing socket files; source symlinks are resolved to canonical paths. Targets must be absolute and are normalized. Source and target socket paths may contain at most 107 bytes; at most 256 forwards are supported, including the SSH agent alias. Duplicate targets are errors. Use TOML for paths containing commas, which separate CLI fields.

Targets must lie on a writable guest filesystem, such as `/run`, `/tmp`, `/var/tmp`, ephemeral home, a custom tmpfs, or an explicit writable share. The guest root skeleton remains read-only. Before dropping privileges, the guest helper creates missing parent directories with mode 0700 and assigns them to the guest UID/GID. Existing parent directories keep their ownership and permissions; the immediate parent must allow the guest user to create the socket. For example, use `/run/custom/service.sock` with a new `custom` directory, rather than binding directly in root-owned `/run`. The relay then listens as the guest user with socket mode 0600; an existing destination is an error and is never replaced. Socket creation follows the innermost mount: a writable bind changes its host source, while a tmpfs keeps the directories and socket file in the guest.

`--ssh-agent` (or `[ssh_agent].enabled = true`) is an alias for forwarding the host `SSH_AUTH_SOCK` to `/run/user/<uid>/ssh-agent.socket` and setting the guest `SSH_AUTH_SOCK` to that path. `--no-ssh-agent` disables only this alias, leaving explicit socket forwards intact. With the alias disabled, a custom forward can be paired with an explicit environment value, for example `--socket "src=$SSH_AUTH_SOCK,dst=/run/custom/agent.sock" -e SSH_AUTH_SOCK=/run/custom/agent.sock`.

D-Bus forwarding requires `/usr/bin/xdg-dbus-proxy`. Configure each bus independently:

```toml
[dbus.user]
enabled = true
args = ["--talk=org.freedesktop.Notifications"]

[dbus.system]
enabled = true
args = ["--call=org.freedesktop.UPower=org.freedesktop.DBus.Properties.GetAll@/org/freedesktop/UPower"]
```

Both default to disabled. Optional `address` selects a host D-Bus address; otherwise the host's `DBUS_SESSION_BUS_ADDRESS` / `DBUS_SYSTEM_BUS_ADDRESS` is used. User bus fallback is `$XDG_RUNTIME_DIR/bus` (requires that variable); system bus fallback is `/run/dbus/system_bus_socket`. Addresses are D-Bus address strings, without shell or tilde expansion.

The runner always supplies `--filter`. `args` passes literal per-bus options: `--see=`, `--talk=`, `--own=`, `--call=`, `--broadcast=`, `--log`, `--sloppy-names`, and optional redundant `--filter`. See the [xdg-dbus-proxy manual](https://github.com/flatpak/xdg-dbus-proxy/blob/main/xdg-dbus-proxy.xml) for rule syntax. Empty rules retain the proxy's baseline bus operations only. Process-control options (`--fd`, `--args`), extra address/path pairs and unknown options are rejected. Invalid rule syntax is reported by the proxy at startup.

Each enabled bus gets its own host proxy, readiness handshake and socket broker. The guest receives `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/<uid>/dbus-user.socket` and/or `DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/user/<uid>/dbus-system.socket`. Conflicting explicit environment settings and socket targets are errors. These channels count toward the socket limit and work with networking disabled. `plan` shows enabled buses and filter arguments without launching helpers. Proxy exit terminates the VM; shutdown stops proxies and removes the private runtime sockets.

D-Bus forwarding uses the existing byte-stream relay: **Unix FD passing is unsupported**, so methods requiring file descriptors (including many portal APIs) are not supported. The proxy authenticates upstream as the invoking host user. Filtering controls access within that user's existing bus permissions.

The workload's exit status is returned. SIGINT, SIGTERM, SIGHUP and SIGQUIT sent to the supervisor are forwarded to the guest process group; SIGWINCH updates the guest terminal size. Unresponsive shutdown is forcibly terminated after five seconds. Terminal state is restored on normal supervisor exit and handled signals. No process can restore terminal state after an uncatchable SIGKILL; use `stty sane` if an external kill leaves a terminal in raw mode.

Before starting the VM and host helpers, `run` raises the host process's `RLIMIT_NOFILE` soft limit to its inherited hard limit. The VMM and helpers inherit it; this does not change the invoking shell's limits or the guest's limits.

## Configuration

The default file is `$XDG_CONFIG_HOME/agent-vm/config.toml`, or `~/.config/agent-vm/config.toml`. Project-local configuration is never loaded automatically. `--config FILE` selects a file; `--no-config` disables configuration loading.

See [examples/config.toml](examples/config.toml). CLI scalar settings and environment keys override the file; bind mounts, tmpfs mounts, socket forwards and port publications are appended; masks are combined. Unknown fields are errors. Relative mount and socket source paths in configuration are relative to that file; CLI source paths are relative to the invoking CWD. `~` expands to the invoking user's home. No shell expansion or command substitution is performed.

The generated `/etc` contains minimal account/NSS/host configuration. Timezone, CA certificates and the loader cache are imported from fixed system locations. Host `/etc/ld.so.conf` and the contents of `/etc/ld.so.conf.d/` are copied into the private root when present; symlinks to regular configuration files are copied as files. These are read-only private files. `/etc/resolv.conf` is a separate private writable mount for guest DHCP. The whole host `/etc` is never shared automatically. Explicit file and directory binds below `/etc` are supported, for example `--mount src=/etc/machine-id,dst=/etc/machine-id,ro`; their configured `ro`/`rw` modes apply. Replacing `/etc` itself or `/etc/resolv.conf` is prohibited.

The host prepares a confined object catalog and a bounded binary mount description. Two virtio-fs devices expose a minimal bootstrap root (`/dev/root`) and the catalog (`/.agent-vm/exports`). The guest helper reads the description, creates built-in native tmpfs filesystems, then installs bind mounts and custom tmpfs mounts together from ancestors to descendants. It preserves the guest's proc/sys/dev mounts and pivots into the final root before dropping privileges. Catalog staging and the old bootstrap root are detached from the workload's mount namespace. Full target paths live in the description, so long paths and additional mounts do not consume more device tags or IRQs.

## Isolation and supported boundaries

- The VMM enters its own user, mount, PID, IPC, UTS and network namespaces. It switches to the assembled root, closes unapproved file descriptors, clears all capabilities and uses a seccomp denylist. The supervisor re-execs the VMM with a clean environment/address space before confinement.
- UID/GID mapping contains only the invoking U/G. Guest initialization starts as guest root; the helper drops to U/G before running the command. Host root-owned files may display as an overflow UID. Supplementary group/ACL behavior is not promised to match the host; no subordinate UID ranges or root daemon are needed.
- `/usr`, the host policy skeleton and generated configuration are read-only on the host side. The guest root skeleton is a read-only native tmpfs; ephemeral home, `/tmp`, `/var/tmp`, `/run` and custom tmpfs mounts use the VM's RAM budget without virtio-fs I/O. Writes to explicit writable bind mounts modify their host sources, including bind children inside a tmpfs; writes to the tmpfs itself remain guest-local. `--tmp-size` is a **per-filesystem** limit, not a reservation or aggregate quota; concurrent tmpfs use and processes compete for guest RAM. VM vCPU/RAM settings do not impose a total host cgroup limit or shared-storage quota.
- A source `--mask` covers that subtree through each declared shared path. Existing filesystem bind aliases that could bypass the policy are conservatively rejected, including aliases of `/usr` and the private runtime. Target symlinks, missing mask paths under shared trees, and nested mounts requiring directory creation in read-only shares are rejected. `--mask-target` applies to one guest target. `plan` previews configuration; mount identity and pinned-FD checks also run during actual launch.
- Every catalog object comes from the final host policy tree, after child mounts, read-only attributes and masks have been installed. The VMM itself cannot bypass these policies through an unmasked export or an original source FD. Guest mount instructions determine layout; they do not grant additional host filesystem access.
- The **host is trusted**, as agreed in the design. Host-side renaming/replacing masked directories during a run is outside the guarantee. Masks do not hide copies or hardlinks already placed elsewhere. The guest cannot unmount host masks, and mountpoint-changing guest operations are constrained by the host mount namespace.
- Treat guest and VMM as one resource boundary. libkrun's export path is not a separate containment boundary. This version retains the VMM's private PID-namespace proc and exact KVM device inside its jail for libkrun. It does not claim they are inaccessible to a malicious guest using raw virtio-fs requests. It never shares the outer host proc or whole host `/dev` by default.
- Passt uses a connected socket, without a host TAP device. The first version supports one IPv4 NIC and TCP/UDP publications; IPv6, multiple NICs, full DHCP lease management and destination allowlists are not implemented. Passt networking can access host/LAN destinations available to its host context.
- Socket forwarding grants the guest access to the authorized host service's capabilities. SSH forwarding grants agent signing operations even when `.ssh` is masked. Each bridge connects only to its configured host socket through a fixed authorized vsock port; it does not provide arbitrary host-path RPC. Only filesystem Unix stream byte transport is supported, without datagrams, abstract sockets or `SCM_RIGHTS` file descriptor passing. An internal bounded framing protocol preserves EOF and drains data across libkrun's vsock backend.

The runner is an initial implementation with integration coverage, not an independently audited sandbox. Run guest code only with the writable paths, environment variables, network access and host socket capabilities it should have.

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
# Requires dbus-daemon; add --daemon-prefix toolbox run if installed there.
python3 tests/integration_dbus.py
```

The integration tests use temporary homes/workspaces and local echo services. They do not use real SSH credentials or public services. The network tests retain their temporary logs on failure. A tool sandbox denial is an execution-environment restriction; run these tests outside that sandbox, rather than assuming the physical host lacks KVM.

The initial validation results and exact coverage are recorded in [tests/VALIDATION.md](tests/VALIDATION.md).

## Source map

| File | Responsibility |
| --- | --- |
| `src/config.cpp` | TOML, CLI, configuration validation and plan output |
| `src/sandbox.cpp` | Mount plan execution, namespace setup, UID mapping, mask and seccomp |
| `src/main.cpp` | Doctor, clean worker re-exec, libkrun configuration and lifecycle |
| `src/network.cpp` | Passt process and fixed-target host socket brokers |
| `guest/main.c` | Launch specification, guest identity, command supervision and control channel |
| `guest/filesystem.c` | Mount description validation, native tmpfs, shared objects and guest root switch |
| `guest/relay.c` | Guest Unix stream socket bridges |
| `include/agent_vm/protocol.h` | Bounded launch/control/bridge formats |

## License

MIT; see [LICENSE](LICENSE).
