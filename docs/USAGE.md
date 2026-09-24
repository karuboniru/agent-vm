[中文](USAGE.zh.md) · [README](../README.md)

# Usage guide

## Commands and defaults

```sh
agent-vm [run|plan] [OPTIONS] [-- COMMAND [ARG...]]
agent-vm doctor
agent-vm --help
agent-vm --version
```

`run` starts a VM, using `/bin/sh` if no command is supplied. `plan` validates and displays the effective configuration without starting a VM or creating mountpoints. `doctor` checks dependencies, KVM, and namespace support. Use `--` before the command. Spaces, quotes, empty strings, and newlines in arguments are passed literally, without shell concatenation.

These defaults apply without a configuration file or explicit overrides:

| Option | Default and purpose |
| --- | --- |
| `--cpus N` | 2 vCPUs |
| `--memory MiB` | 2048 MiB guest RAM |
| `--tmp-size MiB` | 256 MiB capacity per guest tmpfs |
| `--cwd-mode ro|rw|none` | `rw`, sharing CWD at its canonical absolute path |
| `--home ephemeral|shared` | `ephemeral`, an empty temporary home |
| `--workdir PATH` | CWD, or home when CWD sharing is disabled |
| `--network none|passt` | `none`, no external networking |
| `--ssh-agent` / `--no-ssh-agent` | SSH agent forwarding is disabled |
| `--debug` | Runtime diagnostics are disabled |

`--tmp-size` is a per-filesystem capacity limit, not a reservation or aggregate quota. Tmpfs and processes compete for guest RAM. vCPU/RAM settings do not limit total host resource use or disk consumption in writable shares.

## Configuration loading and merging

The default file is `$XDG_CONFIG_HOME/agent-vm/config.toml`, falling back to `~/.config/agent-vm/config.toml` when `XDG_CONFIG_HOME` is unset, empty, or relative. A missing default file uses built-in defaults. Project-local configuration is never loaded automatically.

- `--config FILE` loads an explicit file.
- `--profile NAME` loads `NAME.toml` from the same user configuration directory, replacing rather than merging with `config.toml`. The name must be nonempty without path components, and the file must exist.
- `--no-config` disables configuration loading. These three options are mutually exclusive.

CLI scalar settings override the file; environment variables override by name. Bind, tmpfs, socket, and port lists append; masks are combined and deduplicated. Unknown fields are errors. Relative filesystem paths in both TOML and CLI options resolve against the host working directory when invoking `agent-vm`. This applies to mount and socket sources/targets, tmpfs targets, `filesystem.workdir`, `mask_sources`, `mask_try_sources`, and `mask_targets`, as well as `--config FILE`. Changing guest `workdir` does not change this base. Host sources resolve symlinks; guest targets are normalized lexically. D-Bus addresses and environment values remain literal strings. `~` expands to the invoking user's home; no shell expansion or command substitution is performed. See [config.toml](../examples/config.toml) for the full example.

```toml
version = 1

[vm]
cpus = 2
memory_mib = 2048
tmp_mib = 256

[filesystem]
cwd = "rw"
home = "ephemeral"

[[mounts]]
source = "~/datasets"
target = "/data"
mode = "ro"

[[tmpfs]]
target = "/cache"
mode = 0o700

[environment.set]
EDITOR = "vi"

[network]
mode = "none"
```

## File sharing and temporary storage

```sh
agent-vm run --no-config \
  --mount "type=bind,src=$HOME/datasets,dst=/data,ro" \
  --tmpfs target=/cache,mode=0750 --workdir /cache -- bash
```

Repeat `--mount` for multiple shares; read-only is the default, and `rw` changes the host source directly. CLI fields are comma-separated; use TOML for source paths containing commas. CWD reuses a mount with the same source and target, preserving its permissions, and also reuses the built-in `/usr` tree. `--cwd-mode ro` does not downgrade an explicit `rw` mount, or vice versa. Default CWD sharing replaces a conflicting bind or tmpfs at its target; other duplicate mount targets are errors.

Bind and tmpfs mounts are installed together, parents before children, regardless of declaration order. Bind modes are independent: writable children can sit under read-only parents. Beneath a bind, target components cannot be symlinks and file/directory types must match. Read-only parents require existing mountpoints; writable parents allow creation at launch, leaving those paths on the host. Beneath tmpfs, child mountpoints are created privately.

Mounts may use paths beneath `/run`, `/tmp`, `/var/tmp`, `/mnt`, and `/media`, as well as `/etc` and `/usr` subpaths. Targets under the implicit read-only `/usr` must exist; covering an existing directory with tmpfs or a writable bind allows new child mountpoints inside it. `/proc`, `/sys`, `/dev`, FHS aliases, internal bootstrap paths, all of `/etc`, `/etc/resolv.conf`, and protected runtime paths cannot be replaced. Custom tmpfs cannot equal or contain built-in `/tmp`, `/var/tmp`, `/run`, home, or `/run/user/<uid>`, or overlap masks.

`--tmpfs target=PATH[,uid=UID,gid=GID,mode=0700]` creates an empty guest tmpfs; `dst` and `destination` alias `target`. TOML uses `[[tmpfs]]` with `target` and optional integer `uid`, `gid`, and `mode`. UID/GID default to the caller and range from 0 to 4294967294. Mode defaults to 0700; CLI modes are octal, and TOML accepts `0o750`. These options set guest root-directory ownership, without changing workload identity or host ownership. Root ownership with mode 0700 prevents a non-root command from accessing it.

Tmpfs can cover an existing directory in a read-only share, hiding that subtree without modifying the host. Explicit `rw` bind children still modify their host sources. Tmpfs contents disappear on exit. `--workdir` can select a tmpfs root or a parent created for a child mount; other working directories are not created automatically. The example configuration includes a temporary GnuPG home with a read-only public keyring.

## Path masks

`--mask SOURCE` / `[filesystem].mask_sources` hides a host source subtree through every shared alias. `--mask-target TARGET` / `mask_targets` hides one guest target. For example, `[filesystem]` with `mask_sources = [".git"]` hides `.git` in the invoking working directory, allowing the same user configuration to apply to different projects. Missing mask paths inside shared trees are errors; masking does not create host placeholders.

`--mask-try SOURCE` / `[filesystem].mask_try_sources` applies the same source mask only when the path exists at configuration parsing time. Missing paths (including dangling symlinks) are ignored; other filesystem errors and normal mask conflicts still fail. Existing paths are merged with `mask_sources` and deduplicated. Skipped paths are not watched for later creation. For a reusable project policy:

```toml
[filesystem]
mask_try_sources = [".git", ".env"]
```

```sh
# .ssh must exist; share home while hiding its .ssh directory.
agent-vm run --no-config --home shared --mask "$HOME/.ssh" -- bash

# An explicit descendant share can be an exception to a source mask.
agent-vm run --no-config --home shared --mask "$HOME/.ssh" \
  --mount "src=$HOME/.ssh/known_hosts,dst=/keys/known_hosts,ro" -- bash
```

The same source or target cannot be both shared and masked. Explicit descendant exceptions to a source mask remain visible when a target mask also covers their masked ancestor or an intermediate ancestor. Sharing a parent does not cancel masks of its children. Other masked contents remain hidden. Rules do not depend on CLI order.

Launch also checks mount identities and bind aliases, rejecting aliases that could bypass policy. Masks protect paths, not hardlinks or copies elsewhere, and do not defend against the host replacing source paths during a run. See [security boundaries](ARCHITECTURE.md).

## Environment

`-e NAME` inherits a defined host variable, rejecting missing names; `-e NAME=VALUE` sets a literal value. By default, only existing `TERM`, `LANG`, and `LC_ALL` are inherited, alongside generated `HOME`, `USER`, `LOGNAME`, `PATH`, and `XDG_RUNTIME_DIR`. TOML uses `[environment].inherit` and `[environment.set]`. `plan` displays names but omits values. Workload variables reach the command after guest privilege dropping, without entering privileged initialization.

## Networking and ports

```sh
agent-vm run --no-config --network passt \
  -p 127.0.0.1:8080:8000/tcp -- python3 -m http.server 8000 --bind 0.0.0.0
```

`--network none` disables external networking and TSI; guest loopback, fixed control channels, and explicit socket forwarding remain available. `passt` provides one NIC with outbound IPv4/IPv6 where the host supports them. It can reach host/LAN destinations available to its host context, without a destination allowlist.

`-p` / `--publish` uses `[IPv4:]HOST:GUEST[/tcp|udp]`, defaulting to `127.0.0.1` and TCP; publishing requires passt. Undeclared TCP/UDP ports are not published. IPv6 publication addresses, multiple NICs, and full DHCP lease renewal management are unsupported. Passt stdout/stderr go to `/dev/null`, including debug mode; the supervisor reports startup and unexpected-exit errors.

## Unix sockets and SSH agents

```sh
agent-vm run --no-config \
  --socket "src=$XDG_RUNTIME_DIR/service.sock,dst=/run/service/client.sock" -- bash
agent-vm run --no-config --network passt --ssh-agent -- bash
```

Repeat `--socket`, or use `[[sockets]]` with `source` and `target`. Sources must be existing filesystem Unix stream sockets; source symlinks resolve to canonical paths. Relative targets use the invoking host working directory. Each source/target path is limited to 107 bytes, with at most 256 forwards including SSH/D-Bus. Conflicting targets are errors; use TOML for comma-containing paths.

Targets must reside on writable guest filesystems. The helper creates missing parents with caller ownership and mode 0700. Existing directories retain permissions; the immediate parent must allow the caller to create the socket. Use a private subdirectory such as `/run/service/client.sock`, avoiding creation directly in root-owned `/run`. Listeners run as the caller with socket mode 0600 and never replace existing targets. Directories and sockets inside `rw` binds modify the host; those in tmpfs remain guest-private.

`--ssh-agent` forwards the host `SSH_AUTH_SOCK` to `/run/user/<uid>/ssh-agent.socket` and sets the guest variable. `--no-ssh-agent` disables only this alias, leaving explicit forwards active. Custom forwarding can use `-e SSH_AUTH_SOCK=...`. Agent forwarding grants signing operations even when `.ssh` is masked.

Only byte streams are supported, without Unix datagrams, abstract sockets, or `SCM_RIGHTS` FD passing. Reconnection follows socket replacement inside the same host parent directory, but does not track replacement of that directory itself.

## D-Bus

Requires `/usr/bin/xdg-dbus-proxy`. Both buses are independently configured and disabled by default:

```toml
[dbus.user]
enabled = true
args = ["--talk=org.freedesktop.Notifications"]

[dbus.system]
enabled = true
args = ["--talk=org.freedesktop.UPower"]
```

Optional `address` is a literal D-Bus address, without shell or tilde expansion. Otherwise the host `DBUS_SESSION_BUS_ADDRESS` / `DBUS_SYSTEM_BUS_ADDRESS` is used, then `$XDG_RUNTIME_DIR/bus` (requiring that variable) or `/run/dbus/system_bus_socket`, respectively.

`--filter` is mandatory. `args` accepts `--see=`, `--talk=`, `--own=`, `--call=`, `--broadcast=`, `--log`, `--sloppy-names`, and redundant `--filter`. Process-control options, extra addresses/paths, and unknown options are rejected; the proxy reports malformed rules at startup. Empty rules retain only the proxy's baseline bus operations.

Guest addresses are `unix:path=/run/user/<uid>/dbus-user.socket` and `unix:path=/run/user/<uid>/dbus-system.socket`, assigned to their respective environment variables. Conflicting explicit variables or socket targets are errors. `plan` displays filters without starting proxies; unexpected proxy exit terminates the VM. Proxies authenticate upstream as the caller, with filtering constrained by that user's bus permissions. Unix FD passing is unsupported, so methods requiring FDs, including many portal APIs, are unavailable.

## Exit and diagnostics

The workload's exit status is returned; runner errors generally use 125. SIGINT, SIGTERM, SIGHUP, and SIGQUIT are forwarded to the guest process group; SIGWINCH updates terminal size. Unresponsive shutdown is forcibly terminated after five seconds. Normal exit and handled signals restore the terminal; use `stty sane` if SIGKILL leaves it in raw mode.

Before launching the VM/helpers, `run` raises its host `RLIMIT_NOFILE` soft limit to the inherited hard limit, without changing the invoking shell or guest limits. `--debug` provides runtime-path and lifecycle diagnostics. See the [testing guide](TESTING.md) for checks and troubleshooting.
