# agent-vm

[中文](README.zh.md)

agent-vm runs commands in rootless Linux microVMs using libkrun, for coding agents, development tools, and tasks that need isolation. It reuses the host toolchain without requiring a system image. Commands use the invoking user's numeric UID/GID, and changes in shared working directories persist on the host.

## Usage

Running a VM requires access to `/dev/kvm`, unprivileged user namespaces, and libkrun 1.x (>= 1.19) with its firmware. Networking requires `passt`; D-Bus forwarding requires `xdg-dbus-proxy`. See the [development guide](docs/DEVELOPMENT.md) for source installation and the [packaging guide](docs/PACKAGING.md) for RPM builds.

```sh
agent-vm doctor

# Ignore user configuration: writable CWD, temporary home, no external network.
agent-vm run --no-config -- bash

# Preview permissions and configuration; environment values are omitted.
agent-vm plan --no-config --network passt

# Enable networking and publish the guest HTTP service on host loopback.
agent-vm run --no-config --network passt -p 127.0.0.1:8080:8000/tcp \
  -- python3 -m http.server 8000 --bind 0.0.0.0
```

The default configuration is `$XDG_CONFIG_HOME/agent-vm/config.toml`, or `~/.config/agent-vm/config.toml`. `--profile NAME` selects `NAME.toml` in that directory; `--config FILE` selects an explicit file. See [examples/config.toml](examples/config.toml) and the [usage guide](docs/USAGE.md) for mounts, environment variables, masks, SSH agents, and D-Bus forwarding.

## Design overview

- Reuse the host `/usr` read-only, alongside a minimal `/etc`, explicit shares, and temporary filesystems in guest memory. The default working directory is shared; home is temporary.
- Treat the guest and VMM as one security boundary and confine the VMM as far as possible: separate namespaces, a restricted filesystem tree, removal of unnecessary FDs and capabilities, and a seccomp policy. Read-only and mask policies are enforced on the host.
- Provide optional networking through `passt`, and optional Unix socket, SSH agent, and filtered D-Bus forwarding through brokers with fixed upstream targets.
- A C++20 host supervisor manages processes, terminal state, signals, and exit status. A C17 guest helper assembles the filesystem, drops privileges, and starts the command.

Writable shares modify host files; forwarded sockets grant the corresponding service capabilities. The host and its filesystem changes during a run are trusted. The project has no independent security audit. See [architecture and security boundaries](docs/ARCHITECTURE.md) for the detailed scope and limits.

## Documentation

| Guide | Contents |
| --- | --- |
| [Usage](docs/USAGE.md) | CLI, configuration, file sharing, networking, and IPC |
| [Architecture and security boundaries](docs/ARCHITECTURE.md) | Process confinement, filesystem assembly, protocols, and capabilities |
| [Development](docs/DEVELOPMENT.md) | Toolbox builds, installation, source map, and conventions |
| [Testing](docs/TESTING.md) | Test entry points, coverage, and execution requirements |
| [Packaging](docs/PACKAGING.md) | Fedora RPM builds, installation layout, and checks |

License: [MIT](LICENSE).
