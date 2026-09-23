[中文](PACKAGING.zh.md) · [README](../README.md)

# Fedora RPM packaging guide

## Package definition and dependencies

`agent-vm.spec` uses Fedora forge/CMake macros, distribution compiler/linker hardening flags, and automatic ELF dependencies. Listed architectures are x86_64 and aarch64; target repositories must provide libkrun >= 1.19 and < 2 plus other BuildRequires.

The internal core library is linked statically into the command; development libraries and headers are not installed. The spec sets `BUILD_TESTING=OFF`, so RPM builds require neither KVM nor user namespaces. `passt` is an explicit runtime dependency, `xdg-dbus-proxy` is recommended, and firmware comes through libkrun's package dependency chain. Building a package does not validate VM execution on that architecture.

## Build

Local builds use toolbox. `mock` additionally requires an environment supporting its container/privilege mechanisms and configuration for the caller. This example uses `fedora-45-x86_64`, fresh temporary output directories, and the committed checkout as its source:

```sh
rpm_work=$(mktemp -d "$PWD/build-rpm.XXXXXX")
mkdir -p "$rpm_work/sources" "$rpm_work/srpm" "$rpm_work/result"
git archive --format=tar.gz --prefix=agent-vm-master/ HEAD \
  > "$rpm_work/sources/agent-vm-master.tar.gz"
toolbox run mock -r fedora-45-x86_64 --uniqueext=agent-vm --buildsrpm \
  --spec "$PWD/agent-vm.spec" --sources "$rpm_work/sources" \
  --resultdir "$rpm_work/srpm"
toolbox run mock -r fedora-45-x86_64 --uniqueext=agent-vm --rebuild \
  "$rpm_work"/srpm/agent-vm-*.src.rpm --resultdir "$rpm_work/result"
toolbox run rpmlint agent-vm.spec "$rpm_work"/result/*.rpm
```

`git archive HEAD` excludes uncommitted changes. Archive prefixes and filenames must match the spec's forge metadata, and sources must include `LICENSE` and all documentation. The spec defaults to the moving `master` branch; pin a commit or tag and update forge metadata for fixed distribution-build inputs. Keep only this build's artifacts in the SRPM directory so the wildcard does not select multiple versions.

Direct source builds also require toolbox; see the [development guide](DEVELOPMENT.md).

## Installed layout

| Path | Contents |
| --- | --- |
| `/usr/bin/agent-vm` | Main command |
| `/usr/libexec/agent-vm-guest` | Guest helper |
| `/usr/share/agent-vm/config.toml` | Example configuration, not loaded automatically |
| RPM documentation directory | Bilingual READMEs, `docs/`, examples, and a LICENSE copy for links |
| RPM license directory | MIT LICENSE |

## Package checks

```sh
toolbox run rpm -qpl "$rpm_work"/result/agent-vm-[0-9]*.rpm
toolbox run rpm -qp --requires "$rpm_work"/result/agent-vm-[0-9]*.rpm
```

Check main-package layout, dependency resolution, bilingual documentation, and relative links, ensuring internal libraries and development headers are absent. Use `readelf` to inspect both ELFs for PIE, non-executable stacks, RELRO/BIND_NOW, and unexpected RPATH/RUNPATH; check debug packages against their sources. Inspect each `rpmlint` error/warning instead of reporting nonzero results as passes.

In a separate installation environment:

```sh
rpm -V agent-vm
agent-vm --version
agent-vm --help
agent-vm plan --no-config --network passt -- /usr/bin/true
```

These checks do not start a VM. With KVM and namespace permissions, also run `agent-vm doctor` and `agent-vm run --no-config -- id`; see the [testing guide](TESTING.md) for real VM tests. This guide describes packaging and checks, without treating one snapshot's results as guarantees for all builds.
