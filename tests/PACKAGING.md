# Fedora RPM validation

Validated on 2026-09-20 using mock 6.8 and `fedora-45-x86_64`, with the
`agent-vm` unique extension. The source was downloaded from the spec's URL:

https://github.com/karuboniru/agent-vm/archive/master/agent-vm-master.tar.gz

- Source revision: `5f209127382e97cfa17356ccd9bca478c5080faa`.
- Tarball SHA-256: `acb94307e01e51c6ff7835423327a1d1595bda5ff2d49aff7770fecedaedf252`.
- Package version: `0.1.0-1.20260920gitmaster.fc45`.
- Both `mock --buildsrpm` and `mock --rebuild` succeeded.
- Produced the source RPM, main x86_64 RPM, debuginfo and debugsource RPMs.

The README documents the build commands. Local artifacts and full build logs
are in the ignored `build-rpm/result/` directory. This records a specific
snapshot; downloading the moving `master` URL later may produce different bytes.

## Package inspection

The main package contains `/usr/bin/agent-vm`, `/usr/libexec/agent-vm-guest`,
the example configuration under `/usr/share/agent-vm`, documentation, and the
MIT license under `/usr/share/licenses/agent-vm`. It contains no development
headers or internal core library. Debug information is in separate packages.

RPM generated dependencies for libkrun.so.1, libcap, libseccomp, toml++, the
C/C++ runtimes, and their required symbol versions. `passt` is the explicit
runtime dependency. Installing the RPM in mock resolved passt and the
libkrun/libkrunfw dependency chain (libkrun 1.19.0, libkrunfw 5.5.0).

Both executables are PIE with non-executable stacks, GNU_RELRO and BIND_NOW.
Neither has an RPATH or RUNPATH. The build used Fedora's default compiler and
linker flags, including LTO and hardening flags.

## Installed smoke checks

After `mock --install` of the main RPM:

- `rpm -V agent-vm` passed.
- `agent-vm --version` printed `agent-vm 0.1.0`.
- `agent-vm --help` succeeded.
- As the unprivileged mockbuild user, from `/builddir`,
  `agent-vm plan --no-config --network passt -- /usr/bin/true` succeeded.
- The installed guest helper was executable; the license and example
  configuration were readable.

No VM was started, and no KVM or namespace integration tests were run.
Only x86_64 was built; aarch64 is permitted by the spec but was not tested here.

## rpmlint

rpmlint 2.9.0 checked the spec and all four RPMs. Its 15 reported errors were
dictionary false positives for `libkrun`, `microVMs`, `usr`, `passt`, `dev`,
and `kvm`. The four warnings were the absent man page, the deliberately omitted
`%check` section (reported twice), and the forge-generated snapshot release
suffix differing from the initial changelog's `0.1.0-1`. These diagnostics were
not suppressed; rpmlint was not a clean pass. No file-layout, shared-library,
license, or debug-package errors were reported.
