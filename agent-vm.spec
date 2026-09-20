%global forgeurl https://github.com/karuboniru/agent-vm
%global branch master
%forgemeta

Name:           agent-vm
Version:        0.1.0
Release:        1%{?dist}
Summary:        Rootless command runner using libkrun microVMs

License:        MIT
URL:            %{forgeurl}
Source0:        %{forgesource}

# Architectures supported by Fedora's libkrun and libkrunfw packages.
ExclusiveArch:  x86_64 aarch64
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  cmake >= 3.20
BuildRequires:  ninja-build
BuildRequires:  pkgconf-pkg-config
BuildRequires:  (pkgconfig(libkrun) >= 1.19 with pkgconfig(libkrun) < 2)
BuildRequires:  pkgconfig(libcap)
BuildRequires:  pkgconfig(libseccomp)
BuildRequires:  cmake(tomlplusplus)

# Launched with execve, so RPM's ELF dependency generator cannot detect it.
Requires:       passt

%description
agent-vm runs commands in rootless Linux microVMs using libkrun. It shares
the host's /usr read-only, assembles a temporary filesystem, and runs the
workload with the invoking user's numeric UID and GID. Networking through
passt and SSH agent forwarding are configurable. Running a VM requires
access to /dev/kvm and permission to create unprivileged user namespaces.

%prep
%forgeautosetup

%conf
# avm_core is an internal library, not an installed shared library.
# Build services need neither KVM nor namespace access to produce the RPM.
%cmake -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF

%build
%cmake_build

%install
%cmake_install

%files
%license LICENSE
%doc README.md ARCHITECTURE.md
%{_bindir}/agent-vm
%{_libexecdir}/agent-vm-guest
%{_datadir}/agent-vm/

%changelog
* Sun Sep 20 2026 Qiyu Yan <yanqiyu@fedoraproject.org> - 0.1.0-1
- Initial package
