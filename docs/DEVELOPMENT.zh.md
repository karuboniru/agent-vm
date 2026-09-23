[English](DEVELOPMENT.md) · [返回 README](../README.zh.md)

# 开发指南

## 依赖与环境

宿主代码使用 C++20，guest helper 使用 C17。构建需要 CMake >= 3.20、Ninja、pkg-config、libkrun >= 1.19 且 < 2、toml++、libcap、libseccomp，以及 C/C++ 编译器。运行需要 libkrun 固件，可选功能需要 passt 和 `/usr/bin/xdg-dbus-proxy`。

本地配置和编译必须在 `toolbox` 容器中执行。Fedora 容器内安装开发依赖：

```sh
toolbox run sudo dnf install gcc gcc-c++ cmake ninja-build pkgconf-pkg-config \
  libkrun-devel libkrunfw tomlplusplus-devel libcap-devel libseccomp-devel \
  passt xdg-dbus-proxy
```

VM 运行环境需要 `/dev/kvm` 可见且调用者可读写，允许无特权 user namespace 及 mount 操作，并支持 `openat2`、`pidfd_open`、`mount_setattr` 等 Linux 接口。LSM、容器和工具沙盒策略也必须允许这些操作。构建成功不代表当前执行环境具备 VM 运行权限。

## 构建与安装

在仓库根目录执行：

```sh
toolbox run cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
toolbox run cmake --build build
./build/agent-vm doctor
./build/agent-vm run --no-config -- id
```

指定容器时使用 `toolbox run --container <容器名> ...`。`doctor` 和 VM 命令应在具备运行依赖、KVM 与 namespace 权限的环境执行；如果该环境是 toolbox，也为运行命令加相同前缀。

可选用户安装：

```sh
toolbox run cmake --install build --prefix "$HOME/.local"
"$HOME/.local/bin/agent-vm" doctor
```

必须同时安装 `agent-vm` 和 `libexec/agent-vm-guest`；可执行文件支持按安装位置寻找 helper。示例配置安装到 `share/agent-vm/config.toml`，不会自动成为用户配置。RPM 布局与构建见[打包指南](PACKAGING.zh.md)。

## 源码分工

| 文件 | 职责 |
| --- | --- |
| `src/config.cpp` | TOML/CLI、路径与策略校验、plan 输出 |
| `include/agent_vm/spec.hpp` | 配置和运行规格 |
| `src/main.cpp` | doctor、worker re-exec、libkrun 配置、进程/TTY/信号生命周期 |
| `src/sandbox.cpp` | namespaces、UID 映射、挂载、mask、VMM seccomp |
| `src/network.cpp` | passt、D-Bus proxy、socket controller 与 stream 转发 |
| `src/socket_sandbox.cpp` | socket controller/data 的 namespace 与 seccomp 隔离 |
| `src/process_title.c` | 宿主/guest 进程名称与 title |
| `guest/main.c` | 启动协议、降权、命令监督与控制通道 |
| `guest/filesystem.c` | 挂载描述、tmpfs、共享对象和 guest 切根 |
| `guest/relay.c` | guest Unix stream listener 与 relay |
| `include/agent_vm/protocol.h` | 宿主/guest 启动、挂载、控制与 stream 协议 |

## 开发约定

- 本地构建统一走 toolbox，使用 CMake 的语言标准和 warning 设置。宿主用 RAII 管理 FD、子进程与清理；guest helper 保持 C 接口和小依赖面。
- 参数与环境按结构化格式传递，不拼接 shell；配置字段由 parser 明确校验，未知字段报错。`plan` 不执行挂载、不输出环境变量值。
- 文件访问授权在宿主 confinement 中实施。挂载、mask、FD、namespace 或 seccomp 改动需检查拒绝路径与资源清理，不仅检查正常运行。
- 宿主与 guest 共用的格式定义集中在 `protocol.h`。修改时同步生产者、消费者、大小限制和版本检查。
- 依据修改范围运行[测试指南](TESTING.zh.md)中的检查；真实 VM、namespace 和打包验证分别记录实际执行范围，不把跳过或环境拒绝写成通过。
- 文档只描述当前实现和限制。`.md` 为英文、同名 `.zh.md` 为中文，两者互链并同步维护；README 只保留用途、用法入口和总体设计，细节放入专题文档。
