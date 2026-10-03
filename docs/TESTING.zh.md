[English](TESTING.md) · [返回 README](../README.zh.md)

# 测试指南

本文列出仓库中的测试入口与覆盖范围，不代表某次执行结果。构建命令与依赖见[开发指南](DEVELOPMENT.zh.md)。所有命令在仓库根目录执行。

## CTest 与宿主隔离测试

```sh
toolbox run cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
toolbox run cmake --build build
ctest --test-dir build --output-on-failure
./build/sandbox-test --integration
```

CTest 不启动真实 VM，但部分 confinement 测试会创建 namespaces，不能仅凭不需要 VM 就认为受限沙盒可以运行。sandbox integration 还需要可访问的 `/dev/kvm`。在具有依赖与权限的环境执行；依赖位于 toolbox 时，可使用 `toolbox run ctest ...` 等前缀。

| CTest 名称 | 覆盖范围 |
| --- | --- |
| `landlock` | 缺失降级／异常失败、文件读写／truncate 拒绝、既有 FD、supervisor 清理和 ABI 9 Unix socket 白名单；ABI 3 缺失返回 77 |
| `config` | CLI/TOML、profile、合并优先级、挂载/tmpfs/mask、环境变量、socket/D-Bus 策略 |
| `process-title` | 短名称与完整 title、原 argv/environment 保留、fork 隔离、转义与截断 |
| `dbus` | proxy readiness、lifetime FD、启动失败和回收；缺少 xdg-dbus-proxy 返回 77，CTest 记为跳过 |
| `wayland` | 宿主 waypipe 参数校验、transport readiness、隔离、GPU 模式选择和生命周期；缺少 waypipe 或 Landlock ABI 3 时返回 77 |
| `network` | passt 参数校验和 helper 生命周期 |
| `relay` | 使用 socketpair 测试原始字节 relay pump，包含半关闭 |
| `control` | 控制端点 inode 固定、符号链接拒绝、父目录替换与 rename 竞态 |
| `paths` | C/C++ 保留路径、规范化与包含关系对照 |
| `sandbox-seccomp` | 危险 syscall 和宿主 socket 地址族拒绝、线程兼容性 |

部分真实 VM socket 转发用例可能暴露 libkrun 1.x path mapping 的已知数据丢失问题；当前测试观察到 payload 尾部的 EOF sentinel 被截断。上游 PR 885 的修复计划 cherry-pick 到未来的 1.x 构建中；目前不指定修复版本。当前 Wayland 验证还曾在提交数个 surface 后因 virtiofs panic 以状态 125 退出。应记录这些失败，不应将受影响用例视为覆盖通过。

`sandbox-test --integration` 额外检查单 ID 映射、namespace、capabilities、只读与嵌套 ro/rw、mask/别名负测、tmpfs 覆盖、bootstrap、FD 清理、固定 socket endpoint，以及 direct/Waypipe IPC allowlist。

## 真实 VM 测试

执行环境必须具备 KVM、namespace 权限和相应运行依赖。Python 脚本默认使用 `build/agent-vm`，可用 `--binary /absolute/path/to/agent-vm` 覆盖。

```sh
python3 tests/integration_core.py
python3 tests/integration_network.py
python3 tests/integration_dbus.py
python3 tests/integration_wayland.py
python3 tests/integration_wayland.py --xwayland-satellite
python3 tests/integration_wayland.py --gpu-flags 963
python3 tests/integration_gpu.py --gpu-flags 0x10b
```

| 脚本 | 覆盖范围 |
| --- | --- |
| `integration_core.py` | argv/env、身份和文件 ownership、home、挂载/mask/tmpfs、只读策略、loopback、退出状态、pipe/PTY、信号、窗口变化、终端恢复、panic 设置 |
| `integration_network.py` | TCP/UDP 出站、IPv6 出站、端口发布、SSH agent 别名、验证 inode 固定和多连接的通用 socket、tmpfs 目标及已有目标拒绝 |
| `integration_dbus.py` | bus 过滤、user/system 独立开关、guest 地址、proxy 生命周期 |
| `integration_wayland.py` | 临时 Weston headless compositor；经 waypipe 重复连接 Wayland registry，映射 `xdg_toplevel` 窗口并提交 256×256、依赖 FD 的 `wl_shm` buffer，等待 frame callback；验证退出状态和 SIGTERM。使用 `--xwayland-satellite` 时还检查 guest `DISPLAY`，并通过 Xwayland 三次连接 X11、创建和映射窗口。使用 `--gpu-flags 963` 时还检查硬件 Venus 和经 DMA-BUF 的 30 帧 Wayland `vkcube` 渲染 |
| `integration_gpu.py` | guest virtio DRM render node 的所有权和 0666 mode、经 VirGL 的 GBM/EGL OpenGL 像素回读，并拒绝软件 renderer；可用 `--gpu-flags` 选择 GPU flag mask |

网络脚本支持单项运行：

```sh
python3 tests/integration_network.py --case sockets
python3 tests/integration_network.py --case ssh
```

其他 case 为 `outbound`、`outbound6`、`publish`。D-Bus 脚本需要 `dbus-daemon`；仅该程序位于 toolbox 时：

```sh
python3 tests/integration_dbus.py --daemon-prefix toolbox run
```

测试使用临时 home/workspace 和本地 TCP/UDP/Unix 服务，SSH stream 测试不使用真实凭据或公共服务。网络测试失败时保留临时日志。

默认 Wayland 测试启动一次性的 Weston headless compositor，不需要桌面会话、X11、GPU 或外部网络。执行环境需具备带 headless backend 的 `weston`、`/usr/bin/waypipe`、`libwayland-client.so.0`、guest `/usr/bin/python3`、KVM、Landlock ABI 3，以及运行 VM 所需的 namespace 权限。可选的 `--xwayland-satellite` 测试还需要执行环境和共享 guest `/usr` 中有 `xwayland-satellite`、`Xwayland` 和 `libX11.so.6`；它在常规退出及信号测试中验证三次 X11 窗口映射和重连。可选的 `--gpu-flags 963` 测试还需要宿主 render node、支持 GPU 的 libkrun、Weston GL renderer，以及执行环境和共享 guest `/usr` 中来自 `vulkan-tools` 的 `vkcube`、`vulkaninfo`。该测试检查硬件 Venus 和 30 帧 DMA-BUF Wayland 渲染；其他硬件或 flag mask 可能表现不同。已检查的可选依赖缺失时脚本返回 77；依赖齐备后的启动或协议失败会使测试失败。若这些包和构建后的程序位于 toolbox，可运行：

```sh
toolbox run python3 tests/integration_wayland.py
toolbox run python3 tests/integration_wayland.py --xwayland-satellite
toolbox run python3 tests/integration_wayland.py --gpu-flags 963
```

GPU 脚本不需要 compositor。它要求宿主 `/dev/dri/renderD*` 可访问、libkrun 支持 GPU、guest `/usr/bin/python3`、Mesa GBM/EGL/OpenGL 库、KVM 及 VM namespace 权限。默认使用原始 mask `0x10b`；可以用其他十进制／十六进制 uint32 mask 测试不同 libkrun 配置。`--gpu-flags 0` 虽是有效的启用请求，但可能在 VM 启动或渲染时失败。已检查的宿主依赖缺失时返回 77；VM 或渲染失败则判为失败。依赖位于 toolbox 时运行：

```sh
toolbox run python3 tests/integration_gpu.py --gpu-flags 0x10b
```

## 安装检查与故障定位

用私有目录检查可重定位安装：

```sh
toolbox run cmake --install build --prefix "$PWD/build/install-smoke"
./build/install-smoke/bin/agent-vm --version
./build/install-smoke/bin/agent-vm doctor
./build/install-smoke/bin/agent-vm run --no-config -- id
```

`doctor` 报告 KVM 不可见、设备权限和 namespace 限制。工具沙盒拒绝不等于物理宿主不支持 KVM；应在允许这些能力的执行环境检查。缺少动态库时也需区分构建容器与运行环境。

若日志出现 `VFS: Busy inodes after unmount` 或 `generic_shutdown_super` guest panic，检查 libkrunfw 所带 guest 内核的 virtiofs 卸载路径。`oops=panic panic=-1` 与失败状态预置只使异常及时退出，不修复内核缺陷；返回 125 或及时退出均不能记为测试通过。

验收时记录执行命令、依赖/内核环境、失败与跳过项。此测试集不等于完整安全审计，也不穷尽原始恶意 virtio-fs 请求、宿主 syscall 或资源耗尽行为。RPM 检查见[打包指南](PACKAGING.zh.md)。
