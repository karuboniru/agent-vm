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

CTest 不启动真实 VM，但 network/socket-sandbox 测试会创建 namespaces，不能仅凭不需要 VM 就认为受限沙盒可以运行。sandbox integration 还需要可访问的 `/dev/kvm`。在具有依赖与权限的环境执行；依赖位于 toolbox 时，可使用 `toolbox run ctest ...` 等前缀。

| CTest 名称 | 覆盖范围 |
| --- | --- |
| `config` | CLI/TOML、profile、合并优先级、挂载/tmpfs/mask、环境变量、socket/D-Bus 策略 |
| `process-title` | 短名称与完整 title、原 argv/environment 保留、fork 隔离、转义与截断 |
| `dbus` | proxy readiness、lifetime FD、启动失败和回收；缺少 xdg-dbus-proxy 返回 77，CTest 记为跳过 |
| `network` | 并发 stream、背压、半关闭、帧校验、重连、共享 controller、data 进程复用及故障清理 |
| `socket-sandbox` | controller/data 文件树与 syscall 边界、独立 PID namespace、锁定子挂载和 socket bind |
| `sandbox-seccomp` | 危险 syscall 拒绝及线程兼容性 |

`sandbox-test --integration` 额外检查单 ID 映射、namespace、capabilities、只读与嵌套 ro/rw、mask/别名负测、tmpfs 覆盖、bootstrap 与 FD 清理。

## 真实 VM 测试

执行环境必须具备 KVM、namespace 权限和相应运行依赖。Python 脚本默认使用 `build/agent-vm`，可用 `--binary /absolute/path/to/agent-vm` 覆盖。

```sh
python3 tests/integration_core.py
python3 tests/integration_network.py
python3 tests/integration_dbus.py
```

| 脚本 | 覆盖范围 |
| --- | --- |
| `integration_core.py` | argv/env、身份和文件 ownership、home、挂载/mask/tmpfs、只读策略、loopback、退出状态、pipe/PTY、信号、窗口变化、终端恢复、panic 设置 |
| `integration_network.py` | TCP/UDP 出站、IPv6 出站、端口发布、SSH agent 别名、通用 socket、多路并发/重连、tmpfs 目标及已有目标拒绝 |
| `integration_dbus.py` | bus 过滤、user/system 独立开关、guest 地址、proxy 生命周期 |

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
