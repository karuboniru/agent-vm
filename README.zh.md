# agent-vm

[English](README.md)

agent-vm 用 libkrun 在无 root 权限的 Linux microVM 中运行命令，适合运行编码 agent、开发工具和需要隔离的任务。它直接复用宿主机的工具链，不需要制作系统镜像；命令使用调用者的数字 UID/GID，共享工作目录中的修改直接保存在宿主机。

## 用法

运行需要可访问的 `/dev/kvm`、无特权 user namespace 和 libkrun 1.x（>= 1.19）及其固件。联网需要 `passt`，D-Bus 转发需要 `xdg-dbus-proxy`。从源码安装见[开发指南](docs/DEVELOPMENT.zh.md)，RPM 构建见[打包指南](docs/PACKAGING.zh.md)。

```sh
agent-vm doctor

# 忽略用户配置：当前目录可写、home 临时、外部网络关闭。
agent-vm run --no-config -- bash

# 预览授权和配置；环境变量值不显示。
agent-vm plan --no-config --network passt

# 联网，并把 guest 的 HTTP 服务发布到宿主 loopback。
agent-vm run --no-config --network passt -p 127.0.0.1:8080:8000/tcp \
  -- python3 -m http.server 8000 --bind 0.0.0.0
```

默认加载 `$XDG_CONFIG_HOME/agent-vm/config.toml`，或 `~/.config/agent-vm/config.toml`。用 `--profile NAME` 选择同目录的 `NAME.toml`，用 `--config FILE` 指定文件。配置示例见 [examples/config.toml](examples/config.toml)；挂载、环境变量、mask、SSH agent 和 D-Bus 转发见[使用指南](docs/USAGE.zh.md)。

## 总体设计

- 只读复用宿主 `/usr`，组合最小 `/etc`、显式共享目录和 guest 内存中的临时文件系统。默认共享当前目录，home 使用临时存储。
- 将 guest 与 VMM 作为同一安全边界，尽可能限制 VMM：独立 namespaces、受限文件树、关闭多余 FD、清除 capabilities，并安装 seccomp 策略。只读和 mask 策略在宿主侧实施。
- 通过 `passt` 提供可选网络；通过固定目标的 socket broker 提供可选 Unix socket、SSH agent 和过滤后的 D-Bus 转发。
- 宿主 C++20 supervisor 管理进程、终端、信号和退出状态；C17 guest helper 装配文件系统、降权并启动命令。

可写共享会修改宿主文件，转发 socket 会授予对应服务能力。宿主及其运行期间的文件修改属于信任边界；项目没有独立安全审计。详细授权范围和限制见[架构与安全边界](docs/ARCHITECTURE.zh.md)。

## 文档

| 文档 | 内容 |
| --- | --- |
| [使用指南](docs/USAGE.zh.md) | CLI、配置、文件共享、网络与 IPC |
| [架构与安全边界](docs/ARCHITECTURE.zh.md) | 进程隔离、文件系统装配、协议及能力边界 |
| [开发指南](docs/DEVELOPMENT.zh.md) | toolbox 构建、安装、源码分工和开发约定 |
| [测试指南](docs/TESTING.zh.md) | 测试入口、覆盖范围和运行环境 |
| [打包指南](docs/PACKAGING.zh.md) | Fedora RPM 构建、安装布局和检查 |

许可证：[MIT](LICENSE)。
