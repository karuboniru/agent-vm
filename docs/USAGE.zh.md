[English](USAGE.md) · [返回 README](../README.zh.md)

# 使用指南

## 命令与默认值

```sh
agent-vm [run|plan] [OPTIONS] [-- COMMAND [ARG...]]
agent-vm doctor
agent-vm --help
agent-vm --version
```

`run` 启动 VM，未指定命令时运行 `/bin/sh`；`plan` 校验并显示最终配置，不启动 VM 或创建挂载点；`doctor` 检查依赖、KVM 和 namespace 条件。命令前使用 `--`，参数中的空格、引号、空字符串和换行按原值传递，不经 shell 拼接。

以下默认值适用于未加载配置、未指定覆盖选项的运行：

| 选项 | 默认值与作用 |
| --- | --- |
| `--cpus N` | 2 个 vCPU |
| `--memory MiB` | 2048 MiB guest RAM |
| `--tmp-size MiB` | 每个 guest tmpfs 上限 256 MiB |
| `--cwd-mode ro|rw|none` | `rw`，在相同规范化绝对路径共享当前目录 |
| `--home ephemeral|shared` | `ephemeral`，空的临时 home |
| `--workdir PATH` | 默认当前目录；禁用 CWD 共享时默认 home |
| `--network none|passt` | `none`，无外部网络 |
| `--ssh-agent` / `--no-ssh-agent` | 默认关闭 SSH agent 转发 |
| `--debug` | 默认关闭运行诊断输出 |

`--tmp-size` 是每个文件系统的容量上限，不是预留内存或总配额；tmpfs 与进程共同使用 guest RAM。vCPU/RAM 设置不限制宿主总资源或可写共享目录的磁盘占用。

## 配置加载与合并

默认文件为 `$XDG_CONFIG_HOME/agent-vm/config.toml`；当 `XDG_CONFIG_HOME` 未设置、为空或不是绝对路径时，使用 `~/.config/agent-vm/config.toml`。默认文件不存在时使用内建默认值，不自动读取项目目录内的配置。

- `--config FILE`：加载指定文件。
- `--profile NAME`：加载同一用户配置目录中的 `NAME.toml`，替代而不合并 `config.toml`。名称非空且不含路径组件，文件必须存在。
- `--no-config`：禁用配置文件。以上三个选项互斥。

CLI 标量覆盖文件设置，环境变量按名称覆盖；bind、tmpfs、socket 和端口列表追加，mask 合并去重。未知字段报错。配置和 CLI 中的相对文件系统路径均相对于启动 `agent-vm` 时的宿主当前工作目录，适用于 mount、socket 的 source/target、tmpfs 的 target，以及 `filesystem.workdir`、`mask_sources`、`mask_try_sources`、`mask_targets` 和 `--config FILE`。修改 guest 的 `workdir` 不改变解析基准。宿主源路径解析符号链接，guest 目标路径仅做词法规范化。D-Bus 地址和环境变量值仍按字面字符串处理。`~` 展开为调用者 home，不做 shell 展开或命令替换。完整字段示例见 [config.toml](../examples/config.toml)。

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

## 文件共享与临时存储

```sh
agent-vm run --no-config \
  --mount "type=bind,src=$HOME/datasets,dst=/data,ro" \
  --tmpfs target=/cache,mode=0750 --workdir /cache -- bash
```

`--mount` 可重复使用，默认只读；`rw` 直接修改宿主源。CLI 字段用逗号分隔，含逗号的源路径使用 TOML。CWD 优先复用相同源和目标的挂载，保留已有权限，也复用内建 `/usr`；`--cwd-mode ro` 不会把显式 `rw` 改为只读，反之亦然。相同 CWD 目标上的冲突 bind 或 tmpfs 会被默认 CWD 共享替换；其他重复挂载目标报错。

父子 bind/tmpfs 统一按先父后子安装，与声明顺序无关。各 bind 权限独立，可以在只读父挂载下提供可写子挂载。最近父层为 bind 时，目标不能经过 symlink，文件/目录类型必须匹配；只读父层要求挂载点已存在，可写父层允许启动时创建，创建的路径保留在宿主上。最近父层为 tmpfs 时，子挂载点在私有文件系统中创建。

可在 `/run`、`/tmp`、`/var/tmp`、`/mnt`、`/media` 下挂载，也支持 `/etc` 和 `/usr` 子路径。隐式只读 `/usr` 下的目标必须存在；在已有目录覆盖 tmpfs 或可写 bind 后，可在其内部创建子挂载点。`/proc`、`/sys`、`/dev`、FHS 别名、内部启动路径、整个 `/etc`、`/etc/resolv.conf` 和受保护的 runtime 路径不可替换。自定义 tmpfs 不能等于或包含内建 `/tmp`、`/var/tmp`、`/run`、home 或 `/run/user/<uid>`，也不能与 mask 重叠。

`--tmpfs target=PATH[,uid=UID,gid=GID,mode=0700]` 创建空的 guest tmpfs，`dst`、`destination` 也是 `target` 的别名。TOML 使用 `[[tmpfs]]`，字段为 `target`、可选整数 `uid`、`gid`、`mode`。UID/GID 默认调用者，范围为 0–4294967294；mode 默认 0700，CLI 按八进制解析，TOML 可写 `0o750`。这是 guest 内的根目录 ownership，不改变命令身份或宿主 ownership；root 所有且 mode 0700 会阻止非 root 命令访问。

tmpfs 可覆盖只读共享中的现有目录，遮住原子树而不修改宿主；其中显式 `rw` bind 子挂载仍会修改宿主。tmpfs 自身内容退出即丢弃。`--workdir` 可选 tmpfs 根或为子挂载创建的父目录，不会自动创建其他工作目录。示例配置包含临时 GnuPG home 加只读公钥环的组合。

## 路径 mask

`--mask SOURCE` / `[filesystem].mask_sources` 在每个共享别名中遮挡宿主源子树；`--mask-target TARGET` / `mask_targets` 遮挡一个 guest 目标。例如在 `[filesystem]` 中设置 `mask_sources = [".git"]`，会遮挡调用时当前目录中的 `.git`，方便同一份用户配置用于不同项目。共享树内缺失的 mask 路径报错，不为 mask 创建宿主占位文件。

`--mask-try SOURCE` / `[filesystem].mask_try_sources` 仅在配置解析时路径存在的情况下应用相同的源 mask。不存在的路径（含悬空符号链接）会被忽略；其他文件系统错误和普通 mask 冲突仍报错。存在的路径会与 `mask_sources` 合并去重，忽略的路径不会在后续创建时自动加入 mask。可复用的项目配置示例：

```toml
[filesystem]
mask_try_sources = [".git", ".env"]
```

```sh
# .ssh 必须存在；共享 home，同时隐藏其 .ssh。
agent-vm run --no-config --home shared --mask "$HOME/.ssh" -- bash

# 显式共享后代可作为源 mask 的例外。
agent-vm run --no-config --home shared --mask "$HOME/.ssh" \
  --mount "src=$HOME/.ssh/known_hosts,dst=/keys/known_hosts,ro" -- bash
```

同一源或目标不能既共享又 mask。源 mask 的显式后代共享例外，在其 masked 祖先或中间祖先再被 target mask 覆盖时仍保留；共享父目录不会取消其子路径的 mask。其他被遮挡内容仍不可见。规则不依赖 CLI 顺序。

启动时还会检查挂载身份与 bind 别名，拒绝能够绕过策略的别名。mask 保护路径，不追踪其他位置的硬链接或副本；不保证防御宿主在运行期间替换源路径。详见[安全边界](ARCHITECTURE.zh.md)。

## 环境变量

`-e NAME` 继承已定义的宿主变量，未定义时报错；`-e NAME=VALUE` 设置字面值。默认仅继承存在的 `TERM`、`LANG`、`LC_ALL`，并生成 `HOME`、`USER`、`LOGNAME`、`PATH`、`XDG_RUNTIME_DIR`。TOML 使用 `[environment].inherit` 和 `[environment.set]`。`plan` 显示变量名但省略值。workload 环境在 guest 降权后交给命令，不注入特权初始化流程。

## 网络与端口

```sh
agent-vm run --no-config --network passt \
  -p 127.0.0.1:8080:8000/tcp -- python3 -m http.server 8000 --bind 0.0.0.0
```

`--network none` 禁用外部网络和 TSI，guest loopback、固定控制通道和显式 socket 转发仍可用。`passt` 模式提供一张网卡，支持宿主条件允许的 IPv4/IPv6 出站流量，可访问其宿主上下文能够访问的宿主/LAN 目标，没有目标地址 allowlist。

`-p` / `--publish` 格式为 `[IPv4:]HOST:GUEST[/tcp|udp]`，默认 `127.0.0.1` 和 TCP；发布必须启用 passt。未声明的 TCP/UDP 端口不发布。IPv6 发布地址、多 NIC、完整 DHCP 续租管理不支持。passt 的 stdout/stderr（包括 debug 模式）送到 `/dev/null`，启动和意外退出错误由 supervisor 报告。

## Unix socket 与 SSH agent

```sh
agent-vm run --no-config \
  --socket "src=$XDG_RUNTIME_DIR/service.sock,dst=/run/service/client.sock" -- bash
agent-vm run --no-config --network passt --ssh-agent -- bash
```

`--socket` 可重复；TOML 使用 `[[sockets]]` 的 `source` 和 `target`。源必须是存在的文件系统 Unix stream socket，源 symlink 解析为规范路径。相对目标路径以调用时的宿主当前目录为基准；解析后源和目标各最多 107 字节，总计最多 256 个转发（含 SSH/D-Bus）。冲突目标报错，含逗号路径使用 TOML。

目标必须位于可写 guest 文件系统。helper 创建缺失父目录并设为调用者所有、0700；已有目录保持权限，直接父目录必须允许调用者创建 socket。用 `/run/service/client.sock` 等私有子目录，避免直接在 root 所有的 `/run` 创建。listener 以调用者运行，socket mode 为 0600，不替换已有目标。位于 `rw` bind 内的目录和 socket 会写入宿主，位于 tmpfs 内则保持 guest 私有。

`--ssh-agent` 把宿主 `SSH_AUTH_SOCK` 转发到 `/run/user/<uid>/ssh-agent.socket` 并设置 guest 变量。`--no-ssh-agent` 仅关闭该别名，不关闭显式转发。自定义转发可以配合 `-e SSH_AUTH_SOCK=...`。SSH agent 转发授予签名能力，即使 `.ssh` 被 mask 也如此。

只支持字节流，不支持 Unix datagram、abstract socket 或 `SCM_RIGHTS` FD 传递。宿主服务在同一父目录内替换 socket 后可重连；不追踪父目录本身的替换。

## D-Bus

需要 `/usr/bin/xdg-dbus-proxy`；两个 bus 独立配置，默认都关闭：

```toml
[dbus.user]
enabled = true
args = ["--talk=org.freedesktop.Notifications"]

[dbus.system]
enabled = true
args = ["--talk=org.freedesktop.UPower"]
```

可选 `address` 使用字面的 D-Bus 地址，不做 shell 或 tilde 展开。未指定时分别读取宿主 `DBUS_SESSION_BUS_ADDRESS` / `DBUS_SYSTEM_BUS_ADDRESS`；再分别回退到 `$XDG_RUNTIME_DIR/bus`（需要该变量）和 `/run/dbus/system_bus_socket`。

始终启用 `--filter`。`args` 允许 `--see=`、`--talk=`、`--own=`、`--call=`、`--broadcast=`、`--log`、`--sloppy-names` 和冗余 `--filter`；拒绝进程控制选项、额外地址/路径及未知选项，规则语法错误由 proxy 启动时报错。空规则仅保留 proxy 的基本 bus 操作。

guest 地址为 `unix:path=/run/user/<uid>/dbus-user.socket` 和 `unix:path=/run/user/<uid>/dbus-system.socket`，分别写入对应环境变量。冲突的显式环境变量或 socket 目标报错。`plan` 显示过滤参数但不启动 proxy；proxy 意外退出会终止 VM。代理以调用者身份访问宿主 bus，过滤范围受其既有权限限制。转发不支持 Unix FD，因此需要 FD 的方法（包括许多 portal API）不可用。

## 退出与诊断

返回 workload 退出状态；运行器错误通常为 125。SIGINT、SIGTERM、SIGHUP、SIGQUIT 转发给 guest 进程组，SIGWINCH 同步终端大小；无响应关闭在五秒后强制终止。正常退出或处理到的信号会恢复终端，SIGKILL 后终端若停留在 raw 模式可执行 `stty sane`。

`run` 在启动 VM/helpers 前把宿主进程 `RLIMIT_NOFILE` soft limit 提升到继承的 hard limit，不改变调用 shell 或 guest 的 limit。`--debug` 提供运行路径与生命周期诊断；测试与故障定位见[测试指南](TESTING.zh.md)。
