[English](ARCHITECTURE.md) · [返回 README](../README.zh.md)

# 架构与安全边界

## 组件与生命周期

```text
agent-vm supervisor
  ├─ passt                         可选，宿主网络
  ├─ xdg-dbus-proxy                 每个启用的 bus 一个
  ├─ socket controller             所有转发共用
  │    └─ socket data processes     每个转发一个
  └─ clean re-exec → VMM worker     libkrun + namespaces + mount jail
       └─ guest init
            └─ agent-vm-guest
                 ├─ socket relays
                 └─ workload       调用者 UID/GID
```

supervisor 解析 TOML/CLI，形成 `RunSpec`，准备私有运行目录、启动配置和固定通信端点。D-Bus proxy 完成 readiness 后才建立 socket broker；passt 和 brokers 启动后，supervisor 进入仅映射调用者的 user namespace 和空 network namespace，清 capabilities、设置 `no_new_privs`，然后 fork/re-exec VMM worker。网络关闭时也隔离 supervisor。

worker 以精简环境重新 exec，隔离配置解析留下的地址空间与宿主原始环境。它建立 user、mount、PID、IPC、UTS、network namespaces，装配受限根，关闭非白名单 FD、清 capabilities 并安装 seccomp denylist，再启动 libkrun。supervisor 管理信号、TTY、退出状态和 helper 清理；helper 意外退出会结束 VM。

## 授权边界

安全边界是 **guest 与整个 VMM 能访问的宿主资源集合**。virtio-fs export path 不构成独立隔离边界；guest 内的 mount 权限也不承担宿主资源隔离。宿主只读属性、mask、切根和 FD 清理在创建文件共享后端之前完成。

VMM jail 保留精确的 `/dev/kvm` 节点和私有 PID namespace 的 proc，后者供 libkrun 使用 `/proc/self/fd`。这些属于 VMM 授权资源，不承诺对恶意 guest 的原始文件协议请求不可达。默认不共享外层宿主 proc 或整个宿主 `/dev`。VMM seccomp 使用 denylist，包含全部三个 io_uring syscall、userfaultfd、quotactl_fd 和 kcmp；宿主 socket/socketpair 仅允许 AF_UNIX，guest AF_VSOCK 使用 libkrun 的 Unix backend，passt 使用继承的 Unix stream。socket helpers 使用 allowlist；没有独立安全审计，也没有对恶意 virtio-fs 原始协议的穷尽验证。

宿主是可信的；运行期间宿主重命名、替换或重建被 mask 的路径不在保证范围内。mask 保护共享入口，不隐藏其他位置已有的硬链接、副本或已授出的 FD。可写共享授予直接修改对应宿主源的权限。

共享树内可达的宿主 Unix socket 也属于服务能力边界，即使共享目录是只读。guest 的显式 relay 只传字节；被控制的 VMM 若能直接连接可达服务，可使用该服务授予的能力，包括服务主动传来的 FD。因此 `--network none`、只读 bind 和路径 mask 不限制服务经已授权连接另行授予的权限。

## UID/GID 与降权

仅映射调用者数字 U/G，例如调用者为 `1000:1000` 时：

```text
uid_map: 1000 1000 1
gid_map: 1000 1000 1
```

映射相对于直接外层 user namespace；嵌套容器内不等同于物理宿主 initial namespace。无特权 GID 映射使用 `setgroups=deny`，不需要 subordinate ID 范围或 root daemon。未映射的宿主 owner 可能显示为 overflow ID；不改变宿主 `/usr` ownership，也不承诺 supplementary groups/ACL 行为与宿主完全一致。

setup 阶段使用 namespace capabilities 完成挂载和切根，在启动 VMM 前清空 capabilities 并设置 `no_new_privs`。guest helper 先以 guest root 装配文件系统，再设置 groups、GID、UID，锁定 securebits、清 capabilities 并设置 `no_new_privs` 后运行命令。没有 guest sudo/提权运行模式。

## 宿主策略树与 guest 文件系统

host mount namespace 的传播设为 recursive private。源对象用 FD 固定，目标通过受限 `openat2` 解析；挂载按祖先顺序装配，应用子挂载、只读属性和 mask。只读属性由宿主 `mount_setattr` 实施，不能仅依赖 guest 的 ro 挂载。显式子挂载独立保留各自权限。

所有导出对象来自最终受限策略树，不直接导出原始 source FD。mask 用只读空文件/目录覆盖，按配置保留显式后代例外；mountinfo 检查拒绝可绕过 mask、只读 `/usr` 或私有 runtime 的 bind 别名。`plan` 做静态配置和文件系统检查，启动时进一步检查 pinned FD 和挂载身份。

两个固定 virtio-fs 设备向 guest 提供启动材料：

| 设备 | 内容 |
| --- | --- |
| `/dev/root` | 最小 bootstrap：helper、启动/挂载描述、只读 `/usr`、私有 `/etc` 和启动所需目录 |
| `/.agent-vm/exports` | 受限对象目录，条目通过 `/N/root` 或 `/N/file` 引用 |

完整目标路径保存在有长度上限的挂载描述中，因此挂载数量和长路径不需要额外设备 tag。guest helper 在独立 mount namespace 创建本地 tmpfs 根，先装配内建文件系统，再按祖先顺序混合装配 bind 与自定义 tmpfs。它保留 guest 内核/init 的 proc/sys/dev，移除 catalog staging、`pivot_root` 并断开旧 bootstrap，随后锁定根骨架只读。guest PID 1 的启动视图与最终视图共享同一私有 resolver 文件。

| guest 路径 | 来源 |
| --- | --- |
| `/usr` | 宿主只读共享；保留执行权限，禁止 suid |
| `/bin`, `/sbin`, `/lib`, `/lib64` | 按宿主布局链接到 `/usr` 内相应位置 |
| `/etc` | 生成最小账户、NSS、hosts、hostname；按固定位置导入 CA、时区、loader cache/config |
| `/etc/alternatives` | 存在时只读 bind，保留 symlink |
| `/etc/resolv.conf` | 独立私有可写文件，供 DHCP 写入 |
| home | 默认 guest tmpfs，显式配置时共享宿主 home |
| CWD | 默认相同绝对路径的可写共享 |
| `/tmp`, `/var/tmp`, `/run` | guest tmpfs；`/run/user/U` 归 U 所有、0700 |
| 自定义 tmpfs | guest 本地临时存储，可含显式 bind/tmpfs 子挂载 |
| `/proc`, `/sys`, `/dev` 及其内建挂载 | guest 内核/init 提供 |
| 其他根目录 | 最小占位目录及显式挂载 |

宿主 `/etc/ld.so.conf` 和 `ld.so.conf.d/`（存在时）复制到私有只读 `/etc`，指向普通配置文件的 symlink 复制为文件。不自动共享整个宿主 `/etc`。复用 `/usr` 不保证每个宿主命令都具备所需的外部配置、服务或 symlink 目标，也不提供运行期间一致的软件快照。

自定义 tmpfs 在宿主侧对应私有 staging 骨架，用于隐藏被覆盖的源子树、准备子挂载并导出最终策略。骨架只读，显式可写子 bind 保持可写；实际 tmpfs 内容位于 guest RAM，不写入宿主 staging。`--tmp-size` 对每个 tmpfs 分别限容，VM 内存不构成宿主 cgroup 总限额或共享磁盘配额。

## 网络、vsock 与协议

passt 留在宿主 network namespace，通过预连接 Unix stream FD 与 libkrun 交换以太网帧，不使用宿主 TAP。VMM 位于空 network namespace；隐式 vsock/TSI 关闭，只有显式端口映射：

| vsock 端口 | 用途 |
| --- | --- |
| 1024 | 固定信号与终端 resize 控制消息 |
| 1025–1280 | 至多 256 个授权 socket 转发 |
| 1281 | 一次性 guest readiness 连接 |

IPC 不进入 bootstrap 或 export catalog。已监听的 broker/readiness socket 逐个按 inode 只读 bind，父目录只读；broker upstream socket 替换后的重连仍经过 broker。宿主 runtime IPC 目录不再挂入 VMM。libkrun 延迟创建的 control listener 位于 supervisor 创建的 detached tmpfs（64 KiB、16 个 inode），supervisor 保留 dirfd，VMM 挂载同一文件系统。它不占用宿主 runtime 文件系统路径，VM 和 supervisor 释放引用后自动回收。控制消息通过固定 dirfd，以 `O_PATH | O_NOFOLLOW` 打开 `control.sock`，`fstat` 确认 socket，并保持 inode FD 存活，通过 `/proc/self/fd/<fd>` 连接，避免路径替换竞态。受攻陷的 VMM 仍可破坏自身控制通道；supervisor 五秒后的强制终止机制保留。readiness 无 payload，不使用共享文件标记，只是生命周期提示，不是 guest 可信证明。控制协议不接收宿主路径或任意命令。

`include/agent_vm/protocol.h` 定义协议：启动格式版本 2、挂载格式版本 3，使用本机字节序，要求同架构 host/guest；配置大小上限为 1 MiB，字符串带长度。stream relay 使用网络字节序的长度、DATA/EOF/ACK 帧，单帧数据最多 65536 字节。EOF 与确认保证半关闭及尾部数据排空后再关闭内部传输。

启用网络时 guest helper 校验地址、路由和 DNS，再启动 workload。guest 内核参数为 `oops=panic panic=-1`，helper 在装配前预置失败状态 125，正常退出状态在 helper 完成退出后由 libkrun init 写入。该机制使 guest 内核异常及时结束，不修复固件内核本身的错误。

## Socket broker 隔离

N 个转发共用一个 controller 和 N 个持久 data process，每个转发最多 64 个并发连接。controller 只按配置的 basename 连接预先授权的父目录，不提供任意路径 RPC。

controller 位于私有 user、mount、network、IPC、UTS namespaces。根中只读挂载授权 upstream 父目录，重复目录只挂一次，遮挡无关子挂载。保留父目录使同目录内的 socket 替换可重连；不追踪父目录替换。同目录兄弟 socket 位于 controller 的文件系统权限范围内，但正常运行只连接配置目标。seccomp allowlist 允许 accept、选择预打开目录、连接 Unix stream 和发送成对 FD，不允许读取 stream、打开文件或执行程序。

每个 data process 是独立 PID namespace 的 PID 1，根为空且只读，无 proc/dev、标准流、宿主目录或 listener FD。它仅从私有单向通道接收已连接 FD 对并转发字节；allowlist 禁止文件打开、socket 创建/连接、exec、fork、ptrace 和 namespace 修改。controller 与 data process 均清空包括 bounding set 在内的 capabilities，设置 `no_new_privs` 后报告就绪。data process 失败会引发整个 broker 清理。

内部 FD 交接使用 `SCM_RIGHTS`，不等于 guest FD 转发。没有额外 idle timeout 或宿主总资源配额。broker 隔离不为独立的 `xdg-dbus-proxy` 添加沙盒，也不改变 passt 自身沙盒。每个启用的 D-Bus 使用独立过滤 proxy；策略和 upstream 地址不序列化给 clean VMM worker，worker 只得到解析后的 socket 映射。

## 进程可观测性

`ps -eo pid,ppid,comm,args` 可见 `avm-supervisor`、`avm-sock-ctl`、`avm-sock-N`、`avm-vmm-wait`，data title 包含宿主源和 guest 目标。VMM title 为 `agent-vm: virtual machine`，libkrun 自行设置主线程名。guest 使用 `avm-guest`、`avm-relay-N`、`avm-stream-N`；workload、passt 和 D-Bus proxy 保留自身程序名。

title 在 confinement 前设置，转义控制字符，长度受原 argv/environment 存储限制。复用存储前分别保存原 argv/environment，极小启动环境可能使长 title 截断。实现分工和测试入口见[开发指南](DEVELOPMENT.zh.md)与[测试指南](TESTING.zh.md)。
