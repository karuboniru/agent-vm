# agent-vm 架构草案

状态：已实现 0.1.0 初版运行器，核心流程、passt 与 SSH relay 已通过真实 VM 集成验证；尚未进行独立安全审计。基线为当前环境的 libkrun 1.19.0、Linux rootless、同架构 guest；2026-09-20。构建和操作见 [README.md](README.md)，下文保留设计依据及后续加固项目。

用户已确认：只需当前运行用户及其工作文件的数字 UID/GID 一致；宿主 `/usr` 文件不必在 guest 显示为 root。

用户进一步确认：宿主行为在信任边界之内，不要求防御宿主在运行期间重命名、替换或重建被 mask 的路径。实现保证 guest 侧共享入口的遮挡，并检查启动时的挂载别名；不将该保证延伸到不可信宿主。

## 1. 推荐方案与范围

采用 **C++20 宿主程序 + 小型 C17 guest helper + libkrun C API + passt**。首版是一条命令启动一个临时 VM，无常驻 root daemon、无 OCI 镜像构建步骤。动态复用宿主 `/usr`，其他路径由临时 FHS 根和显式共享组成。

首版支持：CWD 共享、TOML 用户配置、CLI 共享挂载/自定义 tmpfs/环境变量覆盖、路径 mask、单用户 identity map、IPv4 passt 网络、TCP/UDP 端口发布、显式文件系统 Unix stream socket 转发，以及 SSH agent 转发别名。默认 CWD 可写、home 临时、网络关闭、不转发 socket；用户可在配置中改变默认值。

不将多用户 guest、Unix datagram/abstract socket、SCM_RIGHTS 文件描述符传递、跨架构执行、通用 OCI runtime 或 GPU 纳入首版。宿主 `/usr` 更新会改变下次运行环境，因此这不是可复现的软件镜像；以后可另加 snapshot/image 后端。

## 2. 进程与权限边界

```text
agent-vm CLI / supervisor                    调用者 UID，宿主视图
  ├─ passt                                  宿主 netns，仅在联网时启动
  ├─ socket brokers                         每个转发对应固定授权的宿主目标，可选
  └─ sandbox setup → VMM worker + libkrun    user/mount/pid/ipc/uts/net namespace
       ├─ 最小 bootstrap → virtio-fs /dev/root → guest 启动根
       ├─ 受限对象目录 → virtio-fs /.agent-vm/exports → guest 挂载装配
       ├─ 已连接 socket FD ↔ passt ↔ host network
       └─ virtio-vsock ↔ broker 的精确 Unix socket

guest: libkrun init（PID 1）
  └─ agent-vm-guest helper
       ├─ 读取挂载描述、创建本地 tmpfs、挂载对象、切入最终根
       ├─ socket relays（目标 UID，每个转发一个，可选）
       └─ 用户命令（目标 UID/GID）
```

supervisor 解析配置、形成不可变 RunSpec、启动进程、处理信号和退出码；运行阶段不提供让 guest 任意打开宿主路径的 RPC。broker 只连接启动时授权的固定 endpoint。

**隔离边界是整个 VMM 所能访问的宿主资源集合。** libkrun 明确要求将 guest 与 VMM 视作同一安全主体；virtio-fs 的 export path 本身不保证文件树隔离。因此必须先建立 mount jail、切根、断开旧根和不必要的 FD，才启动 VM。[libkrun 安全模型](https://github.com/libkrun/libkrun/blob/v1.19.0/README.md#security-model)

可以把 VMM 运行文件与 guest root 放在 jail 中不同目录，但这种目录划分不构成额外安全边界。尤其不能认为 guest 再挂一层 `/proc` 或 `/dev` 就隐藏了底层 host 资源。

## 3. UID/GID：默认只映射调用者

假设调用者 UID/GID 是 `1000:1000`：

```text
uid_map: 1000 1000 1
gid_map: 1000 1000 1
```

数字依次为 namespace 内 ID、直接外层 namespace 的 ID、长度。`gid_map` 的无特权写入路径先写 `setgroups=deny`。在 Toolbx 等嵌套容器内，“外层”是调用者所在 namespace，不能直接等同于物理宿主 initial userns。

这是一种保留当前 ID 的单用户模式，不是完整的 Podman 多 ID keep-id 映射。默认不需要 `/etc/subuid`、`/etc/subgid` 或 newuidmap/newgidmap；以后需要多个 guest 用户时再加 subordinate-ID 模式。宿主未映射的 `/usr` owner 可以显示为 overflow ID，通常是 65534，不改宿主文件 ownership。[user_namespaces(7)](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)

关键实现次序：

1. 单线程 setup 子进程进入 userns 后，以临时 namespace capabilities 完成 mount、mask 和切根；避免在这段中途 exec 导致非零 UID 丢失 capabilities。
2. 在创建 libkrun 文件共享后端之前清除全部 capabilities，并设置 no_new_privs；VMM 本身保持 U/G。
3. guest init 先以 guest root 完成初始化；我们的 helper 再执行 `setgroups`、`setresgid(G)`、`setresuid(U)`，清 guest capabilities、设置 no_new_privs 后运行用户命令。

v1.19.0 的 virtio-fs 后端在缺少 CAP_SETUID/CAP_SETGID 时支持自身 U/G 和 guest root 的请求，文件操作实际由宿主 U/G 完成；其他 ID 的切换受限。因此 guest root 创建的共享文件也可能归宿主 U/G，而不是宿主 root。[v1.19.0 passthrough 实现](https://github.com/libkrun/libkrun/blob/v1.19.0/src/devices/src/virtio/fs/linux/passthrough.rs)

不要用 `krun_setuid()` / `krun_setgid()` 代替 guest 降权：它们改变的是宿主 VMM 的身份。共享文件的 numeric owner、guest 进程身份、生成的 passwd/group 三者都要一致。[v1.19.0 C API](https://github.com/libkrun/libkrun/blob/v1.19.0/include/libkrun.h)

`setgroups=deny` 不会清掉宿主已经继承的 supplementary groups。首版仅承诺主 UID/GID，记录并检查宿主补充组；guest 补充组、组授权目录和 ACL 的兼容性单独验证，不伪造 `/etc/group` 来声称具备实际组权限。

## 4. mount jail 与 FHS 根

host 在新 mountns 中先将传播设为 recursive private，用 tmpfs 构造受限策略树，安装共享路径、嵌套覆盖、ro 属性和 mask。所有导出对象都从最终策略树取得，不能直接使用原始 source FD 导出。切根后断开旧根并关闭源 FD，VMM 自身也无法从原始路径或导出别名绕过策略。

host 不再提供承载 guest 临时文件的 tmpfs。它生成最多 1 MiB 的二进制挂载描述（版本、条目数、tmpfs 限额；每条包括类型、权限、UID/GID、目标路径、对象路径），并提供两个固定 virtio-fs 设备：

- `/dev/root`：最小启动根，包含 helper、描述文件、只读 `/usr`、生成的 `/etc` 和 guest 内核挂载所需的空目录。
- `/.agent-vm/exports`：只包含已 confinement 的文件/目录对象。条目用 `/N/root` 或 `/N/file` 引用对象，完整目标路径放在描述中。

tag 可以用路径形式，但每个目标一个设备会耗尽 libkrun 1.19 的 IRQ。固定两个设备配合对象路径避免这个限制，也避免长目标路径超过 tag 长度上限。guest helper 在独立 mount namespace 内创建本地 tmpfs 根和内建临时目录，再将用户 bind 与自定义 tmpfs 合并按先祖先、后后代的顺序安装；允许在可写宿主共享目录里创建缺失的挂载点。它保留 libkrun init 已挂载的 guest proc/sys/dev，卸载对象目录的 staging 挂载，随后 `pivot_root` 并断开 bootstrap。PID 1 保留启动 namespace，DHCP resolver 文件在两个视图中引用同一份受限私有文件。

guest 最终视图如下：

| 路径 | 来源与规则 |
| --- | --- |
| `/usr` | 宿主 bind，递归只读，nosuid；保留执行权限 |
| `/bin`, `/sbin` | 分别链接到 `usr/bin`, `usr/sbin` |
| `/lib`, `/lib64` | 按架构与宿主布局链接到 `usr/lib`, `usr/lib64`；不制造无效链接 |
| `/etc` | 生成私有 passwd、group、nsswitch.conf、hosts、hostname；复制宿主 ld.so.conf 和 ld.so.conf.d/ 内容（存在时，普通配置文件的符号链接复制为文件）；CA、时区、ld.so.cache 从固定系统位置单独导入，最终只读 |
| `/etc/resolv.conf` | 私有普通文件，通过独立 rw file bind 挂入只读 `/etc`，供 guest DHCP 写入 |
| `/home/...` | 默认空的 guest 本地 tmpfs home；显式请求时才共享宿主 home |
| CWD | 默认同绝对路径 rw bind；可通过 CLI 改为 ro 或其他目标 |
| `/tmp`, `/var/tmp` | guest 本地 tmpfs，1777，设置容量限制 |
| `/run`, `/run/user/U` | guest 本地 tmpfs 中的运行目录，后者归 U、0700 |
| 自定义 `[[tmpfs]].target` | guest 本地 tmpfs，可包含显式子挂载；根目录 UID/GID 默认调用者 U/G，mode 默认 0700，支持显式指定；tmpfs 自身内容退出后丢弃 |
| `/var`, `/opt`, `/srv`, `/mnt`, `/media`, `/root` | 最小占位目录，需要时加私有可写子挂载 |
| `/proc`, `/sys`, `/dev`, `/dev/pts`, `/dev/shm` | 由 guest 内核/init 挂载；不整体 bind 宿主对应目录 |

只共享 `/usr` 不等于所有宿主命令都开箱即用：CA、NSS、locale、timezone、`/usr/local` 中指向外部的 symlink 等要检测目标。`/etc` 默认生成和按需导入，不整体共享。宿主的 `/home → /var/home` 等布局需要解析、保留必要别名，HOME 与 CWD 必须指向实际可达路径。

共享对象的只读约束在 host 上通过挂载属性实施，不能仅靠 guest 以 ro 挂载 virtio-fs。使用固定 FD 的 bind 和 `mount_setattr(..., AT_RECURSIVE, MOUNT_ATTR_RDONLY)`；父挂载先安装，显式子挂载随后覆盖，不能重新递归锁定父目录而破坏 rw 子挂载。对象目录同时含 ro/rw 内容，不能把整个 export 标成 read_only。[mount_setattr(2)](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

host 策略骨架和启动配置在装配结束后锁为只读；guest 根骨架也在切根完成后锁为只读，私有可写目录与 rw 共享保持独立子挂载。两侧都使用 `pivot_root`，`chdir("/")`，卸载旧根，失败即终止。guest 本地 tmpfs 消耗 VM RAM，`--tmp-size` / `[vm].tmp_mib` 是每个文件系统（包括自定义 tmpfs）的容量上限，不预留内存；多个 tmpfs 和进程共同竞争 `--memory` 的预算。自定义条目不另设容量选项。

### VMM 的 `/proc`、KVM 和 FD 生命周期

VMM 需要 `/dev/kvm`，libkrun 1.19 的内建文件后端需要 `/proc/self/fd`。这些属于运行时依赖，不能忽略，也不能因此 bind 整个宿主 `/dev` 或宿主 proc。

首个技术验证必须固定：独立 PID namespace 中的 proc、最少设备、启动前后的 FD 白名单、旧根引用全部关闭、VMM exec/bootstrap 环境清理。保留的资源全部计入 guest/VMM 的授权上界；不能将其描述成对恶意 guest 不可见。host namespace 的 proc 不进入 jail。

若要求连 VMM 自身的 proc 路径也从可达文件树消失，可扩展 libkrun 暴露预打开的 proc-self-fd dirfd / KVM FD 或分阶段 prepare/start 接口；内部文件后端已有 `proc_sfd_rawfd` 字段，但当前公共 C API 没有完整接线。此路径需要一个小型上游补丁，不能假定现有 API 已支持。

## 5. 挂载与 mask 的明确语义

配置和命令行先合并成 MountPlan，再执行；mask 是最终 deny 规则，CLI 新增挂载不能隐式取消 mask。

父子挂载的模式独立：允许 ro 父挂载下配置 rw 子挂载，也允许 rw 父挂载下配置 ro 子挂载。父挂载的 ro 属性递归约束其树，但单独声明的子挂载按各自模式生效。用户 bind 与自定义 tmpfs 可以交替嵌套，统一按先祖先、后后代的顺序安装，与配置或命令行中的声明顺序无关。最近父层为共享挂载时，嵌套目标的文件/目录类型须与子挂载源匹配，且路径各级不得经过 symlink；可写父层允许启动时创建缺失的挂载点，只读父层要求目标已存在；最近父层为 tmpfs 时，可在私有树内创建子挂载点。可写共享中创建的挂载点在退出后保留；配置校验与 plan 不创建路径。因此只读共享 home 可以保留默认可写 CWD。

自定义 tmpfs 可以覆盖共享源中已有且路径各级均无 symlink 的目录，包括 ro 共享目录。host 为 tmpfs 建立私有 staging 树，在其中创建子挂载占位文件或目录并安装显式子挂载，导出前将 staging 骨架锁为只读，保留显式 rw bind 子挂载的写权限。被覆盖的原宿主子树不会通过底层导出暴露，也不修改宿主源目录或 ownership。guest 先装配内建 tmpfs，再按祖先优先顺序混合安装用户 bind 和自定义 tmpfs。tmpfs 自身写入只占 guest RAM，退出后丢弃；其中显式 rw bind 子挂载仍写入对应宿主源。

tmpfs target 重复或与 bind target 相同时拒绝，等于或包含内建 `/tmp`、`/var/tmp`、`/run`、home 或 `/run/user/U` 时也拒绝；保护的系统路径和 `/.oldroot` 不能覆盖，与 mask 重叠也报错。允许 `/run/myapp` 等后代路径。workdir 可以是 tmpfs 根，或为子挂载创建挂载点时产生的父目录；不会自动创建空 tmpfs 内的其他工作目录。socket target 可以位于自定义 tmpfs 内，即使该 tmpfs 覆盖的是 ro 共享子树。

例如在 `[[tmpfs]]` 中设置 `target = "~/.gnupg"`，另用只读 `[[mounts]]` 将宿主 `~/.gnupg/pubring.kbx` 挂到相同 guest 路径，可在临时 GnuPG home 内只暴露现有公钥环。tmpfs 的 UID/GID 默认调用者 U/G，也可显式指定为 1000；该组合不能再与 `.gnupg` 的 source/target mask 重叠。examples/config.toml 包含默认不启用的完整示例。

建议区分两种策略：

- `--mask SOURCE`：宿主源路径策略。`--mask ~/.ssh` 会遮住所有共享挂载中通往该源子树的入口。
- `--mask-target DEST`：guest 目标路径策略，只遮指定位置。

例如 home 同时挂到 `/home/yan` 和 `/backup/home`，源 mask `~/.ssh` 要在两个位置都生效；若又显式把 `~/.ssh` 或其后代挂到 `/keys`，计划阶段直接拒绝。CWD 落在被 mask 的子树内也应报错。

实现流程：

1. 展开受支持的 home/CWD 占位符；规范化路径，解析源 symlink，保留源与目标的映射关系。
2. 用 FD 固定源对象；目标解析使用受限的 `openat2`，禁止逃逸、magic link 与不受控的 symlink 跟随，防止检查与使用之间的替换。[openat2(2)](https://man7.org/linux/man-pages/man2/openat2.2.html)
3. 安装普通挂载，对每个来源映射计算 mask 的相对位置，再用只读空目录或空文件覆盖。
4. 检查所有重叠挂载与别名，锁定 mount tree，最后关闭未遮蔽源路径的 FD。

仅允许在可写共享目录中创建缺失的 mountpoint；不得为 mask 创建宿主占位文件。已有路径可直接覆盖；不存在的 mask 是一条持续策略：只要共享源仍可能被宿主修改，就需提供隔离的 overlay/投影视图预留遮挡，或明确拒绝该组合，不能当作成功的 no-op。ro bind 也受此约束，因为它不阻止宿主在真实源目录新建 `.ssh`；只有不共享其祖先、真正不可变快照等可证明条件才能例外。

路径 mask 保护可达路径，不是数据溯源或内容防泄漏。已经位于其他共享路径的硬链接、复制内容，以及运行前已泄漏的 FD，不会因为遮住 `.ssh` 自动消失。源文件系统的其他挂载别名也要进入规划检测；无法确认的冲突应拒绝，而非声称绝对隐藏。

## 6. 配置与 CLI

默认配置：`$XDG_CONFIG_HOME/agent-vm/config.toml`，未设置时为 `~/.config/agent-vm/config.toml`。运行元数据放 `$XDG_RUNTIME_DIR/agent-vm/<run-id>/`，0700；不要把整个配置目录或 runtime directory 自动共享。

已实现的配置示例（完整带注释版本见 examples/config.toml）：

```toml
version = 1

[vm]
cpus = 4
memory_mib = 4096

[filesystem]
cwd = "rw"
home = "ephemeral"
mask_sources = ["~/.ssh", "~/.gnupg"]

[[mounts]]
source = "~/datasets"
target = "/data"
mode = "ro"

[[tmpfs]]
target = "/cache"
# uid = 1000
# gid = 1000
# mode = 0o750

[[sockets]]
source = "~/service.sock"
target = "/run/service/client.sock"

[environment]
inherit = ["TERM", "LANG", "LC_ALL"]

[environment.set]
EDITOR = "vim"

[network]
mode = "passt"
publish = ["127.0.0.1:8080:8080/tcp"]

[ssh_agent]
enabled = false
```

```sh
agent-vm doctor
agent-vm plan --mask "$HOME/.ssh"
agent-vm run --network passt \
  --mount type=bind,src="$HOME/datasets",dst=/data,ro \
  --tmpfs target=/cache \
  --socket src="$XDG_RUNTIME_DIR/service.sock",dst=/run/service/client.sock \
  --mask "$HOME/.ssh" \
  -e EDITOR=vim -e API_TOKEN \
  -p 127.0.0.1:8080:8080/tcp \
  --ssh-agent -- bash
```

`-e KEY=VALUE` 设置值，`-e KEY` 从调用者继承该变量，未定义时报错。默认白名单继承；HOME/USER/LOGNAME/PATH/XDG_RUNTIME_DIR 按 guest 生成。SSH 转发别名启用时自动设置 guest SSH_AUTH_SOCK；别名关闭时可显式指定 SSH_AUTH_SOCK，配合自定义 socket 转发使用。

`[[tmpfs]]` 必须提供 `target`，可选整数 `uid`、`gid` 默认调用者数字 U/G，可选整数 `mode` 默认 `0o700`。CLI 可重复使用 `--tmpfs target=/cache,uid=1000,gid=1000,mode=0750`，`dst`、`destination` 是 `target` 的别名，mode 按八进制解析。UID/GID 范围是 0 到 4294967294，`UINT32_MAX` 无效；mode 范围是八进制 0000 到 7777。UID/GID 是独立于宿主身份映射的 guest ID，通过 tmpfs mount options 设置根目录 ownership 和权限，不对宿主执行 chown，也不改变 workload 身份；例如 root owner 与 0700 会阻止非 root workload 访问。

标量 CLI 覆盖配置；环境变量按 key 覆盖；bind mount、tmpfs、socket 和端口发布列表追加，重复 target 报错；mask 取并集。mount 与 socket 的相对源路径以 CLI 的 CWD 或配置文件所在目录解析，`~` 展开为调用者 home，并写入 plan 输出。配置不执行 shell、不做任意命令替换。未知字段报错。首版不自动读取工作区内不可信配置。

`plan` 展示最终文件树、UID/GID、网络、socket 授权与环境变量名；秘密值隐藏。用户传入的 workload env 不直接注入 root guest bootstrap，防止 LD_PRELOAD 或 KRUN_* 配置影响初始化；helper 在降权后才交给 execve。启动参数通过私有只读结构化配置传递，不经 shell 拼接。

## 7. passt 联网与端口发布

supervisor 在原宿主 netns 中启动 passt；VMM 自己进入独立、无外部网卡的 netns。通过预连接 Unix stream FD 传输以太网帧，保留 passt 的宿主联网能力而不让 VMM 直接使用宿主网络。

```c
// 顺序示意，生产代码检查每个返回值和 FD 所有权。
krun_disable_implicit_vsock(ctx);
krun_add_net_unixstream(ctx, NULL, passt_fd, mac,
                       COMPAT_NET_FEATURES, NET_FLAG_DHCP_CLIENT);
```

FD 来自 `socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, ...)`，一端供 `passt -f --fd N`，另一端供 libkrun。只有指定继承的 FD 跨 exec。[官方 C 示例](https://github.com/libkrun/libkrun/blob/v1.19.0/examples/chroot_vm.c)

端口发布编译成 passt 参数，例如 `-t 127.0.0.1/8080:8080 -u none`。明确指定 TCP 和 UDP 两类策略，默认都为 none，默认发布地址为 loopback；不使用 TSI 专属的 `krun_set_port_map`。[passt 手册](https://passt.top/builds/latest/web/passt.1.html)

guest 使用 libkrun 内建 IPv4 DHCP，helper 验证地址/路由/DNS 后才启动需要联网的命令。内建初始化对 DHCP 失败可能只发警告，不能把 VM 启动成功视为网络就绪。`/etc/resolv.conf` 是每次运行私有文件；不要复制宿主不可达的 stub DNS 地址。[DHCP 实现](https://github.com/libkrun/libkrun/blob/v1.19.0/init/dhcp.c)

`--network none` 同时意味着不启动 passt、不加 NIC、显式禁用 implicit vsock/TSI；若有明确授权的 IPC，再加无 TSI 的 vsock。普通 passt 出站网络不是域名/IP allowlist 防火墙，访问宿主/LAN 的策略需另行定义。IPv6、DHCP 续租和多 NIC 后续单独实现验证。

## 8. Unix socket 转发与 vsock

```text
guest client → 配置的 guest socket target → guest relay
             → AF_VSOCK(CID_HOST=2, port=P) → libkrun Unix backend
             → jail 中该转发的 broker socket → host broker → 配置的 host source
```

```c
krun_disable_implicit_vsock(ctx);  // 每个 context 初始化时一次
krun_add_vsock(ctx, 0);           // 不启用 INET / UNIX TSI
krun_add_vsock_port2(ctx, P, "/ipc/socket-0.sock", false);
```

`false` 代表 guest 发起连接到 host Unix socket；反方向使用 true。这个 API 接收 pathname，不接收已连接 FD。使用 libkrun 用户态 Unix backend 时，不要求宿主 `/dev/vsock` 或 `/dev/vhost-vsock`；guest 需要 virtio-vsock。[Unix backend](https://github.com/libkrun/libkrun/blob/v1.19.0/src/devices/src/virtio/vsock/unix.rs)

`--socket src=SOURCE,dst=TARGET` 可重复指定，TOML 使用 `[[sockets]]` 的 `source`、`target` 字段。source 必须解析为现存 socket 文件，并固定为规范化后的宿主绝对路径；target 必须为绝对路径，经过路径规范化。两端 socket pathname 最长 107 字节，转发总数最多 256（包含 SSH agent 别名），重复 guest target 报错。路径含逗号时使用 TOML，避免 CLI 字段分隔歧义。

每个转发有独立的 host broker、guest relay 和固定授权的 vsock port。broker 在隔离后仍能按固定宿主路径重新连接服务，不共享整个宿主 runtime 目录。broker 路径和 endpoint 在启动时授权，guest 不可传任意宿主目标。转发不依赖 passt，`--network none` 也可使用。

guest helper 先以 root 为 target 创建缺失的父目录（0700），并将新目录 owner 设为 U/G，再降权，以 U/G 创建监听 socket（0600）。已有父目录的 owner 和权限保持不变；已有目标一律报错，不删除或替换。target 必须位于可写 guest 文件系统，例如 `/run`、`/tmp`、`/var/tmp`、临时 home、自定义 tmpfs 或显式 rw 共享；不为 socket 解锁只读根骨架。目录和 socket 文件写入最近的挂载层：rw bind 对应宿主源，tmpfs 对应 guest 临时存储。

`--ssh-agent` / `[ssh_agent].enabled` 保留为别名：将宿主 SSH_AUTH_SOCK 转发到 `/run/user/U/ssh-agent.socket`，并设置 guest SSH_AUTH_SOCK。`--no-ssh-agent` 只关闭别名，不移除显式转发；别名关闭时可以显式设置 SSH_AUTH_SOCK 指向自定义转发。

每个客户端独立连接，处理半关闭、背压、并发和退出回收。仅承诺文件系统 Unix stream byte-stream，不支持 datagram、abstract socket 或 SCM_RIGHTS 等跨 VM 的 Unix socket 语义。显式转发授权 guest 使用该宿主服务的能力；SSH forwarding 是签名能力授权，即使 `.ssh` 被 mask，启用它仍允许使用 agent。

## 9. 启动顺序、退出与模块

1. 读取调用者身份/CWD/配置，验证依赖，构建 RunSpec 与 MountPlan。
2. 准备明确授权的 FD 和运行目录；按需启动 passt、broker。
3. 单线程 sandbox setup 建 userns 并同步写映射，再建 mount/ipc/uts/net namespace；PID namespace 要 fork 后才对新子进程生效。
4. 在新 namespace 内安装 bind/mask/ro 属性，从最终视图创建对象目录、bootstrap 和挂载描述；切根、清理旧根引用与 FD。
5. 清 capabilities、设置 no_new_privs，装载经验证的 VMM seccomp 策略；确保动态库/固件/KVM/proc 需求都在允许视图内。
6. 使用 libkrun 1.19 C API 配置 RAM/vCPU、virtio-fs、显式 NIC/vsock、guest helper 和精简 bootstrap 环境；调用 krun_start_enter。
7. libkrun init 挂载 guest 伪文件系统、配置网络；helper 根据描述装配本地 tmpfs 和导出对象，保留 guest 伪文件系统、切入最终根，创建 runtime 和 socket 父目录、设置新目录 owner，再降权、按需启动 relay 并监督 workload。
8. supervisor 用 pidfd/signalfd 等管理退出；guest helper 转发信号、回收子进程、传递退出码。TTY 输入、窗口大小、非交互信号和强制停止需要端到端验证；使用超时升级停止，清理 passt/broker 和临时目录。

libkrun 的 start/enter 是进入 VMM 运行循环的接口，因此隔离成独立子进程，supervisor 负责生命周期。需要额外控制通道时只接受固定操作（停止、resize、状态），不接受 guest 指定宿主路径。

建议模块：`config`、`run_spec`、`mount_plan`、`sandbox`、`krun_backend`、`network`、`socket_broker`、`supervisor`、`doctor`，以及独立的 `guest/` C helper。宿主 C++ 用 RAII 管 FD/子进程/清理，fork 前不启动线程；guest helper 维持小依赖面。

## 10. 交付顺序与验收

| 阶段 | 产物与必须通过的检查 |
| --- | --- |
| P0：集成验证 | 真正可访问 KVM 的环境；单 ID map + cap 清理 + virtio-fs 读写；私有 proc/旧根/FD 生命周期；明确 libkrun 是否需补丁 |
| P1：最小运行器 | readonly `/usr`、临时 FHS、CWD、guest helper；guest id 正确，新建文件宿主 owner 正确；退出码/TTY 可用 |
| P2：策略 | TOML/CLI/plan、mask、挂载覆盖；home 双重挂载、源 symlink、CWD 在 mask 内、子挂载 ro、不存在 mask 的可写父目录 |
| P3：网络与 IPC | passt/DHCP/DNS、TCP/UDP 发布、SSH relay；none 模式无意外 TSI，未声明端口未发布，SSH 并发/重连可用 |
| P4：发布前加固 | guest 原始文件协议/路径遍历、proc/fd、mask bypass 测试；VMM syscall 策略、资源限制、故障退出无遗留进程 |

隔离相关负面测试是发布条件：不能仅验证“正常命令能跑”。尤其验收宿主 `/usr` 不可写、未授权路径不可达、mask 不被别名重挂载绕过。单用户模式还需验证 guest root 和 U/G 两种文件请求、0700 home、补充组与 ACL 的行为。

RAM/vCPU 限制不覆盖所有宿主资源：私有 tmpfs 要有大小/ inode 限制；VMM 与 helpers 尽量进入委派的 cgroup v2，约束内存、进程数和 CPU。共享 rw 目录的磁盘用量受宿主配额控制；不能声称 VM RAM 上限同时限制宿主磁盘写入。

## 11. 当前环境与依赖

初始检查在工具沙盒内进行；随后按用户授权在沙盒外进行了 namespace 和真实 VM 测试。用户已安装开发依赖，代理没有执行安装。沙盒外执行仍使用普通用户，无需 sudo。

| 项目 | 当前可见状态 |
| --- | --- |
| 系统 | Fedora 45 Toolbx，x86_64，Linux 7.2.6 |
| libkrun / devel | 已装 1.19.0-3.fc45；运行时查询 NET、BLK、INIT_BLOB 均返回 1 |
| libkrunfw | 已装 5.5.0-3.fc45 |
| passt | 已装 0^20260728.gf8df3f1-2.fc45 |
| C / pkg-config | GCC、pkgconf 已有 |
| namespace 工具 | unshare、newuidmap、newgidmap 已有；当前 subuid/subgid 文件没有配置条目 |
| C++ / build | 用户已安装 gcc-c++、cmake、ninja-build，项目编译成功 |
| 开发库 | 用户已安装 tomlplusplus-devel、libcap-devel、libseccomp-devel |
| KVM | 工具沙盒内不可见；沙盒外可打开，KVM_GET_API_VERSION=12，KVM_CREATE_VM 成功，真实 libkrun VM 已启动并正常退出 |

其他 Fedora 环境准备开发依赖时可安装（当前环境已经具备）：

```sh
sudo dnf install gcc-c++ cmake ninja-build tomlplusplus-devel libcap-devel libseccomp-devel
```

libkrun、固件、passt 已有，无需重复安装。guest helper 可复用共享 `/usr` 中的运行库；若选择静态 glibc helper，再加 `glibc-static`，不是默认必需项。消费预编译 libkrun 无需安装 Rust toolchain；只有修改/重建 libkrun 时才需要其构建依赖。

此环境的 VM 实测需要在工具沙盒外执行；已证实外层环境支持所需 KVM 与嵌套 namespace 操作。doctor 应分别报告：设备不存在、设备权限拒绝、namespace 被容器/LSM/seccomp 限制、依赖缺失，而不是统一建议 sudo。所有这里的接口结论按本机 1.19 头文件和对应版本源码核对；升级至 libkrun 2.x 需重新验证后端适配层。

## 12. 已执行的最小验证

测试代码和日志保留在 `/tmp`，用于验证架构假设，不是产品实现或完整安全审计。

**独立 namespace 测试**：`/tmp/agent-vm-ns-spike.c`，日志 `/tmp/agent-vm-ns-spike.log`。单 ID userns、private mount propagation、tmpfs 新根、ro bind、现存 secret 目录 mask、pivot_root、卸载旧根、清 capabilities 与 no_new_privs 均成功。UID/GID 保持 1000:1000；对只读共享的写入返回 EROFS；mask 目录为空，原 secret 返回 ENOENT；宿主源文件内容未变，临时源目录清理成功。

**真实 libkrun 测试**：源码 `/tmp/agent-vm-research/krun-probe.c` 与 `guest-probe.c`，最终通过日志 `/tmp/agent-vm-research/krun-smoke-ao5zcbnv/output.log`。使用 1 vCPU、512 MiB、单 ID userns、独立 mount/pid/ipc/uts/net namespace、只读 `/usr`、临时共享工作目录、精确 KVM bind 和新 PID namespace 的 proc。

实测输出：

```text
VMM_SANDBOX uid=1000 gid=1000 pid=1 caps=0 no_new_privs=1
GUEST_BOOT uid=0 gid=0
GUEST_ROOT_USR_WRITE errno=30 (Read-only file system)
GUEST_USER uid=1000 gid=1000
GUEST_FILES root_request=1000:1000 user_request=1000:1000
GUEST_USR_WRITE errno=13 (Permission denied)
GUEST_DISABLED_VSOCK rc=-1 errno=19 (No such device)
GUEST_PROBE_PASS
```

外层再次 stat 两个文件，owner 都为 1000:1000、内容一致。测试整体退出码 0；VM 退出后临时根的挂载消失。普通 guest 用户写 `/usr` 可能先被 DAC 拒绝为 EACCES，因此另以 guest root 验证确实收到 EROFS，避免把两种拒绝混为一谈。

上述原型已证实单 ID 映射、guest 显式降权、共享文件 ownership、root 对 `/usr` 的只读约束，以及禁用 implicit vsock 的基本行为。后续正式实现的验证见下一节；不能从正常启动推导对原始恶意 virtio-fs 请求的完整安全性。

## 13. 0.1.0 实现结果与明确边界

- 已实现 CLI/TOML/plan/doctor、namespace/FHS/UID、挂载与 mask、passt、TCP/UDP 发布、Unix stream socket relay 与 SSH agent 别名、guest 降权、信号/退出码/终端管理。
- VMM 先以精简环境重新 exec，再进入 namespace，避免宿主原始环境及配置解析内存残留在 VMM 地址空间中。启动前关闭非白名单 FD、清空 capability sets，并安装 seccomp denylist。
- 同一源目录的多个声明挂载均安装 mask；mountinfo 校验拒绝未覆盖的 bind 别名、`/usr` 的可写别名、runtime 的别名暴露。父子挂载模式独立，允许 ro 父挂载下的 rw 子挂载，以及 bind/tmpfs 交替嵌套；最近父层为共享挂载时，嵌套目标须类型匹配且无 symlink，可写父层允许创建缺失目标，只读父层要求目标已存在；最近父层为 tmpfs 时，在私有树中准备挂载点。缺失的 mask 和需要在只读共享中创建嵌套挂载点的请求不支持，启动失败，不悄悄放行。
- 固定 control vsock 始终启用，TSI 显式关闭；network none 不运行 passt。内核可能自带无路由的 dummy0，验收关注无外部 NIC/路由/TSI，以及 guest 本地 loopback 可用。
- libkrun 1.19 Unix backend 在 HUP 与 IN 同时发生时可能丢失尾部数据。因此 socket 内部通道使用 DATA/EOF/ACK，控制通道也等待 ACK 后才关闭；对外保留正常字节流和半关闭语义。
- `tests/config_test.cpp` 覆盖解析和策略；`tests/network_test.cpp` 覆盖并发/背压/半关闭/非法帧/清理；`tests/sandbox_test.cpp --integration` 验证切根、FD 清理、权限、mask 和真实 bind 别名负测；两份 Python integration 脚本通过真实 VM 验证核心功能与网络/SSH。
- 当前保留 VMM 私有 proc 和精确 KVM 节点；seccomp 是 denylist，而非完整 syscall allowlist。原始恶意 virtio-fs 协议审计、宿主 cgroup 总资源限制、持久磁盘配额、IPv6、多 NIC 和 DHCP 续租仍属后续工作。`--tmp-size` 分别限制各临时文件系统，不是总内存限额。

## Filtered D-Bus forwarding

`[dbus.user]` and `[dbus.system]` independently enable host-side xdg-dbus-proxy
instances with literal per-bus filter arguments. Filtering is mandatory; callers
cannot inject extra listeners or override lifecycle descriptors through arguments.
Proxy sockets live outside the exported IPC directory in the private runtime.
Only the existing framed brokers are reachable through authorized vsock ports.
The supervisor waits for proxy readiness before creating brokers or launching the
VM, monitors proxy exits and cleans up helpers on shutdown. Host proxy policy and
upstream addresses are not serialized to the clean VMM worker; resolved socket
mappings and guest bus environment values use the existing launch formats.

Authentication reaches the bus through the host proxy with the invoking user's
identity. The transport carries bytes, not SCM_RIGHTS; D-Bus methods requiring
Unix file descriptors remain unsupported. Empty rules retain xdg-dbus-proxy's
baseline bus access, rather than granting access to arbitrary service names.
