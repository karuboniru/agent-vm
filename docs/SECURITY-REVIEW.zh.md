# IPC、seccomp 与路径策略复核（2026-09-23）

本报告记录 2026-09-23 的安全复核结果，socket forwarding 架构已由 inode-pinned direct mapping 取代 broker；下文 broker 测试结果仅是旧实现的历史记录，不能证明当前 path mapping 行为。当前实现将 IPC 排除在 bootstrap 和 virtio-fs export catalog 外，授权宿主 Unix socket 在 VMM sandbox setup 时按 inode 只读 bind 到私有 IPC 目录。guest 通过普通路径操作 IPC 的旧复现不能直接套用；这不是对恶意原始 virtio-fs 请求的穷尽验证。项目将 guest 和 VMM 视为同一安全边界。

| 建议 | 判断与处理 |
| --- | --- |
| 1. syscall denylist | 成立。加入 `io_uring_setup/register/enter`、`userfaultfd`、`quotactl_fd`、`kcmp`，逐项断言 `EPERM`。保留全局 denylist 模型。 |
| 2. IPC 端点替换 | 旧 broker/readiness socket 通过 inode 单独只读 bind 保护。当前配置的宿主 socket 在 VMM sandbox setup 时固定源 inode 并只读 bind；替换宿主源路径不会让 VM 重连到新 inode。同一个被固定的 listener 仍按服务本身行为接收连接。 |
| 3. supervisor 连接越界 | 原实现按宿主路径跟随符号链接，成立。改为固定 control dirfd，`openat(O_PATH | O_NOFOLLOW)`、`fstat` 验证 socket，并持有端点 FD 通过 `/proc/self/fd/<fd>` 连接。拒绝绝对/相对链接和非 socket；覆盖父目录替换及端点 rename 竞态。原问题影响限于连接与固定 20 字节控制消息，回复不返回 guest，不能表述为任意写或无限挂死。 |
| 4. 宿主 AF_VSOCK | 成立：原 seccomp 未拒绝该地址族，不能只依赖 netns。宿主 `socket/socketpair` 仅允许 AF_UNIX，全部 io_uring 入口同时拒绝。guest 的虚拟 vsock 与 passt Unix backend 仍可用。 |
| 5. runtime 空间耗尽 | 当前普通 guest 不直接看到 IPC，但原 VMM 持有可写宿主目录。移除该目录挂载；libkrun 延迟创建的控制端点使用独立 detached tmpfs，限制为 64 KiB、16 inode，宿主通过 FD 访问。测试实际触发字节和 inode 的 `ENOSPC`，不填充宿主 runtime 文件系统。 |
| 6. 路径策略与函数拆分 | 成立。新增标准库实现 `include/agent_vm/paths.hpp`，host 统一规范化、包含关系和保留路径规则；guest C 实现位于 `guest/paths.c`，同组用例比较两份实现。统一 `/.oldroot` 和 `/run` 规则。沙箱拆为 `pin_sources`、`build_policy_tree`、`apply_masks`、`export_catalog`。 |

控制 tmpfs 不在宿主 runtime 文件系统中创建路径。supervisor 和 VMM 关闭引用后由内核回收，无需额外卸载清理。受攻陷的 VMM 仍可能耗尽其受限控制 tmpfs 或破坏自身 listener，造成该 VM 的控制通道不可用；五秒后的强制终止逻辑保留。

## 验证

配置、编译与执行均通过 `toolbox run`：

- CMake 构建成功，`git diff --check` 无错误。
- CTest：7 项通过；D-Bus 因缺少 `/usr/bin/xdg-dbus-proxy` 跳过。
- `build/sandbox-test --integration`：通过，包含 mask 的 24 组组合、嵌套挂载、IPC inode 不可替换、tmpfs 字节/inode 限额及隔离后 AF_VSOCK 拒绝。
- `tests/integration_network.py --case ssh`、`--case sockets`：此处记录的通过结果来自旧 broker 实现，不能作为当前 direct mapping 的结果。当前测试观察到 payload 尾部 EOF sentinel 被截断；libkrun 1.x path mapping 的修复计划通过上游 PR 885 cherry-pick 到未来 1.x 构建，未指定固定版本。
- 单独提取执行 `integration_core.py` 中现有控制测试：7 项检查通过，包括 SIGTERM、带 passt 的进程组 SIGTERM、PTY 窗口调整与终端恢复。
- 完整 core/network VM 套件未通过：在 guest 退出时遇到 `VFS: Busy inodes after unmount` / `generic_shutdown_super` panic，与当时记录的故障特征一致。此历史结果不代表 socket refactor 的验证。当前 Wayland 验证曾提交数个 surface 后因 virtiofs panic 以状态 125 退出。未将工作负载输出正确但退出 125 的用例记为通过，也未在本次修改中尝试修复 libkrunfw guest 内核。
