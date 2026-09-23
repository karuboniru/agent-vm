[English](PACKAGING.md) · [返回 README](../README.zh.md)

# Fedora RPM 打包指南

## 包定义与依赖

`agent-vm.spec` 使用 Fedora forge/CMake 宏、发行版编译与链接加固参数和自动 ELF 依赖。架构列表为 x86_64、aarch64；构建目标仓库需要提供 libkrun >= 1.19 且 < 2 及其他 BuildRequires。

内部 core 库静态链接到命令，不安装开发库或头文件。spec 设置 `BUILD_TESTING=OFF`，RPM 构建不需要 KVM 或 user namespace。`passt` 是显式运行依赖，`xdg-dbus-proxy` 为 Recommends，固件由 libkrun 的包依赖链提供。构建包不代表已经验证该架构的 VM 运行。

## 构建

本地构建通过 toolbox；`mock` 还需要所在环境支持其容器/权限机制并已为调用者配置。以下示例使用 `fedora-45-x86_64` 目标和独立临时输出目录，源来自已提交的当前 checkout：

```sh
rpm_work=$(mktemp -d "$PWD/build-rpm.XXXXXX")
mkdir -p "$rpm_work/sources" "$rpm_work/srpm" "$rpm_work/result"
git archive --format=tar.gz --prefix=agent-vm-master/ HEAD \
  > "$rpm_work/sources/agent-vm-master.tar.gz"
toolbox run mock -r fedora-45-x86_64 --uniqueext=agent-vm --buildsrpm \
  --spec "$PWD/agent-vm.spec" --sources "$rpm_work/sources" \
  --resultdir "$rpm_work/srpm"
toolbox run mock -r fedora-45-x86_64 --uniqueext=agent-vm --rebuild \
  "$rpm_work"/srpm/agent-vm-*.src.rpm --resultdir "$rpm_work/result"
toolbox run rpmlint agent-vm.spec "$rpm_work"/result/*.rpm
```

`git archive HEAD` 不包含未提交改动。归档前缀、文件名与 spec 的 forge 元数据必须匹配；源中必须包含 `LICENSE` 和全部文档。spec 默认引用移动的 `master` 分支，分发构建需固定源码提交或 tag 并同步 forge 元数据，才能固定输入。SRPM 目录保持只有本次构建产物，避免通配符选中多个版本。

直接使用源码构建时也必须通过 toolbox，命令见[开发指南](DEVELOPMENT.zh.md)。

## 安装布局

| 路径 | 内容 |
| --- | --- |
| `/usr/bin/agent-vm` | 主命令 |
| `/usr/libexec/agent-vm-guest` | guest helper |
| `/usr/share/agent-vm/config.toml` | 示例配置，不自动加载 |
| RPM 文档目录 | 双语 README、`docs/`、示例与供链接使用的 LICENSE 副本 |
| RPM license 目录 | MIT LICENSE |

## 包检查

```sh
toolbox run rpm -qpl "$rpm_work"/result/agent-vm-[0-9]*.rpm
toolbox run rpm -qp --requires "$rpm_work"/result/agent-vm-[0-9]*.rpm
```

检查主包文件布局、依赖解析、双语文档及相对链接，确认未包含内部库或开发头文件。用 `readelf` 检查两个 ELF 的 PIE、非可执行栈、RELRO/BIND_NOW 和无意外 RPATH/RUNPATH；检查 debug 包与源码匹配。`rpmlint` 的错误和警告应逐项检查，不把非零结果写成通过。

在独立安装环境验证：

```sh
rpm -V agent-vm
agent-vm --version
agent-vm --help
agent-vm plan --no-config --network passt -- /usr/bin/true
```

这些检查不启动 VM。具备 KVM 与 namespace 权限时，再执行 `agent-vm doctor` 和 `agent-vm run --no-config -- id`；真实 VM 测试见[测试指南](TESTING.zh.md)。文档描述打包方式与检查项，不把特定快照的结果当作所有构建的保证。
