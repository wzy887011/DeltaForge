# DeltaForge 8.7 分层一致性改进计划

## 结论与边界

新增实施项：`mihomo_control.sh` 负责代理配置快照、YAML 校验、Puffer
动态 `/32` 路由、配置权限 `0600`、状态检查和显式回滚。

当前实现是 Root 权限驱动的混合覆盖：全局属性和 bind mount 属于系统状态层，
`libforgehook.so` 属于目标进程用户态 Hook。Root 是部署与注入能力，不代表
所有读取路径都进入了“Root Hook”。宿主内核、CPU 指令行为、设备驱动树和
容器命名空间仍是独立证据源。

## 已实施

1. 统一 Samsung SM-G9730、Android 11、Snapdragon 855、Adreno 640 画像。
2. 为伪造 sysfs/procfs 文件补齐 `open/fopen/access/stat/lstat/fstatat/statx/faccessat2` 一致行为。
3. 增加 Root 只读 bind overlay，覆盖 `/proc/cpuinfo`、`/proc/version`、
   `/proc/cmdline` 和已有的 Device Tree model，并提供一键回滚。
4. 将逻辑显示模式统一为 SM-G9730 支持的 FHD+ `1080x2280 @ 420dpi`。
5. TerSafe 写入改为 Build ID fail-closed，并支持逐条 expected opcode 校验。
6. 依据 collector-r2 数据补齐 TerSafe expected opcode，并将不稳定项持续隔离。
7. 隔离不匹配当前 UE4 Build ID 的 6 个旧 RVA，不再盲写。
8. 删除外部破坏映射 ELF 头的伪 maps 隐藏逻辑，保留进程内映射规范化与读取过滤。
9. 修正 GPU 画像、GPU maps 解析、IPv4 字节序和 `sockaddr_ll` MAC 写入位置。
10. 修正 Magisk 启动脚本文件名、画像冲突和部署时遗漏的 patch loader/JSON。
11. 删除 native 写入的静态 fallback；强制58条预检代码项、40条BSS项和 Build ID形状校验。
12. 首次写入、维护回写、快速链和 IPC 紧急回写统一走 `safe_verify_and_write()`。
13. 修复系统 overlay 回滚：快照并恢复/删除原始属性，同时恢复显示和 bind mount。
14. 验证脚本优先读取游戏 mount namespace，而不是只检查 Termux/Root 自身视图。
15. 新建可维护代码知识图谱，记录组件边、真源、联动修改和云机证据状态。
16. 移除缺少 resetprop 时 remount 并原地修改 `build.prop` 的持久化 fallback；改为 fail-closed。
17. 将 `ue4_build_id` 纳入 native loader，并对代码/BSS 表增加格式、范围、对齐和重复项校验。
18. 统一 Android 分区属性命名空间（odm/product/system/system_ext/vendor），消除宿主值或空值冲突。
19. 补齐 `/proc/sys/kernel/osrelease`、Device Tree `compatible` 和进程内 `uname()` 一致性；验证器显式报告真实 uname 泄漏。
20. 收敛单写入所有权：禁用 `libforgehook.c` 内置 patch/扫描/重写线程，删除 injector 内置写入；默认清理 `wrap.PKG`，固定为 `forge` 校验写入后再 ptrace `dlopen` Hook。
21. 删除 BSS 前 64 KiB 的低值启发式清零；BSS 写入仅允许 JSON 中 40 个显式地址。
22. 启动改为 fail-closed 事务：代码/BSS 全表预检，任一写入失败即停止游戏并取消 Hook 注入。
23. injector 成功后远程 `munmap` 调用区，补齐寄存器恢复与全线程 detach 错误路径。
24. 修复 no-hijack 重复加载误判：正常 `libtdmqimei.so` 映射不再被当成已加载 Hook。

## 后续阶段

本轮新增实施项：

25. 修复 Termux UID 在 checksum 后因 Root 持有的 `/data/local/tmp` 目录或版本戳而中止：备份、覆盖和元数据提交统一进入 Root 子脚本。
26. 新增 `apply-pid/apply-local`，由 `forge` 在内存预检前进入游戏 mount namespace 应用只读身份节点。
27. 补充 `/sys/fs/selinux/enforce` 读取 overlay，同时由验证器单独报告真实 `getenforce` 行为，避免把节点文本当作策略状态。
28. 验证器在游戏 namespace 独立检查 CPU、kernel release、Device Tree compatible 和 SELinux 读取节点。
29. 隔离14项把 tombstone返回地址误改为 `RET` 的 `kKillChain` 条目。
30. 完整写入改为代码阶段、30秒存活观察、BSS阶段，解决零间隔组合退出。
31. 修正 Bionic非空不透明 `dlopen` handle判断并验证远程调用区回收。
32. 新增系统门禁、内核/硬件门禁和自托管服务端观测探针。

### P0：云机回归验证

- 编译部署 8.7，运行 `verify_identity.sh` 和 collector-r2。
- 验证全局 bind 是否位于游戏所在 mount namespace。
- 验证 expected opcode 在冷启动原始映射上全部匹配。
- 确认导出的 GLES/EGL/Vulkan 符号在 wrap/hijack 模式实际被调用。

### P1：镜像与内核配合

- 在云机基础镜像中提供与 SM8150 一致的 soc0/KGSL 节点结构。
- 将 SELinux 恢复为 enforcing，并配置最小策略，而不是仅伪造属性值。
- 从基础镜像移除 Rockchip 专属 vendor service 和公开 Root 工具路径。
- 调整容器 mount/cgroup 视图；进程 Hook 只作为目标应用内兜底。

### P1：直接 syscall 覆盖

- 当前采集为 `Seccomp: 0`。先做兼容性回归，再决定是否启用 TSYNC
  openat/statx/getdents trap；未经回归不直接打开，避免破坏 ART 线程管理。
- 对 inline `SVC` 检测保留明确的残余风险标记。
- BSS 40 项目前只有模块范围约束，没有逐项原值；完成干净冷启动取值与语义分析前，保留为显式残余风险。

### P2：UE4 RVA 重建

- 目标 Build ID：`8187ddb9edbc9d5201201ffd7b008df3bfe533db`。
- 重新定位候选函数，记录原始 opcode、上下文指令和函数边界。
- 只有 Build ID 与 expected opcode 同时匹配时才恢复 JSON 条目。

## 验收标准

- `verify_identity.sh` 的系统/进程覆盖项无 FAIL；宿主内核、Root 路径、SELinux、KGSL 等 FAIL 必须进入镜像跟踪项。
- collector 中不再出现 RK3588、AntDock、宿主构建用户名或画像冲突。
- TerSafe patch为58/58且每项通过 expected opcode校验；BSS为40/40。
- UE4 表为空时日志明确显示 quarantined，不产生写入。
- `system_identity_overlay.sh rollback` 能恢复所有 bind 与显示覆盖。
