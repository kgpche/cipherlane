# cipherlane 迁移记录：Node → Rust 单一实现（已完成，v1.0.0）

## 最终状态

- **产品是同一套 Rust 实现**，三个 binary：
  - `cipherlane` —— 中继服务器（房间/在线/邀请/长轮询/背压/续传/托盘端点），网页前端经
    `include_bytes!` 编译期内嵌，单文件即全部功能
  - `cipherlane-cli` —— 命令行（devices / send / send-text / recv / listen、定向直发、
    指纹校验、批量与目录递归、断点续传、协议 v2 AAD + v1 回退、控制字符净化）
  - `cipherlane-tray` —— 系统托盘（仅 Linux：ksni 0.3 + 纯 Rust zbus，无 libdbus 依赖）
- **浏览器端保持原生 JS 不动**：非安全上下文（明文 http 局域网）没有 `crypto.subtle`，
  纯 JS AES-256-GCM / SHA-256 / X25519 是产品必需能力，无法用 Rust 替代（WASM 会引入
  构建链与更大资产）。Rust 只承担服务器/CLI/托盘。
- **Node 版实现与 Node 单文件可执行打包链已移除**；Node（≥18）现在仅是 8 套 `.mjs`
  测试的运行器，产品构建与运行都不需要 Node。
- **三平台产物全部 Rust 原生构建**（不再交叉编译 Node）：
  - Linux：`cipherlane_<v>_amd64.deb` —— musl 静态 server + tray + cli，systemd 单元、
    桌面入口、托盘自启
  - Windows：`cipherlane_<v>_windows_x64.zip` —— `cipherlane.exe` + `cipherlane-cli.exe`，
    静态 CRT，无 VC++ 运行库依赖
  - macOS：`cipherlane_<v>_macos_universal.tar.gz` —— `lipo` 合并 x86_64 + arm64 的
    server/cli，附 `cipherlane.command` 启动器
- **版本号唯一来源** = `cipherlane-rs/Cargo.toml`；`package.json` 只是测试/开发入口，
  两者一致性由 `scripts/check-consistency.mjs` 校验（同时校验 `include_bytes!` 资源
  ↔ `public/`、三个 bin 声明、测试文件存在、产品链路无 Node 实现残留）。
- **CI/发布**：CI = Rust 三 bin 构建 + `cargo test` + musl 协议平价 + deb 打包冒烟 +
  Node 18/20/22 上的 JS 套件；Release = 打 `v*` 标签后三平台原生构建并 `gh release`
  发布产物与统一 SHA256SUMS。

## 迁移原则（已兑现）

- 浏览器端 JS 保持不动，纯 JS 加密路径继续由真实浏览器测试覆盖。
- 线协议逐字节兼容：协议 v2（AAD = `cipherlane/chunk/v2|<room>|<index>`）+ v1 回退；
  `X-Chunk-Seq` 幂等重投；`X-Resume` 可续传语义不变。
- 迁移期曾用双实现平价（`CIPHERLANE_TEST_SERVER` / `CL_SERVER_BIN`）作为验收手段；
  v1.0.0 起 Node 实现删除，测试直接、且只针对 Rust 二进制运行，平价钩子退化为
  “指定被测二进制”的测试参数（`CIPHERLANE_SERVER_BIN` / `CIPHERLANE_CLI_BIN`）。

## 阶段记录

- **P0 工具链（完成）**：Rust stable + musl target；无 cc 环境的兜底方案已记录备查。
- **P1 服务器核心（2026-10-19 完成）**：全协议端点移植（presence / devices / offers 长轮询 /
  rooms / chunk 经典+可续传 / done / progress / ack 凭证 / version / shutdown 令牌双闸 /
  update / adopt）+ 静态资源编译期内嵌；断连检测用 `/proc/net/tcp` 轮询等价 Node 的
  `res.on('close')` 配额释放语义；协议/CLI/浏览器三套测试曾全量对 Rust 跑通。
- **P2/P3（2026-10-19 完成）**：musl 静态 server/tray 进入 deb（deb 31MB → ≈1.1MB）；
  桌面集成 + 双主题图标 + 托盘自启；ksni 真·托盘（GNOME 需 AppIndicator 扩展）。
- **P4（2026-10-20 完成）**：CLI 全量 Rust 化（rustcrypto：aes-gcm / x25519-dalek / sha2，
  qrcodegen 生成二维码），与浏览器逐字节互通由既有 x25519/aesgcm 向量与真实浏览器
  互操作场景锁定；`test/cli.test.mjs` 切换到 Rust 二进制。
- **v1.0.0 收尾（2026-10-20）**：删除 Node 实现与单文件可执行打包链；`build/package.sh`
  按宿主平台原生构建；新增 `release.yml`（三平台原生构建 + `gh release`）；
  README（中/英）与本文档同步为 Rust 单实现。

## 依赖面

- 服务器：`tiny_http` + `serde_json` + `rand` + `base64` + `if-addrs`（+ `sha2` 用于 ETag，
  `libc` 用于 unix 信号）
- 托盘：`ksni`（zbus，纯 Rust）
- CLI：`sha2` / `aes-gcm` / `x25519-dalek` / `qrcodegen` / `rand` / `base64`
- 服务器仍保持零知识：不引入任何需要接触明文/密钥的服务端加密库，CLI 的密码学依赖
  只在客户端二进制中。

## 已知边界 / 未在本机验证项

- 托盘仅 Linux（StatusNotifierItem / AppIndicator）；Windows/macOS 为终端运行 server/cli，
  无托盘。
- Windows 构建在本机无法验证（需 Windows 环境）：由 CI 的 `windows-latest` 原生构建；
  静态 CRT 目标为 Windows 10/11 x64。
- macOS universal 构建在本机无法验证（需 macOS + Xcode CLT 的 `lipo`）：由 CI 的
  `macos-latest` 原生构建；未签名/未公证，首次运行需右键打开。
- 线协议兼容：v1.0 与 v0.5.x 线协议一致；v0.5.0+ 发送端与 v0.4.x 接收端不兼容
  （协议 v2 升级），两端需同时升级。
