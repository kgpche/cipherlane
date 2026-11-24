# cipherlane 迁移记录：Node → Rust 单一实现（已完成，v1.0.0）

## 最终状态

- **产品与测试是同一套 Rust 实现**，三个 binary + 五个测试目标：
  - `cipherlane` —— 中继服务器（房间/在线/邀请/长轮询/背压/续传/托盘端点），网页前端经
    `include_bytes!` 编译期内嵌，单文件即全部功能
  - `cipherlane-cli` —— 命令行（devices / send / send-text / recv / listen、定向直发、
    指纹校验、批量与目录递归、断点续传、协议 v2 AAD + v1 回退、控制字符净化）
  - `cipherlane-tray` —— 系统托盘（仅 Linux：ksni 0.3 + 纯 Rust zbus，无 libdbus 依赖）
  - `cipherlane-rs/tests/{crypto,protocol,cli,browser,consistency}.rs` —— 全部测试套件，
    由 `cargo test` 运行（浏览器套件用 Rust CDP 客户端驱动真实无头 Chrome）
- **浏览器端保持原生 JS 不动**：非安全上下文（明文 http 局域网）没有 `crypto.subtle`，
  纯 JS AES-256-GCM / SHA-256 / X25519 是产品必需能力，无法用 Rust 替代（WASM 会引入
  构建链与更大资产）。Rust 承担服务器/CLI/托盘 + 全部测试。
- **Node 彻底移除**：Node 版实现、Node 单文件可执行打包链、Node 测试运行器与旧的
  `test/*.mjs` 套件全部删除。仓库级零 Node：构建、运行、测试都只需要 Rust 工具链。
  浏览器前端 JS 由 Rust 测试通过 CDP 驱动 Chrome 验证。
- **三平台产物全部 Rust 原生构建**：
  - Linux：`cipherlane_<v>_amd64.deb` —— musl 静态 server + tray + cli，systemd 单元、
    桌面入口、托盘自启
  - Windows：`cipherlane_<v>_windows_x64.zip` —— `cipherlane.exe` + `cipherlane-cli.exe`，
    静态 CRT，无 VC++ 运行库依赖
  - macOS：`cipherlane_<v>_macos_universal.tar.gz` —— `lipo` 合并 x86_64 + arm64 的
    server/cli，附 `cipherlane.command` 启动器
- **版本号唯一来源** = `cipherlane-rs/Cargo.toml`；README（中/英）版本徽章与之一致，
  由 Rust 测试 `consistency` 强制校验（同时校验 `include_bytes!` ↔ `public/`、三个 bin
  源文件、五个测试目标存在，以及产品/构建/CI/文档命令块的零 Node 守卫）。
- **CI/发布**：CI = Rust 三 bin 构建 + `cargo test --release`（全量含浏览器/一致性）
  + musl 协议平价 + deb 打包冒烟；Release = 打 `v*` 标签后三平台原生构建并 `gh release`
  发布产物与统一 SHA256SUMS。

## 测试（v1.0 最终）

| 目标 | 覆盖 |
| --- | --- |
| `crypto` | 原 aesgcm/sha256/x25519/qrcode/avatar 五套迁移：FIPS/RFC 标准向量、随机交叉、AAD 与篡改/错位拒绝 |
| `protocol` | 原 protocol 26 组：在线/邀请/接受拒绝/上限/并发/ack 凭证/ETag/Host 门/413/配额/update/面板/SIGTERM 等，只测 Rust 服务器二进制 |
| `cli` | 原 CLI 11 组：devices / 直发 / 批量 / 续传 / v2 AAD 与 v1 回退 / listen+verify / 控制字符净化，真实子进程 |
| `browser` | 原 browser 19 组：Rust CDP 客户端驱动真实无头 Chrome，双页收发、错误路径、Worker 池、FSA 续传等 |
| `consistency` | 版本徽章 ↔ Cargo.toml、`include_bytes!` ↔ public/、bin/测试目标存在、零 Node 守卫 |

统一入口：

```bash
cargo build --release --manifest-path cipherlane-rs/Cargo.toml
cargo test  --release --manifest-path cipherlane-rs/Cargo.toml                    # 全部
cargo test  --release --manifest-path cipherlane-rs/Cargo.toml --test protocol    # 单个
```

迁移期曾用双实现平价（`CIPHERLANE_TEST_SERVER` / `CL_SERVER_BIN`）作为验收手段；
v1.0.0 起 Node 实现删除，测试只针对 Rust 二进制运行，平价钩子退化为“指定被测二进制”
的测试参数（`CIPHERLANE_SERVER_BIN` / `CIPHERLANE_CLI_BIN`，CI 用 musl 产物跑 protocol）。

## 迁移原则（已兑现）

- 浏览器端 JS 保持不动，纯 JS 加密路径继续由真实浏览器（Rust 测试驱动）覆盖。
- 线协议逐字节兼容：协议 v2（AAD = `cipherlane/chunk/v2|<room>|<index>`）+ v1 回退；
  `X-Chunk-Seq` 幂等重投；`X-Resume` 可续传语义不变。
- 测试覆盖强度不降：旧 `.mjs` 的断言点逐项迁移，标准向量与负向用例全部保留。

## 阶段记录

- **P0 工具链（完成）**：Rust stable + musl target；无 cc 环境的兜底方案已记录备查。
- **P1 服务器核心（2026-10-19 完成）**：全协议端点移植（presence / devices / offers 长轮询 /
  rooms / chunk 经典+可续传 / done / progress / ack 凭证 / version / shutdown 令牌双闸 /
  update / adopt）+ 静态资源编译期内嵌；断连检测用 `/proc/net/tcp` 轮询等价旧实现的
  `res.on('close')` 配额释放语义。
- **P2/P3（2026-10-19 完成）**：musl 静态 server/tray 进入 deb（deb 31MB → ≈1.3MB）；
  桌面集成 + 双主题图标 + 托盘自启；ksni 真·托盘（GNOME 需 AppIndicator 扩展）。
- **P4（2026-10-20 完成）**：CLI 全量 Rust 化（rustcrypto：aes-gcm / x25519-dalek / sha2，
  qrcodegen 生成二维码），与浏览器逐字节互通由既有 x25519/aesgcm 向量与真实浏览器
  互操作场景锁定。
- **测试 Rust 化（2026-10-20 完成）**：五套测试全部迁为 `cargo test` 目标，CDP 客户端
  用 `tungstenite` 直连 Chrome DevTools，不再有 Node 测试运行器。
- **v1.0.0 收尾（2026-10-20）**：删除 Node 实现、单文件可执行打包链、旧 `.mjs` 套件与
  Node 一致性脚本；`build/package.sh` 按宿主平台原生构建；新增 `release.yml`
  （三平台原生构建 + `gh release`）；README（中/英）与本文档同步为零 Node 的 Rust 单实现。

## 依赖面

- 服务器：`tiny_http`（**vendor 补丁版**，见 `vendor/tiny_http/PATCHES.md`）+ `serde_json`
  + `rand` + `base64` + `if-addrs`（+ `sha2` 用于 ETag，`rustls`/`webpki-roots` 用于
  https 更新源，`libc` 用于 unix 信号，后两者按 target 隔离）
- 托盘：`ksni`（zbus，纯 Rust，仅 Linux target）
- CLI：`sha2` / `aes-gcm` / `x25519-dalek` / `qrcodegen` / `rand` / `base64`
- 测试（dev-dependencies）：`tungstenite`（CDP over WebSocket）
- 服务器仍保持零知识：不引入任何需要接触明文/密钥的服务端加密库，CLI 的密码学依赖
  只在客户端二进制中。

## 已知边界 / 未在本机验证项

- 托盘仅 Linux（StatusNotifierItem / AppIndicator）；Windows/macOS 为终端运行 server/cli，
  无托盘。
- `browser` 测试需要 Chrome/Chromium：CI 的 ubuntu-latest 自带 google-chrome；本机缺失时
  测试内部打印跳过并以成功返回（与旧套件语义一致）；CI 设 `CIPHERLANE_REQUIRE_CHROME=1`
  把"无 Chrome"升级为失败，防止前端覆盖静默清零。
- Windows 构建在本机无法验证（需 Windows 环境）：由 CI 的 `windows-latest` 原生构建；
  静态 CRT 目标为 Windows 10/11 x64。
- macOS universal 构建在本机无法验证（需 macOS + Xcode CLT 的 `lipo`）：由 CI 的
  `macos-latest` 原生构建；未签名/未公证，首次运行需右键打开。
- 线协议兼容：v1.0 与 v0.5.x 线协议一致；v0.5.0+ 发送端与 v0.4.x 接收端不兼容
  （协议 v2 升级），两端需同时升级。

## v1.0 加固收口（2026-10-20，review 后全面优化）

Rust 化 review 发现的三类缺口全部修复：

- **连接层**：`tiny_http` 改为 vendor 补丁版（`vendor/tiny_http/`，`[patch.crates-io]`
  接入，差异见其 `PATCHES.md`）——请求头 16KiB 预算、每连接 60s 读/写超时（上游
  client.rs 本就内置 TimedOut→408 断连，只是从未有人设超时）、并发连接上限 256。
  旧 JS 运行时的默认防护（maxHeaderSize/headersTimeout 等）就此补齐，slowloris 面关闭。
- **优雅停机**：SIGTERM/SIGINT 由 `pthread_sigmask`+`sigwait` 专职线程消费——打印文案、
  停止向 worker 派发（unblock×WORKERS）、在途请求最多 250ms 排干（对齐旧版
  closeAllConnections 时点）、exit 0；`/api/shutdown` 走同一条排干路径（不再裸 exit）。
- **故障隔离**：worker 以 `catch_unwind` 包住 handler（单请求 panic 只丢该连接）；
  全部锁改为毒化恢复（`PoisonError::into_inner`），杜绝"一锁毒化级联团灭全部 worker"；
  `/api/update` 单飞等待 30s 有界 + panic 安全复位（Drop guard）。
- **`/api/update` 补 https**：引入 `rustls`（ring 后端，纯 Rust TLS）+ `webpki-roots`，
  支持 https、≤3 次 30x 重定向、chunked/Content-Length 双解码、响应上限 64KiB、
  URL 字符白名单（防 CRLF 注入上游请求行）。
- **并发窗口收口**：DEVICES_MAX / 建房双闸 / 全局与 per-IP 字节配额三处 check-then-act
  全部并入单一临界区（字节配额经 `ByteAccount::try_add` 原子检查+入账）。
- **协议边角对齐**：offer 的 hint 必须为 string（缺失/非 string → 400，对齐旧版）；
  `?i` 只接受唯一纯十进制参数（重复/百分号编码 → 400）；长轮询 per-IP 配额只在真正
  挂起时占用（即时应答不计数，对齐旧版）。
- **工程**：静态资源 `Arc<[u8]>` 零拷贝回源；死代码/警告清零；CI 增 Windows/macOS
  编译门禁（push/PR 即验证，不再等发版）、Chrome 必需断言（`CIPHERLANE_REQUIRE_CHROME=1`）、
  deb 巡检断言三 bin + postinst/prerm/postrm 齐全；release 校验 tag↔Cargo.toml 版本；
  deb 补 prerm（升级/卸载停服）/postrm（daemon-reload）；Windows zip 附 SmartScreen 提示。

## Rust 版 CI 首跑后的收口（2026-11-24）

- **tiny_http 任务池丢唤醒**（vendor 补丁 4，见 `vendor/tiny_http/PATCHES.md`）：上游把
  "已被唤醒、还没回到取任务循环"的线程仍算作空闲，浏览器并发建连时多出来的连接任务被
  塞进队列却没人认领——连接已被接受、请求一直没人读，页面停在 loading。4 核环境下约
  1/4 的页面加载中招（回环与局域网地址都会），这正是 Rust 版 CI 在 Linux 上首跑时
  browser 套件里 3 个"页面加载超时"的根因。空闲线程改为先预约再唤醒；回归 g28
  （按路径引入 vendored 的 `task_pool.rs` 直接驱动，上游实现下必失败）+ g27。
- **Windows / macOS 编译门禁补全**：`tests/screenshots.rs` 与 `protocol.rs` 的 g26 用到
  unix 专有接口（libc 原始 socket、SIGTERM），此前在 Windows 上编译测试目标必然失败。
  现按 unix 门控（同 `tests/cli.rs`）。本机用 scratch crate 对全部测试目标做了
  `cargo check --tests --target x86_64-pc-windows-msvc / aarch64-apple-darwin`（零错误
  零警告）；vendored tiny_http 另对 Windows / macOS / musl 三个目标做了类型检查。
  **Windows / macOS 仍然只验证"能编译"，一次都没有真跑过测试**（`tests/protocol.rs`
  的 g26 在 Windows 上不编译；`cli` / `screenshots` 为空目标）。
- **Release 工作流首次空跑**（`gh workflow run release.yml`，只出 artifact 不发布）：Linux 与
  Windows 产物构建成功，macOS 在 `build/package.sh` 第 267 行失败——`$t（server / cli）` 这种
  "变量名后紧跟全角字符"的写法在 macOS 自带的 bash 3.2 下会把后面的字节并进变量名，
  `set -u` 报 unbound variable（Linux 的 dash / bash 5 上正常，同一个 bash 3.2 在 Linux
  容器里也不复现）。相关写法改为 `${变量名}`，`tests/consistency.rs` 新增守卫。
- **v1.0.0 首次打 tag 发布**：三平台构建成功，Publish job 失败——"failed to run git:
  fatal: not a git repository"。该 job 没有 checkout，三条 `gh release` 命令都没带
  `--repo`（空跑不执行 publish job，所以空跑发现不了）。已改为显式 `--repo
  "$GITHUB_REPOSITORY"`；tag v1.0.0 重新指向修复后的提交，再由工作流发布。

