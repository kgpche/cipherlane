# Rust 重构计划（分阶段、协议兼容优先）

## 原则
- **浏览器端保持 JS 不动**：非安全上下文（http 局域网）的纯 JS 加密（AES-GCM/X25519/SHA-256）
  无法用 Rust 替代（WASM 需要构建链与更大资产，破坏零构建理念）。Rust 重构范围 = 服务器 + CLI + 原生托盘。
- **线协议逐字节兼容**：现有 8 套测试（protocol 14 组 / cli 6 组 / browser 10 组）为验收标准。
  测试增加 `CIPHERLANE_TEST_SERVER` 环境变量,可对 Node 版或 Rust 版跑同一套断言（平价对照引擎）。
- **迁移期 Node 版保留**,Rust 版达成全绿后切换打包,Node 版转维护模式。

## 阶段
- P0 工具链：`sudo apt install build-essential`（宿主构建脚本需要 cc;musl 静态目标交叉产物）
- P1 服务器核心（本 crate）：静态资源(编译期内嵌 include_bytes,等价 SEA)、rooms/chunks 长轮询/背压、
  presence/devices/offers、done/ack、清扫。验收 = protocol 测试对 Rust 全绿。
- P2 面板端点(version/shutdown 令牌/update) + 打包：musl 静态单文件(≈3-5MB,替代 125MB SEA)、
  deb(桌面集成沿用)、Windows(cross x86_64-pc-windows-gnu)、macOS。
- P3 真·系统托盘（ksni crate,GNOME 需 AppIndicator 扩展——Ubuntu 自带）：菜单 打开/开启/退出/关于/检查更新。
- P4 CLI 重构（rustcrypto：aes-gcm/x25519-dalek/sha2,与浏览器逐字节互通用现有 x25519 测试向量锁定）。

## 备注
- 无 cc 环境的兜底（已验证到链接层,记录备查）：~/.local/bin/ld-shim 用自带 rust-lld 做 cc→ld 方言翻译,
  宿主 glibc 链接可通但构建脚本运行异常——正式环境直接装 build-essential。
- 依赖面：tiny_http + serde_json + rand + base64（服务器零知识,无需任何加密库）。

## P1 完成记录（2026-10-19）
- 全协议端点移植：presence/devices/offers 长轮询/rooms/chunk(经典+X-Resume 可续传)/
  done/progress/ack(凭证)/version/shutdown(令牌双闸)/update + 14 项静态资源编译期内嵌
- 平价验证：protocol 14 组、cli 6 组、browser 10 组全部对 Rust 版跑通
  （CIPHERLANE_TEST_SERVER / CL_SERVER_BIN 环境变量切换被测实现）
- 断连检测：/proc/net/tcp 轮询(100ms 片)等价 Node res.on('close') 的配额释放语义
- 产物：release 单文件 ~800KB（Node SEA 125MB 的 1/156）；EADDRINUSE 友好提示保留
- P2 待办：musl 静态构建入打包脚本、deb/exe/osx 切换 Rust 产物；P3 真·托盘(ksni)

## P2/P3 完成记录（2026-10-19）
- P3 真·系统托盘（ksni 0.3 + 纯 Rust zbus，零系统 libdbus 依赖）：
  菜单 = 打开主页/打开控制面板/启动服务/停止服务/检查更新/关于/退出托盘；
  托盘启动的服务持停机令牌；assume_sni_available 兼容 ubuntu:GNOME（watcher 未注册场景）；
  D-Bus 注册验证通过（org.kde.StatusNotifierItem-*）
- P2 deb 切换 Rust：cipherlane(musl 静态 0.9MB) + cipherlane-tray(2.3MB) +
  /etc/xdg/autostart 自启 + 双主题图标（运行绿盾/停止灰盾）；
  deb 31MB → 1.1MB；无 Rust 工具链时回退 Node SEA
- Windows/macOS 暂留 Node SEA（待 mingw/osxcross 交叉工具链）
