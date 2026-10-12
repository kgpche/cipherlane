<div align="center">

<img src="logo/02-shield-lane.svg" width="96" height="96" alt="cipherlane logo" />

# cipherlane · 密道

**局域网端到端加密传输 —— 局域网 AirDrop**

选设备直发（X25519 密钥协商）或链接收发，HTTP 明文环境下内容依然全程加密。

![version](https://img.shields.io/badge/version-0.2.0-37d4a0) ![node](https://img.shields.io/badge/node-%E2%89%A518-4285f4) ![tests](https://img.shields.io/badge/tests-4%E5%A5%97%E5%85%A8%E8%BF%87-f9ab00) ![license](https://img.shields.io/badge/license-MIT-8291b0)

</div>

---

## 目录

- [两种发送方式](#两种发送方式)
- [截图](#截图)
- [快速开始](#快速开始)
- [工作原理与协议](#工作原理与协议)
- [安全模型](#安全模型)
- [浏览器兼容性](#浏览器兼容性)
- [FAQ](#faq)
- [目录结构](#目录结构)
- [测试](#测试)
- [更新日志](#更新日志)
- [路线图](#路线图)
- [License](#license)

## 两种发送方式

| | 设备直发（默认） | 链接模式 |
| --- | --- | --- |
| 适用 | 局域网内，即选即发 | 跨网段 / 经微信、邮件发送 |
| 密钥 | X25519 在双方浏览器内协商派生，**永不过网** | 随机密钥藏于 URL `#fragment`，带外传递 |
| 防嗅探 / 防服务器翻日志 | ✓ / ✓ | ✓ / ✓ |
| 防服务器主动 MITM | ✗（公钥经服务器分发，见[安全模型](#安全模型)） | ✓（密钥不经服务器，完全零知识） |

一个局域网 IP = 一台终端：每台设备有**名称**（可改）、**几何头像**（由 IP 确定性生成，Material 扁平风）和 **X25519 身份密钥**（浏览器存 localStorage）。

## 截图

| 设备直发首页（在线设备网格 + 几何头像） | 链接模式发送完成 | 文本接收（解密即呈现） |
| :---: | :---: | :---: |
| <img src="docs/screenshots/landing.png" width="280" alt="首页设备网格" /> | <img src="docs/screenshots/send-done.png" width="280" alt="发送完成" /> | <img src="docs/screenshots/recv-text.png" width="280" alt="文本接收" /> |

页面任意位置 `Ctrl+V` 即可粘贴发送：截图/文件直接发，文本已选设备则直发、未选则填入输入框。

## 快速开始

```bash
node server.js            # 或 npm start；默认端口 7777，可用 PORT= 环境变量改
```

启动后打印局域网地址（如 `http://192.168.1.117:7777`）。其他设备连**同一 WiFi** 用浏览器打开：

1. 首页改好你的名字 → 对方出现在"在线设备"里
2. 点选设备 → 拖入文件 / 粘贴文本 → 对方页面弹出邀请卡片（含解密后的文件名与大小）→ 接受即收

无浏览器的机器用 CLI（与浏览器完全互通）：

```bash
node cli.mjs devices --server http://192.168.1.117:7777        # 查看在线设备
node cli.mjs send big.zip --to 192.168.1.50 --server http://... # 定向直发（无需传链接）
node cli.mjs listen --yes -o ~/downloads --server http://...    # 常驻接收端（可被直发）
node cli.mjs send big.zip --server http://...                   # 链接模式：打印接收链接
node cli.mjs recv 'http://.../#ROOM.KEY' [-o 保存路径]           # 链接模式接收
```

## 工作原理与协议

<details>
<summary>架构图（点开）</summary>

```
发送方浏览器/CLI                      局域网（HTTP 明文可被嗅探）              接收方浏览器/CLI
┌─────────────┐   设备发现/X25519公钥  ┌──────────────┐                     ┌─────────────┐
│ 选目标设备   │ ◀─────────────────▶ │  哑中继服务器  │ ◀────────────────▶ │ 在线列表被选中 │
│ ECDH 派生密钥 │     （只见公钥）      │  只见密文与流量 │    （只见公钥）      │ ECDH 派生密钥 │
│ AES-GCM 加密 │ ──── 密文分片 ────▶ │  邀请/中转/背压 │ ──── 密文分片 ────▶ │ AES-GCM 解密 │
└─────────────┘                     └──────────────┘                     └─────────────┘
     房间密钥 = SHA-256( X25519 双方私钥协商 ‖ 双方公钥 ‖ 房间号 )，两侧独立算出、一致
```

</details>

**协议一览**（全部端点见 `server.js`，限额为默认值）：

| 端点 | 作用 |
| --- | --- |
| `POST /api/presence` | 设备心跳注册（同 IP 最后写入者生效，5s 心跳 / 20s TTL） |
| `GET /api/devices` | 在线设备列表（IP / 名称 / X25519 公钥） |
| `POST /api/rooms` | 创建传输房间（房间号 10 位 base62 ≈ 59.6 bit） |
| `POST /api/rooms/:id/chunk` | 投递密文分片（1 MiB 明文/片，背压窗口 64 片，需 room token） |
| `GET /api/rooms/:id/chunk?i=N` | 顺序拉取（25s 长轮询，一次性消费） |
| `POST /api/rooms/:id/offer` | 挂载定向邀请（加密预览 hint，须在投递分片之前） |
| `GET /api/offers` | 长轮询本机待处理邀请（**secret + 来源 IP 双重绑定**） |
| `POST /api/offers/:id/accept\|reject` | 接受 / 拒绝（拒绝后房间保留 2 分钟供发送方观测） |
| `POST /api/rooms/:id/done` / `ack` | 发送完毕 / 接收确认；房间空闲 15 分钟自动回收 |

限额：单房间 64 分片 / 64 MB 背压，全局 256 MB，单设备待处理邀请 ≤ 8（TTL 5 分钟），设备表 ≤ 256。

## 安全模型

| 威胁 | 防护 |
| --- | --- |
| 局域网嗅探（明文 HTTP） | 内容、文件名、类型全部 AES-256-GCM 加密，密文分片独立验签 |
| 运行服务器的人（链接模式） | 零知识：随机密钥经 URL `#fragment` 点对点传递，永不到达服务器 |
| 运行服务器的人（设备直发） | 房间密钥由 X25519 协商派生，服务器只见公钥与密文，事后翻日志无法解密 |
| 偷走设备 secret | 无效：领取邀请需 **secret 与来源 IP 同时匹配**，换台机器即 401 |
| 链接被无关者拿到 | 房间号不可枚举；分片顺序一次性消费，一人取走他人即 410 |
| 传输中被篡改 | GCM 认证标签逐分片校验；邀请预览验签失败自动拒绝 |
| 冒充发送方投毒 | 投递分片需持有随机 room token（仅发送方内存中有） |
| 小阶点 / 无效公钥攻击 | X25519 共享密钥全零即拒绝（RFC 7748 要求） |
| 房间滥用占内存 | 见上文限额，空闲自动回收 |

**已知边界（如实说明）**：

- **设备直发无法防服务器主动 MITM**：设备公钥由服务器分发，恶意服务器理论上可调包公钥冒充接收方。防"被动嗅探 / 被动翻日志"成立，防"主动欺骗"不成立——极高安全需求请用链接模式。与 AirDrop 等无带外验证的方案是同一取舍（路线图中有"公钥指纹核验"对策）
- 设备名称与在线状态对服务器及局域网内打开页面的用户可见——这是"设备发现"的固有代价
- 接收不支持断点续传：分片顺序一次性消费，刷新页面需发送方重发
- 恶意丢弃流量属于 DoS，可检测（传输卡住/报错）但无法防止
- 同一 IP 多个**不同浏览器**同时在线时，设备条目以后注册者为准（同浏览器多标签已通过共享 secret 解决）

**技术上如何做到 http 下也能加密**：浏览器 `crypto.subtle` 只在安全上下文存在。本项目自带纯 JS 实现，非安全上下文自动降级：AES-256-GCM（`public/aesgcm.js`）、SHA-256（`public/sha256.js`）、X25519（`public/x25519.js`，BigInt + RFC 7748 Montgomery 阶梯）；localhost/https 下 AES 走原生 WebCrypto。纯 JS 与 node:crypto 原生逐字节一致（有测试）。

## 浏览器兼容性

| 要求 | 说明 |
| --- | --- |
| BigInt（X25519 需要） | Chrome 67+ / Edge 79+ / Firefox 68+ / Safari 14+ |
| 流式保存（可选） | Chromium 系支持 `showSaveFilePicker`；其他浏览器自动回退内存模式下载 |
| 粘贴发送（可选） | 支持剪贴板事件的现代浏览器；移动端长按粘贴进文本框即可 |

CLI 需要 Node ≥ 18（原生 X25519 与 AES-GCM）。

## FAQ

**改版 / 重启服务器后页面还是旧样子？**
静态资源在服务器启动时读入内存，浏览器也可能复用旧标签页——**关掉标签重开**或强制刷新（Ctrl+Shift+R）。

**启动报 `EADDRINUSE: 7777`？**
端口被占用。`PORT=7788 node server.js` 换端口，或找到占用的旧进程停掉。

**手机上看不到设备 / 别人看不到我？**
必须连**同一个 WiFi / 网段**；首次使用注意系统防火墙是否放行了端口（Windows 会弹一次询问）；确认打开的是启动时打印的局域网地址而不是 `127.0.0.1`（回环只有本机能访问）。

**在 ZCode / Electron 等嵌入式浏览器里弹窗不生效？**
部分嵌入式 webview 的 `alert/confirm` 与文件保存器不可用，属宿主限制。正式使用建议系统浏览器（Chrome / Edge / Safari）。

**发大文件接收方刷新了页面怎么办？**
当前不支持断点续传，重新发一次即可（路线图项）。

**纯 JS 降级路径速度如何？**
约 10–20 MB/s（每 1 MiB 分片独立加解密）；localhost / https 下走原生 WebCrypto 更快。X25519 为毫秒级，无感。

## 目录结构

```
cipherlane/
├── server.js           # 零依赖中继服务器：房间 + 设备在线 + 邀请（Node 内置模块 only）
├── cli.mjs             # 命令行：devices / 定向发送 / listen 常驻接收 / 链接收发
├── logo/               # Logo：盾上密径（主/小尺寸母版 + 全部提案 preview.html）
├── docs/screenshots/   # README 截图
├── public/
│   ├── index.html      # 单页应用（设备网格 · 几何头像 · 邀请卡片 · 双接收布局）
│   ├── app.js          # 收发逻辑 + 双加密路径 + X25519 身份
│   ├── aesgcm.js       # 纯 JS AES-256-GCM（http 降级路径）
│   ├── sha256.js       # 纯 JS SHA-256（密钥派生 KDF）
│   ├── x25519.js       # 纯 JS X25519（设备直发密钥协商）
│   ├── avatar.js       # 设备几何头像（Material 扁平风，由 IP 确定性生成）
│   └── style.css
└── test/               # aesgcm / sha256 / x25519 / protocol 四套
```

## 测试

```bash
npm test    # 或逐个: node test/<name>.test.mjs
```

- **aesgcm**：S-box 标准向量、GHASH 交叉验证、0B~1MiB 与 node 原生逐字节比对
- **sha256**：FIPS 180-4 向量 + 500 组随机交叉
- **x25519**：RFC 7748 向量 + 200 组随机 vs node ECDH 双向、小阶点拒绝
- **protocol**：起真实 server，覆盖在线/邀请/接受/拒绝/上限/同 IP 轮换/链接模式全链路

## 更新日志

**v0.2.0**（2026-10-12）
- 设备直发：一个 IP = 一台终端（名称 / 几何头像 / X25519 身份），选设备即发、邀请卡片、接受/拒绝
- 纯 JS X25519 + SHA-256（RFC 7748 / FIPS 180-4，与 node 原生互通有测试）
- 接收端文本 / 文件两套独立布局；页面任意位置 Ctrl+V 粘贴即发
- 发送视图终态修复（完成后"返回首页"、进度 100%、拒绝消息不被覆盖）
- CLI：`devices` / `--to` 定向发送 / `listen` 常驻接收
- Logo 定稿「盾上密径」并集成页头与 favicon

**v0.1.0**（2026-10-11）
- 链接模式端到端加密传输：AES-256-GCM、零知识中继、纯 JS 加密降级路径、CLI 收发

## 路线图

- [ ] 纯 JS AES 路径性能优化（T-table / SIMD 化 GHASH）
- [ ] 二维码展示接收链接（手机扫码）
- [ ] 多文件 / 目录传输
- [ ] 断点续传（分片可重放 + 位置协商）
- [ ] 设备直发的公钥指纹核验（对抗服务器主动 MITM）

## License

[MIT](LICENSE) © 2026 joker
