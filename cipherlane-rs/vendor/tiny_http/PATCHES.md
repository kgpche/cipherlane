# tiny_http 0.12.0（cipherlane vendor 补丁版）

上游：https://github.com/tiny-http/tiny-http （crates.io 0.12.0，MIT OR Apache-2.0）
本目录是上游 0.12.0 的逐字节拷贝 + 以下三处补丁，经 `[patch.crates-io]` 生效。
升级上游时请重新套用并保留差异说明。

## 补丁动机

原版 tiny_http 0.12 对连接层没有任何限制：请求头逐字节读入无上限的 `Vec`、
socket 从不设置读/写超时、每连接一个可无界繁殖的池线程。在 v0.x 中这些防护
由 Node 运行时默认提供（`maxHeaderSize`=16KiB、`headersTimeout`=60s 等），
Rust 化后缺失，构成局域网内单主机即可打瘫服务的 slowloris 面（见 v1.0 review）。

## 差异清单

### 1. `src/client.rs` —— 请求头总预算（对齐 Node `maxHeaderSize`）

- 新增常量 `MAX_HEAD_BYTES = 16 * 1024`。
- `read_next_line(&mut self)` → `read_next_line(&mut self, budget: &mut usize)`：
  请求行 + 所有头行的总字节数计入预算，超出返回 `InvalidData` 错误。
  该错误在 `ClientConnection::next()` 中落入 `ReadIoError(_) => return None`
  分支，直接关闭连接（无响应写出）。

### 2. `src/lib.rs` —— 每连接读/写超时（对齐 Node `headersTimeout` 上界）

- 新增常量 `READ_TIMEOUT` / `WRITE_TIMEOUT`（各 60s）。
- accept 循环对每个新 socket 调用 `set_read_timeout` / `set_write_timeout`。
- 上游 `client.rs` 本就内置对 `ErrorKind::TimedOut` 的处理（回 408 并断连），
  只是从来没有人设置超时——补丁只补上这一步。空闲 keep-alive 连接也会因此
  在 60s 后被 408 关闭，浏览器会自动重连，与 Node `keepAliveTimeout` 语义一致。

### 3. `src/lib.rs` —— 并发连接上限

- 新增常量 `MAX_CONNECTIONS = 256`、静态计数 `ACTIVE_CONNECTIONS` 与
  RAII 守卫 `ActiveConnGuard`（在任务池任务开始时 acquire、连接结束时 drop）。
- 超过上限的新连接被立即关闭（不 accept 进处理循环），客户端重试即可。
  上限同时约束了任务池线程数的上界（每连接至多一个池线程）。

## 未改动

- 协议解析、请求/响应语义、keep-alive、100-continue、SSL 特性全部保持上游原样。

## 附带清理（不影响行为）

- `src/util/mod.rs`：删除未被使用的 `SequentialWriter` 再导出（上游自带的 unused 警告）。
- `src/lib.rs`：`MustBeShareDummy` trait 加 `#[allow(dead_code)]`（上游自带的 dead_code 警告）。
- `src/connection.rs`：新增 `set_timeouts` 帮助方法（补丁 2 使用的平台统一入口）。

