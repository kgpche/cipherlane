# tiny_http 0.12.0（cipherlane vendor 补丁版）

上游：https://github.com/tiny-http/tiny-http （crates.io 0.12.0，MIT OR Apache-2.0）
本目录是上游 0.12.0 的拷贝 + 以下四处补丁，经 `[patch.crates-io]` 生效。
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

### 4. `src/util/task_pool.rs` —— 任务池不丢唤醒（连接被接受后必须有人处理）

- **问题**：上游 `TaskPool::spawn` 用一把独立的原子计数 `waiting_tasks` 判断"有没有空闲
  线程在等"：线程在调用 `wait` 之前加一、醒来回到循环之后才减一。于是"已经被
  `notify_one` 唤醒、但还没抢到锁回到循环"的线程仍被算作空闲。浏览器打开一个页面会
  并发建立约 6 条 keep-alive 连接，accept 线程把它们接连收下并 spawn：前几次 notify
  唤醒了全部 4 个常驻线程，之后的 spawn 读到的计数仍 > 0，于是把任务塞进队列再
  notify——此时已经没有真正睡在 condvar 上的线程，信号落空。被唤醒的线程各取走一个
  任务后，多出来的任务就一直躺在队列里，直到某个线程干完活回到循环才被捡起。对
  keep-alive 连接来说就是：连接已被接受、请求字节堆在内核接收队列里，却一直没人读。
- **影响**：页面加载偶尔缺一两个静态资源、一直停在 loading（浏览器每主机 6 条连接，
  第 5、6 条最容易中招）。核越少、调度越慢越容易撞上：16 核开发机上极少见，整机压到
  4 核（CI runner、NAS、树莓派的量级）实测约 1/4 的页面加载中招。回环地址与局域网
  地址都会出现，与地址无关。
- **修法**：待办队列与空闲线程计数放进同一把锁（`state: Mutex<State>`），用两个计数
  精确描述空闲线程：`waiting`（已登记为空闲、尚未被任何 spawn 预约）与 `reserved`
  （spawn 已从 waiting 扣减、尚未被某个被唤醒线程认领的预约）。spawn 先预约
  （`waiting -= 1; reserved += 1`）再 `notify_one`；被唤醒的线程回到循环时认领预约
  （`reserved -= 1`），若是超时或虚假唤醒（没人预约过）则自己撤销空闲登记。任何时刻
  `waiting` 都不会把"已唤醒未回循环"的线程算进去：并发到达的 spawn 要么各预约到不同
  的线程，要么发现没有可预约的空闲线程而直接开新线程。线程的创建、5 秒空闲退出、
  `MIN_THREADS` 语义与上游一致。
- **回归**：`tests/protocol.rs` 的 g28 按路径把本文件引入测试目标直接驱动 TaskPool
  （本线程与池线程钉在同一个 CPU 上，一口气 spawn 8 个长任务）：上游实现下必失败
  （只有 4 个任务开始执行），修复后全过。g27 是经由真实服务器的突发连接冒烟。真实
  页面加载的对照：整机钉在 4 核上加载页面 60 次，修复前约 1/4 停在 loading，修复后
  0/60；browser 套件钉在 4 核上连跑 6 次，修复前每次都有页面加载超时，修复后全绿。

## 未改动

- 协议解析、请求/响应语义、keep-alive、100-continue、SSL 特性全部保持上游原样。

## 附带清理（不影响行为）

- `src/util/mod.rs`：删除未被使用的 `SequentialWriter` 再导出（上游自带的 unused 警告）。
- `src/lib.rs`：`MustBeShareDummy` trait 加 `#[allow(dead_code)]`（上游自带的 dead_code 警告）。
- `src/connection.rs`：新增 `set_timeouts` 帮助方法（补丁 2 使用的平台统一入口）。
- `src/connection.rs`：`PathBuf` 只在 unix 分支（Unix 域套接字）使用，import 加
  `cfg(unix)`——上游在 Windows 上留下一条 unused import 警告（CI 的三平台编译门禁要求零警告）。

