// cipherlane · 密道 —— Rust 版服务器
//
// 线协议为唯一实现；验收 = cargo test --test protocol（Rust 集成测试）对本实现全绿。
// 架构：tiny_http（vendor 补丁版：请求头 16KiB 预算 / 每连接 60s 读写超时 /
// 并发连接上限 256 / 任务池不丢唤醒，见 vendor/tiny_http/PATCHES.md）+ 全部监听地址共用
// 一组工作线程（每个监听器只有一条"泵"线程在 recv() 上等，见"监听器（动态绑定）"）；
// 监听地址动态维护：HOST 未设时每 1s、以及每次 /api/version，重新枚举 RFC1918 网卡地址，
// 新地址补上监听——开机时服务总是先于 Wi-Fi 启动，只在启动时枚举一次会让它整个开机周期
// 都只监听回环（别的设备连不上）；笔记本换网络 / 休眠唤醒后地址变化同理；
// worker 带 panic 隔离（catch_unwind）与锁毒化恢复，单个请求异常不波及服务；
// 长轮询以 Condvar 挂起（LAN 规模下每接收方 ≤4 个挂起请求，线程余量充足）；
// 优雅停机：sigwait 专职线程 → 停止派发 → 250ms 排干 → exit 0（对齐 Node 语义）。
// 零知识：服务器只存转 AES-256-GCM 密文分片，永不做任何加解密。
// 锁序：rooms → room.inner → global_buffered → ip_bytes（全程按此序获取）。
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Response, Server};

// ---------- 限制（与 v0.x Node 版一致） ----------
const ROOMS_MAX: usize = 128;
const BODY_MAX: usize = 1536 * 1024;
const ROOM_CHUNKS_BUF: u64 = 64;
const ROOM_BYTES_MAX: usize = 64 * 1024 * 1024;
const GLOBAL_BYTES_MAX: usize = 256 * 1024 * 1024;
const ROOM_IDLE_MS: u128 = 15 * 60 * 1000;
const ACK_IDLE_MS: u128 = 2 * 60 * 1000;
const LONGPOLL: Duration = Duration::from_secs(25);
// 长轮询挂起期间的断连检测周期（每次检测整读一遍 /proc/net/tcp，见 conn_alive）。
// 内核按全机 socket 数生成这张表，台式机上实测一次约 3.6ms；而每个打开的页面常驻一条
// 邀请长轮询：100ms 周期下每条挂起连接约占 3.6% 单核（5 台设备常驻约 18%），二十几条
// 就吃满一核。放宽到 1s 后降到约 0.36%；代价是客户端断开后 worker 线程与 per-IP
// 长轮询配额最多多占 1s 才释放（新数据的到达仍由 Condvar 即时唤醒，不受此周期影响）。
const ALIVE_SLICE: Duration = Duration::from_secs(1);
const LONGPOLL_PER_IP: i32 = 8;
const DEVICE_TTL_MS: u128 = 20 * 1000;
const DEVICE_MEM_MS: u128 = 5 * 60 * 1000;
const DEVICES_MAX: usize = 256;
const DEVICE_NAME_MAX: usize = 32;
const OFFER_TTL_MS: u128 = 5 * 60 * 1000;
const OFFERS_MAX: usize = 8;
const REJECT_GRACE_MS: u128 = 2 * 60 * 1000;
// per-IP 配额：防止单个局域网 IP 耗尽全站房间/内存（CIPHERLANE_TEST_LIMITS=1 仅供测试降阈值）
const PER_IP_ROOMS: usize = 64;
const PER_IP_BYTES: usize = 96 * 1024 * 1024;
const ROOM_CREATE_PER_MIN: usize = 120;
const UPDATE_CACHE_MS: u128 = 5 * 60 * 1000;
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
// 工作线程：全部监听地址共用 256 个（= vendored tiny_http 的并发连接上限，最坏情况下每个
// 连接一个挂起的长轮询也各有 worker），128KB 小栈。此前是"每监听地址各 128 个"，动态
// 补绑地址后那种分法会让线程数随见过的网卡地址成倍增长；共用池每多一个地址只多 1 条泵线程。
// 总数仍少于过去三个地址各 128 个（384）；小栈把虚拟内存从 2MB/线程压到 128KB。
const WORKERS: usize = 256;
const WORKER_STACK: usize = 128 * 1024;
const ROOM_ID_LEN: usize = 10;

const B62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const VERSION: &str = env!("CARGO_PKG_VERSION");
static PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(7777);

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

// ---------- 静态资源（编译期内嵌，等价 SEA） ----------
// data 用 Arc：每请求响应只克隆指针（app.js 等较大文件高频回源时不再整体拷贝）
struct StaticFile {
    data: Arc<[u8]>,
    ctype: &'static str,
    etag: String,
}
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}
fn static_routes() -> Vec<(&'static str, StaticFile)> {
    let sf = |data: &'static [u8], t: &'static str| {
        let data: Arc<[u8]> = Arc::from(data.to_vec());
        let etag = format!("\"{}\"", sha256_hex(&data));
        StaticFile { data, ctype: t, etag }
    };
    let mut v: Vec<(&'static str, StaticFile)> = vec![
        ("/", sf(include_bytes!("../../public/index.html"), "text/html; charset=utf-8")),
        ("/app.js", sf(include_bytes!("../../public/app.js"), "text/javascript; charset=utf-8")),
        ("/aesgcm.js", sf(include_bytes!("../../public/aesgcm.js"), "text/javascript; charset=utf-8")),
        ("/sha256.js", sf(include_bytes!("../../public/sha256.js"), "text/javascript; charset=utf-8")),
        ("/x25519.js", sf(include_bytes!("../../public/x25519.js"), "text/javascript; charset=utf-8")),
        ("/avatar.js", sf(include_bytes!("../../public/avatar.js"), "text/javascript; charset=utf-8")),
        ("/qrcode.js", sf(include_bytes!("../../public/qrcode.js"), "text/javascript; charset=utf-8")),
        ("/crypto-worker.js", sf(include_bytes!("../../public/crypto-worker.js"), "text/javascript; charset=utf-8")),
        ("/logo.svg", sf(include_bytes!("../../logo/02-shield-lane.svg"), "image/svg+xml")),
        ("/logo-small.svg", sf(include_bytes!("../../logo/02-shield-lane-small.svg"), "image/svg+xml")),
        ("/style.css", sf(include_bytes!("../../public/style.css"), "text/css; charset=utf-8")),
        ("/panel", sf(include_bytes!("../../public/panel.html"), "text/html; charset=utf-8")),
        ("/panel.js", sf(include_bytes!("../../public/panel.js"), "text/javascript; charset=utf-8")),
        ("/panel.css", sf(include_bytes!("../../public/panel.css"), "text/css; charset=utf-8")),
    ];
    for e in v.iter_mut() {
        if e.0 == "/" {
            let s = String::from_utf8_lossy(&e.1.data).replace("__VERSION__", VERSION);
            e.1.data = Arc::from(s.into_bytes());
            // ETag 必须基于替换版本号后的最终字节（与 Node 的读取顺序一致）
            e.1.etag = format!("\"{}\"", sha256_hex(&e.1.data));
        }
    }
    v
}

// ---------- 领域状态 ----------
struct Offer {
    id: String,
    to_ip: String,
    from_ip: String,
    from_name: Option<String>,
    pub_: String,
    hint: String,
    state: Mutex<String>,
    created_at: u128,
}
struct RoomInner {
    token: String,
    posted: u64,
    head: u64,
    pulled: u64,
    buffer: HashMap<u64, Arc<Vec<u8>>>,
    bytes: usize,
    receiver_seen: bool,
    sender_done: bool,
    acked: bool,
    ack_proof: Option<String>,
    resumable: bool,
    through: u64,
    rejected_at: Option<u128>,
    offer: Option<Arc<Offer>>,
    dead: bool,
}
struct Room {
    id: String,
    sender_ip: String,
    last_active: Mutex<u128>,
    inner: Mutex<RoomInner>,
    cond: Condvar,
}
struct Device {
    ip: String,
    id: String,
    secret: String,
    name: Mutex<String>,
    pub_: Mutex<String>,
    last_seen: Mutex<u128>,
}
struct World {
    // 锁获取统一用 unwrap_or_else(PoisonError::into_inner)（毒化恢复）：配合 worker 的
    // catch_unwind，单个请求 panic 至多留下计数/集合的轻微漂移（Rust 保证结构始终
    // 内存安全），不允许毒化连锁击杀其余 worker（Node 版等价行为：try/catch 后继续服务）。
    rooms: Mutex<HashMap<String, Arc<Room>>>,
    devices: Mutex<HashMap<String, Arc<Device>>>,
    offers_by_id: Mutex<HashMap<String, String>>,
    global_buffered: Mutex<usize>,
    // ip → 当前滞留密文字节（与 global_buffered 同点增减）
    ip_bytes: Mutex<HashMap<String, usize>>,
    // ip → 最近 60s 建房时间戳（滑动窗口限流）
    ip_creates: Mutex<HashMap<String, Vec<u128>>>,
    longpoll_count: Mutex<HashMap<String, i32>>,
    offers_mutex: Mutex<()>,
    offers_cond: Condvar,
    started_at: u128,
}
// 运行期可调限额：CIPHERLANE_TEST_LIMITS=1 时降为测试阈值（速率保持 120/min）
struct Limits {
    ip_rooms_max: usize,
    ip_bytes_max: usize,
}
// /api/update 的 5min 成功缓存 + 并发去重（in-flight 共享同一上游结果）
#[derive(Default)]
struct UpdateState {
    cache: Option<(u128, String)>,
    inflight: bool,
    last_result: Option<String>,
}
// 单飞标志的 panic 安全复位：fetch_update 期间 panic（被 worker 的 catch_unwind
// 隔离）时由 Drop 复位 inflight 并唤醒等待者，避免后来请求永久挂起
struct UpdateInflightGuard<'a>(&'a Ctx);
impl Drop for UpdateInflightGuard<'_> {
    fn drop(&mut self) {
        let mut st = self.0.update.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.inflight {
            st.inflight = false;
            self.0.update_cond.notify_all();
        }
    }
}
// 密文字节记账（room.bytes / global_buffered / ip_bytes 必须在同一处成对增减）
struct ByteAccount<'a> {
    global: &'a Mutex<usize>,
    ip_bytes: &'a Mutex<HashMap<String, usize>>,
    ip: &'a str,
}
impl ByteAccount<'_> {
    fn del(&self, inner: &mut RoomInner, n: usize) {
        if n == 0 {
            return;
        }
        inner.bytes = inner.bytes.saturating_sub(n);
        counter_sub(self.global, n);
        ip_bytes_sub(self.ip_bytes, self.ip, n);
    }
    /// 原子上账：在同一组全局锁（global_buffered → ip_bytes，锁序见文件头）下
    /// 检查并加上 n 字节；任一全局/per-IP 配额不满足则不动任何计数返回 false。
    /// 房间级配额（outstanding/room bytes）由调用方在 inner 锁内自查。
    /// 与 del 的锁序一致，跨房间的检查+入账不再有 TOCTOU 窗口。
    fn try_add(&self, inner: &mut RoomInner, n: usize, global_max: usize, ip_max: usize) -> bool {
        let mut g = self.global.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut ipm = self.ip_bytes.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let ip_used = ipm.get(self.ip).copied().unwrap_or(0);
        if *g + n > global_max || ip_used + n > ip_max {
            return false;
        }
        inner.bytes = inner.bytes.saturating_add(n);
        *g = g.saturating_add(n);
        ipm.insert(self.ip.to_string(), ip_used.saturating_add(n));
        true
    }
}
fn ip_bytes_sub(map: &Mutex<HashMap<String, usize>>, ip: &str, n: usize) {
    let mut m = map.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let left = m.get(ip).copied().unwrap_or(0).saturating_sub(n);
    if left > 0 {
        m.insert(ip.to_string(), left);
    } else {
        m.remove(ip);
    }
}

// ---------- 工具 ----------
fn rand_room_id() -> String {
    let mut rng = rand::thread_rng();
    let mut s = String::with_capacity(ROOM_ID_LEN);
    while s.len() < ROOM_ID_LEN {
        let b: u8 = rng.gen();
        if b < 248 {
            s.push(B62[(b % 62) as usize] as char) // 拒绝采样消除模偏置
        }
    }
    s
}
fn rand_hex16() -> String {
    format!("{:016x}", rand::thread_rng().gen::<u64>())
}
fn rand_secret32() -> String {
    let b: [u8; 16] = rand::thread_rng().gen();
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn client_ip(req: &tiny_http::Request) -> String {
    match req.remote_addr() {
        Some(SocketAddr::V6(v6)) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.ip().to_string(),
        },
        Some(SocketAddr::V4(v4)) => v4.ip().to_string(),
        None => String::new(),
    }
}
fn hdr(req: &tiny_http::Request, name: &'static str) -> String {
    req.headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().trim().to_string())
        .unwrap_or_default()
}
// 取某个头的全部原始值（不做 trim）。tiny_http 的 value 是 AsciiString，取字节不会引入
// UTF-8 假设；同名头可能重复出现，调用方按 Node 的合并语义决定如何处理。
fn hdr_values(req: &tiny_http::Request, name: &'static str) -> Vec<Vec<u8>> {
    req.headers().iter().filter(|h| h.field.equiv(name)).map(|h| h.value.as_bytes().to_vec()).collect()
}
fn h(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).unwrap()
}
fn json_resp(res: tiny_http::Request, code: u16, body: String) {
    let _ = res.respond(
        Response::from_string(body)
            .with_status_code(code)
            .with_header(h("Content-Type", "application/json; charset=utf-8"))
            .with_header(h("Cache-Control", "no-store"))
            .with_header(h("X-Content-Type-Options", "nosniff")),
    );
}
fn jerr(mut res: tiny_http::Request, code: u16, err: &str) {
    // tiny_http 无法从响应侧强制关闭 keep-alive 连接（Connection 头会被剥离）。很多拒绝
    // 路径（Host/Origin 闸门、token 403 等）在读取请求体之前就返回，连接上残留的 body
    // 会被当成下一个请求解析成 400。因此这里先排空请求体再响应：已知 Content-Length
    // 时精确读取（限量 BODY_MAX+1KiB），未知长度时最多读同样上限；超大 body 不排空，
    // 避免被慢速攻击者占住 worker。
    let cap = BODY_MAX + 1024;
    match res.body_length() {
        Some(n) if n <= cap => {
            let mut buf = vec![0u8; n];
            let _ = res.as_reader().read_exact(&mut buf);
        }
        None => {
            let mut sink = Vec::new();
            let _ = res.as_reader().take(cap as u64).read_to_end(&mut sink);
        }
        Some(_) => { /* 声明的 body 超大：不排空，交给客户端/连接超时处理 */ }
    }
    let _ = res.respond(
        Response::from_string(format!("{{\"error\":\"{}\"}}", err))
            .with_status_code(code)
            .with_header(h("Content-Type", "application/json; charset=utf-8"))
            .with_header(h("Cache-Control", "no-store"))
            .with_header(h("X-Content-Type-Options", "nosniff")),
    );
}
fn read_body(req: &mut tiny_http::Request, cap: usize) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut reader = req.as_reader().take((cap + 1) as u64);
    if reader.read_to_end(&mut buf).is_err() {
        return Some(Vec::new());
    }
    if buf.len() > cap {
        return None; // 413
    }
    Some(buf)
}
fn valid_pub(p: &str) -> bool {
    p.len() == 43 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn valid_room_id(s: &str) -> bool {
    s.len() == ROOM_ID_LEN && s.bytes().all(|b| b.is_ascii_alphanumeric())
}
fn touch(room: &Room) {
    *room.last_active.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = now_ms();
}
// 全局缓冲计数：减法都走 counter_sub（与 destroy_room / take_chunk / advance_through 串行），
// saturating_sub 兜底——即使将来记账出错，也不会留下巨大计数把全站上传永久顶死；
// 产线加值走 ByteAccount::try_add（原子检查+入账），counter_add 仅供测试构造场景。
fn counter_sub(c: &Mutex<usize>, n: usize) {
    let mut g = c.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    *g = g.saturating_sub(n);
}
// X-Chunk-Seq 严格解析：只接受十进制非负整数，拒绝符号、中间空白、非数字和溢出。
// 首尾允许 HTTP OWS（空格 / 制表符）——Node 的 req.headers 会去掉首尾空白，这里对齐；
// 上限对齐 Node 的 Number.isSafeInteger（2^53-1），超过按 400 bad-seq 处理而不是 409。
const CHUNK_SEQ_MAX: u64 = 9_007_199_254_740_991; // 2^53 - 1
fn parse_chunk_seq(raw: &[u8]) -> Option<u64> {
    let mut lo = 0usize;
    let mut hi = raw.len();
    while lo < hi && (raw[lo] == b' ' || raw[lo] == b'\t') {
        lo += 1;
    }
    while hi > lo && (raw[hi - 1] == b' ' || raw[hi - 1] == b'\t') {
        hi -= 1;
    }
    if lo == hi {
        return None;
    }
    let mut v: u64 = 0;
    for &b in &raw[lo..hi] {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
        if v > CHUNK_SEQ_MAX {
            return None;
        }
    }
    Some(v)
}

// ---------- 安全 / 兼容工具 ----------
// 常量时间比较：长度不同直接 false；长度相同按字节 OR 累积差异（不提前返回，避免计时侧信道）
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
// 设备名：先剔除 C0/C1 控制字符（防终端转义注入），再 trim/slice，空名回落默认值
fn clean_device_name(raw: &str) -> String {
    let filtered: String = raw
        .chars()
        .filter(|c| {
            let n = *c as u32;
            !(n <= 0x1f || (0x7f..=0x9f).contains(&n))
        })
        .collect();
    let s: String = filtered.trim().chars().take(DEVICE_NAME_MAX).collect();
    if s.is_empty() {
        "未命名设备".into()
    } else {
        s
    }
}
// GET ?i= 的严格十进制解析（不接受符号/空白/空串；上限对齐 Number.isSafeInteger）
fn parse_strict_digits(raw: &str) -> Option<u64> {
    if raw.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for b in raw.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
        if v > CHUNK_SEQ_MAX {
            return None;
        }
    }
    Some(v)
}
// Host 头归一化：去端口 / 去 IPv6 方括号 / 小写 / 去尾点（对齐 v0.x Node 版 hostnameOf）
fn hostname_of(host_header: &str) -> String {
    let h = host_header.trim().to_ascii_lowercase();
    if h.is_empty() {
        return String::new();
    }
    if h.parse::<IpAddr>().is_ok() {
        return h;
    }
    let mut out: String;
    if let Some(rest) = h.strip_prefix('[') {
        match rest.find(']') {
            Some(end) => out = rest[..end].to_string(),
            None => return String::new(),
        }
    } else if let Some((pre, _)) = h.split_once(':') {
        out = pre.to_string();
    } else {
        out = h.clone();
    }
    if out.ends_with('.') {
        out.pop();
    }
    out
}
fn host_allowed(host_header: &str, allowed: &HashSet<String>) -> bool {
    let h = hostname_of(host_header);
    !h.is_empty() && (allowed.contains(&h) || h.parse::<IpAddr>().is_ok())
}
// Origin/Referer 若存在，其 host 也必须在白名单内；缺失（CLI/同源 GET 被裁剪）直接放行
fn origin_allowed(value: &str, allowed: &HashSet<String>) -> bool {
    let raw = value.trim();
    if raw.is_empty() {
        return true;
    }
    match raw.split_once("://") {
        Some((_, rest)) => {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
            let hostport = authority.rsplit('@').next().unwrap_or(authority);
            host_allowed(hostport, allowed)
        }
        None => false,
    }
}
fn etag_matches(header: &str, etag: &str) -> bool {
    let h = header.trim();
    if h == "*" {
        return true;
    }
    h.split(',').any(|t| t.trim() == etag)
}
// 语义化版本比较：仅按数字段（0.4.3 > 0.4.2；非法值一律不视为更新）
fn semver_parts(v: &str) -> Option<Vec<u64>> {
    let t = v.trim();
    let t = t.strip_prefix('v').unwrap_or(t);
    let bytes = t.as_bytes();
    let mut parts = Vec::new();
    let mut i = 0;
    loop {
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return if parts.is_empty() { None } else { Some(parts) };
        }
        let n: u64 = std::str::from_utf8(&bytes[start..i]).ok()?.parse().ok()?;
        parts.push(n);
        if i < bytes.len() && bytes[i] == b'.' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            i += 1;
        } else {
            return Some(parts);
        }
    }
}
fn semver_newer(latest: &str, current: &str) -> bool {
    let (a, b) = match (semver_parts(latest), semver_parts(current)) {
        (Some(a), Some(b)) => (a, b),
        _ => return false,
    };
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        if x != y {
            return x > y;
        }
    }
    false
}
fn update_scheme(url: &str) -> Option<String> {
    url.split_once("://").map(|(s, _)| s.to_ascii_lowercase())
}

// ---------- 连接活性检测（Linux）----------
// 同步模型无法感知客户端断连；轮询 /proc/net/tcp，客户端 abort 后连接
// 进入 CLOSE_WAIT/消失即视为断开，等价 Node 的 res.on('close') 释放语义。
fn hex_le(ip: &std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{:02X}{:02X}{:02X}{:02X}", o[3], o[2], o[1], o[0])
        }
        std::net::IpAddr::V6(v6) => {
            // /proc/net/tcp6：每个 32 位字按小端十六进制
            let o = v6.octets();
            (0..4).map(|w| format!("{:02X}{:02X}{:02X}{:02X}", o[w * 4 + 3], o[w * 4 + 2], o[w * 4 + 1], o[w * 4])).collect()
        }
    }
}
fn conn_alive(server_port: u16, remote: Option<SocketAddr>) -> bool {
    let remote = match remote {
        Some(r) => r,
        None => return true,
    };
    let needle = format!("{}:{}", hex_le(&remote.ip()), format!("{:04X}", remote.port()));
    let lport = format!("{:04X}", server_port);
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let content = match std::fs::read_to_string(f) {
            Ok(c) => c,
            Err(_) => return true, // 非 Linux：保守视为存活
        };
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                continue;
            }
            let (local, peer, st) = (cols[1], cols[2], cols[3]);
            if peer == needle && local.rsplit(':').next() == Some(lport.as_str()) {
                return st == "01"; // ESTABLISHED
            }
        }
    }
    false // 未找到连接：已关闭
}

// ---------- 长轮询计数 ----------
struct LongpollGuard {
    world: Arc<World>,
    ip: String,
}
impl LongpollGuard {
    fn enter(world: &Arc<World>, ip: &str) -> Option<LongpollGuard> {
        let mut m = world.longpoll_count.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let n = m.get(ip).copied().unwrap_or(0) + 1;
        if n > LONGPOLL_PER_IP {
            return None;
        }
        m.insert(ip.to_string(), n);
        Some(LongpollGuard { world: world.clone(), ip: ip.to_string() })
    }
}
impl Drop for LongpollGuard {
    fn drop(&mut self) {
        let mut m = self.world.longpoll_count.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let n = m.get(&self.ip).copied().unwrap_or(1) - 1;
        if n <= 0 {
            m.remove(&self.ip);
        } else {
            m.insert(self.ip.clone(), n);
        }
    }
}

// ---------- 房间操作 ----------
fn device_alive(d: &Device) -> bool {
    now_ms().saturating_sub(*d.last_seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner)) <= DEVICE_TTL_MS
}
fn pending_offers_for(world: &World, ip: &str) -> Vec<serde_json::Value> {
    let rooms = world.rooms.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = now_ms();
    let mut list = vec![];
    for room in rooms.values() {
        let inner = room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(o) = &inner.offer {
            if o.to_ip == ip && *o.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner) == "pending" && now.saturating_sub(o.created_at) <= OFFER_TTL_MS {
                list.push(serde_json::json!({
                    "id": o.id, "room": room.id, "pub": o.pub_, "hint": o.hint,
                    "from": { "ip": o.from_ip, "name": o.from_name },
                }));
            }
        }
    }
    list
}
fn take_chunk(inner: &mut RoomInner, acct: &ByteAccount, i: u64) -> Option<Arc<Vec<u8>>> {
    let c = inner.buffer.remove(&i)?;
    acct.del(inner, c.len());
    // head 只在按序取走时推进：越序 GET 不得把低序号分片变成不可达垃圾。
    // 推进时跳过“已投递但 buffer 缺失（= 已被越序取走）”的序号。
    if i == inner.head {
        inner.head = i + 1;
        while inner.head < inner.posted && !inner.buffer.contains_key(&inner.head) {
            inner.head += 1;
        }
    }
    if inner.head > inner.pulled {
        inner.pulled = inner.head;
    }
    inner.receiver_seen = true;
    Some(c)
}
fn advance_through(inner: &mut RoomInner, acct: &ByteAccount, through: u64) -> bool {
    if through > inner.posted {
        return false;
    }
    if through <= inner.through {
        return true;
    }
    let mut freed = 0usize;
    inner.buffer.retain(|&i, c| {
        if i >= 1 && i < through {
            freed += c.len();
            false
        } else {
            true
        }
    });
    acct.del(inner, freed);
    inner.through = through;
    if inner.through > inner.pulled {
        inner.pulled = inner.through;
    }
    true
}
fn destroy_room(world: &World, room: &Arc<Room>) {
    {
        let mut rooms = world.rooms.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !rooms.contains_key(&room.id) {
            return;
        }
        rooms.remove(&room.id);
    }
    {
        let mut inner = room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let bytes = std::mem::take(&mut inner.bytes);
        inner.buffer.clear();
        // 与 global_buffered / ip_bytes 在同一临界区成对释放
        counter_sub(&world.global_buffered, bytes);
        ip_bytes_sub(&world.ip_bytes, &room.sender_ip, bytes);
        inner.dead = true;
        if let Some(o) = &inner.offer {
            world.offers_by_id.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&o.id);
            println!("[offer] - {}（房间销毁）", o.id);
        }
    }
    room.cond.notify_all();
    println!("[room] - {}", room.id);
}
// 滑动 60s 建房速率：返回 0 = 已记账允许；>0 = 需等待的秒数
fn create_rate_wait(world: &World, ip: &str, now: u128) -> u64 {
    let mut m = world.ip_creates.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let ts = m.entry(ip.to_string()).or_default();
    ts.retain(|t| now.saturating_sub(*t) < 60_000);
    if ts.len() >= ROOM_CREATE_PER_MIN {
        let elapsed = now.saturating_sub(ts[0]);
        let wait = 60_000u128.saturating_sub(elapsed).div_ceil(1000);
        return wait.max(1) as u64;
    }
    ts.push(now);
    0
}

// ---------- 分片拉取（长轮询挂起） ----------
enum Pull {
    Done(Vec<u8>),
    Timeout,
    Gone(&'static str),
    Conflict,
    Behind(u64),
    TooMany,
}
fn pull_chunk(world: &Arc<World>, room: &Arc<Room>, ip: &str, i: u64, resume: bool, remote: Option<SocketAddr>) -> Pull {
    let deadline = Instant::now() + LONGPOLL;
    let mut inner = room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if resume {
        inner.resumable = true;
    }
    let mut parked = false;
    // per-IP 长轮询配额只在真正挂起时占用（对齐 Node：即时应答不计数）
    let mut guard: Option<LongpollGuard> = None;
    loop {
        if inner.dead {
            return Pull::Gone("gone");
        }
        if inner.resumable {
            if let Some(c) = inner.buffer.get(&i).cloned() {
                inner.receiver_seen = true;
                touch(room);
                return Pull::Done(c.as_ref().clone());
            }
            if i >= 1 && i < inner.through {
                return Pull::Behind(inner.through);
            }
            if inner.sender_done && i >= inner.posted {
                return Pull::Gone("sender-gone");
            }
        } else {
            if i < inner.head {
                // 挂起中被并发取走 → 冲突；新到访已消费 → consumed
                return if parked { Pull::Conflict } else { Pull::Gone("consumed") };
            }
            let acct = ByteAccount { global: &world.global_buffered, ip_bytes: &world.ip_bytes, ip: &room.sender_ip };
            if let Some(c) = take_chunk(&mut inner, &acct, i) {
                touch(room);
                return Pull::Done(c.as_ref().clone());
            }
            // 已投递但 buffer 缺失 = 已被越序/并发取走（经典模式取走即焚）→ 明确 410，不要挂空等待
            if i < inner.posted {
                return if parked { Pull::Conflict } else { Pull::Gone("consumed") };
            }
            if inner.sender_done && i >= inner.posted {
                return Pull::Gone("sender-gone");
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return Pull::Timeout;
        }
        if parked && !conn_alive(PORT.load(std::sync::atomic::Ordering::Relaxed), remote) {
            return Pull::Timeout; // 客户端已断开：释放线程与配额（响应无人收听）
        }
        // 即将挂起：先占 per-IP 配额，超限直接 429
        if guard.is_none() {
            match LongpollGuard::enter(world, ip) {
                Some(g) => guard = Some(g),
                None => return Pull::TooMany,
            }
        }
        let slice = (deadline - now).min(ALIVE_SLICE);
        let (g, _) = room.cond.wait_timeout(inner, slice).unwrap_or_else(std::sync::PoisonError::into_inner);
        inner = g;
        parked = true;
    }
}

// ---------- 邀请长轮询 ----------
fn wait_offers(world: &Arc<World>, ip: &str, remote: Option<SocketAddr>) -> Result<Vec<serde_json::Value>, ()> {
    let deadline = Instant::now() + LONGPOLL;
    let mut guard: Option<LongpollGuard> = None;
    let mut m = world.offers_mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    loop {
        let list = pending_offers_for(world, ip);
        if !list.is_empty() {
            return Ok(list);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(vec![]);
        }
        if !conn_alive(PORT.load(std::sync::atomic::Ordering::Relaxed), remote) {
            return Ok(vec![]);
        }
        // 即将挂起才占 per-IP 配额（对齐 Node：即时应答不计数），超限 → 429
        if guard.is_none() {
            guard = Some(LongpollGuard::enter(world, ip).ok_or(())?);
        }
        let slice = (deadline - now).min(ALIVE_SLICE);
        let (gm, _) = world.offers_cond.wait_timeout(m, slice).unwrap_or_else(std::sync::PoisonError::into_inner);
        m = gm;
    }
}

// ---------- 检查更新（http/https，跟随 ≤3 次重定向） ----------
// 更新源由运维经 CIPHERLANE_UPDATE_URL 配置（非远程可控）；这里仍对 host/path 做
// 字符白名单校验，拒绝空白/控制字符，杜绝把 CRLF 注入上游请求行/Host 头。
const UPDATE_BODY_MAX: usize = 64 * 1024;
const UPDATE_HEAD_MAX: usize = 16 * 1024;
const UPDATE_REDIRECTS: usize = 3;

struct UpdateUrl {
    tls: bool,
    host: String,   // 不含端口；IPv6 为括号内内容
    port: u16,
    path: String,
}
fn parse_update_url(url: &str) -> Option<UpdateUrl> {
    let (scheme, rest) = url.split_once("://")?;
    let tls = match scheme.to_ascii_lowercase().as_str() {
        "http" => false,
        "https" => true,
        _ => return None,
    };
    let (hostport, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{}", p)),
        None => (rest, "/".to_string()),
    };
    if hostport.contains('@') {
        return None; // 不接受 userinfo
    }
    if path.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return None;
    }
    let default_port: u16 = if tls { 443 } else { 80 };
    let (host, port) = if let Some(inner) = hostport.strip_prefix('[') {
        // IPv6 字面量：[::1] 或 [::1]:8443
        let end = inner.find(']')?;
        let host = inner[..end].to_string();
        let tail = &inner[end + 1..];
        let port = if tail.is_empty() { default_port } else { tail.strip_prefix(':')?.parse().ok()? };
        (host, port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
                (h.to_string(), p.parse().ok()?)
            }
            _ => (hostport.to_string(), default_port),
        }
    };
    if host.is_empty() || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b"-.:".contains(&b)) {
        return None;
    }
    Some(UpdateUrl { tls, host, port, path })
}

// 读一行（以 \n 结尾，容忍裸 \n；上限 cap 内找不到换行即报错）
fn read_line_from<R: Read>(r: &mut R, cap: usize) -> Result<String, String> {
    let mut buf = Vec::new();
    let mut one = [0u8; 1];
    while buf.len() <= cap {
        match r.read(&mut one) {
            Ok(0) => break,
            Ok(_) => {
                buf.push(one[0]);
                if one[0] == b'\n' {
                    break;
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    if !buf.ends_with(b"\n") {
        return Err("响应头过长".into());
    }
    let mut line = String::from_utf8_lossy(&buf).to_string();
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

// 在已建立的连接上完成一次 GET：返回 (status, headers, body)。body 支持
// Content-Length 与 chunked，总量不超过 UPDATE_BODY_MAX。超时由调用方在
// TcpStream 上预设（连接建立后设置，TLS 包装前）。
fn http_get_on<R: Read + Write>(sock: &mut R, u: &UpdateUrl) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let hostport = if u.host.contains(':') { format!("[{}]:{}", u.host, u.port) } else { format!("{}:{}", u.host, u.port) };
    write!(sock, "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: cipherlane/{}\r\nAccept: text/plain\r\nConnection: close\r\n\r\n", u.path, hostport, VERSION)
        .map_err(|e| e.to_string())?;
    // ---- 状态行 + 响应头 ----
    let status_line = read_line_from(sock, UPDATE_HEAD_MAX)?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| "上游响应非法".to_string())?;
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let line = read_line_from(sock, UPDATE_HEAD_MAX)?;
        if line.is_empty() {
            break;
        }
        if headers.len() >= 100 {
            return Err("上游响应头过多".into());
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let header = |name: &str| -> Option<&str> {
        headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    };
    // ---- body ----
    let mut body: Vec<u8> = Vec::new();
    let chunked = header("transfer-encoding").map(|v| v.to_ascii_lowercase().contains("chunked")).unwrap_or(false);
    if chunked {
        loop {
            let line = read_line_from(sock, UPDATE_HEAD_MAX)?;
            let size_txt = line.split(';').next().unwrap_or("").trim();
            let n = usize::from_str_radix(size_txt, 16).map_err(|_| "上游 chunked 非法".to_string())?;
            if n == 0 {
                break; // 末块；Connection: close，不再等 trailer
            }
            if body.len() + n > UPDATE_BODY_MAX {
                return Err("更新源响应过大".into());
            }
            let mut chunk = vec![0u8; n];
            sock.read_exact(&mut chunk).map_err(|e| e.to_string())?;
            body.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            sock.read_exact(&mut crlf).map_err(|e| e.to_string())?;
        }
    } else if let Some(cl) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        if cl > UPDATE_BODY_MAX {
            return Err("更新源响应过大".into());
        }
        body.resize(cl, 0);
        sock.read_exact(&mut body).map_err(|e| e.to_string())?;
    } else {
        // 无长度：读到连接关闭（Connection: close），封顶 UPDATE_BODY_MAX
        sock.take(UPDATE_BODY_MAX as u64 + 1).read_to_end(&mut body).map_err(|e| e.to_string())?;
        if body.len() > UPDATE_BODY_MAX {
            return Err("更新源响应过大".into());
        }
    }
    Ok((status, headers, body))
}

fn tls_client_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

// 抓取更新源文本：跟随 ≤3 次 30x 重定向（绝对地址或站内根相对路径），每跳独立超时。
fn fetch_url_text(url: &str, timeout: Duration) -> Result<String, String> {
    let cfg = tls_client_config();
    let mut current = url.to_string();
    for _ in 0..=UPDATE_REDIRECTS {
        let u = parse_update_url(&current).ok_or_else(|| "bad-update-url".to_string())?;
        let addr = format!("{}:{}", u.host, u.port);
        let mut stream = None;
        for a in addr.to_socket_addrs().map_err(|e| e.to_string())? {
            if let Ok(s) = TcpStream::connect_timeout(&a, timeout) {
                stream = Some(s);
                break;
            }
        }
        let tcp = stream.ok_or_else(|| "连接更新源失败".to_string())?;
        tcp.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
        tcp.set_write_timeout(Some(timeout)).map_err(|e| e.to_string())?;
        let (status, headers, body) = if u.tls {
            let name = rustls::pki_types::ServerName::try_from(u.host.clone())
                .map_err(|_| "更新源主机名无法用于 TLS".to_string())?;
            let conn = rustls::ClientConnection::new(cfg.clone(), name).map_err(|e| e.to_string())?;
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            http_get_on(&mut tls, &u)?
        } else {
            let mut tcp = tcp;
            http_get_on(&mut tcp, &u)?
        };
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let loc = headers
                .iter()
                .find(|(k, _)| k == "location")
                .map(|(_, v)| v.clone())
                .ok_or_else(|| "上游重定向缺少 Location".to_string())?;
            current = if loc.contains("://") {
                loc
            } else if loc.starts_with('/') {
                let scheme = if u.tls { "https" } else { "http" };
                let hostport = if u.host.contains(':') { format!("[{}]:{}", u.host, u.port) } else { format!("{}:{}", u.host, u.port) };
                format!("{}://{}{}", scheme, hostport, loc)
            } else {
                return Err("上游重定向不支持相对路径".into());
            };
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(format!("upstream {}", status));
        }
        return String::from_utf8(body).map_err(|_| "更新源响应非 UTF-8".to_string());
    }
    Err("更新源重定向次数过多".into())
}

// 返回 (是否可缓存, JSON 响应体)：成功缓存 5min，错误如实上报且不缓存。
fn fetch_update(url: &str, timeout: Duration) -> (bool, String) {
    match fetch_url_text(url, timeout) {
        Ok(text) => {
            let latest = text.trim().to_string();
            let newer = semver_newer(&latest, VERSION);
            (true, serde_json::json!({"source": url, "current": VERSION, "latest": latest, "newer": newer}).to_string())
        }
        Err(e) => (false, serde_json::json!({"source": url, "current": VERSION, "error": e}).to_string()),
    }
}

// ---------- 监听器（动态绑定） ----------
// 背景：服务由 systemd 在开机时拉起，几乎总是早于 Wi-Fi 认证 + DHCP；而它只在启动那一刻
// 枚举一次网卡地址。结果是每次开机都只监听了 127.0.0.1——进程在跑、托盘显示"运行中"，
// 但别的设备连不上，托盘 / 桌面启动器打开的局域网地址也没人应答。笔记本换 Wi-Fi、休眠
// 唤醒后 DHCP 给了新地址，是同一个问题的另一副面孔。所以监听器必须能随网卡地址变化：
// HOST 未设时，巡检线程每 1s、以及每次 /api/version，都重新枚举 RFC1918 地址并补绑新地址。
//
// 线程模型：所有监听器共用一组 worker。每个监听器只起一条"泵"线程阻塞在 server.recv()，
// 取到请求就放进共用队列，worker 从队列取请求处理。这样每多一个监听地址只多 1 条线程
//（地址消失后它的监听器原样留着：2 条空闲线程，地址回来时立刻又能用），线程数不会随
// "这台机器见过的网卡地址"成倍增长。只增不减，也避免了对 tiny_http 做运行期摘除监听器。
struct RequestQueue<T> {
    // None 是停机令牌：worker 取到即退出
    q: Mutex<VecDeque<Option<T>>>,
    cv: Condvar,
}
impl<T> RequestQueue<T> {
    fn new() -> Self {
        RequestQueue { q: Mutex::new(VecDeque::new()), cv: Condvar::new() }
    }
    fn push(&self, req: T) {
        self.q.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push_back(Some(req));
        self.cv.notify_one();
    }
    /// 唤醒一个 worker 并让它退出。Condvar::notify_one 每次只唤醒一个，故按 worker 数投放。
    fn unblock(&self) {
        self.q.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push_back(None);
        self.cv.notify_one();
    }
    /// 阻塞到有请求；返回 None = 停机令牌
    fn pop(&self) -> Option<T> {
        let mut g = self.q.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(item) = g.pop_front() {
                return item;
            }
            g = self.cv.wait(g).unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}
// 补绑的串行化：巡检线程与 /api/version 的处理线程可能同时进来，同一地址只绑一次
static BIND_LOCK: Mutex<()> = Mutex::new(());
// 停机已开始：泵线程此时退出是正常的，不要当成"监听器出错"去补绑
static SHUTTING_DOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
// 当前绑不上的地址（只为了"首次失败 / 恢复"各打印一次，不让巡检每轮刷屏；每轮都会重试）
static BIND_FAILED: Mutex<Vec<String>> = Mutex::new(Vec::new());

// 重新枚举网卡地址的间隔。1s 意味着 Wi-Fi 拿到地址后最迟 1s 开始监听（期间若有
// 页面 / 托盘来问 /api/version 会立即补绑）；枚举是一次 getifaddrs 加读一行
// /proc/net/route，亚毫秒，常驻开销可以忽略。
// CIPHERLANE_LISTENER_POLL_MS 可覆盖（测试把它调快，或调到很长以单独验证同步补绑那条路）。
fn listener_poll() -> Duration {
    let ms = std::env::var("CIPHERLANE_LISTENER_POLL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1000);
    Duration::from_millis(clamp_poll_ms(ms))
}
// 下限 200ms（再快没有意义）；上限 1 小时（测试用"很长"来单独验证同步补绑那条路）
fn clamp_poll_ms(ms: u64) -> u64 {
    ms.clamp(200, 3_600_000)
}

// 绑定一个地址、登记进监听器表并起它的泵线程。调用方负责持有 BIND_LOCK。
// Err 是给用户看的错误文本；失败时不会留下半登记的状态。
fn bind_listener(ctx: &Arc<Ctx>, ip: &str) -> Result<Arc<Server>, String> {
    let bind = format!("{}:{}", ip, ctx.port);
    let server = Server::http(bind.as_str()).map(Arc::new).map_err(|e| e.to_string())?;
    let pumped = Arc::clone(&server);
    let queue = Arc::clone(&ctx.queue);
    let pump_ctx = Arc::clone(ctx);
    let pump_ip = ip.to_string();
    // 泵线程起不来就不登记这个监听器（Server 随即 Drop、关掉套接字）：
    // 一个"接受连接却永远没人处理"的监听器比没有更糟
    std::thread::Builder::new()
        .name("cipherlane-pump".into())
        .stack_size(WORKER_STACK)
        .spawn(move || {
            // recv() 只在停机（unblock）或监听器内部出错时返回 Err → 泵退出
            while let Ok(req) = pumped.recv() {
                queue.push(req);
            }
            // 监听器内部出错：tiny_http 的 accept 线程遇到错误会把错误推进队列然后退出
            //（比如文件描述符耗尽时的 accept 失败），这个地址从此没人接受连接。把它从
            // 监听器表摘掉——动态模式下巡检会重新绑一个；这是旧实现"一次 accept 失败 =
            // 这个地址到重启前一直死着"的自愈。
            if !SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
                pump_ctx.listeners.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&pump_ip);
                eprintln!(
                    "[listen] 监听器 {}:{} 已停止（内部出错），{}",
                    pump_ip,
                    pump_ctx.port,
                    if pump_ctx.dynamic { "将自动重新监听" } else { "退出服务" }
                );
                if !pump_ctx.dynamic && pump_ctx.listeners.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty() {
                    // 显式 HOST 只监听这一个地址，它没了服务就没有存在意义：
                    // 以失败码退出，交给 systemd（Restart=on-failure）/ 托盘 / 终端处理
                    std::process::exit(1);
                }
            }
        })
        .map_err(|e| format!("无法创建监听泵线程：{e}"))?;
    ctx.listeners.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(ip.to_string(), server.clone());
    Ok(server)
}

// 动态模式下：把当前所有网卡地址里"还没在监听"的补上。显式 HOST 时什么都不做。
fn ensure_listeners(ctx: &Arc<Ctx>) {
    ensure_listeners_if(ctx, !SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst));
}
// `allowed` = 现在允许补绑（停机已开始后为 false）。拆出来是为了能不碰全局状态做单元测试。
fn ensure_listeners_if(ctx: &Arc<Ctx>, allowed: bool) {
    if !allowed || !ctx.dynamic {
        return;
    }
    let _serial = BIND_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    // 回环也在这里维持：托盘 / 面板 / 启动器都走它，它要是停了同样要补回来
    let mut wanted = vec!["127.0.0.1".to_string()];
    wanted.extend(lan_addresses().iter().map(|a| a.to_string()));
    for ip in wanted {
        if ctx.listeners.lock().unwrap_or_else(std::sync::PoisonError::into_inner).contains_key(&ip) {
            continue;
        }
        match bind_listener(ctx, &ip) {
            Ok(_) => {
                let mut failed = BIND_FAILED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let recovered = failed.contains(&ip);
                failed.retain(|x| *x != ip);
                println!(
                    "  →  http://{}:{}（{}）",
                    ip,
                    ctx.port,
                    if recovered { "重新监听" } else { "网卡地址已就绪，开始监听" }
                );
            }
            Err(e) => {
                let mut failed = BIND_FAILED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                if !failed.contains(&ip) {
                    failed.push(ip.clone());
                    eprintln!("[listen] 监听 {}:{} 失败（会自动重试）：{}", ip, ctx.port, e);
                }
            }
        }
    }
}

// worker：从共用队列取请求处理，取到停机令牌即退出。
fn worker(ctx: Arc<Ctx>) {
    while let Some(req) = ctx.queue.pop() {
        // panic 隔离：单个请求的异常只丢该连接，不带走 worker，
        // 也不允许毒化锁级联击杀其余 worker（Node 版为 try/catch 500）
        INFLIGHT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle(req, &ctx)));
        INFLIGHT.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        if let Err(p) = r {
            let msg = p
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "未知 panic".to_string());
            eprintln!("[cipherlane] 请求处理 panic（已隔离，服务继续）：{}", msg);
        }
    }
}

fn print_bind_error(ip: &str, port: u16, e: &str) {
    let bind = format!("{}:{}", ip, port);
    if e.contains("Address already in use") {
        eprintln!("\n✗ {} 已被占用——可能有一个旧的密道实例还在运行。\n", bind);
        eprintln!("  · 到旧实例所在终端按 Ctrl+C 停止，或执行：fuser -k {}/tcp", port);
        eprintln!("  · 或换端口启动：PORT=7788 cipherlane\n");
    } else {
        eprintln!("\n✗ 监听 {} 失败：{}", bind, e);
    }
}

// ---------- 主处理 ----------
struct Ctx {
    world: Arc<World>,
    statics: Vec<(&'static str, StaticFile)>,
    limits: Limits,
    // Host/Origin 白名单（IP 字面量动态放行，其余按集合）
    allowed_hosts: HashSet<String>,
    update: Mutex<UpdateState>,
    update_cond: Condvar,
    // 监听器表（地址 → Server）与所有监听器共用的请求队列，见"监听器（动态绑定）"
    listeners: Mutex<HashMap<String, Arc<Server>>>,
    queue: Arc<RequestQueue<tiny_http::Request>>,
    port: u16,
    // HOST 未设：动态补绑后到的网卡地址；显式 HOST：只监听该地址（绑不上直接退出）
    dynamic: bool,
}

fn decorate_static<R: Read>(mut resp: Response<R>, f: &StaticFile) -> Response<R> {
    resp = resp
        .with_header(h("Content-Type", f.ctype))
        .with_header(h("Content-Security-Policy", CSP))
        .with_header(h("Referrer-Policy", "no-referrer"))
        .with_header(h("X-Content-Type-Options", "nosniff"));
    if f.ctype.starts_with("text/html") {
        // HTML 内嵌版本号且体积小：保持 no-store，避免回源校验收不到更新
        resp = resp.with_header(h("Cache-Control", "no-store"));
    } else {
        resp = resp.with_header(h("Cache-Control", "no-cache")).with_header(h("ETag", &f.etag));
    }
    resp
}

fn send_static(req: tiny_http::Request, f: &StaticFile) {
    let is_html = f.ctype.starts_with("text/html");
    if !is_html && etag_matches(&hdr(&req, "If-None-Match"), &f.etag) {
        let _ = req.respond(decorate_static(Response::empty(304), f));
        return;
    }
    // Arc 只克隆引用计数；data_length 显式给出 Content-Length（不做 chunked）
    let resp = Response::new(
        tiny_http::StatusCode(200),
        vec![],
        std::io::Cursor::new(f.data.clone()),
        Some(f.data.len()),
        None,
    );
    let _ = req.respond(decorate_static(resp, f));
}

fn handle(mut req: tiny_http::Request, ctx: &Arc<Ctx>) {
    let method = req.method().as_str().to_string();
    let url = req.url().to_string();
    let (rawpath, query) = match url.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (url.clone(), String::new()),
    };
    let path = {
        let t = rawpath.trim_end_matches('/');
        if t.is_empty() { "/".to_string() } else { t.to_string() }
    };
    let ip = client_ip(&req);
    let w = &ctx.world;

    // ---- /api/* Host/Origin 闸门（防 DNS rebinding 与跨站 CSRF；静态页不受限） ----
    if path == "/api" || path.starts_with("/api/") {
        if !host_allowed(&hdr(&req, "Host"), &ctx.allowed_hosts) {
            return jerr(req, 403, "bad-host");
        }
        if !origin_allowed(&hdr(&req, "Origin"), &ctx.allowed_hosts)
            || !origin_allowed(&hdr(&req, "Referer"), &ctx.allowed_hosts)
        {
            return jerr(req, 403, "bad-origin");
        }
    }

    // ---- 静态资源 ----
    if method == "GET" {
        if path == "/favicon.ico" {
            let _ = req.respond(Response::empty(204));
            return;
        }
        if path == "/" || path == "/index.html" {
            return send_static(req, &ctx.statics[0].1);
        }
        if let Some(f) = ctx.statics.iter().skip(1).find(|(r, _)| *r == path) {
            return send_static(req, &f.1);
        }
    }

    // ---- POST /api/presence ----
    if path == "/api/presence" && method == "POST" {
        let body = match read_body(&mut req, 2048) {
            Some(b) => b,
            None => return jerr(req, 400, "bad-body"),
        };
        let j: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => return jerr(req, 400, "bad-body"),
        };
        let name = clean_device_name(j.get("name").and_then(|v| v.as_str()).unwrap_or(""));
        let pub_ = j.get("pub").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !valid_pub(&pub_) {
            return jerr(req, 400, "bad-pub");
        }
        let secret_hdr = hdr(&req, "X-Device-Secret");
        let existing = w.devices.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&ip).cloned();
        if let Some(prev) = existing {
            if !secret_hdr.is_empty() && ct_eq(&prev.secret, &secret_hdr) {
                *prev.name.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = name;
                *prev.pub_.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = pub_;
                *prev.last_seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = now_ms();
                return json_resp(req, 200, serde_json::json!({ "ip": ip, "id": prev.id, "secret": prev.secret }).to_string());
            }
        }
        // 检查与插入同一临界区：并发 fresh presence 不得越过 DEVICES_MAX（TOCTOU 收口）
        let dev = Arc::new(Device {
            ip: ip.clone(),
            id: rand_hex16(),
            secret: rand_secret32(),
            name: Mutex::new(name),
            pub_: Mutex::new(pub_),
            last_seen: Mutex::new(now_ms()),
        });
        {
            let mut devices = w.devices.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if devices.len() >= DEVICES_MAX && !devices.contains_key(&ip) {
                drop(devices);
                return jerr(req, 503, "too-many-devices");
            }
            println!("[device] + {} {}", dev.ip, dev.name.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
            let (id, secret) = (dev.id.clone(), dev.secret.clone());
            devices.insert(ip.clone(), dev);
            drop(devices);
            return json_resp(req, 200, serde_json::json!({ "ip": ip, "id": id, "secret": secret }).to_string());
        }
    }

    // ---- POST /api/adopt：本机托盘接管（交接停机令牌）----
    // 场景：服务先于托盘启动（无令牌运行）。托盘经回环调用本端点换得令牌，
    // 从此"退出=关服务"。仅接受 127.0.0.1/::1 来源；已有令牌的服务拒绝接管（防第二个托盘抢权）。
    if path == "/api/adopt" && method == "POST" {
        let local = ip == "127.0.0.1" || ip == "::1";
        if !local {
            return jerr(req, 403, "forbidden");
        }
        let body = read_body(&mut req, 1024).unwrap_or_default();
        let new_token = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|j| j.get("token").and_then(|v| v.as_str().map(String::from)))
            .unwrap_or_default();
        if new_token.len() < 16 {
            return jerr(req, 400, "bad-token");
        }
        let current = std::env::var("CIPHERLANE_SHUTDOWN_TOKEN").unwrap_or_default();
        if !current.is_empty() {
            return jerr(req, 409, "already-managed");
        }
        std::env::set_var("CIPHERLANE_SHUTDOWN_TOKEN", new_token.clone());
        println!("[panel] 已被本机托盘接管（令牌交接）");
        return json_resp(req, 200, serde_json::json!({ "ok": true }).to_string());
    }

    // ---- GET /api/version ----
    if path == "/api/version" && method == "GET" {
        let rooms = w.rooms.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len();
        // 先补绑再回答：回环打开的页面、托盘、桌面启动器都拿这里的 lan 提示去拼局域网链接，
        // 刚连上 Wi-Fi 的那一瞬间点开也必须能打开。补绑是毫秒级的 getifaddrs + bind。
        ensure_listeners(ctx);
        // lan：本机首选的、此刻确实在监听的局域网地址（供回环来源的客户端升级链接/跳转
        // 目标；没有这样的地址则 null，调用方退回 location.origin / 回环）。提示一个没人
        // 监听的地址 = 对端打不开，所以这里只认监听器表里有的
        let lan = {
            let listeners = ctx.listeners.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            lan_addresses().iter().map(|a| a.to_string()).find(|a| listeners.contains_key(a))
        };
        return json_resp(req, 200, serde_json::json!({ "version": VERSION, "rooms": rooms, "startedAt": w.started_at, "lan": lan }).to_string());
    }

    // ---- POST /api/shutdown：仅本机 + 会话停机令牌 ----
    if path == "/api/shutdown" && method == "POST" {
        let token = std::env::var("CIPHERLANE_SHUTDOWN_TOKEN").unwrap_or_default();
        let body = read_body(&mut req, 1024).unwrap_or_default();
        let sent = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|j| j.get("token").and_then(|v| v.as_str().map(String::from)))
            .unwrap_or_default();
        let local = ip == "127.0.0.1" || ip == "::1";
        if token.len() < 16 || !ct_eq(&sent, &token) || !local {
            return jerr(req, 403, "forbidden");
        }
        json_resp(req, 200, "{\"ok\":true}".into());
        println!("[panel] 服务已从控制面板停止");
        // 与 SIGTERM 同一条排干路径：停派发 → 250ms 排干 → exit 0
        // （响应先落盘给客户端，停机线程延迟 150ms 后开始排干）
        SHUTDOWN_BY_PANEL.store(true, std::sync::atomic::Ordering::SeqCst);
        return;
    }

    // ---- GET /api/update：5min 缓存 + in-flight 去重 + 仅 http/https ----
    if path == "/api/update" && method == "GET" {
        let url = match std::env::var("CIPHERLANE_UPDATE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => return json_resp(req, 200, serde_json::json!({ "source": null, "current": VERSION, "message": "未配置更新源（CIPHERLANE_UPDATE_URL）" }).to_string()),
        };
        match update_scheme(&url).as_deref() {
            Some("http") | Some("https") => {}
            _ => {
                return json_resp(req, 400, serde_json::json!({ "source": url, "current": VERSION, "error": "bad-update-url" }).to_string())
            }
        }
        // 5 分钟成功结果缓存（错误不缓存）
        {
            let st = ctx.update.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some((at, payload)) = &st.cache {
                if now_ms().saturating_sub(*at) < UPDATE_CACHE_MS {
                    return json_resp(req, 200, payload.clone());
                }
            }
        }
        // 单飞：已有上游请求进行中则等它完成，共享同一结果（成功或错误）。
        // 等待有界（30s > 单跳超时 5s × 最多 4 跳）：上游/取数线程异常时不至于
        // 把所有 worker 永久挂死在这条 condvar 上。
        {
            let mut st = ctx.update.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if st.inflight {
                let deadline = Instant::now() + Duration::from_secs(30);
                while st.inflight {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return json_resp(req, 200, serde_json::json!({ "source": url, "current": VERSION, "error": "update-wait-timeout" }).to_string());
                    }
                    let (g, _) = ctx.update_cond.wait_timeout(st, left).unwrap_or_else(std::sync::PoisonError::into_inner);
                    st = g;
                }
                if let Some(p) = st.last_result.clone() {
                    return json_resp(req, 200, p);
                }
            }
            st.inflight = true;
        }
        // 取数期间若 panic（被 worker 的 catch_unwind 隔离），guard 的 Drop 会复位
        // inflight 并唤醒等待者，之后的新请求自行重新发起上游取数
        let _inflight_guard = UpdateInflightGuard(ctx);
        let (cacheable, payload) = fetch_update(&url, Duration::from_secs(5));
        {
            let mut st = ctx.update.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if cacheable {
                st.cache = Some((now_ms(), payload.clone()));
            }
            st.last_result = Some(payload.clone());
            st.inflight = false;
            ctx.update_cond.notify_all();
        }
        return json_resp(req, 200, payload);
    }

    // ---- GET /api/devices ----
    if path == "/api/devices" && method == "GET" {
        let devices = w.devices.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut list: Vec<serde_json::Value> = devices
            .values()
            .filter(|d| device_alive(d))
            .map(|d| serde_json::json!({ "ip": d.ip, "id": d.id, "name": *d.name.lock().unwrap_or_else(std::sync::PoisonError::into_inner), "pub": *d.pub_.lock().unwrap_or_else(std::sync::PoisonError::into_inner) }))
            .collect();
        // HashMap 迭代顺序每个进程随机；按 IP 排序让 /api/devices 输出确定，客户端/测试
        // 不依赖哈希顺序（本机回环 + LAN 地址可能同时存在多个设备条目）。
        list.sort_by(|a, b| a["ip"].as_str().unwrap_or("").cmp(b["ip"].as_str().unwrap_or("")));
        return json_resp(req, 200, serde_json::json!({ "devices": list }).to_string());
    }

    // ---- GET /api/offers：长轮询 ----
    if path == "/api/offers" && method == "GET" {
        let secret = hdr(&req, "X-Device-Secret");
        let dev = { w.devices.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&ip).filter(|d| ct_eq(&d.secret, &secret)).cloned() };
        let dev = match dev {
            Some(d) => d,
            None => return jerr(req, 401, "bad-secret"),
        };
        *dev.last_seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = now_ms();
        if !pending_offers_for(w, &ip).is_empty() {
            return json_resp(req, 200, serde_json::json!({ "offers": pending_offers_for(w, &ip) }).to_string());
        }
        match wait_offers(w, &ip, req.remote_addr().copied()) {
            Ok(list) => json_resp(req, 200, serde_json::json!({ "offers": list }).to_string()),
            Err(()) => json_resp(req, 429, "{\"error\":\"too-many-polls\",\"retry\":1}".into()),
        }
        return;
    }

    // ---- POST /api/offers/:id/accept | reject ----
    if let Some(rest) = path.strip_prefix("/api/offers/") {
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() == 2 && (parts[1] == "accept" || parts[1] == "reject") && method == "POST" {
            let secret = hdr(&req, "X-Device-Secret");
            let dev = { w.devices.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&ip).filter(|d| ct_eq(&d.secret, &secret)).cloned() };
            if dev.is_none() {
                return jerr(req, 401, "bad-secret");
            }
            let offer_id = parts[0];
            let room_id = w.offers_by_id.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(offer_id).cloned();
            let room = room_id.and_then(|rid| w.rooms.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&rid).cloned());
            let room = match room {
                Some(r) => r,
                None => return jerr(req, 410, "gone"),
            };
            {
                let inner = room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let offer = match &inner.offer {
                    Some(o) if o.id == offer_id => o.clone(),
                    _ => return jerr(req, 410, "gone"),
                };
                if *offer.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner) != "pending" || offer.to_ip != ip {
                    return jerr(req, 410, "gone");
                }
            }
            let _ = read_body(&mut req, 1024);
            // 读包期间房间可能已被 DELETE/清扫销毁（roomAlive 语义）
            if room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).dead {
                return jerr(req, 410, "gone");
            }
            touch(&room);
            let mut inner = room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let offer_opt = inner.offer.clone();
            if let Some(offer) = offer_opt {
                if parts[1] == "accept" {
                    *offer.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = "accepted".into();
                    println!("[offer] ✓ {} {} → {}", offer.id, offer.from_ip, ip);
                    let rid = room.id.clone();
                    drop(inner);
                    return json_resp(req, 200, serde_json::json!({ "ok": true, "room": rid }).to_string());
                }
                *offer.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = "rejected".into();
                inner.rejected_at = Some(now_ms());
                println!("[offer] ✗ {} {} → {}", offer.id, offer.from_ip, ip);
                drop(inner);
                return json_resp(req, 200, "{\"ok\":true}".into());
            }
            return jerr(req, 410, "gone");
        }
    }

    // ---- POST /api/rooms：per-IP 房间数/建房速率双闸 ----
    if path == "/api/rooms" && method == "POST" {
        let _ = read_body(&mut req, 1024);
        // 速率窗口先记账（与 Node 一致：被配额拒绝的尝试也占用速率额度）
        let rate_wait = create_rate_wait(w, &ip, now_ms());
        if rate_wait > 0 {
            return json_resp(req, 429, format!("{{\"error\":\"ip-quota\",\"retry\":{}}}", rate_wait));
        }
        // 配额检查与插入同一临界区：并发建房不得越过 ip_rooms_max / ROOMS_MAX（TOCTOU 收口）
        let id = rand_room_id();
        let room = Arc::new(Room {
            id: id.clone(),
            sender_ip: ip.clone(),
            last_active: Mutex::new(now_ms()),
            cond: Condvar::new(),
            inner: Mutex::new(RoomInner {
                token: rand_secret32(),
                posted: 0,
                head: 0,
                pulled: 0,
                buffer: HashMap::new(),
                bytes: 0,
                receiver_seen: false,
                sender_done: false,
                acked: false,
                ack_proof: None,
                resumable: false,
                through: 0,
                rejected_at: None,
                offer: None,
                dead: false,
            }),
        });
        let token = room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).token.clone();
        {
            let mut rooms = w.rooms.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let by_ip = rooms.values().filter(|r| r.sender_ip == ip).count();
            if by_ip >= ctx.limits.ip_rooms_max {
                drop(rooms);
                return json_resp(req, 429, "{\"error\":\"ip-quota\",\"retry\":1}".into());
            }
            if rooms.len() >= ROOMS_MAX {
                drop(rooms);
                return jerr(req, 503, "too-many-rooms");
            }
            rooms.insert(id.clone(), room);
        }
        println!("[room] + {}", id);
        return json_resp(req, 200, serde_json::json!({ "room": id, "token": token }).to_string());
    }

    // ---- /api/rooms/:id[/sub] ----
    if let Some(rest) = path.strip_prefix("/api/rooms/") {
        let parts: Vec<&str> = rest.split('/').collect();
        if !parts.is_empty() && valid_room_id(parts[0]) {
            let sub = parts.get(1).copied().unwrap_or("");
            let token_hdr = hdr(&req, "X-Room-Token");
            let room = w.rooms.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(parts[0]).cloned();

            if method == "DELETE" && sub.is_empty() {
                return match room {
                    None => jerr(req, 404, "no-room"),
                    Some(r) => {
                        if !ct_eq(&token_hdr, &r.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).token) {
                            return jerr(req, 403, "bad-token");
                        }
                        destroy_room(w, &r);
                        json_resp(req, 200, "{\"ok\":true}".into())
                    }
                };
            }
            let room = match room {
                Some(r) => r,
                None => return jerr(req, 404, "no-room"),
            };
            let token_ok = ct_eq(&token_hdr, &room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).token);

            // GET state
            if sub == "state" && method == "GET" {
                let inner = room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let offer_state = inner.offer.as_ref().map(|o| o.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone());
                return json_resp(req, 200, serde_json::json!({
                    "posted": inner.posted, "head": inner.head, "pulled": inner.pulled,
                    "receiverSeen": inner.receiver_seen, "senderDone": inner.sender_done,
                    "acked": inner.acked, "ackProof": inner.ack_proof,
                    "resumable": inner.resumable, "through": inner.through,
                    "offer": offer_state,
                }).to_string());
            }

            // POST offer —— 须在投递分片之前
            if sub == "offer" && method == "POST" {
                if !token_ok {
                    return jerr(req, 403, "bad-token");
                }
                {
                    let inner = room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    if inner.offer.is_some() {
                        return jerr(req, 409, "offer-exists");
                    }
                    if inner.posted > 0 {
                        return jerr(req, 409, "late-offer");
                    }
                }
                let body = match read_body(&mut req, 8192) {
                    Some(b) => b,
                    None => return jerr(req, 400, "bad-body"),
                };
                let j: serde_json::Value = match serde_json::from_slice(&body) {
                    Ok(v) => v,
                    Err(_) => return jerr(req, 400, "bad-body"),
                };
                // 读包期间房间可能已被销毁（roomAlive 语义）
                if room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).dead {
                    return jerr(req, 410, "gone");
                }
                let to = j.get("to").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let pub_ = j.get("pub").and_then(|v| v.as_str()).unwrap_or("").to_string();
                // hint 必须是 string 且 ≤4096：对齐 Node（缺失/非 string → 400 bad-hint）
                let hint = match j.get("hint").and_then(|v| v.as_str()) {
                    Some(h) if h.len() <= 4096 => h.to_string(),
                    _ => return jerr(req, 400, "bad-hint"),
                };
                // 目标设备必须在线（能力校验；target 值本身不进入响应）
                if !{ w.devices.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&to).is_some_and(|d| device_alive(d)) } {
                    return jerr(req, 404, "device-offline");
                }
                if !valid_pub(&pub_) {
                    return jerr(req, 400, "bad-pub");
                }
                {
                    let rooms = w.rooms.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    let pending = rooms.values().filter(|r| {
                        let inner = r.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        inner.offer.as_ref().map(|o| *o.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner) == "pending" && o.to_ip == to).unwrap_or(false)
                    }).count();
                    if pending >= OFFERS_MAX {
                        return jerr(req, 429, "too-many-offers");
                    }
                }
                let sender = { w.devices.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&ip).cloned() };
                let from_name = sender.as_ref().filter(|d| device_alive(d)).map(|d| d.name.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone());
                let offer = Arc::new(Offer {
                    id: rand_hex16(),
                    to_ip: to.clone(),
                    from_ip: ip.clone(),
                    from_name,
                    pub_: pub_,
                    hint,
                    state: Mutex::new("pending".into()),
                    created_at: now_ms(),
                });
                let oid = offer.id.clone();
                {
                    let mut inner = room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    inner.offer = Some(offer);
                }
                w.offers_by_id.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(oid.clone(), room.id.clone());
                touch(&room);
                drop(w.offers_mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
                w.offers_cond.notify_all();
                println!("[offer] + {} {} → {}", oid, ip, to);
                return json_resp(req, 200, serde_json::json!({ "offer": oid }).to_string());
            }

            // POST chunk（可选 X-Chunk-Seq：发送端重投时幂等确认）
            if sub == "chunk" && method == "POST" {
                if !token_ok {
                    return jerr(req, 403, "bad-token");
                }
                let body = match read_body(&mut req, BODY_MAX) {
                    Some(b) => b,
                    None => return jerr(req, 413, "bad-body"),
                };
                let mut inner = room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                // 房间清扫可能与慢速请求竞争：已销毁的房间不再接受分片，否则分片记账
                // 只增不减（房间已从 rooms 移除，永远不会再有 destroy 来释放这笔计数）。
                if inner.dead {
                    drop(inner);
                    return jerr(req, 410, "gone");
                }
                if body.is_empty() {
                    drop(inner);
                    return jerr(req, 400, "empty-chunk");
                }
                // X-Chunk-Seq（可选头，向后兼容）：缺失 → 旧语义 index = posted++。
                //   seq == posted → 正常入库，响应 {index:seq}
                //   seq <  posted → 该序号已入账：200 duplicate，不写 buffer/bytes/global、
                //                   不占背压、不 notify（重投幂等）
                //   seq >  posted → 409 out-of-order（带当前 posted，发送端可据此对齐）
                // 重复的同名头按 Node 的合并语义（"a, b"）必然非法，统一 400 bad-seq。
                let seq_vals = hdr_values(&req, "X-Chunk-Seq");
                let seq = match seq_vals.len() {
                    0 => None,
                    1 => match parse_chunk_seq(&seq_vals[0]) {
                        Some(v) => Some(v),
                        None => {
                            drop(inner);
                            return jerr(req, 400, "bad-seq");
                        }
                    },
                    _ => {
                        drop(inner);
                        return jerr(req, 400, "bad-seq");
                    }
                };
                if let Some(seq) = seq {
                    let posted = inner.posted;
                    if seq > posted {
                        drop(inner);
                        return json_resp(req, 409, format!("{{\"error\":\"out-of-order\",\"posted\":{}}}", posted));
                    }
                    if seq < posted {
                        drop(inner);
                        return json_resp(req, 200, format!("{{\"ok\":true,\"index\":{},\"duplicate\":true}}", seq));
                    }
                    // seq == posted：与无头路径一致，落到下面的背压检查/入库
                }
                let outstanding = if inner.resumable { inner.posted - inner.through } else { inner.buffer.len() as u64 };
                // 房间级配额在 inner 锁内自查；全局/per-IP 配额由 try_add 在同一组
                // 全局锁下检查+入账（锁序 inner → global_buffered → ip_bytes），
                // 跨房间不再有"检查后放锁再入账"的 TOCTOU 窗口。
                let acct = ByteAccount { global: &w.global_buffered, ip_bytes: &w.ip_bytes, ip: &room.sender_ip };
                if outstanding >= ROOM_CHUNKS_BUF
                    || inner.bytes + body.len() > ROOM_BYTES_MAX
                    || !acct.try_add(&mut inner, body.len(), GLOBAL_BYTES_MAX, ctx.limits.ip_bytes_max)
                {
                    drop(inner);
                    return json_resp(req, 429, "{\"error\":\"backpressure\",\"retry\":1}".into());
                }
                let i = inner.posted;
                inner.posted += 1;
                inner.buffer.insert(i, Arc::new(body));
                drop(inner);
                touch(&room);
                room.cond.notify_all();
                return json_resp(req, 200, serde_json::json!({ "index": i }).to_string());
            }

            // GET chunk?i=N（X-Resume: 1 可续传）
            if sub == "chunk" && method == "GET" {
                // ?i 只接受唯一且纯十进制的参数：缺失/重复/百分号编码/符号/超安全整数
                // 一律 400（比 Node 的 URLSearchParams 解码语义更严；浏览器与 CLI 只发纯数字）
                let mut i_vals: Vec<&str> = query
                    .split('&')
                    .filter_map(|kv| {
                        if kv == "i" {
                            Some("")
                        } else {
                            kv.split_once('=').filter(|(k, _)| *k == "i").map(|(_, v)| v)
                        }
                    })
                    .collect();
                let i = match i_vals.pop() {
                    Some(v) if i_vals.is_empty() => match parse_strict_digits(v) {
                        Some(n) => n,
                        None => return jerr(req, 400, "bad-index"),
                    },
                    _ => return jerr(req, 400, "bad-index"),
                };
                let resume = hdr(&req, "X-Resume") == "1";
                return match pull_chunk(w, &room, &ip, i, resume, req.remote_addr().copied()) {
                    Pull::Done(body) => {
                        let _ = req.respond(
                            Response::from_data(body)
                                .with_header(h("Content-Type", "application/octet-stream"))
                                .with_header(h("X-Chunk-Index", &i.to_string()))
                                .with_header(h("Cache-Control", "no-store")),
                        );
                    }
                    Pull::Timeout => jerr(req, 408, "timeout"),
                    Pull::Gone(msg) => jerr(req, 410, msg),
                    Pull::Conflict => jerr(req, 409, "conflict"),
                    Pull::Behind(t) => json_resp(req, 410, format!("{{\"error\":\"behind\",\"through\":{}}}", t)),
                    Pull::TooMany => json_resp(req, 429, "{\"error\":\"too-many-polls\",\"retry\":1}".into()),
                };
            }

            // POST done
            if sub == "done" && method == "POST" {
                if !token_ok {
                    return jerr(req, 403, "bad-token");
                }
                let _ = read_body(&mut req, 1024);
                room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).sender_done = true;
                touch(&room);
                room.cond.notify_all();
                return json_resp(req, 200, "{\"ok\":true}".into());
            }

            // POST progress —— 可续传模式：接收方上报已落盘分片数
            if sub == "progress" && method == "POST" {
                let body = read_body(&mut req, 1024).unwrap_or_default();
                // 读包期间房间可能已被销毁（roomAlive 语义）
                if room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).dead {
                    return jerr(req, 410, "gone");
                }
                let through = serde_json::from_slice::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|j| j.get("through").and_then(|v| v.as_u64()));
                let through = match through {
                    Some(t) => t,
                    None => return jerr(req, 400, "bad-through"),
                };
                let mut inner = room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                if !inner.resumable {
                    drop(inner);
                    return jerr(req, 409, "not-resumable");
                }
                let acct = ByteAccount { global: &w.global_buffered, ip_bytes: &w.ip_bytes, ip: &room.sender_ip };
                if !advance_through(&mut inner, &acct, through) {
                    drop(inner);
                    return jerr(req, 400, "bad-through");
                }
                let t = inner.through;
                drop(inner);
                touch(&room);
                return json_resp(req, 200, serde_json::json!({ "ok": true, "through": t }).to_string());
            }

            // POST ack（可选密钥凭证 proof，供发送方本地核对）
            if sub == "ack" && method == "POST" {
                let body = read_body(&mut req, 1024).unwrap_or_default();
                // 读包期间房间可能已被销毁（roomAlive 语义）
                if room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).dead {
                    return jerr(req, 410, "gone");
                }
                let proof = serde_json::from_slice::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|j| j.get("proof").and_then(|v| v.as_str().map(String::from)))
                    .filter(|p| p.len() == 64 && p.bytes().all(|b| b.is_ascii_hexdigit()));
                {
                    let mut inner = room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    inner.acked = true;
                    inner.ack_proof = proof;
                }
                touch(&room);
                return json_resp(req, 200, "{\"ok\":true}".into());
            }
        }
    }

    jerr(req, 404, "not-found");
}

// ---------- 过期清扫 ----------
fn sweeper(ctx: Arc<Ctx>) {
    loop {
        std::thread::sleep(Duration::from_secs(30));
        let now = now_ms();
        let w = &ctx.world;
        let rooms: Vec<Arc<Room>> = w.rooms.lock().unwrap_or_else(std::sync::PoisonError::into_inner).values().cloned().collect();
        for room in rooms {
            let idle = now.saturating_sub(*room.last_active.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
            let (acked, offer_expired, reject_expired) = {
                let inner = room.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let oe = inner.offer.as_ref().map(|o| *o.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner) == "pending" && now.saturating_sub(o.created_at) > OFFER_TTL_MS).unwrap_or(false);
                let re = inner.rejected_at.map(|t| now.saturating_sub(t) > REJECT_GRACE_MS).unwrap_or(false);
                (inner.acked, oe, re)
            };
            if (acked && idle > ACK_IDLE_MS) || idle > ROOM_IDLE_MS || offer_expired || reject_expired {
                destroy_room(w, &room);
            }
        }
        w.devices.lock().unwrap_or_else(std::sync::PoisonError::into_inner).retain(|_, d| now.saturating_sub(*d.last_seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner)) <= DEVICE_MEM_MS);
        // 建房速率窗口清理，避免按 IP 无界增长
        let mut creates = w.ip_creates.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        creates.retain(|_, ts| {
            ts.retain(|t| now.saturating_sub(*t) < 60_000);
            !ts.is_empty()
        });
    }
}

// ---------- 启动 ----------
// 默认路由网卡名（/proc/net/route 中 Destination=00000000 的第一行）。
// 多网卡（如 WiFi 192.168.1.x + 热点 192.168.137.x）时，lan 提示/链接/二维码
// 必须选"真正能出网的那个网卡"的地址——按枚举顺序挑会随接口增减漂移，
// 对端拿到不可达地址（历史上"链接时对时错"的根源）。非 Linux 读不到则退化为原顺序。
fn default_route_iface() -> Option<String> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 2 && cols[1] == "00000000" && !cols[0].is_empty() {
            return Some(cols[0].to_string());
        }
    }
    None
}
// CIPHERLANE_LAN_ADDRS_FILE：网卡地址来源的覆盖（测试与特殊部署用）。设置后不再枚举网卡，
// 而是每次调用从该文件读 IPv4 地址——每行一个、# 之后是注释、首个即 lan 提示；文件不存在
// 或读不出来 = 没有局域网地址。它让"服务启动后地址才出现 / 地址变了"这类场景可以在
// 没有 root、不碰真实网卡的情况下被测试驱动。
fn parse_addrs_file(text: &str) -> Vec<std::net::Ipv4Addr> {
    let mut out: Vec<std::net::Ipv4Addr> = Vec::new();
    for line in text.lines() {
        let field = line.split('#').next().unwrap_or("").trim();
        if let Ok(a) = field.parse::<std::net::Ipv4Addr>() {
            if !out.contains(&a) {
                out.push(a);
            }
        }
    }
    out
}
fn lan_addresses() -> Vec<std::net::Ipv4Addr> {
    if let Ok(path) = std::env::var("CIPHERLANE_LAN_ADDRS_FILE") {
        if !path.is_empty() {
            return std::fs::read_to_string(&path).map(|s| parse_addrs_file(&s)).unwrap_or_default();
        }
    }
    let mut out: Vec<(Option<String>, std::net::Ipv4Addr)> = vec![];
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for i in ifaces {
            if let std::net::IpAddr::V4(v4) = i.ip() {
                if !v4.is_loopback() && v4.is_private() && !out.iter().any(|(_, a)| *a == v4) {
                    out.push((Some(i.name), v4));
                }
            }
        }
    }
    let preferred = default_route_iface();
    // 默认路由网卡的地址排最前（lan 提示取 [0]）；同组内保持枚举顺序稳定
    out.sort_by_key(|(name, _)| if preferred.is_some() && *name == preferred { 0 } else { 1 });
    out.into_iter().map(|(_, a)| a).collect()
}

// Host/Origin 白名单：内置回环名 + 实际绑定地址/HOST（域名时）+ os.hostname()（含短名）
// + CIPHERLANE_EXTRA_HOSTS（逗号分隔，忽略端口）。IP 字面量在 host_allowed 中动态放行。
fn build_allowed_hosts(addrs: &[String], host_env: &str) -> HashSet<String> {
    let mut set: HashSet<String> = ["localhost", "127.0.0.1", "::1"].iter().map(|s| s.to_string()).collect();
    for a in addrs {
        let a = a.trim().to_ascii_lowercase();
        if !a.is_empty() && a != "0.0.0.0" && a != "::" && a.parse::<IpAddr>().is_err() {
            set.insert(a);
        }
    }
    let host_env = host_env.trim().to_ascii_lowercase();
    if !host_env.is_empty() && host_env.parse::<IpAddr>().is_err() {
        set.insert(host_env);
    }
    let os_host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()));
    if let Some(h) = os_host {
        if let Some(short) = h.split('.').next() {
            set.insert(short.to_string());
        }
        set.insert(h);
    }
    if let Ok(extra) = std::env::var("CIPHERLANE_EXTRA_HOSTS") {
        for part in extra.split(',') {
            let mut v = part.trim().to_ascii_lowercase();
            // 忽略端口（对齐 Node 的 replace(/:\d+$/, '')）
            if let Some(idx) = v.rfind(':') {
                let port = &v[idx + 1..];
                if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
                    v.truncate(idx);
                }
            }
            if !v.is_empty() {
                set.insert(v);
            }
        }
    }
    set
}

// ---------- 优雅停机 ----------
// 语义对齐 v0.x Node 版：SIGTERM/SIGINT → 打印文案 → 停止向 worker 派发新请求 →
// 给在途处理最多 250ms 排干（Node 在 250ms 处 closeAllConnections 强切）→ exit 0。
// 实现为 pthread_sigmask(SIG_BLOCK) + sigwait：信号只由专职线程消费，
// 处理路径上没有任何非异步信号安全的调用；/api/shutdown 置位后走同一条排干路径。
static SHUTDOWN_BY_PANEL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
// 在途请求数：优雅停机的排干依据（worker 在 handle 前后增减）
static INFLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
// 排干窗口：对齐 Node 版 closeAllConnections 的 250ms
const DRAIN_MS: Duration = Duration::from_millis(250);

// 在创建任何线程之前阻塞 SIGTERM/SIGINT：之后派生的线程全部继承该掩码，
// 信号只会送达下面 sigwait 专职线程，不会随机打在某个 worker 上。
#[cfg(unix)]
fn block_termination_signals() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
}
#[cfg(unix)]
fn wait_termination_signal() -> libc::c_int {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        let mut sig: libc::c_int = 0;
        libc::sigwait(&set, &mut sig);
        sig
    }
}
// 停止派发 + 排干 + 退出。先让每条泵线程的 recv() 返回（每个监听器一条泵，各唤醒一次），
// 再给共用队列按 worker 数逐个投放停机令牌（每次只唤醒一个 worker）；随后等待在途请求
// 归零或超时。
fn drain_and_exit(ctx: &Arc<Ctx>) -> ! {
    SHUTTING_DOWN.store(true, std::sync::atomic::Ordering::SeqCst);
    {
        let listeners = ctx.listeners.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for s in listeners.values() {
            s.unblock();
        }
    }
    for _ in 0..WORKERS {
        ctx.queue.unblock();
    }
    let deadline = Instant::now() + DRAIN_MS;
    while INFLIGHT.load(std::sync::atomic::Ordering::SeqCst) > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let left = INFLIGHT.load(std::sync::atomic::Ordering::SeqCst);
    if left > 0 {
        eprintln!("[shutdown] {} 个在途请求未及排干（250ms 排干上限，对齐旧版 250ms 强切语义）", left);
    }
    std::process::exit(0)
}

fn main() {
    // --version / -V：只打印版本号就退出（装完包确认跑的是哪一版）
    if std::env::args().skip(1).any(|a| a == "--version" || a == "-V") {
        println!("cipherlane {}", VERSION);
        return;
    }

    #[cfg(unix)]
    block_termination_signals();

    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(7777);
    PORT.store(port, std::sync::atomic::Ordering::Relaxed);
    let host = std::env::var("HOST").unwrap_or_default();
    // HOST 未设 = 动态模式：监听 127.0.0.1 + 局域网（RFC1918）网卡，且地址后到 / 变化时
    // 自动补绑（见"监听器（动态绑定）"）；显式 HOST = 只监听该地址，绑不上直接退出。
    let dynamic = host.is_empty();

    // CIPHERLANE_TEST_LIMITS=1：仅降 per-IP 房间数/字节阈值，建房速率保持 120/min
    let test_limits = std::env::var("CIPHERLANE_TEST_LIMITS").map(|v| v == "1").unwrap_or(false);
    let limits = Limits {
        ip_rooms_max: if test_limits { 4 } else { PER_IP_ROOMS },
        ip_bytes_max: if test_limits { 2 * 1024 * 1024 } else { PER_IP_BYTES },
    };
    // Host/Origin 白名单只收主机名（IP 字面量在 host_allowed 里动态放行），所以后到的
    // 网卡地址不需要补进白名单
    let allowed_hosts = if dynamic {
        build_allowed_hosts(&["127.0.0.1".to_string()], &host)
    } else {
        build_allowed_hosts(&[host.clone()], &host)
    };

    let ctx = Arc::new(Ctx {
        world: Arc::new(World {
            rooms: Mutex::new(HashMap::new()),
            devices: Mutex::new(HashMap::new()),
            offers_by_id: Mutex::new(HashMap::new()),
            global_buffered: Mutex::new(0),
            ip_bytes: Mutex::new(HashMap::new()),
            ip_creates: Mutex::new(HashMap::new()),
            longpoll_count: Mutex::new(HashMap::new()),
            offers_mutex: Mutex::new(()),
            offers_cond: Condvar::new(),
            started_at: now_ms(),
        }),
        statics: static_routes(),
        limits,
        allowed_hosts,
        update: Mutex::new(UpdateState::default()),
        update_cond: Condvar::new(),
        listeners: Mutex::new(HashMap::new()),
        queue: Arc::new(RequestQueue::new()),
        port,
        dynamic,
    });

    // ---- 绑定 ----
    // 动态模式：回环必须绑上（端口被占等 → 退出并提示）；启动时已有的局域网地址单个绑不上
    // 不算致命（比如恰好有别的程序占了那一个地址的端口），记一笔、交给巡检重试。
    // 显式 HOST：只绑它，绑不上就退出（保持原有行为：地址写错要立刻暴露，而不是静默等待）。
    if dynamic {
        if let Err(e) = bind_listener(&ctx, "127.0.0.1") {
            print_bind_error("127.0.0.1", port, &e);
            std::process::exit(1);
        }
        let _serial = BIND_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let startup = lan_addresses();
        for ip in &startup {
            let ip = ip.to_string();
            if let Err(e) = bind_listener(&ctx, &ip) {
                eprintln!("[listen] 启动时无法监听局域网地址 {}:{}（会自动重试）：{}", ip, port, e);
                BIND_FAILED.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(ip);
            }
        }
    } else if let Err(e) = bind_listener(&ctx, &host) {
        print_bind_error(&host, port, &e);
        std::process::exit(1);
    }

    // 优雅停机线程：SIGTERM/SIGINT（unix）与面板停机（跨平台）共用排干路径
    #[cfg(unix)]
    {
        let ctx = ctx.clone();
        std::thread::spawn(move || loop {
            match wait_termination_signal() {
                libc::SIGINT => println!("\n再见"),
                _ => println!("\n收到 SIGTERM，正在优雅停机…"),
            }
            drain_and_exit(&ctx);
        });
    }
    {
        let ctx = ctx.clone();
        std::thread::spawn(move || loop {
            if SHUTDOWN_BY_PANEL.load(std::sync::atomic::Ordering::SeqCst) {
                // 先给 150ms 让 /api/shutdown 的 200 响应送达客户端（对齐 Node 版），
                // 再停派发、排干、退出
                std::thread::sleep(Duration::from_millis(150));
                drain_and_exit(&ctx);
            }
            std::thread::sleep(Duration::from_millis(50));
        });
    }

    std::thread::spawn({
        let ctx = ctx.clone();
        move || sweeper(ctx)
    });

    // 巡检线程：只负责"没人在页面上时地址才到"的情况；页面 / 托盘问 /api/version 时
    // 还会同步补绑一次，所以开机后第一次点开主页不需要等这个周期
    if ctx.dynamic {
        let ctx = ctx.clone();
        let poll = listener_poll();
        std::thread::spawn(move || loop {
            std::thread::sleep(poll);
            ensure_listeners(&ctx);
        });
    }

    // 共用的工作线程池：所有监听地址的请求都在这里处理
    let mut spawned = 0usize;
    for _ in 0..WORKERS {
        let ctx = ctx.clone();
        if std::thread::Builder::new().stack_size(WORKER_STACK).spawn(move || worker(ctx)).is_ok() {
            spawned += 1;
        }
    }
    // 线程起不来不能静默：一个 worker 都没有 = 接受请求却永远不处理
    if spawned == 0 {
        eprintln!("\n✗ 无法创建工作线程（系统线程数已达上限？），退出。");
        std::process::exit(1);
    } else if spawned < WORKERS {
        eprintln!("[cipherlane] 警告：工作线程只创建了 {spawned}/{WORKERS} 个，高并发时吞吐会下降");
    }

    println!("cipherlane · 密道 v{}（Rust）—— 局域网端到端加密传输", VERSION);
    println!("  服务器零知识：只中转密文，密钥永不离开收发双方的浏览器\n");
    let mut bound: Vec<String> = ctx.listeners.lock().unwrap_or_else(std::sync::PoisonError::into_inner).keys().cloned().collect();
    bound.sort_by_key(|a| (a.as_str() != "127.0.0.1", a.parse::<IpAddr>().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))));
    for ip in &bound {
        println!("  →  http://{}:{}", ip, port);
    }
    if dynamic && bound.len() < 2 {
        println!("  （还没有局域网地址：连上 Wi-Fi / 插上网线后会自动开始监听，不需要重启）");
    }
    println!("\n等待传输…（Ctrl+C 退出）");
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 测试辅助：插入分片并记账（产线的入账走 chunk POST 的 try_add 原子路径；
    // 这里独立构造同样语义，用于验证记账不变量本身）
    fn counter_add(c: &Mutex<usize>, n: usize) {
        let mut g = c.lock().unwrap();
        *g = g.saturating_add(n);
    }
    impl ByteAccount<'_> {
        fn add(&self, inner: &mut RoomInner, n: usize) {
            inner.bytes = inner.bytes.saturating_add(n);
            counter_add(self.global, n);
            let mut m = self.ip_bytes.lock().unwrap();
            let cur = m.get(self.ip).copied().unwrap_or(0);
            m.insert(self.ip.to_string(), cur.saturating_add(n));
        }
    }
    fn insert_chunk(inner: &mut RoomInner, acct: &ByteAccount, i: u64, body: Vec<u8>) -> usize {
        let arc = Arc::new(body);
        let added = arc.len();
        inner.buffer.insert(i, arc);
        acct.add(inner, added);
        added
    }

    fn empty_room() -> RoomInner {
        RoomInner {
            token: String::new(),
            posted: 0,
            head: 0,
            pulled: 0,
            buffer: HashMap::new(),
            bytes: 0,
            receiver_seen: false,
            sender_done: false,
            acked: false,
            ack_proof: None,
            resumable: false,
            through: 0,
            rejected_at: None,
            offer: None,
            dead: false,
        }
    }

    // 减法兜底：旧实现用裸 `-=`，减法先于加法时会回绕成巨值（窗口内其它上传被 429）。
    #[test]
    fn counter_sub_never_wraps() {
        let c = Mutex::new(0usize);
        counter_sub(&c, BODY_MAX);
        assert_eq!(*c.lock().unwrap_or_else(std::sync::PoisonError::into_inner), 0);
        counter_add(&c, 10);
        counter_sub(&c, 4);
        assert_eq!(*c.lock().unwrap_or_else(std::sync::PoisonError::into_inner), 6);
    }

    // 插入/取走分片后，房间字节数、全局计数与 ip_bytes 必须同步归零；重复取走不得二次扣减。
    #[test]
    fn insert_and_take_keep_byte_accounting_in_sync() {
        let c = Mutex::new(0usize);
        let ips = Mutex::new(HashMap::new());
        let acct = ByteAccount { global: &c, ip_bytes: &ips, ip: "10.0.0.1" };
        let mut room = empty_room();
        room.posted = 3;
        insert_chunk(&mut room, &acct, 0, vec![7u8; 1024]);
        insert_chunk(&mut room, &acct, 1, vec![7u8; 2048]);
        insert_chunk(&mut room, &acct, 2, vec![7u8; 512]);
        assert_eq!(*c.lock().unwrap_or_else(std::sync::PoisonError::into_inner), 3584);
        assert_eq!(*ips.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get("10.0.0.1").unwrap(), 3584);
        assert_eq!(room.bytes, 3584);
        // 越序先取 1：head 不得推进（否则 0 号分片会变成不可达垃圾）
        assert!(take_chunk(&mut room, &acct, 1).is_some());
        assert_eq!(room.head, 0);
        assert_eq!(room.bytes, 1536);
        // 按序取 0：head 推进到 1，并跳过已取走的 1 → 2
        assert!(take_chunk(&mut room, &acct, 0).is_some());
        assert_eq!(room.head, 2);
        assert_eq!(room.pulled, 2);
        // 重复取走不得二次扣减
        assert!(take_chunk(&mut room, &acct, 0).is_none());
        assert_eq!(*c.lock().unwrap_or_else(std::sync::PoisonError::into_inner), 512);
        assert_eq!(*ips.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get("10.0.0.1").unwrap(), 512);
        assert!(take_chunk(&mut room, &acct, 2).is_some());
        assert_eq!(*c.lock().unwrap_or_else(std::sync::PoisonError::into_inner), 0);
        assert!(!ips.lock().unwrap_or_else(std::sync::PoisonError::into_inner).contains_key("10.0.0.1"));
    }

    // progress 只释放 [1, through) 的数据分片，0 号 manifest 必须保留（续传重读用）。
    #[test]
    fn progress_releases_below_through_but_keeps_manifest() {
        let c = Mutex::new(0usize);
        let ips = Mutex::new(HashMap::new());
        let acct = ByteAccount { global: &c, ip_bytes: &ips, ip: "10.0.0.1" };
        let mut room = empty_room();
        for i in 0..3u64 {
            insert_chunk(&mut room, &acct, i, vec![0u8; 100]);
        }
        room.posted = 3; // 真实路径里 posted 由 handler 递增，insert_chunk 只管数据与记账
        assert_eq!(*c.lock().unwrap_or_else(std::sync::PoisonError::into_inner), 300);
        assert!(advance_through(&mut room, &acct, 2));
        assert_eq!(*c.lock().unwrap_or_else(std::sync::PoisonError::into_inner), 200);
        assert_eq!(*ips.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get("10.0.0.1").unwrap(), 200);
        assert!(room.buffer.contains_key(&0));
        assert!(advance_through(&mut room, &acct, 2)); // 重复/滞后上报幂等
        assert_eq!(*c.lock().unwrap_or_else(std::sync::PoisonError::into_inner), 200);
    }

    // X-Chunk-Seq 必须是严格十进制安全整数：+1/-1/中间空白/小数/非 ASCII/溢出/超 2^53-1
    // 一律 400 bad-seq；首尾 OWS（空格/制表符）与 Node req.headers 的 trim 行为对齐。
    #[test]
    fn chunk_seq_parsing_is_strict_decimal() {
        assert_eq!(parse_chunk_seq(b"0"), Some(0));
        assert_eq!(parse_chunk_seq(b"007"), Some(7));
        assert_eq!(parse_chunk_seq(b" 1 "), Some(1));
        assert_eq!(parse_chunk_seq(b"\t2\t"), Some(2));
        assert_eq!(parse_chunk_seq(b"9007199254740991"), Some(CHUNK_SEQ_MAX));
        for bad in [
            &b""[..],
            &b" "[..],
            &b"+1"[..],
            &b"-1"[..],
            &b"1 2"[..],
            &b"1\t2"[..],
            &b"1.0"[..],
            &b"1e3"[..],
            &b"a"[..],
            &b"9007199254740992"[..],
            &b"18446744073709551615"[..],
            &b"18446744073709551616"[..],
            &b"\xf0\x9f\x98\x80"[..],
        ] {
            assert!(parse_chunk_seq(bad).is_none(), "应拒绝 {:?}", bad);
        }
    }

    // 地址来源文件：每行一个 IPv4，# 之后是注释；去重、保持顺序；非法行忽略
    #[test]
    fn addrs_file_parsing() {
        use std::net::Ipv4Addr;
        let none: Vec<Ipv4Addr> = Vec::new();
        assert_eq!(parse_addrs_file(""), none);
        assert_eq!(parse_addrs_file("# 只有注释\n\n   \n"), none);
        assert_eq!(parse_addrs_file("文件不存在时读到的是空串也一样"), none);
        assert_eq!(
            parse_addrs_file("127.0.0.2\n# 192.168.9.9\n 192.168.1.5 # 行尾注释\n127.0.0.2\nnot-an-ip\nfe80::1\n999.1.1.1\n"),
            vec!["127.0.0.2".parse::<Ipv4Addr>().unwrap(), "192.168.1.5".parse::<Ipv4Addr>().unwrap()]
        );
    }

    // 共用请求队列：先进先出；停机令牌只让取到它的那一个 worker 退出，不会吞掉前后的请求
    #[test]
    fn request_queue_is_fifo_and_tokens_are_per_worker() {
        let q: RequestQueue<u32> = RequestQueue::new();
        q.push(1);
        q.unblock();
        q.push(2);
        q.unblock();
        q.push(3);
        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), None, "第一个令牌：取到它的 worker 退出");
        assert_eq!(q.pop(), Some(2), "令牌之后的请求照常处理");
        assert_eq!(q.pop(), None, "第二个令牌");
        assert_eq!(q.pop(), Some(3));
    }

    // 巡检周期的钳位：默认 1s；下限 200ms；上限 1 小时
    #[test]
    fn listener_poll_is_clamped() {
        assert_eq!(clamp_poll_ms(1000), 1000);
        assert_eq!(clamp_poll_ms(0), 200);
        assert_eq!(clamp_poll_ms(1), 200);
        assert_eq!(clamp_poll_ms(199), 200);
        assert_eq!(clamp_poll_ms(200), 200);
        assert_eq!(clamp_poll_ms(u64::MAX), 3_600_000);
    }

    // 仅供单元测试：在指定端口上建一个动态模式的 Ctx（World 是全新的空状态）
    fn test_ctx(port: u16) -> Arc<Ctx> {
        Arc::new(Ctx {
            world: Arc::new(World {
                rooms: Mutex::new(HashMap::new()),
                devices: Mutex::new(HashMap::new()),
                offers_by_id: Mutex::new(HashMap::new()),
                global_buffered: Mutex::new(0),
                ip_bytes: Mutex::new(HashMap::new()),
                ip_creates: Mutex::new(HashMap::new()),
                longpoll_count: Mutex::new(HashMap::new()),
                offers_mutex: Mutex::new(()),
                offers_cond: Condvar::new(),
                started_at: 0,
            }),
            statics: static_routes(),
            limits: Limits { ip_rooms_max: PER_IP_ROOMS, ip_bytes_max: PER_IP_BYTES },
            allowed_hosts: HashSet::new(),
            update: Mutex::new(UpdateState::default()),
            update_cond: Condvar::new(),
            listeners: Mutex::new(HashMap::new()),
            queue: Arc::new(RequestQueue::new()),
            port,
            dynamic: true,
        })
    }

    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    }

    // 自愈：某个监听器的泵退出（等价于 tiny_http 的 accept 线程出错）后，这个地址从监听器表
    // 摘掉，下一次 ensure_listeners 重新绑上，连接继续被接受。旧实现里一次 accept 失败
    // 意味着这个地址到重启前一直死着。
    // 用 unblock() 触发泵退出：对泵而言 recv() 返回 Err 的两种原因（停机 / 内部出错）在此等价。
    #[test]
    fn dead_listener_is_rebound() {
        use std::sync::atomic::Ordering;
        // 供 ensure_listeners 用的地址来源：只列回环（不依赖本机真实网卡）
        let dir = std::env::temp_dir().join(format!("cipherlane-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("addrs.txt");
        std::fs::write(&file, "127.0.0.1\n").unwrap();

        let port = free_port();
        let ctx = test_ctx(port);
        // 共用队列需要有 worker 在消费（main 里同样起这些线程）
        for _ in 0..2 {
            std::thread::spawn({
                let ctx = ctx.clone();
                move || worker(ctx)
            });
        }
        std::env::set_var("CIPHERLANE_LAN_ADDRS_FILE", &file);
        struct EnvGuard(&'static str);
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                std::env::remove_var(self.0);
            }
        }
        let _guard = EnvGuard("CIPHERLANE_LAN_ADDRS_FILE"); // 断言失败也把环境变量清掉
        ensure_listeners(&ctx);
        let first = ctx.listeners.lock().unwrap().get("127.0.0.1").cloned().expect("回环应已绑定");
        assert!(
            matches!(first.server_addr(), tiny_http::ListenAddr::IP(a) if a.port() == port),
            "监听器应在测试选的端口上：{:?}",
            first.server_addr()
        );
        assert!(!SHUTTING_DOWN.load(Ordering::SeqCst), "测试前不应处于停机状态");
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok(), "刚绑上就应接受连接");

        // 泵退出 = 这个监听器死了
        first.unblock();
        let gone = (0..200).any(|_| {
            if ctx.listeners.lock().unwrap().contains_key("127.0.0.1") {
                std::thread::sleep(Duration::from_millis(10));
                false
            } else {
                true
            }
        });
        assert!(gone, "泵退出后监听器应从表里摘掉");

        // 生产环境里没有人再持有旧监听器：泵一退出它就被 Drop，Drop 会让 tiny_http 的 accept
        // 线程退出、套接字关闭。测试这边同样放手，再去重新绑
        drop(first);
        // 自愈：重新绑上（旧套接字可能还要几毫秒才关完，所以这里允许几轮重试——生产里由
        // 巡检的下一轮承担同样的重试），然后请求照常被处理
        let rebound = (0..300).any(|_| {
            ensure_listeners(&ctx);
            if ctx.listeners.lock().unwrap().contains_key("127.0.0.1") {
                true
            } else {
                std::thread::sleep(Duration::from_millis(10));
                false
            }
        });
        assert!(rebound, "应重新绑上");
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("重新绑上的地址应接受连接");
        stream.write_all(b"GET /api/version HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        assert!(buf.starts_with(b"HTTP/1."), "请求应被处理：{}", String::from_utf8_lossy(&buf));
        drop(_guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // 停机开始后不再补绑：drain_and_exit 期间泵退出是正常的，不能反过来触发重新监听。
    // 不动全局的 SHUTTING_DOWN（单元测试并行跑），直接验证"不允许时什么都不绑"
    #[test]
    fn no_rebinding_once_shutting_down() {
        let ctx = test_ctx(free_port());
        ensure_listeners_if(&ctx, false);
        assert!(ctx.listeners.lock().unwrap().is_empty(), "停机中不应绑任何地址");
        // 对照：允许时把当前枚举到的地址都绑上（地址来源仍是真实网卡——只验证"会绑"，不验证绑了谁）
        ensure_listeners_if(&ctx, true);
        assert!(ctx.listeners.lock().unwrap().contains_key("127.0.0.1"), "允许时应至少绑上回环");
    }

    #[test]
    fn host_origin_gate_follows_node_rules() {
        let mut allowed = HashSet::new();
        for h in ["localhost", "127.0.0.1", "::1", "mybox.lan", "cipherlane-insecure.test"] {
            allowed.insert(h.to_string());
        }
        // Host：IP 字面量动态放行；域名只在白名单；端口/大小写/尾点归一化
        assert!(host_allowed("127.0.0.1:7777", &allowed));
        assert!(host_allowed("[::1]:7777", &allowed));
        assert!(host_allowed("::1", &allowed));
        assert!(host_allowed("192.168.1.9:7777", &allowed));
        assert!(host_allowed("LOCALHOST.:7777", &allowed));
        assert!(host_allowed("mybox.lan:7777", &allowed));
        assert!(!host_allowed("evil.example", &allowed));
        assert!(!host_allowed("", &allowed));
        // Origin/Referer：缺失放行；有值则 host 必须合法
        assert!(origin_allowed("", &allowed));
        assert!(origin_allowed("http://127.0.0.1:7777", &allowed));
        assert!(origin_allowed("https://cipherlane-insecure.test:7777/page", &allowed));
        assert!(!origin_allowed("https://evil.example", &allowed));
        assert!(!origin_allowed("not-a-url", &allowed));
    }

    #[test]
    fn semver_compares_numeric_segments() {
        assert!(semver_newer("9.9.9", "0.5.1"));
        assert!(semver_newer("0.6", "0.5.1"));
        assert!(!semver_newer("0.0.1", "0.5.1"));
        assert!(!semver_newer("0.5.1", "0.5.1"));
        assert!(semver_newer("v1.0.0", "0.9.9"));
        assert!(!semver_newer("garbage", "0.5.1"));
        assert!(!semver_newer("0.5.1", "garbage"));
    }

    #[test]
    fn device_name_control_chars_are_stripped() {
        assert_eq!(clean_device_name("evil\u{1b}[31m\u{0}line\nname\u{9b}"), "evil[31mlinename");
        assert_eq!(clean_device_name("  \u{1b}\u{0}  "), "未命名设备");
        assert_eq!(clean_device_name("正常名字"), "正常名字");
        let long: String = "a".repeat(DEVICE_NAME_MAX + 5);
        assert_eq!(clean_device_name(&long).chars().count(), DEVICE_NAME_MAX);
    }

    #[test]
    fn constant_time_compare_and_etag_helpers() {
        assert!(ct_eq("abcdef", "abcdef"));
        assert!(!ct_eq("abcdef", "abcdeg"));
        assert!(!ct_eq("abc", "abcdef"));
        let etag = "\"0123456789abcdef\"";
        assert!(etag_matches(etag, etag));
        assert!(etag_matches("*", etag));
        assert!(etag_matches(&format!("W/\"x\", {}", etag), etag));
        assert!(!etag_matches("\"other\"", etag));
        assert_eq!(parse_strict_digits("007"), Some(7));
        assert_eq!(parse_strict_digits(""), None);
        assert_eq!(parse_strict_digits("+1"), None);
        assert_eq!(parse_strict_digits("1 "), None);
        assert_eq!(parse_strict_digits("9007199254740992"), None);
    }
}
