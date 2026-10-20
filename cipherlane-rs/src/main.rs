// cipherlane · 密道 —— Rust 重构版服务器
//
// 线协议与 Node 版(server.js)逐字节兼容；验收 = test/protocol.test.mjs 对本实现全绿。
// 架构：tiny_http 同步模型 + 每地址 256 工作线程；长轮询以 Condvar 挂起
// （LAN 规模下每接收方 ≤4 个挂起请求，线程余量充足）。
// 零知识：服务器只存转 AES-256-GCM 密文分片，永不做任何加解密。
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Response, Server};

// ---------- 限制（与 server.js 一致） ----------
const ROOMS_MAX: usize = 128;
const BODY_MAX: usize = 1536 * 1024;
const ROOM_CHUNKS_BUF: u64 = 64;
const ROOM_BYTES_MAX: usize = 64 * 1024 * 1024;
const GLOBAL_BYTES_MAX: usize = 256 * 1024 * 1024;
const ROOM_IDLE_MS: u128 = 15 * 60 * 1000;
const ACK_IDLE_MS: u128 = 2 * 60 * 1000;
const LONGPOLL: Duration = Duration::from_secs(25);
const ALIVE_SLICE: Duration = Duration::from_millis(100);
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
// 工作线程：每监听地址 128 个、128KB 小栈。足以承载 LAN 规模的长轮询并发
// （每接收方 ≤4 挂起 × 30 设备 ≈ 120）；小栈把虚拟内存从 2MB/线程压到 128KB，
// 避免 256×2MB=1.6GB VIRT 被 system monitor 误读为"内存泄漏"（实际 RSS ~5MB）。
const WORKERS: usize = 128;
const WORKER_STACK: usize = 128 * 1024;
const ROOM_ID_LEN: usize = 10;

const B62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const VERSION: &str = env!("CARGO_PKG_VERSION");
static PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(7777);

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

// ---------- 静态资源（编译期内嵌，等价 SEA） ----------
struct StaticFile {
    data: Vec<u8>,
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
        let data = data.to_vec();
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
            e.1.data = s.into_bytes();
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
    created_at: u128,
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
    since: u128,
    last_seen: Mutex<u128>,
}
struct World {
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
// 密文字节记账（room.bytes / global_buffered / ip_bytes 必须在同一处成对增减）
struct ByteAccount<'a> {
    global: &'a Mutex<usize>,
    ip_bytes: &'a Mutex<HashMap<String, usize>>,
    ip: &'a str,
}
impl ByteAccount<'_> {
    fn add(&self, inner: &mut RoomInner, n: usize) {
        inner.bytes = inner.bytes.saturating_add(n);
        counter_add(self.global, n);
        let mut m = self.ip_bytes.lock().unwrap();
        let cur = m.get(self.ip).copied().unwrap_or(0);
        m.insert(self.ip.to_string(), cur.saturating_add(n));
    }
    fn del(&self, inner: &mut RoomInner, n: usize) {
        if n == 0 {
            return;
        }
        inner.bytes = inner.bytes.saturating_sub(n);
        counter_sub(self.global, n);
        ip_bytes_sub(self.ip_bytes, self.ip, n);
    }
}
fn ip_bytes_sub(map: &Mutex<HashMap<String, usize>>, ip: &str, n: usize) {
    let mut m = map.lock().unwrap();
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
fn json_resp(mut res: tiny_http::Request, code: u16, body: String) {
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
    *room.last_active.lock().unwrap() = now_ms();
}
// 全局缓冲计数：所有加值都必须在持有房间 inner 锁时完成（锁序 inner → global_buffered），
// 与 take_chunk / advance_through / destroy_room 的减法串行，避免"减法先于加法"造成
// usize 瞬时回绕（窗口内并发上传会被误判超限 429）。减法再用 saturating_sub 兜底：
// 即使将来记账再出错，也不会留下一个巨大计数把全站上传永久顶死。
fn counter_add(c: &Mutex<usize>, n: usize) {
    let mut g = c.lock().unwrap();
    *g = g.saturating_add(n);
}
fn counter_sub(c: &Mutex<usize>, n: usize) {
    let mut g = c.lock().unwrap();
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
// Host 头归一化：去端口 / 去 IPv6 方括号 / 小写 / 去尾点（对齐 server.js hostnameOf）
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
        let mut m = world.longpoll_count.lock().unwrap();
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
        let mut m = self.world.longpoll_count.lock().unwrap();
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
    now_ms().saturating_sub(*d.last_seen.lock().unwrap()) <= DEVICE_TTL_MS
}
fn pending_offers_for(world: &World, ip: &str) -> Vec<serde_json::Value> {
    let rooms = world.rooms.lock().unwrap();
    let now = now_ms();
    let mut list = vec![];
    for room in rooms.values() {
        let inner = room.inner.lock().unwrap();
        if let Some(o) = &inner.offer {
            if o.to_ip == ip && *o.state.lock().unwrap() == "pending" && now.saturating_sub(o.created_at) <= OFFER_TTL_MS {
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
// 插入分片并记账：inner.bytes / global_buffered / ip_bytes 的加值都在调用方持有的
// inner 锁内完成，与所有减法路径串行，杜绝“减法先于加法”的瞬时回绕。
fn insert_chunk(inner: &mut RoomInner, acct: &ByteAccount, i: u64, body: Vec<u8>) -> usize {
    let arc = Arc::new(body);
    let added = arc.len();
    inner.buffer.insert(i, arc);
    acct.add(inner, added);
    added
}
fn destroy_room(world: &World, room: &Arc<Room>) {
    {
        let mut rooms = world.rooms.lock().unwrap();
        if !rooms.contains_key(&room.id) {
            return;
        }
        rooms.remove(&room.id);
    }
    {
        let mut inner = room.inner.lock().unwrap();
        let bytes = std::mem::take(&mut inner.bytes);
        inner.buffer.clear();
        // 与 global_buffered / ip_bytes 在同一临界区成对释放
        counter_sub(&world.global_buffered, bytes);
        ip_bytes_sub(&world.ip_bytes, &room.sender_ip, bytes);
        inner.dead = true;
        if let Some(o) = &inner.offer {
            world.offers_by_id.lock().unwrap().remove(&o.id);
            println!("[offer] - {}（房间销毁）", o.id);
        }
    }
    room.cond.notify_all();
    println!("[room] - {}", room.id);
}
// 滑动 60s 建房速率：返回 0 = 已记账允许；>0 = 需等待的秒数
fn create_rate_wait(world: &World, ip: &str, now: u128) -> u64 {
    let mut m = world.ip_creates.lock().unwrap();
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
    let _guard = match LongpollGuard::enter(world, ip) {
        Some(g) => g,
        None => return Pull::TooMany,
    };
    let deadline = Instant::now() + LONGPOLL;
    let mut inner = room.inner.lock().unwrap();
    if resume {
        inner.resumable = true;
    }
    let mut parked = false;
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
        let slice = (deadline - now).min(ALIVE_SLICE);
        let (guard, _) = room.cond.wait_timeout(inner, slice).unwrap();
        inner = guard;
        parked = true;
    }
}

// ---------- 邀请长轮询 ----------
fn wait_offers(world: &Arc<World>, ip: &str, remote: Option<SocketAddr>) -> Result<Vec<serde_json::Value>, ()> {
    let _guard = LongpollGuard::enter(world, ip).ok_or(())?;
    let deadline = Instant::now() + LONGPOLL;
    let mut m = world.offers_mutex.lock().unwrap();
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
        let slice = (deadline - now).min(ALIVE_SLICE);
        let (guard, _) = world.offers_cond.wait_timeout(m, slice).unwrap();
        m = guard;
    }
}

// ---------- 极简 HTTP GET（检查更新用，仅 http；https 见 fetch_update 的说明） ----------
fn http_get_text(url: &str, timeout: Duration) -> Result<String, String> {
    let rest = url.strip_prefix("http://").ok_or("仅支持 http 更新源")?;
    let (hostport, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp.to_string(), format!("/{}", p)),
        None => (rest.to_string(), "/".to_string()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h.to_string(), p.parse::<u16>().unwrap_or(80)),
        _ => (hostport.clone(), 80),
    };
    let addr = format!("{}:{}", host, port);
    let mut stream = None;
    for a in addr.to_socket_addrs().map_err(|e| e.to_string())? {
        if let Ok(s) = TcpStream::connect_timeout(&a, timeout) {
            stream = Some(s);
            break;
        }
    }
    let mut stream = stream.ok_or("连接更新源失败")?;
    stream.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    write!(stream, "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n", path, hostport).map_err(|e| e.to_string())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).map_err(|e| e.to_string())?;
    let (head, body) = match raw.split_once("\r\n\r\n") {
        Some((h, b)) => (h, b.to_string()),
        None => (raw.as_str(), String::new()),
    };
    let status = head.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(format!("upstream {}", status));
    }
    Ok(body)
}
// 返回 (是否可缓存, JSON 响应体)。https 无 TLS 依赖：如实返回错误而不是假成功。
fn fetch_update(url: &str, timeout: Duration) -> (bool, String) {
    let fetched = match update_scheme(url).as_deref() {
        Some("http") => http_get_text(url, timeout),
        Some("https") => Err("https 更新源暂不支持（Rust 版无 TLS）".to_string()),
        _ => Err("bad-update-url".to_string()),
    };
    match fetched {
        Ok(text) => {
            let latest = text.trim().to_string();
            let newer = semver_newer(&latest, VERSION);
            (true, serde_json::json!({"source": url, "current": VERSION, "latest": latest, "newer": newer}).to_string())
        }
        Err(e) => (false, serde_json::json!({"source": url, "current": VERSION, "error": e}).to_string()),
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

fn send_static(mut req: tiny_http::Request, f: &StaticFile) {
    let is_html = f.ctype.starts_with("text/html");
    if !is_html && etag_matches(&hdr(&req, "If-None-Match"), &f.etag) {
        let _ = req.respond(decorate_static(Response::empty(304), f));
        return;
    }
    let _ = req.respond(decorate_static(Response::from_data(f.data.clone()), f));
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
        let existing = w.devices.lock().unwrap().get(&ip).cloned();
        if let Some(prev) = existing {
            if !secret_hdr.is_empty() && ct_eq(&prev.secret, &secret_hdr) {
                *prev.name.lock().unwrap() = name;
                *prev.pub_.lock().unwrap() = pub_;
                *prev.last_seen.lock().unwrap() = now_ms();
                return json_resp(req, 200, serde_json::json!({ "ip": ip, "id": prev.id, "secret": prev.secret }).to_string());
            }
        }
        {
            let devices = w.devices.lock().unwrap();
            if devices.len() >= DEVICES_MAX && !devices.contains_key(&ip) {
                return jerr(req, 503, "too-many-devices");
            }
        }
        let dev = Arc::new(Device {
            ip: ip.clone(),
            id: rand_hex16(),
            secret: rand_secret32(),
            name: Mutex::new(name),
            pub_: Mutex::new(pub_),
            since: now_ms(),
            last_seen: Mutex::new(now_ms()),
        });
        println!("[device] + {} {}", dev.ip, dev.name.lock().unwrap());
        let (id, secret) = (dev.id.clone(), dev.secret.clone());
        w.devices.lock().unwrap().insert(ip.clone(), dev);
        return json_resp(req, 200, serde_json::json!({ "ip": ip, "id": id, "secret": secret }).to_string());
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
        let rooms = w.rooms.lock().unwrap().len();
        // lan：本机首选局域网地址（供回环来源的客户端升级链接/跳转目标；无则 null）
        let lan = lan_addresses().first().map(|a| a.to_string());
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
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(150));
            std::process::exit(0);
        });
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
            let st = ctx.update.lock().unwrap();
            if let Some((at, payload)) = &st.cache {
                if now_ms().saturating_sub(*at) < UPDATE_CACHE_MS {
                    return json_resp(req, 200, payload.clone());
                }
            }
        }
        // 单飞：已有上游请求进行中则等它完成，共享同一结果（成功或错误）
        {
            let mut st = ctx.update.lock().unwrap();
            if st.inflight {
                while st.inflight {
                    st = ctx.update_cond.wait(st).unwrap();
                }
                if let Some(p) = st.last_result.clone() {
                    return json_resp(req, 200, p);
                }
            }
            st.inflight = true;
        }
        let (cacheable, payload) = fetch_update(&url, Duration::from_secs(5));
        {
            let mut st = ctx.update.lock().unwrap();
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
        let devices = w.devices.lock().unwrap();
        let mut list: Vec<serde_json::Value> = devices
            .values()
            .filter(|d| device_alive(d))
            .map(|d| serde_json::json!({ "ip": d.ip, "id": d.id, "name": *d.name.lock().unwrap(), "pub": *d.pub_.lock().unwrap() }))
            .collect();
        // HashMap 迭代顺序每个进程随机；按 IP 排序让 /api/devices 输出确定，客户端/测试
        // 不依赖哈希顺序（本机回环 + LAN 地址可能同时存在多个设备条目）。
        list.sort_by(|a, b| a["ip"].as_str().unwrap_or("").cmp(b["ip"].as_str().unwrap_or("")));
        return json_resp(req, 200, serde_json::json!({ "devices": list }).to_string());
    }

    // ---- GET /api/offers：长轮询 ----
    if path == "/api/offers" && method == "GET" {
        let secret = hdr(&req, "X-Device-Secret");
        let dev = { w.devices.lock().unwrap().get(&ip).filter(|d| ct_eq(&d.secret, &secret)).cloned() };
        let dev = match dev {
            Some(d) => d,
            None => return jerr(req, 401, "bad-secret"),
        };
        *dev.last_seen.lock().unwrap() = now_ms();
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
            let dev = { w.devices.lock().unwrap().get(&ip).filter(|d| ct_eq(&d.secret, &secret)).cloned() };
            if dev.is_none() {
                return jerr(req, 401, "bad-secret");
            }
            let offer_id = parts[0];
            let room_id = w.offers_by_id.lock().unwrap().get(offer_id).cloned();
            let room = room_id.and_then(|rid| w.rooms.lock().unwrap().get(&rid).cloned());
            let room = match room {
                Some(r) => r,
                None => return jerr(req, 410, "gone"),
            };
            {
                let inner = room.inner.lock().unwrap();
                let offer = match &inner.offer {
                    Some(o) if o.id == offer_id => o.clone(),
                    _ => return jerr(req, 410, "gone"),
                };
                if *offer.state.lock().unwrap() != "pending" || offer.to_ip != ip {
                    return jerr(req, 410, "gone");
                }
            }
            let _ = read_body(&mut req, 1024);
            // 读包期间房间可能已被 DELETE/清扫销毁（roomAlive 语义）
            if room.inner.lock().unwrap().dead {
                return jerr(req, 410, "gone");
            }
            touch(&room);
            let mut inner = room.inner.lock().unwrap();
            let offer_opt = inner.offer.clone();
            if let Some(offer) = offer_opt {
                if parts[1] == "accept" {
                    *offer.state.lock().unwrap() = "accepted".into();
                    println!("[offer] ✓ {} {} → {}", offer.id, offer.from_ip, ip);
                    let rid = room.id.clone();
                    drop(inner);
                    return json_resp(req, 200, serde_json::json!({ "ok": true, "room": rid }).to_string());
                }
                *offer.state.lock().unwrap() = "rejected".into();
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
        {
            let rooms = w.rooms.lock().unwrap();
            let by_ip = rooms.values().filter(|r| r.sender_ip == ip).count();
            if by_ip >= ctx.limits.ip_rooms_max {
                drop(rooms);
                return json_resp(req, 429, "{\"error\":\"ip-quota\",\"retry\":1}".into());
            }
            if rooms.len() >= ROOMS_MAX {
                drop(rooms);
                return jerr(req, 503, "too-many-rooms");
            }
        }
        let id = rand_room_id();
        let room = Arc::new(Room {
            id: id.clone(),
            sender_ip: ip.clone(),
            created_at: now_ms(),
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
        let token = room.inner.lock().unwrap().token.clone();
        w.rooms.lock().unwrap().insert(id.clone(), room);
        println!("[room] + {}", id);
        return json_resp(req, 200, serde_json::json!({ "room": id, "token": token }).to_string());
    }

    // ---- /api/rooms/:id[/sub] ----
    if let Some(rest) = path.strip_prefix("/api/rooms/") {
        let parts: Vec<&str> = rest.split('/').collect();
        if !parts.is_empty() && valid_room_id(parts[0]) {
            let sub = parts.get(1).copied().unwrap_or("");
            let token_hdr = hdr(&req, "X-Room-Token");
            let room = w.rooms.lock().unwrap().get(parts[0]).cloned();

            if method == "DELETE" && sub.is_empty() {
                return match room {
                    None => jerr(req, 404, "no-room"),
                    Some(r) => {
                        if !ct_eq(&token_hdr, &r.inner.lock().unwrap().token) {
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
            let token_ok = ct_eq(&token_hdr, &room.inner.lock().unwrap().token);

            // GET state
            if sub == "state" && method == "GET" {
                let inner = room.inner.lock().unwrap();
                let offer_state = inner.offer.as_ref().map(|o| o.state.lock().unwrap().clone());
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
                    let inner = room.inner.lock().unwrap();
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
                if room.inner.lock().unwrap().dead {
                    return jerr(req, 410, "gone");
                }
                let to = j.get("to").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let pub_ = j.get("pub").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let hint = j.get("hint").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let target = { w.devices.lock().unwrap().get(&to).filter(|d| device_alive(d)).cloned() };
                let target = match target {
                    Some(t) => t,
                    None => return jerr(req, 404, "device-offline"),
                };
                if !valid_pub(&pub_) {
                    return jerr(req, 400, "bad-pub");
                }
                if hint.len() > 4096 {
                    return jerr(req, 400, "bad-hint");
                }
                {
                    let rooms = w.rooms.lock().unwrap();
                    let pending = rooms.values().filter(|r| {
                        let inner = r.inner.lock().unwrap();
                        inner.offer.as_ref().map(|o| *o.state.lock().unwrap() == "pending" && o.to_ip == to).unwrap_or(false)
                    }).count();
                    if pending >= OFFERS_MAX {
                        return jerr(req, 429, "too-many-offers");
                    }
                }
                let sender = { w.devices.lock().unwrap().get(&ip).cloned() };
                let from_name = sender.as_ref().filter(|d| device_alive(d)).map(|d| d.name.lock().unwrap().clone());
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
                    let mut inner = room.inner.lock().unwrap();
                    inner.offer = Some(offer);
                }
                w.offers_by_id.lock().unwrap().insert(oid.clone(), room.id.clone());
                touch(&room);
                drop(w.offers_mutex.lock().unwrap());
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
                let mut inner = room.inner.lock().unwrap();
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
                let global = *w.global_buffered.lock().unwrap();
                // per-IP 字节配额：按房间创建者 IP 归属（与 Node 的 room.senderIp 一致）
                let ip_used = w.ip_bytes.lock().unwrap().get(&room.sender_ip).copied().unwrap_or(0);
                if outstanding >= ROOM_CHUNKS_BUF
                    || inner.bytes + body.len() > ROOM_BYTES_MAX
                    || global + body.len() > GLOBAL_BYTES_MAX
                    || ip_used + body.len() > ctx.limits.ip_bytes_max
                {
                    drop(inner);
                    return json_resp(req, 429, "{\"error\":\"backpressure\",\"retry\":1}".into());
                }
                let i = inner.posted;
                inner.posted += 1;
                // 记账与插入在同一 inner 临界区内完成（inner.bytes/global/ip_bytes 成对增减）
                let acct = ByteAccount { global: &w.global_buffered, ip_bytes: &w.ip_bytes, ip: &room.sender_ip };
                insert_chunk(&mut inner, &acct, i, body);
                drop(inner);
                touch(&room);
                room.cond.notify_all();
                return json_resp(req, 200, serde_json::json!({ "index": i }).to_string());
            }

            // GET chunk?i=N（X-Resume: 1 可续传）
            if sub == "chunk" && method == "GET" {
                // 缺省/空/带符号/超安全整数一律 400，不能用 Number(null)=0 静默消费 0 号分片
                let i_raw: Option<&str> = query
                    .split('&')
                    .find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == "i").map(|(_, v)| v));
                let i = match i_raw.and_then(parse_strict_digits) {
                    Some(v) => v,
                    None => return jerr(req, 400, "bad-index"),
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
                room.inner.lock().unwrap().sender_done = true;
                touch(&room);
                room.cond.notify_all();
                return json_resp(req, 200, "{\"ok\":true}".into());
            }

            // POST progress —— 可续传模式：接收方上报已落盘分片数
            if sub == "progress" && method == "POST" {
                let body = read_body(&mut req, 1024).unwrap_or_default();
                // 读包期间房间可能已被销毁（roomAlive 语义）
                if room.inner.lock().unwrap().dead {
                    return jerr(req, 410, "gone");
                }
                let through = serde_json::from_slice::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|j| j.get("through").and_then(|v| v.as_u64()));
                let through = match through {
                    Some(t) => t,
                    None => return jerr(req, 400, "bad-through"),
                };
                let mut inner = room.inner.lock().unwrap();
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
                if room.inner.lock().unwrap().dead {
                    return jerr(req, 410, "gone");
                }
                let proof = serde_json::from_slice::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|j| j.get("proof").and_then(|v| v.as_str().map(String::from)))
                    .filter(|p| p.len() == 64 && p.bytes().all(|b| b.is_ascii_hexdigit()));
                {
                    let mut inner = room.inner.lock().unwrap();
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
        let rooms: Vec<Arc<Room>> = w.rooms.lock().unwrap().values().cloned().collect();
        for room in rooms {
            let idle = now.saturating_sub(*room.last_active.lock().unwrap());
            let (acked, offer_expired, reject_expired) = {
                let inner = room.inner.lock().unwrap();
                let oe = inner.offer.as_ref().map(|o| *o.state.lock().unwrap() == "pending" && now.saturating_sub(o.created_at) > OFFER_TTL_MS).unwrap_or(false);
                let re = inner.rejected_at.map(|t| now.saturating_sub(t) > REJECT_GRACE_MS).unwrap_or(false);
                (inner.acked, oe, re)
            };
            if (acked && idle > ACK_IDLE_MS) || idle > ROOM_IDLE_MS || offer_expired || reject_expired {
                destroy_room(w, &room);
            }
        }
        w.devices.lock().unwrap().retain(|_, d| now.saturating_sub(*d.last_seen.lock().unwrap()) <= DEVICE_MEM_MS);
        // 建房速率窗口清理，避免按 IP 无界增长
        let mut creates = w.ip_creates.lock().unwrap();
        creates.retain(|_, ts| {
            ts.retain(|t| now.saturating_sub(*t) < 60_000);
            !ts.is_empty()
        });
    }
}

// ---------- 启动 ----------
fn lan_addresses() -> Vec<std::net::Ipv4Addr> {
    let mut out = vec![];
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for i in ifaces {
            if let std::net::IpAddr::V4(v4) = i.ip() {
                if !v4.is_loopback() && v4.is_private() && !out.contains(&v4) {
                    out.push(v4);
                }
            }
        }
    }
    out
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

// SIGTERM/SIGINT：异步信号安全地打印停机文案后 exit 0（与 Node 的优雅停机语义对齐）。
// Node 的 SIGINT 文案是“再见”，SIGTERM 是“正在优雅停机…”，这里保持一致。
#[cfg(unix)]
fn install_signal_handlers() {
    extern "C" fn on_sigterm(_: libc::c_int) {
        const MSG: &[u8] = "\n收到 SIGTERM，正在优雅停机…\n".as_bytes();
        unsafe {
            libc::write(1, MSG.as_ptr() as *const libc::c_void, MSG.len());
            libc::_exit(0);
        }
    }
    extern "C" fn on_sigint(_: libc::c_int) {
        const MSG: &[u8] = "\n再见\n".as_bytes();
        unsafe {
            libc::write(1, MSG.as_ptr() as *const libc::c_void, MSG.len());
            libc::_exit(0);
        }
    }
    unsafe {
        libc::signal(libc::SIGTERM, on_sigterm as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t);
    }
}

fn main() {
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(7777);
    PORT.store(port, std::sync::atomic::Ordering::Relaxed);
    let host = std::env::var("HOST").unwrap_or_default();

    // 默认绑 127.0.0.1 + 局域网（RFC1918）网卡；显式 HOST 则只绑该地址
    let addrs: Vec<String> = if host.is_empty() {
        let mut v = vec!["127.0.0.1".to_string()];
        v.extend(lan_addresses().iter().map(|a| a.to_string()));
        v
    } else {
        vec![host.clone()]
    };

    // CIPHERLANE_TEST_LIMITS=1：仅降 per-IP 房间数/字节阈值，建房速率保持 120/min
    let test_limits = std::env::var("CIPHERLANE_TEST_LIMITS").map(|v| v == "1").unwrap_or(false);
    let limits = Limits {
        ip_rooms_max: if test_limits { 4 } else { PER_IP_ROOMS },
        ip_bytes_max: if test_limits { 2 * 1024 * 1024 } else { PER_IP_BYTES },
    };
    let allowed_hosts = build_allowed_hosts(&addrs, &host);

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
    });

    let mut servers = vec![];
    for addr in &addrs {
        let bind = format!("{}:{}", addr, port);
        match Server::http(bind.as_str()) {
            Ok(s) => servers.push((addr.clone(), Arc::new(s))),
            Err(e) => {
                if e.to_string().contains("Address already in use") {
                    eprintln!("\n✗ {} 已被占用——可能有一个旧的密道实例还在运行。\n", bind);
                    eprintln!("  · 到旧实例所在终端按 Ctrl+C 停止，或执行：fuser -k {}/tcp", port);
                    eprintln!("  · 或换端口启动：PORT=7788 cipherlane\n");
                } else {
                    eprintln!("\n✗ 监听 {} 失败：{}", bind, e);
                }
                std::process::exit(1);
            }
        }
    }

    // 优雅停机：SIGTERM/SIGINT 打印关键词后 exit 0（测试会断言退出码 0）
    #[cfg(unix)]
    #[cfg(unix)]
    install_signal_handlers();

    std::thread::spawn({
        let ctx = ctx.clone();
        move || sweeper(ctx)
    });

    for (addr, server) in &servers {
        for _ in 0..WORKERS {
            let server = server.clone();
            let ctx = ctx.clone();
            let _ = std::thread::Builder::new()
                .stack_size(WORKER_STACK)
                .spawn(move || loop {
                    match server.recv() {
                        Ok(req) => handle(req, &ctx),
                        Err(_) => break,
                    }
                });
        }
    }

    println!("cipherlane · 密道 v{}（Rust）—— 局域网端到端加密传输", VERSION);
    println!("  服务器零知识：只中转密文，密钥永不离开收发双方的浏览器\n");
    for (addr, _) in &servers {
        println!("  →  http://{}:{}", addr, port);
    }
    println!("\n等待传输…（Ctrl+C 退出）");
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(*c.lock().unwrap(), 0);
        counter_add(&c, 10);
        counter_sub(&c, 4);
        assert_eq!(*c.lock().unwrap(), 6);
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
        assert_eq!(*c.lock().unwrap(), 3584);
        assert_eq!(*ips.lock().unwrap().get("10.0.0.1").unwrap(), 3584);
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
        assert_eq!(*c.lock().unwrap(), 512);
        assert_eq!(*ips.lock().unwrap().get("10.0.0.1").unwrap(), 512);
        assert!(take_chunk(&mut room, &acct, 2).is_some());
        assert_eq!(*c.lock().unwrap(), 0);
        assert!(!ips.lock().unwrap().contains_key("10.0.0.1"));
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
        assert_eq!(*c.lock().unwrap(), 300);
        assert!(advance_through(&mut room, &acct, 2));
        assert_eq!(*c.lock().unwrap(), 200);
        assert_eq!(*ips.lock().unwrap().get("10.0.0.1").unwrap(), 200);
        assert!(room.buffer.contains_key(&0));
        assert!(advance_through(&mut room, &acct, 2)); // 重复/滞后上报幂等
        assert_eq!(*c.lock().unwrap(), 200);
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
