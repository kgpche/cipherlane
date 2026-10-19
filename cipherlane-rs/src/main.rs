// cipherlane · 密道 —— Rust 重构版服务器
//
// 线协议与 Node 版(server.js)逐字节兼容；验收 = test/protocol.test.mjs 对本实现全绿。
// 架构：tiny_http 同步模型 + 每地址 256 工作线程；长轮询以 Condvar 挂起
// （LAN 规模下每接收方 ≤4 个挂起请求，线程余量充足）。
// 零知识：服务器只存转 AES-256-GCM 密文分片，永不做任何加解密。
use rand::Rng;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
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
const WORKERS: usize = 256;
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
}
fn static_routes() -> Vec<(&'static str, StaticFile)> {
    let sf = |data: &'static [u8], t: &'static str| StaticFile { data: data.to_vec(), ctype: t };
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
    longpoll_count: Mutex<HashMap<String, i32>>,
    offers_mutex: Mutex<()>,
    offers_cond: Condvar,
    started_at: u128,
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
fn jerr(res: tiny_http::Request, code: u16, err: &str) {
    json_resp(res, code, format!("{{\"error\":\"{}\"}}", err));
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
fn take_chunk(inner: &mut RoomInner, world: &World, i: u64) -> Option<Arc<Vec<u8>>> {
    let c = inner.buffer.remove(&i)?;
    inner.bytes -= c.len();
    *world.global_buffered.lock().unwrap() -= c.len();
    inner.head = i + 1;
    if inner.head > inner.pulled {
        inner.pulled = inner.head;
    }
    inner.receiver_seen = true;
    Some(c)
}
fn advance_through(inner: &mut RoomInner, world: &World, through: u64) -> bool {
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
    inner.bytes -= freed;
    *world.global_buffered.lock().unwrap() -= freed;
    inner.through = through;
    if inner.through > inner.pulled {
        inner.pulled = inner.through;
    }
    true
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
        *world.global_buffered.lock().unwrap() -= bytes;
        inner.dead = true;
        if let Some(o) = &inner.offer {
            world.offers_by_id.lock().unwrap().remove(&o.id);
            println!("[offer] - {}（房间销毁）", o.id);
        }
    }
    room.cond.notify_all();
    println!("[room] - {}", room.id);
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
            if let Some(c) = take_chunk(&mut inner, world, i) {
                touch(room);
                return Pull::Done(c.as_ref().clone());
            }
            if inner.sender_done && i >= inner.posted {
                return Pull::Gone("sender-gone");
            }
            if parked && inner.posted > i {
                return Pull::Conflict;
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

// ---------- 极简 HTTP GET（检查更新用，仅 http） ----------
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
    let mut stream = TcpStream::connect(addr.as_str()).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    write!(stream, "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n", path, hostport).map_err(|e| e.to_string())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).map_err(|e| e.to_string())?;
    match raw.split_once("\r\n\r\n") {
        Some((_, body)) => Ok(body.to_string()),
        None => Ok(raw),
    }
}

// ---------- 主处理 ----------
struct Ctx {
    world: Arc<World>,
    statics: Vec<(&'static str, StaticFile)>,
}

fn send_static(mut req: tiny_http::Request, f: &StaticFile) {
    let _ = req.respond(
        Response::from_data(f.data.clone())
            .with_header(h("Content-Type", f.ctype))
            .with_header(h("Cache-Control", "no-store"))
            .with_header(h(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            ))
            .with_header(h("Referrer-Policy", "no-referrer"))
            .with_header(h("X-Content-Type-Options", "nosniff")),
    );
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
        let name_raw = j.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        let name: String = if name_raw.is_empty() { "未命名设备".into() } else { name_raw.chars().take(DEVICE_NAME_MAX).collect() };
        let pub_ = j.get("pub").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !valid_pub(&pub_) {
            return jerr(req, 400, "bad-pub");
        }
        let secret_hdr = hdr(&req, "X-Device-Secret");
        let existing = w.devices.lock().unwrap().get(&ip).cloned();
        if let Some(prev) = existing {
            if !secret_hdr.is_empty() && prev.secret == secret_hdr {
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

    // ---- GET /api/version ----
    if path == "/api/version" && method == "GET" {
        let rooms = w.rooms.lock().unwrap().len();
        return json_resp(req, 200, serde_json::json!({ "version": VERSION, "rooms": rooms, "startedAt": w.started_at }).to_string());
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
        if token.len() < 16 || sent != token || !local {
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

    // ---- GET /api/update ----
    if path == "/api/update" && method == "GET" {
        let url = match std::env::var("CIPHERLANE_UPDATE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => return json_resp(req, 200, serde_json::json!({ "source": null, "current": VERSION, "message": "未配置更新源（CIPHERLANE_UPDATE_URL）" }).to_string()),
        };
        match http_get_text(&url, Duration::from_secs(5)) {
            Ok(text) => {
                let latest = text.trim().to_string();
                let newer = latest.starts_with(|c: char| c.is_ascii_digit()) && latest != VERSION;
                return json_resp(req, 200, serde_json::json!({ "source": url, "current": VERSION, "latest": latest, "newer": newer }).to_string());
            }
            Err(e) => return json_resp(req, 200, serde_json::json!({ "source": url, "current": VERSION, "error": e }).to_string()),
        }
    }

    // ---- GET /api/devices ----
    if path == "/api/devices" && method == "GET" {
        let devices = w.devices.lock().unwrap();
        let list: Vec<serde_json::Value> = devices
            .values()
            .filter(|d| device_alive(d))
            .map(|d| serde_json::json!({ "ip": d.ip, "id": d.id, "name": *d.name.lock().unwrap(), "pub": *d.pub_.lock().unwrap() }))
            .collect();
        return json_resp(req, 200, serde_json::json!({ "devices": list }).to_string());
    }

    // ---- GET /api/offers：长轮询 ----
    if path == "/api/offers" && method == "GET" {
        let secret = hdr(&req, "X-Device-Secret");
        let dev = { w.devices.lock().unwrap().get(&ip).filter(|d| d.secret == secret).cloned() };
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
            let dev = { w.devices.lock().unwrap().get(&ip).filter(|d| d.secret == secret).cloned() };
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

    // ---- POST /api/rooms ----
    if path == "/api/rooms" && method == "POST" {
        let _ = read_body(&mut req, 1024);
        if w.rooms.lock().unwrap().len() >= ROOMS_MAX {
            return jerr(req, 503, "too-many-rooms");
        }
        let id = rand_room_id();
        let room = Arc::new(Room {
            id: id.clone(),
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
                        if token_hdr != r.inner.lock().unwrap().token {
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
            let token_ok = token_hdr == room.inner.lock().unwrap().token;

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

            // POST chunk
            if sub == "chunk" && method == "POST" {
                if !token_ok {
                    return jerr(req, 403, "bad-token");
                }
                let body = match read_body(&mut req, BODY_MAX) {
                    Some(b) => b,
                    None => return jerr(req, 413, "bad-body"),
                };
                if body.is_empty() {
                    return jerr(req, 400, "empty-chunk");
                }
                let mut inner = room.inner.lock().unwrap();
                let outstanding = if inner.resumable { inner.posted - inner.through } else { inner.buffer.len() as u64 };
                let global = *w.global_buffered.lock().unwrap();
                if outstanding >= ROOM_CHUNKS_BUF || inner.bytes + body.len() > ROOM_BYTES_MAX || global + body.len() > GLOBAL_BYTES_MAX {
                    drop(inner);
                    return json_resp(req, 429, "{\"error\":\"backpressure\",\"retry\":1}".into());
                }
                let i = inner.posted;
                inner.posted += 1;
                let arc = Arc::new(body);
                let added = arc.len();
                inner.buffer.insert(i, arc);
                inner.bytes += added;
                drop(inner);
                *w.global_buffered.lock().unwrap() += added;
                touch(&room);
                room.cond.notify_all();
                return json_resp(req, 200, serde_json::json!({ "index": i }).to_string());
            }

            // GET chunk?i=N（X-Resume: 1 可续传）
            if sub == "chunk" && method == "GET" {
                let i: Option<u64> = query.split('&').find_map(|kv| kv.strip_prefix("i=")).and_then(|v| v.parse().ok());
                let i = match i {
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
                if !advance_through(&mut inner, w, through) {
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

fn main() {
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(7777);
    PORT.store(port, std::sync::atomic::Ordering::Relaxed);
    let host = std::env::var("HOST").unwrap_or_default();

    let ctx = Arc::new(Ctx {
        world: Arc::new(World {
            rooms: Mutex::new(HashMap::new()),
            devices: Mutex::new(HashMap::new()),
            offers_by_id: Mutex::new(HashMap::new()),
            global_buffered: Mutex::new(0),
            longpoll_count: Mutex::new(HashMap::new()),
            offers_mutex: Mutex::new(()),
            offers_cond: Condvar::new(),
            started_at: now_ms(),
        }),
        statics: static_routes(),
    });

    // 默认绑 127.0.0.1 + 局域网（RFC1918）网卡；显式 HOST 则只绑该地址
    let addrs: Vec<String> = if host.is_empty() {
        let mut v = vec!["127.0.0.1".to_string()];
        v.extend(lan_addresses().iter().map(|a| a.to_string()));
        v
    } else {
        vec![host]
    };

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

    std::thread::spawn({
        let ctx = ctx.clone();
        move || sweeper(ctx)
    });

    for (addr, server) in &servers {
        for _ in 0..WORKERS {
            let server = server.clone();
            let ctx = ctx.clone();
            std::thread::spawn(move || loop {
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
