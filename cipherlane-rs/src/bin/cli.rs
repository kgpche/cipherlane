// cipherlane-cli —— Rust 版命令行（v1.0：去 Node，唯一 CLI 实现）
//
// 与 public/app.js / 原 cli.mjs 的 v0.5.1 行为逐字节互操作：
//   - X25519 房间密钥 = SHA256(shared ‖ senderPub ‖ receiverPub ‖ "cipherlane/device/v1\0"+room)
//   - AES-256-GCM 线上格式 IV(12) ‖ 密文 ‖ TAG(16)
//   - 协议 v2 分片位置绑定：AAD = "cipherlane/chunk/v2|" + room + "|" + index
//   - ackProof = SHA256(key ‖ "cipherlane/ack/v1|" + room)（hex）
//   - 指纹 = SHA256(原始 32B 公钥) 前 16 字节（32 hex）
// 子命令：devices / send / send-text / recv / listen；选项 --to/--verify/--name/--server/-o/--yes。
// HTTP 客户端为 std TcpStream 手写（仅 http，局域网场景），全部请求带超时。

use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPub, StaticSecret};

const CHUNK: usize = 1024 * 1024;
const FILES_MAX: usize = 256;
const ROOM_ID_LEN: usize = 10;
// 与 public/x25519.js 的 LABEL 完全一致（含结尾 NUL）
const KDF_LABEL: &[u8] = b"cipherlane/device/v1\x00";
const ACK_LABEL: &str = "cipherlane/ack/v1|";
const AAD_PREFIX: &str = "cipherlane/chunk/v2|";

type CResult<T> = Result<T, String>;

// ============================================================
// 参数解析
// ============================================================
#[derive(Default)]
struct Opts {
    cmd: Option<String>,
    pos: Vec<String>,
    server: Option<String>,
    out: Option<String>,
    to: Option<String>,
    verify: Option<String>,
    name: Option<String>,
    yes: bool,
    help: bool,
}

fn parse_args() -> Opts {
    let argv: Vec<String> = env::args().skip(1).collect();
    let mut o = Opts::default();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--server" => {
                i += 1;
                o.server = argv.get(i).cloned();
            }
            "-o" => {
                i += 1;
                o.out = argv.get(i).cloned();
            }
            "--to" => {
                i += 1;
                o.to = argv.get(i).cloned();
            }
            "--name" => {
                i += 1;
                o.name = argv.get(i).cloned();
            }
            "--verify" => {
                i += 1;
                o.verify = argv.get(i).cloned();
            }
            "--yes" | "-y" => o.yes = true,
            "--help" | "-h" => o.help = true,
            _ => o.pos.push(argv[i].clone()),
        }
        i += 1;
    }
    o.cmd = o.pos.first().cloned();
    o
}

fn usage() {
    println!("cipherlane · 密道 CLI（Rust 版，v1.0）");
    println!();
    println!("用法:");
    println!("  cipherlane-cli devices                       [--server http://<局域网IP>:7777]");
    println!("  cipherlane-cli send <文件/目录...> [--to <设备IP>] [--verify <指纹hex≥8>] [--name <名称>] [--server ...]");
    println!("  cipherlane-cli send-text <文本> [--to <设备IP>] [--verify <指纹hex≥8>] [--name <名称>] [--server ...]");
    println!("  cipherlane-cli recv '<接收链接>' [-o 输出路径]");
    println!("  cipherlane-cli listen [--yes] [-o 保存目录] [--name <名称>] [--server ...]");
    println!();
    println!("设备直发：--to 指定在线设备（cipherlane-cli devices 查看），密钥 X25519 协商，无需传链接。");
    println!("  指纹 = SHA256(X25519 公钥) 前 16 字节（32 hex）；可用 --verify 核对目标指纹（≥8 位前缀）。");
    println!("listen：常驻接收端，无浏览器的机器也能被直发（--yes 自动接受）。");
}

// ============================================================
// 小工具：格式化 / 净化 / 头像 / base64 / 随机
// ============================================================
fn fmt_bytes(n: u64) -> String {
    if n < 1024 {
        return format!("{} B", n);
    }
    let units = ["KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i: usize = 0;
    loop {
        v /= 1024.0;
        if v < 1024.0 || i + 1 >= units.len() {
            break;
        }
        i += 1;
    }
    format!("{:.1} {}", v, units[i])
}

// 终端输出净化：过滤 OSC/CSI/其他转义与 C0/C1 控制字符（防终端注入）。
fn clean(raw: &str, max: usize) -> String {
    let mut out = String::new();
    let mut it = raw.chars().peekable();
    while let Some(c) = it.next() {
        let u = c as u32;
        if c == '\u{1b}' {
            match it.peek().copied() {
                Some(']') => {
                    it.next();
                    // OSC … BEL 或 ST(ESC \)
                    while let Some(x) = it.next() {
                        if x == '\u{7}' {
                            break;
                        }
                        if x == '\u{1b}' {
                            if it.peek() == Some(&'\\') {
                                it.next();
                            }
                            break;
                        }
                    }
                }
                Some('[') => {
                    it.next();
                    // CSI … final byte 0x40..=0x7e
                    while let Some(x) = it.next() {
                        let xu = x as u32;
                        if (0x40..=0x7e).contains(&xu) {
                            break;
                        }
                    }
                }
                Some(_) => {
                    it.next();
                }
                None => {}
            }
            continue;
        }
        if u < 0x20 || (0x7f..=0x9f).contains(&u) {
            continue; // C0/C1（含 DEL、BEL）
        }
        out.push(c);
    }
    if out.chars().count() > max {
        let mut t: String = out.chars().take(max).collect();
        t.push('…');
        return t;
    }
    out
}

// 接收文件名净化（对齐 cli.mjs 的 safeName）：取最后一段，
// 非 [\w.\- CJK 空格] 的连续串替换为 '_'，剥掉前导点/空白。
fn safe_name(raw: &str) -> String {
    let base = raw.rsplit(|c| c == '/' || c == '\\').next().unwrap_or("");
    let mut s = String::new();
    let mut last_underscore = false;
    for ch in base.chars() {
        let u = ch as u32;
        let ok = ch.is_ascii_alphanumeric()
            || ch == '_'
            || ch == '.'
            || ch == '-'
            || ch == ' '
            || (0x4e00..=0x9fa5).contains(&u);
        if ok {
            s.push(ch);
            last_underscore = false;
        } else if !last_underscore {
            s.push('_');
            last_underscore = true;
        }
    }
    let s = s.trim_start_matches(|c: char| c == '.' || c.is_whitespace());
    if s.is_empty() {
        "received".to_string()
    } else {
        s.to_string()
    }
}

fn safe_join(dir: &Path, rel: &str) -> PathBuf {
    let mut p = dir.to_path_buf();
    let mut any = false;
    for seg in rel.split('/') {
        let n = safe_name(seg);
        if n.is_empty() {
            continue;
        }
        p.push(n);
        any = true;
    }
    if any {
        p
    } else {
        dir.join("received")
    }
}

fn fnv1a(s: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for c in s.chars() {
        h ^= c as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

fn avatar_of(seed: &str) -> String {
    let colors = [39u32, 48, 178, 203, 170, 214];
    let glyphs = ["◆", "▲", "●", "■", "✦", "◐", "◀", "▼"];
    let h = fnv1a(&format!("cipherlane·{}", seed));
    let c = colors[(h as usize) % colors.len()];
    let g1 = glyphs[((h >> 8) as usize) % glyphs.len()];
    let g2 = glyphs[((h >> 16) as usize) % glyphs.len()];
    format!("\x1b[38;5;{}m{}{}\x1b[0m", c, g1, g2)
}

fn b64u(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}
fn from_b64u(s: &str) -> CResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|_| "base64url 解码失败".to_string())
}
fn hexstr(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}
fn hostname() -> String {
    // 跨平台：unix 用 HOSTNAME，Windows 用 COMPUTERNAME；都缺失时回退固定名。
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "cipherlane".to_string())
}

// ============================================================
// 密码学（与浏览器 / Node 版逐字节一致）
// ============================================================
#[derive(Clone, Copy)]
struct Identity {
    seed: [u8; 32],
    public: [u8; 32],
}

fn gen_identity() -> Identity {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let sk = StaticSecret::from(seed);
    let public = XPub::from(&sk).to_bytes();
    Identity { seed, public }
}

// RFC 7748 DH；全零共享密钥（小阶点）拒绝。
fn dh(seed: &[u8; 32], their_pub: &[u8; 32]) -> CResult<[u8; 32]> {
    let sk = StaticSecret::from(*seed);
    let pk = XPub::from(*their_pub);
    let shared = sk.diffie_hellman(&pk).to_bytes();
    if shared.iter().all(|&b| b == 0) {
        return Err("X25519 无效公钥（共享密钥为全零）".into());
    }
    Ok(shared)
}

// roomKey = SHA256(shared ‖ senderPub ‖ receiverPub ‖ label+room)
fn room_key(shared: &[u8; 32], sender_pub: &[u8; 32], receiver_pub: &[u8; 32], room: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(shared);
    h.update(sender_pub);
    h.update(receiver_pub);
    h.update(KDF_LABEL);
    h.update(room.as_bytes());
    let out = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out);
    k
}

fn ack_proof_hex(key: &[u8; 32], room: &str) -> String {
    let mut h = Sha256::new();
    h.update(key);
    h.update(ACK_LABEL.as_bytes());
    h.update(room.as_bytes());
    hexstr(&h.finalize())
}

// 指纹 = SHA256(原始 32B 公钥) 前 16 字节 → 32 hex（与 app.js/cli.mjs 一致）
fn fp_hex(raw_pub: &[u8]) -> String {
    hexstr(&Sha256::digest(raw_pub)[..16])
}

fn chunk_aad(room: &str, index: u64) -> Vec<u8> {
    format!("{}{}|{}", AAD_PREFIX, room, index).into_bytes()
}

fn seal(key: &[u8; 32], pt: &[u8], aad: Option<&[u8]>) -> CResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "AES 密钥非法".to_string())?;
    let iv = random_bytes(12);
    let nonce = Nonce::from_slice(&iv);
    let ct = cipher
        .encrypt(nonce, Payload { msg: pt, aad: aad.unwrap_or(&[]) })
        .map_err(|_| "GCM 加密失败".to_string())?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn unseal(key: &[u8; 32], packed: &[u8], aad: Option<&[u8]>) -> CResult<Vec<u8>> {
    if packed.len() < 28 {
        return Err("数据不完整".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "AES 密钥非法".to_string())?;
    let iv = &packed[..12];
    let ct = &packed[12..];
    cipher
        .decrypt(Nonce::from_slice(iv), Payload { msg: ct, aad: aad.unwrap_or(&[]) })
        .map_err(|_| "GCM 验证失败：密钥错误或数据被篡改".to_string())
}

// ============================================================
// 极简 HTTP/1.1 客户端（std TcpStream，全部请求带超时）
// ============================================================
#[derive(Debug)]
enum HttpErr {
    Timeout,
    Conn(String),
    Proto(String),
}
impl HttpErr {
    fn msg(&self) -> String {
        match self {
            HttpErr::Timeout => "连接超时".to_string(),
            HttpErr::Conn(e) => format!("连接失败: {}", e),
            HttpErr::Proto(e) => format!("HTTP 协议错误: {}", e),
        }
    }
}

#[derive(Clone)]
struct UrlParts {
    host: String,
    port: u16,
    path: String,
    origin: String,
}

fn parse_origin(server: &str) -> CResult<UrlParts> {
    let rest = server
        .strip_prefix("http://")
        .ok_or_else(|| format!("仅支持 http:// 服务器地址: {}", server))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return Err("服务器地址缺少主机".into());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| "端口非法".to_string())?,
        ),
        _ => (authority.to_string(), 80u16),
    };
    Ok(UrlParts { host: host.clone(), port, path, origin: format!("http://{}:{}", host, port) })
}

fn url(origin: &UrlParts, path_with_query: &str) -> UrlParts {
    UrlParts {
        host: origin.host.clone(),
        port: origin.port,
        path: path_with_query.to_string(),
        origin: origin.origin.clone(),
    }
}

struct Resp {
    status: u16,
    body: Vec<u8>,
}

fn read_with_deadline(stream: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> Result<usize, HttpErr> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(HttpErr::Timeout);
        }
        let remain = deadline - now;
        let _ = stream.set_read_timeout(Some(remain.max(Duration::from_millis(1))));
        match stream.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                return Err(HttpErr::Timeout);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(HttpErr::Conn(e.to_string())),
        }
    }
}

fn http_request(
    method: &str,
    u: &UrlParts,
    headers: &[(&str, String)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<Resp, HttpErr> {
    let deadline = Instant::now() + timeout;
    let addr_iter = (u.host.as_str(), u.port)
        .to_socket_addrs()
        .map_err(|e| HttpErr::Conn(e.to_string()))?;
    let mut last_err = HttpErr::Conn(format!("无法解析 {}", u.host));
    let mut stream = None;
    for sa in addr_iter {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            return Err(HttpErr::Timeout);
        }
        match TcpStream::connect_timeout(&sa, remain.min(Duration::from_secs(5))) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_err = HttpErr::Conn(e.to_string()),
        }
    }
    let mut stream = stream.ok_or(last_err)?;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(
        deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1)),
    ));

    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n",
        method, u.path, u.host, u.port
    );
    for (k, v) in headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).map_err(|e| HttpErr::Conn(e.to_string()))?;
    if let Some(b) = body {
        stream.write_all(b).map_err(|e| HttpErr::Conn(e.to_string()))?;
    }
    let _ = stream.flush();

    // 读响应头
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 8192];
    let header_end;
    loop {
        if let Some(p) = find_subslice(&buf, b"\r\n\r\n") {
            header_end = p + 4;
            break;
        }
        let n = read_with_deadline(&mut stream, &mut tmp, deadline)?;
        if n == 0 {
            return Err(HttpErr::Proto("连接在读响应头前关闭".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 1024 * 1024 {
            return Err(HttpErr::Proto("响应头过大".into()));
        }
    }
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| HttpErr::Proto(format!("非法状态行: {}", status_line)))?;
    let mut headers_map: HashMap<String, String> = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers_map.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let mut body_bytes: Vec<u8> = buf[header_end..].to_vec();
    if headers_map
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        let decoded = loop {
            if let Some(d) = try_decode_chunked(&body_bytes) {
                break d;
            }
            let n = read_with_deadline(&mut stream, &mut tmp, deadline)?;
            if n == 0 {
                return Err(HttpErr::Proto("chunked 响应被截断".into()));
            }
            body_bytes.extend_from_slice(&tmp[..n]);
        };
        return Ok(Resp { status, body: decoded });
    }
    if let Some(cl) = headers_map.get("content-length").and_then(|v| v.parse::<usize>().ok()) {
        while body_bytes.len() < cl {
            let n = read_with_deadline(&mut stream, &mut tmp, deadline)?;
            if n == 0 {
                break;
            }
            body_bytes.extend_from_slice(&tmp[..n]);
        }
        body_bytes.truncate(cl);
        return Ok(Resp { status, body: body_bytes });
    }
    // 无长度：读到 EOF（超时视为结束，JSON 小响应已完整）
    loop {
        match read_with_deadline(&mut stream, &mut tmp, deadline) {
            Ok(0) => break,
            Ok(n) => body_bytes.extend_from_slice(&tmp[..n]),
            Err(HttpErr::Timeout) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(Resp { status, body: body_bytes })
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

fn try_decode_chunked(raw: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    loop {
        let line_end = find_subslice(&raw[pos..], b"\r\n")? + pos;
        let size_line = std::str::from_utf8(&raw[pos..line_end]).ok()?;
        let size = usize::from_str_radix(size_line.split(';').next()?.trim(), 16).ok()?;
        pos = line_end + 2;
        if size == 0 {
            return Some(out);
        }
        if raw.len() < pos + size + 2 {
            return None;
        }
        out.extend_from_slice(&raw[pos..pos + size]);
        pos += size + 2;
    }
}

fn err_body(resp: &Resp) -> String {
    let t = String::from_utf8_lossy(&resp.body).to_string();
    if t.chars().count() > 160 {
        t.chars().take(160).collect()
    } else {
        t
    }
}

fn req_json(
    method: &str,
    u: &UrlParts,
    headers: &[(&str, String)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> CResult<Value> {
    let resp = http_request(method, u, headers, body, timeout).map_err(|e| e.msg())?;
    serde_json::from_slice(&resp.body)
        .map_err(|_| format!("服务器返回非 JSON（HTTP {}: {}）", resp.status, err_body(&resp)))
}

fn jget(u: &UrlParts, headers: &[(&str, String)], timeout: Duration) -> CResult<Value> {
    req_json("GET", u, headers, None, timeout)
}

// ============================================================
// 协议层
// ============================================================
fn json_ct() -> (&'static str, String) {
    ("Content-Type", "application/json".to_string())
}

fn get_state(server: &UrlParts, room: &str) -> CResult<Value> {
    jget(&url(server, &format!("/api/rooms/{}/state", room)), &[], Duration::from_secs(10))
}

fn create_room(server: &UrlParts) -> CResult<(String, String)> {
    let r = http_request("POST", &url(server, "/api/rooms"), &[], None, Duration::from_secs(10))
        .map_err(|e| e.msg())?;
    if r.status != 200 {
        return Err(format!("创建房间失败 {}", r.status));
    }
    let j: Value = serde_json::from_slice(&r.body).map_err(|_| "创建房间响应非法".to_string())?;
    let room = j.get("room").and_then(|v| v.as_str()).ok_or("创建房间缺少 room")?.to_string();
    let token = j.get("token").and_then(|v| v.as_str()).ok_or("创建房间缺少 token")?.to_string();
    Ok((room, token))
}

// 幂等投递：X-Chunk-Seq；超时/429 重试复用同一 seq；409 明确报错。
fn post_chunk(server: &UrlParts, room: &str, token: &str, seq: u64, body: &[u8]) -> CResult<()> {
    let u = url(server, &format!("/api/rooms/{}/chunk", room));
    loop {
        let hdrs = vec![
            ("X-Room-Token", token.to_string()),
            ("X-Chunk-Seq", seq.to_string()),
        ];
        match http_request("POST", &u, &hdrs, Some(body), Duration::from_secs(30)) {
            Ok(r) => match r.status {
                200 => return Ok(()),
                429 => {
                    thread::sleep(Duration::from_millis(250));
                    continue;
                }
                409 => {
                    return Err(format!(
                        "服务器分片计数不同步（seq={}, out-of-order），请重新建立传输",
                        seq
                    ))
                }
                s => return Err(format!("投递分片失败 {}", s)),
            },
            Err(HttpErr::Timeout) => {
                thread::sleep(Duration::from_millis(500));
                continue;
            }
            Err(e) => return Err(e.msg()),
        }
    }
}

fn get_chunk_at(origin: &UrlParts, room: &str, i: u64, resume: bool) -> CResult<Vec<u8>> {
    let u = url(origin, &format!("/api/rooms/{}/chunk?i={}", room, i));
    let hdrs: Vec<(&str, String)> = if resume {
        vec![("X-Resume", "1".to_string())]
    } else {
        vec![]
    };
    loop {
        match http_request("GET", &u, &hdrs, None, Duration::from_secs(35)) {
            Ok(r) => match r.status {
                200 => return Ok(r.body),
                408 => continue,
                429 => {
                    thread::sleep(Duration::from_millis(500));
                    continue;
                }
                409 => return Err("链接正被另一个接收方使用".into()),
                404 => return Err("链接无效或已过期".into()),
                410 => return Err("链接已被使用、过期，或发送方中断".into()),
                s => return Err(format!("拉取分片失败 {}", s)),
            },
            Err(HttpErr::Timeout) => continue,
            Err(e) => return Err(e.msg()),
        }
    }
}

struct Progress {
    origin: UrlParts,
    room: String,
    alive: bool,
}
impl Progress {
    fn new(origin: &UrlParts, room: &str) -> Self {
        Progress { origin: origin.clone(), room: room.to_string(), alive: true }
    }
    fn post(&mut self, through: u64) {
        if !self.alive {
            return;
        }
        let u = url(&self.origin, &format!("/api/rooms/{}/progress", self.room));
        let body = format!("{{\"through\":{}}}", through).into_bytes();
        match http_request("POST", &u, &[json_ct()], Some(&body), Duration::from_secs(10)) {
            Ok(r) => {
                if r.status == 404 || r.status == 409 {
                    self.alive = false;
                }
            }
            Err(_) => { /* 上报失败无害：服务器多留一会儿缓存 */ }
        }
    }
}

// 读 0 号 meta：先 v2(AAD room|0) 解，失败回退 v1（无 AAD）。
fn read_meta(origin: &UrlParts, room: &str, key: &[u8; 32], resume: bool) -> CResult<(Value, bool)> {
    let packed = get_chunk_at(origin, room, 0, resume)?;
    let aad = chunk_aad(room, 0);
    let pt = match unseal(key, &packed, Some(&aad)) {
        Ok(v) => v,
        Err(_) => unseal(key, &packed, None)?,
    };
    let meta: Value = serde_json::from_slice(&pt).map_err(|_| "meta JSON 非法".to_string())?;
    let use_aad = meta.get("v").and_then(|v| v.as_u64()) == Some(2);
    Ok((meta, use_aad))
}

fn post_ack(origin: &UrlParts, room: &str, key: &[u8; 32]) {
    let u = url(origin, &format!("/api/rooms/{}/ack", room));
    let body = json!({ "proof": ack_proof_hex(key, room) }).to_string().into_bytes();
    let _ = http_request("POST", &u, &[json_ct()], Some(&body), Duration::from_secs(10));
}

fn meta_u64(meta: &Value, k: &str) -> u64 {
    meta.get(k).and_then(|v| v.as_u64()).unwrap_or(0)
}
fn meta_str<'a>(meta: &'a Value, k: &str) -> Option<&'a str> {
    meta.get(k).and_then(|v| v.as_str())
}

// ============================================================
// 身份 / presence
// ============================================================
type Presence = Option<Value>;

fn presence_secret(p: &Presence) -> Option<String> {
    p.as_ref()
        .and_then(|v| v.get("secret"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn heartbeat(server: &UrlParts, name: &str, id: &Identity, presence: &Presence) -> CResult<Value> {
    let u = url(server, "/api/presence");
    let mut hdrs: Vec<(&str, String)> = vec![json_ct()];
    if let Some(sec) = presence_secret(presence) {
        hdrs.push(("X-Device-Secret", sec));
    }
    let body = json!({ "name": name, "pub": b64u(&id.public) }).to_string().into_bytes();
    let r = http_request("POST", &u, &hdrs, Some(&body), Duration::from_secs(10)).map_err(|e| e.msg())?;
    if r.status != 200 {
        return Err(format!("设备注册失败 {}", r.status));
    }
    serde_json::from_slice(&r.body).map_err(|_| "presence 响应非法".to_string())
}

fn list_devices(server: &UrlParts) -> CResult<Vec<Value>> {
    let j = jget(&url(server, "/api/devices"), &[], Duration::from_secs(10))?;
    Ok(j.get("devices").and_then(|v| v.as_array()).cloned().unwrap_or_default())
}

// ============================================================
// 房间 / 发送端
// ============================================================
struct RoomInfo {
    room: String,
    token: String,
    key: [u8; 32],
    target: Option<Value>,
}

struct SendArgs<'a> {
    server: &'a UrlParts,
    opts: &'a Opts,
}

fn open_room(sa: &SendArgs, preview: Value, id: &Identity) -> CResult<RoomInfo> {
    let (room, token) = create_room(sa.server)?;
    let server = sa.server;
    let mut target: Option<Value> = None;
    let key: [u8; 32];
    if let Some(to) = &sa.opts.to {
        let devices = list_devices(server)?;
        let t = devices
            .iter()
            .find(|d| d.get("ip").and_then(|v| v.as_str()) == Some(to.as_str()))
            .cloned()
            .ok_or_else(|| format!("设备 {} 不在线（cipherlane-cli devices 查看）", to))?;
        let target_pub_b64 = t.get("pub").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let target_pub_bytes = from_b64u(&target_pub_b64)?;
        if target_pub_bytes.len() != 32 {
            return Err("目标公钥长度非法".into());
        }
        let mut target_pub = [0u8; 32];
        target_pub.copy_from_slice(&target_pub_bytes);

        let name = clean(t.get("name").and_then(|v| v.as_str()).unwrap_or("未命名设备"), 32);
        let ip = clean(to, 64);
        let fp = fp_hex(&target_pub);
        if let Some(v) = &sa.opts.verify {
            let want0 = v.to_lowercase();
            let want = want0.strip_prefix('#').unwrap_or(&want0).to_string();
            let ok_len = (8..=32).contains(&want.len()) && want.chars().all(|c| c.is_ascii_hexdigit());
            if !ok_len {
                return Err("--verify 需要 8~32 位十六进制指纹前缀".into());
            }
            if !fp.starts_with(&want) {
                return Err(format!(
                    "目标指纹不符：期望 {}… 实际 #{}（可能被调包，已拒绝发送）",
                    want, fp
                ));
            }
            println!("\n  ✓ 目标 {} @ {} 指纹核对通过 #{}", name, ip, fp);
        } else {
            println!("\n  ⚠ 目标 {} @ {} 指纹 #{}", name, ip, fp);
            println!("    请与对方当面/口头核对；下次可用 --verify <指纹前8位以上> 强制校验");
        }

        let shared = dh(&id.seed, &target_pub)?;
        key = room_key(&shared, &id.public, &target_pub, &room);
        let hint = b64u(&seal(&key, preview.to_string().as_bytes(), None)?);
        let body = json!({ "to": to, "pub": b64u(&id.public), "hint": hint }).to_string().into_bytes();
        let u = url(server, &format!("/api/rooms/{}/offer", room));
        let r = http_request(
            "POST",
            &u,
            &[json_ct(), ("X-Room-Token", token.clone())],
            Some(&body),
            Duration::from_secs(10),
        )
        .map_err(|e| e.msg())?;
        if r.status != 200 {
            return Err(format!("投递邀请失败 {}", r.status));
        }
        println!("\n{}  已向 {} ({}) 发出邀请，等待接受…", avatar_of(to), name, ip);
        let deadline = Instant::now() + Duration::from_secs(5 * 60);
        loop {
            if Instant::now() > deadline {
                return Err("对方超时未接受".into());
            }
            let st = match get_state(server, &room) {
                Ok(v) => v,
                Err(_) => return Err("邀请已过期（房间被回收）".into()),
            };
            match st.get("offer").and_then(|v| v.as_str()) {
                Some("accepted") => break,
                Some("rejected") => return Err(format!("对方（{}）拒绝了传输", ip)),
                _ => {}
            }
            thread::sleep(Duration::from_millis(1000));
        }
        println!("  对方已接受，开始传输…\n");
        target = Some(t);
    } else {
        let k = random_bytes(32);
        let mut kk = [0u8; 32];
        kk.copy_from_slice(&k);
        key = kk;
        let link = format!("{}/#{}.{}", server.origin, room, b64u(&key));
        println!("\n╔══════════════════════════════════════════╗");
        println!("║  把下面的接收链接发给对方（浏览器打开即可）  ║");
        println!("╚══════════════════════════════════════════╝\n");
        println!("  {}\n", link);
        print_qr(&link);
    }
    Ok(RoomInfo { room, token, key, target })
}

fn print_qr(link: &str) {
    // 与 Node 版一致：链接过长（>106B，等价 QR v1-5 容量）时跳过二维码
    if link.len() > 106 {
        return;
    }
    let qr = match qrcodegen::QrCode::encode_text(link, qrcodegen::QrCodeEcc::Low) {
        Ok(q) => q,
        Err(_) => return,
    };
    let border = 2i32;
    let size = qr.size();
    let mut out = String::new();
    for y in -border..size + border {
        for x in -border..size + border {
            let dark = x >= 0 && y >= 0 && x < size && y < size && qr.get_module(x, y);
            out.push_str(if dark { "██" } else { "  " });
        }
        out.push('\n');
    }
    println!("{}  ↑ 手机扫码接收\n", out);
}

fn await_ack(server: &UrlParts, room: &str, key: &[u8; 32], target: &Option<Value>) {
    let deadline = Instant::now() + Duration::from_secs(15 * 60);
    print!("\n  等待对方接收…");
    let _ = io::stdout().flush();
    loop {
        thread::sleep(Duration::from_millis(1500));
        if Instant::now() > deadline {
            println!("\n⏱ 等待超时退出（对方可能已中断）");
            return;
        }
        let st = match get_state(server, room) {
            Ok(v) => v,
            Err(_) => {
                println!("\n⚠ 服务器已清除房间（可能超时）");
                return;
            }
        };
        if st.get("acked").and_then(|v| v.as_bool()) == Some(true) {
            let proof = st.get("ackProof").and_then(|v| v.as_str()).unwrap_or("");
            let verified = !proof.is_empty() && proof == ack_proof_hex(key, room);
            let who = target
                .as_ref()
                .map(|t| {
                    let n = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let ip = t.get("ip").and_then(|v| v.as_str()).unwrap_or("");
                    clean(if n.is_empty() { ip } else { n }, 32)
                })
                .unwrap_or_else(|| "对方".to_string());
            if verified {
                println!("\n\n✅ {}已完整接收（凭证校验通过）", who);
            } else {
                println!("\n\n⚠ {}已接收，但 ack 无有效凭证——房间号泄露时可能被伪造\n", who);
            }
            return;
        }
    }
}

fn post_done(server: &UrlParts, room: &str, token: &str) -> CResult<()> {
    let u = url(server, &format!("/api/rooms/{}/done", room));
    let r = http_request(
        "POST",
        &u,
        &[("X-Room-Token", token.to_string())],
        None,
        Duration::from_secs(10),
    )
    .map_err(|e| e.msg())?;
    if r.status != 200 {
        return Err(format!("结束标记失败 {}", r.status));
    }
    Ok(())
}

// ============================================================
// 发送
// ============================================================
fn read_file_chunk(fh: &mut File, index: u64, size: u64) -> CResult<Vec<u8>> {
    let off = index * CHUNK as u64;
    if off >= size {
        return Ok(Vec::new());
    }
    let len = std::cmp::min(CHUNK as u64, size - off) as usize;
    fh.seek(SeekFrom::Start(off)).map_err(|e| format!("读取文件失败: {}", e))?;
    let mut buf = vec![0u8; len];
    let mut got = 0usize;
    while got < len {
        match fh.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("读取文件失败: {}", e)),
        }
    }
    buf.truncate(got);
    Ok(buf)
}

fn do_send_file(sa: &SendArgs, path: &Path) -> CResult<()> {
    let id = gen_identity();
    if sa.opts.to.is_some() {
        let name = sa.opts.name.clone().unwrap_or_else(hostname);
        let _ = heartbeat(sa.server, &name, &id, &None)?;
    }
    let mut fh = File::open(path).map_err(|e| format!("路径不存在: {} ({})", path.display(), e))?;
    let size = fh.metadata().map_err(|e| e.to_string())?.len();
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let data_chunks = if size == 0 { 0 } else { (size + CHUNK as u64 - 1) / CHUNK as u64 };
    let count = 1 + data_chunks;
    let preview = json!({ "kind": "file", "name": file_name, "size": size });
    let info = open_room(sa, preview, &id)?;
    let meta = json!({ "v": 2, "type": "file", "name": file_name, "mime": Value::Null, "size": size, "count": count });
    let sealed = seal(&info.key, meta.to_string().as_bytes(), Some(&chunk_aad(&info.room, 0)))?;
    post_chunk(sa.server, &info.room, &info.token, 0, &sealed)?;
    for i in 1..count {
        let pt = read_file_chunk(&mut fh, i - 1, size)?;
        let sealed = seal(&info.key, &pt, Some(&chunk_aad(&info.room, i)))?;
        post_chunk(sa.server, &info.room, &info.token, i, &sealed)?;
        let done = std::cmp::min(i * CHUNK as u64, size);
        print!("\r  已发送 {} / {}", fmt_bytes(done), fmt_bytes(size));
        let _ = io::stdout().flush();
    }
    if count == 1 {
        print!("\r  已发送 {} / {}", fmt_bytes(size), fmt_bytes(size));
        let _ = io::stdout().flush();
    }
    post_done(sa.server, &info.room, &info.token)?;
    await_ack(sa.server, &info.room, &info.key, &info.target);
    Ok(())
}

fn do_send_text(sa: &SendArgs, text: &str) -> CResult<()> {
    let id = gen_identity();
    if sa.opts.to.is_some() {
        let name = sa.opts.name.clone().unwrap_or_else(hostname);
        let _ = heartbeat(sa.server, &name, &id, &None)?;
    }
    let pt = text.as_bytes().to_vec();
    let size = pt.len() as u64;
    let count = 2u64; // meta + 1 片
    let preview = json!({ "kind": "text", "name": Value::Null, "size": size });
    let info = open_room(sa, preview, &id)?;
    let meta = json!({ "v": 2, "type": "text", "name": Value::Null, "mime": Value::Null, "size": size, "count": count });
    let sealed = seal(&info.key, meta.to_string().as_bytes(), Some(&chunk_aad(&info.room, 0)))?;
    post_chunk(sa.server, &info.room, &info.token, 0, &sealed)?;
    let sealed1 = seal(&info.key, &pt, Some(&chunk_aad(&info.room, 1)))?;
    post_chunk(sa.server, &info.room, &info.token, 1, &sealed1)?;
    print!("\r  已发送 {} / {}", fmt_bytes(size), fmt_bytes(size));
    let _ = io::stdout().flush();
    post_done(sa.server, &info.room, &info.token)?;
    await_ack(sa.server, &info.room, &info.key, &info.target);
    Ok(())
}

struct FileEntry {
    abs: PathBuf,
    rel: String,
    size: u64,
}

fn gather_files(paths: &[String]) -> CResult<Vec<FileEntry>> {
    let mut files: Vec<FileEntry> = Vec::new();
    for p in paths {
        let path = Path::new(p);
        let md = fs::metadata(path).map_err(|_| format!("路径不存在: {}", p))?;
        if md.is_dir() {
            walk_dir(path, "", &mut files)?;
        } else if md.is_file() {
            let rel = path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "file".into());
            files.push(FileEntry { abs: path.to_path_buf(), rel, size: md.len() });
        } else {
            return Err(format!("不支持的路径类型: {}", p));
        }
    }
    if files.is_empty() {
        return Err("没有可发送的文件（目录为空或只含隐藏文件）".into());
    }
    if files.len() > FILES_MAX {
        return Err(format!("文件数超过上限 {}（当前 {}）", FILES_MAX, files.len()));
    }
    Ok(files)
}

fn walk_dir(dir: &Path, prefix: &str, out: &mut Vec<FileEntry>) -> CResult<()> {
    let rd = fs::read_dir(dir).map_err(|e| format!("读取目录失败 {}: {}", dir.display(), e))?;
    for ent in rd {
        let ent = ent.map_err(|e| e.to_string())?;
        let name = ent.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue; // .git / .DS_Store 等隐藏项
        }
        let p = ent.path();
        let rel = if prefix.is_empty() { name.clone() } else { format!("{}/{}", prefix, name) };
        let md = fs::metadata(&p).map_err(|e| e.to_string())?;
        if md.is_dir() {
            walk_dir(&p, &rel, out)?;
        } else if md.is_file() {
            out.push(FileEntry { abs: p, rel, size: md.len() });
        }
    }
    Ok(())
}

fn data_chunk_count(size: u64) -> u64 {
    if size == 0 {
        0
    } else {
        (size + CHUNK as u64 - 1) / CHUNK as u64
    }
}

fn do_send_batch(sa: &SendArgs, paths: &[String]) -> CResult<()> {
    let id = gen_identity();
    if sa.opts.to.is_some() {
        let name = sa.opts.name.clone().unwrap_or_else(hostname);
        let _ = heartbeat(sa.server, &name, &id, &None)?;
    }
    let files = gather_files(paths)?;
    let total: u64 = files.iter().map(|f| f.size).sum();
    let manifest: Vec<Value> = files
        .iter()
        .map(|f| json!({ "name": f.rel, "size": f.size, "count": data_chunk_count(f.size) }))
        .collect();
    let preview = json!({ "kind": "batch", "count": manifest.len(), "size": total });
    let info = open_room(sa, preview, &id)?;
    let data_total: u64 = files.iter().map(|f| data_chunk_count(f.size)).sum();
    let count = 1 + data_total;
    let meta = json!({ "v": 2, "type": "batch", "files": manifest, "count": count, "size": total });
    let sealed = seal(&info.key, meta.to_string().as_bytes(), Some(&chunk_aad(&info.room, 0)))?;
    post_chunk(sa.server, &info.room, &info.token, 0, &sealed)?;
    let mut sent: u64 = 0;
    let mut seq: u64 = 1;
    for (fi, f) in files.iter().enumerate() {
        let n = data_chunk_count(f.size);
        if n > 0 {
            let mut fh = File::open(&f.abs).map_err(|e| format!("打开失败 {}: {}", f.abs.display(), e))?;
            for i in 0..n {
                let pt = read_file_chunk(&mut fh, i, f.size)?;
                let sealed = seal(&info.key, &pt, Some(&chunk_aad(&info.room, seq)))?;
                post_chunk(sa.server, &info.room, &info.token, seq, &sealed)?;
                seq += 1;
                sent += pt.len() as u64;
                print!(
                    "\r  [{}/{}] {} 已发送 {} / {}",
                    fi + 1,
                    files.len(),
                    clean(&f.rel, 28),
                    fmt_bytes(sent),
                    fmt_bytes(total)
                );
                let _ = io::stdout().flush();
            }
        }
    }
    post_done(sa.server, &info.room, &info.token)?;
    println!("\n  共 {} 个文件（{}）已全部发出", files.len(), fmt_bytes(total));
    await_ack(sa.server, &info.room, &info.key, &info.target);
    Ok(())
}

// ============================================================
// 接收
// ============================================================
struct LinkInfo {
    origin: UrlParts,
    room: String,
    key: [u8; 32],
}

fn parse_link(link: &str) -> CResult<LinkInfo> {
    let (base, frag) = match link.split_once('#') {
        Some((b, f)) => (b, f),
        None => return Err("链接格式不正确".into()),
    };
    let origin = parse_origin(base.trim_end_matches('/'))?;
    let (room, key_b64) = match frag.split_once('.') {
        Some((r, k)) => (r, k),
        None => return Err("链接格式不正确".into()),
    };
    if room.len() != ROOM_ID_LEN || !room.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err("链接格式不正确".into());
    }
    let key_bytes = from_b64u(key_b64)?;
    if key_bytes.len() != 32 {
        return Err("链接格式不正确".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(LinkInfo { origin, room: room.to_string(), key })
}

#[allow(clippy::too_many_arguments)]
fn receive_to_file(
    origin: &UrlParts,
    room: &str,
    key: &[u8; 32],
    use_aad: bool,
    resume: bool,
    meta: &Value,
    target: &Path,
    start_index: u64,
    start_from: u64,
    initial_got: u64,
    progress: &mut Progress,
) -> CResult<()> {
    let size = meta_u64(meta, "size");
    let count = meta_u64(meta, "count");
    let part = PathBuf::from(format!("{}.part", target.display()));
    let mut fh = if start_from > 1 {
        OpenOptions::new().create(true).append(true).open(&part)
    } else {
        File::create(&part)
    }
    .map_err(|e| format!("无法写入 {}: {}", part.display(), e))?;
    let mut got = initial_got;
    let t0 = Instant::now();
    for i in start_from..count {
        let global = start_index + i - 1;
        let packed = match get_chunk_at(origin, room, global, resume) {
            Ok(v) => v,
            Err(e) => {
                drop(fh);
                if !e.contains("GCM") && !e.contains("auth") && !e.contains("完整性") {
                    println!(
                        "\n  ⏸ 传输中断,进度已保留: {}\n  重跑同一命令即可从断点继续（链接与输出路径不变）",
                        part.display()
                    );
                }
                return Err(e);
            }
        };
        let aad = if use_aad { Some(chunk_aad(room, global)) } else { None };
        let pt = match unseal(key, &packed, aad.as_deref()) {
            Ok(v) => v,
            Err(e) => {
                drop(fh);
                if !e.contains("GCM") && !e.contains("auth") && !e.contains("完整性") {
                    println!(
                        "\n  ⏸ 传输中断,进度已保留: {}\n  重跑同一命令即可从断点继续（链接与输出路径不变）",
                        part.display()
                    );
                }
                return Err(e);
            }
        };
        got += pt.len() as u64;
        fh.write_all(&pt).map_err(|e| format!("写入失败: {}", e))?;
        let _ = fh.flush();
        progress.post(start_index + i - 1);
        let sp = (got - initial_got) as f64 / t0.elapsed().as_secs_f64().max(0.001);
        print!("\r  已接收 {} / {} · {}/s", fmt_bytes(got), fmt_bytes(size), fmt_bytes(sp as u64));
        let _ = io::stdout().flush();
    }
    drop(fh);
    if got != size {
        return Err(format!("完整性校验失败：文件大小 {} ≠ {}", got, size));
    }
    fs::rename(&part, target).map_err(|e| format!("重命名失败: {}", e))?;
    Ok(())
}

fn receive_resumable(
    origin: &UrlParts,
    room: &str,
    key: &[u8; 32],
    use_aad: bool,
    meta: &Value,
    target: &Path,
    start: u64,
) -> CResult<()> {
    let mut progress = Progress::new(origin, room);
    if start == 1 {
        progress.post(1); // 元信息已解析
    }
    let count = meta_u64(meta, "count");
    let part = PathBuf::from(format!("{}.part", target.display()));
    let run = |start_from: u64, initial_got: u64, progress: &mut Progress| -> CResult<()> {
        receive_to_file(origin, room, key, use_aad, true, meta, target, start, start_from, initial_got, progress)
    };
    let st = fs::metadata(&part).ok();
    let full_commit = |progress: &mut Progress| progress.post(start + count - 1);
    let result = (|| -> CResult<()> {
        if let Some(md) = st {
            let lt = std::cmp::min(md.len() / CHUNK as u64, count.saturating_sub(1));
            if lt > 0 {
                let f = OpenOptions::new().write(true).open(&part).map_err(|e| e.to_string())?;
                f.set_len(lt * CHUNK as u64).map_err(|e| e.to_string())?;
                drop(f);
                println!("  ↻ 检测到未完成的接收，从第 {}/{} 片续传", lt + 1, count.saturating_sub(1));
                run(lt + 1, lt * CHUNK as u64, &mut progress)?;
            } else {
                run(1, 0, &mut progress)?;
            }
        } else {
            run(1, 0, &mut progress)?;
        }
        full_commit(&mut progress);
        Ok(())
    })();
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            if e.contains("GCM") || e.contains("auth") {
                let _ = fs::remove_file(&part);
                println!("  ⚠ 已有 .part 与本次传输不符（验签失败），重新完整接收");
                run(1, 0, &mut progress)?;
                full_commit(&mut progress);
                Ok(())
            } else if e.contains("已被使用") {
                let _ = fs::remove_file(&part);
                println!("  ⚠ 断点已被服务器回收，从头完整接收");
                run(1, 0, &mut progress)?;
                full_commit(&mut progress);
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

fn receive_batch(origin: &UrlParts, room: &str, key: &[u8; 32], meta: &Value, out_dir: &Path, use_aad: bool) -> CResult<()> {
    fs::create_dir_all(out_dir).map_err(|e| format!("无法创建目录 {}: {}", out_dir.display(), e))?;
    let mut progress = Progress::new(origin, room);
    progress.post(1);
    let files = meta.get("files").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let manifest_sum: u64 = files.iter().map(|f| f.get("size").and_then(|v| v.as_u64()).unwrap_or(0)).sum();
    let total = meta_u64(meta, "size");
    if manifest_sum != total {
        return Err(format!("完整性校验失败：manifest 总大小 {} ≠ {}", manifest_sum, total));
    }
    let mut idx: u64 = 1;
    for f in &files {
        let rel = f.get("name").and_then(|v| v.as_str()).unwrap_or("received");
        let target = safe_join(out_dir, rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let n = f.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let fsize = f.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
        if n == 0 {
            fs::write(&target, []).map_err(|e| e.to_string())?;
            println!("\n  ✓ {}（0 B，空文件）", clean(rel, 200));
            continue;
        }
        let start = idx;
        idx += n;
        let file_meta = json!({ "size": fsize, "count": n + 1 });
        receive_resumable(origin, room, key, use_aad, &file_meta, &target, start)?;
        println!("\n  ✓ {}（{}）", clean(rel, 200), fmt_bytes(fsize));
    }
    Ok(())
}

fn do_recv(origin: &UrlParts, room: &str, key: &[u8; 32], opts: &Opts) -> CResult<()> {
    let (meta, use_aad) = read_meta(origin, room, key, true)?;
    let kind = meta_str(&meta, "type").unwrap_or("file").to_string();
    if kind == "batch" {
        let dir = PathBuf::from(opts.out.clone().unwrap_or_else(|| ".".into()));
        receive_batch(origin, room, key, &meta, &dir, use_aad)?;
        post_ack(origin, room, key);
        let abs = fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
        let n = meta.get("files").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
        println!("\n\n✅ 已解密并保存 {} 个文件到 {}\n", n, abs.display());
        return Ok(());
    }
    if kind == "text" {
        let size = meta_u64(&meta, "size");
        let packed = get_chunk_at(origin, room, 1, true)?;
        let aad = if use_aad { Some(chunk_aad(room, 1)) } else { None };
        let pt = unseal(key, &packed, aad.as_deref())?;
        if pt.len() as u64 != size {
            return Err(format!("完整性校验失败：文本长度 {} ≠ {}", pt.len(), size));
        }
        io::stdout().write_all(&pt).map_err(|e| e.to_string())?;
        let _ = io::stdout().flush();
        post_ack(origin, room, key);
        return Ok(());
    }
    let target = match &opts.out {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(safe_name(meta_str(&meta, "name").unwrap_or("received"))),
    };
    receive_resumable(origin, room, key, use_aad, &meta, &target, 1)?;
    post_ack(origin, room, key);
    println!("\n\n✅ 已解密并保存到 {}（{}）\n", target.display(), fmt_bytes(meta_u64(&meta, "size")));
    Ok(())
}

// ============================================================
// listen（常驻接收端）
// ============================================================
fn accept_offer(server: &UrlParts, secret: &str, id: &Identity, opts: &Opts, offer: &Value) -> CResult<()> {
    let room = offer.get("room").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let pub_b64 = offer.get("pub").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let hint_b64 = offer.get("hint").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let oid = offer.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let from = offer.get("from").cloned().unwrap_or(Value::Null);
    let from_ip = clean(from.get("ip").and_then(|v| v.as_str()).unwrap_or("?"), 64);
    let from_name = clean(from.get("name").and_then(|v| v.as_str()).unwrap_or("未知设备"), 32);
    let their_bytes = from_b64u(&pub_b64)?;
    if their_bytes.len() != 32 {
        return Err("邀请公钥长度非法".into());
    }
    let mut their = [0u8; 32];
    their.copy_from_slice(&their_bytes);
    let fp = fp_hex(&their);
    let shared = dh(&id.seed, &their)?;
    let key = room_key(&shared, &their, &id.public, &room);
    let hint = from_b64u(&hint_b64)?;
    let preview: Value = match unseal(&key, &hint, None).and_then(|pt| {
        serde_json::from_slice(&pt).map_err(|_| "预览 JSON 非法".to_string())
    }) {
        Ok(v) => v,
        Err(_) => {
            println!("\n  ⚠ 来自 {} 的邀请预览解密失败（可能被篡改），已拒绝", from_ip);
            let _ = reject_offer(server, secret, &oid);
            return Ok(());
        }
    };
    let kind = preview.get("kind").and_then(|v| v.as_str()).unwrap_or("file").to_string();
    let psize = preview.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
    let desc = match kind.as_str() {
        "text" => format!("一段文本（{}）", fmt_bytes(psize)),
        "batch" => format!(
            "{} 个文件（{}）",
            clean(&preview.get("count").map(|v| v.to_string()).unwrap_or_default(), 12),
            fmt_bytes(psize)
        ),
        _ => format!(
            "{}（{}）",
            clean(preview.get("name").and_then(|v| v.as_str()).unwrap_or("未命名文件"), 64),
            fmt_bytes(psize)
        ),
    };
    println!("\n{}  {} @ {} 想发给你：{}", avatar_of(&from_ip), from_name, from_ip, desc);
    println!("  发送方公钥指纹 #{}", fp);
    println!("  （请与发送方当面/口头核对；不会自动比对）");

    if !opts.yes {
        use std::io::IsTerminal;
        let is_tty = std::io::stdin().is_terminal();
        if !is_tty {
            println!("  非 TTY 环境需 --yes 才能自动接受，已拒绝");
            let _ = reject_offer(server, secret, &oid);
            return Ok(());
        }
        print!("  接受？(y/n) ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        let _ = io::stdin().lock().read_line(&mut line);
        let ans = line.trim().to_lowercase();
        if ans != "y" && ans != "yes" {
            println!("  已拒绝");
            let _ = reject_offer(server, secret, &oid);
            return Ok(());
        }
    }
    let r = http_request(
        "POST",
        &url(server, &format!("/api/offers/{}/accept", oid)),
        &[("X-Device-Secret", secret.to_string())],
        None,
        Duration::from_secs(10),
    )
    .map_err(|e| e.msg())?;
    if r.status != 200 {
        return Err(format!("接受失败 {}", r.status));
    }

    // 设备直发用经典消费语义（resume=false），避免无 progress 时报背压死锁
    let (meta, use_aad) = read_meta(server, &room, &key, false)?;
    let kind = meta_str(&meta, "type").unwrap_or("file").to_string();
    let size = meta_u64(&meta, "size");
    let pull = |i: u64| -> CResult<Vec<u8>> {
        let packed = get_chunk_at(server, &room, i, false)?;
        let aad = if use_aad { Some(chunk_aad(&room, i)) } else { None };
        unseal(&key, &packed, aad.as_deref())
    };
    if kind == "batch" {
        let dir = PathBuf::from(opts.out.clone().unwrap_or_else(|| ".".into()));
        receive_batch(server, &room, &key, &meta, &dir, use_aad)?;
        post_ack(server, &room, &key);
        let abs = fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
        let n = meta.get("files").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
        println!("\n  ✅ 已解密保存 {} 个文件到 {}\n", n, abs.display());
        return Ok(());
    }
    if kind == "text" {
        let pt = pull(1)?;
        if pt.len() as u64 != size {
            return Err(format!("完整性校验失败：文本长度 {} ≠ {}", pt.len(), size));
        }
        println!("  ──────── 文本开始 ────────");
        io::stdout().write_all(&pt).map_err(|e| e.to_string())?;
        if !pt.ends_with(b"\n") {
            println!();
        }
        let _ = io::stdout().flush();
        println!("  ──────── 文本结束 ────────");
        post_ack(server, &room, &key);
        return Ok(());
    }

    let target = PathBuf::from(opts.out.clone().unwrap_or_else(|| ".".into()))
        .join(safe_name(meta_str(&meta, "name").unwrap_or("received")));
    let mut progress = Progress::new(server, &room);
    receive_to_file(server, &room, &key, use_aad, false, &meta, &target, 1, 1, 0, &mut progress)?;
    post_ack(server, &room, &key);
    println!(
        "\n  ✅ 已解密保存到 {}（{}）\n",
        safe_name(meta_str(&meta, "name").unwrap_or("received")),
        fmt_bytes(size)
    );
    Ok(())
}

fn reject_offer(server: &UrlParts, secret: &str, oid: &str) {
    let _ = http_request(
        "POST",
        &url(server, &format!("/api/offers/{}/reject", oid)),
        &[("X-Device-Secret", secret.to_string())],
        None,
        Duration::from_secs(10),
    );
}

fn do_listen(sa: &SendArgs) -> CResult<()> {
    let id = gen_identity();
    let name = sa.opts.name.clone().unwrap_or_else(hostname);
    let presence0 = heartbeat(sa.server, &name, &id, &None)?;
    let presence: Arc<Mutex<Presence>> = Arc::new(Mutex::new(Some(presence0.clone())));
    {
        let server = sa.server.clone();
        let name = name.clone();
        let presence = presence.clone();
        thread::spawn(move || {
            let mut failing = false;
            loop {
                thread::sleep(Duration::from_secs(5));
                let cur = presence.lock().unwrap().clone();
                match heartbeat(&server, &name, &id, &cur) {
                    Ok(v) => {
                        *presence.lock().unwrap() = Some(v);
                        failing = false;
                    }
                    Err(e) => {
                        if !failing {
                            failing = true;
                            eprintln!("  ⚠ 心跳失败：{}（持续重试,恢复后自动重新上线）", e);
                        }
                    }
                }
            }
        });
    }
    let ip = presence0.get("ip").and_then(|v| v.as_str()).unwrap_or("?").to_string();
    println!(
        "{}  本机已上线：{} @ {}（服务器 {}）",
        avatar_of(&ip),
        clean(&name, 64),
        clean(&ip, 64),
        sa.server.origin
    );
    println!("  等待直发请求…（Ctrl+C 退出）\n");

    loop {
        let secret = presence_secret(&presence.lock().unwrap().clone()).unwrap_or_default();
        let u = url(sa.server, "/api/offers");
        let resp = http_request(
            "GET",
            &u,
            &[("X-Device-Secret", secret.clone())],
            None,
            Duration::from_secs(35),
        );
        let offers: Vec<Value> = match resp {
            Ok(r) if r.status == 401 => {
                let cur = presence.lock().unwrap().clone();
                if let Ok(v) = heartbeat(sa.server, &name, &id, &cur) {
                    *presence.lock().unwrap() = Some(v);
                }
                continue;
            }
            Ok(r) if r.status != 200 => {
                thread::sleep(Duration::from_millis(2000));
                continue;
            }
            Ok(r) => serde_json::from_slice::<Value>(&r.body)
                .ok()
                .and_then(|j| j.get("offers").and_then(|v| v.as_array()).cloned())
                .unwrap_or_default(),
            Err(_) => {
                thread::sleep(Duration::from_millis(2000));
                continue;
            }
        };
        for offer in offers {
            if let Err(e) = accept_offer(sa.server, &secret, &id, sa.opts, &offer) {
                eprintln!("  ✗ 处理邀请失败：{}", e);
                let oid = offer.get("id").and_then(|v| v.as_str()).unwrap_or("");
                reject_offer(sa.server, &secret, oid);
            }
        }
    }
}

// ============================================================
// 子命令：devices
// ============================================================
fn do_devices(server: &UrlParts) -> CResult<()> {
    let list = list_devices(server)?;
    if list.is_empty() {
        println!("当前没有在线设备（对方打开本页或运行 listen 后出现）");
        return Ok(());
    }
    println!("在线设备 {} 台（指纹 = SHA256(公钥) 前 32 hex，可与对方当面核对）：\n", list.len());
    for d in &list {
        let name = clean(d.get("name").and_then(|v| v.as_str()).unwrap_or("未命名设备"), 32);
        let ip = clean(d.get("ip").and_then(|v| v.as_str()).unwrap_or("?"), 64);
        let pub_b64 = d.get("pub").and_then(|v| v.as_str()).unwrap_or("");
        let fp = from_b64u(pub_b64).map(|raw| fp_hex(&raw)).unwrap_or_else(|_| "?".into());
        println!("  {}  {:<20} {}", avatar_of(&ip), name, ip);
        println!("      #{}", fp);
    }
    if let Some(first) = list.first() {
        let ip = first.get("ip").and_then(|v| v.as_str()).unwrap_or("127.0.0.1");
        println!("\n直发示例: cipherlane-cli send big.zip --to {} --verify <对方指纹前8位以上>", ip);
    }
    Ok(())
}

// ============================================================
// main
// ============================================================
fn main() {
    let opts = parse_args();
    if opts.help {
        usage();
        return;
    }
    let server_raw = opts
        .server
        .clone()
        .or_else(|| env::var("CIPHERLANE_SERVER").ok())
        .or_else(|| env::var("LANDROP_SERVER").ok())
        .unwrap_or_else(|| "http://127.0.0.1:7777".to_string());
    let server = match parse_origin(server_raw.trim_end_matches('/')) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("✗ {}", e);
            process::exit(1);
        }
    };
    let sa = SendArgs { server: &server, opts: &opts };
    let result: CResult<()> = match opts.cmd.as_deref() {
        Some("devices") => do_devices(&server),
        Some("send") => {
            let paths: Vec<String> = opts.pos.iter().skip(1).cloned().collect();
            if paths.is_empty() {
                usage();
                process::exit(1);
            }
            let single = paths.len() == 1 && Path::new(&paths[0]).is_file();
            if single {
                do_send_file(&sa, Path::new(&paths[0]))
            } else {
                do_send_batch(&sa, &paths)
            }
        }
        Some("send-text") => {
            if opts.pos.get(1).is_none() {
                usage();
                process::exit(1);
            }
            let text = opts.pos.get(1).cloned().unwrap_or_default();
            do_send_text(&sa, &text)
        }
        Some("recv") => match opts.pos.get(1) {
            Some(link) => match parse_link(link) {
                Ok(li) => do_recv(&li.origin, &li.room, &li.key, &opts),
                Err(e) => Err(e),
            },
            None => {
                usage();
                process::exit(1);
            }
        },
        Some("listen") => do_listen(&sa),
        _ => {
            usage();
            process::exit(1);
        }
    };
    if let Err(e) = result {
        eprintln!("✗ {}", e);
        process::exit(1);
    }
}
