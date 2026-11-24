//! CLI 端到端（Rust 版，零 Node）：真实 `cipherlane` 服务器 + 真实 `cipherlane-cli` 子进程。
//!
//! 覆盖（对齐 v1.0 前 `test/cli.test.mjs` 的 11 组，不删组不放水）：
//!   1) 单文件链接模式（线上 meta.v=2 / AAD）
//!   2) 目录递归批量（嵌套 / 中文 / 空文件 / 隐藏项跳过）
//!   3) 多路径混合（散文件 + 目录）
//!   4) 文本链路
//!   5) SIGKILL 中断 → `.part` 断点续传
//!   6) 协议 v2 完整性校验（长度篡改拒绝、不 ack、无产物）
//!   7) v1 回退（旧无 AAD 发送端 → 新 CLI 接收端）
//!   8) v2 AAD 错位拒绝（含正控与"旧实现位置盲"证明）
//!   9) 定向模式（proxy 伪装 127.0.0.2 / devices 指纹 / --verify / send+send-text --to）
//!  10) 独立实现互操作：本测试用 x25519-dalek/aes-gcm/sha2 独立构造房间密钥/hint/v2 分片/ackProof，
//!      由 Rust CLI listen 解密、展示指纹并 ack——锁定 KDF/指纹/AAD/ackProof 逐字节兼容。
//!  11) 终端注入净化（设备名 / 文件名中的 ANSI/BEL 控制字符）
//!  12) --version / -V（版本号来自 Cargo.toml）
//!
//! 所有测试通过 `common::serial()` 跨进程串行，避免端口/设备单 IP 模型互相干扰。
#![cfg(unix)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPub, StaticSecret};

const CHUNK: usize = 1024 * 1024;
const KDF_LABEL: &[u8] = b"cipherlane/device/v1\x00";
const ACK_LABEL: &str = "cipherlane/ack/v1|";
const AAD_PREFIX: &str = "cipherlane/chunk/v2|";

// ============================================================
// 临时目录 / 文件树 / 轮询
// ============================================================
struct TempDir(PathBuf);

impl TempDir {
    fn new(prefix: &str) -> TempDir {
        TempDir(common::unique_dir(prefix))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn wait_until<F: FnMut() -> bool>(timeout: Duration, what: &str, mut f: F) {
    let deadline = Instant::now() + timeout;
    loop {
        if f() {
            return;
        }
        if Instant::now() > deadline {
            panic!("等待超时（{what}）");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn collect_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("读取目录 {} 失败: {e}", dir.display()))
            .map(|e| e.expect("目录项"))
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for ent in entries {
            let name = ent.file_name().to_string_lossy().to_string();
            let rel = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
            let p = ent.path();
            let md = fs::metadata(&p).expect("metadata");
            if md.is_dir() {
                walk(&p, &rel, out);
            } else {
                out.insert(rel, fs::read(&p).expect("读取文件"));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, "", &mut out);
    out
}

// ============================================================
// CLI 子进程封装（stdout+stderr 合流，可轮询输出、可 SIGKILL）
// ============================================================
struct Cli {
    child: Child,
    out: Arc<Mutex<String>>,
}

impl Cli {
    fn spawn(server: &str, args: &[&str]) -> Cli {
        let mut cmd = Command::new(common::cli_bin());
        cmd.args(args)
            .env("CIPHERLANE_SERVER", server)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("启动 cipherlane-cli 失败");
        let out = Arc::new(Mutex::new(String::new()));
        let mut so = child.stdout.take().expect("stdout");
        let mut se = child.stderr.take().expect("stderr");
        let o1 = out.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            while let Ok(n) = so.read(&mut buf) {
                if n == 0 {
                    break;
                }
                o1.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
        let o2 = out.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            while let Ok(n) = se.read(&mut buf) {
                if n == 0 {
                    break;
                }
                o2.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
        Cli { child, out }
    }

    fn output(&self) -> String {
        self.out.lock().unwrap().clone()
    }

    fn wait_for_output(&self, needle: &str, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            let out = self.output();
            if out.contains(needle) {
                return out;
            }
            if Instant::now() > deadline {
                panic!("等待 CLI 输出包含 {needle:?} 超时，实际输出:\n{out}");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// 等待退出；返回 (exit code, 合并输出)。超时 kill 并 panic。
    fn wait_timeout(&mut self, timeout: Duration) -> (i32, String) {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                // 管道读取线程可能还差最后几字节，短暂等待输出静默
                let mut last = usize::MAX;
                for _ in 0..100 {
                    let n = self.output().len();
                    if n == last {
                        break;
                    }
                    last = n;
                    thread::sleep(Duration::from_millis(10));
                }
                let code = status.code().unwrap_or(-1);
                return (code, self.output());
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("CLI 超时（{}s）:\n{}", timeout.as_secs(), self.output());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn kill(&mut self) {
        let _ = self.child.kill(); // unix: SIGKILL
        let _ = self.child.wait();
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run_cli(server: &str, args: &[&str]) -> (i32, String) {
    let mut c = Cli::spawn(server, args);
    c.wait_timeout(Duration::from_secs(180))
}

/// 从发送方输出中提取 `http://.../#room.key` 接收链接（QR 行不会含 #）。
fn extract_link(out: &str) -> Option<String> {
    for tok in out.split_whitespace() {
        if let Some(pos) = tok.find("http://") {
            let s = &tok[pos..];
            if s.contains('#') && s.matches("http://").count() == 1 {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn wait_link(cli: &Cli, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(link) = extract_link(&cli.output()) {
            return link;
        }
        if Instant::now() > deadline {
            panic!("发送方未打印接收链接:\n{}", cli.output());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn split_link(link: &str) -> (String, [u8; 32]) {
    let (_, frag) = link
        .split_once('#')
        .unwrap_or_else(|| panic!("链接缺少 #fragment: {link}"));
    let (room, key_b64) = frag
        .split_once('.')
        .unwrap_or_else(|| panic!("链接 fragment 非法: {frag}"));
    assert_eq!(room.len(), 10, "房间号应为 10 位: {room}");
    (room.to_string(), key32(&common::from_b64u(key_b64)))
}

// ============================================================
// 独立实现的密码学（与 CLI/浏览器逐字节一致；不依赖 CLI 内部代码）
// ============================================================
fn key32(bytes: &[u8]) -> [u8; 32] {
    assert_eq!(bytes.len(), 32, "需要 32 字节密钥/公钥");
    let mut k = [0u8; 32];
    k.copy_from_slice(bytes);
    k
}

fn x_pub(seed: &[u8; 32]) -> [u8; 32] {
    XPub::from(&StaticSecret::from(*seed)).to_bytes()
}

fn dh(seed: &[u8; 32], their_pub: &[u8; 32]) -> [u8; 32] {
    let shared = StaticSecret::from(*seed).diffie_hellman(&XPub::from(*their_pub)).to_bytes();
    assert!(shared.iter().any(|b| *b != 0), "X25519 共享密钥不得为全零");
    shared
}

fn room_key(shared: &[u8; 32], sender_pub: &[u8; 32], receiver_pub: &[u8; 32], room: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(shared);
    h.update(sender_pub);
    h.update(receiver_pub);
    h.update(KDF_LABEL);
    h.update(room.as_bytes());
    key32(&h.finalize())
}

fn ack_proof_hex(key: &[u8; 32], room: &str) -> String {
    let mut h = Sha256::new();
    h.update(key);
    h.update(ACK_LABEL.as_bytes());
    h.update(room.as_bytes());
    common::hex(&h.finalize())
}

fn fp_hex(pubkey: &[u8]) -> String {
    common::hex(&Sha256::digest(pubkey)[..16])
}

fn chunk_aad(room: &str, index: u64) -> Vec<u8> {
    format!("{AAD_PREFIX}{room}|{index}").into_bytes()
}

fn seal(key: &[u8; 32], pt: &[u8], aad: Option<&[u8]>) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256-GCM 密钥");
    let iv = common::random_bytes(12);
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: pt, aad: aad.unwrap_or(&[]) })
        .expect("GCM 加密失败");
    let mut out = iv;
    out.extend_from_slice(&ct);
    out
}

fn unseal(key: &[u8; 32], packed: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, String> {
    if packed.len() < 28 {
        return Err("数据不完整".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "AES 密钥非法".to_string())?;
    cipher
        .decrypt(
            Nonce::from_slice(&packed[..12]),
            Payload { msg: &packed[12..], aad: aad.unwrap_or(&[]) },
        )
        .map_err(|_| "GCM 验证失败：密钥错误或数据被篡改".to_string())
}

fn link_of(server: &str, room: &str, key: &[u8; 32]) -> String {
    format!("{}/#{}.{}", server.trim_end_matches('/'), room, common::b64u(key))
}

fn now_millis() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
}

// ============================================================
// 服务器 HTTP 辅助（独立构造协议样本）
// ============================================================
fn create_room(port: u16) -> (String, String) {
    let r = common::http(port, "POST", "/api/rooms", &[], None).expect("POST /api/rooms");
    assert_eq!(r.status, 200, "建房失败: {}", r.text());
    let j = r.json();
    (
        j["room"].as_str().expect("room").to_string(),
        j["token"].as_str().expect("token").to_string(),
    )
}

fn post_chunk(port: u16, room: &str, token: &str, seq: u64, body: &[u8]) {
    let path = format!("/api/rooms/{room}/chunk");
    let seq_s = seq.to_string();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let headers = [("X-Room-Token", token), ("X-Chunk-Seq", seq_s.as_str())];
        let r = common::http(port, "POST", &path, &headers, Some(body)).expect("POST chunk");
        match r.status {
            200 => return,
            429 if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            s => panic!("投递分片 seq={seq} 失败: HTTP {s} {}", r.text()),
        }
    }
}

fn get_chunk(port: u16, room: &str, index: u64, resume: bool) -> Vec<u8> {
    let path = format!("/api/rooms/{room}/chunk?i={index}");
    let headers: &[(&str, &str)] = if resume { &[("X-Resume", "1")] } else { &[] };
    let r = common::http(port, "GET", &path, headers, None).expect("GET chunk");
    assert_eq!(r.status, 200, "拉取分片 {index} 失败: {}", r.text());
    r.body
}

fn room_state(port: u16, room: &str) -> serde_json::Value {
    common::http(port, "GET", &format!("/api/rooms/{room}/state"), &[], None)
        .expect("GET state")
        .json()
}

fn devices_json(port: u16) -> serde_json::Value {
    common::http(port, "GET", "/api/devices", &[], None)
        .expect("GET devices")
        .json()
}

fn register_presence(port: u16, name: &str, pubkey: &[u8; 32]) {
    let body = serde_json::json!({ "name": name, "pub": common::b64u(pubkey) }).to_string();
    let r = common::http(
        port,
        "POST",
        "/api/presence",
        &[("Content-Type", "application/json")],
        Some(body.as_bytes()),
    )
    .expect("POST presence");
    assert_eq!(r.status, 200, "presence 注册失败: {}", r.text());
}

fn post_offer(port: u16, room: &str, token: &str, to: &str, pub_b64: &str, hint_b64: &str) {
    let body = serde_json::json!({ "to": to, "pub": pub_b64, "hint": hint_b64 }).to_string();
    let path = format!("/api/rooms/{room}/offer");
    let r = common::http(
        port,
        "POST",
        &path,
        &[("Content-Type", "application/json"), ("X-Room-Token", token)],
        Some(body.as_bytes()),
    )
    .expect("POST offer");
    assert_eq!(r.status, 200, "投递邀请失败: {}", r.text());
}

/// 从 devices 输出中取某 IP 后面的 32 hex 指纹。
fn fp_after(out: &str, ip: &str) -> String {
    let at = out
        .find(ip)
        .unwrap_or_else(|| panic!("devices 输出不含 {ip}:\n{out}"));
    let rest = &out[at..];
    let hash = rest
        .find('#')
        .unwrap_or_else(|| panic!("# 指纹不在 {ip} 之后:\n{out}"));
    let fp: String = rest[hash + 1..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .take(32)
        .collect();
    assert_eq!(fp.len(), 32, "指纹应为 32 hex:\n{out}");
    fp
}

// ============================================================
// 127.0.0.2 代理（libc 原始 socket：绑定源地址后连接服务器）
// ============================================================
fn connect_from(local: Ipv4Addr, remote: (Ipv4Addr, u16)) -> std::io::Result<TcpStream> {
    use std::os::fd::FromRawFd;
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut la: libc::sockaddr_in = std::mem::zeroed();
        la.sin_family = libc::AF_INET as libc::sa_family_t;
        la.sin_port = 0;
        la.sin_addr.s_addr = u32::from_ne_bytes(local.octets());
        if libc::bind(
            fd,
            &la as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        let mut ra: libc::sockaddr_in = std::mem::zeroed();
        ra.sin_family = libc::AF_INET as libc::sa_family_t;
        ra.sin_port = remote.1.to_be();
        ra.sin_addr.s_addr = u32::from_ne_bytes(remote.0.octets());
        if libc::connect(
            fd,
            &ra as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(TcpStream::from_raw_fd(fd))
    }
}

struct Proxy {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Proxy {
    /// 监听 `bind:target_port`，把连接转发到 127.0.0.1:target_port，且源地址伪装为 bind。
    fn start(bind: Ipv4Addr, target_port: u16) -> Proxy {
        let listener = TcpListener::bind((bind, target_port)).expect("绑定 127.0.0.2 代理端口失败");
        listener.set_nonblocking(true).expect("nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let handle = thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((client, _)) => {
                        thread::spawn(move || relay(client, target_port));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => break,
                }
            }
        });
        Proxy { stop, handle: Some(handle) }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn relay(client: TcpStream, target_port: u16) {
    let server = match connect_from(Ipv4Addr::new(127, 0, 0, 2), (Ipv4Addr::LOCALHOST, target_port)) {
        Ok(s) => s,
        Err(_) => return,
    };
    let (mut c1, mut s1) = (client, server);
    let (mut c2, mut s2) = match (c1.try_clone(), s1.try_clone()) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return,
    };
    let t1 = thread::spawn(move || {
        let _ = std::io::copy(&mut c1, &mut s1);
        let _ = s1.shutdown(Shutdown::Both);
    });
    let t2 = thread::spawn(move || {
        let _ = std::io::copy(&mut s2, &mut c2);
        let _ = c2.shutdown(Shutdown::Both);
    });
    let _ = t1.join();
    let _ = t2.join();
}

/// 起一个监听 `127.0.0.2:<server_port>` 的代理并等待 CLI listen 上线。
fn start_listener(server_port: u16, recv_dir: &Path) -> (Proxy, Cli) {
    let proxy = Proxy::start(Ipv4Addr::new(127, 0, 0, 2), server_port);
    let target = format!("http://127.0.0.2:{server_port}");
    let listener = Cli::spawn(
        &target,
        &[
            "listen",
            "--yes",
            "-o",
            recv_dir.to_str().expect("recv_dir utf8"),
            "--name",
            "测试机B",
            "--server",
            &target,
        ],
    );
    wait_until(Duration::from_secs(20), "listen 上线（127.0.0.2 出现在设备列表）", || {
        devices_json(server_port)["devices"]
            .as_array()
            .map(|a| a.iter().any(|d| d["ip"].as_str() == Some("127.0.0.2")))
            .unwrap_or(false)
    });
    (proxy, listener)
}

// ============================================================
// 1) 单文件链接模式（在线 meta.v=2 / AAD）
// ============================================================
#[test]
fn single_file_link_mode() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let tmp = TempDir::new("cl-cli-single");
    let src = tmp.path().join("one.bin");
    let data = common::random_bytes(2 * 1024 * 1024 + 777);
    fs::write(&src, &data).expect("写源文件");

    let mut send = Cli::spawn(&srv.url(), &["send", src.to_str().unwrap()]);
    let link = wait_link(&send, Duration::from_secs(30));
    let (room, key) = split_link(&link);

    // 独立验证线上协议：X-Resume 只读拉 0 号 meta，v2 AAD 可解、无 AAD 不可解
    let packed0 = get_chunk(srv.port, &room, 0, true);
    let meta_pt = unseal(&key, &packed0, Some(&chunk_aad(&room, 0))).expect("v2 AAD 应能解 meta");
    let meta: serde_json::Value = serde_json::from_slice(&meta_pt).expect("meta JSON");
    assert_eq!(meta["v"], 2, "CLI 发送端 meta.v 应为 2: {meta}");
    assert!(
        unseal(&key, &packed0, None).is_err(),
        "v2 meta 不应能按旧无 AAD 方式解开"
    );

    let out = tmp.path().join("got-one.bin");
    let (code, rtxt) = run_cli(
        &srv.url(),
        &["recv", &link, "-o", out.to_str().unwrap()],
    );
    assert_eq!(code, 0, "recv 失败:\n{rtxt}");
    assert_eq!(fs::read(&out).expect("读回文件"), data, "单文件字节不一致");

    let (scode, sout) = send.wait_timeout(Duration::from_secs(120));
    assert_eq!(scode, 0, "发送方失败:\n{sout}");
    assert!(sout.contains("凭证校验通过"), "发送方应显示凭证校验通过:\n{sout}");
    // 发送方观测到带凭证的 ack 后应删除房间：立即释放服务端内存与 per-IP 配额，
    // 而不是等 2 分钟空闲清扫（残留房间会让同一 IP 的下一次大文件发送被背压卡住）
    let after = common::http(srv.port, "GET", &format!("/api/rooms/{room}/state"), &[], None)
        .expect("GET state（发送完成后）");
    assert_eq!(after.status, 404, "ack 后发送方应已删除房间，state 实际返回 {}: {}", after.status, after.text());
}

// ============================================================
// 2) 目录递归批量
// ============================================================
#[test]
fn directory_recursive_batch() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let tmp = TempDir::new("cl-cli-tree");
    let dir = tmp.path().join("src-tree");
    fs::create_dir_all(dir.join("sub/deeper")).expect("建目录");
    fs::write(dir.join("a.txt"), "顶层文件").expect("写 a.txt");
    fs::write(dir.join("sub/b.bin"), common::random_bytes(1000)).expect("写 b.bin");
    fs::write(dir.join("sub/deeper/c 大.bin"), common::random_bytes(3 * 1024 * 1024))
        .expect("写 c 大.bin");
    fs::write(dir.join("empty.dat"), []).expect("写空文件");
    fs::create_dir_all(dir.join(".git")).expect("建 .git");
    fs::write(dir.join(".git/config"), "x").expect("写 .git/config");

    let mut send = Cli::spawn(&srv.url(), &["send", dir.to_str().unwrap()]);
    let link = wait_link(&send, Duration::from_secs(30));
    let out_dir = tmp.path().join("got-tree");
    let (code, rtxt) = run_cli(&srv.url(), &["recv", &link, "-o", out_dir.to_str().unwrap()]);
    assert_eq!(code, 0, "recv 失败:\n{rtxt}");

    let mut want = collect_tree(&dir);
    want.remove(".git/config"); // 隐藏项应被发送端跳过
    let got = collect_tree(&out_dir);
    let want_keys: Vec<_> = want.keys().cloned().collect();
    let got_keys: Vec<_> = got.keys().cloned().collect();
    assert_eq!(got_keys, want_keys, "文件清单不一致:\n got {got_keys:?}\n want {want_keys:?}");
    for (rel, bytes) in &want {
        assert_eq!(got.get(rel), Some(bytes), "内容不一致: {rel}");
    }

    let (scode, sout) = send.wait_timeout(Duration::from_secs(120));
    assert_eq!(scode, 0, "发送方失败:\n{sout}");
}

// ============================================================
// 3) 多路径混合
// ============================================================
#[test]
fn multi_path_mixed() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let tmp = TempDir::new("cl-cli-multi");
    let tree = tmp.path().join("src-tree");
    fs::create_dir_all(tree.join("sub/deeper")).expect("建目录");
    fs::write(tree.join("a.txt"), "A").expect("写");
    fs::write(tree.join("sub/b.bin"), common::random_bytes(1000)).expect("写");
    fs::write(tree.join("sub/deeper/c.bin"), common::random_bytes(4096)).expect("写");
    let extra = tmp.path().join("extra.bin");
    let extra_bytes = common::random_bytes(5000);
    fs::write(&extra, &extra_bytes).expect("写 extra");

    let mut send = Cli::spawn(
        &srv.url(),
        &["send", extra.to_str().unwrap(), tree.join("sub").to_str().unwrap()],
    );
    let link = wait_link(&send, Duration::from_secs(30));
    let out_dir = tmp.path().join("got-multi");
    let (code, rtxt) = run_cli(&srv.url(), &["recv", &link, "-o", out_dir.to_str().unwrap()]);
    assert_eq!(code, 0, "recv 失败:\n{rtxt}");
    let got = collect_tree(&out_dir);
    assert_eq!(
        got.get("extra.bin"),
        Some(&extra_bytes),
        "应收到散文件，实际: {:?}",
        got.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        got.get("b.bin"),
        Some(&fs::read(tree.join("sub/b.bin")).unwrap()),
        "应同时收到目录内容，实际: {:?}",
        got.keys().collect::<Vec<_>>()
    );
    let (scode, sout) = send.wait_timeout(Duration::from_secs(120));
    assert_eq!(scode, 0, "发送方失败:\n{sout}");
}

// ============================================================
// 4) 文本链路
// ============================================================
#[test]
fn text_link() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let text = format!("CLI 文本回归 {}", common::hex(&common::random_bytes(4)));
    let mut send = Cli::spawn(&srv.url(), &["send-text", &text]);
    let link = wait_link(&send, Duration::from_secs(30));
    let (code, rtxt) = run_cli(&srv.url(), &["recv", &link]);
    assert_eq!(code, 0, "recv 失败:\n{rtxt}");
    assert!(rtxt.contains(&text), "文本内容未出现在接收输出:\n{rtxt}");
    let (scode, sout) = send.wait_timeout(Duration::from_secs(120));
    assert_eq!(scode, 0, "发送方失败:\n{sout}");
}

// ============================================================
// 5) SIGKILL 中断 → .part 断点续传
// ============================================================
#[test]
fn resume_after_sigkill() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let tmp = TempDir::new("cl-cli-resume");
    let src = tmp.path().join("resume.bin");
    let data = common::random_bytes(24 * 1024 * 1024 + 4321); // 25 片
    fs::write(&src, &data).expect("写源文件");

    let mut send = Cli::spawn(&srv.url(), &["send", src.to_str().unwrap()]);
    let link = wait_link(&send, Duration::from_secs(60));
    let out = tmp.path().join("resume-out.bin");
    let part = PathBuf::from(format!("{}.part", out.display()));

    let mut first = Cli::spawn(&srv.url(), &["recv", &link, "-o", out.to_str().unwrap()]);
    let threshold = 3 * CHUNK as u64;
    wait_until(Duration::from_secs(60), ".part 落盘 ≥3MiB", || {
        fs::metadata(&part).map(|m| m.len() >= threshold).unwrap_or(false)
    });
    first.kill(); // SIGKILL

    let st = fs::metadata(&part).expect("中断后 .part 应存在");
    assert!(
        st.len() >= threshold && st.len() < data.len() as u64,
        "中断后应有部分进度且未完成: {} / {}",
        st.len(),
        data.len()
    );

    let (code, rtxt) = run_cli(&srv.url(), &["recv", &link, "-o", out.to_str().unwrap()]);
    assert_eq!(code, 0, "续传失败:\n{rtxt}");
    assert!(rtxt.contains("续传"), "应提示检测到断点:\n{rtxt}");
    assert_eq!(fs::read(&out).expect("读回续传结果"), data, "续传结果字节不一致");
    assert!(!part.exists(), ".part 完成后应已改名");

    let (scode, sout) = send.wait_timeout(Duration::from_secs(180));
    assert_eq!(scode, 0, "发送方失败:\n{sout}");
}

// ============================================================
// 6) v2 完整性校验：meta.size 与真实数据不符
// ============================================================
#[test]
fn v2_integrity_mismatch_rejected() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let tmp = TempDir::new("cl-cli-integrity");
    let (room, token) = create_room(srv.port);
    let key = key32(&common::random_bytes(32));
    let meta = serde_json::json!({ "v": 2, "type": "file", "name": "trunc.bin",
                                   "mime": null, "size": 100, "count": 2 });
    post_chunk(srv.port, &room, &token, 0, &seal(&key, meta.to_string().as_bytes(), Some(&chunk_aad(&room, 0))));
    post_chunk(srv.port, &room, &token, 1, &seal(&key, &common::random_bytes(10), Some(&chunk_aad(&room, 1))));

    let out = tmp.path().join("trunc-out.bin");
    let (code, txt) = run_cli(&srv.url(), &["recv", &link_of(&srv.url(), &room, &key), "-o", out.to_str().unwrap()]);
    assert_ne!(code, 0, "截断传输必须失败:\n{txt}");
    assert!(txt.contains("完整性校验失败"), "应报完整性校验失败:\n{txt}");
    assert!(!out.exists(), "完整性校验失败不应产出目标文件");
    assert_eq!(room_state(srv.port, &room)["acked"], false, "完整性校验失败不得 ack");
}

// ============================================================
// 7) v1 回退：旧无 AAD 发送端 → 新 CLI 接收端
// ============================================================
#[test]
fn v1_fallback_without_aad() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let tmp = TempDir::new("cl-cli-v1");
    let (room, token) = create_room(srv.port);
    let key = key32(&common::random_bytes(32));
    let data = common::random_bytes(70_000);
    let meta = serde_json::json!({ "v": 1, "type": "file", "name": "legacy-v1.bin",
                                   "mime": null, "size": data.len(), "count": 2 });
    post_chunk(srv.port, &room, &token, 0, &seal(&key, meta.to_string().as_bytes(), None)); // 无 AAD
    post_chunk(srv.port, &room, &token, 1, &seal(&key, &data, None));

    let out = tmp.path().join("legacy-v1-out.bin");
    let (code, txt) = run_cli(&srv.url(), &["recv", &link_of(&srv.url(), &room, &key), "-o", out.to_str().unwrap()]);
    assert_eq!(code, 0, "旧发送端→新接收端应可用:\n{txt}");
    assert_eq!(fs::read(&out).expect("读回 v1 结果"), data, "v1 回退内容不一致");
}

// ============================================================
// 8) v2 AAD 错位：接收端必须拒绝
// ============================================================
#[test]
fn v2_aad_misplaced_rejected() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let tmp = TempDir::new("cl-cli-aad");
    let (room, token) = create_room(srv.port);
    let key = key32(&common::random_bytes(32));
    let meta = serde_json::json!({ "v": 2, "type": "file", "name": "misplaced.bin",
                                   "mime": null, "size": 32, "count": 2 });
    post_chunk(srv.port, &room, &token, 0, &seal(&key, meta.to_string().as_bytes(), Some(&chunk_aad(&room, 0))));
    // 数据分片用了 0 号 AAD 放在 1 号位置
    post_chunk(srv.port, &room, &token, 1, &seal(&key, &common::random_bytes(32), Some(&chunk_aad(&room, 0))));

    // 正控：错位密文用其原始 AAD 可解；用本位置 AAD 必须验签失败
    let packed1 = get_chunk(srv.port, &room, 1, true);
    assert_eq!(
        unseal(&key, &packed1, Some(&chunk_aad(&room, 0))).expect("正控应可解").len(),
        32,
        "正控：错位密文用其原始 AAD 应可解开"
    );
    assert!(
        unseal(&key, &packed1, Some(&chunk_aad(&room, 1))).is_err(),
        "错位密文用本位置 AAD 必须验签失败"
    );
    // 旧实现无 AAD、对位置完全盲：无 AAD 密文任意位置都能解（旧实现静默接受的根因）
    let blind = seal(&key, &common::random_bytes(32), None);
    assert_eq!(unseal(&key, &blind, None).expect("旧格式自洽").len(), 32);

    let out = tmp.path().join("misplaced-out.bin");
    let (code, txt) = run_cli(&srv.url(), &["recv", &link_of(&srv.url(), &room, &key), "-o", out.to_str().unwrap()]);
    assert_ne!(code, 0, "错位分片必须失败:\n{txt}");
    assert!(
        txt.contains("GCM") || txt.contains("验签") || txt.contains("auth"),
        "错位分片应报验签失败:\n{txt}"
    );
    assert_eq!(room_state(srv.port, &room)["acked"], false, "错位分片失败不得 ack");
}

// ============================================================
// 9) 定向模式：devices / listen --yes / --verify / send(+text) --to
// ============================================================
#[test]
fn targeted_mode() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let tmp = TempDir::new("cl-cli-targeted");
    let recv_dir = tmp.path().join("targeted-recv");
    fs::create_dir_all(&recv_dir).expect("建接收目录");
    let (_proxy, mut listener) = start_listener(srv.port, &recv_dir);

    // devices：应列出对端与 32 hex 指纹
    let (dcode, dout) = run_cli(&srv.url(), &["devices"]);
    assert_eq!(dcode, 0, "devices 失败:\n{dout}");
    assert!(dout.contains("测试机B") && dout.contains("127.0.0.2"), "devices 应列出对端:\n{dout}");
    let target_fp = fp_after(&dout, "127.0.0.2");

    // --verify：错误前缀必须拒绝；正确前缀放行
    let (bcode, bout) = run_cli(
        &srv.url(),
        &["send-text", "should-not-send", "--to", "127.0.0.2", "--verify", "deadbeef"],
    );
    assert_ne!(bcode, 0, "错误 --verify 应拒绝发送:\n{bout}");
    assert!(bout.contains("指纹不符"), "应提示目标指纹不符:\n{bout}");

    let vpayload = format!("指纹校验后直发 {}", now_millis());
    let (vcode, vout) = run_cli(
        &srv.url(),
        &["send-text", &vpayload, "--to", "127.0.0.2", "--verify", &target_fp[..16]],
    );
    assert_eq!(vcode, 0, "正确 --verify 应放行:\n{vout}");
    assert!(vout.contains("指纹核对通过"), "应显示指纹核对通过:\n{vout}");
    listener.wait_for_output(&vpayload, Duration::from_secs(20));

    // 定向文本
    let payload = format!("定向直发自动化验证:CLI send-text --to {}", now_millis());
    let (code, out) = run_cli(&srv.url(), &["send-text", &payload, "--to", "127.0.0.2", "--name", "测试机A"]);
    assert_eq!(code, 0, "定向 send-text 失败:\n{out}");
    assert!(out.contains("已完整接收"), "发送方应确认完整接收:\n{out}");
    listener.wait_for_output(&payload, Duration::from_secs(20));

    // 定向文件
    let fdata = common::random_bytes(1536 * 1024 + 99);
    let tsrc = tmp.path().join("targeted-src.bin");
    fs::write(&tsrc, &fdata).expect("写定向源文件");
    let (fcode, fout) = run_cli(&srv.url(), &["send", tsrc.to_str().unwrap(), "--to", "127.0.0.2", "--name", "测试机A"]);
    assert_eq!(fcode, 0, "定向 send 失败:\n{fout}");
    let saved = recv_dir.join("targeted-src.bin");
    wait_until(Duration::from_secs(20), "定向文件落盘", || saved.exists());
    wait_until(Duration::from_secs(20), "定向文件写完", || {
        fs::metadata(&saved).map(|m| m.len() == fdata.len() as u64).unwrap_or(false)
    });
    assert_eq!(fs::read(&saved).expect("读回定向文件"), fdata, "定向文件应逐字节落盘");
    listener.kill();
}

// ============================================================
// 10) 独立实现互操作：外部构造 KDF/hint/v2 分片/ackProof → Rust CLI 解密并 ack
// ============================================================
#[test]
fn cross_impl_independent_sender() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let tmp = TempDir::new("cl-cli-cross");
    let recv_dir = tmp.path().join("cross-recv");
    fs::create_dir_all(&recv_dir).expect("建接收目录");
    let (_proxy, mut listener) = start_listener(srv.port, &recv_dir);

    // 取 Rust listener 公钥
    let rust_pub = {
        let devs = devices_json(srv.port);
        let dev = devs["devices"]
            .as_array()
            .and_then(|a| a.iter().find(|d| d["ip"].as_str() == Some("127.0.0.2")))
            .cloned()
            .expect("Rust listener 应在线");
        key32(&common::from_b64u(dev["pub"].as_str().expect("pub")))
    };
    let want_fp = fp_hex(&rust_pub);
    let (dcode, dout) = run_cli(&srv.url(), &["devices"]);
    assert_eq!(dcode, 0, "devices 失败:\n{dout}");
    assert!(
        dout[dout.find("127.0.0.2").expect("devices 应含 listener")..].contains(&format!("#{want_fp}")),
        "Rust 指纹应与独立 SHA256(pub) 前 16B 一致:\n{dout}"
    );

    // 独立身份 + 房间密钥（KDF 逐字节）
    let seed = key32(&common::random_bytes(32));
    let my_pub = x_pub(&seed);
    let (room, token) = create_room(srv.port);
    let shared = dh(&seed, &rust_pub);
    let key = room_key(&shared, &my_pub, &rust_pub, &room);

    // 邀请（hint 无 AAD，AES-GCM）
    let payload = format!("外部实现→Rust CLI 直发 {}", now_millis());
    let pt = payload.as_bytes();
    let preview = serde_json::json!({ "kind": "text", "size": pt.len() });
    let hint = common::b64u(&seal(&key, preview.to_string().as_bytes(), None));
    post_offer(srv.port, &room, &token, "127.0.0.2", &common::b64u(&my_pub), &hint);

    // v2 meta + 数据分片（AAD 位置绑定）
    let meta = serde_json::json!({ "v": 2, "type": "text", "name": null, "mime": null,
                                   "size": pt.len(), "count": 2 });
    post_chunk(srv.port, &room, &token, 0, &seal(&key, meta.to_string().as_bytes(), Some(&chunk_aad(&room, 0))));
    post_chunk(srv.port, &room, &token, 1, &seal(&key, pt, Some(&chunk_aad(&room, 1))));

    // Rust CLI 必须解密展示文本、打印发送方指纹、并 ack
    listener.wait_for_output(&payload, Duration::from_secs(30));
    listener.wait_for_output(&format!("#{}", fp_hex(&my_pub)), Duration::from_secs(10));
    wait_until(Duration::from_secs(30), "Rust CLI 应 ack", || {
        room_state(srv.port, &room)["acked"].as_bool() == Some(true)
    });
    let st = room_state(srv.port, &room);
    assert_eq!(
        st["ackProof"].as_str(),
        Some(ack_proof_hex(&key, &room).as_str()),
        "Rust ackProof 必须与独立 SHA256(key‖label‖room) 一致"
    );
    listener.kill();
}

// ============================================================
// 11) 终端注入净化：设备名 / 文件名中的 ANSI/BEL
// ============================================================
#[test]
fn terminal_injection_sanitized() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let tmp = TempDir::new("cl-cli-clean");

    // 11a) 设备名（服务端注册 + CLI devices 展示，双重净化）
    let pubkey = x_pub(&key32(&common::random_bytes(32)));
    let evil_name = "evil\u{1b}[31mPWNED\u{1b}[0m\u{7}name";
    register_presence(srv.port, evil_name, &pubkey);
    let (dcode, dout) = run_cli(&srv.url(), &["devices"]);
    assert_eq!(dcode, 0, "devices 失败:\n{dout}");
    assert!(
        !dout.contains("\u{1b}[31m") && !dout.contains('\u{7}'),
        "设备名中的控制字符未被过滤: {dout:?}"
    );

    // 11b) 文件名（明文入 meta）→ CLI 接收端 clean() 必须剥掉 ANSI/BEL
    let (room, token) = create_room(srv.port);
    let key = key32(&common::random_bytes(32));
    let evil_file = "evil\u{1b}[31mPWNED\u{1b}[0m\u{7}.txt";
    let data = b"AAAA";
    let meta = serde_json::json!({ "v": 2, "type": "batch",
                                   "files": [{ "name": evil_file, "size": data.len(), "count": 1 }],
                                   "count": 2, "size": data.len() });
    post_chunk(srv.port, &room, &token, 0, &seal(&key, meta.to_string().as_bytes(), Some(&chunk_aad(&room, 0))));
    post_chunk(srv.port, &room, &token, 1, &seal(&key, data, Some(&chunk_aad(&room, 1))));

    let dir = tmp.path().join("clean-recv");
    let (code, txt) = run_cli(&srv.url(), &["recv", &link_of(&srv.url(), &room, &key), "-o", dir.to_str().unwrap()]);
    assert_eq!(code, 0, "recv 失败:\n{txt}");
    assert!(!txt.contains('\u{1b}'), "CLI 输出不应含 ESC: {txt:?}");
    assert!(!txt.contains('\u{7}'), "CLI 输出不应含 BEL: {txt:?}");
    assert!(txt.contains("evilPWNED"), "净化后应保留可见文本: {txt:?}");
}

// ============================================================
// 12) --version / -V：版本号来自 Cargo.toml（装完包确认跑的是哪一版）
// ============================================================
#[test]
fn version_flag() {
    let expect = format!("cipherlane-cli {}", env!("CARGO_PKG_VERSION"));
    for flag in ["--version", "-V"] {
        let out = Command::new(common::cli_bin()).arg(flag).output().expect("运行 --version");
        assert!(out.status.success(), "{flag} 应成功退出");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), expect, "{flag} 的输出");
        assert!(out.stderr.is_empty(), "{flag} 不该往 stderr 写东西");
    }
    let help = run_cli("http://127.0.0.1:1", &["--help"]).1;
    assert!(help.contains(&format!("v{}", env!("CARGO_PKG_VERSION"))), "--help 的标题行也应带真实版本号：{help}");
}

