//! v1.0 协议层集成测试（纯 Rust）：只对 Rust 服务器二进制跑真实 HTTP 全链路。
//!
//! 移植自旧 test/protocol.test.mjs 的 26 组断言（零 Node）：
//!   group 1  设备注册 / 同 IP 轮换 / 旧 secret 失效 401 / 重注册
//!   group 2  在线设备列表（名称 / 公钥 / IP）
//!   group 3  定向邀请：建房 → X25519 双侧派生一致 → 长轮询唤醒 → hint 预览解密
//!   group 4  定向传输全链路：接受 → 3MiB+ 密文分片 → 逐字节一致 → ack
//!   group 5  拒绝路径：state 可见 rejected，重复处理 410
//!   group 6  邀请约束：分片后 409 / 目标离线 404 / 非法公钥 400 / 错 token 403
//!   group 7  单设备待处理邀请上限 8 → 第 9 个 429
//!   group 8  链接模式回归：随机密钥分片收发逐字节一致
//!   group 9  X-Chunk-Seq 幂等（无头 / duplicate / 跳号 / 非法 / 429 后同 seq 重投）
//!   group 10 并发拉取同一分片：先到 200 / 后来者 409 / 再来者 410 / 发送方 200
//!   group 11 ack 密钥凭证：构造一致 / state 透出 / 无凭证与非法凭证为 null
//!   group 12 默认绑定面：仅回环 / RFC1918（HOST=""）
//!   group 13 长轮询并发上限：第 9 个 429 / 断开释放后可再挂
//!   group 14 可续传模式：只读回放 / progress 释放·单调·越界 / 经典模式不受影响
//!   group 15 静态资源：JS 200+ETag/no-cache → 304；HTML 仍 no-store
//!   group 16 413 可达：>1.5MiB 分片回 413 JSON（非 ECONNRESET），服务继续可用
//!   group 17 请求边界：缺/空 ?i→400；越序 GET 不产生不可达分片；DEPTH=3 并发预取
//!   group 18 竞态：慢速 chunk POST 期间房间被 DELETE → 410 gone（不写已销毁房间）
//!   group 19 Host/Origin 闸门：域名 Host 403 / IP Host 200 / 跨站 Origin 403 / 同源放行
//!   group 20 /api/update：并发/缓存只请求上游一次、semver newer 正确、旧版本不误报
//!   group 21 per-IP 配额：4 房 429 ip-quota / 2MB backpressure / destroy·take·advance 释放 / 非法 URL 400
//!   group 22 建房限流：60s 内第 121 次建房 → 429 ip-quota（滑动窗口，retry 有值）
//!   group 23 设备名净化：ESC/NUL/换行/C1 被剔除，/api/devices 返回干净名称
//!   group 24 面板端点：version / shutdown 令牌双闸 403 / update source / panel 页可达
//!   group 25 adopt：回环接管 200 / 短令牌 400 / 二次接管 409 / shutdown 空令牌 403
//!   group 26 SIGTERM 优雅停机：退出码 0 +「优雅停机」
mod common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use common::HttpResponse;

type Key32 = [u8; 32];

fn ok(name: &str) {
    println!("  ✓ {name}");
}

// ==================== 基础 HTTP ====================

fn req(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: Option<&[u8]>,
) -> HttpResponse {
    let hs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
    common::http(port, method, path, &hs, body)
        .unwrap_or_else(|e| panic!("{method} {path} 请求失败: {e}"))
}

fn get(port: u16, path: &str) -> HttpResponse {
    req(port, "GET", path, &[], None)
}

fn get_h(port: u16, path: &str, headers: &[(&str, String)]) -> HttpResponse {
    req(port, "GET", path, headers, None)
}

fn post(port: u16, path: &str, headers: &[(&str, String)], body: Option<&[u8]>) -> HttpResponse {
    req(port, "POST", path, headers, body)
}

fn post_json(port: u16, path: &str, headers: &[(&str, String)], value: &Value) -> HttpResponse {
    let body = value.to_string();
    let mut hs: Vec<(&str, String)> = headers.to_vec();
    hs.push(("Content-Type", "application/json".into()));
    req(port, "POST", path, &hs, Some(body.as_bytes()))
}

fn assert_status(r: &HttpResponse, want: u16, what: &str) {
    assert_eq!(r.status, want, "{what}: status={} body={}", r.status, r.text());
}

// ==================== 房间 / 设备 便捷封装 ====================

struct Room {
    id: String,
    token: String,
}

fn create_room(port: u16) -> Room {
    let r = post(port, "/api/rooms", &[], None);
    assert_status(&r, 200, "建房");
    let j = r.json();
    Room {
        id: j["room"].as_str().expect("room").to_string(),
        token: j["token"].as_str().expect("token").to_string(),
    }
}

fn room_state(port: u16, room: &Room) -> Value {
    get(port, &format!("/api/rooms/{}/state", room.id)).json()
}

fn token_hdr(room: &Room) -> Vec<(&'static str, String)> {
    vec![("X-Room-Token", room.token.clone())]
}

fn post_chunk(port: u16, room: &Room, body: &[u8]) -> HttpResponse {
    post(port, &format!("/api/rooms/{}/chunk", room.id), &token_hdr(room), Some(body))
}

fn post_chunk_seq(port: u16, room: &Room, seq: Option<&str>, body: &[u8]) -> HttpResponse {
    let mut hs = token_hdr(room);
    if let Some(s) = seq {
        hs.push(("X-Chunk-Seq", s.to_string()));
    }
    post(port, &format!("/api/rooms/{}/chunk", room.id), &hs, Some(body))
}

fn post_done(port: u16, room: &Room) -> HttpResponse {
    post(port, &format!("/api/rooms/{}/done", room.id), &token_hdr(room), None)
}

fn post_ack(port: u16, room: &Room, proof: Option<&str>) -> HttpResponse {
    match proof {
        Some(p) => post_json(
            port,
            &format!("/api/rooms/{}/ack", room.id),
            &[],
            &json!({ "proof": p }),
        ),
        None => post(port, &format!("/api/rooms/{}/ack", room.id), &[], None),
    }
}

fn delete_room(port: u16, room: &Room) -> HttpResponse {
    req(
        port,
        "DELETE",
        &format!("/api/rooms/{}", room.id),
        &token_hdr(room),
        None,
    )
}

struct Identity {
    sk: Key32,
    pk: Key32,
}

struct Device {
    name: String,
    sk: Key32,
    pk: Key32,
    secret: String,
    ip: String,
}

fn gen_identity() -> Identity {
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&common::random_bytes(32));
    let pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();
    Identity { sk, pk }
}

fn presence(port: u16, name: &str, identity: &Identity, secret: Option<&str>) -> Value {
    let body = json!({ "name": name, "pub": common::b64u(&identity.pk) });
    let mut hs: Vec<(&str, String)> = Vec::new();
    if let Some(s) = secret {
        hs.push(("X-Device-Secret", s.to_string()));
    }
    let r = post_json(port, "/api/presence", &hs, &body);
    assert_status(&r, 200, "设备注册");
    r.json()
}

fn register(port: u16, name: &str) -> Device {
    let identity = gen_identity();
    let j = presence(port, name, &identity, None);
    Device {
        name: name.to_string(),
        sk: identity.sk,
        pk: identity.pk,
        secret: j["secret"].as_str().expect("secret").to_string(),
        ip: j["ip"].as_str().expect("ip").to_string(),
    }
}

// ==================== 密码学（与 public/x25519.js / app.js 逐字节一致） ====================

fn session_key(shared: &Key32, sender_pub: &Key32, receiver_pub: &Key32, room: &str) -> Key32 {
    // public/x25519.js：SHA256(shared ‖ senderPub ‖ receiverPub ‖ "cipherlane/device/v1\0"+room)
    let mut h = Sha256::new();
    h.update(shared);
    h.update(sender_pub);
    h.update(receiver_pub);
    h.update(format!("cipherlane/device/v1\u{0}{room}").as_bytes());
    h.finalize().into()
}

fn dh(sk: &Key32, their_pk: &Key32) -> Key32 {
    StaticSecret::from(*sk)
        .diffie_hellman(&PublicKey::from(*their_pk))
        .to_bytes()
}

fn seal(key: &Key32, plaintext: &[u8]) -> Vec<u8> {
    // 与浏览器一致：IV(12) ‖ 密文 ‖ TAG(16)（aes-gcm crate 的 encrypt 输出已含 tag）
    let cipher = Aes256Gcm::new_from_slice(key).expect("AES key");
    let iv = common::random_bytes(12);
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext)
        .expect("AES-GCM 加密失败");
    let mut out = iv;
    out.extend_from_slice(&ct);
    out
}

fn unseal(key: &Key32, packed: &[u8]) -> Vec<u8> {
    assert!(packed.len() >= 28, "密文过短: {}", packed.len());
    let cipher = Aes256Gcm::new_from_slice(key).expect("AES key");
    cipher
        .decrypt(Nonce::from_slice(&packed[..12]), &packed[12..])
        .unwrap_or_else(|_| panic!("AES-GCM 解密失败"))
}

fn ack_proof(key: &Key32, room: &str) -> String {
    let mut h = Sha256::new();
    h.update(key);
    h.update(format!("cipherlane/ack/v1|{room}").as_bytes());
    common::hex(&h.finalize())
}

// ==================== 计数用更新上游 ====================

struct Upstream {
    port: u16,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Upstream {
    fn start() -> Upstream {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind 更新上游");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let h2 = Arc::clone(&hits);
        let s2 = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !s2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        h2.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut buf = Vec::new();
                        let mut tmp = [0u8; 1024];
                        loop {
                            match stream.read(&mut tmp) {
                                Ok(0) => break,
                                Ok(n) => {
                                    buf.extend_from_slice(&tmp[..n]);
                                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        let head = String::from_utf8_lossy(&buf).to_string();
                        let path = head
                            .lines()
                            .next()
                            .unwrap_or("")
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("/")
                            .to_string();
                        let body = if path.contains("/old") { "0.0.1\n" } else { "9.9.9\n" };
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Upstream { port, hits, stop, handle: Some(handle) }
    }
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ==================== 长轮询 / 慢速请求原始 socket ====================

fn parked_stream(port: u16, path: &str, timeout_ms: u64) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .expect("read timeout");
    let head = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    s.write_all(head.as_bytes()).expect("write long-poll");
    s
}

/// 断言请求被挂起（到超时仍无响应字节）。
fn expect_parked(port: u16, path: &str) {
    let mut s = parked_stream(port, path, 1200);
    let mut b = [0u8; 1];
    match s.read(&mut b) {
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) => {}
        Ok(0) => panic!("长轮询连接被关闭（未挂起）"),
        Ok(_) => panic!("长轮询未挂起，收到响应"),
        Err(e) => panic!("长轮询读取错误: {e}"),
    }
    let _ = s.shutdown(Shutdown::Both);
}

fn parse_http(raw: &[u8]) -> (u16, Vec<u8>) {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let body = if split <= raw.len() { raw[split..].to_vec() } else { Vec::new() };
    (status, body)
}

// ==================== group 1-11, 14：主链路 ====================

#[test]
fn g01_11_14_core_flow() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let p = srv.port;

    // ---- group 1) 设备注册 / 同 IP 轮换 / 旧 secret 失效 401 / 重注册 ----
    let mut rx = register(p, "接收端-测试机");
    assert_eq!(rx.ip, "127.0.0.1");
    let tx = register(p, "发送端-测试机");
    assert_ne!(tx.secret, rx.secret, "同 IP 后注册应轮换 secret");

    let r = get_h(p, "/api/offers", &[("X-Device-Secret", rx.secret.clone())]);
    assert_status(&r, 401, "旧 secret 应失效");
    // 用同一密钥对重新注册拿新 secret
    let rx_id = Identity { sk: rx.sk, pk: rx.pk };
    let j = presence(p, &rx.name, &rx_id, None);
    assert_eq!(j["ip"], "127.0.0.1");
    rx.secret = j["secret"].as_str().expect("secret").to_string();
    ok("设备注册 / 同 IP 轮换 / 旧 secret 失效 401 / 重注册");

    // ---- group 2) 设备列表 ----
    let j = get(p, "/api/devices").json();
    let devs = j["devices"].as_array().expect("devices");
    assert_eq!(devs.len(), 1);
    assert_eq!(devs[0]["name"].as_str(), Some(rx.name.as_str()));
    assert_eq!(devs[0]["pub"].as_str(), Some(common::b64u(&rx.pk).as_str()));
    assert_eq!(devs[0]["ip"].as_str(), Some("127.0.0.1"));
    ok("在线设备列表（名称 / 公钥 / IP）");

    // ---- group 3) 定向邀请 + hint 预览 ----
    let file_data = common::random_bytes(3 * 1024 * 1024 + 12345);
    const CHUNK: usize = 1024 * 1024;
    let room = create_room(p);

    let shared_s = dh(&tx.sk, &rx.pk);
    let key_s = session_key(&shared_s, &tx.pk, &rx.pk, &room.id);
    let shared_r = dh(&rx.sk, &tx.pk);
    let key_r = session_key(&shared_r, &tx.pk, &rx.pk, &room.id);
    assert_eq!(key_s, key_r, "两侧房间密钥不一致");
    assert_ne!(key_s, shared_s, "房间密钥应为 KDF 输出");

    let hint = common::b64u(&seal(
        &key_s,
        json!({"kind": "file", "name": "机密文件.bin", "size": file_data.len()})
            .to_string()
            .as_bytes(),
    ));

    // 长轮询先行挂起，验证邀请到达即被唤醒
    let poll_secret = rx.secret.clone();
    let poller = thread::spawn(move || {
        let hs: Vec<(&str, &str)> = vec![("X-Device-Secret", poll_secret.as_str())];
        common::http(p, "GET", "/api/offers", &hs, None).expect("offers 长轮询")
    });
    thread::sleep(Duration::from_millis(250));

    let r = post_json(
        p,
        &format!("/api/rooms/{}/offer", room.id),
        &token_hdr(&room),
        &json!({ "to": "127.0.0.1", "pub": common::b64u(&tx.pk), "hint": hint }),
    );
    assert_status(&r, 200, "投递邀请");
    let offer_id = r.json()["offer"].as_str().expect("offer id").to_string();

    let polled = poller.join().expect("offers 线程").json();
    let offers = polled["offers"].as_array().expect("offers");
    assert_eq!(offers.len(), 1);
    let o = &offers[0];
    assert_eq!(o["id"].as_str(), Some(offer_id.as_str()));
    assert_eq!(o["room"].as_str(), Some(room.id.as_str()));
    assert_eq!(o["pub"].as_str(), Some(common::b64u(&tx.pk).as_str()));
    assert_eq!(o["from"]["name"].as_str(), Some(rx.name.as_str()));
    let preview: Value =
        serde_json::from_slice(&unseal(&key_r, &common::from_b64u(o["hint"].as_str().unwrap())))
            .expect("预览 JSON");
    assert_eq!(preview["name"].as_str(), Some("机密文件.bin"));
    assert_eq!(preview["size"].as_u64(), Some(file_data.len() as u64));
    ok("定向邀请：建房 → X25519 双侧派生一致 → 长轮询唤醒 → hint 预览解密");

    // ---- group 4) 接受 + 传输全链路 ----
    let r = post(p, &format!("/api/offers/{offer_id}/accept"), &[("X-Device-Secret", rx.secret.clone())], None);
    assert_status(&r, 200, "接受邀请");
    let mut accepted = false;
    for _ in 0..40 {
        if room_state(p, &room)["offer"].as_str() == Some("accepted") {
            accepted = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(accepted, "state 应可见 accepted");

    let count = 1 + file_data.chunks(CHUNK).count();
    let meta = json!({
        "v": 1, "type": "file", "name": "机密文件.bin", "mime": null,
        "size": file_data.len(), "count": count
    });
    post_chunk(p, &room, &seal(&key_s, meta.to_string().as_bytes()));
    for chunk in file_data.chunks(CHUNK) {
        let r = post_chunk(p, &room, &seal(&key_s, chunk));
        assert_status(&r, 200, "投递数据分片");
    }
    post_done(p, &room);

    let mut got = Vec::new();
    for i in 0..count {
        let rr = get(p, &format!("/api/rooms/{}/chunk?i={i}", room.id));
        assert_status(&rr, 200, &format!("chunk {i}"));
        let pt = unseal(&key_r, &rr.body);
        if i > 0 {
            got.extend_from_slice(&pt);
        }
    }
    assert_eq!(got, file_data, "接收内容与原文逐字节一致");
    post_ack(p, &room, None);
    thread::sleep(Duration::from_millis(50));
    assert_eq!(room_state(p, &room)["acked"].as_bool(), Some(true));
    ok("定向传输全链路：接受 → 3MiB+ 密文分片 → 逐字节一致 → ack");

    // ---- group 5) 拒绝路径 ----
    let room2 = create_room(p);
    let key2 = session_key(&dh(&tx.sk, &rx.pk), &tx.pk, &rx.pk, &room2.id);
    let hint2 = common::b64u(&seal(&key2, b"{}"));
    let r = post_json(
        p,
        &format!("/api/rooms/{}/offer", room2.id),
        &token_hdr(&room2),
        &json!({ "to": "127.0.0.1", "pub": common::b64u(&tx.pk), "hint": hint2 }),
    );
    assert_status(&r, 200, "投递邀请 2");
    let offer2 = r.json()["offer"].as_str().expect("offer2").to_string();
    let r = post(p, &format!("/api/offers/{offer2}/reject"), &[("X-Device-Secret", rx.secret.clone())], None);
    assert_status(&r, 200, "拒绝邀请");
    assert_eq!(room_state(p, &room2)["offer"].as_str(), Some("rejected"));
    let r = post(p, &format!("/api/offers/{offer2}/accept"), &[("X-Device-Secret", rx.secret.clone())], None);
    assert_status(&r, 410, "已处理邀请不可重复处理");
    ok("拒绝路径：state 可见 rejected，重复处理返回 410");

    // ---- group 6) 邀请约束 ----
    let room3 = create_room(p);
    post_chunk(p, &room3, b"x");
    let r = post_json(
        p,
        &format!("/api/rooms/{}/offer", room3.id),
        &token_hdr(&room3),
        &json!({ "to": "127.0.0.1", "pub": common::b64u(&tx.pk), "hint": hint2 }),
    );
    assert_status(&r, 409, "分片后挂邀请应 409");

    let room4 = create_room(p);
    let mk_offer = |to: &str, pub_: &str, tok: &str| {
        post_json(
            p,
            &format!("/api/rooms/{}/offer", room4.id),
            &[("X-Room-Token", tok.to_string())],
            &json!({ "to": to, "pub": pub_, "hint": hint2 }),
        )
    };
    assert_status(&mk_offer("10.255.255.1", &common::b64u(&tx.pk), &room4.token), 404, "目标离线");
    assert_status(&mk_offer("127.0.0.1", "not-a-pub!!", &room4.token), 400, "非法公钥");
    assert_status(&mk_offer("127.0.0.1", &common::b64u(&tx.pk), "deadbeef"), 403, "错 token");
    assert_status(&delete_room(p, &room4), 200, "删除 room4");
    ok("邀请约束：分片后 409 / 目标离线 404 / 非法公钥 400 / 错 token 403");

    // ---- group 7) 邀请上限 ----
    let mut token_list = Vec::new();
    for _ in 0..8 {
        let rr = create_room(p);
        let hint = common::b64u(&common::random_bytes(32));
        let r = post_json(
            p,
            &format!("/api/rooms/{}/offer", rr.id),
            &token_hdr(&rr),
            &json!({ "to": "127.0.0.1", "pub": common::b64u(&tx.pk), "hint": hint }),
        );
        assert_status(&r, 200, "前 8 个邀请应成功");
        token_list.push(rr);
    }
    let ninth = create_room(p);
    let r = post_json(
        p,
        &format!("/api/rooms/{}/offer", ninth.id),
        &token_hdr(&ninth),
        &json!({ "to": "127.0.0.1", "pub": common::b64u(&tx.pk), "hint": hint2 }),
    );
    assert_status(&r, 429, "第 9 个邀请应 429");
    token_list.push(ninth);
    for rr in &token_list {
        assert_status(&delete_room(p, rr), 200, "清理邀请房间");
    }
    ok("单设备待处理邀请上限 8 → 第 9 个 429");

    // ---- group 8) 链接模式 ----
    let link_key: Key32 = common::random_bytes(32).try_into().unwrap();
    let payload = "cipherlane link-mode regression 🚀".as_bytes().to_vec();
    let lr = create_room(p);
    post_chunk(p, &lr, &seal(&link_key, b"{\"v\":1,\"type\":\"text\"}"));
    post_chunk(p, &lr, &seal(&link_key, &payload));
    post_done(p, &lr);
    let m0: Value =
        serde_json::from_slice(&unseal(&link_key, &get(p, &format!("/api/rooms/{}/chunk?i=0", lr.id)).body))
            .expect("meta");
    assert_eq!(m0["type"].as_str(), Some("text"));
    let p1 = unseal(&link_key, &get(p, &format!("/api/rooms/{}/chunk?i=1", lr.id)).body);
    assert_eq!(p1, payload);
    post_ack(p, &lr, None);
    ok("链接模式回归：随机密钥分片收发逐字节一致");

    // ---- group 9) X-Chunk-Seq 幂等 ----
    let ir = create_room(p);
    let r = post_chunk_seq(p, &ir, None, b"legacy-no-seq");
    assert_status(&r, 200, "无头旧语义");
    assert_eq!(r.json()["index"].as_u64(), Some(0));
    assert_eq!(room_state(p, &ir)["posted"].as_u64(), Some(1));

    let r = post_chunk_seq(p, &ir, Some("1"), b"seq-one");
    assert_status(&r, 200, "seq=1 正常入库");
    assert_eq!(r.json()["index"].as_u64(), Some(1));
    let r = post_chunk_seq(p, &ir, Some("1"), b"seq-one");
    assert_status(&r, 200, "重复 seq 应 200");
    assert_eq!(r.json()["duplicate"].as_bool(), Some(true));
    assert_eq!(r.json()["index"].as_u64(), Some(1));
    assert_eq!(room_state(p, &ir)["posted"].as_u64(), Some(2), "重复包不应推进 posted");
    let r = post_chunk_seq(p, &ir, Some("0"), b"legacy-no-seq");
    assert_eq!(r.json()["duplicate"].as_bool(), Some(true));
    assert_eq!(room_state(p, &ir)["posted"].as_u64(), Some(2));

    let oor = create_room(p);
    let r = post_chunk_seq(p, &oor, Some("1"), b"skip-zero");
    assert_status(&r, 409, "跳号应 409");
    assert_eq!(r.json()["error"].as_str(), Some("out-of-order"));
    assert_eq!(r.json()["posted"].as_u64(), Some(0));
    assert_eq!(room_state(p, &oor)["posted"].as_u64(), Some(0));

    for bad in ["x", "-1", "1.5", "1e2", "9007199254740993"] {
        let r = post_chunk_seq(p, &oor, Some(bad), b"bad");
        assert_status(&r, 400, &format!("非法 seq {bad} 应 400"));
        assert_eq!(r.json()["error"].as_str(), Some("bad-seq"));
    }

    let br = create_room(p);
    for i in 0..64 {
        let r = post_chunk_seq(p, &br, Some(&i.to_string()), format!("c{i}").as_bytes());
        assert_status(&r, 200, &format!("第 {i} 片应入库"));
    }
    let r = post_chunk_seq(p, &br, Some("64"), b"c64");
    assert_status(&r, 429, "背压窗口满应 429");
    assert_eq!(room_state(p, &br)["posted"].as_u64(), Some(64), "429 不得推进 posted");
    assert_status(&get(p, &format!("/api/rooms/{}/chunk?i=0", br.id)), 200, "消费一片");
    let r = post_chunk_seq(p, &br, Some("64"), b"c64");
    assert_status(&r, 200, "消费后同 seq 重投应成功");
    assert_eq!(r.json()["index"].as_u64(), Some(64));
    let r = post_chunk_seq(p, &br, Some("64"), b"c64");
    assert_eq!(r.json()["duplicate"].as_bool(), Some(true));
    assert_eq!(room_state(p, &br)["posted"].as_u64(), Some(65));
    ok("幂等重投：无头旧语义 / duplicate 零记账 / 跳号 409 / 非法 400 / 429 后同 seq 重投成功");

    // ---- group 10) 并发拉取同一分片 ----
    let cr = create_room(p);
    let port = p;
    let path = format!("/api/rooms/{}/chunk?i=0", cr.id);
    let path2 = path.clone();
    let g1 = thread::spawn(move || common::http(port, "GET", &path, &[], None));
    let g2 = thread::spawn(move || common::http(port, "GET", &path2, &[], None));
    thread::sleep(Duration::from_millis(300));
    let r = post_chunk(p, &cr, b"concurrent-pull");
    assert_status(&r, 200, "发送方 POST 不应被并发拉取拖垮");
    let r1 = g1.join().expect("g1").expect("g1 http");
    let r2 = g2.join().expect("g2").expect("g2 http");
    let mut statuses = [r1.status, r2.status];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 409], "一者 200 一者 409");
    let winner = if r1.status == 200 { r1 } else { r2 };
    assert_eq!(winner.text(), "concurrent-pull");
    assert_status(&get(p, &format!("/api/rooms/{}/chunk?i=0", cr.id)), 410, "已消费分片再取应 410");
    assert_status(&delete_room(p, &cr), 200, "删除 cr");
    ok("并发拉取同一分片：先到 200 / 后来者 409 / 再来者 410 / 发送方 200");

    // ---- group 11) ack 凭证 ----
    let akey: Key32 = common::random_bytes(32).try_into().unwrap();
    let ar = create_room(p);
    let proof = ack_proof(&akey, &ar.id);
    post_ack(p, &ar, Some(&proof));
    assert_eq!(room_state(p, &ar)["ackProof"].as_str(), Some(proof.as_str()));
    let ar2 = create_room(p);
    post_ack(p, &ar2, None);
    assert_eq!(room_state(p, &ar2)["ackProof"], Value::Null);
    let ar3 = create_room(p);
    post_ack(p, &ar3, Some("zzz-not-hex"));
    assert_eq!(room_state(p, &ar3)["ackProof"], Value::Null);
    ok("ack 密钥凭证：双侧构造一致 / state 透出 / 无凭证与非法凭证为 null");

    // ---- group 14) 可续传模式 ----
    let pr = create_room(p);
    for body in ["meta", "c1", "c2"] {
        assert_status(&post_chunk(p, &pr, body.as_bytes()), 200, "resume 预置分片");
    }
    let g1 = get_h(p, &format!("/api/rooms/{}/chunk?i=1", pr.id), &[("X-Resume", "1".into())]);
    let g1b = get_h(p, &format!("/api/rooms/{}/chunk?i=1", pr.id), &[("X-Resume", "1".into())]);
    assert_status(&g1, 200, "只读回放 200");
    assert_status(&g1b, 200, "只读回放 200");
    assert_eq!(g1.body, g1b.body, "只读回放应返回同一份");
    assert_eq!(room_state(p, &pr)["resumable"].as_bool(), Some(true));
    let r = post_json(p, &format!("/api/rooms/{}/progress", pr.id), &[], &json!({ "through": 2 }));
    assert_status(&r, 200, "progress 释放");
    assert_status(
        &get_h(p, &format!("/api/rooms/{}/chunk?i=1", pr.id), &[("X-Resume", "1".into())]),
        410,
        "已确认落盘分片应被释放",
    );
    let r = post_json(p, &format!("/api/rooms/{}/progress", pr.id), &[], &json!({ "through": 1 }));
    assert_status(&r, 200, "滞后上报幂等");
    assert_eq!(room_state(p, &pr)["through"].as_u64(), Some(2), "进度单调不回退");
    let r = post_json(p, &format!("/api/rooms/{}/progress", pr.id), &[], &json!({ "through": 999 }));
    assert_status(&r, 400, "越界拒绝");
    // 经典兼容：取走即焚
    let cr = create_room(p);
    post_chunk(p, &cr, b"x");
    let c1 = get(p, &format!("/api/rooms/{}/chunk?i=0", cr.id));
    let c2 = get(p, &format!("/api/rooms/{}/chunk?i=0", cr.id));
    assert!(c1.status == 200 && c2.status == 410, "经典模式应取走即焚({}/{})", c1.status, c2.status);
    ok("可续传模式：只读回放 / progress 释放·单调·越界 / 经典模式不受影响");
}

// ==================== group 12) 默认绑定面 ====================

fn is_trusted_lan(ip: &str) -> bool {
    if ip == "127.0.0.1" {
        return true;
    }
    if ip.starts_with("10.") || ip.starts_with("192.168.") {
        return true;
    }
    if let Some(rest) = ip.strip_prefix("172.") {
        if let Some(second) = rest.split('.').next().and_then(|s| s.parse::<u8>().ok()) {
            return (16..=31).contains(&second);
        }
    }
    false
}

#[test]
fn g12_default_binding() {
    let _g = common::serial();
    // HOST="" = 自动绑定回环 + RFC1918 网卡
    let srv = common::spawn_server(&[("HOST", "")]);
    thread::sleep(Duration::from_millis(400));
    let out = srv.stdout();
    let mut shown = Vec::new();
    for line in out.lines() {
        if let Some(idx) = line.find("http://") {
            let rest = &line[idx + "http://".len()..];
            let ip: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if !ip.is_empty() {
                shown.push(ip);
            }
        }
    }
    assert!(!shown.is_empty(), "横幅未列出任何地址:\n{out}");
    for ip in &shown {
        assert!(is_trusted_lan(ip), "默认绑定面出现非信任网段地址: {ip}\n{out}");
    }
    ok(&format!("默认绑定面仅回环/RFC1918（横幅 {}）", shown.join(", ")));
}

// ==================== group 13) 长轮询并发上限 ====================

#[test]
fn g13_longpoll_cap() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let p = srv.port;
    let room = create_room(p);
    let path = format!("/api/rooms/{}/chunk?i=0", room.id);

    let mut parked = Vec::new();
    for _ in 0..8 {
        parked.push(parked_stream(p, &path, 30_000));
    }
    thread::sleep(Duration::from_millis(300));
    let ninth = get(p, &path);
    assert_status(&ninth, 429, "第 9 个并发长轮询应 429");
    for s in parked {
        let _ = s.shutdown(Shutdown::Both);
    }
    // 客户端断连由服务端按 ALIVE_SLICE（1s）周期检测：留足一个周期以上再验证配额已释放
    thread::sleep(Duration::from_millis(1500));
    expect_parked(p, &path); // 释放后应允许新的长轮询挂起
    assert_status(&delete_room(p, &room), 200, "删除长轮询房间");
    ok("长轮询并发上限：第 9 个 429 / 断开释放后可再挂");
}

// ==================== group 15) 静态资源 ETag/304 ====================

#[test]
fn g15_static_etag() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let p = srv.port;

    let a = get(p, "/app.js");
    assert_status(&a, 200, "GET /app.js");
    let etag = a.header("etag").expect("静态 JS 应带 ETag").to_string();
    assert!(
        etag.len() == 66 && etag.starts_with('"') && etag.ends_with('"')
            && etag[1..65].chars().all(|c| c.is_ascii_hexdigit()),
        "ETag 应为带引号的 sha256 hex: {etag}"
    );
    assert_eq!(a.header("cache-control"), Some("no-cache"), "JS 应回源校验（no-cache）");
    let b = get_h(p, "/app.js", &[("If-None-Match", etag.clone())]);
    assert_status(&b, 304, "ETag 命中应 304");
    assert_eq!(b.header("etag"), Some(etag.as_str()), "304 也应带 ETag");
    let html = get(p, "/");
    assert_eq!(html.header("cache-control"), Some("no-store"), "HTML 必须保持 no-store");
    let panel = get(p, "/panel");
    assert_status(&panel, 200, "GET /panel");
    assert!(panel.text().contains("控制面板"), "panel 页内容");
    ok("静态资源：JS 200+ETag/no-cache → 304；HTML 仍 no-store");
}

// ==================== group 16) 413 可达 ====================

#[test]
fn g16_413_reachable() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let p = srv.port;
    let room = create_room(p);
    let big = vec![0u8; 2 * 1024 * 1024];
    let r = post(p, &format!("/api/rooms/{}/chunk", room.id), &token_hdr(&room), Some(&big));
    assert_status(&r, 413, "超 BODY_MAX 应回 413，而不是连接重置");
    assert_eq!(r.json()["error"].as_str(), Some("bad-body"));
    assert_status(&get(p, "/api/version"), 200, "413 后服务器应继续可用");
    ok("413 可达：>1.5MiB 分片回 413 JSON（非 ECONNRESET），服务继续可用");
}

// ==================== group 17) 请求边界 / DEPTH=3 ====================

#[test]
fn g17_request_boundary() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let p = srv.port;

    let br = create_room(p);
    for body in ["meta", "a", "b"] {
        assert_status(&post_chunk(p, &br, body.as_bytes()), 200, "预置分片");
    }
    assert_status(&get(p, &format!("/api/rooms/{}/chunk", br.id)), 400, "缺 ?i 应 400");
    assert_status(&get(p, &format!("/api/rooms/{}/chunk?i=", br.id)), 400, "空 ?i 应 400");
    // 越序 GET 不产生不可达分片
    assert_status(&get(p, &format!("/api/rooms/{}/chunk?i=1", br.id)), 200, "越序取 1");
    assert_status(&get(p, &format!("/api/rooms/{}/chunk?i=0", br.id)), 200, "越序取 1 后仍应能取 0");
    assert_status(&get(p, &format!("/api/rooms/{}/chunk?i=2", br.id)), 200, "取 2");
    let st = room_state(p, &br);
    assert_eq!(st["head"].as_u64(), Some(3), "head 应推进到 3");
    assert_eq!(st["pulled"].as_u64(), Some(3));
    assert_status(&get(p, &format!("/api/rooms/{}/chunk?i=1", br.id)), 410, "已消费分片再取 410");

    // DEPTH=3 并发按序预取
    let pr = create_room(p);
    for body in ["meta", "0", "1", "2"] {
        assert_status(&post_chunk(p, &pr, body.as_bytes()), 200, "预置并发分片");
    }
    let port = p;
    let room_id = pr.id.clone();
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let path = format!("/api/rooms/{room_id}/chunk?i={i}");
            thread::spawn(move || common::http(port, "GET", &path, &[], None).expect("并发 GET"))
        })
        .collect();
    let statuses: Vec<u16> = handles
        .into_iter()
        .map(|h| h.join().expect("并发线程").status)
        .collect();
    assert_eq!(statuses, vec![200, 200, 200, 200], "DEPTH=3 并发按序预取应全 200");
    assert_eq!(room_state(p, &pr)["head"].as_u64(), Some(4));
    ok("请求边界：缺/空 ?i→400；越序 GET 不产生不可达分片；DEPTH=3 并发预取正常");
}

// ==================== group 18) 慢速 POST → 房间 DELETE 竞态 ====================

#[test]
fn g18_slow_post_race() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let p = srv.port;
    let room = create_room(p);
    let payload = common::random_bytes(64 * 1024);
    let half = payload.len() / 2;

    let mut stream = TcpStream::connect(("127.0.0.1", p)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let head = format!(
        "POST /api/rooms/{}/chunk HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nX-Room-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        room.id,
        room.token,
        payload.len()
    );
    stream.write_all(head.as_bytes()).expect("写 header");
    stream.write_all(&payload[..half]).expect("写半包");
    thread::sleep(Duration::from_millis(500));
    // 读包期间销毁房间
    assert_status(&delete_room(p, &room), 200, "DELETE 房间");
    stream.write_all(&payload[half..]).expect("写剩余包");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("读竞态响应");
    let (status, body) = parse_http(&raw);
    assert_eq!(status, 410, "房间销毁后完成投递应 410 gone，实际 {status}");
    assert!(
        String::from_utf8_lossy(&body).contains("gone"),
        "响应应为 gone: {}",
        String::from_utf8_lossy(&body)
    );
    // 顺序 DELETE 后再投递：路由层已无此房间 → 404（竞态路径才是 410）
    let sequential = post(p, &format!("/api/rooms/{}/chunk", room.id), &token_hdr(&room), Some(b"x"));
    assert_status(&sequential, 404, "顺序 DELETE 后投递应 404");
    assert_status(&post(p, "/api/rooms", &[], None), 200, "服务器仍健康");
    ok("竞态：慢速 chunk POST 期间房间被 DELETE → 410 gone（不写已销毁房间）");
}

// ==================== group 19) Host/Origin 闸门 ====================

#[test]
fn g19_host_origin() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let p = srv.port;

    assert_status(
        &get_h(p, "/api/devices", &[("Host", "evil.example".into())]),
        403,
        "域名 Host 应 403",
    );
    assert_status(
        &get_h(p, "/api/devices", &[("Host", format!("127.0.0.1:{p}"))]),
        200,
        "IP Host 应 200",
    );
    assert_status(
        &get_h(p, "/", &[("Host", "evil.example".into())]),
        200,
        "静态页不受 Host 限制",
    );
    let evil_adopt = post_json(
        p,
        "/api/adopt",
        &[
            ("Host", format!("127.0.0.1:{p}")),
            ("Origin", "https://evil.example".into()),
        ],
        &json!({ "token": "z".repeat(24) }),
    );
    assert_status(&evil_adopt, 403, "跨站 Origin 的 adopt 应 403");
    assert_status(
        &get_h(p, "/api/version", &[("Origin", format!("http://127.0.0.1:{p}"))]),
        200,
        "同源 Origin 应放行",
    );
    ok("Host/Origin：域名 Host 403 / IP Host 200 / 跨站 Origin 403 / 同源放行 / 静态页不受限");
}

// ==================== group 20) /api/update 缓存 + semver ====================

#[test]
fn g20_update_cache() {
    let _g = common::serial();
    let up = Upstream::start();
    let new_url = up.url("/new");
    let srv = common::spawn_server(&[("CIPHERLANE_UPDATE_URL", new_url.as_str())]);
    let p = srv.port;

    let hits0 = up.hits();
    let port = p;
    let t1 = thread::spawn(move || common::http(port, "GET", "/api/update", &[], None).expect("update1"));
    let port = p;
    let t2 = thread::spawn(move || common::http(port, "GET", "/api/update", &[], None).expect("update2"));
    let u1 = t1.join().expect("t1");
    let u2 = t2.join().expect("t2");
    assert_status(&u1, 200, "update 1");
    let j1 = u1.json();
    assert_eq!(j1["latest"].as_str(), Some("9.9.9"));
    assert_eq!(j1["newer"].as_bool(), Some(true), "9.9.9 应判定为更新");
    assert_eq!(j1["source"].as_str(), Some(new_url.as_str()));
    assert_eq!(u2.json(), j1, "并发调用结果应一致");
    assert_eq!(up.hits() - hits0, 1, "并发两次 /api/update 只应命中上游一次");
    let u3 = get(p, "/api/update");
    assert_eq!(u3.json(), j1, "缓存命中结果应一致");
    assert_eq!(up.hits() - hits0, 1, "5min 缓存期内不应再请求上游");

    // 旧版本不得判定为 newer
    let old_url = up.url("/old");
    let srv2 = common::spawn_server(&[("CIPHERLANE_UPDATE_URL", old_url.as_str())]);
    let old = get(srv2.port, "/api/update").json();
    assert_eq!(old["latest"].as_str(), Some("0.0.1"));
    assert_eq!(old["newer"].as_bool(), Some(false), "0.0.1 不应判定为更新（语义化比较）");
    ok("/api/update：并发/缓存只请求上游一次、semver newer 正确、旧版本不误报");
}

// ==================== group 21) per-IP 配额 ====================

#[test]
fn g21_per_ip_quota() {
    let _g = common::serial();
    let srv = common::spawn_server(&[
        ("CIPHERLANE_TEST_LIMITS", "1"),
        ("CIPHERLANE_UPDATE_URL", "file:///etc/hostname"),
    ]);
    let p = srv.port;

    let mut rooms = Vec::new();
    for _ in 0..4 {
        rooms.push(create_room(p));
    }
    let over = post(p, "/api/rooms", &[], None);
    assert_status(&over, 429, "第 5 个房间应 429");
    assert_eq!(over.json()["error"].as_str(), Some("ip-quota"));

    let mib = vec![0u8; 1024 * 1024];
    assert_status(&post_chunk(p, &rooms[0], &mib), 200, "第 1MiB");
    assert_status(&post_chunk(p, &rooms[0], &mib), 200, "第 2MiB");
    let bq = post_chunk(p, &rooms[0], &mib);
    assert_status(&bq, 429, "单 IP 2MB 字节配额：第 3MiB 应 429");
    assert_eq!(bq.json()["error"].as_str(), Some("backpressure"));

    for rr in &rooms {
        assert_status(&delete_room(p, rr), 200, "清理配额房间");
    }
    let fresh = create_room(p);
    assert_status(&post_chunk(p, &fresh, &mib), 200, "destroy 后 ipBytes 应已释放");
    assert_status(&get(p, &format!("/api/rooms/{}/chunk?i=0", fresh.id)), 200, "take 一片");
    assert_status(&post_chunk(p, &fresh, &mib), 200, "takeChunk 后 ipBytes 应已释放");
    assert_status(
        &get_h(p, &format!("/api/rooms/{}/chunk?i=1", fresh.id), &[("X-Resume", "1".into())]),
        200,
        "X-Resume 只读回放",
    );
    assert_status(
        &post_json(p, &format!("/api/rooms/{}/progress", fresh.id), &[], &json!({ "through": 2 })),
        200,
        "progress 释放",
    );
    assert_status(&post_chunk(p, &fresh, &mib), 200, "advanceThrough 后 ipBytes 应已释放");
    assert_status(&post_chunk(p, &fresh, &mib), 200, "再次累计 2MiB");
    assert_status(&post_chunk(p, &fresh, &mib), 429, "重新累计到 2MB 后应再次 429");

    let bad = get(p, "/api/update");
    assert_status(&bad, 400, "file:// 更新源应 400");
    assert_eq!(bad.json()["error"].as_str(), Some("bad-update-url"));
    ok("per-IP 配额：4 房上限→第 5 个 429 ip-quota / 2MB 字节上限→backpressure / destroy·take·advance 均释放 / 非法 update URL 400");
}

// ==================== group 22) 建房限流 ====================

#[test]
fn g22_room_rate_limit() {
    let _g = common::serial();
    let srv = common::spawn_server(&[("CIPHERLANE_TEST_LIMITS", "1")]);
    let p = srv.port;
    for i in 0..120 {
        let room = create_room(p);
        assert_status(&delete_room(p, &room), 200, &format!("第 {i} 次建房后删除"));
    }
    let over = post(p, "/api/rooms", &[], None);
    assert_status(&over, 429, "第 121 次建房应 429");
    let j = over.json();
    assert_eq!(j["error"].as_str(), Some("ip-quota"));
    assert!(
        j["retry"].as_u64().map(|v| v >= 1).unwrap_or(false),
        "应给出 retry 秒数: {j}"
    );
    ok("建房限流：60s 内第 121 次建房 → 429 ip-quota（滑动窗口，retry 有值）");
}

// ==================== group 23) 设备名净化 ====================

#[test]
fn g23_device_name_sanitize() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let p = srv.port;
    let identity = gen_identity();
    let dirty = "evil\u{1b}[31m\u{0}line\nname\u{9b}";
    let r = post_json(
        p,
        "/api/presence",
        &[],
        &json!({ "name": dirty, "pub": common::b64u(&identity.pk) }),
    );
    assert_status(&r, 200, "注册脏名字");
    let j = get(p, "/api/devices").json();
    let me = j["devices"]
        .as_array()
        .expect("devices")
        .iter()
        .find(|d| d["ip"].as_str() == Some("127.0.0.1"))
        .expect("设备应在线");
    assert_eq!(
        me["name"].as_str(),
        Some("evil[31mlinename"),
        "控制字符应被移除后再 trim/slice"
    );
    ok("设备名净化：ESC/NUL/换行/C1 被剔除，/api/devices 返回干净名称");
}

// ==================== group 24) 面板端点 ====================

#[test]
fn g24_panel_endpoints() {
    let _g = common::serial();
    let up = Upstream::start();
    let url = up.url("/new");
    let srv = common::spawn_server(&[("CIPHERLANE_UPDATE_URL", url.as_str())]);
    let p = srv.port;

    let v = get(p, "/api/version").json();
    assert!(
        v["version"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "version 应存在"
    );
    assert!(v["startedAt"].is_u64() || v["startedAt"].is_i64(), "startedAt 应存在");
    let r = post_json(p, "/api/shutdown", &[], &json!({}));
    assert_status(&r, 403, "空令牌应 403");
    let r = post_json(p, "/api/shutdown", &[], &json!({ "token": "x".repeat(24) }));
    assert_status(&r, 403, "错令牌应 403");
    let u = get(p, "/api/update");
    assert_status(&u, 200, "update 200");
    assert_eq!(u.json()["source"].as_str(), Some(url.as_str()));
    let panel = get(p, "/panel");
    assert_status(&panel, 200, "panel 页可达");
    assert!(panel.text().contains("控制面板"));
    ok("面板端点：version / shutdown 令牌双闸 403 / update source 如实 / panel 页可达");
}

// ==================== group 25) adopt 托盘接管 ====================

#[test]
fn g25_adopt() {
    let _g = common::serial();
    let srv = common::spawn_server(&[]);
    let p = srv.port;
    let r = post_json(p, "/api/adopt", &[], &json!({ "token": "short" }));
    assert_status(&r, 400, "短令牌应 400");
    let tok = "a".repeat(24);
    let r = post_json(p, "/api/adopt", &[], &json!({ "token": tok }));
    assert_status(&r, 200, "回环 adopt 应 200");
    let r = post_json(p, "/api/adopt", &[], &json!({ "token": "b".repeat(24) }));
    assert_status(&r, 409, "已有管理者应 409");
    let r = post_json(p, "/api/shutdown", &[], &json!({}));
    assert_status(&r, 403, "shutdown 空令牌仍 403");
    ok("adopt：回环接管 200 / 短令牌 400 / 二次接管 409 / shutdown 空令牌仍 403");
}

// ==================== group 26) SIGTERM 优雅停机 ====================

#[test]
fn g26_sigterm_graceful() {
    let _g = common::serial();
    let mut srv = common::spawn_server(&[]);
    let pid = srv.child.id();
    // SIGTERM 不能走 Child::kill（那是 SIGKILL）
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut status = None;
    while Instant::now() < deadline {
        if let Some(st) = srv.child.try_wait().expect("try_wait") {
            status = Some(st);
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let status = status.expect("SIGTERM 后 3s 内未退出（优雅停机未生效）");
    assert_eq!(status.code(), Some(0), "SIGTERM 应退出码 0: {status:?}");
    thread::sleep(Duration::from_millis(100));
    let out = srv.stdout();
    assert!(out.contains("优雅停机"), "应打印优雅停机文案: {out}");
    ok("SIGTERM 优雅停机：关闭监听/连接后 exit 0");
}
