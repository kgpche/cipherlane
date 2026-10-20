//! v1.0 测试基建（Rust）：被测产品是三个 Rust 二进制，测试通过 CDP 驱动真实 Chrome
//! 验证浏览器端 JS（前端语言本身无法用 Rust 替代），全部测试由 `cargo test` 运行，
//! 不再依赖 Node/npm。
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

// ---------- 跨进程串行锁 ----------
static LOCK_NAME: &str = "cipherlane-rust-tests.lock";

pub struct Serial {
    path: PathBuf,
}

impl Drop for Serial {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// 测试二进制之间串行化（cargo 默认会并行跑多个 tests/*.rs）。退出时自动释放。
pub fn serial() -> Serial {
    let path = std::env::temp_dir().join(LOCK_NAME);
    let deadline = Instant::now() + Duration::from_secs(600);
    loop {
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                let _ = writeln!(f, "{}", std::process::id());
                return Serial { path };
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if let Ok(meta) = std::fs::metadata(&path) {
                    if let Ok(modified) = meta.modified() {
                        if modified.elapsed().map(|d| d > Duration::from_secs(600)).unwrap_or(false) {
                            let _ = std::fs::remove_file(&path);
                            continue;
                        }
                    }
                }
                if Instant::now() > deadline {
                    panic!("等待测试串行锁超时: {}", path.display());
                }
                std::thread::sleep(Duration::from_millis(150));
            }
            Err(e) => panic!("创建测试锁失败: {e}"),
        }
    }
}

// ---------- 通用工具 ----------
pub fn unique_dir(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&p).expect("创建临时目录失败");
    p
}

pub fn free_port() -> u16 {
    for _ in 0..200 {
        let p = 20000 + (rand_u32() % 20000) as u16;
        if TcpListener::bind(("127.0.0.1", p)).is_ok() {
            return p;
        }
    }
    panic!("找不到空闲端口");
}

fn rand_u32() -> u32 {
    use rand::RngCore;
    rand::rngs::OsRng.next_u32()
}

pub fn b64u(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn from_b64u(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).expect("base64url 解码失败")
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut v = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut v);
    v
}

// ---------- 被测二进制 ----------
pub fn server_bin() -> PathBuf {
    match std::env::var("CIPHERLANE_SERVER_BIN") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => PathBuf::from(env!("CARGO_BIN_EXE_cipherlane")),
    }
}

pub fn cli_bin() -> PathBuf {
    match std::env::var("CIPHERLANE_CLI_BIN") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => PathBuf::from(env!("CARGO_BIN_EXE_cipherlane-cli")),
    }
}

pub struct Server {
    pub child: Child,
    pub port: u16,
    pub stdout_path: PathBuf,
}

impl Server {
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
    pub fn stdout(&self) -> String {
        std::fs::read_to_string(&self.stdout_path).unwrap_or_default()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 启动被测服务器。extra_env 覆盖默认值；未显式给 HOST 时只绑回环。
pub fn spawn_server(extra_env: &[(&str, &str)]) -> Server {
    let port = free_port();
    let log = unique_dir("cipherlane-srv").join("stdout.log");
    let mut cmd = Command::new(server_bin());
    cmd.env("PORT", port.to_string());
    cmd.env("HOST", "127.0.0.1");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::from(std::fs::File::create(&log).expect("创建 server 日志失败")));
    cmd.stderr(Stdio::null());
    let child = cmd.spawn().expect("启动 cipherlane 服务器失败");
    let mut srv = Server { child, port, stdout_path: log };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(r) = http(port, "GET", "/api/version", &[], None) {
            if r.status == 200 {
                return srv;
            }
        }
        if Instant::now() > deadline {
            let out = srv.stdout();
            let _ = srv.stop();
            panic!("服务器 10s 内未就绪: {out}");
        }
        std::thread::sleep(Duration::from_millis(30));
    }
}

// ---------- 原始 HTTP ----------
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|_| panic!("响应不是 JSON: {}", self.text()))
    }
}

/// HTTP/1.1 原始请求（默认 Host + Connection: close；headers 可覆盖 Host）。
pub fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> std::io::Result<HttpResponse> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(40)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut has_host = false;
    let mut head = format!("{method} {path} HTTP/1.1\r\n");
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_host {
        head.push_str(&format!("Host: 127.0.0.1:{port}\r\n"));
    }
    head.push_str("Connection: close\r\n");
    if let Some(b) = body {
        head.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    head.push_str("\r\n");
    // 413 等场景服务器可能在客户端写完 body 前就回应并关闭读端：忽略写错误，
    // 继续读响应（与浏览器 fetch 的"提前响应"语义一致）。
    let _ = stream.write_all(head.as_bytes());
    if let Some(b) = body {
        let _ = stream.write_all(b);
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    let (head_bytes, body_bytes) = match split {
        Some(i) => (&raw[..i], &raw[i..]),
        None => (&raw[..], &[][..]),
    };
    let head_text = String::from_utf8_lossy(head_bytes);
    let mut lines = head_text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let mut hs = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            hs.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let chunked = hs
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"));
    let body_vec = if chunked { dechunk(body_bytes) } else { body_bytes.to_vec() };
    Ok(HttpResponse { status, headers: hs, body: body_vec })
}

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(pos) = data.windows(2).position(|w| w == b"\r\n") else { break };
        let line = String::from_utf8_lossy(&data[..pos]);
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
        data = &data[pos + 2..];
        if size == 0 {
            break;
        }
        if data.len() < size {
            out.extend_from_slice(data);
            break;
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        if data.starts_with(b"\r\n") {
            data = &data[2..];
        }
    }
    out
}

// ---------- Chrome + CDP ----------
pub fn find_chrome() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CHROME_BIN") {
        if Path::new(&p).exists() {
            return Some(PathBuf::from(p));
        }
    }
    [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/opt/google/chrome/chrome",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

pub struct Chrome {
    pub child: Child,
    pub ws_url: String,
    profile: PathBuf,
}

impl Drop for Chrome {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

/// 启动 headless Chrome；无浏览器时返回 None（测试打印跳过并正常退出）。
pub fn launch_chrome() -> Option<Chrome> {
    let bin = find_chrome()?;
    let profile = unique_dir("cipherlane-chrome");
    let mut child = Command::new(&bin)
        .args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--mute-audio",
            "--window-size=1280,900",
            "--no-proxy-server",
            "--host-resolver-rules=MAP cipherlane-insecure.test 127.0.0.1",
            "--remote-debugging-port=0",
            "about:blank",
        ])
        .arg(format!("--user-data-dir={}", profile.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("启动 Chrome 失败");
    let stderr = child.stderr.take().expect("Chrome stderr");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().flatten() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut ws_url = None;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                if let Some(idx) = line.find("DevTools listening on ") {
                    let rest = &line[idx + "DevTools listening on ".len()..];
                    let url = rest.split_whitespace().next().unwrap_or("").to_string();
                    if url.starts_with("ws://") {
                        ws_url = Some(url);
                        break;
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let Some(ws_url) = ws_url else {
        let _ = child.kill();
        panic!("Chrome 未能启动调试端口");
    };
    Some(Chrome { child, ws_url, profile })
}

/// 极简同步 CDP 客户端（flatten session）：发送命令并等待同 id 响应，事件忽略。
pub struct Cdp {
    ws: tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    next_id: u64,
}

impl Cdp {
    pub fn connect(ws_url: &str) -> Cdp {
        loop {
            match tungstenite::connect(ws_url) {
                Ok((mut ws, _)) => {
                    if let tungstenite::stream::MaybeTlsStream::Plain(tcp) = ws.get_mut() {
                        let _ = tcp.set_read_timeout(Some(Duration::from_secs(150)));
                        let _ = tcp.set_write_timeout(Some(Duration::from_secs(10)));
                    }
                    return Cdp { ws, next_id: 0 };
                }
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }

    pub fn send(&mut self, session: Option<&str>, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let mut msg = json!({ "id": id, "method": method, "params": params });
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        self.ws
            .send(tungstenite::Message::Text(msg.to_string()))
            .unwrap_or_else(|e| panic!("CDP 发送失败 {method}: {e}"));
        loop {
            let m = self
                .ws
                .read()
                .unwrap_or_else(|e| panic!("CDP 读取失败（等待 {method}）: {e}"));
            match m {
                tungstenite::Message::Text(t) => {
                    let v: Value = serde_json::from_str(&t).expect("CDP 响应不是 JSON");
                    if v.get("id").and_then(|x| x.as_u64()) == Some(id) {
                        if let Some(err) = v.get("error") {
                            panic!("CDP {method} 失败: {err}");
                        }
                        return v.get("result").cloned().unwrap_or(Value::Null);
                    }
                }
                tungstenite::Message::Ping(p) => {
                    let _ = self.ws.send(tungstenite::Message::Pong(p));
                }
                tungstenite::Message::Close(_) => panic!("CDP 连接被关闭（等待 {method}）"),
                _ => {}
            }
        }
    }

    pub fn new_page(&mut self) -> Page {
        let target = self.send(None, "Target.createTarget", json!({ "url": "about:blank" }))["targetId"]
            .as_str()
            .expect("targetId")
            .to_string();
        let sid = self.send(
            None,
            "Target.attachToTarget",
            json!({ "targetId": target, "flatten": true }),
        )["sessionId"]
            .as_str()
            .expect("sessionId")
            .to_string();
        self.send(Some(&sid), "Page.enable", json!({}));
        self.send(Some(&sid), "Runtime.enable", json!({}));
        Page { sid, target }
    }

    pub fn close_page(&mut self, page: &Page) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.send(None, "Target.closeTarget", json!({ "targetId": page.target }));
        }));
    }

    pub fn eval(&mut self, page: &Page, expr: &str) -> Value {
        self.eval_opt(page, expr, false)
    }
    pub fn eval_gesture(&mut self, page: &Page, expr: &str) -> Value {
        self.eval_opt(page, expr, true)
    }
    fn eval_opt(&mut self, page: &Page, expr: &str, gesture: bool) -> Value {
        let res = self.send(
            Some(&page.sid),
            "Runtime.evaluate",
            json!({
                "expression": expr,
                "awaitPromise": true,
                "returnByValue": true,
                "userGesture": gesture,
            }),
        );
        if let Some(ex) = res.get("exceptionDetails") {
            let desc = ex
                .get("exception")
                .and_then(|e| e.get("description"))
                .and_then(|d| d.as_str())
                .or_else(|| ex.get("text").and_then(|t| t.as_str()))
                .unwrap_or("?");
            panic!("页面执行失败: {desc}\n  ← {}", &expr[..expr.len().min(160)]);
        }
        res.get("result")
            .and_then(|r| r.get("value"))
            .cloned()
            .unwrap_or(Value::Null)
    }

    pub fn navigate(&mut self, page: &Page, url: &str) {
        self.send(Some(&page.sid), "Page.navigate", json!({ "url": url }));
        self.wait_for(page, "document.readyState === 'complete'", 15000, "页面加载");
    }

    pub fn wait_for(&mut self, page: &Page, expr: &str, timeout_ms: u64, what: &str) -> Value {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.eval(page, expr)));
            if let Ok(v) = ok {
                if v.as_bool().unwrap_or_else(|| !v.is_null()) {
                    return v;
                }
            }
            if Instant::now() > deadline {
                panic!("等待超时（{what}）: {expr}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn set_files(&mut self, page: &Page, selector: &str, files: &[PathBuf]) {
        self.send(Some(&page.sid), "DOM.enable", json!({}));
        let root = self.send(Some(&page.sid), "DOM.getDocument", json!({}))["root"]["nodeId"].clone();
        let node = self.send(
            Some(&page.sid),
            "DOM.querySelector",
            json!({ "nodeId": root, "selector": selector }),
        )["nodeId"]
            .clone();
        self.send(
            Some(&page.sid),
            "DOM.setFileInputFiles",
            json!({
                "files": files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "nodeId": node,
            }),
        );
    }
}

pub struct Page {
    pub sid: String,
    pub target: String,
}
