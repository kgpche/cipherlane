// cipherlane · 密道 —— 系统托盘（StatusNotifierItem/AppIndicator）
//
// 菜单：打开主页 / 打开控制面板 / 启动服务 / 停止服务 / 检查更新 / 关于 / 退出托盘。
// 托盘启动的服务持有停机令牌（面板"退出"可用）；外部启动的服务（如 systemd）只读管理。
use ksni::blocking::TrayMethods; // 提供 Tray::spawn() 的同步阻塞版本
use ksni::menu::StandardItem;
use ksni::{Icon, MenuItem, ToolTip, Tray};
use rand::Rng;
use std::net::TcpStream;
use std::io::{Read, Write};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn port() -> u16 {
    std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(7777)
}

fn server_up() -> bool {
    let mut s = match TcpStream::connect(("127.0.0.1", port())) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = write!(s, "GET /api/version HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let mut buf = [0u8; 256];
    match s.read(&mut buf) {
        Ok(n) => String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1."),
        Err(_) => false,
    }
}

fn http_get_json(path: &str) -> Option<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port())).ok()?;
    let _ = write!(s, "GET {} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n", path);
    let mut raw = String::new();
    s.read_to_string(&mut raw).ok()?;
    raw.split_once("\r\n\r\n").map(|(_, b)| b.to_string())
}

fn open(url: &str) {
    Command::new("xdg-open").arg(url).spawn().ok();
}

fn rand_token() -> String {
    let b: [u8; 18] = rand::thread_rng().gen();
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

struct CipherlaneTray {
    running: bool,
    token: Option<String>, // 托盘自己启动的服务才持有停机令牌
    note: String,          // 状态/更新检查结果，显示为禁用菜单项
    server: Arc<Mutex<Option<std::process::Child>>>,
}

impl CipherlaneTray {
    fn base(&self) -> String {
        format!("http://127.0.0.1:{}", port())
    }
    // 主页用 LAN 地址打开：经回环打开会让链接/二维码变成 127.0.0.1（对方不可达）
    fn lan_base(&self) -> String {
        let lan = if_addrs::get_if_addrs()
            .ok()
            .map(|v| {
                v.into_iter()
                    .filter_map(|i| match i.ip() {
                        std::net::IpAddr::V4(v4) if !v4.is_loopback() && v4.is_private() => Some(v4),
                        _ => None,
                    })
                    .next()
            })
            .flatten();
        format!("http://{}:{}", lan.map(|a| a.to_string()).unwrap_or_else(|| "127.0.0.1".into()), port())
    }
    fn start_server(&mut self) {
        if self.running {
            return;
        }
        let token = rand_token();
        match Command::new("cipherlane")
            .env("CIPHERLANE_SHUTDOWN_TOKEN", &token)
            .env("PORT", port().to_string())
            .spawn()
        {
            Ok(child) => {
                // 等就绪
                for _ in 0..50 {
                    if server_up() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                *self.server.lock().unwrap() = Some(child);
                self.token = Some(token);
                self.running = true;
                self.note.clear();
            }
            Err(e) => self.note = format!("启动失败：{}", e),
        }
    }
    fn stop_server(&mut self) {
        let token = match &self.token {
            Some(t) => t.clone(),
            None => return, // 非托盘启动：无令牌，由面板或 systemctl 管理
        };
        if let Some(mut child) = self.server.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // 也调 API（覆盖"进程在但 child 句柄丢失"的场景）
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port())) {
            let body = format!("{{\"token\":\"{}\"}}", token);
            let _ = write!(
                s,
                "POST /api/shutdown HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
        }
        self.token = None;
        self.running = false;
    }
}

impl Tray for CipherlaneTray {
    fn id(&self) -> String {
        "cipherlane".into()
    }
    fn title(&self) -> String {
        "cipherlane 密道".into()
    }
    fn icon_name(&self) -> String {
        if self.running { "cipherlane" } else { "cipherlane-stopped" }.into()
    }
    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            icon_name: self.icon_name(),
            icon_pixmap: Vec::new(),
            title: "cipherlane 密道".into(),
            description: if self.running {
                format!("v{} · 服务运行中 · {}", VERSION, self.base())
            } else {
                format!("v{} · 服务未运行", VERSION)
            },
        }
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        if self.running {
            open(&format!("{}/", self.lan_base()));
        } else {
            self.start_server();
        }
    }
    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items: Vec<MenuItem<Self>> = vec![
            MenuItem::Standard(StandardItem {
                label: if self.running { "● 服务运行中".into() } else { "○ 服务未运行".into() },
                enabled: false,
                ..Default::default()
            }),
            MenuItem::Separator,
        ];
        if !self.note.is_empty() {
            let note = self.note.clone();
            items.push(MenuItem::Standard(StandardItem {
                label: note,
                enabled: false,
                ..Default::default()
            }));
            items.push(MenuItem::Separator);
        }
        if self.running {
            let base = self.base();
            items.push(MenuItem::Standard(StandardItem {
                label: "打开主页".into(),
                activate: Box::new(|t: &mut Self| open(&format!("{}/", t.lan_base()))),
                ..Default::default()
            }));
            items.push(MenuItem::Standard(StandardItem {
                label: "打开控制面板".into(),
                activate: Box::new(move |t: &mut Self| {
                    let url = match &t.token {
                        Some(tok) => format!("{}/panel#{}", t.base(), tok),
                        None => format!("{}/panel", t.base()),
                    };
                    open(&url);
                }),
                ..Default::default()
            }));
            items.push(MenuItem::Standard(StandardItem {
                label: "停止服务".into(),
                enabled: self.token.is_some(),
                activate: Box::new(|t: &mut Self| t.stop_server()),
                ..Default::default()
            }));
            items.push(MenuItem::Standard(StandardItem {
                label: "检查更新".into(),
                activate: Box::new(|t: &mut Self| {
                    match http_get_json("/api/update") {
                        Some(body) => {
                            let latest = body.split("\"latest\":\"").nth(1).and_then(|s| s.split('"').next()).unwrap_or("?").to_string();
                            if body.contains("\"source\":null") {
                                t.note = format!("v{} · 未配置更新源", VERSION);
                            } else if body.contains("\"newer\":true") {
                                t.note = format!("🟢 有新版本 v{} → v{}", VERSION, latest);
                            } else if body.contains("\"error\"") {
                                t.note = "⚠️ 更新源不可达".into();
                            } else {
                                t.note = format!("✅ 已是最新 v{}", VERSION);
                            }
                        }
                        None => t.note = "⚠️ 服务不可达".into(),
                    }
                }),
                ..Default::default()
            }));
        } else {
            items.push(MenuItem::Standard(StandardItem {
                label: "启动服务".into(),
                activate: Box::new(|t: &mut Self| t.start_server()),
                ..Default::default()
            }));
        }
        items.push(MenuItem::Separator);
        items.push(MenuItem::Standard(StandardItem {
            label: format!("关于 cipherlane v{}（MIT）", VERSION),
            enabled: false,
            ..Default::default()
        }));
        items.push(MenuItem::Standard(StandardItem {
            label: "退出托盘".into(),
            activate: Box::new(|_t: &mut Self| std::process::exit(0)),
            ..Default::default()
        }));
        items
    }
}

fn main() {
    let running = server_up();
    let tray = CipherlaneTray {
        running,
        token: None,
        note: if running { "外部启动的服务：停止请用控制面板或 systemctl".into() } else { String::new() },
        server: Arc::new(Mutex::new(None)),
    };
    // ubuntu:GNOME 下 org.kde.StatusNotifierWatcher 常未注册（AppIndicator 扩展例外注册 item），
    // assume_sni_available 跳过 watcher 探测直接注册 StatusNotifierItem
    let handle = tray
        .assume_sni_available(true)
        .spawn()
        .expect("托盘初始化失败（无 D-Bus 环境？）");
    // 状态轮询：外部启停也会反映到图标
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(2));
        handle.update(|t| {
            let up = server_up();
            if up != t.running {
                t.running = up;
                if !up {
                    t.token = None;
                    *t.server.lock().unwrap() = None;
                }
            }
        });
    });
    loop {
        std::thread::park();
    }
}
