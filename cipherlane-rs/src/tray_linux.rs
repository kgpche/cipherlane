// cipherlane · 密道 —— 系统托盘（StatusNotifierItem/AppIndicator）
//
// 菜单：打开主页 / 打开控制面板 / 启动服务 / 停止服务 / 检查更新 / 关于 / 退出托盘。
// 托盘启动的服务持有停机令牌（面板"退出"可用）；外部启动的服务（如 systemd）只读管理。
use ksni::blocking::TrayMethods; // 提供 Tray::spawn() 的同步阻塞版本
use ksni::menu::StandardItem;
use ksni::{MenuItem, ToolTip, Tray};
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
fn http_post_json(path: &str, body: &str) -> Option<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port())).ok()?;
    let _ = write!(
        s,
        "POST {} HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        body.len(),
        body
    );
    let mut raw = String::new();
    s.read_to_string(&mut raw).ok()?;
    Some(raw)
}

fn rand_token() -> String {
    let b: [u8; 18] = rand::thread_rng().gen();
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

// 接管在跑的无令牌服务：换得停机令牌，从此"退出=关服务"。
// 返回 (令牌, 附注)：409 = 服务已被他人持令牌管理（如另一托盘/旧启动器残留）。
fn try_adopt() -> (Option<String>, String) {
    let t0 = rand_token();
    match http_post_json("/api/adopt", &format!("{{\"token\":\"{}\"}}", t0)) {
        Some(raw) if raw.contains("200") => (Some(t0), String::new()),
        Some(raw) if raw.contains("409") => {
            (None, "服务由其他管理者持有（如 systemd/另一托盘）".into())
        }
        _ => (None, "接管失败：旧版本服务器？退出将仅退托盘".into()),
    }
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
    // 主页用 LAN 地址打开：经回环打开会让链接/二维码变成 127.0.0.1（对方不可达）。
    // 与服务器 /api/version 的 lan 字段同源（含"默认路由网卡优先"的排序），避免两处各挑各的
    fn lan_base(&self) -> String {
        let lan = http_get_json("/api/version")
            .and_then(|body| body.split("\"lan\":\"").nth(1).and_then(|s| s.split('"').next()).map(String::from))
            .filter(|s| !s.is_empty());
        match lan {
            Some(ip) => format!("http://{}:{}", ip, port()),
            None => {
                // 服务器未就绪/lan:null：退回本地枚举（再退回环）
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
        }
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
        // 停机 API 兜底（覆盖"进程在但 child 句柄丢失/接管来的服务"场景）
        let _ = http_post_json("/api/shutdown", &format!("{{\"token\":\"{}\"}}", token));
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
        // 退出 = 尽力关闭服务（持令牌或接管所得）并退出托盘
        items.push(MenuItem::Standard(StandardItem {
            label: if self.running { "退出（关闭服务并退出托盘）".into() } else { "退出托盘".into() },
            activate: Box::new(|t: &mut Self| {
                if t.running && t.token.is_some() {
                    t.stop_server();
                }
                std::process::exit(0)
            }),
            ..Default::default()
        }));
        items
    }
}

pub fn main() {
    let running = server_up();
    let mut token: Option<String> = None;
    let mut note = String::new();
    if running {
        // 接管在跑的无令牌服务:换得停机令牌,从此"退出=关服务"
        let (t, n) = try_adopt();
        token = t;
        note = n;
        if token.is_some() {
            println!("已接管运行中的服务（令牌交接）");
        }
    }
    let tray = CipherlaneTray {
        running,
        token,
        note,
        server: Arc::new(Mutex::new(None)),
    };
    // ubuntu:GNOME 下 org.kde.StatusNotifierWatcher 常未注册（AppIndicator 扩展例外注册 item），
    // assume_sni_available 跳过 watcher 探测直接注册 StatusNotifierItem
    let handle = tray
        .assume_sni_available(true)
        .spawn()
        .expect("托盘初始化失败（无 D-Bus 环境？）");
    // 状态轮询：外部启停也会反映到图标；服务由外部（桌面启动器/systemd）拉起时
    // 主动 adopt 接管——否则托盘永远无令牌，"停止服务"会一直是灰的
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(2));
        handle.update(|t| {
            let up = server_up();
            if up != t.running {
                t.running = up;
                if !up {
                    t.token = None;
                    *t.server.lock().unwrap() = None;
                } else if t.token.is_none() {
                    let (tok, n) = try_adopt();
                    if tok.is_some() {
                        t.token = tok;
                        t.note.clear();
                        println!("已接管后启动的服务（令牌交接）");
                    } else {
                        t.note = n;
                    }
                }
            }
        });
    });
    loop {
        std::thread::park();
    }
}
