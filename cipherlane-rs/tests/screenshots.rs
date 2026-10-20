//! 文档截图再生成（维护工具，默认不跑）：
//!   cargo test --release --manifest-path cipherlane-rs/Cargo.toml --test screenshots -- --ignored
//! 需要本机 Chrome/Chromium；输出直接覆盖 docs/screenshots/{landing,send-done,recv-text}.png。
//! 用真实 Rust 服务器 + headless Chrome 驱动前端，保证截图与当前 UI 一致。
mod common;

use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::path::Path;
use std::time::Duration;

use base64::Engine;
use serde_json::{json, Value};

fn shot(cdp: &mut common::Cdp, page: &common::Page, name: &str) {
    let res = cdp.send(
        Some(&page.sid),
        "Page.captureScreenshot",
        json!({ "format": "png", "captureBeyondViewport": false }),
    );
    let b64 = res.get("data").and_then(|v| v.as_str()).expect("screenshot data");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("decode png");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/screenshots");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, &bytes).unwrap_or_else(|e| panic!("写截图失败 {}: {e}", path.display()));
    println!("  ✓ {}", path.display());
}

unsafe fn in_addr(ip: &str) -> libc::in_addr {
    let o: Vec<u8> = ip.split('.').map(|x| x.parse().expect("ipv4")).collect();
    libc::in_addr { s_addr: u32::from_ne_bytes([o[0], o[1], o[2], o[3]]) }
}

/// 用 127.0.0.x 源地址注册一台假设备（模拟局域网里的其他终端）。
fn register_fake(src_ip: &str, port: u16, name: &str) {
    // std 无 bind-before-connect 的公共 API（本工具链 std::net::TcpSocket 不可用），
    // 用 libc 原始 socket：先 bind 到 127.0.0.x 再连 127.0.0.1，服务器才看到不同来源 IP。
    let pub_key = common::b64u(&common::random_bytes(32));
    let body = json!({ "name": name, "pub": pub_key }).to_string();
    let req = format!(
        "POST /api/presence HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        assert!(fd >= 0, "socket() 失败");
        let mut local: libc::sockaddr_in = std::mem::zeroed();
        local.sin_family = libc::AF_INET as libc::sa_family_t;
        local.sin_port = 0;
        local.sin_addr = in_addr(src_ip);
        assert_eq!(
            libc::bind(fd, &local as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32),
            0,
            "bind {src_ip} 失败"
        );
        let mut peer: libc::sockaddr_in = std::mem::zeroed();
        peer.sin_family = libc::AF_INET as libc::sa_family_t;
        peer.sin_port = port.to_be();
        peer.sin_addr = in_addr("127.0.0.1");
        assert_eq!(
            libc::connect(fd, &peer as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32),
            0,
            "connect 失败"
        );
        let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as u32,
        );
        let mut f = std::fs::File::from_raw_fd(fd);
        let _ = f.write_all(req.as_bytes());
        let mut buf = Vec::new();
        let _ = f.read_to_end(&mut buf);
    }
}

fn metrics(cdp: &mut common::Cdp, page: &common::Page, h: u32) {
    cdp.send(
        Some(&page.sid),
        "Emulation.setDeviceMetricsOverride",
        json!({ "width": 1280, "height": h, "deviceScaleFactor": 1, "mobile": false }),
    );
}

#[test]
#[ignore = "维护工具：重新生成 docs/screenshots，需要 Chrome"]
fn regenerate_docs_screenshots() {
    let _g = common::serial();
    // HOST="" → 恢复"回环 + LAN"自动绑定，链接与二维码才是真实形态
    let srv = common::spawn_server(&[("HOST", "")]);
    let Some(chrome) = common::launch_chrome() else {
        eprintln!("跳过：未找到 Chrome/Chromium");
        return;
    };
    let mut cdp = common::Cdp::connect(&chrome.ws_url);

    // 7 台假设备 → 触发 >6 台的搜索框与单行横滑设备栏
    let names = [
        "客厅 iMac", "书房 MacBook", "手机 · Pixel", "NAS", "工作站", "平板", "会议室电视",
    ];
    for (i, name) in names.iter().enumerate() {
        register_fake(&format!("127.0.0.{}", i + 2), srv.port, name);
    }

    let page = cdp.new_page();
    metrics(&mut cdp, &page, 760);
    cdp.navigate(&page, &format!("{}/", srv.url()));
    cdp.wait_for(
        &page,
        "document.querySelectorAll('#devices .device').length >= 7",
        15000,
        "设备卡片渲染",
    );
    cdp.wait_for(&page, "!document.querySelector('#device-search').hidden", 5000, "搜索框出现");
    std::thread::sleep(Duration::from_millis(300));
    shot(&mut cdp, &page, "landing.png");

    // 链接模式发送一段文本（含二维码），随后由第二个页面接收
    cdp.eval(
        &page,
        "startSend('text', '你好，这是通过密道发送的一段示例文本。', null)",
    );
    cdp.wait_for(&page, "document.querySelector('#link').textContent.startsWith('http')", 15000, "接收链接");
    cdp.wait_for(&page, "document.querySelector('#qr svg') !== null", 8000, "二维码");
    let link = cdp
        .eval(&page, "document.querySelector('#link').textContent")
        .as_str()
        .unwrap()
        .to_string();
    let frag = link.split_once('#').expect("fragment").1.to_string();

    let recv = cdp.new_page();
    metrics(&mut cdp, &recv, 760);
    cdp.navigate(&recv, &format!("{}/#{}", srv.url(), frag));
    cdp.wait_for(
        &recv,
        "!document.querySelector('#recv-text').hidden && document.querySelector('#recv-text').textContent.length > 0",
        20000,
        "文本接收",
    );
    std::thread::sleep(Duration::from_millis(300));
    shot(&mut cdp, &recv, "recv-text.png");

    // 接收方 ack 后，发送方状态变为"已完整接收"
    cdp.wait_for(
        &page,
        "document.querySelector('#send-status').textContent.includes('已完整接收')",
        20000,
        "发送完成状态",
    );
    std::thread::sleep(Duration::from_millis(300));
    shot(&mut cdp, &page, "send-done.png");

    println!("文档截图已更新（landing / send-done / recv-text）");
}

/// 静默未使用告警（保持 Value 导入用于未来扩展）
#[allow(dead_code)]
fn _unused(_v: Value) {}
