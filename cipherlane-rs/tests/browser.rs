//! v1.0 浏览器 E2E（Rust 版）—— `test/browser.test.mjs` 19 组场景的逐一对等移植。
//!
//! 运行：
//!   cargo test --manifest-path cipherlane-rs/Cargo.toml --test browser -- --nocapture
//!
//! 设计：
//! - 产品已去 Node：服务器固定为 `common::spawn_server()` 启动的 Rust 二进制（debug 构建由
//!   `CARGO_BIN_EXE_cipherlane` 提供），前端仍是浏览器里的 JS，本文件用 CDP 驱动真实 Chrome。
//! - 每个 `#[test]` 先取 `common::serial()` 跨进程串行锁（cargo 会并行跑 tests/*.rs，且同文件
//!   内测试也并行）；无 Chrome 时打印跳过并正常 return（不能 fail）。
//! - 场景编号与旧 .mjs 的 `ok()` 一一对应，共 19 条断言（见每个测试的函数注释）。
//! - 服务器统一传 `HOST=""`（恢复"回环 + 局域网网卡"自动绑定，链路里 publicOrigin 会升级为
//!   LAN 地址）与 `CIPHERLANE_EXTRA_HOSTS=cipherlane-insecure.test`（第 9 组非安全上下文用假
//!   域名；Chrome 启动参数里已有 host-resolver-rules 映射到 127.0.0.1）。
mod common;

use common::{hex, random_bytes, Cdp, Chrome, Page, Server};
use serde_json::{json, Value};
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------- 通用小工具 ----------

fn sleep_ms(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

fn ok(name: &str) {
    println!("  ✓ {name}");
}

fn jstr(s: &str) -> String {
    serde_json::to_string(s).expect("JSON 编码失败")
}

/// 把模板里的 `__TOKEN__` 替换成实际 JS 字面量（调用方用 jstr 保证字符串安全）。
fn js(tmpl: &str, vars: &[(&str, &str)]) -> String {
    let mut out = tmpl.to_string();
    for (k, v) in vars {
        out = out.replace(k, v);
    }
    out
}

fn text_of(sel: &str) -> String {
    format!("document.querySelector('{sel}') ? document.querySelector('{sel}').textContent : null")
}

fn eval_text(cdp: &mut Cdp, p: &Page, expr: &str) -> String {
    match cdp.eval(p, expr) {
        Value::String(s) => s,
        Value::Null => String::new(),
        v => v.to_string(),
    }
}

fn text(cdp: &mut Cdp, p: &Page, sel: &str) -> String {
    eval_text(cdp, p, &text_of(sel))
}

fn eval_bool(cdp: &mut Cdp, p: &Page, expr: &str) -> bool {
    cdp.eval(p, expr).as_bool().unwrap_or(false)
}

fn eval_i64(cdp: &mut Cdp, p: &Page, expr: &str) -> i64 {
    cdp.eval(p, expr).as_i64().unwrap_or(-1)
}

fn eval_f64(cdp: &mut Cdp, p: &Page, expr: &str) -> f64 {
    cdp.eval(p, expr).as_f64().unwrap_or(f64::NAN)
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn origin_of(url: &str) -> String {
    match url.strip_prefix("http://") {
        Some(rest) => {
            let hostport = rest.split('/').next().unwrap_or("");
            format!("http://{hostport}")
        }
        None => "null".to_string(),
    }
}

/// 导航并等到"新文档就绪且 origin 匹配"（避免 Page.navigate 返回后仍读到旧文档）。
fn nav(cdp: &mut Cdp, p: &Page, url: &str) {
    cdp.send(Some(&p.sid), "Page.navigate", json!({ "url": url }));
    let origin = origin_of(url);
    let expr = format!(
        "document.readyState === 'complete' && location.origin === {}",
        jstr(&origin)
    );
    cdp.wait_for(p, &expr, 25000, &format!("页面加载 {url}"));
}

/// 启动 Chrome + Rust 服务器 + CDP 连接。无 Chrome 时按策略跳过或失败（见 chrome_or_note）。
fn boot() -> Option<(Server, Chrome, Cdp)> {
    let chrome = common::chrome_or_note("browser 套件")?;
    // HOST="" → 自动绑定 127.0.0.1 + 局域网网卡（与旧 .mjs 的 Node 服务端一致，LAN 链接可达）
    let srv = common::spawn_server(&[
        ("HOST", ""),
        ("CIPHERLANE_EXTRA_HOSTS", "cipherlane-insecure.test"),
    ]);
    let cdp = Cdp::connect(&chrome.ws_url);
    Some((srv, chrome, cdp))
}

/// hidden 不变量：所有带 hidden 的元素计算样式必须是 display:none（历史 P0：自定义 display 覆盖）。
fn hidden_bad(cdp: &mut Cdp, p: &Page) -> Vec<String> {
    let v = cdp.eval(
        p,
        r#"[...document.querySelectorAll('[hidden]')]
  .filter((el) => getComputedStyle(el).display !== 'none')
  .map((el) => el.id || el.className)"#,
    );
    serde_json::from_value(v).unwrap_or_default()
}

fn assert_hidden_ok(cdp: &mut Cdp, p: &Page, when: &str) {
    let bad = hidden_bad(cdp, p);
    if !bad.is_empty() {
        panic!("hidden 属性被 display 覆盖（{when}）: {}", bad.join(","));
    }
}

// =====================================================================================
// 场景 1/19：公钥指纹显示（32 hex = 128bit TOFU 锚点）
// =====================================================================================
#[test]
fn t01_fingerprint_128bit() {
    let _g = common::serial();
    let Some((srv, _chrome, mut cdp)) = boot() else { return };
    let s = srv.url();
    let a = cdp.new_page();
    nav(&mut cdp, &a, &format!("{s}/"));
    cdp.wait_for(
        &a,
        r#"document.querySelector('#me-fp') && /^#[0-9a-f]{32}$/.test(document.querySelector('#me-fp').textContent.trim())"#,
        20000,
        "本机指纹显示",
    );
    ok("公钥指纹显示:本机名片 32 位十六进制(128bit)");
}

// =====================================================================================
// 场景 2/19：链接模式文本全链路 + 返回首页 hash 清理 + 延迟邀请补画（回归）
// =====================================================================================
#[test]
fn t02_text_link_and_back_home() {
    let _g = common::serial();
    let Some((srv, _chrome, mut cdp)) = boot() else { return };
    let s = srv.url();
    let a = cdp.new_page();
    let b = cdp.new_page();
    nav(&mut cdp, &a, &format!("{s}/"));
    nav(&mut cdp, &b, &format!("{s}/"));

    let secret = format!("浏览器 E2E 冒烟 ✅ 中文与 emoji 🚀 {}", hex(&random_bytes(8)));
    cdp.eval(
        &a,
        &format!("document.querySelector('#text').value = {}", jstr(&secret)),
    );
    cdp.eval(&a, "document.querySelector('#send-text').click()");
    cdp.wait_for(
        &a,
        "document.querySelector('#link').textContent.startsWith('http')",
        25000,
        "生成接收链接",
    );
    let link = text(&mut cdp, &a, "#link");
    nav(&mut cdp, &b, &link);
    cdp.wait_for(&b, "!document.querySelector('#recv-text').hidden", 45000, "接收视图出现");
    let got = text(&mut cdp, &b, "#recv-text");
    if got != secret {
        panic!("文本不一致:\n  期望 {secret:?}\n  实际 {got:?}");
    }
    cdp.wait_for(
        &b,
        "document.querySelector('#recv-text-status').textContent.includes('已解密接收')",
        20000,
        "接收完成状态",
    );
    // ack 凭证闭环：接收方带 proof ack → 发送方轮询本地校验通过
    cdp.wait_for(
        &a,
        "document.querySelector('#send-status').textContent.includes('凭证校验通过')",
        20000,
        "发送方凭证校验",
    );

    // 返回首页：hash 清理 + 延迟邀请补画（回归：曾不刷新/不补画）
    cdp.eval(&b, "document.querySelector('#recv-text-back').click()");
    cdp.wait_for(&b, "!document.querySelector('#view-landing').hidden", 20000, "返回首页");
    let hash_now = eval_text(&mut cdp, &b, "location.hash");
    if !hash_now.is_empty() {
        panic!("返回后地址栏 hash 未清除: {hash_now}");
    }
    // 模拟一条在接收视图期间到达的邀请：注入后经 showView 往返，应被补画
    cdp.eval(
        &b,
        r#"(async () => {
  const kp = X25519.genKey()
  const key = X25519.sessionKey(X25519.dh(identity.sk, kp.pk), kp.pk, identity.pk, 'Ab3xYz9kLm')
  const hint = toB64(await sealWith(key, enc.encode(JSON.stringify({ kind: 'text', size: 12 }))))
  incomingOffers.set('fake01', { id: 'fake01', room: 'Ab3xYz9kLm', pub: toB64(kp.pk), hint, from: { ip: '192.168.137.9', name: '延迟到达的邀请' } })
  showView('recv')
  showView('landing')
})()"#,
    );
    cdp.wait_for(&b, "!document.querySelector('#incoming-wrap').hidden", 20000, "延迟邀请区域可见");
    cdp.wait_for(
        &b,
        r#"[...document.querySelectorAll('.o-name')].some((x) => x.textContent.includes('延迟到达的邀请'))"#,
        10000,
        "邀请卡",
    );
    cdp.eval(&b, "incomingOffers.delete('fake01'); renderIncoming()");
    ok("返回首页:hash 清理 + 设备立即刷新 + 延迟邀请补画(回归)");
    assert_hidden_ok(&mut cdp, &b, "返回首页后");
}

// =====================================================================================
// 场景 3/19：协议 v2 错位分片（AAD 绑定位置）必须被拒绝且不 ack
// =====================================================================================
#[test]
fn t03_aad_misplaced_chunk_rejected() {
    let _g = common::serial();
    let Some((srv, _chrome, mut cdp)) = boot() else { return };
    // 构造端放在"非安全上下文"（假域名）→ 纯 JS AESGCM 可用，与旧 .mjs 一致
    let b = cdp.new_page();
    nav(&mut cdp, &b, &format!("http://cipherlane-insecure.test:{}/", srv.port));

    let setup = cdp.eval(
        &b,
        r#"(async () => {
  const created = await (await fetch('/api/rooms', { method: 'POST' })).json()
  const room = created.room, token = created.token
  const key = crypto.getRandomValues(new Uint8Array(32))
  const meta = { v: 2, type: 'file', name: 'aad-misplaced.bin', mime: 'application/octet-stream', size: CHUNK, count: 2 }
  const AAD = (i) => enc.encode('cipherlane/chunk/v2|' + room + '|' + i)
  const seal = (pt, aadBytes) => AESGCM.seal(key, pt, aadBytes)
  const post = async (bytes) => {
    for (;;) {
      const r = await fetch('/api/rooms/' + room + '/chunk', { method: 'POST', headers: { 'X-Room-Token': token }, body: bytes })
      if (r.status === 429) { await new Promise((res) => setTimeout(res, 100)); continue }
      if (!r.ok) throw new Error('post chunk ' + r.status)
      return
    }
  }
  await post(seal(enc.encode(JSON.stringify(meta)), AAD(0))) // meta 用正确 AAD
  const data = new Uint8Array(CHUNK).fill(7)
  const misplaced = seal(data, AAD(0)) // 故意用 0 号 AAD 放到 1 号位置
  await post(misplaced)
  // 正控：用其原始 AAD(0) 可解 → 失败确实来自位置绑定而非密文损坏
  const controlOk = AESGCM.open(key, misplaced, AAD(0)).length === CHUNK
  // 旧实现（无 AAD）对位置完全盲：旧格式无 AAD 密文在任何 index 都能解
  const blindOk = AESGCM.open(key, seal(data, null)).length === CHUNK
  return { link: publicOrigin() + '/#' + room + '.' + toB64(key), room, controlOk, blindOk }
})()"#,
    );
    if !setup["controlOk"].as_bool().unwrap_or(false) {
        panic!("构造错误:错位密文用其原始 AAD 应可解开");
    }
    if !setup["blindOk"].as_bool().unwrap_or(false) {
        panic!("构造错误:旧无 AAD 格式应能解开（位置盲证明失败）");
    }
    let room = setup["room"].as_str().expect("room").to_string();
    let link = setup["link"].as_str().expect("link").to_string();

    nav(&mut cdp, &b, &link);
    cdp.wait_for(
        &b,
        "document.querySelector('#recv-file-status').textContent.startsWith('❌')",
        30000,
        "错位分片报错",
    );
    let err_text = text(&mut cdp, &b, "#recv-file-status");
    if err_text.contains("已保存") {
        panic!("错位分片不应被当作成功: {err_text}");
    }
    if !(err_text.contains("GCM") || err_text.contains("解密") || err_text.contains("验签")) {
        panic!("错位分片应以验签失败报错,实际: {err_text}");
    }
    let acked = eval_bool(
        &mut cdp,
        &b,
        &js(
            r#"(async () => (await (await fetch('/api/rooms/__ROOM__/state')).json()).acked)()"#,
            &[("__ROOM__", &room)],
        ),
    );
    if acked {
        panic!("错位分片失败后不应 ack");
    }
    ok("协议 v2 错位分片被拒绝且不 ack（旧无 AAD 实现位置盲：blindOk 已证）");
}

// =====================================================================================
// 场景 4/19：邀请 TOFU —— 发送方公钥变化 → 卡片警示 + 接受前确认（取消不接收）
// =====================================================================================
#[test]
fn t04_offer_tofu_warning() {
    let _g = common::serial();
    let Some((srv, _chrome, mut cdp)) = boot() else { return };
    let s = srv.url();
    let b = cdp.new_page();
    nav(&mut cdp, &b, &format!("{s}/"));
    cdp.wait_for(&b, "!document.querySelector('#view-landing').hidden", 20000, "回到首页");
    cdp.eval(
        &b,
        r#"(async () => {
  const room = 'Ab3xYz9kLm'
  const kp = X25519.genKey()
  const key = X25519.sessionKey(X25519.dh(identity.sk, kp.pk), kp.pk, identity.pk, room)
  const hint = await sealWith(key, enc.encode(JSON.stringify({ kind: 'text', size: 3 })))
  const known = knownPubs.load()
  known['192.168.137.9'] = toB64(X25519.genKey().pk) // 记录不同公钥 → 触发变化
  knownPubs.save(known)
  incomingOffers.set('tofu01', { id: 'tofu01', room, pub: toB64(kp.pk), hint: toB64(hint), from: { ip: '192.168.137.9', name: 'TOFU 发送方' } })
  renderIncoming()
})()"#,
    );
    cdp.wait_for(
        &b,
        r#"[...document.querySelectorAll('.o-fp-warn')].some((x) => !x.hidden && x.textContent.includes('公钥已变化'))"#,
        10000,
        "邀请卡片 TOFU 警示",
    );
    cdp.wait_for(&b, "!document.querySelector('.o-accept').disabled", 20000, "预览解密完成");
    cdp.eval(&b, "document.querySelector('.o-accept').click()");
    cdp.wait_for(&b, "!document.querySelector('#modal-mask').hidden", 20000, "邀请 TOFU 确认弹窗");
    let title = text(&mut cdp, &b, "#modal-title");
    if !title.contains("公钥已变化") {
        panic!("邀请确认弹窗应提示公钥变化,实际: {title}");
    }
    cdp.eval(&b, "document.querySelector('#modal-cancel').click()");
    cdp.wait_for(&b, "document.querySelector('#modal-mask').hidden", 6000, "取消弹窗");
    let still = eval_bool(
        &mut cdp,
        &b,
        "incomingOffers.has('tofu01') && !document.querySelector('#view-landing').hidden",
    );
    if !still {
        panic!("取消后邀请应保留且不得进入接收");
    }
    cdp.eval(&b, "incomingOffers.delete('tofu01'); renderIncoming()");
    ok("邀请 TOFU：发送方公钥变化 → 卡片警示 + 接受前确认，取消不接收");
}

// =====================================================================================
// 场景 5/19：定向发送到离线设备 —— 建立失败必须有"返回首页"退路（回归：曾死锁）
// =====================================================================================
#[test]
fn t05_offline_device_has_exit() {
    let _g = common::serial();
    let Some((srv, _chrome, mut cdp)) = boot() else { return };
    let s = srv.url();
    let a = cdp.new_page();
    nav(&mut cdp, &a, &format!("{s}/"));
    // 等启动心跳落定（#me-fp 在首轮 heartbeat 后才有值），减少 page-load 期
    // `heartbeat().then(refreshDevices)` 的陈旧回调把注入设备覆盖掉的窗口。
    cdp.wait_for(
        &a,
        r#"document.querySelector('#me-fp') && /^#[0-9a-f]{32}$/.test(document.querySelector('#me-fp').textContent.trim())"#,
        20000,
        "首页心跳就绪",
    );
    // 注入幽灵设备 + 选中 + 点击发送放在同一个同步 eval：startSend 在点击处理里同步
    // 捕获 selectedDevice()，此后即使陈旧 refreshDevices 落地也无法改掉本次 target。
    cdp.eval(
        &a,
        r#"(() => {
  // 桩掉心跳设备刷新:注入的幽灵设备若恰逢 5s 心跳,会被真实列表覆盖
  // (selectedDevice 落空走"离线"分支,本场景等待的报错不出现)
  refreshDevices = () => {}
  deviceCache = deviceCache.filter((d) => d.ip !== '10.99.0.5')
  deviceCache.push({ ip: '10.99.0.5', id: 'ghost', name: '幽灵设备', pub: toB64(X25519.genKey().pk) })
  selectedIp = '10.99.0.5'
  renderDevices()
  document.querySelector('#text').value = '去往幽灵设备的消息'
  document.querySelector('#send-text').click()
})()"#,
    );
    cdp.wait_for(
        &a,
        "document.querySelector('#send-status').textContent.includes('建立密道失败')",
        25000,
        "离线设备报错",
    );
    let cancel_text = text(&mut cdp, &a, "#cancel-send");
    if cancel_text != "返回首页" {
        panic!("失败后取消按钮应为\"返回首页\",实际: {cancel_text}");
    }
    cdp.eval(&a, "document.querySelector('#cancel-send').click()");
    cdp.wait_for(&a, "!document.querySelector('#view-landing').hidden", 20000, "返回首页");
    cdp.eval(
        &a,
        "selectedIp = null; deviceCache = deviceCache.filter((d) => d.ip !== '10.99.0.5'); renderDevices()",
    );
    ok("定向到离线设备:报\"建立密道失败\" + \"返回首页\"可退(回归覆盖)");
}

// =====================================================================================
// 场景 6/19：直发 TOFU —— 目标公钥变化必须先弹确认，取消则绝不发送
// =====================================================================================
#[test]
fn t06_direct_tofu_confirm() {
    let _g = common::serial();
    let Some((srv, _chrome, mut cdp)) = boot() else { return };
    let s = srv.url();
    let a = cdp.new_page();
    nav(&mut cdp, &a, &format!("{s}/"));
    let warned = eval_i64(
        &mut cdp,
        &a,
        r#"(() => {
  refreshDevices = () => {}
  const kp = X25519.genKey()
  deviceCache.push({ ip: '10.99.0.6', id: 'tofu', name: 'TOFU设备', pub: toB64(kp.pk) })
  const known = knownPubs.load()
  known['10.99.0.6'] = toB64(X25519.genKey().pk) // 记录一把不同公钥 → 触发变化
  knownPubs.save(known)
  selectedIp = '10.99.0.6'
  renderDevices()
  return document.querySelectorAll('.device.fp-changed').length
})()"#,
    );
    if warned < 1 {
        panic!("公钥变化设备卡应有\"⚠ 公钥已变化\"警示");
    }
    cdp.eval(&a, "document.querySelector('#text').value = 'TOFU 确认测试'");
    cdp.eval(&a, "document.querySelector('#send-text').click()");
    cdp.wait_for(&a, "!document.querySelector('#modal-mask').hidden", 20000, "直发 TOFU 确认弹窗");
    let title = text(&mut cdp, &a, "#modal-title");
    if !title.contains("公钥已变化") {
        panic!("确认弹窗应提示公钥变化,实际: {title}");
    }
    cdp.eval(&a, "document.querySelector('#modal-cancel').click()");
    cdp.wait_for(&a, "document.querySelector('#modal-mask').hidden", 6000, "取消关闭弹窗");
    if !eval_bool(&mut cdp, &a, "!document.querySelector('#view-landing').hidden") {
        panic!("取消后应留在首页（不发送）");
    }
    cdp.eval(
        &a,
        "selectedIp = null; deviceCache = deviceCache.filter((d) => d.ip !== '10.99.0.6'); renderDevices()",
    );
    ok("直发 TOFU：公钥变化弹确认，取消后不发送");
}

// =====================================================================================
// 场景 7/19：同序号并发拉取 —— X-Resume 只读回放，双双拿到同一份（回归：曾 500+挂起）
// =====================================================================================
#[test]
fn t07_concurrent_same_index() {
    let _g = common::serial();
    let Some((srv, _chrome, mut cdp)) = boot() else { return };
    let s = srv.url();
    let a = cdp.new_page();
    nav(&mut cdp, &a, &format!("{s}/"));
    let concurrent = eval_text(
        &mut cdp,
        &a,
        r#"(async () => {
  const r = await fetch('/api/rooms', { method: 'POST' })
  const { room, token } = await r.json()
  const p1 = getChunk(room, 0)   // 分片未投:两个都进长轮询等待
  const p2 = getChunk(room, 0)
  setTimeout(() => fetch('/api/rooms/' + room + '/chunk', {
    method: 'POST', headers: { 'X-Room-Token': token }, body: new Uint8Array([1, 2, 3]),
  }), 500)
  const [a, b] = await Promise.all([p1, p2])
  const same = a.length === b.length && a.every((x, i) => x === b[i])
  return same ? 'same' : 'diff(' + a.length + '/' + b.length + ')'
})()"#,
    );
    if concurrent != "same" {
        panic!("只读回放应返回同一份: {concurrent}");
    }
    ok("同序号并发拉取:X-Resume 只读回放返回同一份数据(回归覆盖)");
}

// =====================================================================================
// 场景 8/19：文件传输全链路 —— 真实 Worker 加密 + 接收方保存完成
// =====================================================================================
#[test]
fn t08_file_roundtrip_worker_pool() {
    let _g = common::serial();
    let Some((srv, _chrome, mut cdp)) = boot() else { return };
    let s = srv.url();
    let a = cdp.new_page();
    let b = cdp.new_page();
    nav(&mut cdp, &a, &format!("{s}/"));

    let dir = common::unique_dir("e2e-file");
    let file_name = format!("e2e-{}.bin", now_nanos());
    let file_path = dir.join(&file_name);
    fs::write(&file_path, random_bytes(5 * 1024 * 1024)).expect("写测试文件失败");

    cdp.eval(&a, "document.querySelector('#text').value = ''");
    cdp.set_files(&a, "#file", &[file_path.clone()]);
    cdp.eval(&a, "document.querySelector('#file').onchange()");
    cdp.wait_for(
        &a,
        "document.querySelector('#link').textContent.startsWith('http')",
        25000,
        "文件发送链接",
    );
    let file_link = text(&mut cdp, &a, "#link");
    nav(&mut cdp, &b, &file_link);
    let name_js = js(
        "document.querySelector('#fc-name').textContent === __NAME__",
        &[("__NAME__", &jstr(&file_name))],
    );
    cdp.wait_for(&b, &name_js, 45000, "接收文件卡");
    cdp.wait_for(
        &b,
        "document.querySelector('#recv-file-status').textContent.includes('已保存')",
        90000,
        "文件接收完成",
    );
    // 结构断言：加密确实走了 Worker 池而非静默回退主线程（回退路径数据同样正确，须单独验证）
    let workers = eval_i64(
        &mut cdp,
        &a,
        "performance.getEntriesByType('resource').filter((e) => e.name.includes('crypto-worker.js')).length",
    );
    if workers < 2 {
        panic!("加密未走 Worker 池(实例数 {workers}),疑似静默回退主线程");
    }
    ok(&format!(
        "文件传输全链路:Worker 池加密(×{workers}) → 5MiB 分片 → 接收方保存完成"
    ));
    let _ = fs::remove_file(&file_path);
}

// =====================================================================================
// 场景 9/19：纯 JS AES 降级路径（安全上下文发送 ↔ 非安全上下文接收，逐字一致）
// =====================================================================================
#[test]
fn t09_pure_js_aes_downgrade() {
    let _g = common::serial();
    let Some((srv, _chrome, mut cdp)) = boot() else { return };
    let s = srv.url();
    let a = cdp.new_page();
    let c = cdp.new_page();
    nav(&mut cdp, &c, &format!("http://cipherlane-insecure.test:{}/", srv.port));
    let ctx = cdp.eval(
        &c,
        "({ subtle: typeof crypto !== 'undefined' && !!crypto.subtle, aesgcm: typeof AESGCM })",
    );
    if ctx["subtle"].as_bool() != Some(false) || ctx["aesgcm"].as_str() != Some("object") {
        panic!("预期非安全上下文(无 subtle、有纯 JS AESGCM),实际: {ctx}");
    }
    nav(&mut cdp, &a, &format!("{s}/"));
    let secret2 = format!("纯 JS AES 降级路径互操作 🐢 {}", hex(&random_bytes(6)));
    cdp.eval(
        &a,
        &format!("document.querySelector('#text').value = {}", jstr(&secret2)),
    );
    cdp.eval(&a, "document.querySelector('#send-text').click()");
    cdp.wait_for(
        &a,
        "document.querySelector('#link').textContent.startsWith('http')",
        25000,
        "降级路径链接",
    );
    let link = text(&mut cdp, &a, "#link");
    // 强制用假域名 origin 接收：非 localhost 明文 http → 无 crypto.subtle，走纯 JS AES-GCM
    let frag = &link[link.find('#').expect("link 无 fragment")..];
    let link2 = format!("http://cipherlane-insecure.test:{}/{}", srv.port, frag);
    nav(&mut cdp, &c, &link2);
    cdp.wait_for(&c, "!document.querySelector('#recv-text').hidden", 45000, "降级路径接收");
    let got2 = text(&mut cdp, &c, "#recv-text");
    if got2 != secret2 {
        panic!("降级路径文本不一致:\n  期望 {secret2:?}\n  实际 {got2:?}");
    }
    cdp.wait_for(
        &c,
        "document.querySelector('#recv-text-status').textContent.includes('已解密接收')",
        20000,
        "降级路径完成",
    );
    ok("纯 JS AES 降级路径:安全上下文发送 ↔ 非安全上下文接收逐字一致(跨实现互通)");
}

// =====================================================================================
// 场景 10/19：多文件批量 —— 多选 → 链接 → 批量接收（内存模式逐个下载）
// =====================================================================================
#[test]
fn t10_batch_receive() {
    let _g = common::serial();
    let Some((srv, _chrome, mut cdp)) = boot() else { return };
    let s = srv.url();
    let a = cdp.new_page();
    let b = cdp.new_page();
    nav(&mut cdp, &a, &format!("{s}/"));

    let dir = common::unique_dir("e2e-batch");
    let bf1 = dir.join("batch-a.bin");
    let bf2 = dir.join("batch-b.txt");
    fs::write(&bf1, random_bytes(700000)).expect("写 batch-a 失败"); // 不足一片
    fs::write(&bf2, random_bytes(1000)).expect("写 batch-b 失败");
    cdp.set_files(&a, "#file", &[bf1.clone(), bf2.clone()]); // 多选
    cdp.eval(&a, "document.querySelector('#file').onchange()");
    cdp.wait_for(
        &a,
        "document.querySelector('#link').textContent.startsWith('http')",
        25000,
        "批量链接",
    );
    let batch_link = text(&mut cdp, &a, "#link");
    nav(&mut cdp, &b, &batch_link);
    cdp.wait_for(
        &b,
        "document.querySelector('#fc-name').textContent === '2 个文件'",
        45000,
        "批量文件卡",
    );
    cdp.wait_for(
        &b,
        "document.querySelector('#recv-file-status').textContent.includes('已接收 2 个文件')",
        45000,
        "批量完成",
    );
    let _ = fs::remove_file(&bf1);
    let _ = fs::remove_file(&bf2);
    ok("多文件批量:双文件选择 → 链接 → 接收完成(内存模式)");
}

// =====================================================================================
// 场景 11/19：断点续传（内存模式）—— 中途重导航 → IDB 记录 → 从断点续传完成
// =====================================================================================
#[test]
fn t11_resume_memory_mode() {
    let _g = common::serial();
    let Some((srv, _chrome, mut cdp)) = boot() else { return };
    let s = srv.url();
    let a = cdp.new_page();
    let b = cdp.new_page();
    nav(&mut cdp, &a, &format!("{s}/"));

    let dir = common::unique_dir("e2e-resume");
    let rf = dir.join("resume-16m.bin");
    fs::write(&rf, random_bytes(24 * 1024 * 1024)).expect("写续传文件失败");
    cdp.set_files(&a, "#file", &[rf.clone()]);
    cdp.eval(&a, "document.querySelector('#file').onchange()");
    cdp.wait_for(
        &a,
        "document.querySelector('#link').textContent.startsWith('http')",
        25000,
        "续传链接",
    );
    let rlink = text(&mut cdp, &a, "#link");
    let room = rlink
        .split('#')
        .nth(1)
        .and_then(|x| x.split('.').next())
        .expect("链接缺少 room")
        .to_string();
    nav(&mut cdp, &b, &rlink);
    // 显式轮询（waitFor 对 async 表达式恒真，不适用）
    let mut d = 0i64;
    for _ in 0..300 {
        if d >= 2 {
            break;
        }
        d = eval_i64(
            &mut cdp,
            &b,
            &js(
                r#"(async () => (await resumeDB.get(__ROOM__))?.done || 0)()"#,
                &[("__ROOM__", &jstr(&room))],
            ),
        );
        if d < 2 {
            sleep_ms(150);
        }
    }
    if d < 2 {
        panic!("IDB 进度未达 2 片(实际 {d})");
    }
    // "刷新/崩溃"：关闭接收页再重开同源文档。close 前尽力冻结页面（CDP 失败忽略），
    // 消除"关闭生效前接收方继续推进到完成、IDB 断点记录被删除"的竞态。
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cdp.send(Some(&b.sid), "Page.setWebLifecycleState", json!({ "state": "frozen" }));
    }));
    cdp.close_page(&b);
    let b2 = cdp.new_page();
    nav(&mut cdp, &b2, &rlink);
    cdp.wait_for(
        &b2,
        "document.querySelector('#start-recv').textContent.includes('继续接收')",
        25000,
        "续传按钮",
    );
    let done_at_kill = eval_i64(
        &mut cdp,
        &b2,
        &js(
            r#"(async () => (await resumeDB.get(__ROOM__))?.done || 0)()"#,
            &[("__ROOM__", &jstr(&room))],
        ),
    );
    cdp.eval(&b2, "document.querySelector('#start-recv').click()");
    cdp.wait_for(
        &b2,
        "document.querySelector('#recv-file-status').textContent.includes('已保存')",
        90000,
        "续传完成",
    );
    // 重进后的新文档不应重拉已持久化的分片；i=0 是元信息重读（设计内），排除后首片数据应从断点之后开始
    let min_i = eval_f64(
        &mut cdp,
        &b2,
        r#"Math.min(...performance.getEntriesByType('resource').map((e) => /chunk\?i=(\d+)/.exec(e.name)).filter(Boolean).map((m) => +m[1]).filter((i) => i > 0))"#,
    );
    if !(min_i > done_at_kill as f64) {
        panic!("续传应从第 {} 片开始,实际首拉 i={min_i}", done_at_kill + 1);
    }
    let _ = fs::remove_file(&rf);
    ok(&format!("断点续传:中途重导航 → IDB 记录 → 从第 {min_i} 片续传完成"));
}

// =====================================================================================
// 场景 12/19：身份重置 —— 模态取消无副作用 / 确认后指纹·密钥更换·服务器公钥同步
// =====================================================================================
#[test]
fn t12_identity_reset() {
    let _g = common::serial();
    let Some((srv, _chrome, mut cdp)) = boot() else { return };
    let s = srv.url();
    let a = cdp.new_page();
    let sibling = cdp.new_page();
    nav(&mut cdp, &a, &format!("{s}/"));
    nav(&mut cdp, &sibling, &format!("{s}/"));
    // 停掉兄弟页：它与 sidA 同 IP（共享同一设备条目），其心跳会在公钥同步断言窗口内
    // 把 sidA 的新公钥覆盖回旧值；导航到 about:blank 让页面 JS 与心跳确定性停止。
    nav(&mut cdp, &sibling, "about:blank");

    cdp.wait_for(
        &a,
        r#"/^#[0-9a-f]{32}$/.test(document.querySelector('#me-fp').textContent.trim())"#,
        20000,
        "重置前指纹",
    );
    let fp1 = eval_text(&mut cdp, &a, "document.querySelector('#me-fp').textContent.trim()");
    let sk1 = cdp.eval(&a, "localStorage.getItem('cipherlane-sk')");

    // 取消路径：模态出现 → 取消 → 指纹/密钥不变；破坏性操作默认焦点在取消
    cdp.eval(&a, "document.querySelector('#me-reset').click()");
    cdp.wait_for(&a, "!document.querySelector('#modal-mask').hidden", 6000, "模态出现");
    let focused = eval_text(&mut cdp, &a, "document.activeElement.id");
    if focused != "modal-cancel" {
        panic!("破坏性操作默认焦点应在取消,实际: {focused}");
    }
    cdp.eval(&a, "document.querySelector('#modal-cancel').click()");
    cdp.wait_for(&a, "document.querySelector('#modal-mask').hidden", 6000, "模态关闭");
    assert_hidden_ok(&mut cdp, &a, "取消后");
    if eval_text(&mut cdp, &a, "document.querySelector('#me-fp').textContent.trim()") != fp1 {
        panic!("取消不应改变指纹");
    }

    // 确认路径：重置 → reload → 指纹/密钥更换，服务器公钥同步
    cdp.eval(&a, "document.querySelector('#me-reset').click()");
    cdp.wait_for(&a, "!document.querySelector('#modal-mask').hidden", 6000, "模态再次出现");
    cdp.eval(&a, "document.querySelector('#modal-ok').click()");
    let reload_expr = js(
        r#"document.readyState === 'complete' && document.querySelector('#me-fp') && /^#[0-9a-f]{32}$/.test(document.querySelector('#me-fp').textContent.trim()) && document.querySelector('#me-fp').textContent.trim() !== __FP1__"#,
        &[("__FP1__", &jstr(&fp1))],
    );
    cdp.wait_for(&a, &reload_expr, 25000, "reload 后新指纹");
    let sk2 = cdp.eval(&a, "localStorage.getItem('cipherlane-sk')");
    if sk2 == sk1 {
        panic!("密钥未更换");
    }
    let pub_page = eval_text(&mut cdp, &a, "toB64(identity.pk)");
    let mut synced = false;
    for _ in 0..60 {
        let pub_srv = eval_text(
            &mut cdp,
            &a,
            r#"(async () => (await (await fetch('/api/devices')).json()).devices.find((d) => d.ip === '127.0.0.1')?.pub || '')()"#,
        );
        if pub_srv == pub_page {
            synced = true;
            break;
        }
        sleep_ms(250);
    }
    if !synced {
        panic!("服务器公钥未同步为新身份");
    }
    ok("身份重置:模态取消无副作用 / 确认后指纹·密钥更换·服务器公钥同步");
}

// =====================================================================================
// 场景 13/14/15（3 条 ok）：FSA 流式保存 + 续传断点一致性
//   a) userActivation.isActive 是布尔属性，旧 isActive() 必抛 TypeError → FSA 分支死代码
//   b) fs 模式 done 不落盘 → 刷新后按陈旧断点重拉已释放分片 → 410
// 用 OPFS 真实句柄冒充文件选择器结果，让 createWritable/绝对定位写/IDB 句柄持久化真跑。
// =====================================================================================
#[test]
fn t13_fsa_streaming_and_resume() {
    let _g = common::serial();
    let Some((srv, _chrome, mut cdp)) = boot() else { return };
    let s = srv.url();
    let a = cdp.new_page();
    nav(&mut cdp, &a, &format!("{s}/"));

    let setup = cdp.eval(
        &a,
        r#"(async () => {
  const size = 12 * CHUNK - 12345
  const plain = new Uint8Array(size)
  // getRandomValues 单次上限 64KiB(QuotaExceededError),按 64KiB 循环填满
  for (let off = 0; off < size; off += 65536) crypto.getRandomValues(plain.subarray(off, Math.min(off + 65536, size)))
  const created = await (await fetch('/api/rooms', { method: 'POST' })).json()
  const room = created.room, token = created.token
  const key = crypto.getRandomValues(new Uint8Array(32))
  const meta = { v: 1, type: 'file', name: 'fsa-resume-e2e.bin', mime: 'application/octet-stream', size, count: 13 }
  const seal = async (pt) => {
    const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt'])
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, pt))
    const out = new Uint8Array(12 + ct.length)
    out.set(iv); out.set(ct, 12)
    return out
  }
  const chunks = []
  for (let off = 0; off < size; off += CHUNK) chunks.push(plain.subarray(off, Math.min(off + CHUNK, size)))
  // seq = 分片全局序号（X-Chunk-Seq 幂等序号；meta=0，数据从 1 连续）
  const post = async (seq, bytes) => {
    for (;;) {
      const r = await fetch('/api/rooms/' + room + '/chunk', {
        method: 'POST',
        headers: { 'X-Room-Token': token, 'X-Chunk-Seq': String(seq) },
        body: bytes,
      })
      if (r.status === 429) { await new Promise((res) => setTimeout(res, 100)); continue }
      if (!r.ok) throw new Error('post chunk ' + r.status)
      return
    }
  }
  await post(0, await seal(enc.encode(JSON.stringify(meta))))
  for (let i = 0; i < 9; i++) await post(i + 1, await seal(chunks[i])) // 只投前 9 片:接收方会在第 8 片写出持久化检查点后停住
  const dig = [...new Uint8Array(await crypto.subtle.digest('SHA-256', plain))]
    .map((b) => b.toString(16).padStart(2, '0')).join('')
  window.__fsa = { room, token, rest: chunks.slice(9), nextSeq: 10, post, seal }
  return { link: publicOrigin() + '/#' + room + '.' + toB64(key), room, size, dig }
})()"#,
    );
    let setup_room = setup["room"].as_str().expect("room").to_string();
    let setup_size = setup["size"].as_i64().expect("size");
    let setup_dig = setup["dig"].as_str().expect("dig").to_string();
    let setup_link = setup["link"].as_str().expect("link").to_string();
    let frag = setup_link[setup_link.find('#').expect("link 无 fragment")..].to_string();

    // 每个新文档都注入桩：用 OPFS 里真实 FileSystemFileHandle 冒充选择器结果
    //（可结构化克隆，会被存进 IDB 供刷新后续传）。
    let picker_stub = r#"
(() => {
  const stub = async (opts) => {
    window.__pickerCalls = (window.__pickerCalls || 0) + 1
    window.__pickerName = opts && opts.suggestedName
    const root = await navigator.storage.getDirectory()
    return await root.getFileHandle('fsa-picked.bin', { create: true })
  }
  try { Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, value: stub }) }
  catch { try { window.showSaveFilePicker = stub } catch {} }
})()
"#;
    let d = cdp.new_page();
    cdp.send(
        Some(&d.sid),
        "Page.addScriptToEvaluateOnNewDocument",
        json!({ "source": picker_stub }),
    );
    nav(&mut cdp, &d, &format!("{s}/"));

    // ① 直接回归：属性类型 / 旧写法必抛错 / helper 在手势下为 true
    let act = cdp.eval_gesture(
        &d,
        r#"(() => {
  let oldThrew = false
  try { navigator.userActivation.isActive() } catch { oldThrew = true }
  return { type: typeof navigator.userActivation.isActive, oldThrew, helper: hasUserGesture() }
})()"#,
    );
    if act["type"].as_str() != Some("boolean") {
        panic!("userActivation.isActive 应为布尔属性,实际: {}", act["type"]);
    }
    if !act["oldThrew"].as_bool().unwrap_or(false) {
        panic!("旧写法 isActive() 应抛 TypeError(属性不是方法)");
    }
    if !act["helper"].as_bool().unwrap_or(false) {
        panic!("有用户手势时 hasUserGesture() 应为 true,实际: {}", act["helper"]);
    }
    ok("userActivation 回归:isActive 是布尔属性 → 旧 isActive() 必抛错,hasUserGesture() 手势下为 true");

    // ② 手势内进入接收 → FSA 流式分支必须真的启用（旧代码此处恒走内存模式）
    cdp.eval_gesture(
        &d,
        &format!("(location.hash = {}, 'ok')", jstr(&frag)),
    );
    cdp.wait_for(
        &d,
        "document.querySelector('#fc-name').textContent === 'fsa-resume-e2e.bin'",
        30000,
        "FSA 接收文件卡",
    );
    cdp.wait_for(&d, "window.__pickerCalls >= 1", 20000, "showSaveFilePicker 被调用(FSA 分支启用)");
    cdp.wait_for(&d, "!document.querySelector('#fc-bar-wrap').hidden", 30000, "接收进度条出现");

    let idb_js = js(
        r#"(async () => { const r = await resumeDB.get(__ROOM__); return r ? { mode: r.mode, done: r.done } : null })()"#,
        &[("__ROOM__", &jstr(&setup_room))],
    );
    let mut rec_d = Value::Null;
    let mut rec_done = -1i64;
    let mut rec_mode = String::new();
    for _ in 0..300 {
        rec_d = cdp.eval(&d, &idb_js);
        rec_done = rec_d["done"].as_i64().unwrap_or(-1);
        rec_mode = rec_d["mode"].as_str().unwrap_or("").to_string();
        if rec_done >= 8 {
            break;
        }
        sleep_ms(100);
    }
    if rec_d.is_null() {
        panic!("IDB 无续传记录");
    }
    if rec_mode != "fs" {
        panic!("应走 FSA 流式保存(mode=fs),实际 {rec_mode}(isActive 仍被误判为无手势?)");
    }
    if rec_done < 8 {
        panic!("fs 断点记录未随检查点落盘推进(done={rec_done}),刷新后必回退重拉");
    }
    let mut through = 0i64;
    for _ in 0..200 {
        through = eval_i64(
            &mut cdp,
            &d,
            &js(
                r#"(async () => (await (await fetch('/api/rooms/__ROOM__/state')).json()).through)()"#,
                &[("__ROOM__", &setup_room)],
            ),
        );
        if through >= rec_done + 1 {
            break;
        }
        sleep_ms(50);
    }
    if through > rec_done + 1 {
        panic!("server.through({through}) 越过已持久化断点 done={rec_done}");
    }
    ok(&format!(
        "FSA 断点记录:mode=fs、done={rec_done} 已落盘,server.through={through} ≤ done+1"
    ));

    // ③ 刷新：关掉页面重开同源文档（等价 F5，保留 hash）。旧实现 rec.done=0 →
    //    重进后从第 1 片重拉 → server 410 → "续传按钮"都不会出现。
    cdp.close_page(&d);
    let d2 = cdp.new_page();
    cdp.send(
        Some(&d2.sid),
        "Page.addScriptToEvaluateOnNewDocument",
        json!({ "source": picker_stub }),
    );
    let resume_url = format!("{s}/?resume={}{}", now_nanos(), frag);
    nav(&mut cdp, &d2, &resume_url);
    cdp.wait_for(
        &d2,
        "document.querySelector('#start-recv').textContent.includes('继续接收')",
        25000,
        "续传按钮出现",
    );
    let rec_after = cdp.eval(&d2, &idb_js);
    let after_mode = rec_after["mode"].as_str().unwrap_or("");
    let after_done = rec_after["done"].as_i64().unwrap_or(-1);
    if after_mode != "fs" || after_done < 8 {
        panic!("刷新后 FSA 断点记录丢失: {rec_after}");
    }
    // 发送方补齐剩余分片并置 done，再点"继续接收并保存"
    cdp.eval(
        &a,
        r#"(async () => {
  for (const chunk of window.__fsa.rest) await window.__fsa.post(window.__fsa.nextSeq++, await window.__fsa.seal(chunk))
  await fetch('/api/rooms/' + window.__fsa.room + '/done', { method: 'POST', headers: { 'X-Room-Token': window.__fsa.token } })
})()"#,
    );
    cdp.eval_gesture(&d2, "document.querySelector('#start-recv').click()");
    cdp.wait_for(
        &d2,
        "document.querySelector('#recv-file-status').textContent.includes('已保存')",
        90000,
        "FSA 续传完成",
    );
    let out = cdp.eval(
        &d2,
        r#"(async () => {
  const root = await navigator.storage.getDirectory()
  const f = await (await root.getFileHandle('fsa-picked.bin')).getFile()
  const b = new Uint8Array(await f.arrayBuffer())
  const d = [...new Uint8Array(await crypto.subtle.digest('SHA-256', b))]
    .map((x) => x.toString(16).padStart(2, '0')).join('')
  return { size: b.length, dig: d }
})()"#,
    );
    let out_size = out["size"].as_i64().unwrap_or(-1);
    let out_dig = out["dig"].as_str().unwrap_or("");
    if out_size != setup_size || out_dig != setup_dig {
        panic!(
            "FSA 续传后文件内容不完整: size={out_size}/{setup_size} digest一致={}",
            out_dig == setup_dig
        );
    }
    let rec_gone = cdp.eval(
        &d2,
        &js(
            r#"(async () => (await resumeDB.get(__ROOM__)) || null)()"#,
            &[("__ROOM__", &jstr(&setup_room))],
        ),
    );
    if !rec_gone.is_null() {
        panic!("完成后 IDB 断点记录未清理");
    }
    ok(&format!(
        "FSA 刷新续传:保留 {rec_done} 片断点 → 续传后 SHA-256 与原文一致、断点记录已清理"
    ));
    cdp.close_page(&d2);
}

// =====================================================================================
// 场景 16/17/18（3 条 ok）：设备列表差量渲染 / 邀请对账 / X-Chunk-Seq 幂等序号
// =====================================================================================
#[test]
fn t14_diff_render_reconcile_seq_header() {
    let _g = common::serial();
    let Some((srv, _chrome, mut cdp)) = boot() else { return };
    let s = srv.url();
    let a = cdp.new_page();
    nav(&mut cdp, &a, &format!("{s}/"));

    // 16) 差量渲染：同一设备列表连续 renderDevices 两次，DOM 节点引用必须不变
    let diff = cdp.eval(
        &a,
        r#"(() => {
  window.__origRefresh = refreshDevices
  window.__origDeviceCache = deviceCache
  refreshDevices = () => {} // 隔离 5s 心跳的真实设备刷新
  deviceCache = [
    { ip: '10.88.0.1', id: 'diff1', name: '差量设备甲', pub: toB64(X25519.genKey().pk) },
    { ip: '10.88.0.2', id: 'diff2', name: '差量设备乙', pub: toB64(X25519.genKey().pk) },
  ]
  selectedIp = null
  deviceFilter = ''
  renderDevices()
  const before = [...document.querySelectorAll('#devices .device')]
  const countText = document.querySelector('#devices-count').textContent
  renderDevices()
  const after = [...document.querySelectorAll('#devices .device')]
  const sameNodes = before.length === 2 && after.length === 2 && before.every((el, i) => el === after[i])
  selectedIp = '10.88.0.2'
  renderDevices()
  const sel = document.querySelector('#devices .device.selected')
  const selectedOk = !!sel && sel.querySelector('.d-name').textContent === '差量设备乙'
  deviceCache = window.__origDeviceCache || []
  selectedIp = null
  deviceFilter = ''
  renderDevices()
  refreshDevices = window.__origRefresh
  delete window.__origRefresh
  delete window.__origDeviceCache
  return { sameNodes, countText, selectedOk }
})()"#,
    );
    if !diff["sameNodes"].as_bool().unwrap_or(false) {
        panic!("连续两次 renderDevices 的 DOM 节点引用应保持不变(差量渲染未生效)");
    }
    if !diff["selectedOk"].as_bool().unwrap_or(false) {
        panic!("selectedIp 变化后差量渲染未重建成选中卡片");
    }
    let count_text = diff["countText"].as_str().unwrap_or("");
    if !count_text.contains("2 台在线") {
        panic!("设备计数未更新: {count_text}");
    }
    ok("设备列表差量渲染:签名相同不重建(节点引用不变),选中/计数变化正确重建");

    // 17) 邀请对账：以服务端列表为准删除已消失条目；清空后停止标题闪烁
    let rec = cdp.eval(
        &a,
        r#"(async () => {
  const baseTitle = document.title
  const mk = (id, name, ip) => ({ id, room: 'Ab3xYz9kLm', pub: toB64(X25519.genKey().pk), hint: '', from: { ip, name } })
  const keep = mk('recKeep01', '对账保留', '10.88.1.1')
  const gone = mk('recGone02', '对账删除', '10.88.1.2')
  incomingOffers.clear()
  incomingOffers.set(keep.id, keep)
  incomingOffers.set(gone.id, gone)
  notifyNewOffer('📮 对账测试', 'x') // 先启动标题闪烁(真实场景:新邀请到达)
  const changedKeep = reconcileOffers([keep])   // 服务端只剩 keep → 删除 gone
  const keptOk = incomingOffers.size === 1 && incomingOffers.has(keep.id)
  const changedNoop = reconcileOffers([keep])   // 原有条目不变 → 无变化
  const changedEmpty = reconcileOffers([])      // 服务端已无邀请 → 全清
  const emptyOk = incomingOffers.size === 0
  await new Promise((r) => setTimeout(r, 1100)) // 闪烁若未停,标题会在此窗口内变化
  const stopped = document.title === baseTitle
  renderIncoming()
  return { changedKeep, keptOk, changedNoop, changedEmpty, emptyOk, stopped }
})()"#,
    );
    if !rec["changedKeep"].as_bool().unwrap_or(false) || !rec["keptOk"].as_bool().unwrap_or(false) {
        panic!("reconcileOffers 保留语义错误: {rec}");
    }
    if rec["changedNoop"].as_bool().unwrap_or(false) {
        panic!("reconcileOffers 无变化时应返回 false");
    }
    if !rec["changedEmpty"].as_bool().unwrap_or(false) || !rec["emptyOk"].as_bool().unwrap_or(false) {
        panic!("reconcileOffers([]) 应清空全部并返回 true");
    }
    if !rec["stopped"].as_bool().unwrap_or(false) {
        panic!("邀请清空后标题闪烁未停止: {rec}");
    }
    ok("邀请对账:保留未过期、删除已消失(返回 changed),清空后标题恢复");

    // 18) X-Chunk-Seq：meta=0、文本=1，是超时/429 幂等重投的前提
    let seq_text = format!("X-Chunk-Seq 回归 {}", now_nanos());
    nav(&mut cdp, &a, &format!("{s}/"));
    cdp.wait_for(
        &a,
        r#"/^#[0-9a-f]{8,64}$/.test(document.querySelector('#me-fp').textContent.trim())"#,
        20000,
        "首页就绪",
    );
    cdp.eval(
        &a,
        r#"(() => {
  window.__chunkSeqs = []
  window.__origFetchReal = window.fetch
  window.fetch = function (input, init) {
    try {
      const url = String(input)
      if (init && init.method === 'POST' && url.includes('/api/rooms/') && url.includes('/chunk')) {
        const h = init.headers || {}
        window.__chunkSeqs.push(h['X-Chunk-Seq'] === undefined ? null : String(h['X-Chunk-Seq']))
      }
    } catch {}
    return window.__origFetchReal.call(window, input, init)
  }
  return 'hooked'
})()"#,
    );
    cdp.eval(
        &a,
        &format!("document.querySelector('#text').value = {}", jstr(&seq_text)),
    );
    cdp.eval(&a, "document.querySelector('#send-text').click()");
    cdp.wait_for(
        &a,
        "document.querySelector('#link').textContent.startsWith('http')",
        25000,
        "序号测试链接",
    );
    let seq_link = text(&mut cdp, &a, "#link");
    let e = cdp.new_page();
    nav(&mut cdp, &e, &seq_link);
    cdp.wait_for(&e, "!document.querySelector('#recv-text').hidden", 45000, "序号测试接收完成");
    let seqs_raw = cdp.eval(
        &a,
        r#"(() => {
  const s = window.__chunkSeqs.slice()
  window.fetch = window.__origFetchReal
  delete window.__origFetchReal
  return s
})()"#,
    );
    let mut uniq: Vec<String> = Vec::new();
    for v in seqs_raw.as_array().cloned().unwrap_or_default() {
        let t = match v {
            Value::String(s) => s,
            Value::Null => "null".to_string(),
            other => other.to_string(),
        };
        if !uniq.contains(&t) {
            uniq.push(t);
        }
    }
    if uniq.len() != 2 || uniq[0] != "0" || uniq[1] != "1" {
        panic!("X-Chunk-Seq 应为 [0,1],实际 {seqs_raw}");
    }
    let seq_got = text(&mut cdp, &e, "#recv-text");
    if seq_got != seq_text {
        panic!("序号测试文本不一致");
    }
    cdp.close_page(&e);
    ok("X-Chunk-Seq:meta=0 / 文本=1 两片请求头序号正确且收端逐字一致");
}

// =====================================================================================
// 场景 19/19：服务器中途下线 —— 建立失败可退（不卡死在无按钮视图）
// =====================================================================================
#[test]
fn t15_server_downtime_has_exit() {
    let _g = common::serial();
    let Some((mut srv, _chrome, mut cdp)) = boot() else { return };
    let s = srv.url();
    let a = cdp.new_page();
    nav(&mut cdp, &a, &format!("{s}/")); // 趁服务器还在先回到首页（之后不再导航，页面操作走内存态）
    srv.stop();
    sleep_ms(300);
    cdp.eval(&a, "document.querySelector('#text').value = '发往已死服务器的消息'");
    cdp.eval(&a, "document.querySelector('#send-text').click()");
    cdp.wait_for(
        &a,
        "document.querySelector('#send-status').textContent.includes('建立密道失败')",
        25000,
        "服务器下线报错",
    );
    cdp.eval(&a, "document.querySelector('#cancel-send').click()");
    cdp.wait_for(&a, "!document.querySelector('#view-landing').hidden", 20000, "返回首页");
    ok("服务器中途下线:报\"建立密道失败\"且可返回(不卡死在无按钮视图)");
}
