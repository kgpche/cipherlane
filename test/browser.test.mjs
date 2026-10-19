// 浏览器冒烟测试 —— 零依赖：CDP over WebSocket 驱动本机 Chrome/Chromium
//
// 覆盖前端关键路径（app.js 至今无自动化测试，历史 P0 均出在前端）：
//   1) 链接模式文本全链路：双页面 发送→链接→接收→逐字一致
//   2) 定向发送到离线设备：建立阶段失败必须有“返回首页”退路（回归：曾死锁在无按钮视图）
//   3) 同序号并发拉取：先到者得、后来者收到“正被另一个接收方使用”（回归：曾 500+挂起）
//   4) 服务器中途下线：建立失败可退，返回按钮可用
//   5) 文件传输全链路：真实 Worker 加密 + 接收方文件卡与完成状态
//   6) FSA 流式保存 + 续传断点一致性：isActive 属性误调用回归 / fs 模式 done 落盘
//
// 无浏览器环境（未装 Chrome/Chromium 且未设 CHROME_BIN）打印“跳过”并以 0 退出，
// 不阻断 npm test；CI 的 ubuntu 镜像自带 /usr/bin/google-chrome 可真实执行。
//
// 注：127.0.0.1 是安全上下文，走 crypto.subtle 原生路径；纯 JS AES 降级路径
//     仅在非 localhost 的明文 HTTP 下可达，其与原生实现的字节级一致由 aesgcm.test 覆盖。
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// 全局 WebSocket 为 Node 22+ 稳定能力；18/20 跳过浏览器组（CI 矩阵里由 22 全跑）
if (typeof WebSocket === 'undefined') {
  console.log('  – 此 Node 版本无全局 WebSocket（需 22+），跳过浏览器冒烟测试')
  process.exit(0)
}

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.join(__dirname, '..')
const PORT = 20000 + Math.floor(Math.random() * 20000)
const S = `http://127.0.0.1:${PORT}`

let passed = 0
const ok = (name) => { passed++; console.log(`  ✓ ${name}`) }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// ---------- 最小 CDP 客户端 ----------
function cdpConnect(wsUrl) {
  const ws = new WebSocket(wsUrl)
  const pending = new Map()
  const events = []
  const listeners = []
  let id = 0
  const ready = new Promise((res, rej) => {
    ws.onopen = () => res()
    ws.onerror = () => rej(new Error('CDP WebSocket 连接失败'))
  })
  ws.onmessage = (ev) => {
    const m = JSON.parse(typeof ev.data === 'string' ? ev.data : '')
    if (m.id && pending.has(m.id)) {
      const p = pending.get(m.id)
      pending.delete(m.id)
      m.error ? p.rej(new Error(`${m.error.message} (CDP ${m.method || ''})`)) : p.res(m.result)
    } else {
      events.push(m)
      for (const l of listeners) l(m)
    }
  }
  return {
    ready,
    send(method, params = {}, sessionId) {
      const msg = { id: ++id, method, params }
      if (sessionId) msg.sessionId = sessionId
      const p = new Promise((res, rej) => pending.set(msg.id, { res, rej }))
      ws.send(JSON.stringify(msg))
      return p
    },
    on(l) { listeners.push(l) },
    close() { try { ws.close() } catch {} },
  }
}

async function evalJs(c, sid, expression) {
  const r = await c.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sid)
  if (r.exceptionDetails) {
    const d = r.exceptionDetails.exception && r.exceptionDetails.exception.description
    throw new Error('页面执行失败: ' + (d || r.exceptionDetails.text) + '\n  ← ' + expression.slice(0, 120))
  }
  return r.result.value
}

// 带用户手势的求值(CDP userGesture=true 会注入真实用户激活):
// 用于模拟"点击后才允许拉起保存选择器"的浏览器约束,断言 hasUserGesture() 为 true。
async function evalJsGesture(c, sid, expression) {
  const r = await c.send('Runtime.evaluate',
    { expression, awaitPromise: true, returnByValue: true, userGesture: true }, sid)
  if (r.exceptionDetails) {
    const d = r.exceptionDetails.exception && r.exceptionDetails.exception.description
    throw new Error('页面执行失败(gesture): ' + (d || r.exceptionDetails.text) + '\n  ← ' + expression.slice(0, 120))
  }
  return r.result.value
}

async function waitFor(c, sid, expr, timeout = 20000, what = '') {
  const t0 = Date.now()
  for (;;) {
    if (await evalJs(c, sid, `!!(${expr})`)) return
    if (Date.now() - t0 > timeout) throw new Error('等待超时(' + (timeout / 1000) + 's): ' + (what || expr))
    await sleep(120)
  }
}

const textOf = (sel) => `document.querySelector('${sel}') ? document.querySelector('${sel}').textContent : null`
// 全局不变量:所有带 hidden 的元素计算样式必须为 display:none。
// 历史教训:自定义 display(flex/grid)会压过 UA 的 [hidden],曾致 6 处常显
// (含模态遮罩全屏常驻、刷新即弹窗)——DOM 属性断言测不出,必须查计算样式。
const hiddenInvariant = (c, sid) =>
  evalJs(c, sid, `[...document.querySelectorAll('[hidden]')]
    .filter((el) => getComputedStyle(el).display !== 'none')
    .map((el) => el.id || el.className)`)

// ---------- 启动:服务器 + 无头浏览器 ----------
function launchServer() {
  // CL_SERVER_BIN: 直接测试打包产物（SEA 单文件二进制），而非源码
  // CIPHERLANE_EXTRA_HOSTS: 第 6 组用假域名 cipherlane-insecure.test 模拟非安全上下文，
  // 服务端 /api/* 的 Host 闸门默认只放行 IP/localhost，需显式白名单放行该域名。
  const env = { ...process.env, PORT: String(PORT), CIPHERLANE_EXTRA_HOSTS: 'cipherlane-insecure.test' }
  const child = process.env.CL_SERVER_BIN
    ? spawn(process.env.CL_SERVER_BIN, [], {
        env, stdio: ['ignore', 'ignore', 'pipe'],
      })
    : spawn(process.execPath, ['server.js'], {
        cwd: ROOT, env, stdio: ['ignore', 'ignore', 'pipe'],
      })
  child.stderr.on('data', () => {}) // 丢弃启动横幅,避免管道写满
  return child
}

function launchChrome() {
  const bin = process.env.CHROME_BIN
    || ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/opt/google/chrome/chrome']
      .find((p) => fs.existsSync(p))
  if (!bin) return null
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cl-e2e-'))
  const child = spawn(bin, [
    '--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
    '--no-first-run', '--no-default-browser-check', '--mute-audio', '--window-size=1280,900',
    '--no-proxy-server', // 宿主机系统代理会拦截非 localhost 域名(测试机有 clash 类代理),测试直连
    // 假域名映射到本机:提供"非安全上下文"origin(非 localhost 的明文 http),
    // 用于覆盖纯 JS AES 降级路径(127.0.0.1 是安全上下文,走不到它)
    '--host-resolver-rules=MAP cipherlane-insecure.test 127.0.0.1',
    `--user-data-dir=${profile}`, '--remote-debugging-port=0', 'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] })
  const wsUrl = new Promise((res, rej) => {
    let buf = ''
    const t = setTimeout(() => rej(new Error('Chrome 未能启动调试端口:\n' + buf)), 15000)
    child.stderr.on('data', (d) => {
      buf += d
      const m = /DevTools listening on (ws:\/\/\S+)/.exec(buf)
      if (m) { clearTimeout(t); res(m[1]) }
    })
    child.on('exit', () => rej(new Error('Chrome 提前退出:\n' + buf)))
  })
  return { child, wsUrl, profile }
}

async function newPage(c) {
  const { targetId } = await c.send('Target.createTarget', { url: 'about:blank' })
  const { sessionId } = await c.send('Target.attachToTarget', { targetId, flatten: true })
  await c.send('Page.enable', {}, sessionId)
  await c.send('Runtime.enable', {}, sessionId)
  return { sid: sessionId, tid: targetId }
}

async function navigate(c, sid, url) {
  await c.send('Page.navigate', { url }, sid)
  await waitFor(c, sid, `document.readyState === 'complete' && location.origin === '${new URL(url).origin}'`, 15000, '页面加载 ' + url)
}

async function main() {
  const server = launchServer()
  const chrome = launchChrome()
  if (!chrome) {
    console.log('  – 未找到 Chrome/Chromium（可用 CHROME_BIN 指定），跳过浏览器冒烟测试')
    server.kill('SIGINT')
    return
  }
  const cleanup = () => {
    try { chrome.child.kill('SIGKILL') } catch {}
    try { server.kill('SIGINT') } catch {}
    try { fs.rmSync(chrome.profile, { recursive: true, force: true }) } catch {}
  }

  try {
    // 等服务器与浏览器就绪
    const t0 = Date.now()
    for (;;) {
      if (Date.now() - t0 > 8000) throw new Error('服务器未能在 8s 内启动')
      try { await fetch(S + '/'); break } catch { await sleep(150) }
    }
    const c = cdpConnect(await chrome.wsUrl)
    await c.ready

    // 两个独立页面 = 收发双方（同一浏览器 profile,共享 localStorage 的设备 secret,不互踩）
    const pgA = await newPage(c)
    const pgB = await newPage(c)
    const sidA = pgA.sid
    let sidB = pgB.sid
    await navigate(c, sidA, S + '/')
    await navigate(c, sidB, S + '/')

    // 公钥指纹：心跳拿到 IP 后,本机名片显示 32 位十六进制指纹(128bit TOFU 人工比对锚点)
    await waitFor(c, sidA,
      `document.querySelector('#me-fp') && /^#[0-9a-f]{32}$/.test(document.querySelector('#me-fp').textContent.trim())`,
      10000, '本机指纹显示')
    ok('公钥指纹显示:本机名片 32 位十六进制(128bit)')

    // ---------- 1) 链接模式文本全链路 ----------
    const secret = '浏览器 E2E 冒烟 ✅ 中文与 emoji 🚀 ' + randomBytes(8).toString('hex')
    await evalJs(c, sidA, `document.querySelector('#text').value = ${JSON.stringify(secret)}`)
    await evalJs(c, sidA, `document.querySelector('#send-text').click()`)
    await waitFor(c, sidA, `document.querySelector('#link').textContent.startsWith('http')`, 15000, '生成接收链接')
    const link = await evalJs(c, sidA, textOf('#link'))
    await navigate(c, sidB, link)
    await waitFor(c, sidB, `!document.querySelector('#recv-text').hidden`, 20000, '接收视图出现')
    const got = await evalJs(c, sidB, textOf('#recv-text'))
    if (got !== secret) throw new Error(`文本不一致:\n  期望 ${JSON.stringify(secret)}\n  实际 ${JSON.stringify(got)}`)
    await waitFor(c, sidB, `document.querySelector('#recv-text-status').textContent.includes('已解密接收')`, 10000, '接收完成状态')
    // ack 凭证闭环:接收方带 proof ack → 发送方轮询本地校验通过
    await waitFor(c, sidA, `document.querySelector('#send-status').textContent.includes('凭证校验通过')`, 10000, '发送方凭证校验')

    // ---------- 1b) 返回首页:hash 清理 + 延迟邀请补画(回归:曾不刷新/不补画) ----------
    await evalJs(c, sidB, `document.querySelector('#recv-text-back').click()`)
    await waitFor(c, sidB, `!document.querySelector('#view-landing').hidden`, 5000, '返回首页')
    const hashNow = await evalJs(c, sidB, `location.hash`)
    if (hashNow !== '') throw new Error('返回后地址栏 hash 未清除: ' + hashNow)
    // 模拟一条在接收视图期间到达的邀请:注入后经 showView 往返,应被补画
    await evalJs(c, sidB, `(async () => {
      const kp = X25519.genKey()
      const key = X25519.sessionKey(X25519.dh(identity.sk, kp.pk), kp.pk, identity.pk, 'Ab3xYz9kLm')
      const hint = toB64(await sealWith(key, enc.encode(JSON.stringify({ kind: 'text', size: 12 }))))
      incomingOffers.set('fake01', { id: 'fake01', room: 'Ab3xYz9kLm', pub: toB64(kp.pk), hint, from: { ip: '192.168.137.9', name: '延迟到达的邀请' } })
      showView('recv')
      showView('landing')
    })()`)
    await waitFor(c, sidB, `!document.querySelector('#incoming-wrap').hidden`, 5000, '延迟邀请区域可见')
    await waitFor(c, sidB, `[...document.querySelectorAll('.o-name')].some((x) => x.textContent.includes('延迟到达的邀请'))`, 5000, '邀请卡')
    await evalJs(c, sidB, `incomingOffers.delete('fake01'); renderIncoming()`)
    ok('返回首页:hash 清理 + 设备立即刷新 + 延迟邀请补画(回归)')
    {
      const bad = await hiddenInvariant(c, sidB)
      if (bad.length) throw new Error('hidden 属性被 display 覆盖: ' + bad.join(','))
    }

    // ---------- 1c) 协议 v2：错位分片（错误 index 的 AAD）必须被拒绝 ----------
    // 红测证明：旧实现无 AAD，对分片位置完全盲（legacyBlind 用旧格式无 AAD 密文证明：
    // 任意位置的密文都能被旧接收端解开）；新接收端按 index 绑定 AAD，错位必须报错、不 ack。
    {
      // 注：本页经 LAN IP 打开（publicOrigin 把回环升级为 LAN 地址）→ 非安全上下文，
      // 恰好覆盖"纯 JS AES-GCM + Worker"降级路径上的 AAD；构造端也用纯 JS AESGCM。
      const setup = await evalJs(c, sidB, `(async () => {
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
        return {
          link: publicOrigin() + '/#' + room + '.' + toB64(key),
          room, controlOk, blindOk,
        }
      })()`)
      if (!setup.controlOk) throw new Error('构造错误:错位密文用其原始 AAD 应可解开')
      if (!setup.blindOk) throw new Error('构造错误:旧无 AAD 格式应能解开（位置盲证明失败）')
      await navigate(c, sidB, setup.link)
      await waitFor(c, sidB, `document.querySelector('#recv-file-status').textContent.startsWith('❌')`, 20000, '错位分片报错')
      const errText = await evalJs(c, sidB, textOf('#recv-file-status'))
      if (/已保存/.test(errText)) throw new Error('错位分片不应被当作成功: ' + errText)
      if (!/GCM|解密|验签/.test(errText)) throw new Error('错位分片应以验签失败报错,实际: ' + errText)
      const acked = await evalJs(c, sidB, `(async () => (await (await fetch('/api/rooms/${setup.room}/state')).json()).acked)()`)
      if (acked) throw new Error('错位分片失败后不应 ack')
      ok('协议 v2 错位分片被拒绝且不 ack（旧无 AAD 实现位置盲：blindOk 已证）')
    }

    // ---------- 1d) 邀请 TOFU：offer 公钥与此前记录不一致 → 卡片警示 + 接受前确认 ----------
    {
      await navigate(c, sidB, S + '/')
      await waitFor(c, sidB, `!document.querySelector('#view-landing').hidden`, 5000, '回到首页')
      await evalJs(c, sidB, `(async () => {
        const room = 'Ab3xYz9kLm'
        const kp = X25519.genKey()
        const key = X25519.sessionKey(X25519.dh(identity.sk, kp.pk), kp.pk, identity.pk, room)
        const hint = await sealWith(key, enc.encode(JSON.stringify({ kind: 'text', size: 3 })))
        const known = knownPubs.load()
        known['192.168.137.9'] = toB64(X25519.genKey().pk) // 记录不同公钥 → 触发变化
        knownPubs.save(known)
        incomingOffers.set('tofu01', { id: 'tofu01', room, pub: toB64(kp.pk), hint: toB64(hint), from: { ip: '192.168.137.9', name: 'TOFU 发送方' } })
        renderIncoming()
      })()`)
      await waitFor(c, sidB,
        `[...document.querySelectorAll('.o-fp-warn')].some((x) => !x.hidden && x.textContent.includes('公钥已变化'))`,
        5000, '邀请卡片 TOFU 警示')
      await waitFor(c, sidB, `!document.querySelector('.o-accept').disabled`, 5000, '预览解密完成')
      await evalJs(c, sidB, `document.querySelector('.o-accept').click()`)
      await waitFor(c, sidB, `!document.querySelector('#modal-mask').hidden`, 5000, '邀请 TOFU 确认弹窗')
      const t = await evalJs(c, sidB, `document.querySelector('#modal-title').textContent`)
      if (!/公钥已变化/.test(t)) throw new Error('邀请确认弹窗应提示公钥变化,实际: ' + t)
      await evalJs(c, sidB, `document.querySelector('#modal-cancel').click()`)
      await waitFor(c, sidB, `document.querySelector('#modal-mask').hidden`, 3000, '取消弹窗')
      const still = await evalJs(c, sidB, `incomingOffers.has('tofu01') && !document.querySelector('#view-landing').hidden`)
      if (!still) throw new Error('取消后邀请应保留且不得进入接收')
      await evalJs(c, sidB, `incomingOffers.delete('tofu01'); renderIncoming()`)
      ok('邀请 TOFU：发送方公钥变化 → 卡片警示 + 接受前确认，取消不接收')
    }

    // ---------- 2) 定向发送到离线设备:建立失败必须有退路(回归:曾死锁) ----------
    await navigate(c, sidA, S + '/')
    await evalJs(c, sidA, `
      // 桩掉心跳设备刷新:注入的幽灵设备若恰逢 5s 心跳,会被真实列表覆盖
      // (selectedDevice 落空走"离线"分支,本场景等待的报错不出现)——CI 慢机上
      // 曾因此 flake。后续场景不依赖真实设备列表。
      refreshDevices = () => {}
      deviceCache.push({ ip: '10.99.0.5', id: 'ghost', name: '幽灵设备', pub: toB64(X25519.genKey().pk) })
      selectedIp = '10.99.0.5'
      renderDevices()`)
    await evalJs(c, sidA, `document.querySelector('#text').value = '去往幽灵设备的消息'`)
    await evalJs(c, sidA, `document.querySelector('#send-text').click()`)
    await waitFor(c, sidA, `document.querySelector('#send-status').textContent.includes('建立密道失败')`, 15000, '离线设备报错')
    const cancelText = await evalJs(c, sidA, `document.querySelector('#cancel-send').textContent`)
    if (cancelText !== '返回首页') throw new Error('失败后取消按钮应为"返回首页",实际: ' + cancelText)
    await evalJs(c, sidA, `document.querySelector('#cancel-send').click()`)
    await waitFor(c, sidA, `!document.querySelector('#view-landing').hidden`, 5000, '返回首页')
    await evalJs(c, sidA, `selectedIp = null; deviceCache = deviceCache.filter((d) => d.ip !== '10.99.0.5'); renderDevices()`)
    ok('定向到离线设备:报"建立密道失败" + "返回首页"可退(回归覆盖)')

    // ---------- 2b) 直发 TOFU：目标公钥变化必须先弹确认，取消则绝不发送 ----------
    {
      const warned = await evalJs(c, sidA, `(() => {
        refreshDevices = () => {}
        const kp = X25519.genKey()
        deviceCache.push({ ip: '10.99.0.6', id: 'tofu', name: 'TOFU设备', pub: toB64(kp.pk) })
        const known = knownPubs.load()
        known['10.99.0.6'] = toB64(X25519.genKey().pk) // 记录一把不同公钥 → 触发变化
        knownPubs.save(known)
        selectedIp = '10.99.0.6'
        renderDevices()
        return document.querySelectorAll('.device.fp-changed').length
      })()`)
      if (!(warned >= 1)) throw new Error('公钥变化设备卡应有"⚠ 公钥已变化"警示')
      await evalJs(c, sidA, `document.querySelector('#text').value = 'TOFU 确认测试'`)
      await evalJs(c, sidA, `document.querySelector('#send-text').click()`)
      await waitFor(c, sidA, `!document.querySelector('#modal-mask').hidden`, 5000, '直发 TOFU 确认弹窗')
      const tf = await evalJs(c, sidA, `document.querySelector('#modal-title').textContent`)
      if (!/公钥已变化/.test(tf)) throw new Error('确认弹窗应提示公钥变化,实际: ' + tf)
      // 取消 → 不得进入发送视图、不得建房/发送
      await evalJs(c, sidA, `document.querySelector('#modal-cancel').click()`)
      await waitFor(c, sidA, `document.querySelector('#modal-mask').hidden`, 3000, '取消关闭弹窗')
      if (!(await evalJs(c, sidA, `!document.querySelector('#view-landing').hidden`))) {
        throw new Error('取消后应留在首页（不发送）')
      }
      await evalJs(c, sidA, `selectedIp = null; deviceCache = deviceCache.filter((d) => d.ip !== '10.99.0.6'); renderDevices()`)
      ok('直发 TOFU：公钥变化弹确认，取消后不发送')
    }

    // ---------- 3) 同序号并发拉取:X-Resume 只读回放,双双拿到同一份(回归:曾 500+永久挂起) ----------
    // 浏览器端 getChunk 常带 X-Resume → 房间为可续传模式,同序号并发=多播;
    // 经典模式的先到先得 409 由 protocol 第 9 组在服务端锁定。
    const concurrent = await evalJs(c, sidA, `
      (async () => {
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
      })()`)
    if (concurrent !== 'same') throw new Error('只读回放应返回同一份: ' + concurrent)
    ok('同序号并发拉取:X-Resume 只读回放返回同一份数据(回归覆盖)')

    // ---------- 4) 文件传输全链路:真实 Worker 加密 ----------
    const fileName = 'e2e-' + Date.now() + '.bin'
    const filePath = path.join(os.tmpdir(), fileName)
    fs.writeFileSync(filePath, randomBytes(5 * 1024 * 1024)) // 5 个分片
    // 发送方:通过 CDP 注入 File 对象再触发 change(app.js 的 onchange 是属性赋值,可直接调用)
    await evalJs(c, sidA, `document.querySelector('#text').value = ''`)
    const { root } = await c.send('DOM.getDocument', {}, sidA)
    await c.send('DOM.enable', {}, sidA)
    const { nodeId } = await c.send('DOM.querySelector', { nodeId: root.nodeId, selector: '#file' }, sidA)
    await c.send('DOM.setFileInputFiles', { files: [filePath], nodeId }, sidA)
    await evalJs(c, sidA, `document.querySelector('#file').onchange()`)
    await waitFor(c, sidA, `document.querySelector('#link').textContent.startsWith('http')`, 15000, '文件发送链接')
    const fileLink = await evalJs(c, sidA, textOf('#link'))
    await navigate(c, sidB, fileLink)
    await waitFor(c, sidB, `document.querySelector('#fc-name').textContent === '${fileName}'`, 30000, '接收文件卡')
    await waitFor(c, sidB, `document.querySelector('#recv-file-status').textContent.includes('已保存')`, 60000, '文件接收完成')
    // 结构断言:加密确实走了 Worker 池而非静默回退主线程(回退路径数据同样正确,须单独验证)
    // new Worker('/crypto-worker.js') 每次在 resource timing 留一条记录;低核机器池=2,故断言 ≥2
    const workersUsed = await evalJs(c, sidA,
      `performance.getEntriesByType('resource').filter((e) => e.name.includes('crypto-worker.js')).length`)
    if (!(workersUsed >= 2)) throw new Error(`加密未走 Worker 池(实例数 ${workersUsed}),疑似静默回退主线程`)
    ok(`文件传输全链路:Worker 池加密(×${workersUsed}) → 5MiB 分片 → 接收方保存完成`)

    // ---------- 6) 纯 JS AES 降级路径:安全上下文发送 → 非安全上下文接收 ----------
    // 假域名(非 localhost 的明文 http)无 crypto.subtle → 浏览器与 Worker 走纯 JS AES-GCM,
    // 与发送侧的原生 WebCrypto 产出的线上格式必须逐字节互通
    const sidC = (await newPage(c)).sid
    await navigate(c, sidC, `http://cipherlane-insecure.test:${PORT}/`)
    const ctx = await evalJs(c, sidC,
      `({ subtle: typeof crypto !== 'undefined' && !!crypto.subtle, aesgcm: typeof AESGCM })`)
    if (ctx.subtle !== false || ctx.aesgcm !== 'object') {
      throw new Error('预期非安全上下文(无 subtle、有纯 JS AESGCM),实际: ' + JSON.stringify(ctx))
    }
    await navigate(c, sidA, S + '/')
    const secret2 = '纯 JS AES 降级路径互操作 🐢 ' + randomBytes(6).toString('hex')
    await evalJs(c, sidA, `document.querySelector('#text').value = ${JSON.stringify(secret2)}`)
    await evalJs(c, sidA, `document.querySelector('#send-text').click()`)
    await waitFor(c, sidA, `document.querySelector('#link').textContent.startsWith('http')`, 15000, '降级路径链接')
    const link2 = (await evalJs(c, sidA, textOf('#link')))
      .replace(`127.0.0.1:${PORT}`, `cipherlane-insecure.test:${PORT}`)
    await navigate(c, sidC, link2)
    await waitFor(c, sidC, `!document.querySelector('#recv-text').hidden`, 20000, '降级路径接收')
    const got2 = await evalJs(c, sidC, textOf('#recv-text'))
    if (got2 !== secret2) throw new Error(`降级路径文本不一致:\n  期望 ${JSON.stringify(secret2)}\n  实际 ${JSON.stringify(got2)}`)
    await waitFor(c, sidC, `document.querySelector('#recv-text-status').textContent.includes('已解密接收')`, 10000, '降级路径完成')
    ok('纯 JS AES 降级路径:安全上下文发送 ↔ 非安全上下文接收逐字一致(跨实现互通)')

    // ---------- 7) 多文件批量:多选 → 链接 → 批量接收(内存模式逐个下载) ----------
    {
      const bf1 = path.join(os.tmpdir(), 'e2e-batch-a-' + Date.now() + '.bin')
      const bf2 = path.join(os.tmpdir(), 'e2e-batch-b-' + Date.now() + '.txt')
      fs.writeFileSync(bf1, randomBytes(700000)) // 不足一片
      fs.writeFileSync(bf2, randomBytes(1000))
      await navigate(c, sidA, S + '/')
      await c.send('DOM.enable', {}, sidA)
      const { root } = await c.send('DOM.getDocument', {}, sidA)
      const { nodeId } = await c.send('DOM.querySelector', { nodeId: root.nodeId, selector: '#file' }, sidA)
      await c.send('DOM.setFileInputFiles', { files: [bf1, bf2], nodeId }, sidA) // 多选
      await evalJs(c, sidA, `document.querySelector('#file').onchange()`)
      await waitFor(c, sidA, `document.querySelector('#link').textContent.startsWith('http')`, 15000, '批量链接')
      const batchLink = await evalJs(c, sidA, textOf('#link'))
      await navigate(c, sidB, batchLink)
      await waitFor(c, sidB, `document.querySelector('#fc-name').textContent === '2 个文件'`, 30000, '批量文件卡')
      await waitFor(c, sidB, `document.querySelector('#recv-file-status').textContent.includes('已接收 2 个文件')`, 30000, '批量完成')
      fs.rmSync(bf1, { force: true }); fs.rmSync(bf2, { force: true })
      ok('多文件批量:双文件选择 → 链接 → 接收完成(内存模式)')

    // ---------- 9) 断点续传:接收中途重导航(模拟刷新) → IDB 记录 → 按钮续传完成 ----------
    {
      const rf = path.join(os.tmpdir(), 'e2e-resume-' + Date.now() + '.bin')
      fs.writeFileSync(rf, randomBytes(16 * 1024 * 1024))
      await navigate(c, sidA, S + '/')
      await c.send('DOM.enable', {}, sidA)
      const { root } = await c.send('DOM.getDocument', {}, sidA)
      const { nodeId } = await c.send('DOM.querySelector', { nodeId: root.nodeId, selector: '#file' }, sidA)
      await c.send('DOM.setFileInputFiles', { files: [rf], nodeId }, sidA)
      await evalJs(c, sidA, `document.querySelector('#file').onchange()`)
      await waitFor(c, sidA, `document.querySelector('#link').textContent.startsWith('http')`, 15000, '续传链接')
      const rlink = await evalJs(c, sidA, textOf('#link'))
      const room = rlink.split('#')[1].split('.')[0]
      await navigate(c, sidB, rlink)
      // 显式轮询(waitFor 对 async 表达式恒真,不适用)
      {
        let d = 0
        for (let i = 0; i < 200 && d < 2; i++) {
          d = await evalJs(c, sidB, `(async () => (await resumeDB.get('${room}'))?.done || 0)()`)
          if (d < 2) await sleep(150)
        }
        if (d < 2) throw new Error('IDB 进度未达 2 片(实际 ' + d + ')')
      }
      // “刷新/崩溃”:先冻结页面(JS 停摆,零竞态窗口)再关闭重开
      await c.send('Page.setWebLifecycleState', { state: 'frozen' }, sidB).catch(() => {})
      await c.send('Target.closeTarget', { targetId: pgB.tid }).catch(() => {})
      const pgB2 = await newPage(c)
      sidB = pgB2.sid
      await navigate(c, sidB, rlink)
      await waitFor(c, sidB, `document.querySelector('#start-recv').textContent.includes('继续接收')`, 15000, '续传按钮')
      const doneAtKill = await evalJs(c, sidB, `(async () => (await resumeDB.get('${room}'))?.done || 0)()`)
      await evalJs(c, sidB, `document.querySelector('#start-recv').click()`)
      await waitFor(c, sidB, `document.querySelector('#recv-file-status').textContent.includes('已保存')`, 60000, '续传完成')
      // 重进后的新文档不应重拉已持久化的分片
      // i=0 是重进页面的元信息重读(设计内),排除后首片数据应从断点之后开始
      const minI = await evalJs(c, sidB,
        `Math.min(...performance.getEntriesByType('resource').map((e) => /chunk\\?i=(\\d+)/.exec(e.name)).filter(Boolean).map((m) => +m[1]).filter((i) => i > 0))`)
      if (!(minI > doneAtKill)) throw new Error(`续传应从第 ${doneAtKill + 1} 片开始,实际首拉 i=${minI}`)
      fs.rmSync(rf, { force: true })
      ok(`断点续传:中途重导航 → IDB 记录 → 从第 ${minI} 片续传完成`)

    // ---------- 10) 身份重置:应用内模态 —— 取消无副作用 / 确认换新且服务器同步 ----------
    {
      // 冻结其他页面:sidB/sidC 与 sidA 同 IP(共享或轮换同一设备条目),其心跳
      // 会在公钥同步断言窗口内与 sidA 的新公钥互相覆盖,造成竞态
      await c.send('Page.setWebLifecycleState', { state: 'frozen' }, sidB).catch(() => {})
      await c.send('Page.setWebLifecycleState', { state: 'frozen' }, sidC).catch(() => {})
      await navigate(c, sidA, S + '/')
      await waitFor(c, sidA,
        `/^#[0-9a-f]{32}$/.test(document.querySelector('#me-fp').textContent.trim())`, 10000, '重置前指纹')
      const fp1 = await evalJs(c, sidA, `document.querySelector('#me-fp').textContent.trim()`)
      const sk1 = await evalJs(c, sidA, `localStorage.getItem('cipherlane-sk')`)
      // 取消路径:模态出现 → 取消 → 指纹/密钥不变;破坏性操作默认焦点在取消
      await evalJs(c, sidA, `document.querySelector('#me-reset').click()`)
      await waitFor(c, sidA, `!document.querySelector('#modal-mask').hidden`, 3000, '模态出现')
      const focused = await evalJs(c, sidA, `document.activeElement.id`)
      if (focused !== 'modal-cancel') throw new Error('破坏性操作默认焦点应在取消,实际: ' + focused)
      await evalJs(c, sidA, `document.querySelector('#modal-cancel').click()`)
      await waitFor(c, sidA, `document.querySelector('#modal-mask').hidden`, 3000, '模态关闭')
      {
        const bad = await hiddenInvariant(c, sidA)
        if (bad.length) throw new Error('hidden 属性被 display 覆盖(取消后): ' + bad.join(','))
      }
      if (await evalJs(c, sidA, `document.querySelector('#me-fp').textContent.trim()`) !== fp1) {
        throw new Error('取消不应改变指纹')
      }
      // 确认路径:重置 → reload → 指纹/密钥更换,服务器公钥同步
      await evalJs(c, sidA, `document.querySelector('#me-reset').click()`)
      await waitFor(c, sidA, `!document.querySelector('#modal-mask').hidden`, 3000, '模态再次出现')
      await evalJs(c, sidA, `document.querySelector('#modal-ok').click()`)
      await waitFor(c, sidA,
        `document.readyState === 'complete' && document.querySelector('#me-fp') && /^#[0-9a-f]{32}$/.test(document.querySelector('#me-fp').textContent.trim()) && document.querySelector('#me-fp').textContent.trim() !== '${fp1}'`,
        15000, 'reload 后新指纹')
      const sk2 = await evalJs(c, sidA, `localStorage.getItem('cipherlane-sk')`)
      if (sk2 === sk1) throw new Error('密钥未更换')
      const pubPage = await evalJs(c, sidA, `toB64(identity.pk)`)
      let synced = false
      for (let i = 0; i < 40 && !synced; i++) {
        const pubSrv = await evalJs(c, sidA, `(async () => (await (await fetch('/api/devices')).json()).devices[0]?.pub || '')()`)
        if (pubSrv === pubPage) synced = true
        else await sleep(250)
      }
      if (!synced) throw new Error('服务器公钥未同步为新身份')
      ok('身份重置:模态取消无副作用 / 确认后指纹·密钥更换·服务器公钥同步')
    }
    }
    }

    // ---------- 11) FSA 流式保存 + 续传断点一致性 ----------
    // 回归两个耦合缺陷:
    //   a) navigator.userActivation.isActive 是布尔属性,旧代码 isActive() 必抛 TypeError
    //      并被 catch 吞掉 → hasGesture 恒 false → showSaveFilePicker/showDirectoryPicker
    //      整条流式保存分支是死代码,大文件全部退化为内存模式。
    //   b) fs 模式只在一开始 saveRec(done 恒 0),传输中却把服务端 through 推前进;
    //      刷新后按陈旧断点重拉已释放分片,必被 410 → FSA 续传实际不可用。
    // 测试用 OPFS 真实句柄冒充用户在文件选择器里选中的文件,让 FSA 分支在无头
    // 浏览器里真跑(createWritable / 绝对定位写 / IDB 句柄持久化 / 刷新续传)。
    {
      const setup = await evalJs(c, sidA, `(async () => {
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
        const post = async (bytes) => {
          for (;;) {
            const r = await fetch('/api/rooms/' + room + '/chunk', {
              method: 'POST', headers: { 'X-Room-Token': token }, body: bytes,
            })
            if (r.status === 429) { await new Promise((res) => setTimeout(res, 100)); continue }
            if (!r.ok) throw new Error('post chunk ' + r.status)
            return
          }
        }
        await post(await seal(enc.encode(JSON.stringify(meta))))
        for (let i = 0; i < 9; i++) await post(await seal(chunks[i])) // 只投前 9 片:接收方会在第 8 片写出持久化检查点后停住
        const dig = [...new Uint8Array(await crypto.subtle.digest('SHA-256', plain))]
          .map((b) => b.toString(16).padStart(2, '0')).join('')
        window.__fsa = { room, token, rest: chunks.slice(9), post, seal }
        return { link: publicOrigin() + '/#' + room + '.' + toB64(key), room, size, dig }
      })()`)
      const frag = setup.link.slice(setup.link.indexOf('#'))
      // 每个新文档都注入桩:用 OPFS 里真实 FileSystemFileHandle 冒充选择器结果,
      // 且必须可结构化克隆(会被存进 IDB 供刷新后续传)。
      const pickerStub = `
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
      `
      const pgD = await newPage(c)
      let sidD = pgD.sid
      await c.send('Page.addScriptToEvaluateOnNewDocument', { source: pickerStub }, sidD)
      await navigate(c, sidD, S + '/')

      // ① 直接回归:属性类型 / 旧写法必抛错 / helper 在手势下为 true
      const act = await evalJsGesture(c, sidD, `(() => {
        let oldThrew = false
        try { navigator.userActivation.isActive() } catch { oldThrew = true }
        return { type: typeof navigator.userActivation.isActive, oldThrew, helper: hasUserGesture() }
      })()`)
      if (act.type !== 'boolean') throw new Error('userActivation.isActive 应为布尔属性,实际 ' + act.type)
      if (!act.oldThrew) throw new Error('旧写法 isActive() 应抛 TypeError(属性不是方法)')
      if (act.helper !== true) throw new Error('有用户手势时 hasUserGesture() 应为 true,实际 ' + act.helper)
      ok('userActivation 回归:isActive 是布尔属性 → 旧 isActive() 必抛错,hasUserGesture() 手势下为 true')

      // ② 手势内进入接收 → FSA 流式分支必须真的启用(旧代码此处恒走内存模式)
      await evalJsGesture(c, sidD, `(location.hash = ${JSON.stringify(frag)}, 'ok')`)
      await waitFor(c, sidD, `document.querySelector('#fc-name').textContent === 'fsa-resume-e2e.bin'`, 20000, 'FSA 接收文件卡')
      await waitFor(c, sidD, `window.__pickerCalls >= 1`, 5000, 'showSaveFilePicker 被调用(FSA 分支启用)')
      await waitFor(c, sidD, `!document.querySelector('#fc-bar-wrap').hidden`, 10000, '接收进度条出现')
      let recD = null
      for (let i = 0; i < 200 && !(recD && recD.done >= 8); i++) {
        recD = await evalJs(c, sidD, `(async () => { const r = await resumeDB.get('${setup.room}'); return r ? { mode: r.mode, done: r.done } : null })()`)
        if (!recD || recD.done < 8) await sleep(100)
      }
      if (!recD) throw new Error('IDB 无续传记录')
      if (recD.mode !== 'fs') throw new Error('应走 FSA 流式保存(mode=fs),实际 ' + recD.mode + '(isActive 仍被误判为无手势?)')
      if (recD.done < 8) throw new Error('fs 断点记录未随检查点落盘推进(done=' + recD.done + '),刷新后必回退重拉')
      let through = 0
      for (let i = 0; i < 100 && through < recD.done + 1; i++) {
        through = await evalJs(c, sidD, `(async () => (await (await fetch('/api/rooms/${setup.room}/state')).json()).through)()`)
        if (through < recD.done + 1) await sleep(50)
      }
      if (through > recD.done + 1) throw new Error('server.through(' + through + ') 越过已持久化断点 done=' + recD.done)
      ok('FSA 断点记录:mode=fs、done=' + recD.done + ' 已落盘,server.through=' + through + ' ≤ done+1')

      // ③ 刷新:关掉页面重开同源文档(等价 F5,保留 hash)。旧实现 rec.done=0 →
      //    重进后从第 1 片重拉 → server 410 → “续传按钮”都不会出现。
      await c.send('Target.closeTarget', { targetId: pgD.tid }).catch(() => {})
      const pgD2 = await newPage(c)
      sidD = pgD2.sid
      await c.send('Page.addScriptToEvaluateOnNewDocument', { source: pickerStub }, sidD)
      await navigate(c, sidD, S + '/?resume=' + Date.now() + frag)
      await waitFor(c, sidD, `document.querySelector('#start-recv').textContent.includes('继续接收')`, 15000, '续传按钮出现')
      const recAfter = await evalJs(c, sidD, `(async () => { const r = await resumeDB.get('${setup.room}'); return r ? { mode: r.mode, done: r.done } : null })()`)
      if (!recAfter || recAfter.mode !== 'fs' || recAfter.done < 8) throw new Error('刷新后 FSA 断点记录丢失: ' + JSON.stringify(recAfter))
      // 发送方补齐剩余分片并置 done,再点"继续接收并保存"
      await evalJs(c, sidA, `(async () => {
        for (const chunk of window.__fsa.rest) await window.__fsa.post(await window.__fsa.seal(chunk))
        await fetch('/api/rooms/' + window.__fsa.room + '/done', { method: 'POST', headers: { 'X-Room-Token': window.__fsa.token } })
      })()`)
      await evalJsGesture(c, sidD, `document.querySelector('#start-recv').click()`)
      await waitFor(c, sidD, `document.querySelector('#recv-file-status').textContent.includes('已保存')`, 60000, 'FSA 续传完成')
      const out = await evalJs(c, sidD, `(async () => {
        const root = await navigator.storage.getDirectory()
        const f = await (await root.getFileHandle('fsa-picked.bin')).getFile()
        const b = new Uint8Array(await f.arrayBuffer())
        const d = [...new Uint8Array(await crypto.subtle.digest('SHA-256', b))]
          .map((x) => x.toString(16).padStart(2, '0')).join('')
        return { size: b.length, dig: d }
      })()`)
      if (out.size !== setup.size || out.dig !== setup.dig) {
        throw new Error('FSA 续传后文件内容不完整: size=' + out.size + '/' + setup.size + ' digest一致=' + (out.dig === setup.dig))
      }
      const recGone = await evalJs(c, sidD, `(async () => (await resumeDB.get('${setup.room}')) || null)()`)
      if (recGone) throw new Error('完成后 IDB 断点记录未清理')
      ok('FSA 刷新续传:保留 ' + recD.done + ' 片断点 → 续传后 SHA-256 与原文一致、断点记录已清理')
      await c.send('Target.closeTarget', { targetId: pgD2.tid }).catch(() => {})
    }

    // ---------- 5) 服务器中途下线:建立失败可退 ----------
    await navigate(c, sidA, S + '/') // 趁服务器还在先回到首页(之后不再导航,页面操作走内存态)
    server.kill('SIGINT')
    await sleep(300)
    await evalJs(c, sidA, `document.querySelector('#text').value = '发往已死服务器的消息'`)
    await evalJs(c, sidA, `document.querySelector('#send-text').click()`)
    await waitFor(c, sidA, `document.querySelector('#send-status').textContent.includes('建立密道失败')`, 15000, '服务器下线报错')
    await evalJs(c, sidA, `document.querySelector('#cancel-send').click()`)
    await waitFor(c, sidA, `!document.querySelector('#view-landing').hidden`, 5000, '返回首页')
    ok('服务器中途下线:报"建立密道失败"且可返回(不卡死在无按钮视图)')

    c.close()
    console.log(`\nbrowser: 全部 ${passed} 组通过`)
  } finally {
    cleanup()
  }
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
