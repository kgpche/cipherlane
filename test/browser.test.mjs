// 浏览器冒烟测试 —— 零依赖：CDP over WebSocket 驱动本机 Chrome/Chromium
//
// 覆盖前端关键路径（app.js 至今无自动化测试，历史 P0 均出在前端）：
//   1) 链接模式文本全链路：双页面 发送→链接→接收→逐字一致
//   2) 定向发送到离线设备：建立阶段失败必须有“返回首页”退路（回归：曾死锁在无按钮视图）
//   3) 同序号并发拉取：先到者得、后来者收到“正被另一个接收方使用”（回归：曾 500+挂起）
//   4) 服务器中途下线：建立失败可退，返回按钮可用
//   5) 文件传输全链路：真实 Worker 加密 + 接收方文件卡与完成状态
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

async function waitFor(c, sid, expr, timeout = 20000, what = '') {
  const t0 = Date.now()
  for (;;) {
    if (await evalJs(c, sid, `!!(${expr})`)) return
    if (Date.now() - t0 > timeout) throw new Error('等待超时(' + (timeout / 1000) + 's): ' + (what || expr))
    await sleep(120)
  }
}

const textOf = (sel) => `document.querySelector('${sel}') ? document.querySelector('${sel}').textContent : null`

// ---------- 启动:服务器 + 无头浏览器 ----------
function launchServer() {
  // CL_SERVER_BIN: 直接测试打包产物（SEA 单文件二进制），而非源码
  const child = process.env.CL_SERVER_BIN
    ? spawn(process.env.CL_SERVER_BIN, [], {
        env: { ...process.env, PORT: String(PORT) }, stdio: ['ignore', 'ignore', 'pipe'],
      })
    : spawn(process.execPath, ['server.js'], {
        cwd: ROOT, env: { ...process.env, PORT: String(PORT) }, stdio: ['ignore', 'ignore', 'pipe'],
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
  return sessionId
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
    const sidA = await newPage(c)
    const sidB = await newPage(c)
    await navigate(c, sidA, S + '/')
    await navigate(c, sidB, S + '/')

    // 公钥指纹：心跳拿到 IP 后,本机名片显示 8 位十六进制指纹(TOFU 人工比对锚点)
    await waitFor(c, sidA,
      `document.querySelector('#me-fp') && /^#[0-9a-f]{8}$/.test(document.querySelector('#me-fp').textContent.trim())`,
      10000, '本机指纹显示')
    ok('公钥指纹显示:本机名片 8 位十六进制')

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
    ok('链接模式文本全链路:发送 → 链接 → 逐字一致 → ack 凭证校验通过')

    // ---------- 2) 定向发送到离线设备:建立失败必须有退路(回归:曾死锁) ----------
    await navigate(c, sidA, S + '/')
    await evalJs(c, sidA, `
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

    // ---------- 3) 同序号并发拉取:先到先得,后来者明确报错(回归:曾 500+永久挂起) ----------
    const concurrent = await evalJs(c, sidA, `
      (async () => {
        const r = await fetch('/api/rooms', { method: 'POST' })
        const { room, token } = await r.json()
        const p1 = getChunk(room, 0)   // 分片未投:两个都进长轮询等待
        const p2 = getChunk(room, 0)
        setTimeout(() => fetch('/api/rooms/' + room + '/chunk', {
          method: 'POST', headers: { 'X-Room-Token': token }, body: new Uint8Array([1, 2, 3]),
        }), 500)
        const res = await Promise.allSettled([p1, p2])
        return res.map((x) => (x.status === 'fulfilled' ? 'ok' : x.reason.message))
          .sort().join(' | ')
      })()`)
    if (!concurrent.includes('ok') || !concurrent.includes('另一个接收方')) {
      throw new Error('并发拉取结果异常: ' + concurrent)
    }
    ok('同序号并发拉取:一者成功、一者收到"正被另一个接收方使用"(回归覆盖)')

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
    const sidC = await newPage(c)
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
