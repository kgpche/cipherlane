/* cipherlane · 密道 —— 前端逻辑
 *
 * 两种模式：
 *   - 设备直发：一个局域网 IP = 一台终端（名字 + 几何头像 + X25519 身份密钥）。
 *     选设备 → 邀请（hint 预览加密）→ 对方接受 → X25519 派生房间密钥传输。
 *   - 链接模式：随机密钥藏 URL #fragment，零知识中继（跨网段 / 经聊天工具）。
 *
 * 加密层自动选择：
 *   - 安全上下文（localhost / https）→ 原生 WebCrypto
 *   - 局域网 http（非安全上下文，无 crypto.subtle）→ 纯 JS AES-256-GCM（aesgcm.js）
 * 两条路径线上格式一致：IV(12) || 密文 || TAG(16)
 */
'use strict'

const CHUNK = 1024 * 1024 // 1 MiB 明文分片
const $ = (s) => document.querySelector(s)
const enc = new TextEncoder()
const dec = new TextDecoder()
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const subtle = typeof crypto !== 'undefined' && crypto.subtle ? crypto.subtle : null

// ---------- 工具 ----------
function toB64(bytes) {
  let bin = ''
  for (let i = 0; i < bytes.length; i += 0x8000)
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000))
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function fromB64(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
const concat = (a, b) => {
  const o = new Uint8Array(a.length + b.length)
  o.set(a)
  o.set(b, a.length)
  return o
}
function fmtBytes(n) {
  if (n < 1024) return n + ' B'
  const u = ['KB', 'MB', 'GB', 'TB']
  let i = -1
  do { n /= 1024; i++ } while (n >= 1024 && i < u.length - 1)
  return n.toFixed(1) + ' ' + u[i]
}
function makeSpeed() {
  let last = null, ema = 0
  return (bytes) => {
    const now = performance.now()
    if (last) {
      const dt = (now - last.t) / 1000
      if (dt > 0.25) {
        const inst = (bytes - last.b) / dt
        ema = ema ? ema * 0.7 + inst * 0.3 : inst
      }
    }
    last = { b: bytes, t: now }
    return ema
  }
}
async function copyText(t) {
  try { await navigator.clipboard.writeText(t); return true } catch {}
  try {
    const ta = document.createElement('textarea')
    ta.value = t
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    ta.remove()
    return ok
  } catch { return false }
}

// ---------- 几何头像（avatar.js，单色相 Bauhaus 构图） ----------
const avatarSvg = (seed, size) => Avatar.svg(seed, size)

// ---------- 加密层（AES-GCM，双路径） ----------
// 密钥按次传输经参数传递（不做全局状态：同页并发收发会互相污染对方的密钥）
async function sealWith(rawKey, pt) {
  if (subtle) {
    const k = await subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt'])
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, k, pt))
    return concat(iv, ct)
  }
  return AESGCM.seal(rawKey, pt)
}
async function unsealWith(rawKey, packed) {
  if (subtle) {
    const k = await subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt'])
    const iv = packed.subarray(0, 12)
    const ct = packed.subarray(12)
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv }, k, ct))
  }
  return AESGCM.open(rawKey, packed)
}
// ---------- 加密 RPC：分片加解密走 Worker（不卡进度条），Worker 不可用/崩溃回退主线程 ----------
const cryptoRPC = (() => {
  let worker = null // null=未初始化 false=不可用
  const pending = new Map()
  let seq = 0
  function ensure() {
    if (worker !== null) return worker
    try {
      const w = new Worker('/crypto-worker.js')
      w.onmessage = (e) => {
        const p = pending.get(e.data.id)
        if (!p) return
        pending.delete(e.data.id)
        if (e.data.ok) p.resolve(new Uint8Array(e.data.data))
        else p.reject(new Error(e.data.error || 'crypto worker error'))
      }
      w.onerror = () => {
        worker = false
        try { w.terminate() } catch {}
        for (const p of pending.values()) p.reject(new Error('crypto worker 异常'))
        pending.clear()
      }
      worker = w
    } catch { worker = false }
    return worker
  }
  async function call(op, key, data) {
    const w = ensure()
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data)
    if (!w) return op === 'seal' ? sealWith(key, bytes) : unsealWith(key, bytes)
    try {
      return await new Promise((resolve, reject) => {
        const id = ++seq
        pending.set(id, { resolve, reject })
        // 输入不 transfer（保留主线程副本供回退），输出由 worker 零拷贝回传
        w.postMessage({ id, op, key, data: bytes })
      })
    } catch (e) {
      if (worker === false) return op === 'seal' ? sealWith(key, bytes) : unsealWith(key, bytes)
      throw e
    }
  }
  return call
})()
const sealRPC = (key, pt) => cryptoRPC('seal', key, pt)
const unsealRPC = (key, packed) => cryptoRPC('unseal', key, packed)

// ---------- API ----------
async function api(path, opts) {
  const r = await fetch(path, opts)
  if (!r.ok) {
    const e = new Error((await r.json().catch(() => ({}))).error || r.status)
    e.status = r.status
    throw e
  }
  return r
}
async function postChunk(room, token, bytes, signal) {
  for (;;) {
    const r = await fetch(`/api/rooms/${room}/chunk`, {
      method: 'POST',
      headers: { 'X-Room-Token': token },
      body: bytes,
      signal,
    })
    if (r.status === 429) {
      await sleep(250) // 背压：接收方还没跟上
      continue
    }
    if (!r.ok) throw new Error('发送失败 ' + r.status)
    return (await r.json()).index
  }
}
let chunkReqSeq = 0
async function getChunk(room, i, signal) {
  for (;;) {
    // 分片一次性消费：URL 带唯一序号 + cache:'no-store'，确保并发同序号请求
    // 各自独立到达服务器（否则浏览器/代理可能合并 in-flight 请求，把同一份
    // 响应发给两个等待者，绕过服务端的先到先得语义）
    const r = await fetch(`/api/rooms/${room}/chunk?i=${i}&n=${chunkReqSeq++}`, { signal, cache: 'no-store' })
    if (r.status === 408) continue // 长轮询到期，立刻重试继续等
    if (r.status === 409) throw new Error('此链接正被另一个接收方使用')
    if (r.status === 404) throw new Error('链接无效或已过期')
    if (r.status === 410) throw new Error('此链接已被使用、已过期，或发送方已中断')
    if (!r.ok) throw new Error('网络错误 ' + r.status)
    return new Uint8Array(await r.arrayBuffer())
  }
}

// ---------- 视图 ----------
function showView(name) {
  for (const v of ['landing', 'send', 'recv']) $('#view-' + v).hidden = v !== name
}
const setBar = (id, pct) => { $('#' + id).style.width = Math.min(100, pct * 100).toFixed(1) + '%' }
const setStatus = (id, text, cls) => {
  const el = $('#' + id)
  el.textContent = text
  el.className = 'status' + (cls ? ' ' + cls : '')
}

// ---------- 设备身份 / 在线状态 ----------
function guessName() {
  const ua = navigator.userAgent
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android'
    : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS X/.test(ua) ? 'macOS'
    : /Linux/.test(ua) ? 'Linux' : '未知系统'
  const br = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera'
    : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox'
    : /Safari\//.test(ua) ? 'Safari' : '浏览器'
  return br + ' · ' + os
}
const store = {
  get(k) { try { return localStorage.getItem(k) } catch { return null } },
  set(k, v) { try { localStorage.setItem(k, v) } catch {} },
}

// X25519 长期身份密钥（本浏览器唯一；localStorage 不可用时退化为内存）
const identity = (() => {
  const saved = store.get('cipherlane-sk')
  if (saved) {
    try {
      const sk = fromB64(saved)
      if (sk.length === 32) return { sk, pk: X25519.publicFromSecret(sk) }
    } catch {}
  }
  const kp = X25519.genKey()
  store.set('cipherlane-sk', toB64(kp.sk))
  return kp
})()

const my = {
  name: store.get('cipherlane-name') || guessName(),
  ip: null,
  secret: store.get('cipherlane-secret') || null, // 存 localStorage：同浏览器多标签共享，避免互踩轮换
}
let selectedIp = null       // 设备直发的目标
let deviceCache = []        // 最近一次设备列表

async function heartbeat() {
  try {
    const r = await api('/api/presence', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(my.secret ? { 'X-Device-Secret': my.secret } : {}),
      },
      body: JSON.stringify({ name: my.name, pub: toB64(identity.pk) }),
    })
    const j = await r.json()
    my.ip = j.ip
    my.secret = j.secret
    store.set('cipherlane-secret', j.secret)
  } catch { /* 网络抖动，下个心跳重试 */ }
}

async function refreshDevices() {
  try {
    const j = await (await fetch('/api/devices')).json()
    deviceCache = j.devices || []
    renderDevices()
  } catch {}
}

function renderDevices() {
  const box = $('#devices')
  box.innerHTML = ''
  const others = deviceCache.filter((d) => d.ip !== my.ip)
  $('#devices-count').textContent = others.length ? `· ${others.length} 台在线` : ''
  if (selectedIp && !others.some((d) => d.ip === selectedIp)) selectedIp = null
  const empty = $('#devices-empty')
  empty.hidden = others.length > 0
  for (const d of others) {
    const card = document.createElement('button')
    card.className = 'device' + (d.ip === selectedIp ? ' selected' : '')
    card.innerHTML = `${avatarSvg(d.ip, 40)}<span class="d-name"></span><span class="d-ip"></span>`
    card.querySelector('.d-name').textContent = d.name || '未命名设备'
    card.querySelector('.d-ip').textContent = d.ip
    card.onclick = () => {
      selectedIp = selectedIp === d.ip ? null : d.ip
      renderDevices()
    }
    box.appendChild(card)
  }
  updateModeHint()
}

function selectedDevice() {
  return deviceCache.find((d) => d.ip === selectedIp && d.ip !== my.ip) || null
}
function updateModeHint() {
  const dev = selectedDevice()
  $('#mode-hint').innerHTML = dev
    ? `发送目标：<b></b>（点击设备卡片可取消）`
    : `未选设备 → 生成接收链接。在页面任意位置 <code>Ctrl+V</code> 可直接粘贴发送。`
  if (dev) {
    const b = $('#mode-hint').querySelector('b')
    b.textContent = (dev.name || '未命名设备') + ' (' + dev.ip + ')'
  }
}

// ---------- 收到的邀请 ----------
const incomingOffers = new Map() // id → offer

function renderIncoming() {
  const wrap = $('#incoming-wrap')
  const box = $('#incoming')
  box.innerHTML = ''
  wrap.hidden = incomingOffers.size === 0
  for (const o of incomingOffers.values()) {
    const card = document.createElement('div')
    card.className = 'offer'
    card.innerHTML = `${avatarSvg(o.from.ip || '?', 40)}
      <div class="o-body">
        <div class="o-title"><b class="o-name"></b><span class="o-ip"></span></div>
        <div class="o-preview dim"></div>
        <div class="o-error err" hidden></div>
      </div>
      <div class="o-actions">
        <button class="btn primary o-accept">接受</button>
        <button class="btn o-reject">拒绝</button>
      </div>`
    card.querySelector('.o-name').textContent = o.from.name || '未知设备'
    card.querySelector('.o-ip').textContent = ' @ ' + (o.from.ip || '?')
    card.querySelector('.o-preview').textContent = '正在解密预览…'
    const acceptBtn = card.querySelector('.o-accept')
    acceptBtn.disabled = true // 预览解密成功后才可接受
    previewOffer(o, card).then(() => { if (o._key) acceptBtn.disabled = false })
    acceptBtn.onclick = () => acceptOffer(o)
    card.querySelector('.o-reject').onclick = () => rejectOffer(o)
    box.appendChild(card)
  }
}

// 用会话密钥解密邀请预览（文件名 / 大小 / 类型），服务器全程只见密文
async function previewOffer(o, card) {
  try {
    const theirPub = fromB64(o.pub)
    const key = X25519.sessionKey(X25519.dh(identity.sk, theirPub), theirPub, identity.pk, o.room)
    const info = JSON.parse(dec.decode(await unsealWith(key, fromB64(o.hint))))
    o._key = key
    const p = card.querySelector('.o-preview')
    p.textContent = info.kind === 'text'
      ? '📝 一段文本 · ' + fmtBytes(info.size || 0)
      : '📄 ' + (info.name || '未命名文件') + ' · ' + fmtBytes(info.size || 0)
  } catch {
    card.querySelector('.o-preview').hidden = true
    const err = card.querySelector('.o-error')
    err.hidden = false
    err.textContent = '预览解密失败（邀请可能被篡改），建议拒绝'
    card.querySelector('.o-accept').disabled = true
  }
}

async function rejectOffer(o) {
  incomingOffers.delete(o.id)
  renderIncoming()
  api(`/api/offers/${o.id}/reject`, { method: 'POST', headers: { 'X-Device-Secret': my.secret } }).catch(() => {})
}

async function acceptOffer(o) {
  if (!o._key) return
  // 先锁定邀请，避免双击重复接受
  incomingOffers.delete(o.id)
  renderIncoming()
  try {
    await api(`/api/offers/${o.id}/accept`, { method: 'POST', headers: { 'X-Device-Secret': my.secret } })
  } catch (e) {
    alert('接受失败：' + e.message)
    return
  }
  const from = o.from || null
  receiveInto(o.room, o._key, from)
}

// 长轮询本机邀请（任意视图期间都保持监听，回到首页即可看到）
async function pollOffers() {
  for (;;) {
    if (!my.secret) { await sleep(1000); continue }
    try {
      const r = await fetch('/api/offers', { headers: { 'X-Device-Secret': my.secret } })
      if (r.status === 401) { my.secret = null; await heartbeat(); continue }
      if (!r.ok) { await sleep(2000); continue }
      const j = await r.json()
      let changed = false
      for (const o of j.offers || []) {
        if (!incomingOffers.has(o.id)) {
          incomingOffers.set(o.id, o)
          changed = true
          notifyNewOffer('📮 密道 · 收到传输请求', `${(o.from && o.from.name) || '未知设备'}（${(o.from && o.from.ip) || '?'}）想发给你内容`)
        }
      }
      if (changed && !$('#view-landing').hidden) renderIncoming()
    } catch { await sleep(2000) }
  }
}

// ---------- 到货提醒：系统通知（localhost/https）+ 标题闪烁（任何环境）+ 震动（移动端） ----------
const notifyNewOffer = (() => {
  let flashTimer = null
  const origTitle = document.title
  const stopFlash = () => {
    if (flashTimer) { clearInterval(flashTimer); flashTimer = null; document.title = origTitle }
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) stopFlash() })
  return (title, body) => {
    try {
      if ('Notification' in window && Notification.permission === 'granted') {
        const n = new Notification(title, { body, tag: 'cipherlane-offer' })
        n.onclick = () => { window.focus(); n.close() }
      }
    } catch {}
    try { navigator.vibrate && navigator.vibrate([120, 60, 120]) } catch {}
    if (!flashTimer) {
      let on = false
      flashTimer = setInterval(() => {
        document.title = (on = !on) ? '📮 收到传输请求！' : origTitle
      }, 900)
    }
  }
})()
// 首次点击时申请通知权限（局域网 http 无 Notification API 时静默跳过）
document.addEventListener('click', function askOnce() {
  document.removeEventListener('click', askOnce)
  try {
    if ('Notification' in window && Notification.permission === 'default') Notification.requestPermission()
  } catch {}
})

// ---------- 发送 ----------
const sendState = { stopPoll: null } // stopPoll：取消发送时停状态轮询

async function startSend(kind, payload, target) {
  // kind: 'file' | 'text'；payload: File | string；target: 设备对象（null = 链接模式）
  // 已选设备但此刻拿不到（刚掉线）→ 明确报错，绝不静默降级成链接模式
  if (!target && selectedIp) {
    alert('所选设备已离线，请重新选择（本次未发送）')
    selectedIp = null
    renderDevices()
    refreshDevices()
    return
  }
  showView('send')
  const isText = kind === 'text'
  const size = isText ? enc.encode(payload).length : payload.size
  const name = isText ? null : payload.name
  const mime = isText ? null : payload.type || 'application/octet-stream'
  const dataChunks = isText ? 1 : Math.ceil(size / CHUNK)
  const count = 1 + dataChunks // 0 号是加密元信息

  $('#send-title').textContent = target
    ? `📤 发送给 ${target.name || '未命名设备'}`
    : isText ? '📤 发送文本（链接模式）' : '📤 发送文件（链接模式）'
  $('#send-target').hidden = !target
  if (target) {
    $('#send-target').innerHTML = `${avatarSvg(target.ip, 30)} <b class="st-name"></b> <span class="dim st-ip"></span>`
    $('#send-target').querySelector('.st-name').textContent = target.name || '未命名设备'
    $('#send-target').querySelector('.st-ip').textContent = '@ ' + target.ip
  }
  setStatus('send-status', '⚙️ 正在建立密道…', 'warn')

  // 先绑定取消按钮：建立阶段任何一步失败都必须保证有退路
  let room = null, token = null
  const ctl = new AbortController()
  const cancelBtn = $('#cancel-send')
  cancelBtn.className = 'btn danger'
  cancelBtn.textContent = '取消发送'
  cancelBtn.onclick = async () => {
    ctl.abort()
    if (sendState.stopPoll) sendState.stopPoll()
    if (room) api(`/api/rooms/${room}`, { method: 'DELETE', headers: { 'X-Room-Token': token } }).catch(() => {})
    showView('landing')
  }

  let link = null
  let key
  try {
    // 建房 + 协商密钥（密钥只存在于双方浏览器内存；定向模式的密钥经 X25519 派生，永不过网）
    ;({ room, token } = await (await api('/api/rooms', { method: 'POST', signal: ctl.signal })).json())
    if (target) {
      const theirPub = fromB64(target.pub)
      const shared = X25519.dh(identity.sk, theirPub)
      key = X25519.sessionKey(shared, identity.pk, theirPub, room)
      const hintInfo = { kind, name: isText ? null : name, size }
      const hint = toB64(await sealWith(key, enc.encode(JSON.stringify(hintInfo))))
      await api(`/api/rooms/${room}/offer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Room-Token': token },
        body: JSON.stringify({ to: target.ip, pub: toB64(identity.pk), hint }),
        signal: ctl.signal,
      })
      setStatus('send-status', `🟡 等待 ${target.name || '对方'} 接受…`, 'warn')
    } else {
      key = new Uint8Array(32)
      crypto.getRandomValues(key)
      link = location.origin + '/#' + room + '.' + toB64(key)
      setStatus('send-status', '🟡 等待接收方打开链接…', 'warn')
    }
  } catch (e) {
    if (ctl.signal.aborted) return
    setStatus('send-status', '❌ 建立密道失败：' + e.message, 'err')
    cancelBtn.className = 'btn'
    cancelBtn.textContent = '返回首页'
    cancelBtn.onclick = () => showView('landing')
    return
  }
  $('#link-row').hidden = !link
  const qrBox = $('#qr')
  if (link) {
    $('#link').textContent = link
    try {
      // 手机扫码直达；链接超长（>108B）则隐藏二维码
      const qrSvg = QRCode.svg(link, 148)
      qrBox.innerHTML = qrSvg ? qrSvg + '<p class="qr-cap">📱 手机扫码接收</p>' : ''
      qrBox.hidden = !qrSvg
    } catch { qrBox.hidden = true }
  } else {
    qrBox.hidden = true
  }
  setBar('bar-sent', 0); setBar('bar-pulled', 0)
  $('#sent-meta').textContent = '已发送 0 B / ' + fmtBytes(size)
  $('#pulled-meta').textContent = '对方已接收 0 B'

  $('#copy').onclick = async () => {
    $('#copy').textContent = (await copyText(link)) ? '已复制 ✓' : '复制失败'
    setTimeout(() => ($('#copy').textContent = '复制链接'), 1500)
  }

  // 终态：成功时把进度补到 100%，停轮询，"取消发送"换成语义正确的"返回首页"
  const finish = (ok, msg) => {
    if (sendState.stopPoll) sendState.stopPoll()
    if (ok) {
      setBar('bar-pulled', 1)
      $('#pulled-meta').textContent = '对方已接收 ' + fmtBytes(size) + '（100%）'
    }
    if (msg) setStatus('send-status', msg, ok ? 'ok' : 'err')
    cancelBtn.className = 'btn' + (ok ? ' primary' : ' danger')
    cancelBtn.textContent = '返回首页'
    cancelBtn.onclick = () => showView('landing')
  }

  // 状态轮询：对方是否接受 / 接收进度 / 是否收完（终态一律走 finish，防止消息被后续轮询覆盖）
  sendState.stopPoll = (() => {
    const timer = setInterval(async () => {
      try {
        const r = await fetch(`/api/rooms/${room}/state`)
        if (r.status === 404) return finish(false, '❌ 传输已中断（房间过期或被回收）')
        const st = await r.json()
        if (st.acked) return finish(true, target ? `✅ ${target.name || '对方'}已完整接收` : '✅ 对方已完整接收')
        if (st.receiverSeen && !st.acked)
          setStatus('send-status', '📡 传输中…', 'warn')
        const gotBytes = Math.max(0, Math.min(st.pulled - 1, dataChunks)) * CHUNK
        const got = Math.min(gotBytes, size)
        setBar('bar-pulled', size ? got / size : 1)
        $('#pulled-meta').textContent =
          '对方已接收 ' + fmtBytes(got) + '（' + Math.round((size ? got / size : 1) * 100) + '%）'
      } catch {}
    }, 1200)
    return () => clearInterval(timer)
  })()

  // 定向模式：等对方接受后才投递分片（背压窗口需要接收方在拉取）
  if (target) {
    for (;;) {
      if (ctl.signal.aborted) return
      let st
      try {
        const r = await fetch(`/api/rooms/${room}/state`)
        if (r.status === 404) return finish(false, '❌ 对方超时未接受，邀请已过期')
        st = await r.json()
      } catch { await sleep(1000); continue }
      if (st.offer === 'accepted') break
      if (st.offer === 'rejected') return finish(false, `❌ ${target.name || '对方'}拒绝了传输`)
      await sleep(800)
    }
    setStatus('send-status', '📡 对方已接受，传输中…', 'warn')
  }

  try {
    // 0 号分片：加密元信息（文件名也加密）
    const meta = { v: 1, type: isText ? 'text' : 'file', name, mime, size, count }
    await postChunk(room, token, await sealRPC(key, enc.encode(JSON.stringify(meta))), ctl.signal)

    // 数据分片：Worker 加密 + 一片预加密流水线（网络发送与下一片加密重叠）
    const speed = makeSpeed()
    if (isText) {
      await postChunk(room, token, await sealRPC(key, enc.encode(payload)), ctl.signal)
      setBar('bar-sent', 1)
      $('#sent-meta').textContent = '已发送 ' + fmtBytes(size)
    } else {
      let off = 0
      let nextEnc = null
      while (off < size) {
        const encThis = nextEnc || sealRPC(key, new Uint8Array(await payload.slice(off, off + CHUNK).arrayBuffer()))
        const nextOff = off + CHUNK
        nextEnc = nextOff < size
          ? sealRPC(key, new Uint8Array(await payload.slice(nextOff, nextOff + CHUNK).arrayBuffer()))
          : null
        await postChunk(room, token, await encThis, ctl.signal)
        off = Math.min(nextOff, size)
        setBar('bar-sent', off / size)
        const sp = speed(off)
        $('#sent-meta').textContent =
          `已发送 ${fmtBytes(off)} / ${fmtBytes(size)}` + (sp ? ` · ${fmtBytes(sp)}/s` : '')
      }
      if (size === 0) setBar('bar-sent', 1)
    }
    await api(`/api/rooms/${room}/done`, { method: 'POST', headers: { 'X-Room-Token': token } })
    setStatus('send-status', '🟢 已全部发出，等待对方接收完成…', 'warn')
  } catch (e) {
    if (ctl.signal.aborted) return
    finish(false, '❌ 发送失败：' + e.message)
  }
}

// ---------- 接收（文本 / 文件 两套独立布局） ----------

// 统一入口：链接模式（fragment 密钥）与设备直发（X25519 派生密钥）共用
async function receiveInto(room, key, fromInfo) {
  showView('recv')
  $('#recv-text-layout').hidden = true
  $('#recv-file-layout').hidden = true
  $('#recv-from').hidden = !fromInfo
  if (fromInfo) {
    $('#recv-from').innerHTML = `来自 ${avatarSvg(fromInfo.ip || '?', 34)} <b class="rf-name"></b> <span class="dim rf-ip"></span>`
    $('#recv-from').querySelector('.rf-name').textContent = fromInfo.name || '未知设备'
    $('#recv-from').querySelector('.rf-ip').textContent = '@ ' + (fromInfo.ip || '?')
  }

  const ctl = new AbortController()
  const back = () => { ctl.abort(); showView('landing') }
  $('#recv-text-back').onclick = back
  $('#recv-file-back').onclick = back

  let meta
  try {
    // 0 号分片 = 加密元信息
    const packed = await getChunk(room, 0, ctl.signal)
    meta = JSON.parse(dec.decode(await unsealWith(key, packed)))
  } catch (e) {
    if (ctl.signal.aborted) return
    $('#recv-title').textContent = '📥 接收'
    $('#recv-file-layout').hidden = false
    setStatus('recv-file-status', '❌ ' + e.message, 'err')
    return
  }

  if (meta.type === 'text') return receiveText(room, key, ctl)
  return receiveFile(room, key, meta, ctl)
}

// 文本：解密即呈现，无进度条无保存动作
async function receiveText(room, key, ctl) {
  $('#recv-title').textContent = '📥 接收文本'
  $('#recv-text-layout').hidden = false
  setStatus('recv-text-status', '🟡 正在解密…', 'warn')
  $('#recv-text').hidden = true
  $('#recv-text-meta').hidden = true
  $('#recv-copy').hidden = true
  try {
    const pt = dec.decode(await unsealRPC(key, await getChunk(room, 1, ctl.signal)))
    $('#recv-text').hidden = false
    $('#recv-text').textContent = pt
    $('#recv-text-meta').hidden = false
    $('#recv-text-meta').textContent =
      `共 ${[...pt].length} 字 · ${fmtBytes(enc.encode(pt).length)} · 端到端加密已验签`
    const copyBtn = $('#recv-copy')
    copyBtn.hidden = false
    copyBtn.textContent = '复制文本'
    copyBtn.onclick = async () => {
      copyBtn.textContent = (await copyText(pt)) ? '已复制 ✓' : '复制失败'
      setTimeout(() => (copyBtn.textContent = '复制文本'), 1500)
    }
    setStatus('recv-text-status', '✅ 已解密接收', 'ok')
    await fetch(`/api/rooms/${room}/ack`, { method: 'POST' }).catch(() => {})
  } catch (e) {
    if (!ctl.signal.aborted) setStatus('recv-text-status', '❌ ' + e.message, 'err')
  }
}

// 文件：文件卡为主角；接受时的手势还在有效期内，自动拉起保存选择器
async function receiveFile(room, key, meta, ctl) {
  $('#recv-title').textContent = '📥 接收文件'
  $('#recv-file-layout').hidden = false
  $('#recv-filecard').hidden = !meta.size
  $('#fc-name').textContent = meta.name || '(未命名)'
  $('#fc-size').textContent = fmtBytes(meta.size)
  $('#fc-bar-wrap').hidden = true
  $('#recv-meta').textContent = ''
  $('#recv-actions').hidden = true

  if (!meta.size && meta.count === 1) {
    saveEmpty(meta.name)
    setStatus('recv-file-status', '✅ 空文件已保存', 'ok')
    await fetch(`/api/rooms/${room}/ack`, { method: 'POST' }).catch(() => {})
    return
  }

  setStatus('recv-file-status', '🟡 准备接收…', 'warn')
  const start = () => doReceiveFile(room, key, meta, ctl.signal).then((r) => {
    if (r === 'picker-dismissed') {
      $('#recv-actions').hidden = false
      setStatus('recv-file-status', '🟢 已就绪，点击接收并保存', 'ok')
    }
  }).catch((e) => {
    if (!ctl.signal.aborted) setStatus('recv-file-status', '❌ ' + e.message, 'err')
  })
  $('#start-recv').onclick = start
  start() // 自动开始：手势新鲜时直接弹保存选择器；被关闭/失败则显示手动按钮
}

async function doReceiveFile(room, key, meta, signal) {
  // 仅在有激活手势时才自动拉起保存选择器（接受邀请的点击）；
  // 无手势（链接模式直接打开/手势过期/嵌入式 webview）直接走内存模式自动下载，
  // 避免个别环境（如 Electron webview）无手势时选择器 Promise 永久挂起
  let hasGesture = false
  try {
    hasGesture = !!(navigator.userActivation && navigator.userActivation.isActive && navigator.userActivation.isActive())
  } catch { /* 部分嵌入式 webview 的 userActivation 实现不完整 */ }
  const useFSA = 'showSaveFilePicker' in window && hasGesture
  let sink = null
  if (useFSA) {
    try {
      const handle = await window.showSaveFilePicker({ suggestedName: meta.name || 'received' })
      sink = { mode: 'fs', ws: await handle.createWritable() }
    } catch (e) {
      if (e && e.name === 'AbortError') return 'picker-dismissed' // 用户关闭了选择器 → 显示手动按钮
      // 手势过期等其他异常 → 内存模式兜底（完成后自动下载）
    }
  }
  if (!sink) {
    if (meta.size > 512 * 1024 * 1024 && !confirm('此浏览器不支持流式保存，大文件将占用较多内存，继续？')) return 'picker-dismissed'
    sink = { mode: 'mem', parts: [] }
  }

  setStatus('recv-file-status', '📡 接收中…', 'warn')
  $('#fc-bar-wrap').hidden = false
  const speed = makeSpeed()
  let got = 0
  for (let i = 1; i < meta.count; i++) {
    const packed = await getChunk(room, i, signal)
    const pt = await unsealRPC(key, packed) // GCM 验签失败会直接抛错
    got += pt.length
    if (sink.mode === 'fs') await sink.ws.write(pt)
    else sink.parts.push(pt)
    setBar('bar-recv', got / (meta.size || 1))
    const sp = speed(got)
    $('#recv-meta').textContent =
      `已接收 ${fmtBytes(got)} / ${fmtBytes(meta.size)}` + (sp ? ` · ${fmtBytes(sp)}/s` : '')
  }

  if (sink.mode === 'fs') {
    await sink.ws.close()
  } else {
    const blob = new Blob(sink.parts)
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = meta.name || 'received'
    a.click()
    setTimeout(() => URL.revokeObjectURL(a.href), 60_000)
  }
  setBar('bar-recv', 1)
  setStatus('recv-file-status', `✅ 已保存 ${meta.name || 'received'}（${fmtBytes(meta.size)}）`, 'ok')
  await fetch(`/api/rooms/${room}/ack`, { method: 'POST' }).catch(() => {})
}

function saveEmpty(name) {
  const blob = new Blob([new Uint8Array(0)])
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = name || 'received'
  a.click()
}

// 链接模式入口：从 URL fragment 取房间号与密钥
async function startReceive() {
  const frag = location.hash.slice(1)
  const m = /^([0-9A-Za-z]{10})\.([A-Za-z0-9_-]{43})$/.exec(frag)
  if (!m) { showView('landing'); return }
  receiveInto(m[1], fromB64(m[2]), null)
}

// ---------- 入口 ----------
$('#pick').onclick = (e) => { e.stopPropagation(); $('#file').click() }
$('#drop').onclick = () => $('#file').click()
$('#file').onchange = () => {
  const f = $('#file').files[0]
  if (f) startSend('file', f, selectedDevice())
  $('#file').value = ''
}
const drop = $('#drop')
for (const ev of ['dragover', 'dragenter']) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over') })
for (const ev of ['dragleave', 'drop']) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over') })
drop.addEventListener('drop', (e) => {
  const f = e.dataTransfer.files[0]
  if (f) startSend('file', f, selectedDevice())
})
$('#send-text').onclick = () => {
  const t = $('#text').value
  if (!t.trim()) return
  if (enc.encode(t).length > CHUNK) return alert('文本超过 1MB 上限')
  startSend('text', t, selectedDevice())
}

// 全局粘贴：粘贴文件/截图直接发送；粘贴文本时已选设备则直接发、否则填入文本框
document.addEventListener('paste', (e) => {
  if ($('#view-landing').hidden) return
  const t = e.target
  if (t && (t.id === 'text' || t.id === 'me-name')) return // 输入框内正常粘贴
  const files = e.clipboardData && e.clipboardData.files
  if (files && files.length) {
    e.preventDefault()
    startSend('file', files[0], selectedDevice())
    return
  }
  const text = e.clipboardData && e.clipboardData.getData('text/plain')
  if (text) {
    const dev = selectedDevice()
    if (dev) {
      e.preventDefault()
      if (enc.encode(text).length > CHUNK) {
        $('#text').value = text
        alert('文本超过 1MB 上限，已填入文本框')
        $('#text').focus()
        return
      }
      startSend('text', text, dev)
    } else if (document.activeElement !== $('#text')) {
      e.preventDefault()
      $('#text').value = text
      $('#text').focus()
    }
  }
})

// 我的名片：名称可编辑（对方看到的发送者名称）
{
  const input = $('#me-name')
  input.value = my.name
  input.onchange = () => {
    my.name = input.value.trim().slice(0, 32) || guessName()
    input.value = my.name
    store.set('cipherlane-name', my.name)
    heartbeat()
  }
}

// ---------- 启动 ----------
if (location.hash.length > 1) {
  startReceive()
} else {
  showView('landing')
}
// 同标签页粘贴新接收链接时（仅 hash 变化不重载文档）重新进入接收
window.addEventListener('hashchange', () => {
  if (location.hash.length > 1) startReceive()
})
// 心跳 + 设备列表刷新 + 邀请监听（所有模式下常驻）
heartbeat().then(refreshDevices)
setInterval(() => { heartbeat().then(refreshDevices) }, 5000)
$('#me-avatar').innerHTML = Avatar.placeholder(36) // 中性占位，拿到真实 IP 后显示真头像
;(async () => {
  for (let i = 0; i < 50 && !my.ip; i++) await sleep(100)
  if (my.ip) {
    $('#me-avatar').innerHTML = avatarSvg(my.ip, 36)
    $('#me-ip').textContent = my.ip
  }
})()
pollOffers()
