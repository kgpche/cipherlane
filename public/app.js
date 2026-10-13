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

// ---------- 公钥指纹（TOFU：首次使用即信任，此后变化即警示） ----------
// SHA256 前 4 字节十六进制，供双方人工口头比对；指纹不匹配 = 有人调包了公钥
function fpOf(pubB64) {
  const h = SHA256.hash(fromB64(pubB64)).subarray(0, 4)
  return Array.from(h, (b) => b.toString(16).padStart(2, '0')).join('')
}
const knownPubs = {
  load() { try { return JSON.parse(store.get('cipherlane-pubs') || '{}') } catch { return {} } },
  save(m) { store.set('cipherlane-pubs', JSON.stringify(m)) },
}

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
// ---------- 加密 RPC：分片加解密走 Worker 池（不卡进度条、多核并行），不可用/崩溃回退主线程 ----------
const cryptoRPC = (() => {
  let pool = null // null=未初始化；[]=不可用（回退主线程）
  const pending = new Map()
  let seq = 0
  let next = 0
  function ensure() {
    if (pool !== null) return pool
    try {
      // 纯 JS AES 路径（明文 http 非安全上下文）单 worker 仅 ~8MB/s，多核池线性提速
      const n = Math.max(1, Math.min(4, navigator.hardwareConcurrency || 2))
      const ws = []
      const onmessage = (e) => {
        const p = pending.get(e.data.id)
        if (!p) return
        pending.delete(e.data.id)
        if (e.data.ok) p.resolve(new Uint8Array(e.data.data))
        else p.reject(new Error(e.data.error || 'crypto worker error'))
      }
      for (let k = 0; k < n; k++) {
        const w = new Worker('/crypto-worker.js')
        w.onmessage = onmessage
        w.onerror = () => {
          // 任一 worker 异常即整池退役（脚本加载失败等通常全员失败），回退主线程
          for (const x of ws) { try { x.terminate() } catch {} }
          pool = []
          for (const p of pending.values()) p.reject(new Error('crypto worker 异常'))
          pending.clear()
        }
        ws.push(w)
      }
      pool = ws
    } catch { pool = [] }
    return pool
  }
  async function call(op, key, data) {
    const ws = ensure()
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data)
    const fallback = () => (op === 'seal' ? sealWith(key, bytes) : unsealWith(key, bytes))
    if (!ws.length) return fallback()
    const w = ws[next++ % ws.length] // 轮转分发：各分片相互独立，无需保序
    try {
      return await new Promise((resolve, reject) => {
        const id = ++seq
        pending.set(id, { resolve, reject })
        // 输入不 transfer（保留主线程副本供回退），输出由 worker 零拷贝回传
        w.postMessage({ id, op, key, data: bytes })
      })
    } catch (e) {
      if (pool !== null && pool.length === 0) return fallback() // 池已退役（onerror 已重置 pool）
      throw e
    }
  }
  return call
})()
const sealRPC = (key, pt) => cryptoRPC('seal', key, pt)
const unsealRPC = (key, packed) => cryptoRPC('unseal', key, packed)

// ack 密钥凭证：SHA256(key ‖ 标签 ‖ 房间号)。无密钥者算不出、服务器只转存不验证，
// 发送方取回后本地比对即可分辨伪造 ack（与 cli.mjs 的 node:crypto 构造逐字节一致）
function ackProofOf(key, room) {
  const bytes = concat(key, enc.encode('cipherlane/ack/v1|' + room))
  return Array.from(SHA256.hash(bytes), (b) => b.toString(16).padStart(2, '0')).join('')
}

// ---------- API ----------
// 带超时的 fetch：连接"停滞"（既不返回也不报错）时中断重连，而非无限挂起。
// 只对超时重试；快速失败（拒连等）与用户取消原样上抛。
async function fetchT(url, opts, ms) {
  const ctl = new AbortController()
  const follow = () => ctl.abort()
  if (opts.signal) {
    if (opts.signal.aborted) throw new DOMException('Aborted', 'AbortError')
    opts.signal.addEventListener('abort', follow)
  }
  const timer = setTimeout(() => ctl.abort(new DOMException('timeout', 'TimeoutError')), ms)
  try {
    return await fetch(url, { ...opts, signal: ctl.signal })
  } finally {
    clearTimeout(timer)
    if (opts.signal) opts.signal.removeEventListener('abort', follow)
  }
}
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
    let r
    try {
      r = await fetchT(`/api/rooms/${room}/chunk`, {
        method: 'POST',
        headers: { 'X-Room-Token': token },
        body: bytes,
        signal,
      }, 30_000)
    } catch (e) {
      if (signal && signal.aborted) throw new Error('已取消')
      if (e && e.name === 'TimeoutError') { await sleep(500); continue } // 连接停滞:重连重投
      throw e
    }
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
    let r
    try {
      // 超时给足长轮询余量（服务端 25s 到期返回 408 后客户端本就重试）
      // X-Resume 让房间进入可续传模式(只读回放,供刷新后重拉);旧服务器忽略此头
      r = await fetchT(`/api/rooms/${room}/chunk?i=${i}&n=${chunkReqSeq++}`, { signal, cache: 'no-store', headers: { 'X-Resume': '1' } }, 35_000)
    } catch (e) {
      if (signal && signal.aborted) throw new Error('已取消')
      if (e && e.name === 'TimeoutError') continue // 连接停滞:重连再等
      throw e
    }
    if (r.status === 408) continue // 长轮询到期，立刻重试继续等
    if (r.status === 429) { await sleep(500); continue } // 并发长轮询上限:稍候重试
    if (r.status === 409) throw new Error('此链接正被另一个接收方使用')
    if (r.status === 404) throw new Error('链接无效或已过期')
    if (r.status === 410) throw new Error('此链接已被使用、已过期，或发送方已中断')
    if (!r.ok) throw new Error('网络错误 ' + r.status)
    return new Uint8Array(await r.arrayBuffer())
  }
}

// ---------- 断点续传记录（IndexedDB,零依赖;明文 http 下同样可用） ----------
// 链接模式接收方的进度:done = 已持久化的最后数据分片序号(0 = 尚无);
// FSA 模式存目录内文件句柄(可结构化克隆),内存模式逐片存 Blob。
const resumeDB = (() => {
  const open = () => new Promise((res, rej) => {
    const rq = indexedDB.open('cipherlane-resume', 1)
    rq.onupgradeneeded = () => rq.result.createObjectStore('transfers')
    rq.onsuccess = () => res(rq.result)
    rq.onerror = () => rej(rq.error)
  })
  const tx = async (mode, fn) => {
    try {
      const db = await open()
      return await new Promise((res, rej) => {
        const t = db.transaction('transfers', mode)
        const r = fn(t.objectStore('transfers'))
        t.oncomplete = () => { res(r && r.result); db.close() }
        t.onerror = () => { rej(t.error); db.close() }
      })
    } catch { return undefined } // IDB 不可用(隐私模式等)→ 静默退化为不可续传
  }
  return {
    get: (room) => tx('readonly', (st) => st.get(room)),
    set: (room, rec) => tx('readwrite', (st) => st.put(rec, room)),
    del: (room) => tx('readwrite', (st) => st.delete(room)),
  }
})()

// progress 上报(可续传模式):滞后一片提交(同 CLI 语义);旧服务器 404 → 静默禁用
const progressPost = (() => {
  const dead = new Set()
  return (room, through) => {
    if (dead.has(room)) return
    fetch(`/api/rooms/${room}/progress`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ through }),
    }).then((r) => { if (r.status === 404 || r.status === 409) dead.add(room) }).catch(() => {})
  }
})()

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
  // 按名称本地化排序(zh 拼序,中英混排稳定):首见顺序无规律,设备多了找不到了
  const collator = new Intl.Collator('zh', { numeric: true, sensitivity: 'base' })
  const others = deviceCache
    .filter((d) => d.ip !== my.ip)
    .sort((a, b) => collator.compare(a.name || '', b.name || '') || (a.ip < b.ip ? -1 : 1))
  $('#devices-count').textContent = others.length ? `· ${others.length} 台在线` : ''
  if (selectedIp && !others.some((d) => d.ip === selectedIp)) selectedIp = null
  const empty = $('#devices-empty')
  empty.hidden = others.length > 0
  // 公钥变更检测（TOFU）：首见公钥记档；之后不一致则持续警示且不覆盖记录
  const known = knownPubs.load()
  let dirty = false
  for (const d of others) {
    const changed = known[d.ip] && known[d.ip] !== d.pub
    if (!changed && known[d.ip] !== d.pub) { known[d.ip] = d.pub; dirty = true }
    const card = document.createElement('button')
    card.className = 'device' + (d.ip === selectedIp ? ' selected' : '') + (changed ? ' fp-changed' : '')
    card.innerHTML = `${avatarSvg(d.ip, 36)}<span class="d-name"></span><span class="d-sub${changed ? ' warn' : ''}"></span>`
    card.querySelector('.d-name').textContent = d.name || '未命名设备'
    const sub = card.querySelector('.d-sub')
    if (changed) {
      // 变化警示占满副行:变化后的指纹无比对意义,提示本身就比指纹重要
      sub.textContent = '⚠ 公钥已变化'
    } else {
      const ipEl = document.createElement('span')
      ipEl.className = 'd-ip'
      ipEl.textContent = d.ip
      const fpEl = document.createElement('span')
      fpEl.className = 'd-fp'
      fpEl.textContent = '#' + fpOf(d.pub)
      fpEl.title = '公钥指纹（与对方页面显示的比对，防调包）'
      sub.append(ipEl, fpEl)
    }
    card.onclick = () => {
      selectedIp = selectedIp === d.ip ? null : d.ip
      renderDevices()
    }
    box.appendChild(card)
  }
  if (dirty) knownPubs.save(known)
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
        <div class="o-title"><b class="o-name"></b><span class="o-ip"></span><span class="o-fp dim"></span></div>
        <div class="o-preview dim"></div>
        <div class="o-error err" hidden></div>
      </div>
      <div class="o-actions">
        <button class="btn primary o-accept">接受</button>
        <button class="btn o-reject">拒绝</button>
      </div>`
    card.querySelector('.o-name').textContent = o.from.name || '未知设备'
    card.querySelector('.o-ip').textContent = ' @ ' + (o.from.ip || '?')
    const oFp = card.querySelector('.o-fp')
    oFp.textContent = '#' + fpOf(o.pub)
    oFp.title = '发送方公钥指纹'
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
      : info.kind === 'batch'
        ? '🗂 ' + (info.count || '?') + ' 个文件 · ' + fmtBytes(info.size || 0)
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
  const from = o.from ? { ...o.from, fp: fpOf(o.pub) } : null
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

const FILES_MAX = 256
const dataChunkCount = (n) => (n === 0 ? 0 : Math.ceil(n / CHUNK))

async function startSend(kind, payload, target) {
  // kind: 'file' | 'text' | 'batch'；payload: File | string | [{file, rel}]；target: 设备对象（null = 链接模式）
  // 已选设备但此刻拿不到（刚掉线）→ 明确报错，绝不静默降级成链接模式
  if (!target && selectedIp) {
    alert('所选设备已离线，请重新选择（本次未发送）')
    selectedIp = null
    renderDevices()
    refreshDevices()
    return
  }
  if (kind === 'batch' && payload.length > FILES_MAX) {
    alert(`文件数超过上限 ${FILES_MAX}（当前 ${payload.length}），请分批发送`)
    return
  }
  showView('send')
  const isText = kind === 'text'
  const isBatch = kind === 'batch'
  const size = isBatch ? payload.reduce((n, x) => n + x.file.size, 0)
    : isText ? enc.encode(payload).length : payload.size
  const name = isBatch ? null : isText ? null : payload.name
  const mime = isBatch ? null : isText ? null : payload.type || 'application/octet-stream'
  const manifest = isBatch
    ? payload.map((x) => ({ name: x.rel, size: x.file.size, count: dataChunkCount(x.file.size) }))
    : null
  const dataChunks = isBatch ? manifest.reduce((n, m) => n + m.count, 0)
    : isText ? 1 : Math.ceil(size / CHUNK)
  const count = 1 + dataChunks // 0 号是加密元信息

  $('#send-title').textContent = target
    ? `📤 发送给 ${target.name || '未命名设备'}`
    : isText ? '📤 发送文本（链接模式）'
    : isBatch ? `📤 发送 ${manifest.length} 个文件（链接模式）`
    : '📤 发送文件（链接模式）'
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
      const hintInfo = isBatch ? { kind, count: manifest.length, size } : { kind, name: isText ? null : name, size }
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
      // 手机扫码直达；链接超长（>106B）则隐藏二维码
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
        if (st.acked) {
          const verified = st.ackProof && st.ackProof === ackProofOf(key, room)
          const who = target ? target.name || '对方' : '对方'
          return finish(true, verified
            ? `✅ ${who}已完整接收（凭证校验通过）`
            : `⚠ ${who}已接收，但 ack 无有效凭证——房间号泄露时可能被伪造，建议与对方口头确认`)
        }
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
    const meta = isBatch
      ? { v: 1, type: 'batch', files: manifest, count, size }
      : { v: 1, type: isText ? 'text' : 'file', name, mime, size, count }
    await postChunk(room, token, await sealRPC(key, enc.encode(JSON.stringify(meta))), ctl.signal)

    // 数据分片：Worker 加密 + 一片预加密流水线（网络发送与下一片加密重叠）
    const speed = makeSpeed()
    if (isBatch) {
      let sent = 0
      for (let f = 0; f < payload.length; f++) {
        const { file, rel } = payload[f]
        const n = manifest[f].count
        for (let i = 0; i < n; i++) {
          const pt = new Uint8Array(await file.slice(i * CHUNK, Math.min((i + 1) * CHUNK, file.size)).arrayBuffer())
          await postChunk(room, token, await sealRPC(key, pt), ctl.signal)
          sent += pt.length
          setBar('bar-sent', size ? sent / size : 1)
          const sp = speed(sent)
          $('#sent-meta').textContent =
            `[${f + 1}/${payload.length}] ${rel} · ${fmtBytes(sent)} / ${fmtBytes(size)}` + (sp ? ` · ${fmtBytes(sp)}/s` : '')
        }
      }
      if (size === 0) setBar('bar-sent', 1)
    } else if (isText) {
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
async function receiveInto(room, key, fromInfo, fromLink = false) {
  showView('recv')
  $('#recv-text-layout').hidden = true
  $('#recv-file-layout').hidden = true
  $('#recv-from').hidden = !fromInfo
  if (fromInfo) {
    $('#recv-from').innerHTML = `来自 ${avatarSvg(fromInfo.ip || '?', 34)} <b class="rf-name"></b> <span class="dim rf-ip"></span>` + (fromInfo.fp ? ` <span class="dim rf-fp"></span>` : '')
    $('#recv-from').querySelector('.rf-name').textContent = fromInfo.name || '未知设备'
    $('#recv-from').querySelector('.rf-ip').textContent = '@ ' + (fromInfo.ip || '?')
    const rfFp = $('#recv-from').querySelector('.rf-fp')
    if (rfFp) { rfFp.textContent = '#' + fromInfo.fp; rfFp.title = '发送方公钥指纹' }
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
  if (meta.type === 'batch') return receiveBatch(room, key, meta, ctl)
  // 断点续传仅链接模式(设备直发的会话密钥不落盘);fromLink 由入口传入
  const rec = fromLink ? await resumeDB.get(room) : null
  return receiveFile(room, key, meta, ctl, rec)
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
    await fetch(`/api/rooms/${room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, room) }) }).catch(() => {})
  } catch (e) {
    if (!ctl.signal.aborted) setStatus('recv-text-status', '❌ ' + e.message, 'err')
  }
}

// 文件：文件卡为主角；接受时的手势还在有效期内，自动拉起保存选择器
// 路径分段净化(批量接收的相对路径逐段过滤,防穿越/点文件)
function safeSeg(seg) {
  const t = String(seg).replace(/[^\w.\-\u4e00-\u9fa5 ]+/g, '_').replace(/^[.\s]+/, '')
  return t || '_'
}

// 批量接收:manifest 顺序拉流,逐文件写入目录(Chromium 流式)/内存模式逐个下载
async function receiveBatch(room, key, meta, ctl) {
  $('#recv-title').textContent = '📥 接收批量文件'
  $('#recv-file-layout').hidden = false
  $('#recv-filecard').hidden = false
  $('#fc-name').textContent = `${meta.files.length} 个文件`
  $('#fc-size').textContent = fmtBytes(meta.size || 0)
  $('#fc-bar-wrap').hidden = true
  $('#recv-meta').textContent = ''
  $('#recv-actions').hidden = true

  const start = () => doReceiveBatch(room, key, meta, ctl.signal).then((r) => {
    if (r === 'picker-dismissed') {
      $('#recv-actions').hidden = false
      setStatus('recv-file-status', '🟢 已就绪，点击接收并保存', 'ok')
    }
  }).catch((e) => {
    if (!ctl.signal.aborted) setStatus('recv-file-status', '❌ ' + e.message, 'err')
  })
  $('#start-recv').onclick = start
  start()
}

async function doReceiveBatch(room, key, meta, signal) {
  let hasGesture = false
  try {
    hasGesture = !!(navigator.userActivation && navigator.userActivation.isActive && navigator.userActivation.isActive())
  } catch { /* 部分嵌入式 webview 的 userActivation 实现不完整 */ }
  // 目录选择器:有新鲜手势的 Chromium 流式落盘;否则内存模式完成后逐个下载
  let dir = null
  if ('showDirectoryPicker' in window && hasGesture) {
    try {
      dir = await window.showDirectoryPicker({ mode: 'readwrite' })
    } catch (e) {
      if (e && e.name === 'AbortError') return 'picker-dismissed'
      dir = null // 手势过期等 → 内存模式兜底
    }
  }
  if (!dir && (meta.size || 0) > 512 * 1024 * 1024 && !confirm('此浏览器不支持流式目录保存，大文件将占用较多内存，继续？')) return 'picker-dismissed'

  setStatus('recv-file-status', '📡 接收中…', 'warn')
  $('#fc-bar-wrap').hidden = false
  const speed = makeSpeed()
  const memParts = [] // 无目录句柄时的逐文件 Blob
  let got = 0
  let idx = 1 // 下一个文件的首个数据分片序号
  for (let f = 0; f < meta.files.length; f++) {
    const info = meta.files[f]
    $('#fc-name').textContent = `[${f + 1}/${meta.files.length}] ${info.name}`
    $('#fc-size').textContent = `${fmtBytes(got)} / ${fmtBytes(meta.size || 0)}`
    const parts = String(info.name || '').split('/').map(safeSeg).filter(Boolean)
    const fname = parts.pop() || 'received'
    let ws = null
    let parts8 = null
    if (dir) {
      let d = dir
      for (const seg of parts) d = await d.getDirectoryHandle(seg, { create: true })
      const fh = await d.getFileHandle(fname, { create: true })
      ws = await fh.createWritable()
    } else parts8 = []
    const n = info.count || 0
    for (let i = 0; i < n; i++) {
      const pt = await unsealRPC(key, await getChunk(room, idx + i, signal)) // GCM 验签失败直接抛错
      got += pt.length
      if (ws) await ws.write(pt)
      else parts8.push(pt)
      setBar('bar-recv', meta.size ? got / meta.size : 1)
      const sp = speed(got)
      $('#fc-size').textContent = `${fmtBytes(got)} / ${fmtBytes(meta.size || 0)}` + (sp ? ` · ${fmtBytes(sp)}/s` : '')
    }
    idx += n
    if (ws) await ws.close()
    else memParts.push({ name: fname, blob: new Blob(parts8) })
  }
  if (!dir) {
    // 内存模式:顺序触发下载(浏览器会请求"下载多个文件"授权,点允许即可)
    const urls = []
    for (const it of memParts) {
      const a = document.createElement('a')
      const u = URL.createObjectURL(it.blob)
      urls.push(u)
      a.href = u
      a.download = it.name
      a.click()
      await sleep(250)
    }
    setTimeout(() => { for (const u of urls) URL.revokeObjectURL(u) }, 60_000)
  }
  setBar('bar-recv', 1)
  $('#fc-name').textContent = `${meta.files.length} 个文件`
  setStatus('recv-file-status',
    `✅ 已接收 ${meta.files.length} 个文件（${fmtBytes(meta.size || 0)}）` + (dir ? '，已写入所选目录' : '，已触发浏览器下载'),
    'ok')
  await fetch(`/api/rooms/${room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, room) }) }).catch(() => {})
}

async function receiveFile(room, key, meta, ctl, rec) {
  $('#recv-title').textContent = '📥 接收文件'
  $('#recv-file-layout').hidden = false
  $('#recv-filecard').hidden = !meta.size
  $('#fc-name').textContent = meta.name || '(未命名)'
  $('#fc-size').textContent = fmtBytes(meta.size)
  $('#fc-bar-wrap').hidden = true
  $('#recv-meta').textContent = ''
  $('#recv-actions').hidden = true
  // 断点续传(链接模式):记录存在且与本次 meta 匹配 → 询问后续传
  if (rec && rec.meta && rec.meta.size === meta.size && rec.meta.count === meta.count && rec.done > 0) {
    setStatus('recv-file-status',
      `↻ 检测到未完成的接收（${fmtBytes(rec.done * CHUNK)} / ${fmtBytes(meta.size)}），继续？`, 'warn')
    $('#recv-actions').hidden = false
    $('#start-recv').textContent = '继续接收并保存'
    $('#start-recv').onclick = () => {
      $('#recv-actions').hidden = true
      doReceiveFile(room, key, meta, ctl.signal, rec).catch((e) => {
        if (!ctl.signal.aborted) setStatus('recv-file-status', '❌ ' + e.message, 'err')
      })
    }
    return
  }
  if (rec) await resumeDB.del(room) // 记录与本次传输不符:清掉重来

  if (!meta.size && meta.count === 1) {
    saveEmpty(meta.name)
    setStatus('recv-file-status', '✅ 空文件已保存', 'ok')
    await fetch(`/api/rooms/${room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, room) }) }).catch(() => {})
    return
  }

  setStatus('recv-file-status', '🟡 准备接收…', 'warn')
  $('#start-recv').textContent = '接收并保存'
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

async function doReceiveFile(room, key, meta, signal, rec) {
  // 仅在有激活手势时才自动拉起保存选择器（接受邀请的点击）；
  // 无手势（链接模式直接打开/手势过期/嵌入式 webview）直接走内存模式自动下载，
  // 避免个别环境（如 Electron webview）无手势时选择器 Promise 永久挂起
  let hasGesture = false
  try {
    hasGesture = !!(navigator.userActivation && navigator.userActivation.isActive && navigator.userActivation.isActive())
  } catch { /* 部分嵌入式 webview 的 userActivation 实现不完整 */ }

  // ---- 断点续传状态(链接模式):rec.done = 已持久化的最后数据分片序号 ----
  let done = rec && rec.done > 0 ? Math.min(rec.done, meta.count - 1) : 0
  let sink = null
  let handle = null

  if (rec && rec.mode === 'fs' && rec.handle) {
    // FSA 续传:句柄存于 IDB,凭"继续接收并保存"按钮的手势重新授权
    try {
      const perm = await rec.handle.queryPermission({ mode: 'readwrite' })
      if (perm !== 'granted' && !(await rec.handle.requestPermission({ mode: 'readwrite' })))
        throw new Error('目录/文件授权被拒绝')
      handle = rec.handle
      // keepExistingData + 绝对定位写入:分片边界之后的字节直接被覆盖,天然截齐
      sink = { mode: 'fs', ws: await handle.createWritable({ keepExistingData: true }) }
    } catch (e) {
      if (e && e.name === 'AbortError') return 'picker-dismissed'
      sink = null // 授权失败 → 内存模式兜底(原进度作废,从头)
    }
  } else if (rec && rec.mode === 'mem' && Array.isArray(rec.parts)) {
    // 内存模式续传:分片 Blob 存于 IDB(明文 http 也可用,磁盘支撑)
    sink = { mode: 'mem', parts: rec.parts.slice() }
    done = Math.min(done, sink.parts.length)
    sink.parts.length = done
  }

  if (!sink) {
    const useFSA = 'showSaveFilePicker' in window && hasGesture
    if (useFSA) {
      try {
        handle = await window.showSaveFilePicker({ suggestedName: meta.name || 'received' })
        sink = { mode: 'fs', ws: await handle.createWritable() }
      } catch (e) {
        if (e && e.name === 'AbortError') return 'picker-dismissed' // 用户关闭了选择器 → 显示手动按钮
        // 手势过期等其他异常 → 内存模式兜底（完成后自动下载）
      }
    }
    if (!sink) {
      if (meta.size > 512 * 1024 * 1024 && !confirm('此浏览器不支持流式保存，大文件将占用较多内存，继续？')) return 'picker-dismissed'
      sink = { mode: 'mem', parts: [] }
      done = 0
    }
  }
  const saveRec = () => resumeDB.set(room, {
    room, mode: sink.mode, done, meta: { size: meta.size, count: meta.count, name: meta.name },
    handle: sink.mode === 'fs' ? handle : undefined,
    parts: sink.mode === 'mem' ? sink.parts : undefined,
  })
  if (sink.mode === 'fs' && handle) await saveRec() // 句柄先存,刷新后可续
  progressPost(room, done) // 元信息 + 已续传部分对齐服务端进度

  setStatus('recv-file-status', done ? `↻ 继续接收（已 ${fmtBytes(done * CHUNK)}）…` : '📡 接收中…', 'warn')
  $('#fc-bar-wrap').hidden = false
  const speed = makeSpeed()
  let got = done * CHUNK
  let pos = got // FSA 绝对定位
  // 拉取流水线：深度 3 的并行预取，掩盖无线网往返（服务端本就支持按序号乱序拉取；
  // 串行"拉一片等一片"时空转一个 RTT，是 WiFi 实际吞吐的主要瓶颈）
  const DEPTH = 3
  let nextI = done + 1
  const inflight = []
  const pump = () => {
    while (inflight.length < DEPTH && nextI < meta.count) {
      const i = nextI++
      const p = getChunk(room, i, signal)
      p.catch(() => {}) // 未消费的预取在中断/失败时不成为 unhandledrejection
      inflight.push({ i, p })
    }
  }
  pump()
  while (inflight.length) {
    const { i, p } = inflight.shift()
    pump()
    const packed = await p
    const j = i // 本片的绝对序号(供进度上报)
    const pt = await unsealRPC(key, packed) // GCM 验签失败会直接抛错
    got += pt.length
    if (sink.mode === 'fs') await sink.ws.write({ type: 'write', position: pos, data: pt })
    else sink.parts.push(pt)
    pos += pt.length
    setBar('bar-recv', got / (meta.size || 1))
    const sp = speed(got)
    $('#recv-meta').textContent =
      `已接收 ${fmtBytes(got)} / ${fmtBytes(meta.size)}` + (sp ? ` · ${fmtBytes(sp)}/s` : '')
    // 滞后一片提交(同 CLI):写完 j 片才声明 j 之前的都安全,留整片余量
    progressPost(room, j - 1 > done ? j - 1 : done)
    done = j
    if (sink.mode === 'mem') await saveRec() // FSA 模式句柄已存,无需逐片更新
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
  progressPost(room, meta.count) // 全量落盘
  await resumeDB.del(room)
  setBar('bar-recv', 1)
  setStatus('recv-file-status', `✅ 已保存 ${meta.name || 'received'}（${fmtBytes(meta.size)}）`, 'ok')
  await fetch(`/api/rooms/${room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, room) }) }).catch(() => {})
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
  receiveInto(m[1], fromB64(m[2]), null, true)
}

// ---------- 入口 ----------
$('#pick').onclick = (e) => { e.stopPropagation(); $('#file').click() }
$('#pick-dir').onclick = (e) => { e.stopPropagation(); $('#file-dir').click() }
$('#drop').onclick = () => $('#file').click()
const toBatch = (list) => [...list].map((f) => ({ file: f, rel: f.webkitRelativePath || f.name }))
$('#file').onchange = () => {
  const fs = [...$('#file').files]
  if (fs.length === 1) startSend('file', fs[0], selectedDevice())
  else if (fs.length > 1) startSend('batch', toBatch(fs), selectedDevice())
  $('#file').value = ''
}
$('#file-dir').onchange = () => {
  const fs = [...$('#file-dir').files]
  if (fs.length) startSend('batch', toBatch(fs), selectedDevice())
  $('#file-dir').value = ''
}
const drop = $('#drop')
for (const ev of ['dragover', 'dragenter']) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over') })
for (const ev of ['dragleave', 'drop']) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over') })
drop.addEventListener('drop', (e) => {
  const fs = [...e.dataTransfer.files]
  if (fs.length === 1) startSend('file', fs[0], selectedDevice())
  else if (fs.length > 1) startSend('batch', toBatch(fs), selectedDevice())
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
    const fs = [...files]
    if (fs.length === 1) startSend('file', fs[0], selectedDevice())
    else startSend('batch', toBatch(fs), selectedDevice())
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
  // 重置身份密钥：换新 X25519 身份（identity 是启动时读入的模块常量，重载页面生效最干净）。
  // 曾向你发过的设备会看到"⚠ 公钥已变化"——这正是 TOFU 在起作用
  $('#me-reset').onclick = () => {
    if (!confirm('重置身份密钥？你的公钥指纹将变化，向你要过文件的设备会看到"公钥已变化"警示。')) return
    const kp = X25519.genKey()
    store.set('cipherlane-sk', toB64(kp.sk))
    location.reload()
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
    $('#me-fp').textContent = '#' + fpOf(toB64(identity.pk))
    $('#me-fp').title = '本机公钥指纹（对方设备卡上显示的应与此一致）'
  }
})()
pollOffers()
