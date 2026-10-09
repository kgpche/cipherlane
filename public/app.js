/* cipherlane · 密道 —— 前端逻辑
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

// ---------- 加密层（每页一把密钥） ----------
let sessionKey = null
let importedKey = null

async function seal(pt) {
  if (subtle) {
    if (!importedKey)
      importedKey = await subtle.importKey('raw', sessionKey, 'AES-GCM', false, ['encrypt', 'decrypt'])
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, importedKey, pt))
    return concat(iv, ct)
  }
  return AESGCM.seal(sessionKey, pt)
}
async function unseal(packed) {
  if (subtle) {
    if (!importedKey)
      importedKey = await subtle.importKey('raw', sessionKey, 'AES-GCM', false, ['encrypt', 'decrypt'])
    const iv = packed.subarray(0, 12)
    const ct = packed.subarray(12)
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv }, importedKey, ct))
  }
  return AESGCM.open(sessionKey, packed)
}

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
async function getChunk(room, i, signal) {
  for (;;) {
    const r = await fetch(`/api/rooms/${room}/chunk?i=${i}`, { signal })
    if (r.status === 408) continue // 长轮询到期，立刻重试继续等
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

// ---------- 发送 ----------
const sendState = { ctl: null, stopPoll: null }

async function startSend(kind, payload) {
  // kind: 'file' | 'text'；payload: File | string
  showView('send')
  $('#send-title').textContent = kind === 'text' ? '📤 发送文本' : '📤 发送文件'
  setStatus('send-status', '⚙️ 正在建立密道…', 'warn')

  const isText = kind === 'text'
  const size = isText ? enc.encode(payload).length : payload.size
  const name = isText ? null : payload.name
  const mime = isText ? null : payload.type || 'application/octet-stream'
  const dataChunks = isText ? 1 : Math.ceil(size / CHUNK)
  const count = 1 + dataChunks // 0 号是加密元信息

  // 建房 + 生成密钥（密钥只存在于双方浏览器内存与 URL fragment）
  const { room, token } = await (await api('/api/rooms', { method: 'POST' })).json()
  sessionKey = new Uint8Array(32)
  crypto.getRandomValues(sessionKey)
  importedKey = null
  const link = location.origin + '/#' + room + '.' + toB64(sessionKey)
  $('#link').textContent = link
  setStatus('send-status', '🟡 等待接收方打开链接…', 'warn')
  setBar('bar-sent', 0); setBar('bar-pulled', 0)
  $('#sent-meta').textContent = '已发送 0 B / ' + fmtBytes(size)
  $('#pulled-meta').textContent = '对方已接收 0 B'

  const ctl = new AbortController()
  sendState.ctl = ctl
  $('#cancel-send').onclick = async () => {
    ctl.abort()
    if (sendState.stopPoll) sendState.stopPoll()
    api(`/api/rooms/${room}`, { method: 'DELETE', headers: { 'X-Room-Token': token } }).catch(() => {})
    showView('landing')
  }
  $('#copy').onclick = async () => {
    $('#copy').textContent = (await copyText(link)) ? '已复制 ✓' : '复制失败'
    setTimeout(() => ($('#copy').textContent = '复制链接'), 1500)
  }

  // 状态轮询：对方是否打开 / 接收进度 / 是否收完
  sendState.stopPoll = (() => {
    const timer = setInterval(async () => {
      try {
        const st = await (await fetch(`/api/rooms/${room}/state`)).json()
        if (st.acked) {
          setStatus('send-status', '✅ 对方已完整接收', 'ok')
          clearInterval(timer)
          return
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

  try {
    // 0 号分片：加密元信息（文件名也加密）
    const meta = { v: 1, type: isText ? 'text' : 'file', name, mime, size, count }
    await postChunk(room, token, await seal(enc.encode(JSON.stringify(meta))), ctl.signal)

    // 数据分片
    const speed = makeSpeed()
    const t0 = performance.now()
    if (isText) {
      await postChunk(room, token, await seal(enc.encode(payload)), ctl.signal)
      setBar('bar-sent', 1)
      $('#sent-meta').textContent = '已发送 ' + fmtBytes(size)
    } else {
      let off = 0
      while (off < size) {
        const slice = new Uint8Array(await payload.slice(off, off + CHUNK).arrayBuffer())
        await postChunk(room, token, await seal(slice), ctl.signal)
        off += slice.length
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
    setStatus('send-status', '❌ 发送失败：' + e.message, 'err')
  }
}

// ---------- 接收 ----------
const recvState = { ctl: null }

async function startReceive() {
  const frag = location.hash.slice(1)
  const m = /^([0-9A-Za-z]{10})\.([A-Za-z0-9_-]{43})$/.exec(frag)
  if (!m) { showView('landing'); return }
  const room = m[1]
  sessionKey = fromB64(m[2])
  importedKey = null
  showView('recv')
  setStatus('recv-status', '🟡 正在连接，等待发送方投递…（发送方需要先点开始）', 'warn')

  const ctl = new AbortController()
  recvState.ctl = ctl
  $('#cancel-recv').onclick = () => location.replace('/')

  let meta
  try {
    // 0 号分片 = 加密元信息（长轮询：发送方就绪前会一直等）
    const packed = await getChunk(room, 0, ctl.signal)
    meta = JSON.parse(dec.decode(await unseal(packed)))
  } catch (e) {
    if (ctl.signal.aborted) return
    return setStatus('recv-status', '❌ ' + e.message, 'err')
  }

  if (meta.type === 'text') {
    try {
      const pt = dec.decode(await unseal(await getChunk(room, 1, ctl.signal)))
      $('#recv-text').hidden = false
      $('#recv-text').textContent = pt
      $('#recv-text-actions').hidden = false
      $('#recv-copy').onclick = async () => copyText(pt)
      setStatus('recv-status', '✅ 已解密收到文本（' + fmtBytes(pt.length) + '）', 'ok')
      await fetch(`/api/rooms/${room}/ack`, { method: 'POST' }).catch(() => {})
    } catch (e) {
      if (!ctl.signal.aborted) setStatus('recv-status', '❌ ' + e.message, 'err')
    }
    return
  }

  // 文件：先展示（解密后的）信息，再由用户点击保存（浏览器要求用户手势才能选保存位置）
  const info = $('#recv-fileinfo')
  info.hidden = false
  info.innerHTML = ''
  const rows = [
    ['文件名', '<b></b>'],
    ['大小', fmtBytes(meta.size)],
    ['分片数', String(meta.count - 1)],
  ]
  for (const [k, v] of rows) {
    const div = document.createElement('div')
    const span = document.createElement('span')
    span.textContent = k + '：'
    span.style.color = 'var(--dim)'
    div.appendChild(span)
    if (k === '文件名') {
      const b = document.createElement('b')
      b.textContent = meta.name || '(未命名)'
      div.appendChild(b)
    } else {
      div.appendChild(document.createTextNode(v))
    }
    info.appendChild(div)
  }

  if (!meta.size && meta.count === 1) {
    // 空文件
    saveEmpty(meta.name)
    await fetch(`/api/rooms/${room}/ack`, { method: 'POST' }).catch(() => {})
    return
  }

  setStatus('recv-status', '🟢 发送方就绪，可以开始接收', 'ok')
  const btn = $('#start-recv')
  $('#recv-actions').hidden = false
  btn.onclick = () => receiveFile(room, meta, ctl.signal).catch((e) => {
    if (!ctl.signal.aborted) setStatus('recv-status', '❌ ' + e.message, 'err')
  })
}

async function receiveFile(room, meta, signal) {
  $('#recv-actions').hidden = true
  const useFSA = 'showSaveFilePicker' in window
  let sink
  if (useFSA) {
    try {
      const handle = await window.showSaveFilePicker({ suggestedName: meta.name || 'received' })
      sink = { mode: 'fs', ws: await handle.createWritable() }
    } catch (e) {
      if (e && e.name === 'AbortError') return
      sink = null // 权限等异常 → 退回内存模式
    }
  }
  if (!sink) {
    if (meta.size > 512 * 1024 * 1024 && !confirm('此浏览器不支持流式保存，大文件将占用较多内存，继续？')) return
    sink = { mode: 'mem', parts: [] }
  }

  setStatus('recv-status', '📡 接收中…', 'warn')
  const speed = makeSpeed()
  let got = 0
  for (let i = 1; i < meta.count; i++) {
    const packed = await getChunk(room, i, signal)
    const pt = await unseal(packed) // GCM 验签失败会直接抛错
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
  setStatus('recv-status', '✅ 已完整接收并解密保存', 'ok')
  await fetch(`/api/rooms/${room}/ack`, { method: 'POST' }).catch(() => {})
}

function saveEmpty(name) {
  const blob = new Blob([new Uint8Array(0)])
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = name || 'received'
  a.click()
  setStatus('recv-status', '✅ 空文件已保存', 'ok')
}

// ---------- 入口 ----------
$('#pick').onclick = (e) => { e.stopPropagation(); $('#file').click() }
$('#drop').onclick = () => $('#file').click()
$('#file').onchange = () => {
  const f = $('#file').files[0]
  if (f) startSend('file', f)
  $('#file').value = ''
}
const drop = $('#drop')
for (const ev of ['dragover', 'dragenter']) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over') })
for (const ev of ['dragleave', 'drop']) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over') })
drop.addEventListener('drop', (e) => {
  const f = e.dataTransfer.files[0]
  if (f) startSend('file', f)
})
$('#send-text').onclick = () => {
  const t = $('#text').value
  if (!t.trim()) return
  if (enc.encode(t).length > CHUNK) return alert('文本超过 1MB 上限')
  startSend('text', t)
}

if (location.hash.length > 1) startReceive()
else showView('landing')
