#!/usr/bin/env node
'use strict'
// cipherlane —— 局域网 E2EE 文件中继服务器（零依赖，Node ≥ 18）
//
// 安全模型：服务器只存转 AES-256-GCM 密文分片，永远接触不到密钥。
// 密钥放在链接的 #fragment 里，浏览器规范保证 fragment 不会发往服务器。
// 房间号 10 位 base62（约 59.6 bit）不可枚举；发送方持有 token 才能投递分片。

const http = require('node:http')
const crypto = require('node:crypto')
const os = require('node:os')
const fs = require('node:fs')
const path = require('node:path')

const PORT = Number(process.env.PORT || 7777)
const HOST = process.env.HOST || '0.0.0.0'

// ---------- 限制 ----------
const ROOM_ID_LEN = 10
const ROOMS_MAX = 128
const BODY_MAX = 1.5 * 1024 * 1024            // 单分片密文上限（1MiB 明文 + IV + Tag + 余量）
const ROOM_CHUNKS_BUF = 64                   // 发送方可领先接收方的最大分片数（背压窗口）
const ROOM_BYTES_MAX = 64 * 1024 * 1024
const GLOBAL_BYTES_MAX = 256 * 1024 * 1024
const ROOM_IDLE_MS = 15 * 60 * 1000
const ACK_IDLE_MS = 2 * 60 * 1000
const LONGPOLL_MS = 25 * 1000
const ROOM_RE = new RegExp(`^[0-9A-Za-z]{${ROOM_ID_LEN}}$`)

// 设备直发（定向传输）：一个局域网 IP 视为一台终端
const DEVICE_TTL_MS = 20 * 1000        // 心跳超时即离线（客户端 5s 心跳）
const DEVICE_MEM_MS = 5 * 60 * 1000    // 离线后内存保留时长（清扫用）
const DEVICES_MAX = 256
const DEVICE_NAME_MAX = 32
const PUB_RE = /^[A-Za-z0-9_-]{43}$/   // 32 字节 base64url（X25519 公钥）
const OFFER_TTL_MS = 5 * 60 * 1000     // 待处理邀请有效期
const OFFERS_MAX = 8                   // 单设备待处理邀请上限
const REJECT_GRACE_MS = 2 * 60 * 1000  // 被拒房间保留时长（发送方能读到 rejected 再回收）

const B62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
const rooms = new Map()
const devices = new Map()      // ip → { ip, id, secret, name, pub, since, lastSeen }
const offersById = new Map()   // 邀请 id → room（房间销毁时连带清理）
let globalBuffered = 0

// ---------- 工具 ----------
function randRoomId() {
  // 拒绝采样消除模偏置：62 × 4 = 248，≥248 的字节丢弃重取
  let s = ''
  while (s.length < ROOM_ID_LEN) {
    const b = crypto.randomBytes(ROOM_ID_LEN * 2)
    for (let i = 0; i < b.length && s.length < ROOM_ID_LEN; i++)
      if (b[i] < 248) s += B62[b[i] % 62]
  }
  return s
}
const randId = () => crypto.randomBytes(8).toString('hex')

function clientIp(req) {
  let ip = req.socket.remoteAddress || ''
  if (ip.startsWith('::ffff:')) ip = ip.slice(7) // IPv4 映射地址归一化
  return ip
}

function sendJson(res, code, obj) {
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  })
  res.end(JSON.stringify(obj))
}

function readBody(req, cap) {
  return new Promise((resolve, reject) => {
    const parts = []
    let n = 0
    req.on('data', (c) => {
      n += c.length
      if (n > cap) {
        const e = new Error('body too large')
        e.code = 413
        req.destroy()
        reject(e)
        return
      }
      parts.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(parts)))
    req.on('error', reject)
  })
}

// ---------- 静态资源（启动时读入内存） ----------
// SEA（单文件可执行）模式下资源内嵌于二进制；源码运行时从磁盘读取
// 注意：node:sea 在普通 Node 里也可 require，必须用 isSea() 区分
const sea = (() => {
  try {
    const m = require('node:sea')
    return m && typeof m.isSea === 'function' && m.isSea() ? m : null
  } catch { return null }
})()
const readAsset = (rel) => (sea ? Buffer.from(sea.getAsset(rel)) : fs.readFileSync(path.join(__dirname, rel)))
const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
  "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
const staticFiles = new Map()
for (const [route, file, type] of [
  ['/', 'public/index.html', 'text/html; charset=utf-8'],
  ['/index.html', 'public/index.html', 'text/html; charset=utf-8'],
  ['/app.js', 'public/app.js', 'text/javascript; charset=utf-8'],
  ['/aesgcm.js', 'public/aesgcm.js', 'text/javascript; charset=utf-8'],
  ['/sha256.js', 'public/sha256.js', 'text/javascript; charset=utf-8'],
  ['/x25519.js', 'public/x25519.js', 'text/javascript; charset=utf-8'],
  ['/avatar.js', 'public/avatar.js', 'text/javascript; charset=utf-8'],
  ['/qrcode.js', 'public/qrcode.js', 'text/javascript; charset=utf-8'],
  ['/crypto-worker.js', 'public/crypto-worker.js', 'text/javascript; charset=utf-8'],
  ['/logo.svg', 'logo/02-shield-lane.svg', 'image/svg+xml'],
  ['/logo-small.svg', 'logo/02-shield-lane-small.svg', 'image/svg+xml'],
  ['/style.css', 'public/style.css', 'text/css; charset=utf-8'],
]) {
  try {
    staticFiles.set(route, { data: readAsset(file), type })
  } catch { /* 文件缺失时该路由 500 */ }
}

// ---------- 房间 ----------
function createRoom() {
  const id = randRoomId()
  const room = {
    id,
    token: crypto.randomBytes(16).toString('hex'),
    createdAt: Date.now(),
    lastActive: Date.now(),
    posted: 0,        // 已投递分片数（0 号是加密元信息）
    head: 0,          // 最小未取走序号（顺序消费，一次性）
    pulled: 0,        // 接收方已取走数
    buffer: new Map(),// 序号 → 密文 Buffer（只保留未取走的）
    bytes: 0,
    receiverSeen: false,
    senderDone: false,
    acked: false,
    waiters: [],      // 长轮询等待者
  }
  rooms.set(id, room)
  console.log(`[room] + ${id}`)
  return room
}

function takeChunk(room, i) {
  const c = room.buffer.get(i)
  if (!c) return null // 已被并发拉取取走（分片一次性，不会再出现）
  room.buffer.delete(i)
  room.bytes -= c.length
  globalBuffered -= c.length
  room.head = i + 1
  if (room.head > room.pulled) room.pulled = room.head
  room.receiverSeen = true
  room.lastActive = Date.now()
  return c
}

function notifyChunk(room, i) {
  // 无等待者：分片留在缓冲区，供接收方稍后 GET（先发后收的链接模式依赖此语义）
  if (!room.waiters.some((w) => w.i === i)) return
  const c = takeChunk(room, i)
  if (!c) return
  let first = true
  room.waiters = room.waiters.filter((w) => {
    if (w.i !== i) return true
    w.clearTimer()
    if (first) { w.ok(c); first = false }
    else w.fail(409, 'conflict') // 同序号并发等待：先到先得，后来者明确失败而非挂起
    return false
  })
}

function destroyRoom(room) {
  if (!rooms.has(room.id)) return
  rooms.delete(room.id)
  globalBuffered -= room.bytes
  room.buffer.clear()
  room.bytes = 0
  for (const w of room.waiters) {
    w.clearTimer()
    w.fail(410, 'gone')
  }
  room.waiters.length = 0
  if (room.offer) {
    offersById.delete(room.offer.id)
    console.log(`[offer] - ${room.offer.id}（房间销毁）`)
  }
  console.log(`[room] - ${room.id}`)
}

// ---------- 设备与邀请 ----------
function deviceAlive(d) {
  return d && Date.now() - d.lastSeen <= DEVICE_TTL_MS
}

// 某设备当前待处理的邀请（跳过已过期的）
function pendingOffersFor(ip) {
  const now = Date.now()
  const list = []
  for (const room of rooms.values()) {
    const o = room.offer
    if (o && o.state === 'pending' && o.toIp === ip && now - o.createdAt <= OFFER_TTL_MS)
      list.push({ id: o.id, room: room.id, pub: o.pub, hint: o.hint, from: { ip: o.fromIp, name: o.fromName } })
  }
  return list
}

const offerWaiters = new Map() // ip → Set<长轮询等待者>
function notifyOffers(ip) {
  const set = offerWaiters.get(ip)
  if (!set) return
  offerWaiters.set(ip, new Set())
  for (const w of set) {
    w.clearTimer()
    w.ok()
  }
}

// GET /api/rooms/:id/chunk?i=N —— 长轮询取分片（接收方顺序拉取）
function handlePull(room, i, res) {
  if (i < room.head) return sendJson(res, 410, { error: 'consumed' })
  const body = takeChunk(room, i)
  if (body) {
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'X-Chunk-Index': String(i),
      'Cache-Control': 'no-store',
    })
    return res.end(body)
  }
  // 发送方已声明结束但仍缺分片 → 传输被中断
  if (room.senderDone && i >= room.posted) return sendJson(res, 410, { error: 'sender-gone' })

  const w = {
    i,
    settled: false,
    clearTimer() { clearTimeout(this.timer) },
    ok(body) {
      if (this.settled) return
      this.settled = true
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'X-Chunk-Index': String(i),
        'Cache-Control': 'no-store',
      })
      res.end(body)
    },
    fail(code, msg) {
      if (this.settled) return
      this.settled = true
      sendJson(res, code, { error: msg })
    },
  }
  w.timer = setTimeout(() => {
    room.waiters = room.waiters.filter((x) => x !== w)
    w.fail(408, 'timeout') // 长轮询到期，客户端应立即重试
  }, LONGPOLL_MS)
  room.waiters.push(w)
  res.on('close', () => {
    if (w.settled) return
    w.clearTimer()
    w.settled = true
    room.waiters = room.waiters.filter((x) => x !== w)
  })
}

// ---------- HTTP 服务 ----------
const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://localhost')
    const p = u.pathname

    // 静态页面
    if (req.method === 'GET' && staticFiles.has(p)) {
      const f = staticFiles.get(p)
      res.writeHead(200, {
        'Content-Type': f.type,
        'Cache-Control': 'no-store',
        'Content-Security-Policy': CSP,
        'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff',
      })
      return res.end(f.data)
    }
    if (p === '/favicon.ico') { res.writeHead(204); return res.end() }

    // POST /api/presence —— 设备心跳注册（一个 IP 一台终端，最后写入者生效）
    if (p === '/api/presence' && req.method === 'POST') {
      const ip = clientIp(req)
      let body
      try { body = JSON.parse((await readBody(req, 2048)).toString('utf8') || '{}') }
      catch { return sendJson(res, 400, { error: 'bad-body' }) }
      const name = typeof body.name === 'string' && body.name.trim()
        ? body.name.trim().slice(0, DEVICE_NAME_MAX) : '未命名设备'
      if (typeof body.pub !== 'string' || !PUB_RE.test(body.pub)) return sendJson(res, 400, { error: 'bad-pub' })

      const prev = devices.get(ip)
      if (prev && req.headers['x-device-secret'] === prev.secret) {
        prev.name = name
        prev.pub = body.pub
        prev.lastSeen = Date.now()
        return sendJson(res, 200, { ip, id: prev.id, secret: prev.secret })
      }
      if (devices.size >= DEVICES_MAX && !prev) return sendJson(res, 503, { error: 'too-many-devices' })
      const fresh = { ip, id: randId(), secret: crypto.randomBytes(16).toString('hex'), name, pub: body.pub, since: Date.now(), lastSeen: Date.now() }
      devices.set(ip, fresh)
      console.log(`[device] + ${ip} ${name}`)
      return sendJson(res, 200, { ip, id: fresh.id, secret: fresh.secret })
    }

    // GET /api/devices —— 在线设备列表
    if (p === '/api/devices' && req.method === 'GET') {
      const now = Date.now()
      const list = []
      for (const d of devices.values())
        if (now - d.lastSeen <= DEVICE_TTL_MS) list.push({ ip: d.ip, id: d.id, name: d.name, pub: d.pub })
      return sendJson(res, 200, { devices: list })
    }

    // GET /api/offers —— 长轮询本机待处理邀请
    if (p === '/api/offers' && req.method === 'GET') {
      const ip = clientIp(req)
      const dev = devices.get(ip)
      if (!dev || req.headers['x-device-secret'] !== dev.secret) return sendJson(res, 401, { error: 'bad-secret' })
      dev.lastSeen = Date.now()
      const respond = () => sendJson(res, 200, { offers: pendingOffersFor(ip) })
      if (pendingOffersFor(ip).length) return respond()
      const w = {
        settled: false,
        clearTimer() { clearTimeout(this.timer) },
        ok() {
          if (this.settled) return
          this.settled = true
          respond()
        },
      }
      w.timer = setTimeout(() => {
        w.settled = true
        const set = offerWaiters.get(ip)
        if (set) set.delete(w)
        respond() // 到期返回空列表，客户端立即重试
      }, LONGPOLL_MS)
      if (!offerWaiters.has(ip)) offerWaiters.set(ip, new Set())
      offerWaiters.get(ip).add(w)
      res.on('close', () => {
        w.settled = true
        clearTimeout(w.timer)
        const set = offerWaiters.get(ip)
        if (set) set.delete(w)
      })
      return
    }

    // POST /api/offers/:id/accept | reject —— 接收方处理邀请
    {
      const mo = p.match(/^\/api\/offers\/([0-9a-f]{16})\/(accept|reject)\/?$/)
      if (mo) {
        const ip = clientIp(req)
        const dev = devices.get(ip)
        if (!dev || req.headers['x-device-secret'] !== dev.secret) return sendJson(res, 401, { error: 'bad-secret' })
        const room = offersById.get(mo[1])
        if (!room || room.offer.state !== 'pending' || room.offer.toIp !== ip)
          return sendJson(res, 410, { error: 'gone' })
        await readBody(req, 1024).catch(() => {})
        room.lastActive = Date.now()
        if (mo[2] === 'accept') {
          room.offer.state = 'accepted'
          console.log(`[offer] ✓ ${room.offer.id} ${room.offer.fromIp} → ${ip}`)
          return sendJson(res, 200, { ok: true, room: room.id })
        }
        room.offer.state = 'rejected'
        room.rejectedAt = Date.now()
        console.log(`[offer] ✗ ${room.offer.id} ${room.offer.fromIp} → ${ip}`)
        return sendJson(res, 200, { ok: true })
      }
    }

    // POST /api/rooms —— 发送方创建房间
    if (p === '/api/rooms' && req.method === 'POST') {
      await readBody(req, 1024).catch(() => {})
      if (rooms.size >= ROOMS_MAX) return sendJson(res, 503, { error: 'too-many-rooms' })
      const room = createRoom()
      return sendJson(res, 200, { room: room.id, token: room.token })
    }

    // /api/rooms/:id/...
    const m = p.match(/^\/api\/rooms\/([0-9A-Za-z]{10})(?:\/(state|chunk|done|ack|offer))?\/?$/)
    if (m) {
      const room = rooms.get(m[1])
      const sub = m[2] || ''
      const token = req.headers['x-room-token']

      if (req.method === 'DELETE' && !sub) {
        if (!room) return sendJson(res, 404, { error: 'no-room' })
        if (token !== room.token) return sendJson(res, 403, { error: 'bad-token' })
        destroyRoom(room)
        return sendJson(res, 200, { ok: true })
      }
      if (!room) return sendJson(res, 404, { error: 'no-room' })

      if (sub === 'state' && req.method === 'GET') {
        return sendJson(res, 200, {
          posted: room.posted,
          head: room.head,
          pulled: room.pulled,
          receiverSeen: room.receiverSeen,
          senderDone: room.senderDone,
          acked: room.acked,
          ackProof: room.ackProof || null, // 接收方密钥凭证：服务器无法验证，仅供发送方本地核对
          offer: room.offer ? room.offer.state : null,
        })
      }

      // POST /api/rooms/:id/offer —— 发送方把定向邀请挂到房间（须在投递分片之前）
      if (sub === 'offer' && req.method === 'POST') {
        if (token !== room.token) return sendJson(res, 403, { error: 'bad-token' })
        if (room.offer) return sendJson(res, 409, { error: 'offer-exists' })
        if (room.posted > 0) return sendJson(res, 409, { error: 'late-offer' })
        let body
        try { body = JSON.parse((await readBody(req, 8192)).toString('utf8') || '{}') }
        catch { return sendJson(res, 400, { error: 'bad-body' }) }
        const target = devices.get(String(body.to || ''))
        if (!deviceAlive(target)) return sendJson(res, 404, { error: 'device-offline' })
        if (typeof body.pub !== 'string' || !PUB_RE.test(body.pub)) return sendJson(res, 400, { error: 'bad-pub' })
        if (typeof body.hint !== 'string' || body.hint.length > 4096) return sendJson(res, 400, { error: 'bad-hint' })
        let pending = 0
        for (const r of rooms.values())
          if (r.offer && r.offer.state === 'pending' && r.offer.toIp === target.ip) pending++
        if (pending >= OFFERS_MAX) return sendJson(res, 429, { error: 'too-many-offers' })
        const fromIp = clientIp(req)
        const sender = devices.get(fromIp)
        room.offer = {
          id: randId(),
          toIp: target.ip,
          fromIp,
          fromName: deviceAlive(sender) ? sender.name : null,
          pub: body.pub,
          hint: body.hint,
          state: 'pending',
          createdAt: Date.now(),
        }
        offersById.set(room.offer.id, room)
        room.lastActive = Date.now()
        notifyOffers(target.ip)
        console.log(`[offer] + ${room.offer.id} ${fromIp} → ${target.ip}`)
        return sendJson(res, 200, { offer: room.offer.id })
      }

      if (sub === 'chunk' && req.method === 'POST') {
        if (token !== room.token) return sendJson(res, 403, { error: 'bad-token' })
        let body
        try {
          body = await readBody(req, BODY_MAX)
        } catch (e) {
          return sendJson(res, e.code === 413 ? 413 : 400, { error: 'bad-body' })
        }
        if (!body.length) return sendJson(res, 400, { error: 'empty-chunk' })
        // 背压：发送方领先太多时让其稍后重试
        if (
          room.buffer.size >= ROOM_CHUNKS_BUF ||
          room.bytes + body.length > ROOM_BYTES_MAX ||
          globalBuffered + body.length > GLOBAL_BYTES_MAX
        ) {
          return sendJson(res, 429, { error: 'backpressure', retry: 1 })
        }
        const i = room.posted++
        room.buffer.set(i, body)
        room.bytes += body.length
        globalBuffered += body.length
        room.lastActive = Date.now()
        notifyChunk(room, i)
        return sendJson(res, 200, { index: i })
      }

      if (sub === 'chunk' && req.method === 'GET') {
        const i = Number(u.searchParams.get('i'))
        if (!Number.isInteger(i) || i < 0) return sendJson(res, 400, { error: 'bad-index' })
        return handlePull(room, i, res)
      }

      if (sub === 'done' && req.method === 'POST') {
        if (token !== room.token) return sendJson(res, 403, { error: 'bad-token' })
        await readBody(req, 1024).catch(() => {})
        room.senderDone = true
        room.lastActive = Date.now()
        return sendJson(res, 200, { ok: true })
      }

      // POST /api/rooms/:id/ack —— 接收方确认收讫。ack 本身无法向服务器证明身份
      // （零知识模型下服务器不持有密钥），但可附上密钥凭证 proof = SHA256(key‖label‖room)，
      // 由发送方在 state 里取回后本地核对——无密钥者伪造的 ack 发送方一眼可辨。
      if (sub === 'ack' && req.method === 'POST') {
        const body = await readBody(req, 1024).catch(() => null)
        let proof = null
        if (body) {
          try {
            const j = JSON.parse(body.toString('utf8') || '{}')
            if (typeof j.proof === 'string' && /^[0-9a-f]{64}$/.test(j.proof)) proof = j.proof
          } catch { /* 无凭证 ack 兼容旧客户端 */ }
        }
        room.acked = true
        room.ackProof = proof
        room.lastActive = Date.now()
        return sendJson(res, 200, { ok: true })
      }
    }

    return sendJson(res, 404, { error: 'not-found' })
  } catch (e) {
    try { sendJson(res, 500, { error: 'internal' }) } catch {}
    console.error('[http]', e)
  }
})

server.on('clientError', (_err, socket) => socket.destroy())

// ---------- 过期清扫 ----------
setInterval(() => {
  const now = Date.now()
  for (const room of rooms.values()) {
    const idle = now - room.lastActive
    if ((room.acked && idle > ACK_IDLE_MS) || idle > ROOM_IDLE_MS) destroyRoom(room)
    else if (room.offer && room.offer.state === 'pending' && now - room.offer.createdAt > OFFER_TTL_MS) destroyRoom(room)
    else if (room.rejectedAt && now - room.rejectedAt > REJECT_GRACE_MS) destroyRoom(room)
  }
  for (const d of devices.values()) if (now - d.lastSeen > DEVICE_MEM_MS) devices.delete(d.ip)
}, 30 * 1000)

// ---------- 启动 ----------
server.listen(PORT, HOST, () => {
  const ips = ['127.0.0.1']
  for (const list of Object.values(os.networkInterfaces())) {
    for (const ni of list || []) {
      if (ni.family === 'IPv4' && !ni.internal) ips.push(ni.address)
    }
  }
  console.log('cipherlane · 密道 —— 局域网端到端加密传输')
  console.log('  服务器零知识：只中转密文，密钥永不离开收发双方的浏览器\n')
  for (const ip of ips) console.log(`  →  http://${ip}:${PORT}`)
  // 主局域网地址附带终端二维码，手机扫码即开
  const lanIp = ips.find((ip) => ip !== '127.0.0.1')
  if (lanIp) {
    const url = `http://${lanIp}:${PORT}/`
    let qrMod = null
    try {
      qrMod = require('./public/qrcode.js')
    } catch {
      // SEA 单文件模式：qrcode.js 已内嵌为资源，按 CommonJS 方式求值加载
      try {
        const mod = { exports: {} }
        const src = Buffer.from(sea.getAsset('public/qrcode.js')).toString('utf8')
        new Function('module', 'exports', src)(mod, mod.exports)
        qrMod = mod.exports
      } catch {}
    }
    try {
      const qr = qrMod && qrMod.ascii && qrMod.ascii(url)
      if (qr) console.log('\n' + qr + '  ↑ 手机扫码打开 ' + url)
    } catch { /* 二维码不可用时仅打印 URL */ }
    // 保底：终端字体几何不可控时，写一张像素级精确的 PNG 供看图工具扫码
    try {
      const pngData = qrMod && qrMod.png && qrMod.png(url, 10)
      if (pngData) {
        fs.writeFileSync(path.join(process.cwd(), 'cipherlane-qr.png'), pngData)
        console.log('  （终端扫码失败时，用看图工具打开 ./cipherlane-qr.png 扫描）')
      }
    } catch { /* 写入失败则跳过 */ }
  }
  console.log('\n等待传输…（Ctrl+C 退出）')
})

process.on('SIGINT', () => {
  console.log('\n再见')
  process.exit(0)
})
