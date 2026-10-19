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
const net = require('node:net')

const PORT = Number(process.env.PORT || 7777)
// HOST 空(默认)= 自动:绑 127.0.0.1 + 局域网(RFC1918)网卡;显式指定(如 0.0.0.0)则只绑该地址
const HOST = process.env.HOST || ''

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
const LONGPOLL_PER_IP = 8   // 单 IP 并发长轮询上限（正常收发 ≤4：预取 3 + 邀请 1），防 fd 耗尽
// per-IP 配额：防止单个局域网 IP 耗尽全站房间/内存（CIPHERLANE_TEST_LIMITS=1 仅供测试降阈值）
const PER_IP_ROOMS = 64                          // 单 IP 同时存活房间上限
const PER_IP_BYTES = 96 * 1024 * 1024            // 单 IP 当前滞留密文字节上限
const ROOM_CREATE_PER_MIN = 120                  // 单 IP 滑动 60s 建房上限
const TEST_LIMITS = process.env.CIPHERLANE_TEST_LIMITS === '1'
const IP_ROOMS_MAX = TEST_LIMITS ? 4 : PER_IP_ROOMS
const IP_BYTES_MAX = TEST_LIMITS ? 2 * 1024 * 1024 : PER_IP_BYTES
const UPDATE_CACHE_MS = 5 * 60 * 1000            // /api/update 成功结果缓存时长
const longpollCount = new Map() // ip → 当前挂起长轮询数
function longpollEnter(ip) {
  const n = (longpollCount.get(ip) || 0) + 1
  longpollCount.set(ip, n)
  return n
}
function longpollExit(ip) {
  const n = (longpollCount.get(ip) || 1) - 1
  if (n <= 0) longpollCount.delete(ip)
  else longpollCount.set(ip, n)
}

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
const ipBytes = new Map()      // ip → 当前滞留密文字节（与 globalBuffered 同点增减）
const ipCreates = new Map()    // ip → 最近 60s 建房时间戳（滑动窗口限流）
let globalBuffered = 0
let updateCache = null         // { at, payload }：/api/update 成功结果缓存
let updateInflight = null      // 进行中的上游请求（并发去重）
const STARTED_AT = Date.now()

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

// ---------- Host / Origin 校验（仅 /api/*） ----------
// 目的：防跨站 CSRF 与 DNS rebinding。Host 是域名时一律拒绝，只有已知主机名与 IP
// 字面量放行（rebinding 必须借助域名，而正常 LAN 访问用的都是 IP/localhost）。
// CLI/tray 不带 Origin，只要 Host 合法即不受影响。
const ALLOW_HOSTS = new Set(['localhost', '127.0.0.1', '::1'])
// 从 Host 头取 hostname：`example.com:7777`、`[::1]:7777`、`host.` 都要能归一化
function hostnameOf(hostHeader) {
  let h = String(hostHeader || '').trim().toLowerCase()
  if (!h) return ''
  if (net.isIP(h)) return h // 裸 IPv6/IPv4（无端口，非标准 Host 但可容错）
  if (h.startsWith('[')) { // IPv6 字面量（带方括号/端口）
    const end = h.indexOf(']')
    h = end > 0 ? h.slice(1, end) : ''
  } else {
    const colon = h.indexOf(':')
    if (colon !== -1) h = h.slice(0, colon)
  }
  return h.endsWith('.') ? h.slice(0, -1) : h
}
function hostAllowed(hostHeader) {
  const h = hostnameOf(hostHeader)
  return !!h && (ALLOW_HOSTS.has(h) || net.isIP(h) !== 0)
}
// Origin/Referer 若存在，其 host 也必须在允许集合内；缺失（CLI/同源 GET 被裁剪）直接放行
function originAllowed(value) {
  const raw = String(value || '').trim()
  if (!raw) return true
  try { return hostAllowed(new URL(raw).host) } catch { return false }
}

function etagMatches(header, etag) {
  if (!header) return false
  const h = String(header).trim()
  if (h === '*') return true
  return h.split(',').some((t) => t.trim() === etag)
}

// ---------- 安全与记账工具 ----------
// 常量时间比较（长度不同直接 false；room token / device secret / shutdown token 都是 hex 串）
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))
}

// 设备名：先剔除 C0/C1 控制字符（防终端转义注入），再 trim/slice
function cleanDeviceName(raw) {
  const s = String(raw || '').replace(/[\u0000-\u001f\u007f-\u009f]/g, '').trim().slice(0, DEVICE_NAME_MAX)
  return s || '未命名设备'
}

// 密文字节记账：room.bytes / globalBuffered / ipBytes 必须在同一处成对增减，杜绝漂移
function bytesAdd(room, n) {
  room.bytes += n
  globalBuffered += n
  const ip = room.senderIp || ''
  ipBytes.set(ip, (ipBytes.get(ip) || 0) + n)
}
function bytesDel(room, n) {
  if (!n) return
  room.bytes -= n
  globalBuffered -= n
  const ip = room.senderIp || ''
  const left = (ipBytes.get(ip) || 0) - n
  if (left > 0) ipBytes.set(ip, left)
  else ipBytes.delete(ip)
}
function roomsByIp(ip) {
  let n = 0
  for (const r of rooms.values()) if (r.senderIp === ip) n++
  return n
}
// 滑动 60s 建房速率：0 = 允许（已记账），>0 = 需等待的秒数
function createRateWait(ip, now) {
  const ts = (ipCreates.get(ip) || []).filter((t) => now - t < 60 * 1000)
  if (ts.length >= ROOM_CREATE_PER_MIN) {
    ipCreates.set(ip, ts)
    return Math.max(1, Math.ceil((60 * 1000 - (now - ts[0])) / 1000))
  }
  ts.push(now)
  ipCreates.set(ip, ts)
  return 0
}

// 语义化版本比较：仅按数字段（0.4.3 > 0.4.2、0.4.3 == 0.4.3），非法值一律不视为更新
function semverNewer(latest, current) {
  const parse = (v) => {
    const m = /^v?(\d+(?:\.\d+)*)/.exec(String(v || '').trim())
    return m ? m[1].split('.').map(Number) : null
  }
  const a = parse(latest)
  const b = parse(current)
  if (!a || !b) return false
  const n = Math.max(a.length, b.length)
  for (let i = 0; i < n; i++) {
    const x = a[i] || 0
    const y = b[i] || 0
    if (x !== y) return x > y
  }
  return false
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
    let settled = false
    const fail = (e) => {
      if (settled) return
      settled = true
      req.removeListener('data', onData)
      req.resume() // 丢弃剩余请求体（不能 destroy：那样响应还没发出连接就重置了）
      reject(e)
    }
    const onData = (c) => {
      if (settled) return
      n += c.length
      if (n > cap) {
        const e = new Error('body too large')
        e.code = 413
        fail(e)
        return
      }
      parts.push(c)
    }
    req.on('data', onData)
    req.on('end', () => {
      if (settled) return
      settled = true
      resolve(Buffer.concat(parts))
    })
    req.on('error', (e) => {
      if (settled) return
      settled = true
      reject(e)
    })
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
// 版本号:SEA 从内嵌资产读,源码模式直接 require;供横幅与页面 footer 展示
const VERSION = (() => {
  try {
    const raw = sea ? Buffer.from(sea.getAsset('package.json')).toString('utf8') : fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8')
    return JSON.parse(raw).version || '?'
  } catch { return '?' }
})()
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
  ['/panel', 'public/panel.html', 'text/html; charset=utf-8'],
  ['/panel.js', 'public/panel.js', 'text/javascript; charset=utf-8'],
  ['/panel.css', 'public/panel.css', 'text/css; charset=utf-8'],
]) {
  try {
    let data = readAsset(file)
    if (file === 'public/index.html') data = Buffer.from(data.toString('utf8').replaceAll('__VERSION__', VERSION))
    const etag = '"' + crypto.createHash('sha256').update(data).digest('hex') + '"'
    staticFiles.set(route, { data, type, etag })
  } catch { /* 文件缺失时该路由 500 */ }
}

// ---------- 房间 ----------
function createRoom(senderIp) {
  const id = randRoomId()
  const room = {
    id,
    senderIp: senderIp || '',
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
    resumable: false, // 接收方以 X-Resume 首次拉取后进入可续传模式（GET 只读 + progress 释放）
    through: 0,       // 可续传模式下接收方已安全落盘的分片数（0..count，含 0 号元信息）
  }
  rooms.set(id, room)
  console.log(`[room] + ${id}`)
  return room
}

function takeChunk(room, i) {
  const c = room.buffer.get(i)
  if (!c) return null // 已被并发拉取取走（分片一次性，不会再出现）
  room.buffer.delete(i)
  bytesDel(room, c.length)
  // head 只在按序取走时推进；越序取走的序号通过"已投递但不在 buffer"推导，
  // 避免越序 GET 把低序号分片变成不可达垃圾（也避免 taken 集合无界增长）。
  if (i === room.head) {
    room.head = i + 1
    while (room.head < room.posted && !room.buffer.has(room.head)) room.head++
  }
  if (room.head > room.pulled) room.pulled = room.head
  room.receiverSeen = true
  room.lastActive = Date.now()
  return c
}

function notifyChunk(room, i) {
  // 无等待者：分片留在缓冲区，供接收方稍后 GET（先发后收的链接模式依赖此语义）
  if (!room.waiters.some((w) => w.i === i)) return
  if (room.resumable) {
    // 可续传模式：分片只读，同序号的所有等待者都能拿到同一份
    const c = room.buffer.get(i)
    if (!c) return
    room.waiters = room.waiters.filter((w) => {
      if (w.i !== i) return true
      w.clearTimer()
      w.ok(c)
      return false
    })
    return
  }
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

// 接收方上报进度：释放 through 以下已确认落盘的分片（可续传模式）
function advanceThrough(room, through) {
  if (!Number.isInteger(through) || through < 0 || through > room.posted) return false
  if (through <= room.through) return true // 单调，重复/滞后上报幂等
  for (const [i, c] of room.buffer) {
    // 0 号元信息分片不释放：续传的接收方重进房间时还要读 manifest
    if (i >= 1 && i < through) {
      room.buffer.delete(i)
      bytesDel(room, c.length)
    }
  }
  room.through = through
  if (room.through > room.pulled) room.pulled = room.through
  room.lastActive = Date.now()
  return true
}

function destroyRoom(room) {
  if (!rooms.has(room.id)) return
  rooms.delete(room.id)
  bytesDel(room, room.bytes) // 与 globalBuffered/ipBytes 同步释放
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

// destroyRoom 可能发生在任意 await（慢速请求体读取）期间：await 返回后写房间前必须复核存活，
// 否则分片记账会落在已从 rooms 移除、再也不会被销毁的对象上 → globalBuffered 只增不减。
const roomAlive = (room) => rooms.get(room.id) === room

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
// X-Resume: 1 → 可续传模式：GET 只读（同分片可反复拉），由 POST /progress 释放
function handlePull(room, i, res, ip, resume) {
  if (resume) room.resumable = true
  if (room.resumable) {
    const c = room.buffer.get(i)
    if (c) {
      room.receiverSeen = true
      room.lastActive = Date.now()
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'X-Chunk-Index': String(i),
        'Cache-Control': 'no-store',
      })
      return res.end(c)
    }
    // 已被 progress 释放的数据分片（0 号元信息永不释放，供续传者重读 manifest）
    if (i >= 1 && i < room.through) return sendJson(res, 410, { error: 'behind', through: room.through })
    if (room.senderDone && i >= room.posted) return sendJson(res, 410, { error: 'sender-gone' })
    // 未投递：挂长轮询（只读模式可多个等待者共享同一分片）
    return parkWaiter(room, i, res, ip, c)
  }
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
  // 已投递但不在缓冲区 = 已被越序/并发取走（经典模式取走即焚）→ 明确 410，不要挂空等待
  if (i < room.posted) return sendJson(res, 410, { error: 'consumed' })
  // 发送方已声明结束但仍缺分片 → 传输被中断
  if (room.senderDone && i >= room.posted) return sendJson(res, 410, { error: 'sender-gone' })
  return parkWaiter(room, i, res, ip, null)
}

// 长轮询挂起（经典模式：分片到达即取走；可续传模式：只读回放）
function parkWaiter(room, i, res, ip, _snapshot) {
  if (longpollEnter(ip) > LONGPOLL_PER_IP) {
    longpollExit(ip)
    return sendJson(res, 429, { error: 'too-many-polls', retry: 1 })
  }
  const readonly = room.resumable
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
    readonly,
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
    longpollExit(ip)
    if (w.settled) return
    w.clearTimer()
    w.settled = true
    room.waiters = room.waiters.filter((x) => x !== w)
  })
}

// ---------- HTTP 服务 ----------
async function handleRequest(req, res) {
  try {
    const u = new URL(req.url, 'http://localhost')
    const p = u.pathname

    // /api/* 的 Host/Origin 闸门（防 DNS rebinding 与跨站 CSRF）。静态页不做限制，
    // 这样自定义域名只影响 API 调用、不影响页面本身（误伤面最小）。
    if (p === '/api' || p.startsWith('/api/')) {
      if (!hostAllowed(req.headers.host)) return sendJson(res, 403, { error: 'bad-host' })
      if (!originAllowed(req.headers.origin) || !originAllowed(req.headers.referer))
        return sendJson(res, 403, { error: 'bad-origin' })
    }

    // 静态页面：HTML 仍 no-store；JS/CSS/SVG 用 ETag 做回源校验（no-cache）并支持 304
    if (req.method === 'GET' && staticFiles.has(p)) {
      const f = staticFiles.get(p)
      const html = f.type.startsWith('text/html')
      const headers = {
        'Content-Type': f.type,
        'Content-Security-Policy': CSP,
        'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff',
      }
      if (html) {
        headers['Cache-Control'] = 'no-store'
        res.writeHead(200, headers)
        return res.end(f.data)
      }
      headers['Cache-Control'] = 'no-cache' // 可缓存但必须回源校验
      headers['ETag'] = f.etag
      if (etagMatches(req.headers['if-none-match'], f.etag)) {
        res.writeHead(304, headers)
        return res.end()
      }
      res.writeHead(200, headers)
      return res.end(f.data)
    }
    if (p === '/favicon.ico') { res.writeHead(204); return res.end() }

    // POST /api/presence —— 设备心跳注册（一个 IP 一台终端，最后写入者生效）
    if (p === '/api/presence' && req.method === 'POST') {
      const ip = clientIp(req)
      let body
      try { body = JSON.parse((await readBody(req, 2048)).toString('utf8') || '{}') }
      catch { return sendJson(res, 400, { error: 'bad-body' }) }
      const name = typeof body.name === 'string' ? cleanDeviceName(body.name) : '未命名设备'
      if (typeof body.pub !== 'string' || !PUB_RE.test(body.pub)) return sendJson(res, 400, { error: 'bad-pub' })

      const prev = devices.get(ip)
      if (prev && safeEqual(req.headers['x-device-secret'], prev.secret)) {
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

    // POST /api/adopt —— 本机托盘接管（交接停机令牌），与 Rust 版语义一致
    if (p === '/api/adopt' && req.method === 'POST') {
      const ip = clientIp(req)
      if (ip !== '127.0.0.1' && ip !== '::1') return sendJson(res, 403, { error: 'forbidden' })
      const body = await readBody(req, 1024).then((b) => JSON.parse(b.toString('utf8') || '{}')).catch(() => ({}))
      if (typeof body.token !== 'string' || body.token.length < 16) return sendJson(res, 400, { error: 'bad-token' })
      if (process.env.CIPHERLANE_SHUTDOWN_TOKEN) return sendJson(res, 409, { error: 'already-managed' })
      process.env.CIPHERLANE_SHUTDOWN_TOKEN = body.token
      console.log('[panel] 已被本机托盘接管（令牌交接）')
      return sendJson(res, 200, { ok: true })
    }

    // GET /api/version —— 面板用：版本与运行状态
    if (p === '/api/version' && req.method === 'GET') {
      return sendJson(res, 200, { version: VERSION, rooms: rooms.size, startedAt: STARTED_AT, lan: lanAddresses()[0] || null })
    }

    // POST /api/shutdown —— 面板"停止服务"：仅本机 + 会话停机令牌双重校验
    if (p === '/api/shutdown' && req.method === 'POST') {
      const token = process.env.CIPHERLANE_SHUTDOWN_TOKEN || ''
      let body = {}
      try { body = JSON.parse((await readBody(req, 1024)).toString('utf8') || '{}') } catch {}
      const ip = clientIp(req)
      if (!token || token.length < 16 || !safeEqual(body.token, token) || (ip !== '127.0.0.1' && ip !== '::1'))
        return sendJson(res, 403, { error: 'forbidden' })
      sendJson(res, 200, { ok: true })
      console.log('[panel] 服务已从控制面板停止')
      setTimeout(() => process.exit(0), 150)
      return
    }

    // GET /api/update —— 检查更新：CIPHERLANE_UPDATE_URL 指向返回纯文本版本号的 URL
    // 5min 缓存 + in-flight 去重（并发只打一次上游）；错误不缓存；只允许 http/https。
    if (p === '/api/update' && req.method === 'GET') {
      const url = process.env.CIPHERLANE_UPDATE_URL
      if (!url) return sendJson(res, 200, { source: null, current: VERSION, message: '未配置更新源（CIPHERLANE_UPDATE_URL）' })
      let parsed
      try { parsed = new URL(url) } catch { return sendJson(res, 400, { source: url, current: VERSION, error: 'bad-update-url' }) }
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:')
        return sendJson(res, 400, { source: url, current: VERSION, error: 'bad-update-url' })
      const now = Date.now()
      if (updateCache && now - updateCache.at < UPDATE_CACHE_MS) return sendJson(res, 200, updateCache.payload)
      if (!updateInflight) {
        updateInflight = (async () => {
          try {
            const r = await fetch(url, { signal: AbortSignal.timeout(5000) })
            if (!r.ok) throw new Error('upstream ' + r.status)
            const latest = (await r.text()).trim()
            const payload = { source: url, current: VERSION, latest, newer: semverNewer(latest, VERSION) }
            updateCache = { at: Date.now(), payload }
            return payload
          } catch (e) {
            return { source: url, current: VERSION, error: String((e && e.message) || e) } // 错误不缓存
          } finally {
            updateInflight = null
          }
        })()
      }
      return sendJson(res, 200, await updateInflight)
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
      if (!dev || !safeEqual(req.headers['x-device-secret'], dev.secret)) return sendJson(res, 401, { error: 'bad-secret' })
      dev.lastSeen = Date.now()
      const respond = () => sendJson(res, 200, { offers: pendingOffersFor(ip) })
      if (pendingOffersFor(ip).length) return respond()
      if (longpollEnter(ip) > LONGPOLL_PER_IP) {
        longpollExit(ip)
        return sendJson(res, 429, { error: 'too-many-polls', retry: 1 })
      }
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
        longpollExit(ip)
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
        if (!dev || !safeEqual(req.headers['x-device-secret'], dev.secret)) return sendJson(res, 401, { error: 'bad-secret' })
        const room = offersById.get(mo[1])
        if (!room || room.offer.state !== 'pending' || room.offer.toIp !== ip)
          return sendJson(res, 410, { error: 'gone' })
        await readBody(req, 1024).catch(() => {})
        if (!roomAlive(room)) return sendJson(res, 410, { error: 'gone' })
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

    // POST /api/rooms —— 发送方创建房间（per-IP 房间数/建房速率双闸，防单 IP 耗尽全站）
    if (p === '/api/rooms' && req.method === 'POST') {
      await readBody(req, 1024).catch(() => {})
      const ip = clientIp(req)
      const rateWait = createRateWait(ip, Date.now())
      if (rateWait > 0) return sendJson(res, 429, { error: 'ip-quota', retry: rateWait })
      if (roomsByIp(ip) >= IP_ROOMS_MAX) return sendJson(res, 429, { error: 'ip-quota', retry: 1 })
      if (rooms.size >= ROOMS_MAX) return sendJson(res, 503, { error: 'too-many-rooms' })
      const room = createRoom(ip)
      return sendJson(res, 200, { room: room.id, token: room.token })
    }

    // /api/rooms/:id/...
    const m = p.match(/^\/api\/rooms\/([0-9A-Za-z]{10})(?:\/(state|chunk|done|ack|offer|progress))?\/?$/)
    if (m) {
      const room = rooms.get(m[1])
      const sub = m[2] || ''
      const token = req.headers['x-room-token']

      if (req.method === 'DELETE' && !sub) {
        if (!room) return sendJson(res, 404, { error: 'no-room' })
        if (!safeEqual(token, room.token)) return sendJson(res, 403, { error: 'bad-token' })
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
          resumable: room.resumable,
          through: room.through, // 可续传模式下接收方已确认落盘的分片数
          offer: room.offer ? room.offer.state : null,
        })
      }

      // POST /api/rooms/:id/offer —— 发送方把定向邀请挂到房间（须在投递分片之前）
      if (sub === 'offer' && req.method === 'POST') {
        if (!safeEqual(token, room.token)) return sendJson(res, 403, { error: 'bad-token' })
        if (room.offer) return sendJson(res, 409, { error: 'offer-exists' })
        if (room.posted > 0) return sendJson(res, 409, { error: 'late-offer' })
        let body
        try { body = JSON.parse((await readBody(req, 8192)).toString('utf8') || '{}') }
        catch { return sendJson(res, 400, { error: 'bad-body' }) }
        if (!roomAlive(room)) return sendJson(res, 410, { error: 'gone' })
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
        if (!safeEqual(token, room.token)) return sendJson(res, 403, { error: 'bad-token' })
        let body
        try {
          body = await readBody(req, BODY_MAX)
        } catch (e) {
          return sendJson(res, e.code === 413 ? 413 : 400, { error: 'bad-body' })
        }
        // 读包期间房间可能已被 DELETE/清扫销毁：不再接受分片，也不写任何全局计数
        if (!roomAlive(room)) return sendJson(res, 410, { error: 'gone' })
        if (!body.length) return sendJson(res, 400, { error: 'empty-chunk' })
        // 可选幂等序号 X-Chunk-Seq（旧客户端不带该头 → 保持 posted++ 旧语义）：
        // seq<posted = 重投包：零记账/零背压/零 notify，直接 200 duplicate；seq>posted = 乱序 409。
        const seqRaw = req.headers['x-chunk-seq']
        let seq = null
        if (seqRaw !== undefined) {
          if (typeof seqRaw !== 'string' || !/^\d+$/.test(seqRaw)) return sendJson(res, 400, { error: 'bad-seq' })
          seq = Number(seqRaw)
          if (!Number.isSafeInteger(seq)) return sendJson(res, 400, { error: 'bad-seq' })
          if (seq > room.posted) return sendJson(res, 409, { error: 'out-of-order', posted: room.posted })
          if (seq < room.posted) return sendJson(res, 200, { ok: true, index: seq, duplicate: true })
        }
        // 背压：发送方领先太多时让其稍后重试
        // 背压：经典模式按滞留分片数；可续传模式按 未确认分片数(posted - through)
        const outstanding = room.resumable ? room.posted - room.through : room.buffer.size
        const ip = room.senderIp || ''
        if (
          outstanding >= ROOM_CHUNKS_BUF ||
          room.bytes + body.length > ROOM_BYTES_MAX ||
          globalBuffered + body.length > GLOBAL_BYTES_MAX ||
          (ipBytes.get(ip) || 0) + body.length > IP_BYTES_MAX
        ) {
          return sendJson(res, 429, { error: 'backpressure', retry: 1 })
        }
        const i = room.posted++
        room.buffer.set(i, body)
        bytesAdd(room, body.length)
        room.lastActive = Date.now()
        notifyChunk(room, i)
        return sendJson(res, 200, { index: i })
      }

      if (sub === 'chunk' && req.method === 'GET') {
        const iRaw = u.searchParams.get('i')
        // 缺省/非法 i 必须 400：Number(null) === 0 会把"没有参数"静默当成 0 号分片消费掉
        if (iRaw === null || !/^\d+$/.test(iRaw)) return sendJson(res, 400, { error: 'bad-index' })
        const i = Number(iRaw)
        if (!Number.isSafeInteger(i)) return sendJson(res, 400, { error: 'bad-index' })
        return handlePull(room, i, res, clientIp(req), req.headers['x-resume'] === '1')
      }

      if (sub === 'done' && req.method === 'POST') {
        if (!safeEqual(token, room.token)) return sendJson(res, 403, { error: 'bad-token' })
        await readBody(req, 1024).catch(() => {})
        if (!roomAlive(room)) return sendJson(res, 410, { error: 'gone' })
        room.senderDone = true
        room.lastActive = Date.now()
        return sendJson(res, 200, { ok: true })
      }

      // POST /api/rooms/:id/progress —— 可续传模式：接收方上报已安全落盘的分片数，
      // 服务器据此释放之前的缓存。上报本身不要求凭证：伪造进度不会解密任何内容，
      // 其危害等价于既有的分片抢拉（可用性攻击，见 README 安全模型）。
      if (sub === 'progress' && req.method === 'POST') {
        const body = await readBody(req, 1024).catch(() => null)
        if (!roomAlive(room)) return sendJson(res, 410, { error: 'gone' })
        let through = null
        if (body) {
          try {
            const j = JSON.parse(body.toString('utf8') || '{}')
            if (Number.isInteger(j.through)) through = j.through
          } catch { /* 忽略坏包 */ }
        }
        if (through === null) return sendJson(res, 400, { error: 'bad-through' })
        if (!room.resumable) return sendJson(res, 409, { error: 'not-resumable' })
        if (!advanceThrough(room, through)) return sendJson(res, 400, { error: 'bad-through' })
        return sendJson(res, 200, { ok: true, through: room.through })
      }

      // POST /api/rooms/:id/ack —— 接收方确认收讫。ack 本身无法向服务器证明身份
      // （零知识模型下服务器不持有密钥），但可附上密钥凭证 proof = SHA256(key‖label‖room)，
      // 由发送方在 state 里取回后本地核对——无密钥者伪造的 ack 发送方一眼可辨。
      if (sub === 'ack' && req.method === 'POST') {
        const body = await readBody(req, 1024).catch(() => null)
        if (!roomAlive(room)) return sendJson(res, 410, { error: 'gone' })
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
}

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
// 默认只绑 127.0.0.1 与局域网（RFC1918）网卡，不再默认 0.0.0.0——
// 避免把服务暴露到 VPN/tun（如 198.18/15 fake-ip 段）、虚拟网卡等非信任网段。
// 显式 HOST=（含 0.0.0.0，deb/容器模板如此）时只绑指定地址，维持旧行为。
function lanAddresses() {
  const out = []
  for (const list of Object.values(os.networkInterfaces())) {
    for (const ni of list || []) {
      if (ni.family === 'IPv4' && !ni.internal && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ni.address))
        out.push(ni.address)
    }
  }
  return [...new Set(out)]
}
const listenAddrs = HOST ? [HOST] : ['127.0.0.1', ...lanAddresses()]
// 补充 Host 白名单：显式 HOST（域名时）、os.hostname() 及其短名；IP 字面量由 hostAllowed 动态放行
for (const addr of listenAddrs) {
  const a = String(addr).toLowerCase()
  if (a !== '0.0.0.0' && a !== '::' && net.isIP(a) === 0) ALLOW_HOSTS.add(a)
}
if (HOST && net.isIP(String(HOST)) === 0) ALLOW_HOSTS.add(String(HOST).toLowerCase())
const osHost = String(os.hostname() || '').trim().toLowerCase()
if (osHost) {
  ALLOW_HOSTS.add(osHost)
  ALLOW_HOSTS.add(osHost.split('.')[0])
}
// 自定义域名/反代/本地测试域名（如浏览器测试的 *.test）用显式白名单放行：
// CIPHERLANE_EXTRA_HOSTS="files.lan,mybox.example"（逗号分隔，忽略端口）
for (const h of String(process.env.CIPHERLANE_EXTRA_HOSTS || '').split(',')) {
  const v = h.trim().toLowerCase().replace(/:\d+$/, '')
  if (v) ALLOW_HOSTS.add(v)
}
const servers = []
let listenReady = 0
for (const addr of listenAddrs) {
  const s = http.createServer(handleRequest)
  servers.push(s)
  s.on('clientError', (_err, socket) => socket.destroy())
  s.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`\n✗ ${addr}:${PORT} 已被占用——可能有一个旧的密道实例还在运行。\n`)
      console.error(`  · 到旧实例所在终端按 Ctrl+C 停止，或执行：fuser -k ${PORT}/tcp`)
      console.error(`  · 或换端口启动：PORT=7788 node server.js\n`)
    } else {
      console.error(`\n✗ 监听 ${addr} 失败：`, err)
    }
    process.exit(1)
  })
  s.listen(PORT, addr, () => { if (++listenReady === listenAddrs.length) banner() })
}

async function banner() {
  // 展示地址：显式绑 0.0.0.0（= 全网卡）时列出全部网卡地址，其余只列实际绑定地址
  const ips = listenAddrs.includes('0.0.0.0')
    ? ['127.0.0.1', ...Object.values(os.networkInterfaces()).flatMap((l) => l || [])
        .filter((ni) => ni.family === 'IPv4' && !ni.internal).map((ni) => ni.address)]
    : listenAddrs
  console.log(`cipherlane · 密道 v${VERSION} —— 局域网端到端加密传输`)
  console.log('  服务器零知识：只中转密文，密钥永不离开收发双方的浏览器\n')
  for (const ip of ips) console.log(`  →  http://${ip}:${PORT}`)
  // 主局域网地址附带终端二维码，手机扫码即开
  const lanIp = ips.find((ip) => ip !== '127.0.0.1')
  if (!lanIp) {
    console.log('  （未发现局域网网卡：当前仅本机可访问；需要全网卡监听用 HOST=0.0.0.0）')
    console.log('\n等待传输…（Ctrl+C 退出）')
    return
  }
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
      // 终端字符单元格高宽比：环境变量 CIPHERLANE_QR_RATIO 手动指定 > CSI 16t 实测 > 默认 2.0
      const envRatio = Number(process.env.CIPHERLANE_QR_RATIO)
      const ratio = envRatio >= 0.9 && envRatio <= 3
        ? envRatio
        : qrMod && qrMod.measureCellRatio ? await qrMod.measureCellRatio() : 2
      const qr = qrMod && qrMod.asciiAdaptive && qrMod.asciiAdaptive(url, ratio)
      if (qr) console.log('\n' + qr + '  ↑ 手机扫码打开 ' + url)
    } catch { /* 二维码不可用时仅打印 URL */ }
    // 保底：终端字体几何不可控时，写一张像素级精确的 PNG 供看图工具扫码。
    // 写系统临时目录 + 排他创建：固定文件名写在 cwd 有符号链接覆盖风险
    try {
      const pngData = qrMod && qrMod.png && qrMod.png(url, 10)
      if (pngData) {
        const pngPath = path.join(os.tmpdir(), `cipherlane-qr-${process.pid}.png`)
        fs.writeFileSync(pngPath, pngData, { flag: 'wx' })
        console.log(`  （终端扫码失败时，用看图工具打开 ${pngPath} 扫描）`)
      }
    } catch { /* 写入失败则跳过 */ }
  }
  console.log('\n等待传输…（Ctrl+C 退出）')
}

// ---------- 优雅停机 ----------
// SIGINT/SIGTERM 共用：先停监听，250ms 后结束残留连接（keep-alive/长轮询），
// 2s 兜底强制退出。SIGINT 保留原有"再见"文案。
let shuttingDown = false
function shutdown(reason) {
  if (shuttingDown) return
  shuttingDown = true
  console.log(reason === 'SIGTERM' ? '\n收到 SIGTERM，正在优雅停机…' : '\n再见')
  const force = setTimeout(() => process.exit(0), 2000)
  force.unref()
  let pending = servers.length
  const finish = () => { if (--pending <= 0) process.exit(0) }
  if (!pending) process.exit(0)
  for (const s of servers) {
    try { s.close(finish) } catch { finish() }
  }
  const cut = setTimeout(() => {
    for (const s of servers) {
      if (typeof s.closeAllConnections === 'function') {
        try { s.closeAllConnections() } catch {}
      }
    }
  }, 250)
  cut.unref()
}
process.on('SIGINT', () => shutdown('SIGINT'))
process.on('SIGTERM', () => shutdown('SIGTERM'))
