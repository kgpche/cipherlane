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

const B62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
const rooms = new Map()
let globalBuffered = 0

// ---------- 工具 ----------
function randRoomId() {
  const b = crypto.randomBytes(ROOM_ID_LEN)
  let s = ''
  for (let i = 0; i < ROOM_ID_LEN; i++) s += B62[b[i] % 62]
  return s
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
const PUBLIC_DIR = path.join(__dirname, 'public')
const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
  "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
const staticFiles = new Map()
for (const [route, file, type] of [
  ['/', 'index.html', 'text/html; charset=utf-8'],
  ['/index.html', 'index.html', 'text/html; charset=utf-8'],
  ['/app.js', 'app.js', 'text/javascript; charset=utf-8'],
  ['/aesgcm.js', 'aesgcm.js', 'text/javascript; charset=utf-8'],
  ['/style.css', 'style.css', 'text/css; charset=utf-8'],
]) {
  try {
    staticFiles.set(route, { data: fs.readFileSync(path.join(PUBLIC_DIR, file)), type })
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
  room.waiters = room.waiters.filter((w) => {
    if (w.i !== i) return true
    w.clearTimer()
    w.ok(takeChunk(room, i))
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
  console.log(`[room] - ${room.id}`)
}

// GET /api/rooms/:id/chunk?i=N —— 长轮询取分片（接收方顺序拉取）
function handlePull(room, i, res) {
  if (i < room.head) return sendJson(res, 410, { error: 'consumed' })
  const c = room.buffer.get(i)
  if (c) {
    const body = takeChunk(room, i)
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

    // POST /api/rooms —— 发送方创建房间
    if (p === '/api/rooms' && req.method === 'POST') {
      await readBody(req, 1024).catch(() => {})
      if (rooms.size >= ROOMS_MAX) return sendJson(res, 503, { error: 'too-many-rooms' })
      const room = createRoom()
      return sendJson(res, 200, { room: room.id, token: room.token })
    }

    // /api/rooms/:id/...
    const m = p.match(/^\/api\/rooms\/([0-9A-Za-z]{10})(?:\/(state|chunk|done|ack))?\/?$/)
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
        })
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

      if (sub === 'ack' && req.method === 'POST') {
        await readBody(req, 1024).catch(() => {})
        room.acked = true
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
  }
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
  console.log('\n等待传输…（Ctrl+C 退出）')
})

process.on('SIGINT', () => {
  console.log('\n再见')
  process.exit(0)
})
