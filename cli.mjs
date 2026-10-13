#!/usr/bin/env node
// cipherlane CLI —— 命令行收发（无浏览器环境 / 服务器之间）
//
//   node cli.mjs devices                          [--server http://<局域网IP>:7777]
//   node cli.mjs send <文件路径>     [--to <IP>]  [--server ...] [--name 我的名字]
//   node cli.mjs send-text <文本>    [--to <IP>]  [--server ...] [--name 我的名字]
//   node cli.mjs recv '<接收链接>'   [-o 输出路径]
//   node cli.mjs listen [--yes] [-o 保存目录] [--name 我的名字] [--server ...]
//
// 零依赖（Node ≥ 18）。加密使用 node:crypto 原生 aes-256-gcm / X25519，与浏览器端互通。
// 设备直发（--to / listen）的房间密钥由 X25519 派生：SHA-256(shared ‖ pubA ‖ pubB ‖ roomId)，
// 与 public/x25519.js 的纯 JS 路径逐字节一致（见 test/x25519.test.mjs）。

import { randomBytes, createCipheriv, createDecipheriv, createHash, createPublicKey, createPrivateKey, diffieHellman } from 'node:crypto'
import { createRequire } from 'node:module'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import readline from 'node:readline'

const require = createRequire(import.meta.url)
const X25519 = require('./public/x25519.js')
const QRCode = require('./public/qrcode.js')
const { fnv1a } = require('./public/avatar.js')

const CHUNK = 1024 * 1024
const ROOM_RE = /^[0-9A-Za-z]{10}$/

const args = process.argv.slice(2)
const pos = []
const opts = {}
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--server') opts.server = args[++i]
  else if (args[i] === '-o') opts.out = args[++i]
  else if (args[i] === '--to') opts.to = args[++i]
  else if (args[i] === '--name') opts.name = args[++i]
  else if (args[i] === '--yes') opts.yes = true
  else pos.push(args[i])
}
const cmd = pos[0]
// CIPHERLANE_SERVER 环境变量可设默认服务器（旧名 LANDROP_SERVER 仍兼容）
const server = (opts.server || process.env.CIPHERLANE_SERVER || process.env.LANDROP_SERVER || 'http://127.0.0.1:7777').replace(/\/+$/, '')

function usage() {
  console.log(`cipherlane · 密道 CLI

用法:
  node cli.mjs devices                       [--server http://<局域网IP>:7777]
  node cli.mjs send <文件/目录...> [--to <设备IP>] [--name <名称>] [--server ...]   # 多路径/目录递归
  node cli.mjs send-text <文本> [--to <设备IP>] [--name <名称>] [--server ...]
  node cli.mjs recv '<接收链接>' [-o 输出路径]
  node cli.mjs listen [--yes] [-o 保存目录] [--name <名称>] [--server ...]

设备直发：--to 指定在线设备（node cli.mjs devices 查看），密钥 X25519 协商，无需传链接。
listen：常驻接收端，无浏览器的机器也能被直发（--yes 自动接受）。`)
  process.exit(1)
}

const fmt = (n) => {
  if (n < 1024) return n + ' B'
  const u = ['KB', 'MB', 'GB', 'TB']
  let i = -1
  do { n /= 1024; i++ } while (n >= 1024 && i < u.length - 1)
  return n.toFixed(1) + ' ' + u[i]
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const b64u = (u8) => Buffer.from(u8).toString('base64url')
const fromB64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'))

// 接收文件名净化：去路径分隔符与非法字符，剥掉前导点/空白（防点文件植入，如 .bashrc）
function safeName(raw) {
  const base = String(raw || '').split(/[/\\]/).pop()
    .replace(/[^\w.\-\u4e00-\u9fa5 ]+/g, '_')
    .replace(/^[.\s]+/, '')
  return base || 'received'
}

// ---------- AES-GCM（与浏览器端格式一致：IV(12) || 密文 || TAG(16)） ----------
function seal(key, pt) {
  const iv = randomBytes(12)
  const c = createCipheriv('aes-256-gcm', key, iv)
  const ct = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()])
  return Buffer.concat([iv, ct])
}
function unseal(key, packed) {
  packed = Buffer.from(packed)
  if (packed.length < 28) throw new Error('数据不完整')
  const iv = packed.subarray(0, 12)
  const tag = packed.subarray(packed.length - 16)
  const d = createDecipheriv('aes-256-gcm', key, iv)
  d.setAuthTag(tag)
  return Buffer.concat([d.update(packed.subarray(12, packed.length - 16)), d.final()])
}

// ---------- X25519（node 原生，裸 32 字节密钥） ----------
const SPKI = Buffer.from('302a300506032b656e032100', 'hex')
const PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex')
function genIdentity() {
  const seed = randomBytes(32)
  const pub = createPublicKey(createPrivateKey({ key: Buffer.concat([PKCS8, seed]), format: 'der', type: 'pkcs8' }))
  return { seed, pub: new Uint8Array(pub.export({ type: 'spki', format: 'der' }).subarray(12)) }
}
function dh(seed, theirPubRaw) {
  return new Uint8Array(diffieHellman({
    privateKey: createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(seed)]), format: 'der', type: 'pkcs8' }),
    publicKey: createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(theirPubRaw)]), format: 'der', type: 'spki' }),
  }))
}
// 房间密钥派生（两侧参数顺序：发送方公钥, 接收方公钥）
const roomKey = (shared, senderPub, receiverPub, room) =>
  X25519.sessionKey(new Uint8Array(shared), senderPub, receiverPub, room)

// ack 密钥凭证：SHA256(key ‖ 标签 ‖ 房间号)。与 public/app.js 的纯 JS 构造逐字节一致，
// 发送方本地比对即可分辨伪造 ack（协议测试有交叉验证）
const ackProofOf = (key, room) =>
  createHash('sha256')
    .update(Buffer.concat([Buffer.from(key), Buffer.from('cipherlane/ack/v1|' + room)]))
    .digest('hex')

// ---------- 头像（与浏览器同款 fnv1a 种子，终端版几何字符） ----------
function avatarOf(seedStr) {
  const h = fnv1a('cipherlane·' + seedStr)
  const colors = [39, 48, 178, 203, 170, 214]
  const glyphs = ['◆', '▲', '●', '■', '✦', '◐', '◀', '▼']
  return `\x1b[38;5;${colors[h % colors.length]}m${glyphs[(h >>> 8) % glyphs.length]}${glyphs[(h >>> 16) % glyphs.length]}\x1b[0m`
}

// ---------- 协议 ----------
// 带超时的 fetch：连接停滞（既不返回也不报错）时中断重试，而非无限挂起。
// 仅超时可重试；快速失败与调用方 signal 取消原样上抛。
async function fetchT(url, opts, ms) {
  const ctl = new AbortController()
  const follow = () => ctl.abort()
  if (opts && opts.signal) {
    if (opts.signal.aborted) throw new Error('已取消')
    opts.signal.addEventListener('abort', follow)
  }
  const timer = setTimeout(() => {
    const e = new Error('timeout')
    e.name = 'TimeoutError'
    ctl.abort(e)
  }, ms)
  try {
    return await fetch(url, { ...opts, signal: ctl.signal })
  } finally {
    clearTimeout(timer)
    if (opts && opts.signal) opts.signal.removeEventListener('abort', follow)
  }
}
async function jget(pathname, hdrs) {
  const r = await fetch(server + pathname, { headers: hdrs || {} })
  if (!r.ok) throw new Error(`${pathname} → ${r.status}`)
  return r.json()
}
async function createRoom() {
  const r = await fetch(server + '/api/rooms', { method: 'POST' })
  if (!r.ok) throw new Error('创建房间失败 ' + r.status)
  return r.json()
}
async function postChunk(room, token, body) {
  for (;;) {
    let r
    try {
      r = await fetchT(`${server}/api/rooms/${room}/chunk`, {
        method: 'POST',
        headers: { 'X-Room-Token': token },
        body,
      }, 30_000)
    } catch (e) {
      if (e && e.name === 'TimeoutError') { await sleep(500); continue } // 连接停滞:重连重投
      throw e
    }
    if (r.status === 429) { await sleep(250); continue }
    if (!r.ok) throw new Error('投递分片失败 ' + r.status)
    return
  }
}
async function getChunkAt(origin, room, i) {
  for (;;) {
    let r
    try {
      // 超时给足长轮询余量（服务端 25s 到期返回 408 后本就重试）
      r = await fetchT(`${origin}/api/rooms/${room}/chunk?i=${i}`, {}, 35_000)
    } catch (e) {
      if (e && e.name === 'TimeoutError') continue // 连接停滞:重连再等
      throw e
    }
    if (r.status === 408) continue
    if (r.status === 429) { await sleep(500); continue } // 并发长轮询上限:稍候重试
    if (r.status === 409) throw new Error('链接正被另一个接收方使用')
    if (r.status === 404) throw new Error('链接无效或已过期')
    if (r.status === 410) throw new Error('链接已被使用、过期，或发送方中断')
    if (!r.ok) throw new Error('拉取分片失败 ' + r.status)
    return Buffer.from(await r.arrayBuffer())
  }
}
const getState = (room) => jget(`/api/rooms/${room}/state`)

// ---------- 接收文件落盘（.part 临时名 + 成功后改名；失败清理，不留半截文件冒充完整文件） ----------
async function receiveToFile(target, meta, pull) {
  const part = target + '.part'
  const ws = fs.createWriteStream(part)
  const t0 = Date.now()
  let got = 0
  try {
    for (let i = 1; i < meta.count; i++) {
      const pt = await pull(i)
      got += pt.length
      ws.write(pt)
      const sp = got / Math.max(0.001, (Date.now() - t0) / 1000)
      process.stdout.write(`\r  已接收 ${fmt(got)} / ${fmt(meta.size)} · ${fmt(sp)}/s`)
    }
    await new Promise((r) => ws.end(r))
  } catch (e) {
    ws.destroy()
    await fsp.unlink(part).catch(() => {})
    throw e
  }
  await fsp.rename(part, target)
}

// ---------- 设备在线 ----------
let presence = null // { ip, id, secret }
async function heartbeat(name, identity) {
  const r = await fetch(server + '/api/presence', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(presence ? { 'X-Device-Secret': presence.secret } : {}),
    },
    body: JSON.stringify({ name, pub: b64u(identity.pub) }),
  })
  if (!r.ok) throw new Error('设备注册失败 ' + r.status)
  presence = await r.json()
  return presence
}
async function listDevices() {
  return (await jget('/api/devices')).devices || []
}

// ---------- devices 命令 ----------
async function doDevices() {
  const list = await listDevices()
  if (!list.length) return console.log('当前没有在线设备（对方打开本页或运行 listen 后出现）')
  console.log(`在线设备 ${list.length} 台：\n`)
  for (const d of list)
    console.log(`  ${avatarOf(d.ip)}  ${(d.name || '未命名设备').padEnd(20)} ${d.ip}${presence && d.ip === presence.ip ? '  （本机）' : ''}`)
  console.log(`\n直发示例: node cli.mjs send big.zip --to ${list[0].ip}`)
}

// ---------- 房间建立 / 邀请等待（单文件与批量共用） ----------
async function openRoom(preview, identity) {
  const { room, token } = await createRoom()
  let key
  let target = null
  let link = null
  if (opts.to) {
    const devices = await listDevices()
    target = devices.find((d) => d.ip === opts.to)
    if (!target) throw new Error(`设备 ${opts.to} 不在线（node cli.mjs devices 查看）`)
    if (presence && target.ip === presence.ip) throw new Error('不能发送给自己')
    key = roomKey(dh(identity.seed, fromB64u(target.pub)), identity.pub, fromB64u(target.pub), room)
    const hint = b64u(seal(key, Buffer.from(JSON.stringify(preview))))
    const r = await fetch(`${server}/api/rooms/${room}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Room-Token': token },
      body: JSON.stringify({ to: target.ip, pub: b64u(identity.pub), hint }),
    })
    if (!r.ok) throw new Error('投递邀请失败 ' + r.status)
    console.log(`\n${avatarOf(target.ip)}  已向 ${(target.name || '未命名设备')} (${target.ip}) 发出邀请，等待接受…`)
    const deadline = Date.now() + 5 * 60 * 1000
    for (;;) {
      if (Date.now() > deadline) throw new Error('对方超时未接受')
      let st
      try { st = await getState(room) } catch { throw new Error('邀请已过期（房间被回收）') }
      if (st.offer === 'accepted') break
      if (st.offer === 'rejected') throw new Error(`对方（${target.ip}）拒绝了传输`)
      await sleep(1000)
    }
    console.log('  对方已接受，开始传输…\n')
  } else {
    key = randomBytes(32)
    link = `${server}/#${room}.${key.toString('base64url')}`
    console.log('\n╔══════════════════════════════════════════╗')
    console.log('║  把下面的接收链接发给对方（浏览器打开即可）  ║')
    console.log('╚══════════════════════════════════════════╝\n')
    console.log('  ' + link + '\n')
    // 实测终端字符单元格比例（CSI 16t），按比例渲染近正方形模块；超长（>106B）返回 null 跳过
    const ratio = await QRCode.measureCellRatio()
    const qr = QRCode.asciiAdaptive(link, ratio)
    if (qr) console.log(qr + '  ↑ 手机扫码接收\n')
  }
  return { room, token, key, target, link }
}

// 发完之后等 ack（含密钥凭证校验）
async function awaitAck(room, key, target) {
  const deadline = Date.now() + 15 * 60 * 1000
  process.stdout.write('\n  等待对方接收…')
  for (;;) {
    await sleep(1500)
    if (Date.now() > deadline) { console.log('\n⏱ 等待超时退出（对方可能已中断）'); return }
    try {
      const st = await getState(room)
      if (st.acked) {
        const verified = st.ackProof && st.ackProof === ackProofOf(key, room)
        const who = target ? (target.name || target.ip) : '对方'
        console.log(verified
          ? `\n\n✅ ${who}已完整接收（凭证校验通过）`
          : `\n\n⚠ ${who}已接收，但 ack 无有效凭证——房间号泄露时可能被伪造\n`)
        return
      }
    } catch {
      console.log('\n⚠ 服务器已清除房间（可能超时）')
      return
    }
  }
}

// ---------- send（--to 定向 / 默认链接模式，单文件/文本） ----------
async function doSend({ type, name, size, readChunk }) {
  const identity = genIdentity()
  if (opts.to) await heartbeat(opts.name || os.hostname(), identity) // 供对方看到发送者名称
  const dataChunks = type === 'text' ? 1 : size === 0 ? 0 : Math.ceil(size / CHUNK)
  const count = 1 + dataChunks
  const { room, token, key, target } = await openRoom(
    { kind: type, name: type === 'text' ? null : name, size }, identity)

  const meta = { v: 1, type, name: type === 'text' ? null : name, mime: null, size, count }
  await postChunk(room, token, seal(key, Buffer.from(JSON.stringify(meta))))

  for (let i = 1; i < count; i++) {
    const pt = await readChunk(i - 1)
    await postChunk(room, token, seal(key, pt))
    const done = i * CHUNK
    process.stdout.write(`\r  已发送 ${fmt(Math.min(done, size))} / ${fmt(size)}`)
  }
  if (count === 1) process.stdout.write(`\r  已发送 ${fmt(size)} / ${fmt(size)}`)
  await fetch(`${server}/api/rooms/${room}/done`, { method: 'POST', headers: { 'X-Room-Token': token } })
  await awaitAck(room, key, target)
}

// ---------- 批量发送（多文件 / 目录递归，浏览器与 CLI 互通） ----------
const FILES_MAX = 256
const dataChunkCount = (size) => (size === 0 ? 0 : Math.ceil(size / CHUNK))

// 收集发送清单：文件直接入列；目录递归展开为相对路径（跳过点开头隐藏项）
async function gatherFiles(paths) {
  const files = [] // { abs, rel, size }
  for (const p of paths) {
    const st = await fsp.stat(p).catch(() => null)
    if (!st) throw new Error(`路径不存在: ${p}`)
    if (st.isDirectory()) {
      const root = path.resolve(p)
      const walk = async (dir) => {
        for (const e of await fsp.readdir(dir, { withFileTypes: true })) {
          if (e.name.startsWith('.')) continue // .git / .DS_Store 等
          const fp = path.join(dir, e.name)
          if (e.isDirectory()) await walk(fp)
          else if (e.isFile()) files.push({ abs: fp, rel: path.relative(root, fp).split(path.sep).join('/'), size: (await fsp.stat(fp)).size })
        }
      }
      await walk(root)
    } else if (st.isFile()) files.push({ abs: p, rel: path.basename(p), size: st.size })
    else throw new Error(`不支持的路径类型: ${p}`)
  }
  if (!files.length) throw new Error('没有可发送的文件（目录为空或只含隐藏文件）')
  if (files.length > FILES_MAX) throw new Error(`文件数超过上限 ${FILES_MAX}（当前 ${files.length}）`)
  return files
}

async function doSendBatch(files) {
  const identity = genIdentity()
  if (opts.to) await heartbeat(opts.name || os.hostname(), identity)
  const totalSize = files.reduce((n, f) => n + f.size, 0)
  const manifest = files.map((f) => ({ name: f.rel, size: f.size, count: dataChunkCount(f.size) }))
  const { room, token, key, target } = await openRoom(
    { kind: 'batch', count: manifest.length, size: totalSize }, identity)
  const count = 1 + manifest.reduce((n, m) => n + m.count, 0)
  const meta = { v: 1, type: 'batch', files: manifest, count, size: totalSize }
  await postChunk(room, token, seal(key, Buffer.from(JSON.stringify(meta))))

  let sent = 0
  for (let f = 0; f < files.length; f++) {
    const { abs, rel, size } = files[f]
    const n = manifest[f].count
    if (n > 0) {
      const fh = await fsp.open(abs, 'r')
      for (let i = 0; i < n; i++) {
        const len = Math.min(CHUNK, size - i * CHUNK)
        const buf = Buffer.allocUnsafe(len)
        let read = 0
        while (read < len) { // 循环读满：网络盘等场景可能短读
          const { bytesRead } = await fh.read(buf, read, len - read, i * CHUNK + read)
          if (!bytesRead) break
          read += bytesRead
        }
        await postChunk(room, token, seal(key, read === len ? buf : buf.subarray(0, read)))
        sent += read
        process.stdout.write(`\r  [${f + 1}/${files.length}] ${rel.slice(0, 28).padEnd(28)} 已发送 ${fmt(sent)} / ${fmt(totalSize)}`)
      }
      await fh.close()
    }
  }
  await fetch(`${server}/api/rooms/${room}/done`, { method: 'POST', headers: { 'X-Room-Token': token } })
  console.log(`\n  共 ${files.length} 个文件（${fmt(totalSize)}）已全部发出`)
  await awaitAck(room, key, target)
}

// 批量接收落盘：按 manifest 顺序拉流，逐文件写目标目录（相对路径逐段净化）
function safeJoin(dir, rel) {
  const parts = String(rel || '').split('/').map(safeName).filter(Boolean)
  return parts.length ? path.join(dir, ...parts) : path.join(dir, 'received')
}
async function receiveBatch(origin, room, key, meta, outDir) {
  await fsp.mkdir(outDir, { recursive: true })
  let idx = 1 // 下一个文件的首个数据分片序号
  for (const f of meta.files) {
    const target = safeJoin(outDir, f.name)
    await fsp.mkdir(path.dirname(target), { recursive: true })
    if (!f.count) {
      await fsp.writeFile(target, Buffer.alloc(0))
      console.log(`\n  ✓ ${f.name}（0 B，空文件）`)
      continue
    }
    const start = idx
    idx += f.count
    await receiveToFile(target, { size: f.size, count: f.count + 1 },
      async (i) => unseal(key, await getChunkAt(origin, room, start + i - 1)))
    console.log(`\n  ✓ ${f.name}（${fmt(f.size)}）`)
  }
}

// ---------- recv（链接模式） ----------
async function doRecv(link) {
  const u = new URL(link)
  const frag = u.hash.slice(1)
  const m = /^([0-9A-Za-z]{10})\.([A-Za-z0-9_-]{43})$/.exec(frag)
  if (!m || !ROOM_RE.test(m[1])) throw new Error('链接格式不正确')
  const key = Buffer.from(m[2], 'base64url')
  const origin = u.origin
  const room = m[1]

  const meta = JSON.parse(unseal(key, await getChunkAt(origin, room, 0)))
  if (meta.type === 'batch') {
    const dir = opts.out || '.'
    await receiveBatch(origin, room, key, meta, dir)
    await fetch(`${origin}/api/rooms/${room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, room) }) }).catch(() => {})
    console.log(`\n\n✅ 已解密并保存 ${meta.files.length} 个文件到 ${path.resolve(dir)}\n`)
    return
  }
  if (meta.type === 'text') {
    const pt = unseal(key, await getChunkAt(origin, room, 1))
    process.stdout.write(pt)
    await fetch(`${origin}/api/rooms/${room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, room) }) }).catch(() => {})
    return
  }
  const target = opts.out || safeName(meta.name)
  await receiveToFile(target, meta, async (i) => unseal(key, await getChunkAt(origin, room, i)))
  await fetch(`${origin}/api/rooms/${room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, room) }) }).catch(() => {})
  console.log(`\n\n✅ 已解密并保存到 ${target}（${fmt(meta.size)}）\n`)
}

// ---------- listen（常驻接收端，可被直发） ----------
async function doListen() {
  const identity = genIdentity()
  const name = opts.name || os.hostname()
  await heartbeat(name, identity)
  let hbFailing = false
  setInterval(() => {
    heartbeat(name, identity)
      .then(() => { hbFailing = false })
      .catch((e) => {
        if (hbFailing) return // 只在状态翻转时提示,避免每 5s 刷屏
        hbFailing = true
        console.error(`  ⚠ 心跳失败：${e.message}（持续重试,恢复后自动重新上线）`)
      })
  }, 5000)
  console.log(`${avatarOf(presence.ip)}  本机已上线：${name} @ ${presence.ip}（服务器 ${server}）`)
  console.log('  等待直发请求…（Ctrl+C 退出）\n')

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  const ask = (q) => new Promise((r) => rl.question(q, r))

  for (;;) {
    let offers
    try {
      const r = await fetch(server + '/api/offers', { headers: { 'X-Device-Secret': presence.secret } })
      if (r.status === 401) { // 同 IP 其他端点重新注册导致 secret 轮换
        await heartbeat(name, identity)
        continue
      }
      if (!r.ok) { await sleep(2000); continue }
      offers = (await r.json()).offers || []
    } catch { await sleep(2000); continue }

    for (const o of offers) {
      try {
        await handleOffer(o, identity, ask)
      } catch (e) {
        console.error(`  ✗ 处理邀请失败：${e.message}`)
        fetch(`${server}/api/offers/${o.id}/reject`, { method: 'POST', headers: { 'X-Device-Secret': presence.secret } }).catch(() => {})
      }
    }
  }
}

async function handleOffer(o, identity, ask) {
  const theirPub = fromB64u(o.pub)
  const key = roomKey(dh(identity.seed, theirPub), theirPub, identity.pub, o.room)

  let preview
  try {
    preview = JSON.parse(unseal(key, fromB64u(o.hint)))
  } catch {
    console.log(`\n  ⚠ 来自 ${o.from.ip} 的邀请预览解密失败（可能被篡改），已拒绝`)
    return fetch(`${server}/api/offers/${o.id}/reject`, { method: 'POST', headers: { 'X-Device-Secret': presence.secret } })
  }
  const desc = preview.kind === 'text' ? `一段文本（${fmt(preview.size || 0)}）`
    : preview.kind === 'batch' ? `${preview.count} 个文件（${fmt(preview.size || 0)}）`
    : `${preview.name || '未命名文件'}（${fmt(preview.size || 0)}）`
  console.log(`\n${avatarOf(o.from.ip || '?')}  ${(o.from.name || '未知设备')} @ ${o.from.ip} 想发给你：${desc}`)

  if (!opts.yes) {
    if (!process.stdin.isTTY) {
      console.log('  非 TTY 环境需 --yes 才能自动接受，已拒绝')
      return fetch(`${server}/api/offers/${o.id}/reject`, { method: 'POST', headers: { 'X-Device-Secret': presence.secret } })
    }
    const ans = (await ask('  接受？(y/n) ')).trim().toLowerCase()
    if (ans !== 'y' && ans !== 'yes') {
      console.log('  已拒绝')
      return fetch(`${server}/api/offers/${o.id}/reject`, { method: 'POST', headers: { 'X-Device-Secret': presence.secret } })
    }
  }

  const r = await fetch(`${server}/api/offers/${o.id}/accept`, { method: 'POST', headers: { 'X-Device-Secret': presence.secret } })
  if (!r.ok) throw new Error('接受失败 ' + r.status)

  const meta = JSON.parse(unseal(key, await getChunkAt(server, o.room, 0)))
  if (meta.type === 'batch') {
    const dir = opts.out || '.'
    await receiveBatch(server, o.room, key, meta, dir)
    await fetch(`${server}/api/rooms/${o.room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, o.room) }) }).catch(() => {})
    console.log(`\n  ✅ 已解密保存 ${meta.files.length} 个文件到 ${path.resolve(dir)}\n`)
    return
  }
  if (meta.type === 'text') {
    const pt = unseal(key, await getChunkAt(server, o.room, 1))
    console.log('  ──────── 文本开始 ────────')
    process.stdout.write(pt)
    if (!pt.toString().endsWith('\n')) console.log()
    console.log('  ──────── 文本结束 ────────')
    await fetch(`${server}/api/rooms/${o.room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, o.room) }) }).catch(() => {})
    return
  }

  const target = path.join(opts.out || '.', safeName(meta.name))
  await receiveToFile(target, meta, async (i) => unseal(key, await getChunkAt(server, o.room, i)))
  await fetch(`${server}/api/rooms/${o.room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, o.room) }) }).catch(() => {})
  console.log(`\n  ✅ 已解密保存到 ${target}（${fmt(meta.size)}）\n`)
}

// ---------- main ----------
try {
  if (cmd === 'devices') {
    await doDevices()
  } else if (cmd === 'send' && pos[1]) {
    const sendPaths = pos.slice(1)
    const single = sendPaths.length === 1 ? await fsp.stat(sendPaths[0]).catch(() => null) : null
    if (single && single.isFile()) {
    const filePath = pos[1]
    const fh = await fsp.open(filePath, 'r')
    const size = (await fh.stat()).size
    await doSend({
      type: 'file',
      name: path.basename(filePath),
      size,
      readChunk: async (idx) => {
        const len = Math.min(CHUNK, size - idx * CHUNK)
        const buf = Buffer.allocUnsafe(len)
        let read = 0
        while (read < len) { // 循环读满：网络盘等场景 fh.read 可能短读
          const { bytesRead } = await fh.read(buf, read, len - read, idx * CHUNK + read)
          if (!bytesRead) break
          read += bytesRead
        }
        return read === len ? buf : buf.subarray(0, read)
      },
    })
    await fh.close()
    } else {
      await doSendBatch(await gatherFiles(sendPaths))
    }
  } else if (cmd === 'send-text' && pos[1] !== undefined) {
    const pt = Buffer.from(pos[1], 'utf8')
    await doSend({
      type: 'text',
      size: pt.length,
      readChunk: async () => pt,
    })
  } else if (cmd === 'recv' && pos[1]) {
    await doRecv(pos[1])
  } else if (cmd === 'listen') {
    await doListen()
  } else {
    usage()
  }
} catch (e) {
  console.error('✗ ' + e.message)
  process.exit(1)
}
