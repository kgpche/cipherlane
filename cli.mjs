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
  else if (args[i] === '--verify') opts.verify = args[++i]
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
  node cli.mjs send <文件/目录...> [--to <设备IP>] [--verify <指纹hex≥8>] [--name <名称>] [--server ...]
  node cli.mjs send-text <文本> [--to <设备IP>] [--verify <指纹hex≥8>] [--name <名称>] [--server ...]
  node cli.mjs recv '<接收链接>' [-o 输出路径]
  node cli.mjs listen [--yes] [-o 保存目录] [--name <名称>] [--server ...]

设备直发：--to 指定在线设备（node cli.mjs devices 查看），密钥 X25519 协商，无需传链接。
  指纹 = SHA256(X25519 公钥) 前 16 字节（32 hex）；可用 --verify 核对目标指纹（≥8 位前缀）。
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

// 终端输出净化：远端可控字符串（设备名/文件名/预览/邀请字段）打印前过滤 C0/C1、
// ANSI CSI/OSC 转义，防终端注入（光标移动、标题改写、OSC 52 剪贴板写入等）。
function clean(raw, max = 200) {
  let s = String(raw == null ? '' : raw)
  s = s.replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '') // OSC ... BEL/ST
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')              // CSI
    .replace(/\x1b[@-Z\\-_]/g, '')                        // 其他两字节转义
    .replace(/[\x00-\x1f\x7f-\x9f]/g, '')                 // C0/C1 控制字符
  if (s.length > max) s = s.slice(0, max) + '…'
  return s
}

// 公钥指纹（TOFU）：SHA256(原始 32B 公钥) 前 16 字节 → 32 hex。与 public/app.js 的 fpOf 一致。
function fpOfPub(rawPub) {
  return createHash('sha256').update(Buffer.from(rawPub)).digest().subarray(0, 16).toString('hex')
}
const fpOfB64 = (pubB64) => fpOfPub(fromB64u(pubB64))

// 分片位置绑定（协议 v2）：AAD = UTF-8("cipherlane/chunk/v2|" + room + "|" + index)
// 与 public/app.js 的 chunkAAD 必须逐字节一致；index 十进制无补零。
const chunkAAD = (room, index) => Buffer.from('cipherlane/chunk/v2|' + room + '|' + index, 'utf8')

// ---------- AES-GCM（与浏览器端格式一致：IV(12) || 密文 || TAG(16)） ----------
function seal(key, pt, aad) {
  const iv = randomBytes(12)
  const c = createCipheriv('aes-256-gcm', key, iv)
  if (aad) c.setAAD(Buffer.from(aad))
  const ct = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()])
  return Buffer.concat([iv, ct])
}
function unseal(key, packed, aad) {
  packed = Buffer.from(packed)
  if (packed.length < 28) throw new Error('数据不完整')
  const iv = packed.subarray(0, 12)
  const tag = packed.subarray(packed.length - 16)
  const d = createDecipheriv('aes-256-gcm', key, iv)
  if (aad) d.setAAD(Buffer.from(aad))
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
// 幂等投递：请求头带 X-Chunk-Seq；超时/连接失败/429 重试都复用同一 seq，
// 服务端据此把重复包识别为 duplicate（零记账），旧服务器忽略该头、退化为旧行为。
async function postChunk(room, token, seq, body) {
  for (;;) {
    let r
    try {
      r = await fetchT(`${server}/api/rooms/${room}/chunk`, {
        method: 'POST',
        headers: { 'X-Room-Token': token, 'X-Chunk-Seq': String(seq) },
        body,
      }, 30_000)
    } catch (e) {
      if (e && e.name === 'TimeoutError') { await sleep(500); continue } // 连接停滞:重连重投（同 seq）
      throw e
    }
    if (r.status === 429) { await sleep(250); continue } // 背压:同 seq 重投
    // 409 = 服务端 posted 与本地序号脱节（不能靠重试修复），明确报错而非静默重排
    if (r.status === 409) throw new Error(`服务器分片计数不同步（seq=${seq}, out-of-order），请重新建立传输`)
    if (!r.ok) throw new Error('投递分片失败 ' + r.status)
    return
  }
}
async function getChunkAt(origin, room, i, resume) {
  for (;;) {
    let r
    try {
      // 超时给足长轮询余量（服务端 25s 到期返回 408 后本就重试）
      // X-Resume: 1 → 房间进入可续传模式（GET 只读，供中断后重拉）；旧服务器忽略此头
      r = await fetchT(`${origin}/api/rooms/${room}/chunk?i=${i}`,
        resume ? { headers: { 'X-Resume': '1' } } : {}, 35_000)
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

// progress 上报(可续传模式):每落盘一片提交,服务器据此释放缓存。
// 旧服务器 404/经典房间 409 → 静默降级为不可续传
function makeProgress(origin, room) {
  let ok = true
  return async (through) => {
    if (!ok) return
    try {
      const r = await fetchT(`${origin}/api/rooms/${room}/progress`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ through }),
      }, 10_000)
      if (r.status === 404 || r.status === 409) ok = false
    } catch { /* 上报失败无害:服务器多留一会儿缓存 */ }
  }
}

// 读 0 号 meta：先按协议 v2（AAD room|0）解，失败回退 v1（旧发送端/旧测试夹具）。
// resume=false 用于设备直发（经典消费语义，避免直发单文件无进度上报时触发背压死锁）。
async function readMeta(origin, room, key, resume = true) {
  const packed = await getChunkAt(origin, room, 0, resume)
  let pt
  try {
    pt = unseal(key, packed, chunkAAD(room, 0))
  } catch {
    pt = unseal(key, packed)
  }
  return JSON.parse(pt)
}

// ---------- 接收文件落盘 ----------
// .part 临时名 + 成功后改名；opts.startFrom > 1 时为续传（追加写，从该数据分片继续）。
// 中断保留 .part：重跑同一命令按大小对齐到分片边界续传；错误若是 GCM 验签失败
// （密钥不符/对错了链接），由调用方删除重来——无需任何 sidecar 元数据。
async function receiveToFile(target, meta, pull, opts = {}) {
  const part = target + '.part'
  const startFrom = opts.startFrom || 1
  const ws = fs.createWriteStream(part, startFrom > 1 ? { flags: 'a' } : {})
  const t0 = Date.now()
  let got = opts.initialGot || 0
  try {
    for (let i = startFrom; i < meta.count; i++) {
      const pt = await pull(i)
      got += pt.length
      // 进度上报必须在写入回调之后:write 是异步缓冲的,提前上报会在进程被杀后
      // 出现 server.through 领先磁盘实况 → 重跑拉到已释放的分片(410 behind)
      await new Promise((r, j) => ws.write(pt, (e) => { if (e) j(e); else r() }))
      if (opts.onChunk) opts.onChunk(i, got)
      const sp = (got - (opts.initialGot || 0)) / Math.max(0.001, (Date.now() - t0) / 1000)
      process.stdout.write(`\r  已接收 ${fmt(got)} / ${fmt(meta.size)} · ${fmt(sp)}/s`)
    }
    await new Promise((r) => ws.end(r))
  } catch (e) {
    ws.destroy()
    if (!/GCM|auth|完整性/.test(e.message)) {
      // 传输性中断:保留 .part 供续传
      console.log(`\n  ⏸ 传输中断,进度已保留: ${part}\n  重跑同一命令即可从断点继续（链接与输出路径不变）`)
    }
    throw e
  }
  // 完整性：累计明文长度必须与 meta.size 一致（多/少/错位都算失败），不一致不 ack
  if (got !== meta.size) throw new Error(`完整性校验失败：文件大小 ${got} ≠ ${meta.size}`)
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
  console.log(`在线设备 ${list.length} 台（指纹 = SHA256(公钥) 前 32 hex，可与对方当面核对）：\n`)
  for (const d of list) {
    const self = presence && d.ip === presence.ip ? '  （本机）' : ''
    console.log(`  ${avatarOf(d.ip)}  ${clean(d.name || '未命名设备', 32).padEnd(20)} ${clean(d.ip, 64)}${self}`)
    console.log(`      ${' '.repeat(2)}#${fpOfB64(d.pub)}`)
  }
  console.log(`\n直发示例: node cli.mjs send big.zip --to ${list[0].ip} --verify <对方指纹前8位以上>`)
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
    // TOFU 指纹核对：显示目标指纹；--verify 给出 ≥8 位 hex 前缀，不匹配拒绝发送
    const fp = fpOfB64(target.pub)
    if (opts.verify !== undefined) {
      const want = String(opts.verify).toLowerCase().replace(/^#/, '')
      if (!/^[0-9a-f]{8,32}$/.test(want)) throw new Error('--verify 需要 8~32 位十六进制指纹前缀')
      if (!fp.startsWith(want)) throw new Error(`目标指纹不符：期望 ${want}… 实际 #${fp}（可能被调包，已拒绝发送）`)
      console.log(`\n  ✓ 目标 ${clean(target.name || '未命名设备', 32)} @ ${clean(target.ip, 64)} 指纹核对通过 #${fp}`)
    } else {
      console.log(`\n  ⚠ 目标 ${clean(target.name || '未命名设备', 32)} @ ${clean(target.ip, 64)} 指纹 #${fp}`)
      console.log('    请与对方当面/口头核对；下次可用 --verify <指纹前8位以上> 强制校验')
    }
    key = roomKey(dh(identity.seed, fromB64u(target.pub)), identity.pub, fromB64u(target.pub), room)
    const hint = b64u(seal(key, Buffer.from(JSON.stringify(preview))))
    const r = await fetch(`${server}/api/rooms/${room}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Room-Token': token },
      body: JSON.stringify({ to: target.ip, pub: b64u(identity.pub), hint }),
    })
    if (!r.ok) throw new Error('投递邀请失败 ' + r.status)
    console.log(`\n${avatarOf(target.ip)}  已向 ${clean(target.name || '未命名设备', 32)} (${clean(target.ip, 64)}) 发出邀请，等待接受…`)
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
        const who = target ? clean(target.name || target.ip, 32) : '对方'
        if (verified) console.log(`\n\n✅ ${who}已完整接收（凭证校验通过）`)
        else console.log(`\n\n⚠ ${who}已接收，但 ack 无有效凭证——房间号泄露时可能被伪造\n`)
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

  // 协议 v2：0 号 meta 与每个数据分片都用 room+index 的 AAD 绑定位置
  const meta = { v: 2, type, name: type === 'text' ? null : name, mime: null, size, count }
  await postChunk(room, token, 0, seal(key, Buffer.from(JSON.stringify(meta)), chunkAAD(room, 0)))

  for (let i = 1; i < count; i++) {
    const pt = await readChunk(i - 1)
    await postChunk(room, token, i, seal(key, pt, chunkAAD(room, i)))
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
  // 协议 v2：全局分片序号（跨文件连续），每片 AAD 绑定 room+index
  const meta = { v: 2, type: 'batch', files: manifest, count, size: totalSize }
  await postChunk(room, token, 0, seal(key, Buffer.from(JSON.stringify(meta)), chunkAAD(room, 0)))

  let sent = 0
  let ci = 1 // 全局分片序号（0 号是 meta）
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
        const seq = ci++ // 全局序号（跨文件连续），重试复用
        await postChunk(room, token, seq, seal(key, read === len ? buf : buf.subarray(0, read), chunkAAD(room, seq)))
        sent += read
        process.stdout.write(`\r  [${f + 1}/${files.length}] ${clean(rel, 28).padEnd(28)} 已发送 ${fmt(sent)} / ${fmt(totalSize)}`)
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
async function receiveBatch(origin, room, key, meta, outDir, useAAD) {
  await fsp.mkdir(outDir, { recursive: true })
  const progress = makeProgress(origin, room)
  await progress(1)
  // manifest 自洽性前置校验：各文件大小之和必须等于 meta.size
  const manifestSum = (meta.files || []).reduce((n, f) => n + (f.size || 0), 0)
  if (manifestSum !== (meta.size || 0)) throw new Error(`完整性校验失败：manifest 总大小 ${manifestSum} ≠ ${meta.size || 0}`)
  let idx = 1 // 下一个文件的首个数据分片序号
  for (const f of meta.files) {
    const target = safeJoin(outDir, f.name)
    await fsp.mkdir(path.dirname(target), { recursive: true })
    if (!f.count) {
      await fsp.writeFile(target, Buffer.alloc(0))
      console.log(`\n  ✓ ${clean(f.name)}（0 B，空文件）`)
      continue
    }
    const start = idx
    idx += f.count
    await receiveResumable(origin, room, key, { ...f, count: f.count + 1 }, target, start, useAAD)
    console.log(`\n  ✓ ${clean(f.name)}（${fmt(f.size)}）`)
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

  // X-Resume 让房间进入可续传模式（旧服务器忽略该头，自动退化为不可续传）
  const meta = await readMeta(origin, room, key)
  const useAAD = meta.v === 2 // 后续分片路径由 meta.v 决定；v1 旧发送端走无 AAD 旧路径
  if (meta.type === 'batch') {
    const dir = opts.out || '.'
    await receiveBatch(origin, room, key, meta, dir, useAAD)
    await fetch(`${origin}/api/rooms/${room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, room) }) }).catch(() => {})
    console.log(`\n\n✅ 已解密并保存 ${meta.files.length} 个文件到 ${path.resolve(dir)}\n`)
    return
  }
  if (meta.type === 'text') {
    const pt = unseal(key, await getChunkAt(origin, room, 1, true), useAAD ? chunkAAD(room, 1) : null)
    if (pt.length !== meta.size) throw new Error(`完整性校验失败：文本长度 ${pt.length} ≠ ${meta.size}`)
    process.stdout.write(pt)
    await fetch(`${origin}/api/rooms/${room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, room) }) }).catch(() => {})
    return
  }
  const target = opts.out || safeName(meta.name)
  await receiveResumable(origin, room, key, meta, target, 1, useAAD)
  await fetch(`${origin}/api/rooms/${room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, room) }) }).catch(() => {})
  console.log(`\n\n✅ 已解密并保存到 ${target}（${fmt(meta.size)}）\n`)
}

// 单文件接收:.part 存在则对齐分片边界续传;首片 GCM 验签失败 = .part 与本次
// 传输不符（换了链接/密钥）→ 删除重来。start = 该文件数据分片的全局起始序号。
async function receiveResumable(origin, room, key, meta, target, start, useAAD) {
  const progress = makeProgress(origin, room)
  if (start === 1) await progress(1) // 元信息已解析
  const run = (startFrom, initialGot) => receiveToFile(target, meta,
    async (i) => unseal(key, await getChunkAt(origin, room, start + i - 1, true),
      useAAD ? chunkAAD(room, start + i - 1) : null),
    // 滞后一片提交：write 回调(已入内核)后才声明"前一片安全"，留出一整片余量——
    // 否则击杀瞬间磁盘 stat 可能落后内核刷盘,重跑会拉到已释放的分片(410 behind)
    { startFrom, initialGot, onChunk: (i) => progress(start + i - 1) })
  const part = target + '.part'
  const st = await fsp.stat(part).catch(() => null)
  const fullCommit = () => progress(start + meta.count - 1) // 本文件全部落盘(ws.end 已等待)
  try {
    if (st) {
      const lt = Math.min(Math.floor(st.size / CHUNK), meta.count - 1) // 已完整落盘的数据分片数
      if (lt > 0) {
        await fsp.truncate(part, lt * CHUNK)
        console.log(`  ↻ 检测到未完成的接收，从第 ${lt + 1}/${meta.count - 1} 片续传`)
        await run(lt + 1, lt * CHUNK)
      } else await run(1, 0)
    } else await run(1, 0)
    await fullCommit()
  } catch (e) {
    if (/GCM|auth/i.test(e.message)) {
      await fsp.unlink(part).catch(() => {})
      console.log('  ⚠ 已有 .part 与本次传输不符（验签失败），重新完整接收')
      await run(1, 0)
      await fullCommit()
    } else if (/已被使用/.test(e.message)) {
      // 服务器缓存已回收(等价于不可续传)：从头接收兜底
      await fsp.unlink(part).catch(() => {})
      console.log('  ⚠ 断点已被服务器回收，从头完整接收')
      await run(1, 0)
      await fullCommit()
    } else throw e
  }
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
  const fp = fpOfPub(theirPub) // 发送方指纹（TOFU 人工核对锚点）
  const key = roomKey(dh(identity.seed, theirPub), theirPub, identity.pub, o.room)

  let preview
  try {
    preview = JSON.parse(unseal(key, fromB64u(o.hint)))
  } catch {
    console.log(`\n  ⚠ 来自 ${clean(o.from.ip, 64)} 的邀请预览解密失败（可能被篡改），已拒绝`)
    return fetch(`${server}/api/offers/${o.id}/reject`, { method: 'POST', headers: { 'X-Device-Secret': presence.secret } })
  }
  const desc = preview.kind === 'text' ? `一段文本（${fmt(preview.size || 0)}）`
    : preview.kind === 'batch' ? `${clean(preview.count, 12)} 个文件（${fmt(preview.size || 0)}）`
    : `${clean(preview.name || '未命名文件', 64)}（${fmt(preview.size || 0)}）`
  console.log(`\n${avatarOf(o.from.ip || '?')}  ${clean(o.from.name || '未知设备', 32)} @ ${clean(o.from.ip, 64)} 想发给你：${desc}`)
  console.log(`  发送方公钥指纹 #${fp}`)
  console.log('  （请与发送方当面/口头核对；不会自动比对）')

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

  // 设备直发用经典消费语义（resume=false）：直发单文件无进度上报，
  // 若让房间进入可续传模式会因 through 不前进触发发送方背压死锁。
  const meta = await readMeta(server, o.room, key, false)
  const useAAD = meta.v === 2
  const pull = async (i) => unseal(key, await getChunkAt(server, o.room, i, false), useAAD ? chunkAAD(o.room, i) : null)
  if (meta.type === 'batch') {
    const dir = opts.out || '.'
    await receiveBatch(server, o.room, key, meta, dir, useAAD)
    await fetch(`${server}/api/rooms/${o.room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, o.room) }) }).catch(() => {})
    console.log(`\n  ✅ 已解密保存 ${meta.files.length} 个文件到 ${path.resolve(dir)}\n`)
    return
  }
  if (meta.type === 'text') {
    const pt = await pull(1)
    if (pt.length !== meta.size) throw new Error(`完整性校验失败：文本长度 ${pt.length} ≠ ${meta.size}`)
    console.log('  ──────── 文本开始 ────────')
    process.stdout.write(pt)
    if (!pt.toString().endsWith('\n')) console.log()
    console.log('  ──────── 文本结束 ────────')
    await fetch(`${server}/api/rooms/${o.room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, o.room) }) }).catch(() => {})
    return
  }

  const target = path.join(opts.out || '.', safeName(meta.name))
  await receiveToFile(target, meta, pull)
  await fetch(`${server}/api/rooms/${o.room}/ack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ proof: ackProofOf(key, o.room) }) }).catch(() => {})
  console.log(`\n  ✅ 已解密保存到 ${safeName(meta.name)}（${fmt(meta.size)}）\n`)
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
