#!/usr/bin/env node
// cipherlane CLI —— 命令行收发（无浏览器环境 / 服务器之间）
//
//   node cli.mjs send <文件路径>        [--server http://192.168.1.10:7777]
//   node cli.mjs send-text <文本>       [--server ...]
//   node cli.mjs recv '<接收链接>'      [-o 输出路径]
//
// 零依赖（Node ≥ 18）。加密使用 node:crypto 原生 aes-256-gcm，与浏览器端互通。

import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import path from 'node:path'

const CHUNK = 1024 * 1024
const ROOM_RE = /^[0-9A-Za-z]{10}$/

const args = process.argv.slice(2)
const pos = []
const opts = {}
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--server') opts.server = args[++i]
  else if (args[i] === '-o') opts.out = args[++i]
  else pos.push(args[i])
}
const cmd = pos[0]
const server = (opts.server || process.env.LANDROP_SERVER || 'http://127.0.0.1:7777').replace(/\/+$/, '')

function usage() {
  console.log(`cipherlane · 密道 CLI

用法:
  node cli.mjs send <文件路径> [--server http://<局域网IP>:7777]
  node cli.mjs send-text <文本> [--server http://<局域网IP>:7777]
  node cli.mjs recv '<接收链接>' [-o 输出路径]`)
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

// ---------- 加密（与浏览器端格式一致：IV(12) || 密文 || TAG(16)） ----------
function seal(key, pt) {
  const iv = randomBytes(12)
  const c = createCipheriv('aes-256-gcm', key, iv)
  const ct = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()])
  return Buffer.concat([iv, ct])
}
function unseal(key, packed) {
  if (packed.length < 28) throw new Error('数据不完整')
  const iv = packed.subarray(0, 12)
  const ct = packed.subarray(12, packed.length - 16)
  const tag = packed.subarray(packed.length - 16)
  const d = createDecipheriv('aes-256-gcm', key, iv)
  d.setAuthTag(tag)
  return Buffer.concat([d.update(ct), d.final()])
}

// ---------- 协议 ----------
async function createRoom() {
  const r = await fetch(server + '/api/rooms', { method: 'POST' })
  if (!r.ok) throw new Error('创建房间失败 ' + r.status)
  return r.json()
}
async function postChunk(room, token, body) {
  for (;;) {
    const r = await fetch(`${server}/api/rooms/${room}/chunk`, {
      method: 'POST',
      headers: { 'X-Room-Token': token },
      body,
    })
    if (r.status === 429) { await sleep(250); continue }
    if (!r.ok) throw new Error('投递分片失败 ' + r.status)
    return
  }
}
async function getChunk(room, i) {
  for (;;) {
    const r = await fetch(`${server}/api/rooms/${room}/chunk?i=${i}`)
    if (r.status === 408) continue
    if (r.status === 404) throw new Error('链接无效或已过期')
    if (r.status === 410) throw new Error('链接已被使用、过期，或发送方中断')
    if (!r.ok) throw new Error('拉取分片失败 ' + r.status)
    return Buffer.from(await r.arrayBuffer())
  }
}
async function getState(room) {
  const r = await fetch(`${server}/api/rooms/${room}/state`)
  if (!r.ok) throw new Error('查询状态失败')
  return r.json()
}

// ---------- send ----------
async function doSend({ type, name, size, readChunk }) {
  const { room, token } = await createRoom()
  const key = randomBytes(32)
  const link = `${server}/#${room}.${key.toString('base64url')}`
  const dataChunks = type === 'text' ? 1 : size === 0 ? 0 : Math.ceil(size / CHUNK)
  const count = 1 + dataChunks

  console.log('\n╔══════════════════════════════════════════╗')
  console.log('║  把下面的接收链接发给对方（浏览器打开即可）  ║')
  console.log('╚══════════════════════════════════════════╝\n')
  console.log('  ' + link + '\n')

  const meta = { v: 1, type, name: type === 'text' ? null : name, mime: null, size, count }
  await postChunk(room, token, seal(key, Buffer.from(JSON.stringify(meta))))

  const t0 = Date.now()
  for (let i = 1; i < count; i++) {
    const pt = await readChunk(i - 1)
    await postChunk(room, token, seal(key, pt))
    const done = i * CHUNK
    process.stdout.write(`\r  已发送 ${fmt(Math.min(done, size))} / ${fmt(size)}`)
  }
  if (count === 1) process.stdout.write(`\r  已发送 ${fmt(size)} / ${fmt(size)}`)
  await fetch(`${server}/api/rooms/${room}/done`, { method: 'POST', headers: { 'X-Room-Token': token } })

  // 等对方收完
  const deadline = Date.now() + 15 * 60 * 1000
  process.stdout.write('\n  等待对方接收…')
  for (;;) {
    await sleep(1500)
    if (Date.now() > deadline) { console.log('\n⏱ 等待超时退出（对方可能已中断）'); return }
    try {
      const st = await getState(room)
      if (st.acked) {
        console.log('\n\n✅ 对方已完整接收\n')
        return
      }
    } catch {
      console.log('\n⚠ 服务器已清除房间（可能超时）')
      return
    }
  }
}

// ---------- recv ----------
async function doRecv(link) {
  const u = new URL(link)
  const frag = u.hash.slice(1)
  const m = /^([0-9A-Za-z]{10})\.([A-Za-z0-9_-]{43})$/.exec(frag)
  if (!m || !ROOM_RE.test(m[1])) throw new Error('链接格式不正确')
  const key = Buffer.from(m[2], 'base64url')
  const origin = u.origin
  const room = m[1]

  const meta = JSON.parse(unseal(key, await getChunkAt(origin, room, 0)))
  if (meta.type === 'text') {
    const pt = unseal(key, await getChunkAt(origin, room, 1))
    process.stdout.write(pt)
    await fetch(`${origin}/api/rooms/${room}/ack`, { method: 'POST' }).catch(() => {})
    return
  }
  const safe = (meta.name || 'received').split(/[/\\]/).pop().replace(/[^\w.\-\u4e00-\u9fa5 ]+/g, '_') || 'received'
  const target = opts.out || safe
  const ws = fs.createWriteStream(target)
  const t0 = Date.now()
  let got = 0
  for (let i = 1; i < meta.count; i++) {
    const pt = unseal(key, await getChunkAt(origin, room, i))
    got += pt.length
    ws.write(pt)
    const sp = got / Math.max(0.001, (Date.now() - t0) / 1000)
    process.stdout.write(`\r  已接收 ${fmt(got)} / ${fmt(meta.size)} · ${fmt(sp)}/s`)
  }
  await new Promise((r) => ws.end(r))
  await fetch(`${origin}/api/rooms/${room}/ack`, { method: 'POST' }).catch(() => {})
  console.log(`\n\n✅ 已解密并保存到 ${target}（${fmt(meta.size)}）\n`)
}

async function getChunkAt(origin, room, i) {
  for (;;) {
    const r = await fetch(`${origin}/api/rooms/${room}/chunk?i=${i}`)
    if (r.status === 408) continue
    if (r.status === 404) throw new Error('链接无效或已过期')
    if (r.status === 410) throw new Error('链接已被使用、过期，或发送方中断')
    if (!r.ok) throw new Error('拉取分片失败 ' + r.status)
    return Buffer.from(await r.arrayBuffer())
  }
}

// ---------- main ----------
try {
  if (cmd === 'send' && pos[1]) {
    const filePath = pos[1]
    const fh = await fsp.open(filePath, 'r')
    const size = (await fh.stat()).size
    await doSend({
      type: 'file',
      name: path.basename(filePath),
      size,
      readChunk: async (idx) => {
        const buf = Buffer.allocUnsafe(Math.min(CHUNK, size - idx * CHUNK))
        await fh.read(buf, 0, buf.length, idx * CHUNK)
        return buf
      },
    })
    await fh.close()
  } else if (cmd === 'send-text' && pos[1] !== undefined) {
    const pt = Buffer.from(pos[1], 'utf8')
    await doSend({
      type: 'text',
      size: pt.length,
      readChunk: async () => pt,
    })
  } else if (cmd === 'recv' && pos[1]) {
    await doRecv(pos[1])
  } else {
    usage()
  }
} catch (e) {
  console.error('✗ ' + e.message)
  process.exit(1)
}
