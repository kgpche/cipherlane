// 协议层验证 —— 起真实 server：设备在线/邀请/定向传输（X25519 派生密钥）全链路
//
// 注：本测试收发双方都来自 127.0.0.1，与"一个 IP 一台终端"模型形成同 IP 退化场景：
//     后注册者轮换设备条目，先注册者需重新注册拿新 secret —— 测试顺带覆盖该路径。
import { spawn } from 'node:child_process'
import { randomBytes, createCipheriv, createDecipheriv, generateKeyPairSync, createPrivateKey, createPublicKey, diffieHellman, createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import assert from 'node:assert'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const X25519 = require('../public/x25519.js')
const SHA256 = require('../public/sha256.js')
const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.join(__dirname, '..')

const PORT = 20000 + Math.floor(Math.random() * 20000)
const S = `http://127.0.0.1:${PORT}`
const IP = '127.0.0.1'

let passed = 0
const ok = (name) => { passed++; console.log(`  ✓ ${name}`) }

// 与前端一致的 AES-GCM 封装：IV(12) || 密文 || TAG(16)
function seal(key, pt) {
  const iv = randomBytes(12)
  const c = createCipheriv('aes-256-gcm', key, iv)
  const ct = Buffer.concat([c.update(pt), c.final()])
  return Buffer.concat([iv, ct, c.getAuthTag()])
}
function open(key, packed) {
  const iv = packed.subarray(0, 12)
  const d = createDecipheriv('aes-256-gcm', key, iv)
  d.setAuthTag(packed.subarray(packed.length - 16))
  return Buffer.concat([d.update(packed.subarray(12, packed.length - 16)), d.final()])
}

// node 原生 X25519（CLI 路径）：裸密钥 ↔ KeyObject
const SPKI = Buffer.from('302a300506032b656e032100', 'hex')
const PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex')
const pubFromRaw = (raw) => createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(raw)]), format: 'der', type: 'spki' })
const privFromRaw = (raw) => createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(raw)]), format: 'der', type: 'pkcs8' })
const nodeDh = (skRaw, theirPkRaw) =>
  new Uint8Array(diffieHellman({ privateKey: privFromRaw(skRaw), publicKey: pubFromRaw(theirPkRaw) }))

const b64u = (u8) => Buffer.from(u8).toString('base64url')
const fromB64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function jfetch(pathname, opts = {}) {
  const r = await fetch(S + pathname, opts)
  return { status: r.status, json: r.ok || (r.headers.get('content-type') || '').includes('json') ? await r.json().catch(() => ({})) : null }
}

async function register(name) {
  const kp = X25519.genKey()
  const { json } = await jfetch('/api/presence', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(this?.secret ? { 'X-Device-Secret': this.secret } : {}) },
    body: JSON.stringify({ name, pub: b64u(kp.pk) }),
  })
  return { name, kp, secret: json.secret, id: json.id, ip: json.ip }
}

async function main() {
  // ---------- 启动真实服务器 ----------
  const child = spawn(process.execPath, ['server.js'], { cwd: ROOT, env: { ...process.env, PORT: String(PORT) }, stdio: ['ignore', 'pipe', 'pipe'] })
  let logs = ''
  child.stdout.on('data', (d) => { logs += d })
  child.stderr.on('data', (d) => { logs += d })
  const t0 = Date.now()
  for (;;) {
    if (Date.now() - t0 > 8000) throw new Error('服务器未能在 8s 内启动:\n' + logs)
    try { await fetch(S + '/'); break } catch { await sleep(150) }
  }

  try {
    // ---------- 1) 设备注册与轮换 ----------
    const rx = await register('接收端-测试机')       // 先注册（其 secret 随后会被发送端轮换）
    assert.strictEqual(rx.ip, IP)
    const tx = await register('发送端-测试机')       // 同 IP 后注册 → 条目轮换
    assert.notStrictEqual(tx.secret, rx.secret)

    // 旧 secret 失效 → 401
    let r = await jfetch('/api/offers', { headers: { 'X-Device-Secret': rx.secret } })
    assert.strictEqual(r.status, 401)
    // 接收端重新注册拿新 secret（pub 不变，密钥对仍是 rx.kp）
    r = await jfetch('/api/presence', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: rx.name, pub: b64u(rx.kp.pk) }),
    })
    assert.strictEqual(r.json.ip, IP)
    rx.secret = r.json.secret
    ok('设备注册 / 同 IP 轮换 / 旧 secret 失效 401 / 重注册')

    // ---------- 2) 设备列表 ----------
    r = await jfetch('/api/devices')
    assert.strictEqual(r.json.devices.length, 1)
    assert.strictEqual(r.json.devices[0].name, rx.name)
    assert.strictEqual(r.json.devices[0].pub, b64u(rx.kp.pk))
    assert.strictEqual(r.json.devices[0].ip, IP)
    ok('在线设备列表（名称 / 公钥 / IP）')

    // ---------- 3) 定向发送：建房 → 邀请（hint 加密）→ 接受 → 传输 ----------
    const fileData = randomBytes(3 * 1024 * 1024 + 12345) // 3 个分片 + 零头
    const CHUNK = 1024 * 1024

    r = await jfetch('/api/rooms', { method: 'POST' })
    const { room, token } = r.json

    // X25519：发送端纯 JS 路径 ↔ 接收端 node 原生路径，双侧派生同一房间密钥
    const sharedS = X25519.dh(tx.kp.sk, rx.kp.pk)
    const keyS = X25519.sessionKey(sharedS, tx.kp.pk, rx.kp.pk, room)
    const sharedR = nodeDh(rx.kp.sk, tx.kp.pk)
    const keyR = X25519.sessionKey(sharedR, tx.kp.pk, rx.kp.pk, room)
    assert(Buffer.from(keyS).equals(Buffer.from(keyR)), '两侧房间密钥不一致')
    assert(!Buffer.from(keyS).equals(Buffer.from(sharedS)), '房间密钥应为 KDF 输出而非原始共享')

    const hint = b64u(seal(keyS, Buffer.from(JSON.stringify({ kind: 'file', name: '机密文件.bin', size: fileData.length }))))

    // 长轮询先行挂起，验证邀请到达即被唤醒
    const pollPromise = jfetch('/api/offers', { headers: { 'X-Device-Secret': rx.secret } }).then((x) => x.json)

    r = await jfetch(`/api/rooms/${room}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Room-Token': token },
      body: JSON.stringify({ to: IP, pub: b64u(tx.kp.pk), hint }),
    })
    assert.strictEqual(r.status, 200)
    const offerId = r.json.offer

    const polled = await pollPromise
    assert.strictEqual(polled.offers.length, 1)
    const o = polled.offers[0]
    assert.strictEqual(o.id, offerId)
    assert.strictEqual(o.room, room)
    assert.strictEqual(o.pub, b64u(tx.kp.pk))
    assert.strictEqual(o.from.name, rx.name) // 同 IP 退化：fromName 即当前条目名（真实场景为发送端名）

    // 接收端在"接受前"就能解密预览（hint），服务器全程只见密文
    const preview = JSON.parse(open(keyR, Buffer.from(fromB64u(o.hint))).toString())
    assert.strictEqual(preview.name, '机密文件.bin')
    assert.strictEqual(preview.size, fileData.length)
    ok('定向邀请：建房 → X25519 双侧派生一致 → 长轮询唤醒 → hint 预览解密')

    // 接受
    r = await jfetch(`/api/offers/${offerId}/accept`, { method: 'POST', headers: { 'X-Device-Secret': rx.secret } })
    assert.strictEqual(r.status, 200)

    // 发送端看到 accepted 后再投递分片（避免背压死锁的顺序约定）
    for (let i = 0; i < 40 && (await jfetch(`/api/rooms/${room}/state`)).json.offer !== 'accepted'; i++) await sleep(50)
    assert.strictEqual((await jfetch(`/api/rooms/${room}/state`)).json.offer, 'accepted')

    // 0 号元信息 + 数据分片 + done
    const meta = { v: 1, type: 'file', name: '机密文件.bin', mime: null, size: fileData.length, count: 1 + Math.ceil(fileData.length / CHUNK) }
    await jfetch(`/api/rooms/${room}/chunk`, { method: 'POST', headers: { 'X-Room-Token': token }, body: seal(keyS, Buffer.from(JSON.stringify(meta))) })
    for (let off = 0, i = 1; off < fileData.length; off += CHUNK, i++) {
      await jfetch(`/api/rooms/${room}/chunk`, { method: 'POST', headers: { 'X-Room-Token': token }, body: seal(keyS, fileData.subarray(off, off + CHUNK)) })
    }
    await jfetch(`/api/rooms/${room}/done`, { method: 'POST', headers: { 'X-Room-Token': token } })

    // 接收端顺序拉取并解密 —— 逐字节一致
    const got = []
    for (let i = 0; i < meta.count; i++) {
      const rr = await fetch(`${S}/api/rooms/${room}/chunk?i=${i}`)
      assert.strictEqual(rr.status, 200, `chunk ${i}`)
      const pt = open(keyR, Buffer.from(await rr.arrayBuffer()))
      if (i > 0) got.push(pt)
    }
    assert(Buffer.concat(got).equals(fileData), '接收内容与原文逐字节一致')
    await jfetch(`/api/rooms/${room}/ack`, { method: 'POST' })
    await sleep(50)
    assert.strictEqual((await jfetch(`/api/rooms/${room}/state`)).json.acked, true)
    ok('定向传输全链路：接受 → 3MiB+ 密文分片 → 逐字节一致 → ack')

    // ---------- 4) 拒绝路径 ----------
    r = await jfetch('/api/rooms', { method: 'POST' })
    const room2 = r.json.room
    const key2 = X25519.sessionKey(X25519.dh(tx.kp.sk, rx.kp.pk), tx.kp.pk, rx.kp.pk, room2)
    r = await jfetch(`/api/rooms/${room2}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Room-Token': r.json.token },
      body: JSON.stringify({ to: IP, pub: b64u(tx.kp.pk), hint: b64u(seal(key2, Buffer.from('{}'))) }),
    })
    const offer2 = r.json.offer
    r = await jfetch(`/api/offers/${offer2}/reject`, { method: 'POST', headers: { 'X-Device-Secret': rx.secret } })
    assert.strictEqual(r.status, 200)
    assert.strictEqual((await jfetch(`/api/rooms/${room2}/state`)).json.offer, 'rejected')
    // 已处理的邀请不能重复处理
    r = await jfetch(`/api/offers/${offer2}/accept`, { method: 'POST', headers: { 'X-Device-Secret': rx.secret } })
    assert.strictEqual(r.status, 410)
    ok('拒绝路径：state 可见 rejected，重复处理返回 410')

    // ---------- 5) 邀请约束 ----------
    // 分片投递之后不能再挂邀请
    r = await jfetch('/api/rooms', { method: 'POST' })
    const room3 = r.json
    await jfetch(`/api/rooms/${room3.room}/chunk`, { method: 'POST', headers: { 'X-Room-Token': room3.token }, body: seal(Buffer.alloc(32), Buffer.from('x')) })
    r = await jfetch(`/api/rooms/${room3.room}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Room-Token': room3.token },
      body: JSON.stringify({ to: IP, pub: b64u(tx.kp.pk), hint }),
    })
    assert.strictEqual(r.status, 409)
    // 离线目标
    r = await jfetch('/api/rooms', { method: 'POST' })
    const room4 = r.json
    r = await jfetch(`/api/rooms/${room4.room}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Room-Token': room4.token },
      body: JSON.stringify({ to: '10.255.255.1', pub: b64u(tx.kp.pk), hint }),
    })
    assert.strictEqual(r.status, 404)
    // 非法公钥
    r = await jfetch(`/api/rooms/${room4.room}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Room-Token': room4.token },
      body: JSON.stringify({ to: IP, pub: 'not-a-pub!!', hint }),
    })
    assert.strictEqual(r.status, 400)
    // 错 token
    r = await jfetch(`/api/rooms/${room4.room}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Room-Token': 'deadbeef' },
      body: JSON.stringify({ to: IP, pub: b64u(tx.kp.pk), hint }),
    })
    assert.strictEqual(r.status, 403)
    await jfetch(`/api/rooms/${room4.room}`, { method: 'DELETE', headers: { 'X-Room-Token': room4.token } })
    ok('邀请约束：分片后 409 / 目标离线 404 / 非法公钥 400 / 错 token 403')

    // ---------- 6) 邀请数量上限 ----------
    const tokenList = []
    for (let i = 0; i < 8; i++) {
      const rr = await jfetch('/api/rooms', { method: 'POST' })
      const k = X25519.sessionKey(X25519.dh(tx.kp.sk, rx.kp.pk), tx.kp.pk, rx.kp.pk, rr.json.room)
      tokenList.push(rr.json)
      const x = await jfetch(`/api/rooms/${rr.json.room}/offer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Room-Token': rr.json.token },
        body: JSON.stringify({ to: IP, pub: b64u(tx.kp.pk), hint: b64u(seal(k, Buffer.from('{}'))) }),
      })
      assert.strictEqual(x.status, 200)
    }
    const rr = await jfetch('/api/rooms', { method: 'POST' })
    const over = await jfetch(`/api/rooms/${rr.json.room}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Room-Token': rr.json.token },
      body: JSON.stringify({ to: IP, pub: b64u(tx.kp.pk), hint }),
    })
    assert.strictEqual(over.status, 429)
    for (const t of [...tokenList, rr.json]) await jfetch(`/api/rooms/${t.room}`, { method: 'DELETE', headers: { 'X-Room-Token': t.token } })
    ok('单设备待处理邀请上限 8 → 第 9 个 429')

    // ---------- 7) 链接模式回归 ----------
    const linkKey = randomBytes(32)
    const payload = Buffer.from('cipherlane link-mode regression 🚀', 'utf8')
    r = await jfetch('/api/rooms', { method: 'POST' })
    const lr = r.json
    await jfetch(`/api/rooms/${lr.room}/chunk`, { method: 'POST', headers: { 'X-Room-Token': lr.token }, body: seal(linkKey, Buffer.from('{"v":1,"type":"text"}')) })
    await jfetch(`/api/rooms/${lr.room}/chunk`, { method: 'POST', headers: { 'X-Room-Token': lr.token }, body: seal(linkKey, payload) })
    await jfetch(`/api/rooms/${lr.room}/done`, { method: 'POST', headers: { 'X-Room-Token': lr.token } })
    const m0 = JSON.parse(open(linkKey, Buffer.from(await (await fetch(`${S}/api/rooms/${lr.room}/chunk?i=0`)).arrayBuffer())).toString())
    assert.strictEqual(m0.type, 'text')
    const p1 = open(linkKey, Buffer.from(await (await fetch(`${S}/api/rooms/${lr.room}/chunk?i=1`)).arrayBuffer()))
    assert(p1.equals(payload))
    await jfetch(`/api/rooms/${lr.room}/ack`, { method: 'POST' })
    ok('链接模式回归：随机密钥分片收发逐字节一致')

    // ---------- 8) 并发拉取同一分片：先到先得，后来者明确失败，发送方不受影响 ----------
    // 回归：曾经 notifyChunk 会唤醒全部同序号 waiter 并在第二个 takeChunk 上崩溃
    // （发送方 POST 500、后来者响应永久挂起）。
    r = await jfetch('/api/rooms', { method: 'POST' })
    const cr = r.json
    const ckey = randomBytes(32)
    const g1 = fetch(`${S}/api/rooms/${cr.room}/chunk?i=0`)
    const g2 = fetch(`${S}/api/rooms/${cr.room}/chunk?i=0`)
    await sleep(300) // 两个长轮询均已挂起为 waiter
    r = await jfetch(`/api/rooms/${cr.room}/chunk`, {
      method: 'POST', headers: { 'X-Room-Token': cr.token },
      body: seal(ckey, Buffer.from('concurrent-pull')),
    })
    assert.strictEqual(r.status, 200, '发送方 POST 不应被并发拉取拖垮')
    const [ga, gb] = await Promise.all([g1, g2])
    assert.deepStrictEqual([ga.status, gb.status].sort((x, y) => x - y), [200, 409], '一者 200 一者 409')
    const winner = ga.status === 200 ? ga : gb
    assert.strictEqual(open(ckey, Buffer.from(await winner.arrayBuffer())).toString(), 'concurrent-pull')
    const g3 = await fetch(`${S}/api/rooms/${cr.room}/chunk?i=0`) // 分片已消费 → 410
    assert.strictEqual(g3.status, 410)
    await jfetch(`/api/rooms/${cr.room}`, { method: 'DELETE', headers: { 'X-Room-Token': cr.token } })
    ok('并发拉取同一分片：先到 200 / 后来者 409 / 再来者 410 / 发送方 200')

    // ---------- 9) ack 密钥凭证：双侧构造一致、state 透出、无凭证/非法凭证为 null ----------
    {
      const akey = randomBytes(32)
      r = await jfetch('/api/rooms', { method: 'POST' })
      const ar = r.json
      // 浏览器(纯 JS sha256.js)与 CLI(node:crypto)的 proof 构造必须逐字节一致
      const label = Buffer.from('cipherlane/ack/v1|' + ar.room)
      const proofNode = createHash('sha256').update(Buffer.concat([akey, label])).digest('hex')
      const proofJs = Buffer.from(SHA256.hash(new Uint8Array(Buffer.concat([akey, label])))).toString('hex')
      assert.strictEqual(proofNode, proofJs, '双侧 proof 构造不一致')
      await jfetch(`/api/rooms/${ar.room}/ack`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proof: proofNode }),
      })
      assert.strictEqual((await jfetch(`/api/rooms/${ar.room}/state`)).json.ackProof, proofNode)
      // 无凭证 ack（旧客户端兼容）与非法凭证 → 不透出
      r = await jfetch('/api/rooms', { method: 'POST' })
      await jfetch(`/api/rooms/${r.json.room}/ack`, { method: 'POST' })
      assert.strictEqual((await jfetch(`/api/rooms/${r.json.room}/state`)).json.ackProof, null)
      r = await jfetch('/api/rooms', { method: 'POST' })
      await jfetch(`/api/rooms/${r.json.room}/ack`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proof: 'zzz-not-hex' }),
      })
      assert.strictEqual((await jfetch(`/api/rooms/${r.json.room}/state`)).json.ackProof, null)
      ok('ack 密钥凭证：双侧构造一致 / state 透出 / 无凭证与非法凭证为 null')
    }

    // ---------- 10) 默认绑定面：仅回环 + RFC1918，不暴露 tun/公网地址 ----------
    {
      // 127.0.0.1 可达已由本测试全程隐式验证；再断言横幅列出的地址全为回环/RFC1918
      // （本测试未设 HOST，走默认绑定；无多余网卡的 CI 上仅 127.0.0.1）
      const shown = [...logs.matchAll(/→\s+http:\/\/([0-9.]+):/g)].map((m) => m[1])
      assert(shown.length >= 1, '横幅未列出任何地址')
      for (const ip of shown) {
        assert(
          /^(127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip),
          `默认绑定面出现非信任网段地址: ${ip}`,
        )
      }
      ok(`默认绑定面仅回环/RFC1918（横幅 ${shown.join(', ')}）`)
    }

    // ---------- 12) 长轮询并发上限：单 IP 第 9 个挂起 GET → 429，释放后可再挂 ----------
    {
      r = await jfetch('/api/rooms', { method: 'POST' })
      const lr = r.json
      const ctl = new AbortController()
      const polls = Array.from({ length: 9 }, (_, k) => {
        const p = fetch(`${S}/api/rooms/${lr.room}/chunk?i=0&n=${k}`, { signal: ctl.signal }).then((x) => x.status)
        p.catch(() => {}) // abort 后的 AbortError 不成为 unhandledRejection
        return p
      })
      assert.strictEqual(await polls[8], 429, '第 9 个并发长轮询应 429') // 前 8 个挂起中,仅它立即返回
      ctl.abort() // 断开前 8 个 → close 释放计数
      await sleep(300)
      const ctl2 = new AbortController()
      const again = fetch(`${S}/api/rooms/${lr.room}/chunk?i=0&n=99`, { signal: ctl2.signal })
      const verdict = await Promise.race([again.then((x) => x.status), sleep(1200).then(() => 'parked')])
      assert.strictEqual(verdict, 'parked', '释放后应允许新的长轮询挂起（而不是 429）')
      ctl2.abort()
      await Promise.allSettled(polls)
      await jfetch(`/api/rooms/${lr.room}`, { method: 'DELETE', headers: { 'X-Room-Token': lr.token } })
      ok('长轮询并发上限：第 9 个 429 / 断开释放后可再挂')
    }

    console.log(`\nprotocol: 全部 ${passed} 组通过`)
  } finally {
    child.kill('SIGINT')
  }
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
