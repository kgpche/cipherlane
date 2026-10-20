// 协议层验证 —— 对唯一被测实现（Rust 服务器二进制）跑真实 HTTP 全链路：
// 设备在线/邀请/定向传输（X25519 派生密钥）、缓存/配额/加固等 v1.0 服务端能力。
//
// 注：本测试收发双方都来自 127.0.0.1，与"一个 IP 一台终端"模型形成同 IP 退化场景：
//     后注册者轮换设备条目，先注册者需重新注册拿新 secret —— 测试顺带覆盖该路径。
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
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

// v1.0 只测 Rust 二进制（Node 服务端已退出产品）。可用 CIPHERLANE_SERVER_BIN 覆盖路径。
const SERVER_BIN = process.env.CIPHERLANE_SERVER_BIN || path.join(ROOT, 'cipherlane-rs/target/release/cipherlane')
if (!fs.existsSync(SERVER_BIN)) {
  console.error(`✗ 找不到被测服务器二进制：${SERVER_BIN}`)
  console.error('  先构建：export CARGO_HOME=$PWD/build/cargo-home && cargo build --release --manifest-path cipherlane-rs/Cargo.toml')
  console.error('  或设置 CIPHERLANE_SERVER_BIN=<path> 指定二进制。')
  process.exit(1)
}

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

// fetch 不能自定义 Host/Origin：用原始 http.request 验证 Host/Origin 闸门
function rawRequest(pathname, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: IP, port: PORT, path: pathname, method, headers }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }))
    })
    req.on('error', reject)
    if (body) req.write(body)
    req.end()
  })
}

// 独立起一个临时 server（随机端口、仅回环）：配额/更新等测试用，
// 避免把测试专用 env 常驻到主 server 上；被测二进制与主 server 相同。
async function startTestServer(extraEnv = {}) {
  const port = 20000 + Math.floor(Math.random() * 20000)
  const child = spawn(SERVER_BIN, [], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', ...extraEnv },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let logs = ''
  child.stdout.on('data', (d) => { logs += d })
  child.stderr.on('data', (d) => { logs += d })
  const base = `http://127.0.0.1:${port}`
  const t0 = Date.now()
  for (;;) {
    if (Date.now() - t0 > 8000) {
      child.kill('SIGKILL')
      throw new Error('测试服务器未能在 8s 内启动:\n' + logs)
    }
    try { await fetch(base + '/'); return { child, base, port, logs: () => logs } } catch { await sleep(100) }
  }
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
  // ---------- 启动被测服务器（Rust 二进制，唯一实现） ----------
  // /api/update 的计数上游：/new 返回 9.9.9（较新）、/old 返回 0.0.1（较旧）
  let updateHits = 0
  const updateUpstream = http.createServer((req, res) => {
    updateHits++
    res.writeHead(200, { 'Content-Type': 'text/plain' })
    res.end(req.url === '/old' ? '0.0.1\n' : '9.9.9\n')
  })
  await new Promise((r) => updateUpstream.listen(0, '127.0.0.1', r))
  const UPDATE_BASE = `http://127.0.0.1:${updateUpstream.address().port}`
  const UPDATE_URL = UPDATE_BASE + '/new'
  const OLD_UPDATE_URL = UPDATE_BASE + '/old'

  const serverEnv = { ...process.env, PORT: String(PORT), CIPHERLANE_UPDATE_URL: UPDATE_URL }
  const child = spawn(SERVER_BIN, [], { cwd: ROOT, env: serverEnv, stdio: ['ignore', 'pipe', 'pipe'] })
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

    // ---------- 幂等重投：X-Chunk-Seq（无头旧语义 / duplicate / 乱序 / 非法 / 429 后同 seq 重投） ----------
    {
      const mkRoom = async () => (await jfetch('/api/rooms', { method: 'POST' })).json
      const postSeq = (r, seq, body) => jfetch(`/api/rooms/${r.room}/chunk`, {
        method: 'POST',
        headers: { 'X-Room-Token': r.token, ...(seq === undefined ? {} : { 'X-Chunk-Seq': String(seq) }) },
        body,
      })
      // 1) 旧客户端不带 X-Chunk-Seq 头：保持旧语义
      let ir = await mkRoom()
      let x = await postSeq(ir, undefined, Buffer.from('legacy-no-seq'))
      assert.strictEqual(x.status, 200)
      assert.strictEqual(x.json.index, 0)
      assert.strictEqual((await jfetch(`/api/rooms/${ir.room}/state`)).json.posted, 1)
      // 2) 同 seq 重投：duplicate，posted/分片数不变，零记账
      x = await postSeq(ir, 1, Buffer.from('seq-one'))
      assert.strictEqual(x.status, 200)
      assert.strictEqual(x.json.index, 1)
      const dup = await postSeq(ir, 1, Buffer.from('seq-one'))
      assert.strictEqual(dup.status, 200)
      assert.strictEqual(dup.json.duplicate, true)
      assert.strictEqual(dup.json.index, 1)
      assert.strictEqual((await jfetch(`/api/rooms/${ir.room}/state`)).json.posted, 2, '重复包不应推进 posted')
      const dup0 = await postSeq(ir, 0, Buffer.from('legacy-no-seq'))
      assert.strictEqual(dup0.json.duplicate, true)
      assert.strictEqual((await jfetch(`/api/rooms/${ir.room}/state`)).json.posted, 2)
      // 3) 跳号：posted=0 时直接 seq=1 → 409 out-of-order，posted 不动
      const oor = await mkRoom()
      x = await postSeq(oor, 1, Buffer.from('skip-zero'))
      assert.strictEqual(x.status, 409)
      assert.strictEqual(x.json.error, 'out-of-order')
      assert.strictEqual(x.json.posted, 0)
      assert.strictEqual((await jfetch(`/api/rooms/${oor.room}/state`)).json.posted, 0)
      // 4) 非法 seq → 400 bad-seq（用原始 http 请求，避免 fetch 对头值做规范化）
      const rawSeq = async (val) => {
        const raw = await rawRequest(`/api/rooms/${oor.room}/chunk`, {
          method: 'POST', headers: { 'X-Room-Token': oor.token, 'X-Chunk-Seq': val }, body: Buffer.from('bad'),
        })
        return { status: raw.status, json: JSON.parse(raw.body.toString('utf8') || '{}') }
      }
      for (const bad of ['x', '-1', '1.5', '1e2', '9007199254740993']) {
        x = await rawSeq(bad)
        assert.strictEqual(x.status, 400, `非法 seq ${JSON.stringify(bad)} 应 400`)
        assert.strictEqual(x.json.error, 'bad-seq')
      }
      // 5) 背压 429 后用同 seq 重投成功：64 片窗口投满 → 第 65 片 429（posted 不推进）；
      //    经典模式消费一片腾出预算 → 同 seq 重投 200，再次重投 duplicate
      const br = await mkRoom()
      for (let i = 0; i < 64; i++) {
        x = await postSeq(br, i, Buffer.from('c' + i))
        assert.strictEqual(x.status, 200, `第 ${i} 片应入库`)
      }
      const full = await postSeq(br, 64, Buffer.from('c64'))
      assert.strictEqual(full.status, 429, '背压窗口满后应 429')
      assert.strictEqual((await jfetch(`/api/rooms/${br.room}/state`)).json.posted, 64, '429 不得推进 posted')
      const got0 = await fetch(`${S}/api/rooms/${br.room}/chunk?i=0`)
      assert.strictEqual(got0.status, 200)
      await got0.arrayBuffer()
      const retry = await postSeq(br, 64, Buffer.from('c64'))
      assert.strictEqual(retry.status, 200, '消费一片后同 seq 重投应成功')
      assert.strictEqual(retry.json.index, 64)
      const retryDup = await postSeq(br, 64, Buffer.from('c64'))
      assert.strictEqual(retryDup.json.duplicate, true)
      assert.strictEqual((await jfetch(`/api/rooms/${br.room}/state`)).json.posted, 65)
      ok('幂等重投：无头旧语义 / duplicate 零记账 / 跳号 409 / 非法 400 / 429 后同 seq 重投成功')
    }

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

    // ---------- 13) 可续传模式：X-Resume 只读回放 / progress 释放与单调 / 经典兼容 ----------
    {
      r = await jfetch('/api/rooms', { method: 'POST' })
      const pr = r.json
      const k = randomBytes(32)
      const post = (body) => jfetch(`/api/rooms/${pr.room}/chunk`,
        { method: 'POST', headers: { 'X-Room-Token': pr.token }, body })
      await post(seal(k, Buffer.from('meta')))
      await post(seal(k, Buffer.from('c1')))
      await post(seal(k, Buffer.from('c2')))
      // X-Resume：同一分片可反复拉（只读回放，供刷新后的接收方重来）
      const g1 = await fetch(`${S}/api/rooms/${pr.room}/chunk?i=1`, { headers: { 'X-Resume': '1' } })
      const g1b = await fetch(`${S}/api/rooms/${pr.room}/chunk?i=1`, { headers: { 'X-Resume': '1' } })
      assert.strictEqual(g1.status, 200)
      assert.strictEqual(g1b.status, 200)
      assert(Buffer.from(await g1.arrayBuffer()).equals(Buffer.from(await g1b.arrayBuffer())), '只读回放应返回同一份')
      assert.strictEqual((await jfetch(`/api/rooms/${pr.room}/state`)).json.resumable, true)
      // progress：释放 through 以下 → 已释放分片再拉 410 behind；单调不回退；越界拒绝
      assert.strictEqual((await jfetch(`/api/rooms/${pr.room}/progress`,
        { method: 'POST', body: JSON.stringify({ through: 2 }) })).status, 200)
      const g1c = await fetch(`${S}/api/rooms/${pr.room}/chunk?i=1`, { headers: { 'X-Resume': '1' } })
      assert.strictEqual(g1c.status, 410, '已确认落盘的分片应被释放')
      assert.strictEqual((await jfetch(`/api/rooms/${pr.room}/progress`,
        { method: 'POST', body: JSON.stringify({ through: 1 }) })).status, 200, '滞后上报幂等')
      assert.strictEqual((await jfetch(`/api/rooms/${pr.room}/state`)).json.through, 2, '进度单调不回退')
      assert.strictEqual((await jfetch(`/api/rooms/${pr.room}/progress`,
        { method: 'POST', body: JSON.stringify({ through: 999 }) })).status, 400, '越界拒绝')
      // 经典兼容：不带头的房间保持"取走即焚"
      r = await jfetch('/api/rooms', { method: 'POST' })
      const cr = r.json
      await jfetch(`/api/rooms/${cr.room}/chunk`,
        { method: 'POST', headers: { 'X-Room-Token': cr.token }, body: seal(randomBytes(32), Buffer.from('x')) })
      const c1 = await fetch(`${S}/api/rooms/${cr.room}/chunk?i=0`)
      const c2 = await fetch(`${S}/api/rooms/${cr.room}/chunk?i=0`)
      assert(c1.status === 200 && c2.status === 410, `经典模式应取走即焚(${c1.status}/${c2.status})`)
      ok('可续传模式：只读回放 / progress 释放·单调·越界 / 经典模式不受影响')
    }

    
    // ---------- 静态资源：ETag/304（HTML 仍 no-store） ----------
      const a = await fetch(S + '/app.js')
      assert.strictEqual(a.status, 200)
      const etag = a.headers.get('etag')
      assert(etag && /^"[0-9a-f]{64}"$/.test(etag), '静态 JS 应带强 ETag: ' + etag)
      assert.strictEqual(a.headers.get('cache-control'), 'no-cache', 'JS 应回源校验（no-cache）')
      await a.arrayBuffer()
      const b = await fetch(S + '/app.js', { headers: { 'If-None-Match': etag } })
      assert.strictEqual(b.status, 304, 'ETag 命中应 304')
      assert.strictEqual(b.headers.get('etag'), etag)
      const html = await fetch(S + '/')
      assert.strictEqual(html.headers.get('cache-control'), 'no-store', 'HTML 必须保持 no-store')
      await html.text()
      ok('静态资源：JS 200+ETag/no-cache → 304；HTML 仍 no-store')

    // ---------- 413 可达：超 BODY_MAX 回 JSON 而非 ECONNRESET ----------
      const r13 = await jfetch('/api/rooms', { method: 'POST' })
      const rr13 = r13.json
      const big = await fetch(`${S}/api/rooms/${rr13.room}/chunk`, {
        method: 'POST',
        headers: { 'X-Room-Token': rr13.token },
        body: Buffer.alloc(2 * 1024 * 1024),
      })
      assert.strictEqual(big.status, 413, '超 BODY_MAX 应回 413，而不是连接重置')
      assert.strictEqual((await big.json()).error, 'bad-body')
      assert.strictEqual((await jfetch('/api/version')).status, 200, '413 后服务器应继续可用')
      ok('413 可达：>1.5MiB 分片回 413 JSON（非 ECONNRESET），服务继续可用')

    // ---------- 请求边界：?i 缺失 400 / 越序 GET 不产生不可达分片 / DEPTH=3 预取 ----------
      let rb = await jfetch('/api/rooms', { method: 'POST' })
      const br = rb.json
      const bkey = randomBytes(32)
      const bpost = (pt) => jfetch(`/api/rooms/${br.room}/chunk`,
        { method: 'POST', headers: { 'X-Room-Token': br.token }, body: seal(bkey, Buffer.from(pt)) })
      for (const pt of ['meta', 'a', 'b']) await bpost(pt)
      // 缺省/空 ?i 不能再被 Number(null)=0 静默当成 0 号分片
      assert.strictEqual((await jfetch(`/api/rooms/${br.room}/chunk`)).status, 400, '缺 ?i 应 400')
      assert.strictEqual((await fetch(`${S}/api/rooms/${br.room}/chunk?i=`)).status, 400, '空 ?i 应 400')
      // 经典模式越序 GET：先取 1 不应让 0 变成不可达垃圾
      assert.strictEqual((await fetch(`${S}/api/rooms/${br.room}/chunk?i=1`)).status, 200)
      assert.strictEqual((await fetch(`${S}/api/rooms/${br.room}/chunk?i=0`)).status, 200, '越序取 1 后仍应能取 0')
      assert.strictEqual((await fetch(`${S}/api/rooms/${br.room}/chunk?i=2`)).status, 200)
      const bst = (await jfetch(`/api/rooms/${br.room}/state`)).json
      assert.strictEqual(bst.head, 3, 'head 应在连续消费后推进到 3')
      assert.strictEqual(bst.pulled, 3)
      // 重复取已消费分片：明确 410，而不是挂到超时
      assert.strictEqual((await fetch(`${S}/api/rooms/${br.room}/chunk?i=1`)).status, 410)
      // 浏览器 DEPTH=3 并发预取（按序 0..3）不能被 head 逻辑破坏
      rb = await jfetch('/api/rooms', { method: 'POST' })
      const pr = rb.json
      for (const pt of ['meta', '0', '1', '2']) await jfetch(`/api/rooms/${pr.room}/chunk`,
        { method: 'POST', headers: { 'X-Room-Token': pr.token }, body: seal(bkey, Buffer.from(pt)) })
      const par = await Promise.all([0, 1, 2, 3].map((i) => fetch(`${S}/api/rooms/${pr.room}/chunk?i=${i}`)))
      assert.deepStrictEqual(par.map((x) => x.status), [200, 200, 200, 200], 'DEPTH=3 并发按序预取应全 200')
      assert.strictEqual((await jfetch(`/api/rooms/${pr.room}/state`)).json.head, 4)
      ok('请求边界：缺/空 ?i→400；越序 GET 不产生不可达分片；DEPTH=3 并发预取正常')

    // ---------- 房间销毁与慢速 chunk POST 竞态：410 gone，不向已销毁房间记账 ----------
    {
      const rc = await jfetch('/api/rooms', { method: 'POST' })
      const rcr = rc.json
      const payload = randomBytes(64 * 1024)
      const half = payload.length >> 1
      const race = new Promise((resolve, reject) => {
        const q = http.request({
          host: IP, port: PORT, path: `/api/rooms/${rcr.room}/chunk`, method: 'POST',
          headers: { 'X-Room-Token': rcr.token, 'Content-Length': payload.length },
        }, (res) => {
          const chunks = []
          res.on('data', (c) => chunks.push(c))
          res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }))
        })
        q.on('error', reject)
        q.write(payload.subarray(0, half)) // 服务器此刻阻塞在 readBody
        setTimeout(async () => {
          try {
            const del = await jfetch(`/api/rooms/${rcr.room}`, { method: 'DELETE', headers: { 'X-Room-Token': rcr.token } })
            assert.strictEqual(del.status, 200)
            q.end(payload.subarray(half)) // body 读完时必须命中"房间已销毁"
          } catch (e) { reject(e) }
        }, 500)
      })
      const got = await race
      assert.strictEqual(got.status, 410, `房间销毁后完成投递应 410 gone，实际 ${got.status}`)
      assert.strictEqual(JSON.parse(got.body.toString('utf8') || '{}').error, 'gone')
      // 顺序 DELETE 之后再投递：路由层已无此房间 → 404（与 Rust 版一致；竞态路径才是 410）
      const sequential = await rawRequest(`/api/rooms/${rcr.room}/chunk`, {
        method: 'POST', headers: { 'X-Room-Token': rcr.token }, body: Buffer.from('x'),
      })
      assert.strictEqual(sequential.status, 404)
      // 服务器仍健康、记账未写坏：还能继续建房
      assert.strictEqual((await jfetch('/api/rooms', { method: 'POST' })).status, 200)
      ok('竞态：慢速 chunk POST 期间房间被 DELETE → 410 gone（不写已销毁房间）')
    }

    // ---------- Host/Origin 闸门：防 DNS rebinding / 跨站 CSRF ----------
      // 域名 Host（rebinding 前提）→ /api/* 403；IP 字面量 Host 正常
      assert.strictEqual((await rawRequest('/api/devices', { headers: { Host: 'evil.example' } })).status, 403)
      assert.strictEqual((await rawRequest('/api/devices', { headers: { Host: `127.0.0.1:${PORT}` } })).status, 200)
      // 静态页不受 Host/Origin 限制（自定义域名不影响页面本身）
      assert.strictEqual((await rawRequest('/', { headers: { Host: 'evil.example' } })).status, 200)
      // 跨站 Origin 的 adopt 必须 403（网页 CSRF 不能设停机令牌）；同源放行
      const evilAdopt = await rawRequest('/api/adopt', {
        method: 'POST',
        headers: { Host: `127.0.0.1:${PORT}`, Origin: 'https://evil.example', 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: 'z'.repeat(24) }),
      })
      assert.strictEqual(evilAdopt.status, 403, '跨站 Origin 的 adopt 应 403')
      assert.strictEqual((await rawRequest('/api/version', { headers: { Origin: `http://127.0.0.1:${PORT}` } })).status, 200)
      ok('Host/Origin：域名 Host 403 / IP Host 200 / 跨站 Origin 403 / 同源放行 / 静态页不受限')

    // ---------- /api/update：上游只请求一次（缓存 + in-flight 去重）+ 语义化 newer ----------
      const hits0 = updateHits
      const [u1, u2] = await Promise.all([jfetch('/api/update'), jfetch('/api/update')])
      assert.strictEqual(u1.status, 200)
      assert.strictEqual(u1.json.latest, '9.9.9')
      assert.strictEqual(u1.json.newer, true, '9.9.9 应判定为更新')
      assert.strictEqual(u1.json.source, UPDATE_URL)
      assert.deepStrictEqual(u2.json, u1.json, '并发调用的结果应一致')
      assert.strictEqual(updateHits - hits0, 1, '并发两次 /api/update 只应命中上游一次')
      const u3 = await jfetch('/api/update')
      assert.deepStrictEqual(u3.json, u1.json, '缓存命中结果应一致')
      assert.strictEqual(updateHits - hits0, 1, '5min 缓存期内不应再请求上游')
      // 旧版本不得判定为 newer（旧实现 latest !== VERSION 会误报）
      const srv = await startTestServer({ CIPHERLANE_UPDATE_URL: OLD_UPDATE_URL })
      try {
        const old = await (await fetch(srv.base + '/api/update')).json()
        assert.strictEqual(old.latest, '0.0.1')
        assert.strictEqual(old.newer, false, '0.0.1 不应判定为更新（语义化比较）')
      } finally {
        srv.child.kill('SIGINT')
      }
      ok('/api/update：并发/缓存只请求上游一次、semver newer 正确、旧版本不误报')

    // ---------- per-IP 配额：独立低阈值 server（CIPHERLANE_TEST_LIMITS=1 → 4 房 / 2MB） ----------
      const q = await startTestServer({ CIPHERLANE_TEST_LIMITS: '1', CIPHERLANE_UPDATE_URL: 'file:///etc/hostname' })
      try {
        const qrooms = []
        for (let i = 0; i < 4; i++) {
          const rr = await fetch(q.base + '/api/rooms', { method: 'POST' })
          assert.strictEqual(rr.status, 200, '前 4 个房间应成功')
          qrooms.push(await rr.json())
        }
        const over = await fetch(q.base + '/api/rooms', { method: 'POST' })
        assert.strictEqual(over.status, 429, '第 5 个房间应 429')
        assert.strictEqual((await over.json()).error, 'ip-quota')
        const qpost = async (r, buf) => {
          const res = await fetch(`${q.base}/api/rooms/${r.room}/chunk`, {
            method: 'POST', headers: { 'X-Room-Token': r.token }, body: buf,
          })
          return { status: res.status, json: await res.json().catch(() => ({})) }
        }
        assert.strictEqual((await qpost(qrooms[0], Buffer.alloc(1024 * 1024))).status, 200)
        assert.strictEqual((await qpost(qrooms[0], Buffer.alloc(1024 * 1024))).status, 200)
        const bq = await qpost(qrooms[0], Buffer.alloc(1024 * 1024))
        assert.strictEqual(bq.status, 429, '单 IP 2MB 字节配额：第 3MiB 应 429')
        assert.strictEqual(bq.json.error, 'backpressure')
        // 自清理：房间全删后配额回落，再建房应成功（速率 120/min 不受影响）
        for (const rr of qrooms) {
          const d = await fetch(`${q.base}/api/rooms/${rr.room}`, { method: 'DELETE', headers: { 'X-Room-Token': rr.token } })
          assert.strictEqual(d.status, 200)
        }
        const freshRes = await fetch(q.base + '/api/rooms', { method: 'POST' })
        assert.strictEqual(freshRes.status, 200, 'DELETE 后房间配额应回落')
        const fresh = await freshRes.json()
        // destroy/take/advance 三条释放路径都必须把 ipBytes 同步减回去，否则下面会提前 429
        assert.strictEqual((await qpost(fresh, Buffer.alloc(1024 * 1024))).status, 200)
        assert.strictEqual((await fetch(`${q.base}/api/rooms/${fresh.room}/chunk?i=0`)).status, 200)
        assert.strictEqual((await qpost(fresh, Buffer.alloc(1024 * 1024))).status, 200, 'takeChunk 后 ipBytes 应已释放')
        assert.strictEqual((await fetch(`${q.base}/api/rooms/${fresh.room}/chunk?i=1`, { headers: { 'X-Resume': '1' } })).status, 200)
        const prog = await fetch(`${q.base}/api/rooms/${fresh.room}/progress`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ through: 2 }),
        })
        assert.strictEqual(prog.status, 200)
        assert.strictEqual((await qpost(fresh, Buffer.alloc(1024 * 1024))).status, 200, 'advanceThrough 后 ipBytes 应已释放')
        assert.strictEqual((await qpost(fresh, Buffer.alloc(1024 * 1024))).status, 200)
        assert.strictEqual((await qpost(fresh, Buffer.alloc(1024 * 1024))).status, 429, '重新累计到 2MB 后应再次 429')
        // 非法 update URL（file://）→ 400，错误不缓存
        const bad = await fetch(q.base + '/api/update')
        assert.strictEqual(bad.status, 400, 'file:// 更新源应 400')
        assert.strictEqual((await bad.json()).error, 'bad-update-url')
        ok('per-IP 配额：4 房上限→第 5 个 429 ip-quota / 2MB 字节上限→backpressure / destroy·take·advance 均释放 / 非法 update URL 400')
      } finally {
        q.child.kill('SIGINT')
      }

    // ---------- 建房速率：滑动 60s 内第 121 次建房 → 429 ip-quota ----------
      const rs = await startTestServer({ CIPHERLANE_TEST_LIMITS: '1' })
      try {
        for (let i = 0; i < 120; i++) {
          const c = await fetch(rs.base + '/api/rooms', { method: 'POST' })
          assert.strictEqual(c.status, 200, `第 ${i + 1} 次建房应成功`)
          const { room, token } = await c.json()
          const d = await fetch(`${rs.base}/api/rooms/${room}`, { method: 'DELETE', headers: { 'X-Room-Token': token } })
          assert.strictEqual(d.status, 200)
        }
        const over = await fetch(rs.base + '/api/rooms', { method: 'POST' })
        assert.strictEqual(over.status, 429, '第 121 次建房应 429')
        const overJson = await over.json()
        assert.strictEqual(overJson.error, 'ip-quota')
        assert(overJson.retry >= 1, '应给出 retry 秒数')
        ok('建房限流：60s 内第 121 次建房 → 429 ip-quota（滑动窗口，retry 有值）')
      } finally {
        rs.child.kill('SIGINT')
      }

    // ---------- 设备名净化：C0/C1 控制字符入库前剔除（防终端转义注入） ----------
      const kp = X25519.genKey()
      const dirty = 'evil\u001b[31m\u0000line\nname\u009b'
      const reg = await jfetch('/api/presence', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: dirty, pub: b64u(kp.pk) }),
      })
      assert.strictEqual(reg.status, 200)
      const me = (await jfetch('/api/devices')).json.devices.find((d) => d.ip === IP)
      assert(me, '设备应在线')
      assert.strictEqual(me.name, 'evil[31mlinename', '控制字符应被移除后再 trim/slice')
      assert(!/[\u0000-\u001f\u007f-\u009f]/.test(me.name), '不应残留控制字符')
      ok('设备名净化：ESC/NUL/换行/C1 被剔除，/api/devices 返回干净名称')

    // ---------- 面板端点 ----------
    {
      let r = await jfetch('/api/version')
      assert.strictEqual(r.status, 200)
      assert.ok(r.json.version && r.json.startedAt, 'version/startedAt')
      // shutdown：无令牌 403 / 错令牌 403（不真正关停，保持测试服务器存活）
      r = await jfetch('/api/shutdown', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) })
      assert.strictEqual(r.status, 403, '空令牌应 403')
      r = await jfetch('/api/shutdown', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: 'x'.repeat(24) }) })
      assert.strictEqual(r.status, 403, '错令牌应 403')
      // update：主 server 配置了计数上游，source 应如实回显（缓存命中之一致）
      r = await jfetch('/api/update')
      assert.strictEqual(r.status, 200)
      assert.strictEqual(r.json.source, UPDATE_URL)
      // panel 静态页可达
      const html = await fetch(S + '/panel')
      assert.ok(html.ok && (await html.text()).includes('控制面板'))
      ok('面板端点：version / shutdown 令牌双闸 403 / update 无源如实 / panel 页可达')
    }


    // ---------- adopt 托盘接管 ----------
    {
      // 无令牌服务：回环 adopt 成功；错令牌 400
      let r = await jfetch('/api/adopt', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: 'short' }) })
      assert.strictEqual(r.status, 400, '短令牌应 400')
      const tok = 'a'.repeat(24)
      // 注：本测试服务器无 CIPHERLANE_SHUTDOWN_TOKEN → 可接管；接管后即持令牌（顺带验证 shutdown 链路升级）
      r = await jfetch('/api/adopt', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: tok }) })
      assert.strictEqual(r.status, 200, '回环 adopt 应 200: ' + JSON.stringify(r.json))
      // 再次 adopt（已有令牌）→ 409
      r = await jfetch('/api/adopt', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: 'b'.repeat(24) }) })
      assert.strictEqual(r.status, 409, '已有管理者应 409')
      // 接管后令牌可用于 shutdown 校验链（空令牌仍 403；不真关停避免杀测试服务器）
      r = await jfetch('/api/shutdown', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) })
      assert.strictEqual(r.status, 403)
      ok('adopt：回环接管 200 / 短令牌 400 / 二次接管 409 / shutdown 空令牌仍 403')
    }

    // ---------- SIGTERM 优雅停机：退出码 0 + 停机文案 ----------
      const exited = await new Promise((resolve) => {
        const t = setTimeout(() => resolve(null), 3000)
        child.once('close', (code, signal) => { clearTimeout(t); resolve({ code, signal }) })
        child.kill('SIGTERM')
      })
      assert(exited, 'SIGTERM 后 3s 内未退出（优雅停机未生效）')
      assert.strictEqual(exited.code, 0, `SIGTERM 应退出码 0，实际 code=${exited.code} signal=${exited.signal}`)
      assert(/优雅停机/.test(logs), '应打印优雅停机文案: ' + logs.slice(-300))
      ok('SIGTERM 优雅停机：关闭监听/连接后 exit 0')

console.log(`\nprotocol: 全部 ${passed} 组通过`)
  } finally {
    child.kill('SIGINT')
    try { updateUpstream.close() } catch {}
  }
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
