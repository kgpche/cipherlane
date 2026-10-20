// CLI 端到端 —— 起真实 Rust server，以子进程跑真实 Rust CLI（v1.0 去 Node）
//
// 覆盖:单文件链接模式、目录递归批量(含空文件/嵌套/隐藏项跳过)、多路径混合、文本、
//      协议 v2（AAD 位置绑定 / 完整性校验 / v1 回退）、TOFU 指纹与 --verify、终端注入净化。
// 另含一组「Node 独立实现 → Rust CLI」交叉互操作（KDF/hint/AAD/ackProof/指纹逐字节一致）。
// 批量 wire 格式(manifest + 顺序分片)由此测试以真实收发双方锁定。
import { spawn } from 'node:child_process'
import { randomBytes, createCipheriv, createDecipheriv, createHash, generateKeyPairSync } from 'node:crypto'
import { createRequire } from 'node:module'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import assert from 'node:assert'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.join(__dirname, '..')
// v1.0：默认被测实现 = Rust 二进制；可用环境变量指向其他构建产物
const CLI_BIN = process.env.CIPHERLANE_CLI_BIN
  || path.join(ROOT, 'cipherlane-rs/target/release/cipherlane-cli')
const SERVER_BIN = process.env.CIPHERLANE_SERVER_BIN
  || path.join(ROOT, 'cipherlane-rs/target/release/cipherlane')
if (!fs.existsSync(CLI_BIN) || !fs.existsSync(SERVER_BIN)) {
  if (!fs.existsSync(CLI_BIN)) console.error('缺少 Rust CLI 二进制: ' + CLI_BIN)
  if (!fs.existsSync(SERVER_BIN)) console.error('缺少 Rust server 二进制: ' + SERVER_BIN)
  console.error('请先执行：export CARGO_HOME=$PWD/build/cargo-home && (cd cipherlane-rs && cargo build --release)')
  process.exit(1)
}
const require = createRequire(import.meta.url)
const X25519 = require('../public/x25519.js')

const PORT = 20000 + Math.floor(Math.random() * 20000)
const S = `http://127.0.0.1:${PORT}`
let passed = 0
const ok = (name) => { passed++; console.log(`  ✓ ${name}`) }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// ---------- 独立实现的发送端（用于构造 v2 / v1 / 错位 / 截断样本） ----------
const aadOf = (room, i) => Buffer.from('cipherlane/chunk/v2|' + room + '|' + i, 'utf8')
function sealTo(key, pt, aad) {
  const iv = randomBytes(12)
  const c = createCipheriv('aes-256-gcm', key, iv)
  if (aad) c.setAAD(Buffer.from(aad))
  return Buffer.concat([iv, c.update(pt), c.final(), c.getAuthTag()])
}
function openWith(key, packed, aad) {
  packed = Buffer.from(packed)
  const d = createDecipheriv('aes-256-gcm', key, packed.subarray(0, 12))
  if (aad) d.setAAD(Buffer.from(aad))
  d.setAuthTag(packed.subarray(packed.length - 16))
  return Buffer.concat([d.update(packed.subarray(12, packed.length - 16)), d.final()])
}
const newRoom = async () => (await (await fetch(S + '/api/rooms', { method: 'POST' })).json())
const linkOf = (room, key) => `${S}/#${room}.${key.toString('base64url')}`
const roomState = async (room) => (await (await fetch(`${S}/api/rooms/${room}/state`)).json())
async function postRaw(room, token, body) {
  for (;;) {
    const r = await fetch(`${S}/api/rooms/${room}/chunk`, { method: 'POST', headers: { 'X-Room-Token': token }, body })
    if (r.status === 429) { await sleep(100); continue }
    assert(r.ok, 'post chunk ' + r.status)
    return
  }
}

function runCli(args, { timeout = 120000 } = {}) {
  const child = spawn(CLI_BIN, args, {
    cwd: ROOT, env: { ...process.env, CIPHERLANE_SERVER: S }, stdio: ['ignore', 'pipe', 'pipe'],
  })
  let out = ''
  child.stdout.on('data', (d) => { out += d })
  child.stderr.on('data', (d) => { out += d })
  // 退出监听总是挂上(后台启动的发送方稍后由调用方 await done 取结果)
  const done = new Promise((res, rej) => {
    const t = setTimeout(() => { child.kill('SIGKILL'); rej(new Error('CLI 超时:\n' + out)) }, timeout)
    child.on('exit', (c, sig) => { clearTimeout(t); res({ code: c, sig, out }) })
  })
  return { child, out: () => out, done }
}

async function waitLink(p) {
  for (let i = 0; i < 200; i++) {
    const m = /http:\/\/\S+#\S+/.exec(p.out())
    if (m) return m[0]
    await sleep(100)
  }
  throw new Error('发送方未打印链接:\n' + p.out())
}

// 源目录 → { rel: bytes } / 目标目录 → { rel: bytes }
async function tree(root) {
  const files = {}
  async function walk(dir, rel) {
    for (const e of await fsp.readdir(dir, { withFileTypes: true })) {
      const fp = path.join(dir, e.name)
      const r = rel ? `${rel}/${e.name}` : e.name
      if (e.isDirectory()) await walk(fp, r)
      else if (e.isFile()) files[r] = await fsp.readFile(fp)
    }
  }
  await walk(root, '')
  return files
}

async function main() {
  const server = spawn(SERVER_BIN, [], {
    cwd: ROOT, env: { ...process.env, PORT: String(PORT) }, stdio: ['ignore', 'ignore', 'pipe'],
  })
  const t0 = Date.now()
  for (;;) {
    if (Date.now() - t0 > 8000) throw new Error('服务器未能启动')
    try { await fetch(S + '/'); break } catch { await sleep(150) }
  }

  const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cl-cli-'))
  try {
    // ---------- 1) 单文件链接模式(真实子进程全链路) ----------
    {
      const src = path.join(TMP, 'one.bin')
      const data = randomBytes(2 * 1024 * 1024 + 777)
      fs.writeFileSync(src, data)
      const send = runCli(['send', src])
      const link = await waitLink(send)
      // 独立验证发送端协议版本：从链接解出 room/key，以 X-Resume 只读拉 0 号 meta，
      // 必须能用 v2 AAD 解开且 meta.v===2；无 AAD 解不开（证明线上确实是 v2）
      {
        const frag = link.split('#')[1]
        const room = frag.split('.')[0]
        const key = Buffer.from(frag.split('.')[1], 'base64url')
        const r0 = await fetch(`${S}/api/rooms/${room}/chunk?i=0`, { headers: { 'X-Resume': '1' } })
        assert(r0.ok, '拉取 meta 失败 ' + r0.status)
        const packed0 = Buffer.from(await r0.arrayBuffer())
        const meta = JSON.parse(openWith(key, packed0, aadOf(room, 0)).toString())
        assert.strictEqual(meta.v, 2, 'CLI 发送端 meta.v 应为 2')
        assert.throws(() => openWith(key, packed0), /unable to authenticate|bad decrypt/i,
          'v2 meta 不应能按旧无 AAD 方式解开')
      }
      const out = path.join(TMP, 'got-one.bin')
      const recv = await runCli(['recv', link, '-o', out]).done
      assert.strictEqual(recv.code, 0, `sig=${recv.sig} out=${recv.out}`)
      assert(Buffer.compare(data, fs.readFileSync(out)) === 0, '单文件字节不一致')
      const s = await send.done // 发送方应确认 ack 后退出
      assert.strictEqual(s.code, 0, s.out)
      assert(/凭证校验通过/.test(s.out), '发送方应显示凭证校验通过')
      ok('单文件链接模式:send → recv 字节一致,ack 凭证闭环；线上 meta.v=2（AAD）')
    }

    // ---------- 2) 目录递归批量:嵌套/空文件/隐藏项跳过 ----------
    {
      const dir = path.join(TMP, 'src-tree')
      fs.mkdirSync(path.join(dir, 'sub/deeper'), { recursive: true })
      fs.writeFileSync(path.join(dir, 'a.txt'), '顶层文件')
      fs.writeFileSync(path.join(dir, 'sub/b.bin'), randomBytes(1000))
      fs.writeFileSync(path.join(dir, 'sub/deeper/c 大.bin'), randomBytes(3 * 1024 * 1024))
      fs.writeFileSync(path.join(dir, 'empty.dat'), Buffer.alloc(0))
      fs.mkdirSync(path.join(dir, '.git')) // 隐藏目录应被跳过
      fs.writeFileSync(path.join(dir, '.git/config'), 'x')

      const send = runCli(['send', dir])
      const link = await waitLink(send)
      const outDir = path.join(TMP, 'got-tree')
      const recv = await runCli(['recv', link, '-o', outDir]).done
      assert.strictEqual(recv.code, 0, `sig=${recv.sig} out=${recv.out}`)

      const want = await tree(dir)
      const got = await tree(outDir)
      delete want['.git/config']
      assert.deepStrictEqual(Object.keys(got).sort(), Object.keys(want).sort(),
        `文件清单不一致:\n  got  ${Object.keys(got)}\n  want ${Object.keys(want)}`)
      for (const rel of Object.keys(want)) {
        assert(Buffer.compare(want[rel], got[rel]) === 0, `内容不一致: ${rel}`)
      }
      const s = await send.done
      assert.strictEqual(s.code, 0, s.out)
      ok('目录递归批量:嵌套/中文/空文件逐字节一致,隐藏项(.git)被跳过')
    }

    // ---------- 3) 多路径混合发送 ----------
    {
      const extra = path.join(TMP, 'extra.bin')
      fs.writeFileSync(extra, randomBytes(5000))
      const send = runCli(['send', extra, path.join(TMP, 'src-tree', 'sub')])
      const link = await waitLink(send)
      const outDir = path.join(TMP, 'got-multi')
      const recv = await runCli(['recv', link, '-o', outDir]).done
      assert.strictEqual(recv.code, 0, `sig=${recv.sig} out=${recv.out}`)
      const got = await tree(outDir)
      assert(Object.keys(got).includes('extra.bin') && Object.keys(got).includes('b.bin'),
        '应同时收到散文件与目录内容: ' + Object.keys(got))
      ok('多路径混合:文件 + 子目录同批传输')
    }

    // ---------- 4) 文本链路回归 ----------
    {
      const text = 'CLI 文本回归 ' + randomBytes(4).toString('hex')
      const send = runCli(['send-text', text])
      const link = await waitLink(send)
      const recv = await runCli(['recv', link]).done
      assert.strictEqual(recv.code, 0, `sig=${recv.sig} out=${recv.out}`)
      assert(recv.out.includes(text), '文本内容未出现在接收输出')
      ok('文本链路:send-text → recv')
    }

    // ---------- 5) 断点续传:中途 SIGKILL 接收进程 → 重跑同一链接续传完成 ----------
    {
      const src = path.join(TMP, 'resume.bin')
      const data = randomBytes(12 * 1024 * 1024 + 4321) // 13 片
      fs.writeFileSync(src, data)
      const send = runCli(['send', src])
      const link = await waitLink(send)
      const out = path.join(TMP, 'resume-out.bin')
      const part = out + '.part'
      // 第一次接收:落盘 ≥3 片后击杀
      const first = runCli(['recv', link, '-o', out])
      let killed = false
      for (let i = 0; i < 300; i++) {
        const st = await fsp.stat(part).catch(() => null)
        if (st && st.size >= 3 * 1024 * 1024) { first.child.kill('SIGKILL'); killed = true; break }
        await sleep(50)
      }
      assert(killed, '未能在传输中途击杀接收进程(阈值未达到)')
      await sleep(300)
      const stPart = await fsp.stat(part).catch(() => null)
      assert(stPart && stPart.size >= 3 * 1024 * 1024 && stPart.size < data.length, '中断后应有部分进度且未完成')
      // 重跑同一链接:从断点续传并完成
      const second = await runCli(['recv', link, '-o', out]).done
      assert.strictEqual(second.code, 0, second.out)
      assert(/续传/.test(second.out), '应提示检测到断点: ' + second.out.slice(-300))
      assert(Buffer.compare(data, fs.readFileSync(out)) === 0, '续传结果字节不一致')
      assert(!(await fsp.stat(part).catch(() => null)), '.part 完成后应已改名')
      const s = await send.done
      assert.strictEqual(s.code, 0, s.out)
      ok('断点续传:SIGKILL 中断 → .part 保留 → 重跑续传完成,字节一致')
    }

    // ---------- 6) 协议 v2：完整性校验 / v1 回退 / AAD 错位拒绝 ----------
    {
      // 6a) v2 长度篡改（meta.size 与真实数据不符）→ 完整性校验失败、不 ack、不产出文件
      {
        const created = await newRoom()
        const { room, token } = created
        const key = randomBytes(32)
        const meta = { v: 2, type: 'file', name: 'trunc.bin', mime: null, size: 100, count: 2 }
        await postRaw(room, token, sealTo(key, Buffer.from(JSON.stringify(meta)), aadOf(room, 0)))
        await postRaw(room, token, sealTo(key, randomBytes(10), aadOf(room, 1)))
        const out = path.join(TMP, 'trunc-out.bin')
        const r = await runCli(['recv', linkOf(room, key), '-o', out]).done
        assert.notStrictEqual(r.code, 0, '截断传输必须失败: ' + r.out)
        assert(/完整性校验失败/.test(r.out), '应报完整性校验失败: ' + r.out.slice(-300))
        assert(!fs.existsSync(out), '完整性校验失败不应产出目标文件')
        assert.strictEqual((await roomState(room)).acked, false, '完整性校验失败不得 ack')
        ok('v2 完整性:字节数与 meta.size 不符 → 报错、无产物、不 ack')
      }

      // 6b) v1 回退：旧发送端（无 AAD、meta.v=1）→ 新 CLI 接收端必须仍可用
      {
        const { room, token } = await newRoom()
        const key = randomBytes(32)
        const data = randomBytes(70_000)
        const meta = { v: 1, type: 'file', name: 'legacy-v1.bin', mime: null, size: data.length, count: 2 }
        await postRaw(room, token, sealTo(key, Buffer.from(JSON.stringify(meta)))) // 无 AAD
        await postRaw(room, token, sealTo(key, data)) // 无 AAD
        const out = path.join(TMP, 'legacy-v1-out.bin')
        const r = await runCli(['recv', linkOf(room, key), '-o', out]).done
        assert.strictEqual(r.code, 0, `旧发送端→新接收端应可用: ${r.out.slice(-300)}`)
        assert(Buffer.compare(data, fs.readFileSync(out)) === 0, 'v1 回退内容不一致')
        ok('v1 回退:旧无 AAD 发送端 → 新 CLI 接收端逐字节一致')
      }

      // 6c) v2 错位分片：数据分片用了错误 index 的 AAD 放在该 index → 新实现必须拒绝。
      // 正控：该密文用其"本应"的 AAD(room,0) 可解开（证明 GCM 正常，失败只因位置错位）；
      // 旧实现无 AAD、对分片位置完全盲（blind 用无 AAD 密文证明任意位置都能解）。
      {
        const { room, token } = await newRoom()
        const key = randomBytes(32)
        const meta = { v: 2, type: 'file', name: 'misplaced.bin', mime: null, size: 32, count: 2 }
        await postRaw(room, token, sealTo(key, Buffer.from(JSON.stringify(meta)), aadOf(room, 0)))
        await postRaw(room, token, sealTo(key, randomBytes(32), aadOf(room, 0))) // 应为 aadOf(room,1)
        const r0 = await fetch(`${S}/api/rooms/${room}/chunk?i=1`, { headers: { 'X-Resume': '1' } })
        const packed1 = Buffer.from(await r0.arrayBuffer())
        assert.strictEqual(openWith(key, packed1, aadOf(room, 0)).length, 32,
          '正控：错位密文用其原始 AAD 应可解开')
        assert.throws(() => openWith(key, packed1, aadOf(room, 1)), /unable to authenticate|bad decrypt/i,
          '错位密文用本位置 AAD 必须验签失败')
        const blind = sealTo(key, randomBytes(32)) // 旧发送端格式（无 AAD）
        assert.strictEqual(openWith(key, blind).length, 32,
          '旧无 AAD 实现没有位置概念：任意位置密文都能解（旧实现静默接受错位的根因）')
        const out = path.join(TMP, 'misplaced-out.bin')
        const r = await runCli(['recv', linkOf(room, key), '-o', out]).done
        assert.notStrictEqual(r.code, 0, '错位分片必须失败: ' + r.out)
        assert(/GCM|验签|auth/i.test(r.out), '错位分片应报验签失败: ' + r.out.slice(-300))
        assert.strictEqual((await roomState(room)).acked, false, '错位分片失败不得 ack')
        ok('v2 AAD 错位:接收端拒绝；旧无 AAD 实现位置盲（blind 已证）')
      }
    }

    // ---------- 定向模式：devices / listen 常驻 / --to 直发 ----------
    {
      const net = await import('node:net')
      // 127.0.0.2 伪装第二台终端:监听 127.0.0.2:PORT,以 127.0.0.2 为源地址转发到服务器
      const proxy = net.createServer((c) => {
        const u = net.connect({ host: '127.0.0.1', port: PORT, localAddress: '127.0.0.2' })
        c.pipe(u); u.pipe(c)
        c.on('error', () => u.destroy()); u.on('error', () => c.destroy())
      })
      await new Promise((r) => proxy.listen(PORT, '127.0.0.2', r))

      // 接收端:listen --yes 常驻,经代理上线
      const recvDir = path.join(TMP, 'targeted-recv')
      await fsp.mkdir(recvDir, { recursive: true })
      const listener = spawn(CLI_BIN, ['listen', '--yes', '-o', recvDir, '--name', '测试机B', '--server', `http://127.0.0.2:${PORT}`], {
        cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'],
      })
      let lout = ''
      listener.stdout.on('data', (d) => { lout += d })
      listener.stderr.on('data', (d) => { lout += d })

      // 等待 127.0.0.2 上线(经 /api/devices 轮询)
      let up = false
      for (let i = 0; i < 50 && !up; i++) {
        await sleep(200)
        try {
          const j = await (await fetch(`${S}/api/devices`)).json()
          up = j.devices.some((d) => d.ip === '127.0.0.2')
        } catch {}
      }
      assert(up, 'listen 未能上线(127.0.0.2 未出现在设备列表)')

      // devices 列表应含接收端，并显示 32hex（128bit）公钥指纹
      const dev = await runCli(['devices']).done
      assert.strictEqual(dev.code, 0, dev.out)
      assert(/测试机B/.test(dev.out) && /127\.0\.0\.2/.test(dev.out), 'devices 应列出对端: ' + dev.out)
      const ipPos = dev.out.indexOf('127.0.0.2')
      const fpM = /#([0-9a-f]{32})/.exec(dev.out.slice(ipPos))
      assert(fpM, 'devices 应显示 128bit（32 hex）指纹: ' + dev.out)
      const targetFp = fpM[1]

      // --verify：错误前缀必须拒绝发送；正确前缀放行
      const badv = await runCli(['send-text', 'should-not-send', '--to', '127.0.0.2', '--verify', 'deadbeef']).done
      assert.notStrictEqual(badv.code, 0, '错误 --verify 应拒绝发送: ' + badv.out)
      assert(/指纹不符/.test(badv.out), '应提示目标指纹不符: ' + badv.out)
      const vpayload = '指纹校验后直发 ' + Date.now()
      const vgood = await runCli(['send-text', vpayload, '--to', '127.0.0.2', '--verify', targetFp.slice(0, 16)]).done
      assert.strictEqual(vgood.code, 0, '正确 --verify 应放行: ' + vgood.out)
      assert(/指纹核对通过/.test(vgood.out), '应显示指纹核对通过: ' + vgood.out)
      let gotV = false
      for (let i = 0; i < 50 && !gotV; i++) { gotV = lout.includes(vpayload); if (!gotV) await sleep(200) }
      assert(gotV, 'listen 端应收到 --verify 放行的文本')

      // 定向发送文本(发送方经默认源地址 127.0.0.1)
      const payload = '定向直发自动化验证:CLI send-text --to ' + Date.now()
      const sender = runCli(['send-text', payload, '--to', '127.0.0.2', '--name', '测试机A'])
      const sent = await sender.done
      assert.strictEqual(sent.code, 0, sent.out)
      assert(/已完整接收/.test(sent.out), '发送方应确认完整接收: ' + sent.out.slice(-200))
      // 监听端应解密打印同一文本
      let gotText = false
      for (let i = 0; i < 50 && !gotText; i++) { gotText = lout.includes(payload); if (!gotText) await sleep(200) }
      assert(gotText, 'listen 端应收到并解密文本,实际:\n' + lout.slice(-400))

      // 定向发送文件并校验落盘
      const fdata = randomBytes(1.5 * 1024 * 1024 + 99)
      const tsrc = path.join(TMP, 'targeted-src.bin')
      await fsp.writeFile(tsrc, fdata)
      const sender2 = runCli(['send', tsrc, '--to', '127.0.0.2', '--name', '测试机A'])
      const sent2 = await sender2.done
      assert.strictEqual(sent2.code, 0, sent2.out)
      const saved = path.join(recvDir, 'targeted-src.bin')
      let savedOk = false
      for (let i = 0; i < 50 && !savedOk; i++) { savedOk = fs.existsSync(saved); if (!savedOk) await sleep(200) }
      await sleep(300) // 等待写完
      assert(savedOk && Buffer.compare(fdata, fs.readFileSync(saved)) === 0, '定向文件应逐字节落盘')

      // ---------- 8) 跨实现一致性：Node 独立实现 → Rust CLI listen 直发 ----------
      // 用 Node 侧 X25519/roomKey/AES-GCM/ackProof 构造完整直发流，由 Rust CLI 解密/展示/ack，
      // 锁定 KDF、hint、协议 v2 AAD、指纹、ackProof 五项跨实现逐字节一致。
      {
        const devs = await (await fetch(S + '/api/devices')).json()
        const rustDev = devs.devices.find((d) => d.ip === '127.0.0.2')
        assert(rustDev, 'Rust listener 应在线')
        const rustPub = Buffer.from(rustDev.pub, 'base64url')
        assert.strictEqual(rustPub.length, 32, 'Rust 公钥应为 32B')

        // 指纹：Rust devices 输出 vs Node SHA256(原始公钥) 前 16B
        const wantFp = createHash('sha256').update(rustPub).digest().subarray(0, 16).toString('hex')
        const devOut = (await runCli(['devices']).done).out
        const at = devOut.indexOf('127.0.0.2')
        assert(at >= 0, 'devices 应含 Rust listener')
        assert(devOut.slice(at).includes('#' + wantFp), 'Rust 指纹应与 Node 计算一致: ' + devOut)

        // Node 身份 + roomKey（与 public/x25519.js 同源，Rust 必须逐字节一致）
        const nodeSeed = randomBytes(32)
        const nodePub = new Uint8Array(X25519.publicFromSecret(new Uint8Array(nodeSeed)))
        const created = await newRoom()
        const room = created.room, token = created.token
        const shared = X25519.dh(new Uint8Array(nodeSeed), new Uint8Array(rustPub))
        const key = Buffer.from(X25519.sessionKey(shared, nodePub, new Uint8Array(rustPub), room))
        const payload = 'Node→Rust 跨实现直发 ' + Date.now()
        const pt = Buffer.from(payload, 'utf8')
        const hint = sealTo(key, Buffer.from(JSON.stringify({ kind: 'text', size: pt.length })))
        const or = await fetch(`${S}/api/rooms/${room}/offer`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Room-Token': token },
          body: JSON.stringify({ to: '127.0.0.2', pub: Buffer.from(nodePub).toString('base64url'), hint: hint.toString('base64url') }),
        })
        assert(or.ok, '投递 Node 构造的邀请失败 ' + or.status)
        const meta = { v: 2, type: 'text', name: null, mime: null, size: pt.length, count: 2 }
        await postRaw(room, token, sealTo(key, Buffer.from(JSON.stringify(meta)), aadOf(room, 0)))
        await postRaw(room, token, sealTo(key, pt, aadOf(room, 1)))

        let gotText = false
        for (let i = 0; i < 100 && !gotText; i++) {
          gotText = lout.includes(payload)
          if (!gotText) await sleep(100)
        }
        assert(gotText, 'Rust listen 应解密 Node 构造的直发文本,实际:\n' + lout.slice(-500))
        assert(lout.includes('#' + createHash('sha256').update(Buffer.from(nodePub)).digest().subarray(0, 16).toString('hex')),
          'Rust listen 应打印 Node 发送方指纹')
        let st = null
        for (let i = 0; i < 100; i++) {
          st = await roomState(room)
          if (st.acked) break
          await sleep(100)
        }
        assert(st && st.acked, 'Rust listen 应 ack')
        const wantAck = createHash('sha256')
          .update(Buffer.concat([key, Buffer.from('cipherlane/ack/v1|' + room)]))
          .digest('hex')
        assert.strictEqual(st.ackProof, wantAck, 'Rust ackProof 必须与 Node SHA256(key‖label‖room) 一致')
        ok('跨实现一致：Node 构造的 X25519/roomKey/hint/v2 AAD/ackProof → Rust CLI 解密并 ack')
      }

      listener.kill('SIGINT')
      proxy.close()
      ok('定向模式:devices 列表 / listen --yes 常驻 / send+send-text --to 双向确认+落盘一致')
    }

    // ---------- 7) 终端注入净化：远端可控字符串中的 ANSI/控制字符不得原样输出 ----------
    {
      // 7a) 设备名（服务端注册 + CLI devices 展示，双重净化；此处断言最终输出无控制字符）
      const { publicKey } = generateKeyPairSync('x25519')
      const rawPub = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }).subarray(12))
      const evil = 'evil\x1b[31mPWNED\x1b[0m\x07name'
      const pr = await fetch(S + '/api/presence', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: evil, pub: Buffer.from(rawPub).toString('base64url') }),
      })
      assert(pr.ok, 'presence 注册失败 ' + pr.status)
      const out = (await runCli(['devices']).done).out
      assert(!out.includes('\x1b[31m') && !out.includes('\x07'),
        '设备名中的控制字符未被过滤: ' + JSON.stringify(out))

      // 7b) 文件名（明文入 meta，由 CLI 接收端打印）→ CLI 的 clean() 必须剥掉 ANSI/BEL
      const { room, token } = await newRoom()
      const key = randomBytes(32)
      const name = 'evil\x1b[31mPWNED\x1b[0m\x07.txt'
      const data = Buffer.from('AAAA')
      const meta = { v: 2, type: 'batch', files: [{ name, size: data.length, count: 1 }], count: 2, size: data.length }
      await postRaw(room, token, sealTo(key, Buffer.from(JSON.stringify(meta)), aadOf(room, 0)))
      await postRaw(room, token, sealTo(key, data, aadOf(room, 1)))
      const dir = path.join(TMP, 'clean-recv')
      const r = await runCli(['recv', linkOf(room, key), '-o', dir]).done
      assert.strictEqual(r.code, 0, r.out)
      assert(!r.out.includes('\x1b'), 'CLI 输出不应含 ESC: ' + JSON.stringify(r.out))
      assert(!r.out.includes('\x07'), 'CLI 输出不应含 BEL: ' + JSON.stringify(r.out))
      assert(r.out.includes('evilPWNED'), '净化后应保留可见文本: ' + JSON.stringify(r.out))
      ok('终端注入净化:设备名/文件名中的 ANSI/BEL 控制字符被过滤')
    }
    console.log(`\ncli: 全部 ${passed} 组通过`)
  } finally {
    server.kill('SIGINT')
    try { fs.rmSync(TMP, { recursive: true, force: true }) } catch {}
  }
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
