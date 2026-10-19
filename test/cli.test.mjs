// CLI 端到端 —— 起真实 server,以子进程跑真实 cli.mjs 收发
//
// 覆盖:单文件链接模式、目录递归批量(含空文件/嵌套/隐藏项跳过)、多路径混合、文本。
// 批量 wire 格式(manifest + 顺序分片)由此测试以真实收发双方锁定。
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import assert from 'node:assert'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.join(__dirname, '..')
const CLI = path.join(ROOT, 'cli.mjs')

const PORT = 20000 + Math.floor(Math.random() * 20000)
const S = `http://127.0.0.1:${PORT}`
let passed = 0
const ok = (name) => { passed++; console.log(`  ✓ ${name}`) }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function runCli(args, { timeout = 120000 } = {}) {
  const child = spawn(process.execPath, [CLI, ...args], {
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
  const server = spawn(process.execPath, ['server.js'], {
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
      const out = path.join(TMP, 'got-one.bin')
      const recv = await runCli(['recv', link, '-o', out]).done
      assert.strictEqual(recv.code, 0, `sig=${recv.sig} out=${recv.out}`)
      assert(Buffer.compare(data, fs.readFileSync(out)) === 0, '单文件字节不一致')
      const s = await send.done // 发送方应确认 ack 后退出
      assert.strictEqual(s.code, 0, s.out)
      assert(/凭证校验通过/.test(s.out), '发送方应显示凭证校验通过')
      ok('单文件链接模式:send → recv 字节一致,ack 凭证闭环')
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
      const listener = spawn(process.execPath, [CLI, 'listen', '--yes', '-o', recvDir, '--name', '测试机B', '--server', `http://127.0.0.2:${PORT}`], {
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

      // devices 列表应含接收端
      const dev = await runCli(['devices']).done
      assert.strictEqual(dev.code, 0, dev.out)
      assert(/测试机B/.test(dev.out) && /127\.0\.0\.2/.test(dev.out), 'devices 应列出对端: ' + dev.out)

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

      listener.kill('SIGINT')
      proxy.close()
      ok('定向模式:devices 列表 / listen --yes 常驻 / send+send-text --to 双向确认+落盘一致')
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
