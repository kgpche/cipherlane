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
