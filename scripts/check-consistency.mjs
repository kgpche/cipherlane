#!/usr/bin/env node
// cipherlane v1.0 一致性检查（零依赖，仅 Node 内置模块）
//
// 校验：
//   1) 版本一致：package.json version == cipherlane-rs/Cargo.toml [package] version
//   2) Rust include_bytes! 内嵌资源 ↔ public/ 文件（存在、无遗漏、无多余；logo 仅校验存在）
//   3) Cargo.toml 声明三个 bin（server / tray / cli）且源文件存在
//   4) package.json scripts（check / build / test:cargo / test 前置）与测试文件存在
//   5) 产品构建链路不再引用已删除的 Node 实现（server.js / cli.mjs / sea-config.json / postject）
//      —— 根目录旧文件尚未删除时只告警（Lead 集成阶段删除）
//
// 用法：node scripts/check-consistency.mjs      失败时 exit 1，并打印具体差异。
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const errors = []
const warnings = []

const rel = (p) => path.relative(ROOT, p).split(path.sep).join('/')
const read = (p) => readFileSync(path.join(ROOT, p), 'utf8')
const exists = (p) => existsSync(path.join(ROOT, p))
const ok = (msg) => console.log(`  ✓ ${msg}`)
const fail = (msg) => { errors.push(msg); console.log(`  ✗ ${msg}`) }
const warn = (msg) => { warnings.push(msg); console.log(`  ! ${msg}`) }
const sorted = (it) => [...it].sort()
const diff = (a, b) => sorted([...a].filter((x) => !b.has(x)))

// ---------- 1) 版本号 ----------
console.log('[1/5] 版本号')
const pkg = JSON.parse(read('package.json'))
const cargoToml = read('cipherlane-rs/Cargo.toml')
// 只取 [package] 段（dependencies 里也有 version = "..."）
const packageSection = cargoToml.split(/^\[/m).find((s) => s.startsWith('package]')) || ''
const cargoVersion = (packageSection.match(/^\s*version\s*=\s*"([^"]+)"/m) || [])[1]
if (!cargoVersion) {
  fail('cipherlane-rs/Cargo.toml 的 [package] 段缺少 version')
} else if (pkg.version !== cargoVersion) {
  fail(`版本不一致: package.json=${pkg.version} vs Cargo.toml=${cargoVersion}`)
} else {
  ok(`package.json 与 Cargo.toml 均为 ${pkg.version}`)
}

// ---------- 2) include_bytes! ↔ public/ ----------
console.log('[2/5] Rust include_bytes! 内嵌资源')
const srcRoot = path.join(ROOT, 'cipherlane-rs/src')
const rsFiles = []
;(function walkRs(dir) {
  for (const name of readdirSync(dir)) {
    const abs = path.join(dir, name)
    if (statSync(abs).isDirectory()) walkRs(abs)
    else if (name.endsWith('.rs')) rsFiles.push(abs)
  }
})(srcRoot)

const embedded = new Set()
let includeCount = 0
for (const file of rsFiles) {
  const source = readFileSync(file, 'utf8')
  for (const m of source.matchAll(/include_bytes!\s*\(\s*"([^"]+)"\s*\)/g)) {
    includeCount++
    embedded.add(rel(path.resolve(path.dirname(file), m[1])))
  }
}
if (includeCount === 0) fail('未在 cipherlane-rs/src 中找到任何 include_bytes!（静态资源可能未内嵌）')

const missingFiles = sorted(embedded).filter((p) => !exists(p))
if (missingFiles.length) fail(`include_bytes! 引用的文件不存在: ${missingFiles.join(', ')}`)

const publicOnDisk = new Set(readdirSync(path.join(ROOT, 'public')).map((f) => `public/${f}`))
const embeddedPublic = new Set([...embedded].filter((p) => p.startsWith('public/')))
const notEmbedded = diff(publicOnDisk, embeddedPublic)
const dangling = diff(embeddedPublic, publicOnDisk)
if (notEmbedded.length) fail(`public/ 下存在未内嵌的文件（运行时不可达）: ${notEmbedded.join(', ')}`)
if (dangling.length) fail(`include_bytes! 指向 public/ 中不存在的文件: ${dangling.join(', ')}`)
if (!notEmbedded.length && !dangling.length) {
  ok(`public/ 的 ${publicOnDisk.size} 个文件全部被 include_bytes! 内嵌（共 ${includeCount} 处引用，含 logo）`)
}
if (!sorted(embedded).some((p) => p.startsWith('logo/'))) warn('未内嵌任何 logo/ 资源（页面图标可能 404）')

// ---------- 3) Cargo.toml 三个 bin ----------
console.log('[3/5] Cargo.toml 二进制声明')
const bins = {}
for (const m of cargoToml.matchAll(/\[\[bin\]\]([\s\S]*?)(?=\n\[|$)/g)) {
  const block = m[1]
  const name = (block.match(/^\s*name\s*=\s*"([^"]+)"/m) || [])[1]
  const binPath = (block.match(/^\s*path\s*=\s*"([^"]+)"/m) || [])[1]
  if (name) bins[name] = binPath
}
const REQUIRED_BINS = ['cipherlane', 'cipherlane-tray', 'cipherlane-cli']
const missingBins = REQUIRED_BINS.filter((b) => !bins[b])
if (missingBins.length) fail(`Cargo.toml 缺少 [[bin]] 声明: ${missingBins.join(', ')}`)
for (const b of REQUIRED_BINS) {
  if (bins[b] && !exists(path.posix.join('cipherlane-rs', bins[b]))) {
    fail(`bin ${b} 的源文件不存在: cipherlane-rs/${bins[b]}`)
  }
}
if (!missingBins.length) ok(`声明 ${REQUIRED_BINS.join(' / ')} 三个 bin 且源文件存在`)

// ---------- 4) package.json 脚本与测试文件 ----------
console.log('[4/5] 脚本与测试文件')
const scripts = pkg.scripts || {}
const testCmd = scripts.test || ''
if (!testCmd) fail('package.json 缺少 scripts.test')
if (!scripts.check) fail('package.json 缺少 scripts.check')
if (!scripts.build) fail('package.json 缺少 scripts.build（cargo build --release）')
if (!scripts['test:cargo']) fail('package.json 缺少 scripts["test:cargo"]')
if (testCmd && !testCmd.startsWith('node scripts/check-consistency.mjs')) {
  fail('scripts.test 应以 node scripts/check-consistency.mjs 前置')
}
const listed = [...testCmd.matchAll(/node\s+(test\/[A-Za-z0-9._/-]+\.test\.mjs)/g)].map((m) => m[1])
if (!listed.length) fail('scripts.test 中未解析到任何测试文件')
const uniqListed = [...new Set(listed)]
const missingTests = uniqListed.filter((p) => !exists(p))
if (missingTests.length) fail(`scripts.test 列出的测试文件不存在: ${missingTests.join(', ')}`)
if (!missingTests.length && uniqListed.length) ok(`scripts.test 的 ${uniqListed.length} 个测试文件均存在`)

const onDisk = readdirSync(path.join(ROOT, 'test'))
  .filter((f) => /\.test\.mjs$/.test(f))
  .map((f) => `test/${f}`)
const unlisted = onDisk.filter((p) => !testCmd.includes(p))
if (unlisted.length) warn(`test/ 下存在未纳入 scripts.test 的测试文件: ${unlisted.join(', ')}`)

// README 版本徽章（只告警：Lead 集成时统一升版）
for (const doc of ['README.md', 'README.zh-CN.md']) {
  if (!exists(doc)) continue
  const m = read(doc).match(/badge\/version-([0-9]+\.[0-9]+\.[0-9]+)-/)
  if (m && m[1] !== pkg.version) warn(`${doc} 版本徽章为 ${m[1]}，package.json 为 ${pkg.version}（集成交付时同步）`)
}

// ---------- 5) 产品构建链路不再引用 Node 实现 ----------
console.log('[5/5] 产品链路已去 Node')
const PRODUCT_FILES = [
  'build/package.sh',
  'package.json',
  '.github/workflows/ci.yml',
  '.github/workflows/release.yml',
]
const legacyRe = /sea-config\.json|postject|--experimental-sea-config|server\.js|cli\.mjs/
for (const p of PRODUCT_FILES) {
  if (!exists(p)) { fail(`产品文件缺失: ${p}`); continue }
  const lines = read(p).split('\n')
  for (const [i, line] of lines.entries()) {
    if (legacyRe.test(line)) fail(`${p}:${i + 1} 仍引用 Node 实现: ${line.trim()}`)
  }
}
for (const f of rsFiles) {
  // 只检查代码行：历史注释里提到 Node 实现（兼容性说明）不算产品引用
  const hits = readFileSync(f, 'utf8').split('\n')
    .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line) && legacyRe.test(line))
  if (hits.length) fail(`${rel(f)} 仍引用 Node 实现路径（server.js / cli.mjs / SEA 配置）`)
}
// 旧 Node 产物：集成阶段删除，暂只告警
for (const stale of ['server.js', 'cli.mjs', 'sea-config.json']) {
  if (exists(stale)) warn(`旧 Node 产物仍存在，等待集成时删除: ${stale}`)
}
if (!errors.length) ok('产品构建链路无 Node 实现引用')

// ---------- 汇总 ----------
console.log('')
if (errors.length) {
  console.error(`✗ 一致性检查失败：${errors.length} 项错误`)
  for (const e of errors) console.error(`  - ${e}`)
  if (warnings.length) console.error(`  （另有 ${warnings.length} 条告警）`)
  process.exit(1)
}
console.log(`✓ 一致性检查全部通过${warnings.length ? `（${warnings.length} 条告警）` : ''}`)
