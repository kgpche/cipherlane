#!/usr/bin/env node
// cipherlane 一致性检查（零依赖，仅 Node 内置模块）
//
// 校验三件事：
//   1) 版本号：package.json version == cipherlane-rs/Cargo.toml [package] version
//   2) SEA 内嵌资产：sea-config.json 的 assets 与 server.js 引用的静态资源一一对应
//      （server.js 路由表格式可能调整，这里按"引用的资源路径字符串"提取，兼容
//        ['/route', 'public/x.js', 'mime'] / { file: 'public/x.js' } / readAsset('public/x.js') 等写法）
//   3) 存在性：sea 资产文件、package.json scripts.test 列出的测试文件、check 脚本本身
//
// 用法：node scripts/check-consistency.mjs      失败时 exit 1，并打印具体差异。
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const errors = []
const warnings = []

const read = (rel) => readFileSync(path.join(ROOT, rel), 'utf8')
const exists = (rel) => existsSync(path.join(ROOT, rel))
const ok = (msg) => console.log(`  ✓ ${msg}`)
const fail = (msg) => { errors.push(msg); console.log(`  ✗ ${msg}`) }
const warn = (msg) => { warnings.push(msg); console.log(`  ! ${msg}`) }
const sorted = (set) => [...set].sort()

// ---------- 1) 版本号 ----------
console.log('[1/4] 版本号')
const pkg = JSON.parse(read('package.json'))
const cargoToml = read('cipherlane-rs/Cargo.toml')
// 只取 [package] 段内的 version（dependencies 里也可能有 version = "..."）
const packageSection = cargoToml.split(/^\[/m).find((s) => s.startsWith('package]')) || ''
const cargoVersion = (packageSection.match(/^\s*version\s*=\s*"([^"]+)"/m) || [])[1]
if (!cargoVersion) {
  fail('cipherlane-rs/Cargo.toml 的 [package] 段缺少 version')
} else if (pkg.version !== cargoVersion) {
  fail(`版本不一致: package.json=${pkg.version} vs Cargo.toml=${cargoVersion}`)
} else {
  ok(`package.json 与 Cargo.toml 均为 ${pkg.version}`)
}

// ---------- 2) SEA 资产 ↔ server.js 引用 ----------
console.log('[2/4] SEA 资产与 server.js 静态资源引用')
const seaConfig = JSON.parse(read('sea-config.json'))
const assets = seaConfig.assets || {}
const normalize = (p) => p.replace(/^\.\//, '').split(path.sep).join('/')

const seaAssets = new Set()
for (const [key, value] of Object.entries(assets)) {
  const asset = normalize(value)
  if (seaAssets.has(asset)) warn(`sea-config.json assets 重复引用同一文件: ${asset}（键 ${key}）`)
  seaAssets.add(asset)
}

// 从 server.js 提取所有"资源路径"字符串字面量；忽略整行注释，避免注释里的路径造成误报。
// 兼容 './public/x.js'（require）与 'public/x.js'（getAsset/路由表）两种写法。
const ASSET_LITERAL = /(['"])(?:\.\/)?((?:public|logo)\/[A-Za-z0-9][A-Za-z0-9._/-]*)\1/g
const serverAssets = new Set()
for (const line of read('server.js').split('\n')) {
  const trimmed = line.trim()
  if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue
  for (const m of line.matchAll(ASSET_LITERAL)) serverAssets.add(m[2])
}
// package.json 经 sea.getAsset/readFileSync 读取（版本号），同样必须是内嵌资产
if (/(['"])package\.json\1/.test(read('server.js'))) serverAssets.add('package.json')

if (serverAssets.size === 0) {
  fail('无法从 server.js 解析出任何静态资源引用（路由表格式可能已变更，请更新本脚本的解析规则）')
} else {
  const missingInSea = sorted(serverAssets).filter((p) => !seaAssets.has(p))
  const unusedInSea = sorted(seaAssets).filter((p) => !serverAssets.has(p))
  if (missingInSea.length) fail(`sea-config.json 缺少 server.js 引用的资产: ${missingInSea.join(', ')}`)
  if (unusedInSea.length) {
    fail(`sea-config.json 含 server.js 未引用的资产（冗余或路径已改）: ${unusedInSea.join(', ')}`)
  }
  if (!missingInSea.length && !unusedInSea.length) {
    ok(`sea-config.json 与 server.js 引用一一对应（${seaAssets.size} 个资产）`)
  }
}

// ---------- 3) 资产文件 / 测试文件存在 ----------
console.log('[3/4] 资产文件存在')
const missingAssets = sorted(seaAssets).filter((p) => !exists(p))
if (missingAssets.length) fail(`资产文件不存在: ${missingAssets.join(', ')}`)
else if (seaAssets.size) ok(`${seaAssets.size} 个 SEA 资产文件均存在`)

console.log('[4/4] 测试脚本与测试文件')
const testCmd = pkg.scripts?.test || ''
if (!testCmd) fail('package.json 缺少 scripts.test')
const listed = [...testCmd.matchAll(/node\s+(test\/[A-Za-z0-9._/-]+\.test\.mjs)/g)].map((m) => m[1])
if (!listed.length) fail('package.json scripts.test 中未解析到任何测试文件')
const uniqListed = [...new Set(listed)]
const missingTests = uniqListed.filter((p) => !exists(p))
if (missingTests.length) fail(`scripts.test 列出的测试文件不存在: ${missingTests.join(', ')}`)
if (!missingTests.length && uniqListed.length) ok(`scripts.test 的 ${uniqListed.length} 个测试文件均存在`)

// 磁盘上存在但未纳入 test 链的测试文件（只告警：避免本轮并行改动误伤）
const onDisk = readdirSync(path.join(ROOT, 'test'))
  .filter((f) => /\.test\.mjs$/.test(f))
  .map((f) => `test/${f}`)
const unlisted = onDisk.filter((p) => !testCmd.includes(p))
if (unlisted.length) warn(`test/ 下存在未纳入 scripts.test 的测试文件: ${unlisted.join(', ')}`)

// check 脚本本身的注册方式（便于 npm run check / 前置校验）
if (pkg.scripts?.check !== 'node scripts/check-consistency.mjs') {
  fail('package.json scripts.check 应为 "node scripts/check-consistency.mjs"')
}
if (!testCmd.startsWith('node scripts/check-consistency.mjs')) {
  fail('package.json scripts.test 应以 node scripts/check-consistency.mjs 前置')
}

// ---------- 汇总 ----------
console.log('')
if (errors.length) {
  console.error(`✗ 一致性检查失败：${errors.length} 项错误`)
  for (const e of errors) console.error(`  - ${e}`)
  if (warnings.length) console.error(`  （另有 ${warnings.length} 条告警）`)
  process.exit(1)
}
console.log(`✓ 一致性检查全部通过${warnings.length ? `（${warnings.length} 条告警）` : ''}`)
