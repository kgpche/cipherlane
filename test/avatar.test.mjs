// avatar.js 验证 —— 确定性 / 差异性 / 色板不变量（与页面渲染同源）
import { createRequire } from 'node:module'
import assert from 'node:assert'
const require = createRequire(import.meta.url)
const Avatar = require('../public/avatar.js')
const { CHROMA, BG_POOL } = Avatar._test

let passed = 0
const ok = (name) => { passed++; console.log(`  ✓ ${name}`) }

// 1) 确定性：同 IP 两次生成逐字符一致；同 IP 不同尺寸仅尺寸属性不同
{
  const a = Avatar.svg('192.168.1.117', 44)
  const b = Avatar.svg('192.168.1.117', 44)
  const c = Avatar.svg('192.168.1.117', 88)
  assert.strictEqual(a, b, '同 IP 同尺寸应完全一致')
  assert.ok(c.includes('width="88"') && a.includes('width="44"'))
  assert.ok(c.replace('width="88" height="88"', 'width="44" height="44"') === a, '仅尺寸不同')
  ok('同一 IP 永远生成同一头像（尺寸是唯一变量）')
}

// 2) 差异性：真实网段内不同 IP 的头像彼此可区分
{
  const seeds = []
  for (let i = 100; i < 124; i++) seeds.push('192.168.1.' + i)
  const outs = new Set(seeds.map((s) => Avatar.svg(s, 44)))
  assert.strictEqual(outs.size, seeds.length, '不同 IP 应产生不同头像')
  ok(`24 个相邻 IP 的头像互不相同（${outs.size}/${seeds.length}）`)
}

// 3) 结构与色板不变量：底色来自色板、三层形状色来自彩色系且相邻层不同
{
  const hexes = new Set(CHROMA.map((c) => c.hex).concat(BG_POOL.map((c) => c.hex)))
  for (let i = 0; i < 200; i++) {
    const ip = `${1 + (i % 223)}.${i % 255}.${(i * 7) % 255}.${(i * 13) % 255}`
    const svg = Avatar.svg(ip, 44)
    const fills = [...svg.matchAll(/fill="(#[0-9A-Fa-f]{6})"/g)].map((m) => m[1].toUpperCase())
    assert.ok(fills.length >= 4, `至少底色+3 层（${ip}）`)
    for (const f of fills) assert.ok(hexes.has(f), `颜色必须在色板内：${f}`)
    assert.strictEqual(new Set(fills.slice(1, 4)).size, 3, '三层形状色互不相同')
  }
  ok('200 个随机 IP：全部颜色来自 Material 色板，三层形状色互不相同')
}

// 4) 主形状与底色必有明度差（防糊边），形状色不含灰黑系
{
  const chromaHexes = new Set(CHROMA.map((c) => c.hex))
  for (let i = 0; i < 100; i++) {
    const ip = `10.${i}.${i * 3 % 255}.${i * 11 % 255}`
    const svg = Avatar.svg(ip, 44)
    const fills = [...svg.matchAll(/fill="(#[0-9A-Fa-f]{6})"/g)].map((m) => m[1].toUpperCase())
    const bgL = BG_POOL.find((c) => c.hex === fills[0]).L
    const c1L = CHROMA.find((c) => c.hex === fills[1]).L
    assert.ok(Math.abs(bgL - c1L) >= 0.14, `主形状与底色明度差不足（${ip}）`)
    for (const f of fills.slice(1)) assert.ok(chromaHexes.has(f), `形状含非彩色系颜色（${f}）`)
  }
  ok('100 个随机 IP：主形状/底色明度差 ≥0.14，形状色全为彩色系')
}

// 5) 占位符：中性灰、结构稳定、与任何 IP 头像不同
{
  const p1 = Avatar.placeholder(36)
  const p2 = Avatar.placeholder(36)
  assert.strictEqual(p1, p2)
  assert.ok(p1.includes('#3c4658') && p1.includes('circle'))
  assert.ok(!p1.includes('translate'), '占位无随机层')
  for (let i = 0; i < 50; i++) {
    assert.notStrictEqual(Avatar.svg(`172.16.${i}.${i * 5 % 255}`, 36), p1)
  }
  ok('中性占位：恒定、无随机层、不与任何 IP 头像撞形')
}

console.log(`\navatar: 全部 ${passed} 组通过`)
