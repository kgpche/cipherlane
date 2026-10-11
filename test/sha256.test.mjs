// sha256.js 验证 —— FIPS 180-4 标准向量 + 与 node:crypto 逐字节比对
import { createHash, randomBytes } from 'node:crypto'
import { createRequire } from 'node:module'
import assert from 'node:assert'
const require = createRequire(import.meta.url)
const SHA256 = require('../public/sha256.js')

let passed = 0
const ok = (name) => { passed++; console.log(`  ✓ ${name}`) }
const hex = (u8) => Buffer.from(u8).toString('hex')
const ours = (s) => hex(SHA256.hash(new TextEncoder().encode(s)))

// 1) FIPS 180-4 / NIST 标准向量
{
  const vectors = [
    ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
    [
      'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    ],
    ['a'.repeat(1000000), 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0'],
  ]
  for (const [msg, want] of vectors) assert.strictEqual(ours(msg), want, `向量不符: ${msg.slice(0, 12)}…`)
  ok('FIPS 180-4 标准向量（空串 / abc / 448bit / 百万次 a）')
}

// 2) 块边界长度 + 随机长度，与 node 原生逐字节一致
{
  const lens = [
    0, 1, 2, 31, 32, 33, 54, 55, 56, 57, 63, 64, 65, 111, 112, 113,
    119, 120, 127, 128, 129, 255, 256, 1000, 4095, 4096, 65536,
  ]
  for (const len of lens) {
    const buf = randomBytes(len)
    const want = createHash('sha256').update(buf).digest('hex')
    assert.strictEqual(hex(SHA256.hash(new Uint8Array(buf))), want, `len=${len} 不一致`)
  }
  ok('块边界 27 种长度与 node 原生一致（55/56/57/63/64/65/119/120…）')
}

// 3) 500 组随机长度随机内容交叉验证
{
  for (let i = 0; i < 500; i++) {
    const len = Math.floor(Math.random() * 8192)
    const buf = randomBytes(len)
    const want = createHash('sha256').update(buf).digest('hex')
    assert.strictEqual(hex(SHA256.hash(new Uint8Array(buf))), want, `随机 len=${len} 不一致`)
  }
  ok('500 组随机缓冲区与 node 原生逐字节一致')
}

// 4) 非法输入
{
  assert.throws(() => SHA256.hash('不是字节'), /Uint8Array/)
  ok('非 Uint8Array 输入被拒绝')
}

console.log(`\nsha256: 全部 ${passed} 组通过`)
