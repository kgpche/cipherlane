// aesgcm.js 验证 —— 与 node:crypto 原生 aes-256-gcm 逐字节比对
import { createCipheriv, randomBytes } from 'node:crypto'
import { createRequire } from 'node:module'
import assert from 'node:assert'
const require = createRequire(import.meta.url)
const AESGCM = require('../public/aesgcm.js')

let passed = 0
const ok = (name) => { passed++; console.log(`  ✓ ${name}`) }

// 1) S-box 已知向量（FIPS-197 附录：63 7c 77 7b …）
{
  const S = AESGCM._test.SBOX
  assert.deepStrictEqual([S[0], S[1], S[2], S[3], S[0x53], S[0xff]], [0x63, 0x7c, 0x77, 0x7b, 0xed, 0x16])
  ok('S-box 与 FIPS-197 标准一致')
}

// 2) GHASH 快速表与参考实现一致（4-bit 参考版 + 8-bit 热路径版）
{
  const { gfMulRef, buildTables, gfMulT, buildTables8, gfMulT8 } = AESGCM._test
  for (let i = 0; i < 100; i++) {
    const X = randomBytes(16)
    const H = randomBytes(16)
    const out = new Uint8Array(16)
    gfMulT(X, buildTables(H), out)
    assert(Buffer.from(out).equals(Buffer.from(gfMulRef(X, H))))
    gfMulT8(X, buildTables8(H), out)
    assert(Buffer.from(out).equals(Buffer.from(gfMulRef(X, H))))
  }
  ok('GHASH 4-bit / 8-bit 表 × 参考实现各 100 组随机交叉验证')
}

// 3) 与 node 原生 aes-256-gcm 逐字节一致（各种长度，含边界）
{
  for (const len of [0, 1, 15, 16, 17, 31, 32, 33, 255, 4096, 65537, 1024 * 1024]) {
    const key = randomBytes(32)
    const iv = randomBytes(12)
    const pt = randomBytes(len)
    const c = createCipheriv('aes-256-gcm', key, iv)
    const ct = Buffer.concat([c.update(pt), c.final()])
    const tag = c.getAuthTag()

    const ours = AESGCM.encrypt(key, iv, pt)
    assert(Buffer.from(ours.ct).equals(ct), `ct 不一致 len=${len}`)
    assert(Buffer.from(ours.tag).equals(tag), `tag 不一致 len=${len}`)

    const back = AESGCM.decrypt(key, iv, ct, tag)
    assert(Buffer.from(back).equals(pt), `decrypt 不一致 len=${len}`)
  }
  ok('AES-256-GCM 输出与 node 原生逐字节一致（0B ~ 1MiB 共 12 种长度）')
}

// 4) seal/open 封装往返 + 篡改检测
{
  const key = randomBytes(32)
  const pt = new TextEncoder().encode('你好，密道 cipherlane 🚀')
  const packed = AESGCM.seal(key, pt)
  assert.deepStrictEqual(Buffer.from(AESGCM.open(key, packed)), Buffer.from(pt))
  packed[packed.length - 1] ^= 0x01 // 篡改 tag 最后一字节
  assert.throws(() => AESGCM.open(key, packed), /GCM 验证失败/)
  ok('seal/open 往返一致；篡改 1 比特即被检测')
}

// 5) 错误密钥必须失败
{
  const key = randomBytes(32)
  const packed = AESGCM.seal(key, new Uint8Array([1, 2, 3]))
  assert.throws(() => AESGCM.open(randomBytes(32), packed), /GCM 验证失败/)
  ok('错误密钥解密失败（不泄露任何明文）')
}

// 6) 性能参考
{
  const key = randomBytes(32)
  const pt = randomBytes(16 * 1024 * 1024)
  const t0 = performance.now()
  AESGCM.seal(key, pt)
  const dt = (performance.now() - t0) / 1000
  console.log(`  ⚡ 纯 JS 加密速度 ≈ ${((16 / dt)).toFixed(1)} MB/s（http 降级路径；原生 WebCrypto 更快）`)
}

console.log(`\n全部 ${passed} 组验证通过 ✅`)
