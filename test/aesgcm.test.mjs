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

// 4b) AAD（协议 v2 分片位置绑定）：与 node setAAD 逐字节交叉
//     旧实现（无 AAD）解密带 AAD 的密文必须失败 —— 即本组在旧代码上会红。
{
  const cases = [
    [0, 0], [1, 1], [15, 16], [16, 17], [17, 32],
    [1024, 1], [1024, 100], [65537, 255], [1024 * 1024, 32],
  ]
  for (const [len, aadLen] of cases) {
    const key = randomBytes(32)
    const iv = randomBytes(12)
    const pt = randomBytes(len)
    const aad = randomBytes(aadLen)
    const c = createCipheriv('aes-256-gcm', key, iv)
    c.setAAD(aad)
    const ct = Buffer.concat([c.update(pt), c.final()])
    const tag = c.getAuthTag()

    const ours = AESGCM.encrypt(key, iv, pt, aad)
    assert(Buffer.from(ours.ct).equals(ct), `AAD ct 不一致 len=${len} aad=${aadLen}`)
    assert(Buffer.from(ours.tag).equals(tag), `AAD tag 不一致 len=${len} aad=${aadLen}`)
    assert(Buffer.from(AESGCM.decrypt(key, iv, ct, tag, aad)).equals(pt),
      `AAD decrypt 不一致 len=${len} aad=${aadLen}`)

    if (aadLen > 0) {
      // 旧实现（无 AAD）会把这些密文当合法 → 本断言在旧代码上失败（红）
      assert.throws(() => AESGCM.decrypt(key, iv, ct, tag), /GCM 验证失败/,
        `无 AAD 解密不应通过 len=${len} aad=${aadLen}`)
      // AAD 被篡改（错位分片等价场景）必须失败
      const badAad = Buffer.from(aad); badAad[0] ^= 1
      assert.throws(() => AESGCM.decrypt(key, iv, ct, tag, badAad), /GCM 验证失败/)
      // 密文 / tag 篡改同样失败
      const badCt = Buffer.from(ct); badCt[0] ^= 1
      assert.throws(() => AESGCM.decrypt(key, iv, badCt, tag, aad), /GCM 验证失败/)
      const badTag = Buffer.from(tag); badTag[0] ^= 1
      assert.throws(() => AESGCM.decrypt(key, iv, ct, badTag, aad), /GCM 验证失败/)
    }
  }
  ok('AAD 与 node setAAD 逐字节一致；无 AAD/错位 AAD/篡改均被拒（旧实现红）')
}

// 4c) seal/open 的 AAD 封装 + 空 AAD 等价于无 AAD（旧线上格式不变）
{
  const key = randomBytes(32)
  const pt = randomBytes(4096)
  const aad = new TextEncoder().encode('cipherlane/chunk/v2|Ab3xYz9kLm|7')
  const packed = AESGCM.seal(key, pt, aad)
  assert.deepStrictEqual(Buffer.from(AESGCM.open(key, packed, aad)), Buffer.from(pt))
  assert.throws(() => AESGCM.open(key, packed), /GCM 验证失败/)
  const same = new TextEncoder().encode('cipherlane/chunk/v2|Ab3xYz9kLm|8')
  assert.throws(() => AESGCM.open(key, packed, same), /GCM 验证失败/)

  // 空 AAD 的 tag 必须与不传 AAD 完全相同 → 旧无 AAD 输出逐字节不变
  const iv = randomBytes(12)
  const noAad = AESGCM.encrypt(key, iv, pt)
  const emptyAad = AESGCM.encrypt(key, iv, pt, new Uint8Array(0))
  assert(Buffer.from(noAad.tag).equals(Buffer.from(emptyAad.tag)), '空 AAD 必须等价于无 AAD')
  ok('seal/open AAD 往返、AAD 错位拒绝；空 AAD 与无 AAD 输出一致')
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
