// x25519.js 验证 —— RFC 7748 标准向量 + 与 node:crypto 原生 X25519 交叉
import { generateKeyPairSync, createPrivateKey, createPublicKey, diffieHellman, randomBytes } from 'node:crypto'
import { createRequire } from 'node:module'
import assert from 'node:assert'
const require = createRequire(import.meta.url)
const X25519 = require('../public/x25519.js')
const SHA256 = require('../public/sha256.js')

let passed = 0
const ok = (name) => { passed++; console.log(`  ✓ ${name}`) }
const b = (hexstr) => new Uint8Array(Buffer.from(hexstr, 'hex'))
const hex = (u8) => Buffer.from(u8).toString('hex')

// 裸 32 字节密钥 ↔ node KeyObject（X25519 的 DER 定长前缀）
const SPKI = Buffer.from('302a300506032b656e032100', 'hex')  // 公钥 12 字节前缀
const PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex') // 私钥 16 字节前缀
const pubRaw = (ko) => new Uint8Array(ko.export({ type: 'spki', format: 'der' }).subarray(12))
const pubFromRaw = (raw) => createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(raw)]), format: 'der', type: 'spki' })
const privFromRaw = (raw) => createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(raw)]), format: 'der', type: 'pkcs8' })

// 1) RFC 7748 §5.2 标量乘向量（含 clamp，向量按 RFC 直接经 dh 计算）
{
  const vectors = [
    [
      'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
      'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
      'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
    ],
    [
      '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d',
      'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493',
      '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957',
    ],
  ]
  for (const [sk, u, want] of vectors) assert.strictEqual(hex(X25519.dh(b(sk), b(u))), want)
  ok('RFC 7748 §5.2 标准向量')
}

// 2) RFC 7748 §6.1 Diffie-Hellman 向量（Alice/Bob）
{
  const aSk = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
  const aPk = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
  const bSk = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'
  const bPk = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'
  const shared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'
  assert.strictEqual(hex(X25519.publicFromSecret(b(aSk))), aPk, 'Alice 公钥')
  assert.strictEqual(hex(X25519.publicFromSecret(b(bSk))), bPk, 'Bob 公钥')
  assert.strictEqual(hex(X25519.dh(b(aSk), b(bPk))), shared, 'Alice→shared')
  assert.strictEqual(hex(X25519.dh(b(bSk), b(aPk))), shared, 'Bob→shared')
  ok('RFC 7748 §6.1 密钥协商向量（公钥推导 + 双向 DH 一致）')
}

// 3) 200 组随机密钥对与 node 原生 X25519 逐字节一致（双向）
{
  for (let i = 0; i < 200; i++) {
    const ourSk = new Uint8Array(randomBytes(32))
    const ourPk = X25519.publicFromSecret(ourSk)
    const nodePair = generateKeyPairSync('x25519')
    const nPub = pubRaw(nodePair.publicKey)

    const oursShared = X25519.dh(ourSk, nPub)
    const nodeShared = diffieHellman({ privateKey: nodePair.privateKey, publicKey: pubFromRaw(ourPk) })
    assert.strictEqual(hex(oursShared), nodeShared.toString('hex'), `随机组 ${i} 共享密钥不一致`)

    // 反向：node 以同一 seed 作接收方
    const seed = randomBytes(32)
    const nodePriv = privFromRaw(seed)
    const sharedViaNode = diffieHellman({ privateKey: nodePriv, publicKey: nodePair.publicKey })
    assert.strictEqual(hex(X25519.dh(new Uint8Array(seed), nPub)), sharedViaNode.toString('hex'), `随机组 ${i} 反向不一致`)
  }
  ok('200 组随机密钥对与 node 原生双向逐字节一致')
}

// 4) 小阶点 / 全零公钥 → 共享密钥全零，必须抛错
{
  assert.throws(() => X25519.dh(b('11'.repeat(32)), new Uint8Array(32)), /全零/)
  assert.throws(() => X25519.dh(b('22'.repeat(32)), b('01' + '00'.repeat(31))), /全零/)
  ok('全零公钥与小阶点（u=1）被拒绝')
}

// 5) 非法输入长度
{
  assert.throws(() => X25519.dh(b('00'.repeat(31)), b('00'.repeat(32))), /私钥/)
  assert.throws(() => X25519.dh(b('00'.repeat(32)), b('00'.repeat(31))), /公钥/)
  ok('非法密钥长度被拒绝')
}

// 6) sessionKey 派生：两侧一致，且绑定双方公钥与房间号
{
  const A = X25519.genKey(), B = X25519.genKey()
  const sA = X25519.dh(A.sk, B.pk)
  const sB = X25519.dh(B.sk, A.pk)
  const k1 = X25519.sessionKey(sA, A.pk, B.pk, 'Ab3xYz9kLm')
  const k2 = X25519.sessionKey(sB, A.pk, B.pk, 'Ab3xYz9kLm')
  assert.strictEqual(hex(k1), hex(k2), '两侧派生不一致')
  assert.strictEqual(k1.length, 32)
  const k3 = X25519.sessionKey(sA, A.pk, B.pk, 'OTHERROOM1')
  assert.notStrictEqual(hex(k1), hex(k3), '不同房间应派生不同密钥')
  // 与直接 SHA-256 拼接的结果一致（供 CLI/协议测试对齐）
  const manual = SHA256.hash(new Uint8Array(Buffer.concat([
    Buffer.from(sA), Buffer.from(A.pk), Buffer.from(B.pk),
    Buffer.from('cipherlane/device/v1\0Ab3xYz9kLm', 'utf8'),
  ])))
  assert.strictEqual(hex(k1), Buffer.from(manual).toString('hex'))
  ok('sessionKey 两侧一致、绑定公钥与房间号')
}

console.log(`\nx25519: 全部 ${passed} 组通过`)
