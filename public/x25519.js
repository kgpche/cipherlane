/* cipherlane · x25519.js —— 纯 JS X25519（RFC 7748，BigInt，零依赖）
 *
 * 用途：设备定向发送的密钥协商。局域网 http 非安全上下文无 crypto.subtle，
 *       用 BigInt 实现 Montgomery 阶梯；每次传输仅 2 次标量乘，毫秒级足够。
 * 安全：私钥按 RFC 7748 §5 clamp；dh() 输出全零（小阶点攻击）即抛错。
 * 兼容：浏览器挂载全局 X25519；Node 下 module.exports。
 * 依赖：sessionKey() 需先加载 sha256.js（浏览器）或同目录 require（Node）。
 */
(function (global) {
  'use strict'

  const P = (1n << 255n) - 19n
  const A24 = 121665n
  const LABEL = 'cipherlane/device/v1\u0000' // 会话密钥派生的域分隔标签

  // ---------- 字节 ↔ BigInt（小端） ----------
  function bytesToLE(b) {
    let n = 0n
    for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i])
    return n
  }
  function leToBytes(x) {
    const out = new Uint8Array(32)
    for (let i = 0; i < 32; i++) { out[i] = Number(x & 255n); x >>= 8n }
    return out
  }
  function concatBuf(parts) {
    let n = 0
    for (const p of parts) n += p.length
    const out = new Uint8Array(n)
    let off = 0
    for (const p of parts) { out.set(p, off); off += p.length }
    return out
  }
  function random32() {
    const out = new Uint8Array(32)
    if (globalThis.crypto && globalThis.crypto.getRandomValues) globalThis.crypto.getRandomValues(out)
    else if (typeof require === 'function') out.set(require('node:crypto').randomBytes(32))
    else throw new Error('无可用随机源')
    return out
  }

  // RFC 7748 §5：Montgomery 阶梯。k 为已 clamp 的标量，u 为对方公钥的域元素
  function scalarMult(k, u) {
    const x1 = u % P
    let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, swap = 0n
    for (let t = 254; t >= 0; t--) {
      const kt = (k >> BigInt(t)) & 1n
      swap ^= kt
      if (swap) {
        let tmp = x2; x2 = x3; x3 = tmp
        tmp = z2; z2 = z3; z3 = tmp
      }
      swap = kt
      const A = (x2 + z2) % P
      const AA = (A * A) % P
      const B = (x2 - z2 + P) % P
      const BB = (B * B) % P
      const E = (AA - BB + P) % P
      const C = (x3 + z3) % P
      const D = (x3 - z3 + P) % P
      const DA = (D * A) % P
      const CB = (C * B) % P
      x3 = ((DA + CB) % P) * ((DA + CB) % P) % P
      z3 = (x1 * (((DA - CB + P) % P) * ((DA - CB + P) % P) % P)) % P
      x2 = (AA * BB) % P
      z2 = (E * ((AA + A24 * E) % P)) % P
    }
    if (swap) {
      let tmp = x2; x2 = x3; x3 = tmp
      tmp = z2; z2 = z3; z3 = tmp
    }
    return (x2 * modPow(z2, P - 2n, P)) % P
  }

  function modPow(b, e, m) {
    let r = 1n
    b %= m
    while (e > 0n) {
      if (e & 1n) r = (r * b) % m
      b = (b * b) % m
      e >>= 1n
    }
    return r
  }

  function clamp(bytes) {
    const b = bytes.slice()
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return b
  }

  // ---------- 公开 API ----------
  // publicFromSecret(sk) → 32 字节公钥（基点 9 的标量乘）
  function publicFromSecret(skBytes) {
    if (!(skBytes instanceof Uint8Array) || skBytes.length !== 32) throw new Error('X25519 私钥必须是 32 字节')
    return leToBytes(scalarMult(bytesToLE(clamp(skBytes)), 9n))
  }

  // genKey() → { sk, pk }
  function genKey() {
    const sk = random32()
    return { sk, pk: publicFromSecret(sk) }
  }

  // dh(sk, theirPk) → 32 字节共享密钥；全零输出（无效公钥/小阶点）抛错
  function dh(skBytes, theirPk) {
    if (!(skBytes instanceof Uint8Array) || skBytes.length !== 32) throw new Error('X25519 私钥必须是 32 字节')
    if (!(theirPk instanceof Uint8Array) || theirPk.length !== 32) throw new Error('X25519 公钥必须是 32 字节')
    const uBytes = theirPk.slice()
    uBytes[31] &= 127 // RFC 7748：解码 u 坐标时屏蔽最高位
    const out = leToBytes(scalarMult(bytesToLE(clamp(skBytes)), bytesToLE(uBytes)))
    let zero = 0
    for (const b of out) zero |= b
    if (zero === 0) throw new Error('X25519 无效公钥（共享密钥为全零）')
    return out
  }

  // sessionKey(shared, senderPub, receiverPub, roomId) → 32 字节房间密钥
  // 两侧参数顺序必须一致：均为（发送方公钥, 接收方公钥）
  function sessionKey(shared, senderPub, receiverPub, roomId) {
    const SHA = global.SHA256 || (typeof require === 'function' ? require('./sha256.js') : null)
    if (!SHA) throw new Error('缺少 sha256.js')
    return SHA.hash(concatBuf([
      shared,
      senderPub,
      receiverPub,
      new TextEncoder().encode(LABEL + roomId),
    ]))
  }

  const api = { genKey, dh, publicFromSecret, sessionKey, _test: { scalarMult, clamp, P } }
  if (typeof module !== 'undefined' && module.exports) module.exports = api
  else global.X25519 = api
})(typeof self !== 'undefined' ? self : globalThis)
