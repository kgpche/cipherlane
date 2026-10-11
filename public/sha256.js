/* cipherlane · sha256.js —— 纯 JS SHA-256（FIPS 180-4，零依赖）
 *
 * 用途：局域网 http:// 是浏览器"非安全上下文"，crypto.subtle 不可用；
 *       本模块供 X25519 会话密钥派生与设备头像种子使用。
 * 兼容：浏览器挂载全局 SHA256；Node 下 module.exports。
 */
(function (global) {
  'use strict'

  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ])
  const H0 = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ])

  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0

  // hash(msg) → Uint8Array(32)
  function hash(msg) {
    if (!(msg instanceof Uint8Array)) throw new Error('SHA-256 输入必须是 Uint8Array')
    const len = msg.length
    // 填充：0x80 + 0…0 + 8 字节大端比特长度，总长为 64 的倍数
    const nb = Math.ceil((len + 9) / 64)
    const padded = new Uint8Array(nb * 64)
    padded.set(msg)
    padded[len] = 0x80
    const bitsHi = Math.floor(len / 536870912)            // len / 2^29
    const bitsLo = (len % 536870912) * 8
    const dv = padded.length - 8
    padded[dv] = (bitsHi >>> 24) & 255
    padded[dv + 1] = (bitsHi >>> 16) & 255
    padded[dv + 2] = (bitsHi >>> 8) & 255
    padded[dv + 3] = bitsHi & 255
    padded[dv + 4] = (bitsLo >>> 24) & 255
    padded[dv + 5] = (bitsLo >>> 16) & 255
    padded[dv + 6] = (bitsLo >>> 8) & 255
    padded[dv + 7] = bitsLo & 255

    const h = H0.slice()
    const w = new Uint32Array(64)
    for (let b = 0; b < nb; b++) {
      const off = b * 64
      for (let i = 0; i < 16; i++) {
        const j = off + i * 4
        w[i] = ((padded[j] << 24) | (padded[j + 1] << 16) | (padded[j + 2] << 8) | padded[j + 3]) >>> 0
      }
      for (let i = 16; i < 64; i++) {
        const x = w[i - 15], y = w[i - 2]
        const s0 = (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) >>> 0
        const s1 = (rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10)) >>> 0
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0
      }
      let a = h[0], b2 = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7]
      for (let i = 0; i < 64; i++) {
        const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0
        const ch = ((e & f) ^ (~e & g)) >>> 0
        const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0
        const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0
        const mj = ((a & b2) ^ (a & c) ^ (b2 & c)) >>> 0
        const t2 = (S0 + mj) >>> 0
        hh = g; g = f; f = e; e = (d + t1) >>> 0
        d = c; c = b2; b2 = a; a = (t1 + t2) >>> 0
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b2) >>> 0
      h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0
      h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0
    }

    const out = new Uint8Array(32)
    for (let i = 0; i < 8; i++) {
      out[i * 4] = (h[i] >>> 24) & 255
      out[i * 4 + 1] = (h[i] >>> 16) & 255
      out[i * 4 + 2] = (h[i] >>> 8) & 255
      out[i * 4 + 3] = h[i] & 255
    }
    return out
  }

  const api = { hash }
  if (typeof module !== 'undefined' && module.exports) module.exports = api
  else global.SHA256 = api
})(typeof self !== 'undefined' ? self : globalThis)
