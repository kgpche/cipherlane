/* cipherlane · aesgcm.js —— 纯 JS AES-256-GCM（零依赖）
 *
 * 用途：局域网 http:// 是浏览器的“非安全上下文”，crypto.subtle 不可用。
 *       本模块提供与 WebCrypto / node:crypto aes-256-gcm 完全一致的实现。
 * 线上格式：IV(12B) || 密文 || TAG(16B)，分片级独立加密。
 * 兼容：浏览器挂载全局 AESGCM；Node 下 module.exports。
 */
(function (global) {
  'use strict'

  // ============ GF(2^8)：xtime 与 S-box（程序化生成，可自检） ============
  const xtime = (x) => ((x << 1) ^ ((x >> 7) * 0x1b)) & 0xff

  const SBOX = new Uint8Array(256)
  {
    // 生成元 0x03 的 exp/log 表 → 求乘法逆元；再作 Rijndadel 仿射变换
    const exp = new Uint8Array(255)
    const log = new Uint8Array(256)
    let x = 1
    for (let i = 0; i < 255; i++) {
      exp[i] = x
      log[x] = i
      x ^= xtime(x) // x *= 3
    }
    const rot = (v, n) => ((v << n) | (v >>> (8 - n))) & 0xff
    for (let a = 0; a < 256; a++) {
      const inv = a === 0 ? 0 : exp[(255 - log[a]) % 255]
      SBOX[a] = inv ^ rot(inv, 1) ^ rot(inv, 2) ^ rot(inv, 3) ^ rot(inv, 4) ^ 0x63
    }
  }
  const M2 = new Uint8Array(256)
  const M3 = new Uint8Array(256)
  for (let i = 0; i < 256; i++) {
    M2[i] = xtime(i)
    M3[i] = xtime(i) ^ i
  }

  // ============ T-table:AES 轮函数整列查表（S 盒 + MixColumns 合一） ============
  // 每轮 16 次 32 位查表 + 异或,替代逐字节 S 盒/移位/M2·M3,实测快 2~3 倍。
  // 注:T-table 存在 cache 计时侧信道(需同机攻击者持续探测);本项目威胁模型
  // 是网络攻击者(嗅探/MITM),明文 http 降级路径上此取舍可接受。
  const TE0 = new Uint32Array(256)
  const TE1 = new Uint32Array(256)
  const TE2 = new Uint32Array(256)
  const TE3 = new Uint32Array(256)
  for (let x = 0; x < 256; x++) {
    const b = SBOX[x]
    const w = ((M2[b] << 24) | (b << 16) | (b << 8) | M3[b]) >>> 0 // 列贡献 [02,01,01,03]
    TE0[x] = w
    TE1[x] = ((w >>> 8) | (w << 24)) >>> 0                          // [03,02,01,01]
    TE2[x] = ((w >>> 16) | (w << 16)) >>> 0                         // [01,03,02,01]
    TE3[x] = ((w >>> 24) | (w << 8)) >>> 0                          // [01,01,03,02]
  }

  // ============ AES-256 密钥扩展（Nk=8, Nr=14, 15 个轮密钥） ============
  function expandKey256(key) {
    if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error('key 必须是 32 字节')
    const w = new Uint8Array(240)
    w.set(key)
    let rcon = 1
    for (let nw = 8; nw < 60; nw++) {
      const p = 4 * nw
      let t0 = w[p - 4], t1 = w[p - 3], t2 = w[p - 2], t3 = w[p - 1]
      if (nw % 8 === 0) {
        // RotWord + SubWord + Rcon
        const tt = t0
        t0 = SBOX[t1] ^ rcon
        t1 = SBOX[t2]
        t2 = SBOX[t3]
        t3 = SBOX[tt]
        rcon = xtime(rcon)
      } else if (nw % 8 === 4) {
        // AES-256 额外的 SubWord
        t0 = SBOX[t0]; t1 = SBOX[t1]; t2 = SBOX[t2]; t3 = SBOX[t3]
      }
      w[p] = w[p - 32] ^ t0
      w[p + 1] = w[p - 31] ^ t1
      w[p + 2] = w[p - 30] ^ t2
      w[p + 3] = w[p - 29] ^ t3
    }
    return w
  }

  // ============ 单块加密（FIPS-197，state 列优先，s[i]=in[i]） ============
  const _s = new Uint8Array(16)
  function encryptBlock(rk, in16, out16) {
    const s = _s
    s.set(in16)
    // AddRoundKey(0)
    for (let i = 0; i < 16; i++) s[i] ^= rk[i]
    for (let round = 1; round < 14; round++) {
      const o = 16 * round
      // SubBytes
      for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]]
      // ShiftRows（行 r 左移 r）
      let t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t
      t = s[2]; s[2] = s[10]; s[10] = t
      t = s[6]; s[6] = s[14]; s[14] = t
      t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t
      // MixColumns
      for (let c = 0; c < 16; c += 4) {
        const a = s[c], b = s[c + 1], d = s[c + 2], e = s[c + 3]
        s[c] = M2[a] ^ M3[b] ^ d ^ e
        s[c + 1] = a ^ M2[b] ^ M3[d] ^ e
        s[c + 2] = a ^ b ^ M2[d] ^ M3[e]
        s[c + 3] = M3[a] ^ b ^ d ^ M2[e]
      }
      // AddRoundKey(round)
      for (let i = 0; i < 16; i++) s[i] ^= rk[o + i]
    }
    // 最后一轮：无 MixColumns
    for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]]
    let t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t
    t = s[2]; s[2] = s[10]; s[10] = t
    t = s[6]; s[6] = s[14]; s[14] = t
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t
    for (let i = 0; i < 16; i++) out16[i] = s[i] ^ rk[224 + i]
  }

  // T-table 版块加密：rk32 为 60 个大端轮密钥字。与 encryptBlock 输出逐字节一致
  function encryptBlockT(rk32, in16, out16) {
    let s0 = (((in16[0] << 24) | (in16[1] << 16) | (in16[2] << 8) | in16[3]) ^ rk32[0]) | 0
    let s1 = (((in16[4] << 24) | (in16[5] << 16) | (in16[6] << 8) | in16[7]) ^ rk32[1]) | 0
    let s2 = (((in16[8] << 24) | (in16[9] << 16) | (in16[10] << 8) | in16[11]) ^ rk32[2]) | 0
    let s3 = (((in16[12] << 24) | (in16[13] << 16) | (in16[14] << 8) | in16[15]) ^ rk32[3]) | 0
    let t0, t1, t2, t3
    for (let r = 4; r < 56; r += 4) { // 轮 1~13（AddRoundKey(0) 已并入初值）
      t0 = (TE0[s0 >>> 24] ^ TE1[(s1 >>> 16) & 255] ^ TE2[(s2 >>> 8) & 255] ^ TE3[s3 & 255] ^ rk32[r]) | 0
      t1 = (TE0[s1 >>> 24] ^ TE1[(s2 >>> 16) & 255] ^ TE2[(s3 >>> 8) & 255] ^ TE3[s0 & 255] ^ rk32[r + 1]) | 0
      t2 = (TE0[s2 >>> 24] ^ TE1[(s3 >>> 16) & 255] ^ TE2[(s0 >>> 8) & 255] ^ TE3[s1 & 255] ^ rk32[r + 2]) | 0
      t3 = (TE0[s3 >>> 24] ^ TE1[(s0 >>> 16) & 255] ^ TE2[(s1 >>> 8) & 255] ^ TE3[s2 & 255] ^ rk32[r + 3]) | 0
      s0 = t0; s1 = t1; s2 = t2; s3 = t3
    }
    // 末轮：ShiftRows 取字节 + S 盒 + AddRoundKey（无 MixColumns）
    out16[0] = (SBOX[s0 >>> 24] ^ (rk32[56] >>> 24)) & 255
    out16[1] = (SBOX[(s1 >>> 16) & 255] ^ ((rk32[56] >>> 16) & 255)) & 255
    out16[2] = (SBOX[(s2 >>> 8) & 255] ^ ((rk32[56] >>> 8) & 255)) & 255
    out16[3] = (SBOX[s3 & 255] ^ (rk32[56] & 255)) & 255
    out16[4] = (SBOX[s1 >>> 24] ^ (rk32[57] >>> 24)) & 255
    out16[5] = (SBOX[(s2 >>> 16) & 255] ^ ((rk32[57] >>> 16) & 255)) & 255
    out16[6] = (SBOX[(s3 >>> 8) & 255] ^ ((rk32[57] >>> 8) & 255)) & 255
    out16[7] = (SBOX[s0 & 255] ^ (rk32[57] & 255)) & 255
    out16[8] = (SBOX[s2 >>> 24] ^ (rk32[58] >>> 24)) & 255
    out16[9] = (SBOX[(s3 >>> 16) & 255] ^ ((rk32[58] >>> 16) & 255)) & 255
    out16[10] = (SBOX[(s0 >>> 8) & 255] ^ ((rk32[58] >>> 8) & 255)) & 255
    out16[11] = (SBOX[s1 & 255] ^ (rk32[58] & 255)) & 255
    out16[12] = (SBOX[s3 >>> 24] ^ (rk32[59] >>> 24)) & 255
    out16[13] = (SBOX[(s0 >>> 16) & 255] ^ ((rk32[59] >>> 16) & 255)) & 255
    out16[14] = (SBOX[(s1 >>> 8) & 255] ^ ((rk32[59] >>> 8) & 255)) & 255
    out16[15] = (SBOX[s2 & 255] ^ (rk32[59] & 255)) & 255
    return out16
  }

  // ============ 密钥缓存：rk32 / H / 8-bit GHASH 表（同密钥流式分片只算一次） ============
  let _kc = { key: null, rk32: null, tables: null }
  function keyCache(key) {
    if (_kc.key && _kc.key.length === key.length) {
      let same = true
      for (let i = 0; i < key.length; i++) if (_kc.key[i] !== key[i]) { same = false; break }
      if (same) return _kc
    }
    const rk = expandKey256(key)
    const rk32 = new Uint32Array(60)
    for (let i = 0; i < 60; i++)
      rk32[i] = (((rk[4 * i] << 24) | (rk[4 * i + 1] << 16) | (rk[4 * i + 2] << 8) | rk[4 * i + 3]) >>> 0) | 0
    const H = new Uint8Array(16)
    encryptBlockT(rk32, ZEROS16, H)
    _kc = { key: key.slice(), rk32, tables: buildTables8(H) }
    return _kc
  }

  // ============ GF(2^128) 乘法（SP 800-38D，R=0xE1…） ============
  // 参考实现（慢，用于交叉验证）
  function gfMulRef(X, Y) {
    const Z = new Uint8Array(16)
    const V = Uint8Array.from(Y)
    for (let i = 0; i < 16; i++) {
      const x = X[i]
      for (let bit = 7; bit >= 0; bit--) {
        if ((x >> bit) & 1) for (let k = 0; k < 16; k++) Z[k] ^= V[k]
        const lsb = V[15] & 1
        for (let k = 15; k > 0; k--) V[k] = (V[k] >>> 1) | ((V[k - 1] & 1) << 7)
        V[0] = V[0] >>> 1
        if (lsb) V[0] ^= 0xe1
      }
    }
    return Z
  }

  // 乘 x（右移 1 位 + 条件模约减）
  function mulX(v) {
    const o = new Uint8Array(16)
    const lsb = v[15] & 1
    for (let k = 15; k > 0; k--) o[k] = (v[k] >>> 1) | ((v[k - 1] & 1) << 7)
    o[0] = v[0] >>> 1
    if (lsb) o[0] ^= 0xe1
    return o
  }

  // 4-bit 窗口表：M[pos][n] = (n 在第 pos 个 nibble 位置) · H，共 32×16 项
  function buildTables(H) {
    const tables = []
    let cur = Uint8Array.from(H)
    for (let pos = 0; pos < 32; pos++) {
      const t = new Uint8Array(16 * 16)
      let v = cur
      for (let b = 0; b < 4; b++) {
        // nibble 值的位权是反的：值 8↔x^(4pos+0)，值 4↔x^(4pos+1)，…，值 1↔x^(4pos+3)
        t.set(v, 16 * (8 >> b))
        v = mulX(v)
      }
      for (let n = 3; n < 16; n++) {
        if ((n & (n - 1)) === 0) continue
        const lo = n & -n
        const rest = n ^ lo
        for (let k = 0; k < 16; k++) t[16 * n + k] = t[16 * rest + k] ^ t[16 * lo + k]
      }
      tables.push(t)
      cur = mulX(mulX(mulX(mulX(cur))))
    }
    return tables
  }

  function gfMulT(X, tables, out) {
    // 注意：out 与 X 允许是同一 buffer，先在临时区累加
    const Z = new Uint8Array(16)
    for (let pos = 0; pos < 32; pos++) {
      const byte = X[pos >> 1]
      const nib = pos & 1 ? byte & 15 : byte >>> 4
      if (nib) {
        const t = tables[pos]
        const off = 16 * nib
        for (let k = 0; k < 16; k++) Z[k] ^= t[off + k]
      }
    }
    out.set(Z)
  }

  // 8-bit 窗口表（热路径用）：16 字节位 × 256 值 × 16B = 64KB/密钥，
  // 每块 16 次查表（4-bit 版为 32 次），构建一次经 keyCache 复用
  function buildTables8(H) {
    const tables = []
    let cur = Uint8Array.from(H)
    for (let pos = 0; pos < 16; pos++) {
      const t = new Uint8Array(256 * 16)
      // 位权与 4-bit 版一致：MSB(x^0 权)在前，逐位 ×x
      let v = cur
      for (let bit = 128; bit >= 1; bit >>>= 1) {
        t.set(v, 16 * bit)
        v = mulX(v)
      }
      for (let n = 3; n < 256; n++) { // 增量合成：n = 最高位 | 余量
        if ((n & (n - 1)) === 0) continue
        const lo = n & -n
        const rest = n ^ lo
        const a = 16 * rest, b = 16 * lo
        for (let k = 0; k < 16; k++) t[16 * n + k] = t[a + k] ^ t[b + k]
      }
      tables.push(t)
      for (let i = 0; i < 8; i++) cur = mulX(cur)
    }
    return tables
  }
  const _z8 = new Uint8Array(16) // gfMulT8 累加暂存(避免每块分配)
  function gfMulT8(X, tables, out) {
    const Z = _z8
    Z.fill(0)
    for (let pos = 0; pos < 16; pos++) {
      const b = X[pos]
      if (b) {
        const t = tables[pos]
        const off = 16 * b
        for (let k = 0; k < 16; k++) Z[k] ^= t[off + k]
      }
    }
    out.set(Z)
  }

  // ============ GCM ============
  const ZEROS16 = new Uint8Array(16)
  const _j0 = new Uint8Array(16)
  const _mask = new Uint8Array(16)
  const _H = new Uint8Array(16)
  const _ctr = new Uint8Array(16)
  const _ks = new Uint8Array(16)
  const _y = new Uint8Array(16)
  const _x = new Uint8Array(16)

  function inc32(b) {
    for (let i = 15; i >= 12; i--) {
      b[i] = (b[i] + 1) & 0xff
      if (b[i] !== 0) break
    }
  }

  // CTR 加/解密（对称）——T-table 热路径
  function ctrXor(rk32, iv, data) {
    _j0.set(iv); _j0[12] = 0; _j0[13] = 0; _j0[14] = 0; _j0[15] = 1
    _ctr.set(_j0)
    const out = new Uint8Array(data.length)
    for (let off = 0; off < data.length; off += 16) {
      inc32(_ctr)
      encryptBlockT(rk32, _ctr, _ks)
      const n = Math.min(16, data.length - off)
      for (let k = 0; k < n; k++) out[off + k] = data[off + k] ^ _ks[k]
    }
    return out
  }

  // GHASH(H, C)（无 AAD；长度块按比特数）——8-bit 窗口表
  function ghash(ct, tables) {
    _y.fill(0)
    const blocks = Math.ceil(ct.length / 16)
    for (let b = 0; b < blocks; b++) {
      const off = b * 16
      const len = Math.min(16, ct.length - off)
      _x.fill(0)
      _x.set(ct.subarray(off, off + len))
      for (let k = 0; k < 16; k++) _y[k] ^= _x[k]
      gfMulT8(_y, tables, _y)
    }
    // 长度块：[0^64 | bitlen(C)]，bitlen < 2^53 安全
    _x.fill(0)
    let v = ct.length * 8
    for (let k = 15; k >= 8; k--) {
      _x[k] = v & 0xff
      v = Math.floor(v / 256)
    }
    for (let k = 0; k < 16; k++) _y[k] ^= _x[k]
    gfMulT8(_y, tables, _y)
    return Uint8Array.from(_y)
  }

  function gcmTag(rk32, tables, iv, ct) {
    _j0.set(iv); _j0[12] = 0; _j0[13] = 0; _j0[14] = 0; _j0[15] = 1
    encryptBlockT(rk32, _j0, _mask) // E(K, J0)：标签掩码
    const S = ghash(ct, tables)
    const tag = new Uint8Array(16)
    for (let k = 0; k < 16; k++) tag[k] = _mask[k] ^ S[k]
    return tag
  }

  // ============ 对外 API ============
  function randomIV() {
    const iv = new Uint8Array(12)
    if (globalThis.crypto && globalThis.crypto.getRandomValues) globalThis.crypto.getRandomValues(iv)
    else if (typeof require === 'function') iv.set(require('node:crypto').randomBytes(12)) // Node 18 无全局 webcrypto
    else throw new Error('无可用随机源')
    return iv
  }

  // encrypt(key, iv, pt) → { ct, tag }（与 node aes-256-gcm 逐字节一致）
  function encrypt(key, iv, pt) {
    if (!(iv instanceof Uint8Array) || iv.length !== 12) throw new Error('iv 必须是 12 字节')
    const { rk32, tables } = keyCache(key)
    const ct = ctrXor(rk32, iv, pt)
    const tag = gcmTag(rk32, tables, iv, ct)
    return { ct, tag }
  }

  // decrypt(key, iv, ct, tag) → pt；验签失败抛错
  function decrypt(key, iv, ct, tag) {
    const { rk32, tables } = keyCache(key)
    const calc = gcmTag(rk32, tables, iv, ct)
    let diff = 0
    for (let k = 0; k < 16; k++) diff |= calc[k] ^ tag[k]
    if (diff !== 0) throw new Error('GCM 验证失败：密钥错误或数据被篡改')
    return ctrXor(rk32, iv, ct)
  }

  // seal(key, pt, iv?) → iv || ct || tag
  function seal(key, pt, iv) {
    iv = iv || randomIV()
    const { ct, tag } = encrypt(key, iv, pt)
    const out = new Uint8Array(12 + ct.length + 16)
    out.set(iv, 0)
    out.set(ct, 12)
    out.set(tag, 12 + ct.length)
    return out
  }

  // open(key, packed) → pt
  function open(key, packed) {
    if (!(packed instanceof Uint8Array) || packed.length < 28) throw new Error('数据不完整')
    const iv = packed.subarray(0, 12)
    const ct = packed.subarray(12, packed.length - 16)
    const tag = packed.subarray(packed.length - 16)
    return decrypt(key, iv, ct, tag)
  }

  const api = { seal, open, encrypt, decrypt, expandKey256, encryptBlock, encryptBlockT, keyCache, _test: { SBOX, gfMulRef, mulX, buildTables, gfMulT, buildTables8, gfMulT8, TE0 } }
  if (typeof module !== 'undefined' && module.exports) module.exports = api
  else global.AESGCM = api
})(typeof self !== 'undefined' ? self : globalThis)
