/* cipherlane · qrcode.js —— 纯 JS 二维码编码器（零依赖）
 *
 * 范围：字节模式 + ECC L + 版本 1-5（字节容量 17/32/53/78/106 —— 数据码字数
 * 减去 12 位模式+计数头，全部单块免交织）。
 * 覆盖典型接收链接（http://192.168.x.x:7777/#ROOM.KEY ≈ 60-85 字节）；
 * 超长输入 encode() 返回 null，调用方隐藏二维码即可。
 * 兼容：浏览器挂载全局 QRCode；Node 下 module.exports（CLI 终端码 / 测试用）。
 */
(function (global) {
  'use strict'

  // 版本 1-5 / ECC L：数据码字、纠错码字（单块）、校正图形中心（V1 无）
  const VERSIONS = [
    { v: 1, data: 19, ecc: 7, align: 0 },
    { v: 2, data: 34, ecc: 10, align: 18 },
    { v: 3, data: 55, ecc: 15, align: 22 },
    { v: 4, data: 80, ecc: 20, align: 26 },
    { v: 5, data: 108, ecc: 26, align: 30 },
  ]

  // ---------- GF(256)，本原多项式 0x11D ----------
  const EXP = new Uint8Array(512)
  const LOG = new Uint8Array(256)
  {
    let x = 1
    for (let i = 0; i < 255; i++) {
      EXP[i] = x
      LOG[x] = i
      x <<= 1
      if (x & 0x100) x ^= 0x11d
    }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]
  }
  const gmul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]])

  // 生成多项式 g(x) = Π(x - α^i)，i = 0..deg-1，首位为 1
  function genPoly(deg) {
    let g = [1]
    for (let i = 0; i < deg; i++) {
      const next = new Array(g.length + 1).fill(0)
      for (let j = 0; j < g.length; j++) {
        next[j] ^= gmul(g[j], EXP[i])
        next[j + 1] ^= g[j]
      }
      g = next
    }
    return g.reverse() // 惯例：低次在后；下面按高位在前使用
    // 注意：下面 RS 除法以 g[0] 为最高次（=1），此处 reverse 后 g[0]==1
  }

  // Reed-Solomon：求 data·x^deg mod g，返回 ecc 字节
  function rsEncode(data, deg) {
    const g = genPoly(deg)
    const res = new Uint8Array(data.length + deg)
    res.set(data)
    for (let i = 0; i < data.length; i++) {
      const coef = res[i]
      if (coef === 0) continue
      for (let j = 0; j <= deg; j++) res[i + j] ^= gmul(g[j], coef)
    }
    return res.subarray(data.length)
  }

  // ---------- 比特流 ----------
  function codewords(bytes, ver) {
    const bits = []
    const push = (val, n) => { for (let i = n - 1; i >= 0; i--) bits.push((val >> i) & 1) }
    push(4, 4) // 字节模式
    push(bytes.length, 8)
    for (const b of bytes) push(b, 8)
    const cap = ver.data * 8
    // 终止符（至多 4 位 0）+ 补齐到字节边界
    for (let i = 0; i < 4 && bits.length < cap; i++) bits.push(0)
    while (bits.length % 8) bits.push(0)
    const out = []
    for (let i = 0; i < bits.length; i += 8) {
      let b = 0
      for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j]
      out.push(b)
    }
    // 填充字节 0xEC 0x11 交替
    for (let pad = 0xec; out.length < ver.data; pad ^= 0xfd) out.push(pad)
    const data = Uint8Array.from(out)
    const ecc = rsEncode(data, ver.ecc)
    const all = new Uint8Array(ver.data + ver.ecc)
    all.set(data)
    all.set(ecc, ver.data)
    return all
  }

  // ---------- 矩阵 ----------
  const MASKS = [
    (i, j) => (i + j) % 2 === 0,
    (i, j) => i % 2 === 0,
    (i, j) => j % 3 === 0,
    (i, j) => (i + j) % 3 === 0,
    (i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0,
    (i, j) => ((i * j) % 2) + ((i * j) % 3) === 0,
    (i, j) => (((i * j) % 2) + ((i * j) % 3)) % 2 === 0,
    (i, j) => (((i + j) % 2) + ((i * j) % 3)) % 2 === 0,
  ]

  function build(ver, cw) {
    const size = 17 + 4 * ver.v
    const m = new Uint8Array(size * size) // 1=深色模块
    const func = new Uint8Array(size * size) // 1=功能模块（不承载数据、不掩码）
    const set = (r, c, v) => { m[r * size + c] = v; func[r * size + c] = 1 }

    // 三个 7×7 定位图形（含 1 圈留白分隔）
    const finder = (r0, c0) => {
      for (let r = -1; r <= 7; r++)
        for (let c = -1; c <= 7; c++) {
          const rr = r0 + r, cc = c0 + c
          if (rr < 0 || cc < 0 || rr >= size || cc >= size) continue
          const dark = r >= 0 && r <= 6 && c >= 0 && c <= 6 &&
            (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4))
          set(rr, cc, dark ? 1 : 0)
        }
    }
    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)

    // 校正图形（V2+ 单个中心）
    if (ver.align) {
      const a = ver.align
      for (let r = -2; r <= 2; r++)
        for (let c = -2; c <= 2; c++)
          set(a + r, a + c, Math.max(Math.abs(r), Math.abs(c)) !== 1 ? 1 : 0)
    }

    // 时序图形（行列 6，从 8 到 size-9 交替）
    for (let i = 8; i < size - 8; i++) {
      if (!func[6 * size + i]) set(6, i, i % 2 === 0 ? 1 : 0)
      if (!func[i * size + 6]) set(i, 6, i % 2 === 0 ? 1 : 0)
    }

    // 深色模块 + 预留格式信息区
    set(size - 8, 8, 1)
    for (let i = 0; i <= 8; i++) {
      if (i !== 6) { func[8 * size + i] = 1; func[i * size + 8] = 1 } // 跳过时序列
    }
    for (let i = 0; i < 8; i++) { func[8 * size + (size - 1 - i)] = 1; func[(size - 1 - i) * size + 8] = 1 }

    // 格式信息（ECC L=01）15 位：BCH(15,5) 后异或 0x5412（位序 LSB 先，坐标对照 nayuki）
    const placeFormat = (maskId) => {
      const data5 = (0b01 << 3) | maskId // L + mask
      let rem = data5 << 10
      for (let i = 14; i >= 10; i--) if ((rem >> i) & 1) rem ^= 0x537 << (i - 10)
      const fmt = (((data5 << 10) | rem) ^ 0x5412) & 0x7fff
      const bit = (k) => (fmt >> k) & 1 // k: 0=LSB…14=MSB
      // 第一副本：列 8（行 0-7）+ 行 8（列 7-0）；坐标为 [row, col]
      const c1 = [
        [0, 8], [1, 8], [2, 8], [3, 8], [4, 8], [5, 8], [7, 8], [8, 8],
        [8, 7], [8, 5], [8, 4], [8, 3], [8, 2], [8, 1], [8, 0],
      ]
      // 第二副本：行 8 右段（列 size-1..size-8）+ 列 8 下段（行 size-7..size-1）
      const c2 = []
      for (let i = 0; i < 8; i++) c2.push([8, size - 1 - i])
      for (let i = 0; i < 7; i++) c2.push([size - 7 + i, 8])
      for (let i = 0; i < 15; i++) {
        const [r1, c1x] = c1[i]
        m[r1 * size + c1x] = bit(i)
        const [r2, c2x] = c2[i]
        m[r2 * size + c2x] = bit(i)
      }
    }

    // 之字填入数据位（应用掩码候选；col 6 为时序列，跳过后折叠为 (5,4)）
    const bitLen = cw.length * 8
    let bitIdx = 0
    const place = (maskId) => {
      bitIdx = 0
      for (let right = size - 1; right >= 1; right -= 2) {
        if (right === 6) right = 5
        const upward = ((right + 1) & 2) === 0
        for (let k = 0; k < size; k++) {
          const r = upward ? size - 1 - k : k
          for (const c of [right, right - 1]) {
            if (func[r * size + c]) continue
            const bit = bitIdx < bitLen ? (cw[bitIdx >> 3] >> (7 - (bitIdx & 7))) & 1 : 0
            m[r * size + c] = bit ^ (MASKS[maskId](r, c) ? 1 : 0)
            bitIdx++
          }
        }
      }
    }

    // 掩码择优（惩罚规则 N1-N4）
    const penalty = () => {
      let score = 0
      const at = (r, c) => (r < 0 || c < 0 || r >= size || c >= size ? -1 : m[r * size + c])
      // N1 连续同色 ≥5
      const runs = (getR, getC) => {
        for (let a = 0; a < size; a++) {
          let run = 1
          for (let b = 1; b <= size; b++) {
            const cur = b < size ? getR(a, b) : -1
            const prev = getR(a, b - 1)
            if (cur === prev) run++
            else { if (run >= 5) score += 3 + (run - 5); run = 1 }
          }
        }
      }
      runs((a, b) => at(a, b), null)
      runs((a, b) => at(b, a), null)
      // N2 2×2 同色
      for (let r = 0; r < size - 1; r++)
        for (let c = 0; c < size - 1; c++) {
          const v = at(r, c)
          if (v === at(r, c + 1) && v === at(r + 1, c) && v === at(r + 1, c + 1)) score += 3
        }
      // N3 类定位图形 1011101 + 单侧 4 个浅色
      const pat = [1, 0, 1, 1, 1, 0, 1]
      const match = (get) => {
        for (let a = 0; a < size; a++)
          for (let b = 0; b + 7 <= size; b++) {
            let ok = true
            for (let k = 0; k < 7; k++) if (get(a, b + k) !== pat[k]) { ok = false; break }
            if (!ok) continue
            let light = 0
            for (let k = 1; k <= 4; k++) { if (get(a, b - k) === 0) light++; else break }
            if (light === 4) { score += 40; continue }
            light = 0
            for (let k = 1; k <= 4; k++) { if (get(a, b + 6 + k) === 0) light++; else break }
            if (light === 4) score += 40
          }
      }
      match((a, b) => at(a, b))
      match((a, b) => at(b, a))
      // N4 深浅比例
      let dark = 0
      for (let i = 0; i < m.length; i++) dark += m[i]
      score += Math.floor(Math.abs((dark * 100) / m.length - 50) / 5) * 10
      return score
    }

    let best = 0, bestScore = Infinity
    for (let maskId = 0; maskId < 8; maskId++) {
      place(maskId)
      const s = penalty()
      if (s < bestScore) { bestScore = s; best = maskId }
    }
    place(best)
    placeFormat(best)
    return { size, modules: m, mask: best, version: ver.v }
  }

  // encode(text) → { size, modules, version, mask } | null（超长）
  // 字节模式头占 12 位（模式 4 + 计数 8），故容量 = 数据码字数 - 2
  function encode(text) {
    const bytes = new TextEncoder().encode(text)
    const ver = VERSIONS.find((v) => bytes.length + 2 <= v.data)
    if (!ver) return null
    return build(ver, codewords(bytes, ver))
  }

  // svg(text, sizePx, dark, light) → 样式化内联 SVG（圆点模块 + 圆角定位眼），超长返回 null
  // 可扫性保障：数据点直径 0.88 模块、定位眼保持 1:1:3:1:1 结构、4 模块静区
  function svg(text, sizePx = 148, dark = '#0f1420', light = '#ffffff') {
    const qr = encode(text)
    if (!qr) return null
    const s = qr.size
    const q = 4 // 静区
    const n = s + q * 2
    const at = (r, c) => qr.modules[r * s + c] === 1
    const inFinder = (r, c) => (r < 8 && c < 8) || (r < 8 && c >= s - 8) || (r >= s - 8 && c < 8)
    const ALIGN = { 2: 18, 3: 22, 4: 26, 5: 30 }[qr.version] || 0
    const inAlign = (r, c) => ALIGN > 0 && Math.abs(r - ALIGN) <= 2 && Math.abs(c - ALIGN) <= 2

    // 数据区：圆点
    let dots = ''
    for (let r = 0; r < s; r++)
      for (let c = 0; c < s; c++)
        if (at(r, c) && !inFinder(r, c) && !inAlign(r, c))
          dots += `<circle cx="${c + q + 0.5}" cy="${r + q + 0.5}" r="0.42"/>`

    // 三个定位眼：圆角外环 + 圆角瞳孔
    let eyes = ''
    for (const [r0, c0] of [[0, 0], [0, s - 7], [s - 7, 0]]) {
      eyes += `<rect x="${c0 + q}" y="${r0 + q}" width="7" height="7" rx="2.1" fill="none" stroke="${dark}" stroke-width="1"/>`
        + `<rect x="${c0 + q + 2}" y="${r0 + q + 2}" width="3" height="3" rx="1" fill="${dark}"/>`
    }
    // 校正小眼（V2+）
    let alignEye = ''
    if (ALIGN > 0) {
      alignEye = `<rect x="${ALIGN + q - 2}" y="${ALIGN + q - 2}" width="5" height="5" rx="1.5" fill="none" stroke="${dark}" stroke-width="0.9"/>`
        + `<circle cx="${ALIGN + q + 0.5}" cy="${ALIGN + q + 0.5}" r="0.58" fill="${dark}"/>`
    }

    return `<svg class="qr" width="${sizePx}" height="${sizePx}" viewBox="0 0 ${n} ${n}" aria-label="接收链接二维码">` +
      `<rect width="${n}" height="${n}" rx="3" fill="${light}"/>` +
      `<g fill="${dark}">${dots}</g>${eyes}${alignEye}</svg>`
  }

  // asciiAdaptive(text, ratio) → 按终端字符单元格高宽比自适应的终端二维码。
  // ratio = 单元格高/宽（CSI 16t 实测；假设 2.0 为多数终端标准）。
  // 模块 = w_c 字符宽 × h_h 半行高，选取 (w_c, h_h) 使模块最接近正方形：
  //   w_c × 字宽 ≈ (h_h/2) × 行高 ⇒ h_h ≈ 2·w_c/ratio
  // ANSI 白底黑码保证极性与静区；半块字符获得半行粒度。超长返回 null
  function asciiAdaptive(text, ratio = 2) {
    const qr = encode(text)
    if (!qr) return null
    ratio = Math.min(2.6, Math.max(0.9, ratio))
    let wC = 2, hH = Math.round((2 * 2) / ratio)
    for (let w = 2; w <= 8; w++) {
      const h = Math.round((2 * w) / ratio)
      if (h < 1) continue
      if (Math.abs((2 * w) / ratio - h) <= 0.12) { wC = w; hH = h; break }
    }
    const S = qr.size, q = 4 // 静区
    const cols = (S + 2 * q) * wC
    const halfRows = (S + 2 * q) * hH
    const modAt = (hr, cc) => {
      const r = Math.floor((hr + 0.5) / hH) - q
      const c = Math.floor((cc + 0.5) / wC) - q
      return r >= 0 && c >= 0 && r < S && c < S && qr.modules[r * S + c] === 1
    }
    const BG = '\x1b[48;5;231m' // 白底
    const FG = '\x1b[38;5;16m'  // 黑码
    let out = ''
    for (let hr = 0; hr < halfRows; hr += 2) {
      let line = BG + FG + ' '.repeat(wC)
      for (let cc = 0; cc < cols; cc++) {
        const top = modAt(hr, cc)
        const bot = hr + 1 < halfRows ? modAt(hr + 1, cc) : false
        line += top && bot ? '█' : top ? '▀' : bot ? '▄' : ' '
      }
      out += line + ' '.repeat(wC) + '\x1b[0m\n'
    }
    return out
  }

  // ascii(text) → 终端二维码（假设字符高宽比 2:1 的标准终端）
  function ascii(text) {
    return asciiAdaptive(text, 2)
  }

  // png(text, scale) → PNG Buffer（1-bit 灰度，像素级精确，仅 Node：惰性 require zlib）
  // 用途：终端字体几何不可控时的保底扫码路径（图片查看器打开即扫）
  function png(text, scale = 8) {
    const qr = encode(text)
    if (!qr) return null
    const zlib = require('node:zlib')
    const q = 4
    const n = qr.size + 2 * q
    const W = n * scale
    const rowBytes = Math.ceil(W / 8)
    const rows = []
    for (let y = 0; y < W; y++) {
      const r = Math.floor(y / scale) - q
      const row = Buffer.alloc(1 + rowBytes) // filter 0
      for (let bx = 0; bx < rowBytes; bx++) {
        let b = 0
        for (let bit = 0; bit < 8; bit++) {
          const x = bx * 8 + bit
          let dark = false
          if (x < W) {
            const c = Math.floor(x / scale) - q
            dark = r >= 0 && c >= 0 && r < qr.size && c < qr.size && qr.modules[r * qr.size + c] === 1
          }
          b = (b << 1) | (dark ? 0 : 1) // 灰度 1-bit：0=黑，1=白
        }
        row[1 + bx] = b
      }
      rows.push(row)
    }
    const idat = zlib.deflateSync(Buffer.concat(rows), { level: 9 })
    let CRC_T = null
    const crc32 = (buf) => {
      if (!CRC_T) {
        CRC_T = new Uint32Array(256)
        for (let k = 0; k < 256; k++) {
          let c = k
          for (let i = 0; i < 8; i++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
          CRC_T[k] = c
        }
      }
      let c = 0xffffffff
      for (const b of buf) c = CRC_T[(c ^ b) & 255] ^ (c >>> 8)
      return (c ^ 0xffffffff) >>> 0
    }
    const chunk = (type, data) => {
      const out = Buffer.alloc(12 + data.length)
      out.writeUInt32BE(data.length, 0)
      out.write(type, 4, 'ascii')
      data.copy(out, 8)
      out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length)
      return out
    }
    const ihdr = Buffer.alloc(13)
    ihdr.writeUInt32BE(W, 0)
    ihdr.writeUInt32BE(W, 4)
    ihdr[8] = 1 // bit depth
    ihdr[9] = 0 // 灰度
    return Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      chunk('IHDR', ihdr),
      chunk('IDAT', idat),
      chunk('IEND', Buffer.alloc(0)),
    ])
  }

  // measureCellRatio() → Promise<number>（仅 Node TTY）：CSI 16t 实测终端字符单元格
  // 高宽比（像素），无响应/不支持时回落 2.0（多数终端标准）。120ms 超时。
  function measureCellRatio() {
    return new Promise((resolve) => {
      const isNode = typeof process !== 'undefined' && process.versions && process.versions.node
      if (!isNode || !process.stdout.isTTY || !process.stdin.isTTY) return resolve(2)
      let done = false
      const finish = (r) => {
        if (done) return
        done = true
        clearTimeout(timer)
        process.stdin.removeListener('data', on)
        try { process.stdin.setRawMode(false) } catch {}
        process.stdin.pause()
        resolve(r)
      }
      const on = (d) => {
        const m = /\x1b\[6;(\d+);(\d+)t/.exec(d.toString('latin1'))
        if (m) finish(Math.min(2.6, Math.max(0.9, Number(m[1]) / Number(m[2]))))
      }
      const timer = setTimeout(() => finish(2), 120)
      try {
        process.stdin.setRawMode(true)
        process.stdin.resume()
        process.stdin.on('data', on)
        process.stdout.write('\x1b[16t')
      } catch { finish(2) }
    })
  }

  const api = { encode, svg, ascii, asciiAdaptive, png, measureCellRatio, _test: { VERSIONS, codewords, rsEncode, gmul, genPoly } }
  if (typeof module !== 'undefined' && module.exports) module.exports = api
  else global.QRCode = api
})(typeof self !== 'undefined' ? self : globalThis)
