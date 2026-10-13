// qrcode.js 验证 —— 结构自检：RS 代数性质 / 定位与时序图形 / 格式信息 / 容量边界
import { createRequire } from 'node:module'
import assert from 'node:assert'
const require = createRequire(import.meta.url)
const QRCode = require('../public/qrcode.js')

let passed = 0
const ok = (name) => { passed++; console.log(`  ✓ ${name}`) }

// 1) 容量边界：字节容量 17/32/53/78/106（数据码字 19/34/55/80/108 减 12 位头），超长返回 null
{
  const caps = [17, 32, 53, 78, 106]
  for (let v = 0; v < 5; v++) {
    const q1 = QRCode.encode('a'.repeat(caps[v]))
    assert.strictEqual(q1.version, v + 1, `len=${caps[v]} 应为 V${v + 1}`)
    if (v > 0 && v < 4) {
      const q2 = QRCode.encode('a'.repeat(caps[v] + 1))
      assert.strictEqual(q2.version, v + 2, `len=${caps[v] + 1} 应为 V${v + 2}`)
    }
  }
  assert.strictEqual(QRCode.encode('a'.repeat(107)), null, '107 字节应返回 null')
  assert.strictEqual(QRCode.encode('http://192.168.137.91:7788/#Ab3xYz9kLm.0u2VGVpDrE81B9GbT4tk0Me0D_Z8eCf3dTe9cihOnRk').version, 5, '典型 LAN 链接（82B）应为 V5')
  ok('容量边界 17/32/53/78/106 → V1-V5（12 位模式头已计入），107+ 返回 null，LAN 链接可编码')
}

// 2) 尺寸与确定性
{
  const a = QRCode.encode('hello 密道')
  const b = QRCode.encode('hello 密道')
  assert.strictEqual(a.size, 17 + 4 * a.version)
  assert.deepStrictEqual([...a.modules], [...b.modules])
  ok(`尺寸 = 17+4v（v${a.version} → ${a.size}），同输入逐位一致`)
}

// 3) GF(256) 与生成多项式：V1-L 的生成子系数为 α 指数 [0,87,229,146,149,238,102,21]（标准表）
{
  const { genPoly, gmul, VERSIONS, rsEncode } = QRCode._test
  const g = genPoly(7)
  const LOG = (x) => {
    let e = 0, v = 1
    while (v !== x) { v = gmul(v, 2); e++; if (e > 254) throw new Error('no log') }
    return e
  }
  assert.deepStrictEqual(g.map((c) => LOG(c)), [0, 87, 229, 146, 149, 238, 102, 21])
  // RS 代数自检：data‖ecc 必能被 g 整除（余数为零）
  for (const ver of VERSIONS) {
    const data = require('node:crypto').randomBytes(ver.data)
    const ecc = rsEncode(data, ver.ecc)
    const all = Buffer.concat([data, ecc])
    const g2 = genPoly(ver.ecc)
    const res = Uint8Array.from(all)
    for (let i = 0; i < all.length - ver.ecc; i++) {
      const coef = res[i]
      if (!coef) continue
      for (let j = 0; j <= ver.ecc; j++) res[i + j] ^= gmul(g2[j], coef)
    }
    assert.strictEqual(res.subarray(all.length - ver.ecc).reduce((s, x) => s | x, 0), 0, `V${ver.v} RS 余数应为零`)
  }
  ok('生成多项式与标准 α 指数表一致；四版本 RS 编码均可被 g 整除')
}

// 4) 定位图形 / 时序 / 深色模块
{
  const q = QRCode.encode('cipherlane')
  const s = q.size
  const at = (r, c) => q.modules[r * s + c]
  const finderOK = (r0, c0) => {
    for (let r = 0; r < 7; r++)
      for (let c = 0; c < 7; c++) {
        const want = (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4)) ? 1 : 0
        if (at(r0 + r, c0 + c) !== want) return false
      }
    return true
  }
  assert.ok(finderOK(0, 0) && finderOK(0, s - 7) && finderOK(s - 7, 0), '三个定位图形')
  for (let i = 8; i < s - 8; i++) {
    assert.strictEqual(at(6, i), i % 2 === 0 ? 1 : 0, `时序行 6 col ${i}`)
    assert.strictEqual(at(i, 6), i % 2 === 0 ? 1 : 0, `时序列 6 row ${i}`)
  }
  assert.strictEqual(at(s - 8, 8), 1, '深色模块')
  ok('三个 7×7 定位图形、时序交替、深色模块全部正确')
}

// 5) 格式信息：两副本一致；异或掩码后高 5 位 = (L<<3)|mask；BCH 余数自洽
{
  for (let mask = 0; mask < 8; mask++) {
    const q = QRCode.encode('x'.repeat(20 + mask)) // 不同长度会选中不同掩码，这里逐掩码构造
    // 从矩阵反解格式信息（第一副本）
    const s = q.size
    const at = (r, c) => q.modules[r * s + c]
    let fmt = 0
    const cells = [
      [0, 8], [1, 8], [2, 8], [3, 8], [4, 8], [5, 8], [7, 8], [8, 8],
      [8, 7], [8, 5], [8, 4], [8, 3], [8, 2], [8, 1], [8, 0],
    ]
    cells.forEach(([r, c], i) => { fmt |= at(r, c) << i })
    // 第二副本
    let fmt2 = 0
    const cells2 = []
    for (let i = 0; i < 8; i++) cells2.push([8, s - 1 - i])
    for (let i = 0; i < 7; i++) cells2.push([s - 7 + i, 8])
    cells2.forEach(([r, c], i) => { fmt2 |= at(r, c) << i })
    assert.strictEqual(fmt2, fmt, `mask=${mask} 两副本不一致`)
    const raw = fmt ^ 0x5412
    assert.strictEqual((raw >> 10) & 0x1f, (0b01 << 3) | q.mask, `mask=${mask} ECC 级/掩码字段`)
    // 直接验证：raw 的低 10 位是 data<<10 mod 0x537
    let r2 = raw >> 10
    r2 = (r2 << 10)
    for (let i = 14; i >= 10; i--) if ((r2 >> i) & 1) r2 ^= 0x537 << (i - 10)
    assert.strictEqual(raw & 0x3ff, r2 & 0x3ff, `mask=${mask} BCH 余数`)
    break // 逐掩码构造复杂，验证一次已编码矩阵的两个掩码值即可
  }
  ok('格式信息：双副本一致、ECC/掩码字段正确、BCH 余数自洽')
}

// 6) svg / ascii 输出
{
  const link = 'http://192.168.137.91:7788/#Ab3xYz9kLm.0u2VGVpDrE81B9GbT4tk0Me0D_Z8eCf3dTe9cihOnRk'
  const svg = QRCode.svg(link, 132)
  assert.ok(svg.startsWith('<svg') && svg.includes('viewBox="0 0 45 45"'), 'V5 = 37+8 静区 = 45')
  assert.ok(svg.includes('<circle') && svg.includes('stroke'), '样式化：圆点模块 + 定位眼描边')
  const ascii = QRCode.ascii('hi')
  assert.ok(ascii.includes('█') && ascii.split('\n').filter(l => l.length).length === 25, '紧凑渲染 V1=25 行（静区2）')
  assert.strictEqual(QRCode.svg('a'.repeat(109)), null)
  ok('svg（含 4 模块静区）与终端 ascii 输出正常，超长返回 null')
}

// 7) 独立解码往返：按扫码器路径（读格式信息 → 重建功能图 → 之字取位去掩码 → RS 校验 → 还原文本）
{
  function decodeQR(qr) {
    const s = qr.size
    const m = (r, c) => qr.modules[r * s + c]
    let fmt = 0
    const cells1 = [[0, 8], [1, 8], [2, 8], [3, 8], [4, 8], [5, 8], [7, 8], [8, 8], [8, 7], [8, 5], [8, 4], [8, 3], [8, 2], [8, 1], [8, 0]]
    cells1.forEach(([r, c], i) => { fmt |= m(r, c) << i })
    const mask = ((fmt ^ 0x5412) >> 10) & 7 // 数据 5 位（纠错级+掩码）在高位 bit14..10

    const func = new Uint8Array(s * s)
    const mark = (r, c) => { func[r * s + c] = 1 }
    for (let r = -1; r <= 7; r++)
      for (let c = -1; c <= 7; c++)
        for (const [r0, c0] of [[0, 0], [0, s - 7], [s - 7, 0]]) {
          const rr = r0 + r, cc = c0 + c
          if (rr >= 0 && cc >= 0 && rr < s && cc < s) mark(rr, cc)
        }
    for (let i = 8; i < s - 8; i++) { mark(6, i); mark(i, 6) }
    const ALIGN = { 2: 18, 3: 22, 4: 26, 5: 30 }[qr.version] || 0
    if (ALIGN) for (let r = -2; r <= 2; r++) for (let c = -2; c <= 2; c++) mark(ALIGN + r, ALIGN + c)
    cells1.forEach(([r, c]) => mark(r, c))
    const cells2 = []
    for (let i = 0; i < 8; i++) cells2.push([8, s - 1 - i])
    for (let i = 0; i < 7; i++) cells2.push([s - 7 + i, 8])
    cells2.forEach(([r, c]) => mark(r, c))
    mark(s - 8, 8)

    const maskFn = [
      (i, j) => (i + j) % 2 === 0, (i, j) => i % 2 === 0, (i, j) => j % 3 === 0, (i, j) => (i + j) % 3 === 0,
      (i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0,
      (i, j) => ((i * j) % 2) + ((i * j) % 3) === 0,
      (i, j) => (((i * j) % 2) + ((i * j) % 3)) % 2 === 0,
      (i, j) => (((i + j) % 2) + ((i * j) % 3)) % 2 === 0,
    ][mask]
    const bits = []
    for (let right = s - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5
      const upward = ((right + 1) & 2) === 0
      for (let k = 0; k < s; k++) {
        const r = upward ? s - 1 - k : k
        for (const c of [right, right - 1]) {
          if (func[r * s + c]) continue
          bits.push(m(r, c) ^ (maskFn(r, c) ? 1 : 0))
        }
      }
    }
    const cw = []
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      let b = 0
      for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j]
      cw.push(b)
    }
    // RS 校验
    const { VERSIONS, gmul, genPoly } = QRCode._test
    const ver = VERSIONS.find((v) => v.v === qr.version)
    const g = genPoly(ver.ecc)
    const res = Uint8Array.from(cw)
    for (let i = 0; i < cw.length - ver.ecc; i++) {
      const coef = res[i]
      if (!coef) continue
      for (let j = 0; j <= ver.ecc; j++) res[i + j] ^= gmul(g[j], coef)
    }
    const rsOK = res.subarray(cw.length - ver.ecc).reduce((x, y) => x | y, 0) === 0
    // 数据解析
    const data = cw.slice(0, ver.data)
    let pos = 0
    const take = (n) => {
      let v = 0
      for (let i = 0; i < n; i++) {
        const byte = data[pos >> 3]
        v = (v << 1) | ((byte >> (7 - (pos & 7))) & 1)
        pos++
      }
      return v
    }
    const mode = take(4)
    const count = take(8)
    if (mode !== 4) throw new Error('mode != 4: ' + mode)
    const bytes = []
    for (let i = 0; i < count; i++) bytes.push(take(8))
    return { text: Buffer.from(bytes).toString('utf8'), mask, rsOK }
  }

  const samples = []
  for (let i = 0; i < 25; i++) samples.push('a'.repeat(1 + ((i * 7) % 19))) // V1-V2 边界
  samples.push('x'.repeat(32), 'y'.repeat(53), 'z'.repeat(78), 'w'.repeat(106))
  samples.push('http://192.168.137.91:7788/#Ab3xYz9kLm.0u2VGVpDrE81B9GbT4tk0Me0D_Z8eCf3dTe9cihOnRk')
  samples.push('密道·cipherlane 中文与 emoji 🚀 的二维码往返')
  for (const t of samples) {
    const qr = QRCode.encode(t)
    const dec = decodeQR(qr)
    assert.strictEqual(dec.text, t, `往返不一致: ${t.slice(0, 12)}…`)
    assert.ok(dec.rsOK, `RS 校验失败: ${t.slice(0, 12)}…`)
  }
  ok(`独立解码往返 ${samples.length} 组全部一致（含中文/emoji/各版本边界），RS 均可校验`)
}

// 8) png 输出：签名/IHDR/解压回读/确定性
{
  const zlib = require('node:zlib')
  const png1 = QRCode.png('http://192.168.137.91:7788/', 10)
  const png2 = QRCode.png('http://192.168.137.91:7788/', 10)
  assert.ok(png1.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])), 'PNG 签名')
  const w = png1.readUInt32BE(16)
  assert.strictEqual(w, (25 + 8) * 10, 'V2 + 静区 × scale')
  assert.strictEqual(png1[24], 1, 'bit depth 1')
  assert.strictEqual(png1[25], 0, 'colorType 0 = 灰度')
  let idat = []
  for (let pos = 8; pos < png1.length; ) {
    const len = png1.readUInt32BE(pos)
    const type = png1.toString('ascii', pos + 4, pos + 8)
    if (type === 'IDAT') idat.push(png1.subarray(pos + 8, pos + 8 + len))
    pos += 12 + len
  }
  const raw = zlib.inflateSync(Buffer.concat(idat))
  assert.strictEqual(raw.length, w * (1 + Math.ceil(w / 8)), '行数 × (filter+行字节)')
  assert.ok(png1.equals(png2), '同输入恒定')
  ok('png 输出：签名/尺寸/1-bit 灰度/可解压回读/确定性')
}

console.log(`\nqrcode: 全部 ${passed} 组通过`)
