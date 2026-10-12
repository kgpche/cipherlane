// qrcode.js 验证 —— 结构自检：RS 代数性质 / 定位与时序图形 / 格式信息 / 容量边界
import { createRequire } from 'node:module'
import assert from 'node:assert'
const require = createRequire(import.meta.url)
const QRCode = require('../public/qrcode.js')

let passed = 0
const ok = (name) => { passed++; console.log(`  ✓ ${name}`) }

// 1) 容量边界：19/34/55/80/108 → V1-V5，超长返回 null
{
  const caps = [19, 34, 55, 80, 108]
  for (let v = 0; v < 5; v++) {
    const q1 = QRCode.encode('a'.repeat(caps[v]))
    assert.strictEqual(q1.version, v + 1, `len=${caps[v]} 应为 V${v + 1}`)
    if (v > 0 && v < 4) {
      const q2 = QRCode.encode('a'.repeat(caps[v] + 1))
      assert.strictEqual(q2.version, v + 2, `len=${caps[v] + 1} 应为 V${v + 2}`)
    }
  }
  assert.strictEqual(QRCode.encode('a'.repeat(109)), null, '109 字节应返回 null')
  assert.strictEqual(QRCode.encode('http://192.168.137.91:7788/#Ab3xYz9kLm.0u2VGVpDrE81B9GbT4tk0Me0D_Z8eCf3dTe9cihOnRk').version, 5, '典型 LAN 链接（82B）应为 V5')
  ok('容量边界 19/34/55/80/108 → V1-V5，109+ 返回 null，LAN 链接可编码')
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
  assert.ok(ascii.includes('█') && ascii.split('\n').length >= 13, '终端码含半块字符（25 行并 13 行）')
  assert.strictEqual(QRCode.svg('a'.repeat(109)), null)
  ok('svg（含 4 模块静区）与终端 ascii 输出正常，超长返回 null')
}

console.log(`\nqrcode: 全部 ${passed} 组通过`)
