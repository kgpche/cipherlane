/* cipherlane · avatar.js —— 设备几何头像（由 IP 确定性生成，无外部资源）
 *
 * 设计：Google/Material 风格的扁平几何 —— 纯色底上叠 3 层超大平涂形状
 * （三角形 / 圆形 / 正方形），形状比画布大、经裁切出血，实色填充、
 * 无渐变无透明无描边。形状逐层缩小并随意偏移旋转，构图干净直接。
 * 同一 IP 永远生成同一头像。
 * 兼容：浏览器挂载全局 Avatar；Node 下 module.exports（预览/测试用）。
 */
(function (global) {
  'use strict'

  // FNV-1a 32 位（视觉种子，非安全用途）
  function fnv1a(str) {
    let h = 0x811c9dc5
    for (let i = 0; i < str.length; i++) {
      h ^= str.codePointAt(i)
      h = Math.imul(h, 0x01000193) >>> 0
    }
    return h >>> 0
  }

  // Google Material 扁平色板（L 为感知亮度 0~1，用于对比度约束）
  const PALETTE = [
    { hex: '#4285F4', L: 0.55 }, // 蓝
    { hex: '#AECBFA', L: 0.83 }, // 浅蓝
    { hex: '#EA4335', L: 0.48 }, // 红
    { hex: '#F6AEA9', L: 0.84 }, // 浅粉
    { hex: '#FBBC04', L: 0.62 }, // 黄
    { hex: '#FDD663', L: 0.84 }, // 浅黄
    { hex: '#34A853', L: 0.50 }, // 绿
    { hex: '#81C995', L: 0.77 }, // 浅绿
    { hex: '#24C1E0', L: 0.63 }, // 青
    { hex: '#A142F4', L: 0.51 }, // 紫
    { hex: '#D7AEFB', L: 0.84 }, // 浅紫
    { hex: '#F9AB00', L: 0.60 }, // 橙
    { hex: '#5F6368', L: 0.36 }, // 灰
    { hex: '#202124', L: 0.11 }, // 近黑
    { hex: '#E8EAED', L: 0.90 }, // 浅灰
    { hex: '#1A73E8', L: 0.47 }, // 深蓝
  ]

  // 形状库（0..100 画布内定义，中心约 (50,50)）
  const SHAPES = [
    '<circle cx="50" cy="50" r="50"/>',
    '<rect x="0" y="0" width="100" height="100"/>',
    '<path d="M50 7 L100 93.6 H0 Z"/>', // 等边三角
  ]

  // 从色板挑一个与 avoid 项保持对比度的颜色
  function pickColor(h, salt, avoid) {
    for (let k = 0; k < PALETTE.length; k++) {
      const i = (h + salt + k * 7) % PALETTE.length
      if (avoid.some((a) => a === PALETTE[i].hex)) continue
      if (avoid.some((a) => Math.abs(PALETTE[i].L - a.L) < 0.14 && a.strict)) continue
      return PALETTE[i]
    }
    return PALETTE[(h + salt) % PALETTE.length]
  }

  // svg(seed, size) → 内联 SVG 字符串
  function svg(seed, size = 44) {
    const h = fnv1a('cipherlane·' + seed)

    // 底色 → 三层形状色（相邻层不重复，首层与底色保持明度差）
    const bg = PALETTE[h % PALETTE.length]
    const c1 = pickColor(h, 5, [{ hex: bg.hex, L: bg.L, strict: true }])
    const c2 = pickColor(h, 11, [{ hex: bg.hex, L: bg.L }, { hex: c1.hex, L: c1.L, strict: true }])
    const c3 = pickColor(h, 17, [{ hex: bg.hex, L: bg.L }, { hex: c1.hex, L: c1.L }, { hex: c2.hex, L: c2.L }])

    // 三层：1.2×（出血）/ 0.8× / 0.4×；偏移上限按层收紧，
    // 保证形状始终覆盖画布中心，不会整体跑出画面
    const layers = [
      { s: 1.2, dx: 30, dy: 28, color: c1 },
      { s: 0.8, dx: 34, dy: 32, color: c2 },
      { s: 0.4, dx: 30, dy: 28, color: c3 },
    ]
    const body = layers
      .map((L, i) => {
        const shape = SHAPES[(h >>> (11 + i * 3)) % 3]
        const cx = 50 + (((h >>> (i * 8 + 3)) % (2 * L.dx + 1)) - L.dx)
        const cy = 50 + (((h >>> (i * 8 + 21)) % (2 * L.dy + 1)) - L.dy)
        const rot = (h >>> (i * 5 + 27)) % 360
        return `<g transform="translate(${cx} ${cy}) rotate(${rot}) scale(${L.s}) translate(-50 -50)">`
          + shape.replace('/>', ` fill="${L.color.hex}"/>`)
          + `</g>`
      })
      .join('')

    return `<svg class="avatar" width="${size}" height="${size}" viewBox="0 0 100 100" aria-hidden="true">`
      + `<rect width="100" height="100" fill="${bg.hex}"/>${body}</svg>`
  }

  const api = { svg, fnv1a, _test: { PALETTE } }
  if (typeof module !== 'undefined' && module.exports) module.exports = api
  else global.Avatar = api
})(typeof self !== 'undefined' ? self : globalThis)
