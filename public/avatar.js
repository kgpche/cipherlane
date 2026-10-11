/* cipherlane · avatar.js —— 设备几何头像（由 IP 确定性生成，无外部资源）
 *
 * 设计：Google/Material 风格的扁平几何 —— 纯色底上叠 3 层超大平涂形状
 * （三角形 / 圆形 / 正方形），形状比画布大、经裁切出血，实色填充、
 * 无渐变无透明无描边。同一 IP 永远生成同一头像。
 *
 * 稳定性约束：主形状（第 1 层）偏移小、永远主导画面；形状色只用彩色系
 * （灰/黑仅作底色），避免小尺寸下的"黑块/空底"观感；几何参数与配色
 * 用不同哈希源，互不相关。
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
  // 形状只用彩色系；灰/浅灰仅可用作底色
  const CHROMA = [
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
    { hex: '#1A73E8', L: 0.47 }, // 深蓝
  ]
  const BG_POOL = CHROMA.concat([
    { hex: '#5F6368', L: 0.36 }, // 灰
    { hex: '#E8EAED', L: 0.90 }, // 浅灰
  ])

  // 形状库（0..100 画布内定义，中心 (50,50)）
  const SHAPES = [
    '<circle cx="50" cy="50" r="50"/>',
    '<rect x="0" y="0" width="100" height="100"/>',
    '<path d="M50 7 L100 93.6 H0 Z"/>', // 等边三角
  ]

  // 从色板挑一个与 avoid 项保持对比度的颜色
  function pick(pool, base, salt, avoid, strictIdx) {
    for (let k = 0; k < pool.length; k++) {
      const i = (base + salt + k * 7) % pool.length
      const c = pool[i]
      if (avoid.some((a) => a.hex === c.hex)) continue
      if (strictIdx >= 0 && Math.abs(c.L - avoid[strictIdx].L) < 0.14) continue
      return c
    }
    return pool[(base + salt) % pool.length]
  }

  // svg(seed, size) → 内联 SVG 字符串
  function svg(seed, size = 44) {
    // 三个独立哈希源：配色 / 形状+x 偏移 / y 偏移+旋转，位段互不重叠
    const hC = fnv1a('cipherlane·' + seed)
    const hX = fnv1a('cipherlane²' + seed)
    const hY = fnv1a('cipherlane³' + seed)

    // 配色：底色（可含灰）→ 三层彩色形状色（相邻层明度错开）
    const bg = BG_POOL[hC % BG_POOL.length]
    const c1 = pick(CHROMA, hC, 5, [bg], 0)
    const c2 = pick(CHROMA, hC, 11, [bg, c1], 1)
    const c3 = pick(CHROMA, hC, 17, [bg, c1, c2], -1)

    // 三层：1.2×（出血，主形状偏移小）/ 0.8× / 0.4×
    const layers = [
      { s: 1.2, d: 18, color: c1 },
      { s: 0.8, d: 24, color: c2 },
      { s: 0.4, d: 26, color: c3 },
    ]
    const body = layers
      .map((L, i) => {
        const shape = SHAPES[(hX >>> (i * 2)) % 3]                    // 位 0-5
        const cx = 50 + (((hX >>> (6 + i * 6)) % (2 * L.d + 1)) - L.d) // 位 6-23
        const cy = 50 + (((hY >>> (i * 6)) % (2 * L.d + 1)) - L.d)     // 位 0-17
        const rot = ((hY >>> (18 + i * 4)) % 12) * 30                  // 位 18-29，30° 步进
        return `<g transform="translate(${cx} ${cy}) rotate(${rot}) scale(${L.s}) translate(-50 -50)">`
          + shape.replace('/>', ` fill="${L.color.hex}"/>`)
          + `</g>`
      })
      .join('')

    return `<svg class="avatar" width="${size}" height="${size}" viewBox="0 0 100 100" aria-hidden="true">`
      + `<rect width="100" height="100" fill="${bg.hex}"/>${body}</svg>`
  }

  // placeholder(size) → 中性占位（拿到真实 IP 前显示，避免"头像变脸"错觉）
  function placeholder(size = 44) {
    return `<svg class="avatar" width="${size}" height="${size}" viewBox="0 0 100 100" aria-hidden="true">`
      + `<rect width="100" height="100" fill="#3c4658"/>`
      + `<circle cx="50" cy="50" r="26" fill="#4c5870"/>`
      + `</svg>`
  }

  const api = { svg, placeholder, fnv1a, _test: { CHROMA, BG_POOL } }
  if (typeof module !== 'undefined' && module.exports) module.exports = api
  else global.Avatar = api
})(typeof self !== 'undefined' ? self : globalThis)
