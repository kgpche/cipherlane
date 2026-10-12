/* cipherlane · crypto-worker.js —— 分片加解密 Worker（大文件传输不再卡主线程/进度条）
 *
 * 安全上下文用 worker 内 crypto.subtle；非安全上下文 importScripts 纯 JS AES-GCM。
 * 协议：{id, op:'seal'|'unseal', key, data} → {id, ok, data}（data 为 ArrayBuffer，回传零拷贝）
 */
'use strict'
importScripts('/aesgcm.js')

const subtle = typeof crypto !== 'undefined' && crypto.subtle ? crypto.subtle : null

async function seal(key, data) {
  if (subtle) {
    const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt'])
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, k, data))
    const out = new Uint8Array(12 + ct.length)
    out.set(iv, 0)
    out.set(ct, 12)
    return out
  }
  return AESGCM.seal(key, data)
}

async function unseal(key, packed) {
  if (subtle) {
    const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt'])
    const iv = packed.subarray(0, 12)
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv }, k, packed.subarray(12)))
  }
  return AESGCM.open(key, packed)
}

self.onmessage = async (e) => {
  const { id, op, key, data } = e.data
  try {
    const out = op === 'seal'
      ? await seal(new Uint8Array(key), new Uint8Array(data))
      : await unseal(new Uint8Array(key), new Uint8Array(data))
    self.postMessage({ id, ok: true, data: out }, [out.buffer])
  } catch (err) {
    self.postMessage({ id, ok: false, error: String((err && err.message) || err) })
  }
}
