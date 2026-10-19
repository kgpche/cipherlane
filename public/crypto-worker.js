/* cipherlane · crypto-worker.js —— 分片加解密 Worker（大文件传输不再卡主线程/进度条）
 *
 * 安全上下文用 worker 内 crypto.subtle；非安全上下文 importScripts 纯 JS AES-GCM。
 * 协议：{id, op:'seal'|'unseal', key, data, aad?} → {id, ok, data}
 *   - data/aad 为 ArrayBuffer；data 回传时零拷贝转移（aad 可选，null/缺省 = 旧无 AAD 格式）
 *   - aad 用于协议 v2 的分片位置绑定；旧发送端（v1）不带 aad
 */
'use strict'
importScripts('/aesgcm.js')

const subtle = typeof crypto !== 'undefined' && crypto.subtle ? crypto.subtle : null

// aad: ArrayBuffer | null → Uint8Array | null（WebCrypto 与纯 JS 都需要字节视图）
function aadBytes(aad) {
  if (!aad) return null
  return aad instanceof Uint8Array ? aad : new Uint8Array(aad)
}

async function seal(key, data, aad) {
  const A = aadBytes(aad)
  if (subtle) {
    const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt'])
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const params = { name: 'AES-GCM', iv }
    if (A) params.additionalData = A
    const ct = new Uint8Array(await subtle.encrypt(params, k, data))
    const out = new Uint8Array(12 + ct.length)
    out.set(iv, 0)
    out.set(ct, 12)
    return out
  }
  return AESGCM.seal(key, data, A)
}

async function unseal(key, packed, aad) {
  const A = aadBytes(aad)
  if (subtle) {
    const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt'])
    const iv = packed.subarray(0, 12)
    const params = { name: 'AES-GCM', iv }
    if (A) params.additionalData = A
    return new Uint8Array(await subtle.decrypt(params, k, packed.subarray(12)))
  }
  return AESGCM.open(key, packed, A)
}

self.onmessage = async (e) => {
  const { id, op, key, data, aad } = e.data
  try {
    const out = op === 'seal'
      ? await seal(new Uint8Array(key), new Uint8Array(data), aad)
      : await unseal(new Uint8Array(key), new Uint8Array(data), aad)
    self.postMessage({ id, ok: true, data: out }, [out.buffer])
  } catch (err) {
    self.postMessage({ id, ok: false, error: String((err && err.message) || err) })
  }
}
