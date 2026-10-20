//! 零 Node 密码学测试（v1.0）：Rust 测试启动 Rust server + headless Chrome，
//! 经 CDP 在前端页面（index.html 已加载 aesgcm/sha256/x25519/qrcode/avatar 全局脚本）
//! 执行断言；期望值用 Rust crates（aes-gcm / sha2 / x25519-dalek）计算，
//! 等价于原 test/*.test.mjs 里 node:crypto 交叉验证的角色。
//!
//! 覆盖映射（原 5 套 → 本文件 5 个 #[test]）：
//!   aesgcm.test.mjs  → aesgcm_against_rustcrypto（S-box/GHASH 结构、0B~1MiB 逐字节、
//!                       AAD 交叉、篡改/错位拒绝、空 AAD==无 AAD、AAD 错位红测）
//!   sha256.test.mjs  → sha256_against_sha2（FIPS 向量 + 块边界 + 随机 + 非法输入）
//!   x25519.test.mjs  → x25519_against_dalek（RFC7748 向量、随机双向、全零/小阶点/长度拒绝、sessionKey）
//!   qrcode.test.mjs  → qrcode_structure（容量/RS/定位/格式信息/svg+ascii/独立解码往返）
//!   avatar.test.mjs  → avatar_structure（确定性/差异性/色板/明度差/占位）
//!
//! 全部测试以 common::serial() 串行；无 Chrome 时打印跳过并正常返回。

mod common;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPub, StaticSecret};

// ============================================================
// 测试辅助
// ============================================================
/// 与页面内 `__prng` 完全一致的确定性字节流（xorshift32）：
/// 让两侧各自生成同样的明文/密钥，避免在 CDP 表达式里搬运大 buffer。
struct Prng(u32);
impl Prng {
    fn new(seed: u32) -> Self {
        Prng(seed)
    }
    fn next_u32(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x.wrapping_shl(13);
        x ^= x >> 17;
        x ^= x.wrapping_shl(5);
        self.0 = x;
        x
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next_u32() >> 24) as u8).collect()
    }
}

fn boot() -> Option<(common::Chrome, common::Cdp, common::Page, common::Server)> {
    let chrome = common::launch_chrome()?;
    let server = common::spawn_server(&[]);
    let mut cdp = common::Cdp::connect(&chrome.ws_url);
    let page = cdp.new_page();
    let url = format!("{}/", server.url());
    cdp.navigate(&page, &url);
    cdp.wait_for(
        &page,
        "document.readyState==='complete' && typeof AESGCM==='object' && typeof SHA256==='object' && typeof X25519==='object' && typeof QRCode==='object' && typeof Avatar==='object'",
        20000,
        "前端密码学脚本加载",
    );
    let ok = cdp.eval(&page, HELPERS);
    assert_eq!(ok.as_bool(), Some(true), "注入页面测试辅助函数失败");
    Some((chrome, cdp, page, server))
}

fn jstr(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

fn assert_true(v: &Value, key: &str, what: &str) {
    assert_eq!(v.get(key).and_then(|x| x.as_bool()), Some(true), "{what} 失败: {v}");
}

fn hex(bytes: &[u8]) -> String {
    common::hex(bytes)
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn rc_encrypt(key: &[u8], iv: &[u8], pt: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let cipher = Aes256Gcm::new_from_slice(key).expect("AES key");
    let ct_tag = cipher
        .encrypt(Nonce::from_slice(iv), Payload { msg: pt, aad })
        .expect("AES-GCM 加密失败");
    let n = ct_tag.len() - 16;
    (ct_tag[..n].to_vec(), ct_tag[n..].to_vec())
}

fn rc_decrypt(key: &[u8], iv: &[u8], ct: &[u8], tag: &[u8], aad: &[u8]) -> Result<Vec<u8>, ()> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("AES key");
    let mut ct_tag = ct.to_vec();
    ct_tag.extend_from_slice(tag);
    cipher
        .decrypt(Nonce::from_slice(iv), Payload { msg: &ct_tag, aad })
        .map_err(|_| ())
}

fn x_pub(seed: &[u8; 32]) -> [u8; 32] {
    XPub::from(&StaticSecret::from(*seed)).to_bytes()
}
fn x_dh(seed: &[u8; 32], pub_key: &[u8; 32]) -> [u8; 32] {
    StaticSecret::from(*seed).diffie_hellman(&XPub::from(*pub_key)).to_bytes()
}

// ============================================================
// 页面辅助函数（与 Prng 对齐的确定性数据源 + b64/hex）
// ============================================================
const HELPERS: &str = r###"
(() => {
  globalThis.__hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
  globalThis.__unhex = (s) => { const o = new Uint8Array(s.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(s.substr(i * 2, 2), 16); return o; };
  globalThis.__b64 = (u8) => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
  globalThis.__unb64 = (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const b = atob(s); const o = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) o[i] = b.charCodeAt(i); return o; };
  globalThis.__prng = (seed) => { let x = seed >>> 0; return (n) => { const out = new Uint8Array(n); for (let i = 0; i < n; i++) { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; out[i] = x >>> 24; } return out; }; };
  // 页面加密：返回密文 b64 + tag hex（明文由 __prng 两侧同构生成）
  globalThis.__aesCase = (keyHex, ivHex, ptSeed, ptLen, aadSeed, aadLen) => {
    const key = __unhex(keyHex), iv = __unhex(ivHex), pt = __prng(ptSeed)(ptLen);
    const aad = aadLen > 0 ? __prng(aadSeed)(aadLen) : undefined;
    const r = AESGCM.encrypt(key, iv, pt, aad);
    return { ct: __b64(r.ct), tag: __hex(r.tag) };
  };
  // 页面解密 RustCrypto 产出的 IV‖ct‖tag，并核对明文
  globalThis.__aesOpen = (keyHex, packedB64, aadSeed, aadLen, ptSeed, ptLen) => {
    const key = __unhex(keyHex), packed = __unb64(packedB64);
    const aad = aadLen > 0 ? __prng(aadSeed)(aadLen) : undefined;
    const pt = __prng(ptSeed)(ptLen);
    try {
      const out = AESGCM.open(key, packed, aad);
      return { ok: __hex(out) === __hex(pt), len: out.length };
    } catch (e) { return { ok: false, len: -1, err: String(e.message) }; }
  };
  // 页面 seal（随机 IV）→ Rust 侧解密核对
  globalThis.__aesSeal = (keyHex, ptSeed, ptLen, aadSeed, aadLen) => {
    const key = __unhex(keyHex), pt = __prng(ptSeed)(ptLen);
    const aad = aadLen > 0 ? __prng(aadSeed)(aadLen) : undefined;
    return __b64(AESGCM.seal(key, pt, aad));
  };
  globalThis.__shaBatch = (cases) => cases.map((c) => __hex(SHA256.hash(__prng(c[1])(c[0]))));
  // 一批 X25519：pubs = publicFromSecret(sks)；shared = dh(sks[i], pks[i])
  globalThis.__xBatch = (sksHex, pksHex) => {
    const pubs = [], shared = [];
    for (const s of sksHex) pubs.push(__hex(X25519.publicFromSecret(__unhex(s))));
    for (let i = 0; i < sksHex.length; i++) shared.push(__hex(X25519.dh(__unhex(sksHex[i]), __unhex(pksHex[i]))));
    return { pubs, shared };
  };
  globalThis.__xDh = (skHex, pkHex) => __hex(X25519.dh(__unhex(skHex), __unhex(pkHex)));
  globalThis.__xPub = (skHex) => __hex(X25519.publicFromSecret(__unhex(skHex)));
  globalThis.__session = (sharedHex, aHex, bHex, room) => __hex(X25519.sessionKey(__unhex(sharedHex), __unhex(aHex), __unhex(bHex), room));
  return true;
})();
"###;

// ============================================================
// 1) AES-256-GCM：结构 + 0B~1MiB 与 RustCrypto 逐字节等价 + AAD + 红测
// ============================================================
#[test]
fn aesgcm_against_rustcrypto() {
    let _g = common::serial();
    let Some((_chrome, mut cdp, page, _server)) = boot() else {
        println!("  – 未找到 Chrome/Chromium（可用 CHROME_BIN 指定），跳过 aesgcm 组");
        return;
    };

    // 1a) S-box 标准值 + GHASH 4-bit/8-bit 表 × 参考实现交叉（页面内 100 组）
    let structure = cdp.eval(
        &page,
        r###"(() => {
          const S = AESGCM._test.SBOX;
          let ghashOk = true;
          for (let i = 0; i < 100; i++) {
            const X = __prng(1000 + i * 7)(16), H = __prng(9000 + i * 11)(16);
            const out = new Uint8Array(16);
            AESGCM._test.gfMulT(X, AESGCM._test.buildTables(H), out);
            const ref = AESGCM._test.gfMulRef(X, H);
            if (__hex(out) !== __hex(ref)) { ghashOk = false; break; }
            AESGCM._test.gfMulT8(X, AESGCM._test.buildTables8(H), out);
            if (__hex(out) !== __hex(ref)) { ghashOk = false; break; }
          }
          return {
            sbox: __hex(Uint8Array.from([S[0], S[1], S[2], S[3], S[0x53], S[0xff]])),
            ghashOk, te0: AESGCM._test.TE0.length,
          };
        })()"###,
    );
    assert_eq!(
        structure.get("sbox").and_then(|v| v.as_str()),
        Some("637c777bed16"),
        "S-box 前几项应与 FIPS-197 一致: {structure}"
    );
    assert_true(&structure, "ghashOk", "GHASH 4-bit/8-bit 表 × 参考实现");
    assert_eq!(structure.get("te0").and_then(|v| v.as_u64()), Some(256), "T-table TE0 应为 256 项");
    println!("  ✓ S-box 与 FIPS-197 一致；GHASH 表 × 参考实现 100 组一致；TE0=256");

    // 1b) 0B~1MiB 与 RustCrypto(aes-gcm) 逐字节等价 + 双向解密
    let cases: &[(usize, usize)] = &[
        (0, 0), (1, 0), (15, 0), (16, 0), (17, 0), (31, 0), (32, 0), (33, 0),
        (255, 0), (4096, 0), (65537, 0), (1024 * 1024, 0),
        (0, 1), (1, 1), (1024, 1), (1024, 16), (1024, 17), (1024, 32),
        (1024, 255), (65537, 32), (1024 * 1024, 32),
    ];
    for &(len, aad_len) in cases {
        let key = common::random_bytes(32);
        let iv = common::random_bytes(12);
        let seed = rand_u32();
        let mut pt = Prng::new(seed).bytes(len);
        let aad = if aad_len > 0 { Prng::new(seed ^ 0xA5A5_5A5A).bytes(aad_len) } else { Vec::new() };
        let (rc_ct, rc_tag) = rc_encrypt(&key, &iv, &pt, &aad);
        let aad_seed = seed ^ 0xA5A5_5A5A;

        // 页面 AESGCM.encrypt ≡ RustCrypto
        let expr = format!(
            "__aesCase({}, {}, {}, {}, {}, {})",
            jstr(&hex(&key)), jstr(&hex(&iv)), seed, len, aad_seed, aad_len
        );
        let got = cdp.eval(&page, &expr);
        let page_ct = common::from_b64u(got.get("ct").and_then(|v| v.as_str()).expect("ct"));
        let page_tag = unhex(got.get("tag").and_then(|v| v.as_str()).expect("tag"));
        assert_eq!(page_ct, rc_ct, "AESGCM ct 与 RustCrypto 不一致 len={len} aad={aad_len}");
        assert_eq!(page_tag, rc_tag, "AESGCM tag 与 RustCrypto 不一致 len={len} aad={aad_len}");

        // RustCrypto 加密 → 页面 AESGCM.open 解密核对
        if len <= 65537 {
            let mut packed = iv.clone();
            packed.extend_from_slice(&rc_ct);
            packed.extend_from_slice(&rc_tag);
            let expr = format!(
                "__aesOpen({}, {}, {}, {}, {}, {})",
                jstr(&hex(&key)), jstr(&common::b64u(&packed)), aad_seed, aad_len, seed, len
            );
            let v = cdp.eval(&page, &expr);
            assert_true(&v, "ok", &format!("页面解密 RustCrypto 密文 len={len} aad={aad_len}"));
        }

        // 页面 seal（随机 IV）→ RustCrypto 解密核对
        if len <= 65537 {
            let expr = format!(
                "__aesSeal({}, {}, {}, {}, {})",
                jstr(&hex(&key)), seed, len, aad_seed, aad_len
            );
            let seal_b64 = cdp.eval(&page, &expr).as_str().unwrap_or("").to_string();
            let sealed = common::from_b64u(&seal_b64);
            assert!(sealed.len() >= 28, "seal 输出过短 len={len}");
            let s_iv = &sealed[..12];
            let s_ct = &sealed[12..sealed.len() - 16];
            let s_tag = &sealed[sealed.len() - 16..];
            let pt2 = rc_decrypt(&key, s_iv, s_ct, s_tag, &aad)
                .unwrap_or_else(|_| panic!("RustCrypto 无法解密页面 seal 输出 len={len} aad={aad_len}"));
            assert_eq!(pt2, pt, "页面 seal → RustCrypto open 明文不一致 len={len}");
        }
        if len == 0 {
            assert!(pt.is_empty());
        }
        pt.clear();
    }
    println!("  ✓ 0B~1MiB（含 AAD 1~255B）与 RustCrypto 逐字节一致；双向解密一致");

    // 1c) 空 AAD 必须等价于无 AAD（旧线上格式逐字节不变）
    let empty_eq = cdp.eval(
        &page,
        r###"(() => {
          const key = __prng(777)(32), iv = __prng(778)(12), pt = __prng(779)(4096);
          const a = AESGCM.encrypt(key, iv, pt);
          const b = AESGCM.encrypt(key, iv, pt, new Uint8Array(0));
          return __hex(a.ct) === __hex(b.ct) && __hex(a.tag) === __hex(b.tag);
        })()"###,
    );
    assert_eq!(empty_eq.as_bool(), Some(true), "空 AAD 必须等价于无 AAD");
    println!("  ✓ 空 AAD 与无 AAD 的 ct/tag 逐字节相同（旧格式不变）");

    // 1d) AAD 红测证明：同一密文
    //     ① 用正确 AAD 可解；② 按旧实现（无 AAD）解必须失败；③ 错位 AAD 必须失败；
    //     ④ 篡改 tag/ct 必须失败。
    let red = cdp.eval(
        &page,
        r###"(() => {
          const key = __prng(4242)(32), iv = __prng(4243)(12), pt = __prng(4244)(64);
          const aad = __prng(4245)(17);
          const r = AESGCM.encrypt(key, iv, pt, aad);
          const packed = new Uint8Array(12 + r.ct.length + 16);
          packed.set(iv, 0); packed.set(r.ct, 12); packed.set(r.tag, 12 + r.ct.length);
          const res = { ok: false, noAadRejected: false, badAadRejected: false, badTagRejected: false, badCtRejected: false };
          try { res.ok = __hex(AESGCM.open(key, packed, aad)) === __hex(pt); } catch {}
          // 旧实现（无 AAD 路径）会把这些密文当合法数据 → 现在必须拒绝（红测）
          try { AESGCM.open(key, packed); res.noAadRejected = false; } catch { res.noAadRejected = true; }
          // 错位 AAD（等价"分片位置被掉包"）必须拒绝
          const wrong = Uint8Array.from(aad); wrong[0] ^= 1;
          try { AESGCM.open(key, packed, wrong); res.badAadRejected = false; } catch { res.badAadRejected = true; }
          const t = Uint8Array.from(packed); t[t.length - 1] ^= 1;
          try { AESGCM.open(key, t, aad); res.badTagRejected = false; } catch { res.badTagRejected = true; }
          const c = Uint8Array.from(packed); c[12] ^= 1;
          try { AESGCM.open(key, c, aad); res.badCtRejected = false; } catch { res.badCtRejected = true; }
          return res;
        })()"###,
    );
    assert_true(&red, "ok", "AAD 正确时解密");
    assert_true(&red, "noAadRejected", "旧无 AAD 路径必须拒绝带 AAD 的密文（红测）");
    assert_true(&red, "badAadRejected", "AAD 错位必须拒绝（红测）");
    assert_true(&red, "badTagRejected", "tag 篡改必须拒绝");
    assert_true(&red, "badCtRejected", "密文篡改必须拒绝");

    // RustCrypto 侧同样证明：无 AAD / 错位 AAD 解不开
    let key = common::random_bytes(32);
    let iv = common::random_bytes(12);
    let pt = b"red-test-plaintext";
    let aad = b"cipherlane/chunk/v2|Ab3xYz9kLm|7";
    let (ct, tag) = rc_encrypt(&key, &iv, pt, aad);
    assert!(rc_decrypt(&key, &iv, &ct, &tag, aad).is_ok());
    assert!(rc_decrypt(&key, &iv, &ct, &tag, b"").is_err(), "无 AAD 解密必须失败（旧实现红）");
    assert!(
        rc_decrypt(&key, &iv, &ct, &tag, b"cipherlane/chunk/v2|Ab3xYz9kLm|8").is_err(),
        "错位 index 的 AAD 必须失败（旧实现红）"
    );
    println!("  ✓ AAD 红测：旧无 AAD 路径/错位 AAD 均被拒（页面与 RustCrypto 两侧各证一次）");
}

fn rand_u32() -> u32 {
    use rand::RngCore;
    rand::rngs::OsRng.next_u32()
}

// ============================================================
// 2) SHA-256：FIPS 向量 + 块边界 + 随机 + 非法输入
// ============================================================
#[test]
fn sha256_against_sha2() {
    let _g = common::serial();
    let Some((_chrome, mut cdp, page, _server)) = boot() else {
        println!("  – 未找到 Chrome/Chromium（可用 CHROME_BIN 指定），跳过 sha256 组");
        return;
    };

    // 2a) FIPS 180-4 标准向量
    let vectors: &[(&str, &str)] = &[
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];
    for &(msg, want) in vectors {
        let expr = format!(
            "__hex(SHA256.hash(new TextEncoder().encode({})))",
            jstr(msg)
        );
        let got = cdp.eval(&page, &expr).as_str().unwrap_or("").to_string();
        assert_eq!(got, want, "FIPS 向量不符: {}", &msg[..msg.len().min(12)]);
        let mut h = Sha256::new();
        h.update(msg.as_bytes());
        assert_eq!(hex(&h.finalize()), want, "Rust sha2 向量自检");
    }
    // 百万次 'a'
    let got = cdp
        .eval(&page, "__hex(SHA256.hash(new TextEncoder().encode('a'.repeat(1000000))))")
        .as_str()
        .unwrap_or("")
        .to_string();
    assert_eq!(got, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "百万 a 向量");
    println!("  ✓ FIPS 180-4 向量（空串/abc/448bit/百万 a）");

    // 2b) 块边界 + 200 组随机长度：页面纯 JS SHA256 ≡ Rust sha2
    let mut lens: Vec<usize> = vec![
        0, 1, 2, 31, 32, 33, 54, 55, 56, 57, 63, 64, 65, 111, 112, 113, 119, 120, 127, 128, 129,
        255, 256, 1000, 4095, 4096, 65536,
    ];
    for _ in 0..500 {
        lens.push((rand_u32() % 8192) as usize);
    }
    let mut cases = Vec::new();
    let mut expected = Vec::new();
    for &len in &lens {
        let seed = rand_u32();
        let buf = Prng::new(seed).bytes(len);
        let mut h = Sha256::new();
        h.update(&buf);
        expected.push(hex(&h.finalize()));
        cases.push(json!([len, seed]));
    }
    let expr = format!("__shaBatch({})", serde_json::to_string(&cases).unwrap());
    let got = cdp.eval(&page, &expr);
    let arr = got.as_array().expect("shaBatch 应返回数组");
    assert_eq!(arr.len(), expected.len(), "shaBatch 返回数量不符");
    for (i, (want, got)) in expected.iter().zip(arr.iter()).enumerate() {
        assert_eq!(got.as_str(), Some(want.as_str()), "SHA256 不一致 i={i} len={}", lens[i]);
    }
    println!("  ✓ 块边界 + 500 组随机长度与 Rust sha2 逐字节一致（共 {} 组）", lens.len());

    // 2c) 非法输入必须抛错
    let bad = cdp.eval(
        &page,
        "(() => { try { SHA256.hash('不是字节'); return false; } catch (e) { return /Uint8Array/.test(String(e.message)); } })()",
    );
    assert_eq!(bad.as_bool(), Some(true), "非 Uint8Array 输入应被拒绝");
    println!("  ✓ 非 Uint8Array 输入被拒绝");
}

// ============================================================
// 3) X25519：RFC7748 向量 + 随机双向等价 + 全零/小阶点/长度拒绝 + sessionKey
// ============================================================
#[test]
fn x25519_against_dalek() {
    let _g = common::serial();
    let Some((_chrome, mut cdp, page, _server)) = boot() else {
        println!("  – 未找到 Chrome/Chromium（可用 CHROME_BIN 指定），跳过 x25519 组");
        return;
    };

    // 3a) RFC 7748 §5.2 标量乘向量
    let vecs: &[(&str, &str, &str)] = &[
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
    ];
    for &(sk, u, want) in vecs {
        let expr = format!("__xDh({}, {})", jstr(sk), jstr(u));
        let got = cdp.eval(&page, &expr).as_str().unwrap_or("").to_string();
        assert_eq!(got, want, "RFC7748 §5.2 向量不符");
        let sk_bytes = unhex(sk);
        let u_bytes = unhex(u);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a.copy_from_slice(&sk_bytes);
        b.copy_from_slice(&u_bytes);
        assert_eq!(hex(&x_dh(&a, &b)), want, "dalek 侧向量自检");
    }
    // 3b) RFC 7748 §6.1 Alice/Bob
    let a_sk = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    let a_pk = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    let b_sk = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    let b_pk = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    let expr = format!("__xPub({})", jstr(a_sk));
    assert_eq!(cdp.eval(&page, &expr).as_str(), Some(a_pk), "Alice 公钥");
    let expr = format!("__xPub({})", jstr(b_sk));
    assert_eq!(cdp.eval(&page, &expr).as_str(), Some(b_pk), "Bob 公钥");
    let expr = format!("__xDh({}, {})", jstr(a_sk), jstr(b_pk));
    assert_eq!(cdp.eval(&page, &expr).as_str(), Some(shared), "Alice→shared");
    let expr = format!("__xDh({}, {})", jstr(b_sk), jstr(a_pk));
    assert_eq!(cdp.eval(&page, &expr).as_str(), Some(shared), "Bob→shared");
    println!("  ✓ RFC 7748 §5.2 标量乘 + §6.1 Alice/Bob 向量");

    // 3c) 随机双向：页面纯 JS X25519 ≡ dalek（公钥 + 双向共享密钥，200 组）
    let mut seeds = Vec::new();
    let mut peers = Vec::new();
    let mut rust_pubs = Vec::new();
    let mut rust_peer_pubs = Vec::new();
    for _ in 0..200 {
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&common::random_bytes(32));
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&common::random_bytes(32));
        seeds.push(hex(&sk));
        peers.push(hex(&pk));
        rust_pubs.push(hex(&x_pub(&sk)));
        rust_peer_pubs.push(hex(&x_pub(&pk)));
    }
    let expr = format!(
        "__xBatch({}, {})",
        serde_json::to_string(&seeds).unwrap(),
        serde_json::to_string(&rust_peer_pubs).unwrap()
    );
    let batch = cdp.eval(&page, &expr);
    let got_pubs = batch.get("pubs").and_then(|v| v.as_array()).expect("pubs");
    let got_shared = batch.get("shared").and_then(|v| v.as_array()).expect("shared");
    for i in 0..seeds.len() {
        assert_eq!(got_pubs[i].as_str(), Some(rust_pubs[i].as_str()), "随机公钥不一致 i={i}");
        let sk = unhex(&seeds[i]);
        let mut a = [0u8; 32];
        a.copy_from_slice(&sk);
        let peer = unhex(&rust_peer_pubs[i]);
        let mut b = [0u8; 32];
        b.copy_from_slice(&peer);
        assert_eq!(got_shared[i].as_str(), Some(hex(&x_dh(&a, &b)).as_str()), "共享密钥不一致 i={i}");
    }
    // 反向：页面以 peer 私钥 × Rust 公钥
    let expr = format!(
        "__xBatch({}, {})",
        serde_json::to_string(&peers).unwrap(),
        serde_json::to_string(&rust_pubs).unwrap()
    );
    let batch2 = cdp.eval(&page, &expr);
    let got_shared2 = batch2.get("shared").and_then(|v| v.as_array()).expect("shared2");
    for i in 0..seeds.len() {
        let peer = unhex(&peers[i]);
        let mut a = [0u8; 32];
        a.copy_from_slice(&peer);
        let pub_i = unhex(&rust_pubs[i]);
        let mut b = [0u8; 32];
        b.copy_from_slice(&pub_i);
        assert_eq!(got_shared2[i].as_str(), Some(hex(&x_dh(&a, &b)).as_str()), "反向共享密钥不一致 i={i}");
    }
    println!("  ✓ 200 组随机密钥：页面 JS 与 dalek 公钥/双向共享密钥逐字节一致");

    // 3d) 全零公钥 / 小阶点 / 非法长度必须拒绝
    let reject = cdp.eval(
        &page,
        r###"(() => {
          const res = {};
          try { X25519.dh(__unhex('11'.repeat(32)), new Uint8Array(32)); res.zeroPub = false; }
          catch (e) { res.zeroPub = /全零/.test(String(e.message)); }
          try { X25519.dh(__unhex('22'.repeat(32)), __unhex('01' + '00'.repeat(31))); res.smallOrder = false; }
          catch (e) { res.smallOrder = /全零/.test(String(e.message)); }
          try { X25519.dh(__unhex('00'.repeat(31)), new Uint8Array(32)); res.badSk = false; }
          catch (e) { res.badSk = /私钥/.test(String(e.message)); }
          try { X25519.dh(new Uint8Array(32), __unhex('00'.repeat(31))); res.badPk = false; }
          catch (e) { res.badPk = /公钥/.test(String(e.message)); }
          return res;
        })()"###,
    );
    assert_true(&reject, "zeroPub", "全零公钥拒绝");
    assert_true(&reject, "smallOrder", "小阶点 u=1 拒绝");
    assert_true(&reject, "badSk", "非法私钥长度拒绝");
    assert_true(&reject, "badPk", "非法公钥长度拒绝");
    // dalek 侧证明：全零公钥的共享密钥确为全零（这正是 JS 必须拒绝的输入）
    let zero_shared = x_dh(&[0x11u8; 32], &[0u8; 32]);
    assert!(zero_shared.iter().all(|&b| b == 0), "dalek 对全零公钥输出应为全零（JS 侧必须拒绝）");
    println!("  ✓ 全零公钥/小阶点/非法长度均被拒（dalek 侧证实全零共享密钥场景）");

    // 3e) sessionKey：两侧一致、绑定双方公钥与房间号；与 Rust sha2 手工拼接一致
    let mut seed_a = [0u8; 32];
    seed_a.copy_from_slice(&common::random_bytes(32));
    let mut seed_b = [0u8; 32];
    seed_b.copy_from_slice(&common::random_bytes(32));
    let pub_a = x_pub(&seed_a);
    let pub_b = x_pub(&seed_b);
    let shared = x_dh(&seed_a, &pub_b);
    let shared2 = x_dh(&seed_b, &pub_a);
    assert_eq!(shared, shared2, "两方向共享密钥应一致");
    let room = "Ab3xYz9kLm";
    let expr = format!(
        "__session({}, {}, {}, {})",
        jstr(&hex(&shared)),
        jstr(&hex(&pub_a)),
        jstr(&hex(&pub_b)),
        jstr(room)
    );
    let page_key = cdp.eval(&page, &expr).as_str().unwrap_or("").to_string();
    let mut h = Sha256::new();
    h.update(shared);
    h.update(pub_a);
    h.update(pub_b);
    h.update(b"cipherlane/device/v1\x00");
    h.update(room.as_bytes());
    let want_key = hex(&h.finalize());
    assert_eq!(page_key, want_key, "sessionKey 与 Rust sha2 拼接不一致");
    // 两侧顺序一致（交换 sender/receiver 会得到不同 key —— 说明绑定顺序）
    let expr = format!(
        "__session({}, {}, {}, {})",
        jstr(&hex(&shared)), jstr(&hex(&pub_b)), jstr(&hex(&pub_a)), jstr(room)
    );
    let swapped = cdp.eval(&page, &expr).as_str().unwrap_or("").to_string();
    assert_ne!(page_key, swapped, "sender/receiver 顺序必须影响派生");
    let expr = format!(
        "__session({}, {}, {}, {})",
        jstr(&hex(&shared)), jstr(&hex(&pub_a)), jstr(&hex(&pub_b)), jstr("OTHERROOM1")
    );
    let other = cdp.eval(&page, &expr).as_str().unwrap_or("").to_string();
    assert_ne!(page_key, other, "不同房间必须派生不同密钥");
    println!("  ✓ sessionKey：两侧一致、绑定双方公钥+房间号，与 Rust sha2(shared‖pubs‖label+room) 一致");
}

// ============================================================
// 4) QRCode：容量/RS/定位图形/格式信息/svg+ascii/独立解码往返
// ============================================================
#[test]
fn qrcode_structure() {
    let _g = common::serial();
    let Some((_chrome, mut cdp, page, _server)) = boot() else {
        println!("  – 未找到 Chrome/Chromium（可用 CHROME_BIN 指定），跳过 qrcode 组");
        return;
    };

    let result = cdp.eval(&page, QR_JS);
    for key in [
        "capacity", "size", "genpoly", "rs", "finder", "format", "output", "roundtrip",
    ] {
        assert_true(&result, key, &format!("qrcode {key}"));
    }
    let n = result.get("roundtripCount").and_then(|v| v.as_u64()).unwrap_or(0);
    assert!(n >= 30, "独立解码往返样本数不足: {n}");
    println!("  ✓ 容量边界/尺寸确定性/RS 整除/定位与时序/格式信息双副本+BCH/svg+ascii 均通过");
    println!("  ✓ 独立解码往返 {n} 组一致（含中文/emoji/各版本边界）");
}

/// 原 qrcode.test.mjs 的结构/往返断言整体搬进页面执行；返回各分项布尔 + 往返组数。
const QR_JS: &str = r###"
(() => {
  const res = {};
  // 1) 容量边界
  try {
    const caps = [17, 32, 53, 78, 106];
    for (let v = 0; v < 5; v++) {
      const q1 = QRCode.encode('a'.repeat(caps[v]));
      if (q1.version !== v + 1) throw new Error('cap v=' + v);
      if (v > 0 && v < 4) {
        const q2 = QRCode.encode('a'.repeat(caps[v] + 1));
        if (q2.version !== v + 2) throw new Error('overflow v=' + v);
      }
    }
    if (QRCode.encode('a'.repeat(107)) !== null) throw new Error('107 not null');
    const lan = 'http://192.168.137.91:7788/#Ab3xYz9kLm.0u2VGVpDrE81B9GbT4tk0Me0D_Z8eCf3dTe9cihOnRk';
    if (QRCode.encode(lan).version !== 5) throw new Error('lan version');
    res.capacity = true;
  } catch (e) { res.capacity = 'ERR:' + e.message; }

  // 2) 尺寸与确定性
  try {
    const a = QRCode.encode('hello 密道');
    const b = QRCode.encode('hello 密道');
    if (a.size !== 17 + 4 * a.version) throw new Error('size');
    if (__hex(a.modules) !== __hex(b.modules)) throw new Error('nondeterministic');
    res.size = true;
  } catch (e) { res.size = 'ERR:' + e.message; }

  // 3) GF(256)/生成多项式 与 RS 整除
  try {
    const t = QRCode._test;
    const g = t.genPoly(7);
    const LOG = (x) => { let e = 0, v = 1; while (v !== x) { v = t.gmul(v, 2); e++; if (e > 254) throw new Error('no log'); } return e; };
    const want = [0, 87, 229, 146, 149, 238, 102, 21].join(',');
    if (g.map(LOG).join(',') !== want) throw new Error('genpoly');
    for (const ver of t.VERSIONS) {
      const data = __prng(ver.v * 31 + 7)(ver.data);
      const ecc = t.rsEncode(data, ver.ecc);
      const all = new Uint8Array(data.length + ecc.length);
      all.set(data); all.set(ecc, data.length);
      const g2 = t.genPoly(ver.ecc);
      const out = Uint8Array.from(all);
      for (let i = 0; i < all.length - ver.ecc; i++) {
        const coef = out[i];
        if (!coef) continue;
        for (let j = 0; j <= ver.ecc; j++) out[i + j] ^= t.gmul(g2[j], coef);
      }
      let rem = 0;
      for (let i = all.length - ver.ecc; i < all.length; i++) rem |= out[i];
      if (rem !== 0) throw new Error('rs remainder v=' + ver.v);
    }
    res.genpoly = true;
    res.rs = true;
  } catch (e) { res.genpoly = 'ERR:' + e.message; res.rs = res.genpoly; }

  // 4) 定位图形 / 时序 / 深色模块
  try {
    const q = QRCode.encode('cipherlane');
    const s = q.size;
    const at = (r, c) => q.modules[r * s + c];
    const finderOK = (r0, c0) => {
      for (let r = 0; r < 7; r++) for (let c = 0; c < 7; c++) {
        const want = (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4)) ? 1 : 0;
        if (at(r0 + r, c0 + c) !== want) return false;
      }
      return true;
    };
    if (!(finderOK(0, 0) && finderOK(0, s - 7) && finderOK(s - 7, 0))) throw new Error('finder');
    for (let i = 8; i < s - 8; i++) {
      if (at(6, i) !== (i % 2 === 0 ? 1 : 0)) throw new Error('timing row ' + i);
      if (at(i, 6) !== (i % 2 === 0 ? 1 : 0)) throw new Error('timing col ' + i);
    }
    if (at(s - 8, 8) !== 1) throw new Error('dark module');
    res.finder = true;
  } catch (e) { res.finder = 'ERR:' + e.message; }

  // 5) 格式信息：双副本一致、ECC/掩码字段、BCH 余数自洽
  try {
    const q = QRCode.encode('x'.repeat(20));
    const s = q.size;
    const at = (r, c) => q.modules[r * s + c];
    let fmt = 0;
    const cells1 = [[0, 8], [1, 8], [2, 8], [3, 8], [4, 8], [5, 8], [7, 8], [8, 8], [8, 7], [8, 5], [8, 4], [8, 3], [8, 2], [8, 1], [8, 0]];
    cells1.forEach(([r, c], i) => { fmt |= at(r, c) << i; });
    let fmt2 = 0;
    const cells2 = [];
    for (let i = 0; i < 8; i++) cells2.push([8, s - 1 - i]);
    for (let i = 0; i < 7; i++) cells2.push([s - 7 + i, 8]);
    cells2.forEach(([r, c], i) => { fmt2 |= at(r, c) << i; });
    if (fmt2 !== fmt) throw new Error('fmt copies');
    const raw = fmt ^ 0x5412;
    if (((raw >> 10) & 0x1f) !== ((0b01 << 3) | q.mask)) throw new Error('fmt field');
    let r2 = (raw >> 10) << 10;
    for (let i = 14; i >= 10; i--) if ((r2 >> i) & 1) r2 ^= 0x537 << (i - 10);
    if ((raw & 0x3ff) !== (r2 & 0x3ff)) throw new Error('BCH');
    res.format = true;
  } catch (e) { res.format = 'ERR:' + e.message; }

  // 6) svg / ascii 输出
  try {
    const link = 'http://192.168.137.91:7788/#Ab3xYz9kLm.0u2VGVpDrE81B9GbT4tk0Me0D_Z8eCf3dTe9cihOnRk';
    const svg = QRCode.svg(link, 132);
    if (!(svg.startsWith('<svg') && svg.includes('viewBox="0 0 45 45"'))) throw new Error('svg viewBox');
    if (!(svg.includes('<circle') && svg.includes('stroke'))) throw new Error('svg style');
    const ascii = QRCode.ascii('hi');
    if (!(ascii.includes('█') && ascii.split('\n').filter((l) => l.length).length === 25)) throw new Error('ascii');
    if (QRCode.svg('a'.repeat(109)) !== null) throw new Error('svg too long');
    res.output = true;
  } catch (e) { res.output = 'ERR:' + e.message; }

  // 7) 独立解码往返（按扫码器路径：格式信息 → 功能图 → 之字取位去掩码 → RS → 文本）
  try {
    function decodeQR(qr) {
      const s = qr.size;
      const m = (r, c) => qr.modules[r * s + c];
      let fmt = 0;
      const cells1 = [[0, 8], [1, 8], [2, 8], [3, 8], [4, 8], [5, 8], [7, 8], [8, 8], [8, 7], [8, 5], [8, 4], [8, 3], [8, 2], [8, 1], [8, 0]];
      cells1.forEach(([r, c], i) => { fmt |= m(r, c) << i; });
      const mask = ((fmt ^ 0x5412) >> 10) & 7;
      const func = new Uint8Array(s * s);
      const mark = (r, c) => { if (r >= 0 && c >= 0 && r < s && c < s) func[r * s + c] = 1; };
      for (let r = -1; r <= 7; r++) for (let c = -1; c <= 7; c++)
        for (const [r0, c0] of [[0, 0], [0, s - 7], [s - 7, 0]]) mark(r0 + r, c0 + c);
      for (let i = 8; i < s - 8; i++) { mark(6, i); mark(i, 6); }
      const ALIGN = { 2: 18, 3: 22, 4: 26, 5: 30 }[qr.version] || 0;
      if (ALIGN) for (let r = -2; r <= 2; r++) for (let c = -2; c <= 2; c++) mark(ALIGN + r, ALIGN + c);
      cells1.forEach(([r, c]) => mark(r, c));
      const cells2 = [];
      for (let i = 0; i < 8; i++) cells2.push([8, s - 1 - i]);
      for (let i = 0; i < 7; i++) cells2.push([s - 7 + i, 8]);
      cells2.forEach(([r, c]) => mark(r, c));
      mark(s - 8, 8);
      const maskFn = [
        (i, j) => (i + j) % 2 === 0, (i, j) => i % 2 === 0, (i, j) => j % 3 === 0, (i, j) => (i + j) % 3 === 0,
        (i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0,
        (i, j) => ((i * j) % 2) + ((i * j) % 3) === 0,
        (i, j) => (((i * j) % 2) + ((i * j) % 3)) % 2 === 0,
        (i, j) => (((i + j) % 2) + ((i * j) % 3)) % 2 === 0,
      ][mask];
      const bits = [];
      for (let right = s - 1; right >= 1; right -= 2) {
        if (right === 6) right = 5;
        const upward = ((right + 1) & 2) === 0;
        for (let k = 0; k < s; k++) {
          const r = upward ? s - 1 - k : k;
          for (const c of [right, right - 1]) {
            if (func[r * s + c]) continue;
            bits.push(m(r, c) ^ (maskFn(r, c) ? 1 : 0));
          }
        }
      }
      const cw = [];
      for (let i = 0; i + 8 <= bits.length; i += 8) {
        let b = 0;
        for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
        cw.push(b);
      }
      const t = QRCode._test;
      const ver = t.VERSIONS.find((v) => v.v === qr.version);
      const g = t.genPoly(ver.ecc);
      const r = Uint8Array.from(cw);
      for (let i = 0; i < cw.length - ver.ecc; i++) {
        const coef = r[i];
        if (!coef) continue;
        for (let j = 0; j <= ver.ecc; j++) r[i + j] ^= t.gmul(g[j], coef);
      }
      let rem = 0;
      for (let i = cw.length - ver.ecc; i < cw.length; i++) rem |= r[i];
      const data = cw.slice(0, ver.data);
      let pos = 0;
      const take = (n) => {
        let v = 0;
        for (let i = 0; i < n; i++) {
          const byte = data[pos >> 3];
          v = (v << 1) | ((byte >> (7 - (pos & 7))) & 1);
          pos++;
        }
        return v;
      };
      const mode = take(4);
      const count = take(8);
      if (mode !== 4) throw new Error('mode != 4: ' + mode);
      const bytes = [];
      for (let i = 0; i < count; i++) bytes.push(take(8));
      return { text: new TextDecoder().decode(Uint8Array.from(bytes)), mask, rsOK: rem === 0 };
    }
    const samples = [];
    for (let i = 0; i < 25; i++) samples.push('a'.repeat(1 + ((i * 7) % 19)));
    samples.push('x'.repeat(32), 'y'.repeat(53), 'z'.repeat(78), 'w'.repeat(106));
    samples.push('http://192.168.137.91:7788/#Ab3xYz9kLm.0u2VGVpDrE81B9GbT4tk0Me0D_Z8eCf3dTe9cihOnRk');
    samples.push('密道·cipherlane 中文与 emoji 🚀 的二维码往返');
    for (const text of samples) {
      const dec = decodeQR(QRCode.encode(text));
      if (dec.text !== text) throw new Error('往返不一致: ' + text.slice(0, 12));
      if (!dec.rsOK) throw new Error('RS 校验失败: ' + text.slice(0, 12));
    }
    res.roundtrip = true;
    res.roundtripCount = samples.length;
  } catch (e) { res.roundtrip = 'ERR:' + e.message; res.roundtripCount = 0; }

  return res;
})();
"###;

// ============================================================
// 5) Avatar：确定性/差异性/色板不变量/明度差/占位
// ============================================================
#[test]
fn avatar_structure() {
    let _g = common::serial();
    let Some((_chrome, mut cdp, page, _server)) = boot() else {
        println!("  – 未找到 Chrome/Chromium（可用 CHROME_BIN 指定），跳过 avatar 组");
        return;
    };

    let res = cdp.eval(
        &page,
        r###"(() => {
          const out = {};
          // 1) 确定性：同 IP 两次一致；不同尺寸仅 width/height 不同
          try {
            const a = Avatar.svg('192.168.1.117', 44);
            const b = Avatar.svg('192.168.1.117', 44);
            const c = Avatar.svg('192.168.1.117', 88);
            if (a !== b) throw new Error('同 IP 不确定');
            if (!(c.includes('width="88"') && a.includes('width="44"'))) throw new Error('尺寸未生效');
            if (c.replace('width="88" height="88"', 'width="44" height="44"') !== a) throw new Error('尺寸外不一致');
            out.deterministic = true;
          } catch (e) { out.deterministic = 'ERR:' + e.message; }
          // 2) 差异性：24 个相邻 IP 互不相同
          try {
            const seeds = [];
            for (let i = 100; i < 124; i++) seeds.push('192.168.1.' + i);
            const outs = new Set(seeds.map((s) => Avatar.svg(s, 44)));
            if (outs.size !== seeds.length) throw new Error('不同 IP 撞形: ' + outs.size);
            out.distinct = true;
          } catch (e) { out.distinct = 'ERR:' + e.message; }
          // 3) 结构与色板不变量
          try {
            const t = Avatar._test;
            const hexes = new Set(t.CHROMA.map((c) => c.hex).concat(t.BG_POOL.map((c) => c.hex)));
            for (let i = 0; i < 200; i++) {
              const ip = `${1 + (i % 223)}.${i % 255}.${(i * 7) % 255}.${(i * 13) % 255}`;
              const svg = Avatar.svg(ip, 44);
              const fills = [...svg.matchAll(/fill="(#[0-9A-Fa-f]{6})"/g)].map((m) => m[1].toUpperCase());
              if (fills.length < 4) throw new Error('层数不足 ' + ip);
              for (const f of fills) if (!hexes.has(f)) throw new Error('色板外颜色 ' + f);
              if (new Set(fills.slice(1, 4)).size !== 3) throw new Error('三层形状色重复 ' + ip);
            }
            out.palette = true;
          } catch (e) { out.palette = 'ERR:' + e.message; }
          // 4) 主形状与底色明度差 ≥0.14；形状色全为彩色系
          try {
            const t = Avatar._test;
            const chromaHexes = new Set(t.CHROMA.map((c) => c.hex));
            for (let i = 0; i < 100; i++) {
              const ip = `10.${i}.${(i * 3) % 255}.${(i * 11) % 255}`;
              const svg = Avatar.svg(ip, 44);
              const fills = [...svg.matchAll(/fill="(#[0-9A-Fa-f]{6})"/g)].map((m) => m[1].toUpperCase());
              const bg = t.BG_POOL.find((c) => c.hex === fills[0]);
              const c1 = t.CHROMA.find((c) => c.hex === fills[1]);
              if (!bg || !c1) throw new Error('颜色不在池中 ' + ip);
              if (Math.abs(bg.L - c1.L) < 0.14) throw new Error('明度差不足 ' + ip);
              for (const f of fills.slice(1)) if (!chromaHexes.has(f)) throw new Error('形状含非彩色系 ' + f);
            }
            out.luminance = true;
          } catch (e) { out.luminance = 'ERR:' + e.message; }
          // 5) 占位符：恒定、中性灰、无随机层、不与任何 IP 头像相同
          try {
            const p1 = Avatar.placeholder(36);
            const p2 = Avatar.placeholder(36);
            if (p1 !== p2) throw new Error('占位不确定');
            if (!(p1.includes('#3c4658') && p1.includes('circle'))) throw new Error('占位结构');
            if (p1.includes('translate')) throw new Error('占位含随机层');
            for (let i = 0; i < 50; i++) {
              if (Avatar.svg(`172.16.${i}.${(i * 5) % 255}`, 36) === p1) throw new Error('占位撞形');
            }
            out.placeholder = true;
          } catch (e) { out.placeholder = 'ERR:' + e.message; }
          return out;
        })()"###,
    );
    for key in ["deterministic", "distinct", "palette", "luminance", "placeholder"] {
        assert_true(&res, key, &format!("avatar {key}"));
    }
    println!("  ✓ 同 IP 确定性/仅尺寸可变；24 相邻 IP 互异；200 IP 色板不变量；100 IP 明度差≥0.14；占位恒定");
}
