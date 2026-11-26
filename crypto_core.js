/* TH AUDIO - Pure-JS Cryptographic Core (SHA-256, HMAC-SHA256, PBKDF2, SHA-512, RFC 8032 Ed25519)
 * Zero external dependencies. Works 100% offline on iOS Safari 14+, Desktop Chrome/Edge, and file://.
 * Contains ONLY the Public Key fingerprint for seed verification — ZERO Private Key stored here!
 */
(function (root) {
  'use strict';

  const EXPECTED_PUB_HEX = '8E73F37B3A7F4680EEEF92CF5772A04D91C80FF83C41A321EE3FF788A00E959E';

  function utf8ToBytes(str) {
    const out = [];
    for (let i = 0; i < str.length; i++) {
      let c = str.charCodeAt(i);
      if (c < 0x80) {
        out.push(c);
      } else if (c < 0x800) {
        out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
      } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
        const c2 = str.charCodeAt(++i);
        const cp = 0x10000 + (((c & 0x3ff) << 10) | (c2 & 0x3ff));
        out.push(
          0xf0 | (cp >> 18),
          0x80 | ((cp >> 12) & 0x3f),
          0x80 | ((cp >> 6) & 0x3f),
          0x80 | (cp & 0x3f)
        );
      } else {
        out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
      }
    }
    return new Uint8Array(out);
  }

  function bytesToHex(bytes, upper) {
    const hx = upper ? '0123456789ABCDEF' : '0123456789abcdef';
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
      s += hx[bytes[i] >> 4] + hx[bytes[i] & 15];
    }
    return s;
  }

  function hexToBytes(hex) {
    const clean = String(hex || '').replace(/[^0-9a-fA-F]/g, '');
    if (clean.length % 2 !== 0) return null;
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  function concatBytes() {
    let total = 0;
    for (let i = 0; i < arguments.length; i++) total += arguments[i].length;
    const out = new Uint8Array(total);
    let off = 0;
    for (let i = 0; i < arguments.length; i++) {
      out.set(arguments[i], off);
      off += arguments[i].length;
    }
    return out;
  }

  function base64UrlEncodeNoPad(bytes) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let out = '';
    let i = 0;
    for (; i + 2 < bytes.length; i += 3) {
      const v = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      out += alphabet[(v >> 18) & 63] + alphabet[(v >> 12) & 63] + alphabet[(v >> 6) & 63] + alphabet[v & 63];
    }
    if (i < bytes.length) {
      const a = bytes[i];
      const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
      const v = (a << 16) | (b << 8);
      out += alphabet[(v >> 18) & 63] + alphabet[(v >> 12) & 63];
      if (i + 1 < bytes.length) {
        out += alphabet[(v >> 6) & 63];
      }
    }
    return out;
  }

  /* ==================== Pure-JS SHA-256 + HMAC + PBKDF2 ==================== */
  const K256 = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);

  function rotr32(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256(data) {
    const msg = data instanceof Uint8Array ? data : utf8ToBytes(String(data));
    const bitLen = msg.length * 8;
    const paddedLen = (((msg.length + 9 + 63) >> 6) << 6);
    const buf = new Uint8Array(paddedLen);
    buf.set(msg, 0);
    buf[msg.length] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000), false);
    dv.setUint32(paddedLen - 4, bitLen >>> 0, false);

    let h0=0x6a09e667, h1=0xbb67ae85, h2=0x3c6ef372, h3=0xa54ff53a;
    let h4=0x510e527f, h5=0x9b05688c, h6=0x1f83d9ab, h7=0x5be0cd19;
    const w = new Uint32Array(64);

    for (let off = 0; off < paddedLen; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let a=h0, b=h1, c=h2, d=h3, e=h4, f=h5, g=h6, h=h7;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const ch = (e & f) ^ ((~e) & g);
        const t1 = (h + S1 + ch + K256[i] + w[i]) >>> 0;
        const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
      h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
    }

    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    odv.setUint32(0, h0, false); odv.setUint32(4, h1, false);
    odv.setUint32(8, h2, false); odv.setUint32(12, h3, false);
    odv.setUint32(16, h4, false); odv.setUint32(20, h5, false);
    odv.setUint32(24, h6, false); odv.setUint32(28, h7, false);
    return out;
  }

  function hmacSha256(key, msg) {
    const kb = key instanceof Uint8Array ? key : utf8ToBytes(String(key));
    const mb = msg instanceof Uint8Array ? msg : utf8ToBytes(String(msg));
    const kpad = new Uint8Array(64);
    if (kb.length > 64) kpad.set(sha256(kb), 0);
    else kpad.set(kb, 0);
    const ipad = new Uint8Array(64);
    const opad = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
      ipad[i] = kpad[i] ^ 0x36;
      opad[i] = kpad[i] ^ 0x5c;
    }
    return sha256(concatBytes(opad, sha256(concatBytes(ipad, mb))));
  }

  function pbkdf2Sha256(password, salt, iterations, dkLen) {
    const pw = password instanceof Uint8Array ? password : utf8ToBytes(String(password));
    const sb = salt instanceof Uint8Array ? salt : utf8ToBytes(String(salt));
    const blocks = Math.ceil(dkLen / 32);
    const out = new Uint8Array(blocks * 32);
    for (let b = 1; b <= blocks; b++) {
      const idx = new Uint8Array([(b >>> 24) & 255, (b >>> 16) & 255, (b >>> 8) & 255, b & 255]);
      let u = hmacSha256(pw, concatBytes(sb, idx));
      const t = new Uint8Array(u);
      for (let i = 1; i < iterations; i++) {
        u = hmacSha256(pw, u);
        for (let j = 0; j < 32; j++) t[j] ^= u[j];
      }
      out.set(t, (b - 1) * 32);
    }
    return out.slice(0, dkLen);
  }

  /* ==================== Pure-JS SHA-512 (BigInt 64-bit, exact RFC 8032) ==================== */
  const M64 = (1n << 64n) - 1n;
  const K512 = [
    0x428a2f98d728ae22n,0x7137449123ef65cdn,0xb5c0fbcfec4d3b2fn,0xe9b5dba58189dbbcn,
    0x3956c25bf348b538n,0x59f111f1b605d019n,0x923f82a4af194f9bn,0xab1c5ed5da6d8118n,
    0xd807aa98a3030242n,0x12835b0145706fben,0x243185be4ee4b28cn,0x550c7dc3d5ffb4e2n,
    0x72be5d74f27b896fn,0x80deb1fe3b1696b1n,0x9bdc06a725c71235n,0xc19bf174cf692694n,
    0xe49b69c19ef14ad2n,0xefbe4786384f25e3n,0x0fc19dc68b8cd5b5n,0x240ca1cc77ac9c65n,
    0x2de92c6f592b0275n,0x4a7484aa6ea6e483n,0x5cb0a9dcbd41fbd4n,0x76f988da831153b5n,
    0x983e5152ee66dfabn,0xa831c66d2db43210n,0xb00327c898fb213fn,0xbf597fc7beef0ee4n,
    0xc6e00bf33da88fc2n,0xd5a79147930aa725n,0x06ca6351e003826fn,0x142929670a0e6e70n,
    0x27b70a8546d22ffcn,0x2e1b21385c26c926n,0x4d2c6dfc5ac42aedn,0x53380d139d95b3dfn,
    0x650a73548baf63den,0x766a0abb3c77b2a8n,0x81c2c92e47edaee6n,0x92722c851482353bn,
    0xa2bfe8a14cf10364n,0xa81a664bbc423001n,0xc24b8b70d0f89791n,0xc76c51a30654be30n,
    0xd192e819d6ef5218n,0xd69906245565a910n,0xf40e35855771202an,0x106aa07032bbd1b8n,
    0x19a4c116b8d2d0c8n,0x1e376c085141ab53n,0x2748774cdf8eeb99n,0x34b0bcb5e19b48a8n,
    0x391c0cb3c5c95a63n,0x4ed8aa4ae3418acbn,0x5b9cca4f7763e373n,0x682e6ff3d6b2b8a3n,
    0x748f82ee5defb2fcn,0x78a5636f43172f60n,0x84c87814a1f0ab72n,0x8cc702081a6439ecn,
    0x90befffa23631e28n,0xa4506cebde82bde9n,0xbef9a3f7b2c67915n,0xc67178f2e372532bn,
    0xca273eceea26619cn,0xd186b8c721c0c207n,0xeada7dd6cde0eb1en,0xf57d4f7fee6ed178n,
    0x06f067aa72176fban,0x0a637dc5a2c898a6n,0x113f9804bef90daen,0x1b710b35131c471bn,
    0x28db77f523047d84n,0x32caab7b40c72493n,0x3c9ebe0a15c9bebcn,0x431d67c49c100d4cn,
    0x4cc5d4becb3e42b6n,0x597f299cfc657e2an,0x5fcb6fab3ad6faecn,0x6c44198c4a475817n
  ];

  function rotr64(x, n) {
    return ((x >> n) | ((x << (64n - n)) & M64)) & M64;
  }

  function sha512(data) {
    const msg = data instanceof Uint8Array ? data : utf8ToBytes(String(data));
    const bitLen = BigInt(msg.length) * 8n;
    const paddedLen = (((msg.length + 17 + 127) >> 7) << 7);
    const buf = new Uint8Array(paddedLen);
    buf.set(msg, 0);
    buf[msg.length] = 0x80;
    for (let i = 0; i < 16; i++) {
      buf[paddedLen - 1 - i] = Number((bitLen >> BigInt(i * 8)) & 0xffn);
    }

    let h0=0x6a09e667f3bcc908n, h1=0xbb67ae8584caa73bn, h2=0x3c6ef372fe94f82bn, h3=0xa54ff53a5f1d36f1n;
    let h4=0x510e527fade682d1n, h5=0x9b05688c2b3e6c1fn, h6=0x1f83d9abfb41bd6bn, h7=0x5be0cd19137e2179n;
    const w = new Array(80);

    for (let off = 0; off < paddedLen; off += 128) {
      for (let i = 0; i < 16; i++) {
        let v = 0n;
        for (let j = 0; j < 8; j++) v = (v << 8n) | BigInt(buf[off + i * 8 + j]);
        w[i] = v;
      }
      for (let i = 16; i < 80; i++) {
        const s0 = rotr64(w[i - 15], 1n) ^ rotr64(w[i - 15], 8n) ^ (w[i - 15] >> 7n);
        const s1 = rotr64(w[i - 2], 19n) ^ rotr64(w[i - 2], 61n) ^ (w[i - 2] >> 6n);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & M64;
      }
      let a=h0, b=h1, c=h2, d=h3, e=h4, f=h5, g=h6, h=h7;
      for (let i = 0; i < 80; i++) {
        const S1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
        const ch = (e & f) ^ ((~e & M64) & g);
        const t1 = (h + S1 + ch + K512[i] + w[i]) & M64;
        const S0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) & M64;
        h = g; g = f; f = e; e = (d + t1) & M64;
        d = c; c = b; b = a; a = (t1 + t2) & M64;
      }
      h0=(h0+a)&M64; h1=(h1+b)&M64; h2=(h2+c)&M64; h3=(h3+d)&M64;
      h4=(h4+e)&M64; h5=(h5+f)&M64; h6=(h6+g)&M64; h7=(h7+h)&M64;
    }

    const hs = [h0, h1, h2, h3, h4, h5, h6, h7];
    const out = new Uint8Array(64);
    for (let i = 0; i < 8; i++) {
      for (let j = 0; j < 8; j++) {
        out[i * 8 + j] = Number((hs[i] >> BigInt(56 - j * 8)) & 0xffn);
      }
    }
    return out;
  }

  /* ==================== Pure-JS RFC 8032 Ed25519 (BigInt) ==================== */
  const P = (1n << 255n) - 19n;
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;

  function mod(a, m) {
    const r = a % m;
    return r >= 0n ? r : r + m;
  }

  function modPow(base, exp, m) {
    let res = 1n;
    let b = mod(base, m);
    let e = exp;
    while (e > 0n) {
      if (e & 1n) res = (res * b) % m;
      b = (b * b) % m;
      e >>= 1n;
    }
    return res;
  }

  function modInv(a) {
    return modPow(a, P - 2n, P);
  }

  const D = mod(-121665n * modInv(121666n), P);
  const BY = mod(4n * modInv(5n), P);
  const BX = (function () {
    const xx = mod((BY * BY - 1n) * modInv(D * BY * BY + 1n), P);
    let x = modPow(xx, (P + 3n) / 8n, P);
    if (mod(x * x - xx, P) !== 0n) {
      x = mod(x * modPow(2n, (P - 1n) / 4n, P), P);
    }
    if ((x & 1n) !== 0n) x = P - x;
    return x;
  })();
  const B_PT = [BX, BY, 1n, mod(BX * BY, P)];

  function edAdd(p, q) {
    const x1 = p[0], y1 = p[1], z1 = p[2], t1 = p[3];
    const x2 = q[0], y2 = q[1], z2 = q[2], t2 = q[3];
    const A = mod((y1 - x1) * (y2 - x2), P);
    const B = mod((y1 + x1) * (y2 + x2), P);
    const C = mod(2n * D * t1 * t2, P);
    const DD = mod(2n * z1 * z2, P);
    const E = mod(B - A, P);
    const F = mod(DD - C, P);
    const G = mod(DD + C, P);
    const H = mod(B + A, P);
    return [mod(E * F, P), mod(G * H, P), mod(F * G, P), mod(E * H, P)];
  }

  function edMul(pt, scalar) {
    let r = [0n, 1n, 1n, 0n];
    let a = pt;
    let s = scalar;
    while (s > 0n) {
      if (s & 1n) r = edAdd(r, a);
      a = edAdd(a, a);
      s >>= 1n;
    }
    return r;
  }

  function bytesToBigIntLE(bytes) {
    let v = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) {
      v = (v << 8n) | BigInt(bytes[i]);
    }
    return v;
  }

  function bigIntToBytesLE(v, len) {
    const out = new Uint8Array(len);
    let cur = v;
    for (let i = 0; i < len; i++) {
      out[i] = Number(cur & 0xffn);
      cur >>= 8n;
    }
    return out;
  }

  function encodePoint(pt) {
    const zi = modInv(pt[2]);
    const x = mod(pt[0] * zi, P);
    const y = mod(pt[1] * zi, P);
    const out = bigIntToBytesLE(y, 32);
    if ((x & 1n) !== 0n) out[31] |= 0x80;
    return out;
  }

  function ed25519PublicKey(seedBytes) {
    if (!(seedBytes instanceof Uint8Array) || seedBytes.length !== 32) {
      throw new Error('Seed must be 32 bytes');
    }
    const h = sha512(seedBytes);
    const aBytes = h.slice(0, 32);
    aBytes[0] &= 248;
    aBytes[31] &= 127;
    aBytes[31] |= 64;
    const a = bytesToBigIntLE(aBytes);
    return encodePoint(edMul(B_PT, a));
  }

  function ed25519Sign(seedBytes, msgBytes) {
    if (!(seedBytes instanceof Uint8Array) || seedBytes.length !== 32) {
      throw new Error('Seed must be 32 bytes');
    }
    const msg = msgBytes instanceof Uint8Array ? msgBytes : utf8ToBytes(String(msgBytes));
    const h = sha512(seedBytes);
    const aBytes = h.slice(0, 32);
    aBytes[0] &= 248;
    aBytes[31] &= 127;
    aBytes[31] |= 64;
    const a = bytesToBigIntLE(aBytes);
    const pk = encodePoint(edMul(B_PT, a));
    const prefix = h.slice(32, 64);

    const r = mod(bytesToBigIntLE(sha512(concatBytes(prefix, msg))), L);
    const R = encodePoint(edMul(B_PT, r));
    const k = mod(bytesToBigIntLE(sha512(concatBytes(R, pk, msg))), L);
    const S = mod(r + k * a, L);

    return concatBytes(R, bigIntToBytesLE(S, 32));
  }

  /* ==================== TH AUDIO KeyGen & Local PIN Vault ==================== */
  function normalizeHwid(raw) {
    let s = String(raw || '').toUpperCase().replace(/[^A-Z0-9-]/g, '');
    const noDash = s.replace(/-/g, '');
    if (/^TH[0-9A-F]{12}$/.test(noDash)) {
      return 'TH-' + noDash.slice(2, 6) + '-' + noDash.slice(6, 10) + '-' + noDash.slice(10, 14);
    }
    return s;
  }

  function isValidHwid(raw) {
    return /^TH-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/.test(normalizeHwid(raw));
  }

  function verifyMasterSeedHex(seedHex) {
    const sb = hexToBytes(seedHex);
    if (!sb || sb.length !== 32) return { ok: false, error: 'Master Seed phải đủ đúng 64 ký tự Hex.' };
    const pubHex = bytesToHex(ed25519PublicKey(sb), true);
    if (pubHex !== EXPECTED_PUB_HEX) {
      return { ok: false, error: 'Master Seed không khớp với Public Key của Tune AI Pro!' };
    }
    return { ok: true, seedBytes: sb, pubHex: pubHex };
  }

  function generateLicenseKey(seedBytes, tierCode, hwidRaw) {
    const tc = String(tierCode || '').toUpperCase();
    if (tc !== 'LT' && tc !== '1Y' && tc !== '6M') {
      throw new Error('Gói không hợp lệ (chỉ chấp nhận LT, 1Y, 6M)');
    }
    const hwid = normalizeHwid(hwidRaw);
    if (!isValidHwid(hwid)) {
      throw new Error('Mã Thiết Bị không đúng định dạng TH-XXXX-XXXX-XXXX');
    }
    const msg = 'THAUDIO|V2|' + tc + '|' + hwid;
    const sig = ed25519Sign(seedBytes, utf8ToBytes(msg));
    const b64 = base64UrlEncodeNoPad(sig);
    return 'TH' + tc + '-' + b64;
  }

  function signAdminRequest(seedBytes, action, hwidRaw, tsOverride) {
    const act = String(action || '').trim().toUpperCase();
    const hwidNorm = hwidRaw ? normalizeHwid(hwidRaw) : '';
    const ts = tsOverride ? parseInt(tsOverride, 10) : Math.floor(Date.now() / 1000);
    const msg = 'THAUDIO|ADM|V1|' + act + '|' + hwidNorm + '|' + ts;
    const sig = ed25519Sign(seedBytes, utf8ToBytes(msg));
    return { ts: ts, admin_sig: base64UrlEncodeNoPad(sig) };
  }

  function signLicensePolicy(seedBytes, hwidRaw, statusRaw, tierRaw, expiresAtRaw, revRaw) {
    const hwid = normalizeHwid(hwidRaw);
    if (!isValidHwid(hwid)) {
      throw new Error('Mã Thiết Bị không đúng định dạng TH-XXXX-XXXX-XXXX');
    }
    const status = String(statusRaw || 'active').trim().toLowerCase() === 'revoked' ? 'revoked' : 'active';
    const tUp = String(tierRaw || 'LT').trim().toUpperCase();
    const tier = (tUp === 'LT' || tUp === '1Y' || tUp === '6M' || tUp === 'CUSTOM') ? tUp : 'LT';
    const expiresAt = Math.max(0, parseInt(expiresAtRaw || '0', 10) || 0);
    const rev = Math.max(1, parseInt(revRaw || '0', 10) || Math.floor(Date.now() / 1000));
    const msg = 'THAUDIO|POL|V1|' + hwid + '|' + status + '|' + tier + '|' + expiresAt + '|' + rev;
    const sig = ed25519Sign(seedBytes, utf8ToBytes(msg));
    return {
      hwid: hwid,
      status: status,
      tier: tier,
      expires_at: expiresAt,
      rev: rev,
      policy_sig: base64UrlEncodeNoPad(sig)
    };
  }

  function randomBytes(n) {
    const out = new Uint8Array(n);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(out);
    } else {
      for (let i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
    }
    return out;
  }

  function encryptSeedVault(seedBytes, pinStr) {
    const salt = randomBytes(16);
    const dk = pbkdf2Sha256(utf8ToBytes(String(pinStr)), salt, 12000, 64);
    const encKey = dk.slice(0, 32);
    const macKey = dk.slice(32, 64);
    const ct = new Uint8Array(32);
    for (let i = 0; i < 32; i++) ct[i] = seedBytes[i] ^ encKey[i];
    const mac = hmacSha256(macKey, concatBytes(salt, ct));
    return {
      v: 1,
      salt: bytesToHex(salt, false),
      ct: bytesToHex(ct, false),
      mac: bytesToHex(mac, false)
    };
  }

  function decryptSeedVault(vaultObj, pinStr) {
    if (!vaultObj || vaultObj.v !== 1) return null;
    const salt = hexToBytes(vaultObj.salt);
    const ct = hexToBytes(vaultObj.ct);
    const mac = hexToBytes(vaultObj.mac);
    if (!salt || !ct || !mac || salt.length !== 16 || ct.length !== 32 || mac.length !== 32) return null;
    const dk = pbkdf2Sha256(utf8ToBytes(String(pinStr)), salt, 12000, 64);
    const encKey = dk.slice(0, 32);
    const macKey = dk.slice(32, 64);
    const expMac = hmacSha256(macKey, concatBytes(salt, ct));
    let diff = 0;
    for (let i = 0; i < 32; i++) diff |= mac[i] ^ expMac[i];
    if (diff !== 0) return null;
    const pt = new Uint8Array(32);
    for (let i = 0; i < 32; i++) pt[i] = ct[i] ^ encKey[i];
    if (bytesToHex(ed25519PublicKey(pt), true) !== EXPECTED_PUB_HEX) return null;
    return pt;
  }

  const api = {
    EXPECTED_PUB_HEX,
    sha256,
    hmacSha256,
    pbkdf2Sha256,
    sha512,
    ed25519PublicKey,
    ed25519Sign,
    normalizeHwid,
    isValidHwid,
    verifyMasterSeedHex,
    generateLicenseKey,
    signAdminRequest,
    signLicensePolicy,
    base64UrlEncodeNoPad,
    encryptSeedVault,
    decryptSeedVault,
    bytesToHex,
    hexToBytes,
    utf8ToBytes
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    root.THCrypto = api;
  }
})(typeof window !== 'undefined' ? window : globalThis);
