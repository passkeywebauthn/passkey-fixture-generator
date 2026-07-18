// A tiny, dependency-free CBOR encoder/decoder scoped to exactly what WebAuthn
// needs: the `attestationObject` map, COSE_Key maps (which use integer — and
// negative integer — keys), byte strings, text strings and arrays.
//
// Maps are encoded in CTAP2 canonical order (RFC 8949 §4.2.1 / the "deterministic
// encoding" that FIDO servers expect): keys are sorted by their encoded byte
// representation, shorter encodings first, then lexicographically. That is what
// makes the fixtures byte-for-byte reproducible.

function head(major, n) {
  const mt = major << 5;
  if (n < 24) return Buffer.from([mt | n]);
  if (n < 0x100) return Buffer.from([mt | 24, n]);
  if (n < 0x10000) return Buffer.from([mt | 25, n >> 8, n & 0xff]);
  if (n < 0x100000000) {
    const b = Buffer.alloc(5);
    b[0] = mt | 26;
    b.writeUInt32BE(n >>> 0, 1);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = mt | 27;
  b.writeBigUInt64BE(BigInt(n), 1);
  return b;
}

/**
 * Encode a JS value to CBOR. Accepts numbers (incl. negative integers),
 * Buffer/Uint8Array (byte strings), strings (text), arrays, and Map instances.
 * Plain objects are treated as text-keyed maps.
 */
export function encode(value) {
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new TypeError("CBOR: only integers supported");
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const buf = Buffer.isBuffer(value) ? value : Buffer.from(value);
    return Buffer.concat([head(2, buf.length), buf]);
  }
  if (typeof value === "string") {
    const buf = Buffer.from(value, "utf8");
    return Buffer.concat([head(3, buf.length), buf]);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([head(4, value.length), ...value.map(encode)]);
  }
  const entries = value instanceof Map ? [...value.entries()] : Object.entries(value);
  const encoded = entries.map(([k, v]) => ({ k: encode(k), v: encode(v) }));
  encoded.sort((a, b) => (a.k.length - b.k.length) || Buffer.compare(a.k, b.k));
  return Buffer.concat([head(5, encoded.length), ...encoded.flatMap((e) => [e.k, e.v])]);
}

/**
 * Minimal CBOR decoder used by the verification helpers and tests. Returns
 * `{ value, offset }`. Byte strings decode to Buffer; maps to Map (so integer
 * COSE keys survive).
 */
export function decodeFirst(buf, start = 0) {
  let i = start;
  function readLen(ai) {
    if (ai < 24) return ai;
    if (ai === 24) return buf[i++];
    if (ai === 25) { const v = buf.readUInt16BE(i); i += 2; return v; }
    if (ai === 26) { const v = buf.readUInt32BE(i); i += 4; return v; }
    if (ai === 27) { const v = Number(buf.readBigUInt64BE(i)); i += 8; return v; }
    throw new Error("CBOR: indefinite lengths unsupported");
  }
  const b = buf[i++];
  const major = b >> 5;
  const ai = b & 0x1f;
  switch (major) {
    case 0: return { value: readLen(ai), offset: i };
    case 1: return { value: -1 - readLen(ai), offset: i };
    case 2: { const n = readLen(ai); const v = buf.subarray(i, i + n); i += n; return { value: v, offset: i }; }
    case 3: { const n = readLen(ai); const v = buf.toString("utf8", i, i + n); i += n; return { value: v, offset: i }; }
    case 4: {
      const n = readLen(ai);
      const arr = [];
      for (let k = 0; k < n; k++) { const r = decodeFirst(buf, i); arr.push(r.value); i = r.offset; }
      return { value: arr, offset: i };
    }
    case 5: {
      const n = readLen(ai);
      const map = new Map();
      for (let k = 0; k < n; k++) {
        const kr = decodeFirst(buf, i); i = kr.offset;
        const vr = decodeFirst(buf, i); i = vr.offset;
        map.set(kr.value, vr.value);
      }
      return { value: map, offset: i };
    }
    default: throw new Error(`CBOR: unsupported major type ${major}`);
  }
}
