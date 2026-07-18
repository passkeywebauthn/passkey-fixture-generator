// Deterministic P-256 (ES256) key material for the virtual authenticator.
//
// Everything is derived from a seed with HMAC-SHA256, so the same seed always
// produces the same credential IDs, key pairs and (optionally) challenges —
// which is the whole point: reproducible fixtures you can commit next to a test.

import crypto from "node:crypto";
import { toB64u } from "./base64url.js";

// Order n of the P-256 curve.
const P256_N = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

/** Deterministic HMAC-SHA256(seed, label...) -> 32-byte Buffer. */
export function derive(seed, ...labels) {
  const h = crypto.createHmac("sha256", Buffer.from(String(seed), "utf8"));
  for (const l of labels) h.update(Buffer.isBuffer(l) ? l : Buffer.from(String(l), "utf8"));
  return h.digest();
}

export function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

/**
 * Deterministically derive a valid P-256 private scalar from `material`.
 * Rejection-samples (hashing forward) until the scalar lands in [1, n-1].
 */
function deriveScalar(material) {
  let candidate = sha256(material);
  for (let i = 0; i < 1000; i++) {
    const n = BigInt("0x" + candidate.toString("hex"));
    if (n >= 1n && n < P256_N) return candidate;
    candidate = sha256(candidate);
  }
  throw new Error("failed to derive a valid P-256 scalar");
}

/**
 * Build a deterministic P-256 key pair from arbitrary seed material.
 * Returns Node KeyObjects plus the raw affine coordinates (32 bytes each) that
 * feed the COSE_Key encoding.
 */
export function keyPairFromMaterial(material) {
  const d = deriveScalar(material);
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(d);
  const pub = ecdh.getPublicKey(); // 0x04 || X(32) || Y(32)
  const x = pub.subarray(1, 33);
  const y = pub.subarray(33, 65);

  const jwkCommon = { kty: "EC", crv: "P-256", x: toB64u(x), y: toB64u(y) };
  const publicKey = crypto.createPublicKey({ key: jwkCommon, format: "jwk" });
  const privateKey = crypto.createPrivateKey({
    key: { ...jwkCommon, d: toB64u(d) },
    format: "jwk",
  });

  return { privateKey, publicKey, x, y, jwk: jwkCommon };
}

/** ECDSA-SHA256 signature (ASN.1 DER, as authenticators emit it) over `data`. */
export function signES256(privateKey, data) {
  return crypto.sign("sha256", data, privateKey);
}

/** Verify an ES256 DER signature. */
export function verifyES256(publicKey, data, signature) {
  return crypto.verify("sha256", data, publicKey, signature);
}
