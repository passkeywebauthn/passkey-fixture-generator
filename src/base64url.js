// Minimal base64url helpers. All WebAuthn wire fields are base64url-encoded
// (unpadded) when serialized to JSON, so registration/authentication fixtures
// round-trip through these functions.

/** Encode bytes to unpadded base64url. */
export function toB64u(bytes) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode base64url (padded or unpadded) or standard base64 to a Buffer. */
export function fromB64u(str) {
  const norm = String(str).replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(norm, "base64");
}

/** UTF-8 string to Buffer. */
export function fromUtf8(str) {
  return Buffer.from(String(str), "utf8");
}
