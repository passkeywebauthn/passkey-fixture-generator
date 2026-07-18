// Reference verification helpers. These are intentionally small — enough to
// prove a generated fixture is valid and to serve as a readable example of what
// a relying party checks. Production verification should follow the full guide
// at https://www.passkeywebauthn.com/backend-verification-secure-credential-storage/.

import crypto from "node:crypto";
import { fromB64u, toB64u } from "./base64url.js";
import { decodeFirst } from "./cbor.js";
import { decodeCose } from "./cose.js";
import { sha256, verifyES256 } from "./crypto.js";
import { FLAG } from "./authenticator.js";

export function parseAuthData(bytes) {
  const buf = Buffer.from(bytes);
  const rpIdHash = buf.subarray(0, 32);
  const flags = buf[32];
  const signCount = buf.readUInt32BE(33);
  const out = {
    rpIdHash,
    signCount,
    flags: {
      raw: flags,
      up: !!(flags & FLAG.UP),
      uv: !!(flags & FLAG.UV),
      be: !!(flags & FLAG.BE),
      bs: !!(flags & FLAG.BS),
      at: !!(flags & FLAG.AT),
      ed: !!(flags & FLAG.ED),
    },
  };
  if (flags & FLAG.AT) {
    const aaguid = buf.subarray(37, 53);
    const credIdLen = buf.readUInt16BE(53);
    const credentialId = buf.subarray(55, 55 + credIdLen);
    const { value: cose } = decodeFirst(buf, 55 + credIdLen);
    out.aaguid = aaguid.toString("hex");
    out.credentialId = toB64u(credentialId);
    out.cosePublicKey = cose;
  }
  return out;
}

function coseToPublicKey(coseMapOrBytes) {
  const cose = coseMapOrBytes instanceof Map
    ? { kty: coseMapOrBytes.get(1), crv: coseMapOrBytes.get(-1), x: coseMapOrBytes.get(-2), y: coseMapOrBytes.get(-3) }
    : decodeCose(coseMapOrBytes);
  return crypto.createPublicKey({
    key: { kty: "EC", crv: "P-256", x: toB64u(cose.x), y: toB64u(cose.y) },
    format: "jwk",
  });
}

/** Verify a registration fixture. Returns { ok, errors, credentialId, coseKey, publicKeyJwk }. */
export function verifyRegistration({ credential, expectedChallenge, expectedOrigin, expectedRpId }) {
  const errors = [];
  const clientData = JSON.parse(fromB64u(credential.response.clientDataJSON).toString("utf8"));
  if (clientData.type !== "webauthn.create") errors.push(`clientData.type is "${clientData.type}", expected "webauthn.create"`);
  if (expectedChallenge != null && clientData.challenge !== expectedChallenge) errors.push("challenge mismatch");
  if (expectedOrigin != null && clientData.origin !== expectedOrigin) errors.push(`origin "${clientData.origin}" != "${expectedOrigin}"`);

  const { value: att } = decodeFirst(fromB64u(credential.response.attestationObject));
  const authData = parseAuthData(att.get("authData"));
  if (att.get("fmt") !== "none") errors.push(`fmt "${att.get("fmt")}" (this helper only checks "none")`);
  if (!authData.flags.up) errors.push("UP flag not set");
  if (!authData.flags.at) errors.push("AT flag not set (no attested credential data)");
  if (expectedRpId != null && !authData.rpIdHash.equals(sha256(Buffer.from(expectedRpId, "utf8")))) errors.push("rpIdHash mismatch");

  const pub = coseToPublicKey(authData.cosePublicKey);
  return {
    ok: errors.length === 0,
    errors,
    credentialId: authData.credentialId,
    signCount: authData.signCount,
    publicKeyJwk: pub.export({ format: "jwk" }),
    flags: authData.flags,
  };
}

/** Verify an assertion fixture against a known public key (JWK). Returns { ok, errors }. */
export function verifyAssertion({ credential, publicKeyJwk, expectedChallenge, expectedOrigin, expectedRpId, previousSignCount }) {
  const errors = [];
  const clientData = JSON.parse(fromB64u(credential.response.clientDataJSON).toString("utf8"));
  if (clientData.type !== "webauthn.get") errors.push(`clientData.type is "${clientData.type}", expected "webauthn.get"`);
  if (expectedChallenge != null && clientData.challenge !== expectedChallenge) errors.push("challenge mismatch");
  if (expectedOrigin != null && clientData.origin !== expectedOrigin) errors.push(`origin "${clientData.origin}" != "${expectedOrigin}"`);

  const authDataBytes = fromB64u(credential.response.authenticatorData);
  const authData = parseAuthData(authDataBytes);
  if (!authData.flags.up) errors.push("UP flag not set");
  if (expectedRpId != null && !authData.rpIdHash.equals(sha256(Buffer.from(expectedRpId, "utf8")))) errors.push("rpIdHash mismatch");
  if (previousSignCount != null && authData.signCount !== 0 && authData.signCount <= previousSignCount) {
    errors.push(`signCount ${authData.signCount} did not increase past ${previousSignCount}`);
  }

  const pub = crypto.createPublicKey({ key: publicKeyJwk, format: "jwk" });
  const signedData = Buffer.concat([authDataBytes, sha256(fromB64u(credential.response.clientDataJSON))]);
  const sigOk = verifyES256(pub, signedData, fromB64u(credential.response.signature));
  if (!sigOk) errors.push("signature verification failed");

  return { ok: errors.length === 0, errors, signCount: authData.signCount };
}
