// VirtualAuthenticator — a deterministic, software-only FIDO2 authenticator that
// produces valid WebAuthn registration (attestation) and authentication
// (assertion) responses for backend verification tests. It never touches
// hardware and makes no network calls.

import { toB64u, fromB64u, fromUtf8 } from "./base64url.js";
import { derive, sha256, keyPairFromMaterial, signES256 } from "./crypto.js";
import { encodeCoseEs256 } from "./cose.js";
import { encode as cborEncode } from "./cbor.js";

// authenticatorData flag bits (WebAuthn §6.1).
export const FLAG = {
  UP: 0x01, // User Present
  UV: 0x04, // User Verified
  BE: 0x08, // Backup Eligible
  BS: 0x10, // Backup State
  AT: 0x40, // Attested credential data included
  ED: 0x80, // Extension data included
};

const ZERO_AAGUID = Buffer.alloc(16);

function parseAaguid(input) {
  if (input == null) return ZERO_AAGUID;
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) return Buffer.from(input);
  const hex = String(input).replace(/-/g, "");
  if (hex.length !== 32) throw new Error("aaguid must be 16 bytes (32 hex chars)");
  return Buffer.from(hex, "hex");
}

// A challenge may be given as bytes, a base64url string, or omitted (then it is
// derived deterministically from the seed so fixtures stay reproducible).
function resolveChallenge(challenge, seed, kind, counter) {
  if (challenge == null) return derive(seed, "challenge", kind, String(counter));
  if (Buffer.isBuffer(challenge) || challenge instanceof Uint8Array) return Buffer.from(challenge);
  return fromB64u(challenge);
}

function computeFlags({ up = true, uv = true, be = true, bs = true, at = false }) {
  let f = 0;
  if (up) f |= FLAG.UP;
  if (uv) f |= FLAG.UV;
  if (be) f |= FLAG.BE;
  if (bs) f |= FLAG.BS;
  if (at) f |= FLAG.AT;
  return f;
}

function buildAuthData({ rpId, flags, signCount, attestedCredentialData }) {
  const head = Buffer.alloc(37);
  sha256(fromUtf8(rpId)).copy(head, 0); // rpIdHash (32)
  head[32] = flags; // flags (1)
  head.writeUInt32BE(signCount >>> 0, 33); // signCount (4)
  return attestedCredentialData ? Buffer.concat([head, attestedCredentialData]) : head;
}

function buildClientDataJSON({ type, challenge, origin, crossOrigin = false }) {
  // Key order matches what browsers emit; the RP treats it as opaque bytes anyway.
  const obj = { type, challenge: toB64u(challenge), origin, crossOrigin };
  return Buffer.from(JSON.stringify(obj), "utf8");
}

export class VirtualAuthenticator {
  /**
   * @param {object} opts
   * @param {string} opts.seed  Any string. Same seed => same keys/credentials.
   * @param {string} [opts.aaguid]  16-byte AAGUID (hex, dashed or not). Default all-zero.
   * @param {"platform"|"cross-platform"} [opts.attachment]
   * @param {number} [opts.credentialIdLength]  Default 32.
   */
  constructor({ seed, aaguid, attachment = "platform", credentialIdLength = 32 } = {}) {
    if (!seed && seed !== 0) throw new Error("VirtualAuthenticator requires a `seed`");
    this.seed = String(seed);
    this.aaguid = parseAaguid(aaguid);
    this.attachment = attachment;
    this.credentialIdLength = credentialIdLength;
  }

  // Deterministically derive the credential id + key pair for a given RP/user.
  _credential({ rpId, userId, index = 0 }) {
    const credentialId = derive(this.seed, "credid", rpId, userId ?? "", String(index)).subarray(
      0,
      this.credentialIdLength,
    );
    const keys = keyPairFromMaterial(derive(this.seed, "privkey", credentialId));
    return { credentialId, keys };
  }

  /**
   * Produce a registration (attestation) fixture, format `none`.
   * @returns {object} a serialized `navigator.credentials.create()` response
   *   plus decoded convenience fields.
   */
  register({
    rpId,
    origin,
    user = {},
    challenge,
    index = 0,
    signCount = 0,
    up = true,
    uv = true,
    be = true,
    bs = true,
    crossOrigin = false,
  } = {}) {
    if (!rpId) throw new Error("register requires `rpId`");
    origin = origin || `https://${rpId}`;
    const userId = user.id != null ? String(user.id) : rpId + ":" + (user.name ?? "user");
    const { credentialId, keys } = this._credential({ rpId, userId, index });
    const ch = resolveChallenge(challenge, this.seed, "create", index);

    const coseKey = encodeCoseEs256(keys.x, keys.y);
    const acd = Buffer.concat([
      this.aaguid,
      Buffer.from([(credentialId.length >> 8) & 0xff, credentialId.length & 0xff]),
      credentialId,
      coseKey,
    ]);
    const flags = computeFlags({ up, uv, be, bs, at: true });
    const authData = buildAuthData({ rpId, flags, signCount, attestedCredentialData: acd });
    const attestationObject = cborEncode(
      new Map([
        ["fmt", "none"],
        ["attStmt", new Map()],
        ["authData", authData],
      ]),
    );
    const clientDataJSON = buildClientDataJSON({ type: "webauthn.create", challenge: ch, origin, crossOrigin });

    return {
      credential: {
        id: toB64u(credentialId),
        rawId: toB64u(credentialId),
        type: "public-key",
        authenticatorAttachment: this.attachment,
        response: {
          clientDataJSON: toB64u(clientDataJSON),
          attestationObject: toB64u(attestationObject),
          transports: this.attachment === "platform" ? ["internal", "hybrid"] : ["usb", "nfc", "ble"],
        },
        clientExtensionResults: {},
      },
      // convenience / test helpers
      credentialId: toB64u(credentialId),
      challenge: toB64u(ch),
      publicKeyJwk: keys.jwk,
      coseKey: toB64u(coseKey),
      aaguid: this.aaguid.toString("hex"),
      signCount,
      flags,
      rpId,
      origin,
      userId,
    };
  }

  /**
   * Produce an authentication (assertion) fixture for a credential this
   * authenticator issued (identified by its base64url credential id).
   * @returns {object} a serialized `navigator.credentials.get()` response.
   */
  authenticate({
    credentialId,
    rpId,
    origin,
    challenge,
    userHandle,
    signCount = 0,
    counter = 0,
    up = true,
    uv = true,
    be = true,
    bs = true,
    crossOrigin = false,
  } = {}) {
    if (!credentialId) throw new Error("authenticate requires `credentialId`");
    if (!rpId) throw new Error("authenticate requires `rpId`");
    origin = origin || `https://${rpId}`;
    const credIdBytes = fromB64u(credentialId);
    const keys = keyPairFromMaterial(derive(this.seed, "privkey", credIdBytes));
    const ch = resolveChallenge(challenge, this.seed, "get", counter);

    const flags = computeFlags({ up, uv, be, bs, at: false });
    const authData = buildAuthData({ rpId, flags, signCount, attestedCredentialData: null });
    const clientDataJSON = buildClientDataJSON({ type: "webauthn.get", challenge: ch, origin, crossOrigin });
    const signature = signES256(keys.privateKey, Buffer.concat([authData, sha256(clientDataJSON)]));

    return {
      credential: {
        id: toB64u(credIdBytes),
        rawId: toB64u(credIdBytes),
        type: "public-key",
        authenticatorAttachment: this.attachment,
        response: {
          clientDataJSON: toB64u(clientDataJSON),
          authenticatorData: toB64u(authData),
          signature: toB64u(signature),
          userHandle: userHandle != null ? toB64u(fromUtf8(userHandle)) : null,
        },
        clientExtensionResults: {},
      },
      credentialId: toB64u(credIdBytes),
      challenge: toB64u(ch),
      publicKeyJwk: keys.jwk,
      signCount,
      flags,
      rpId,
      origin,
    };
  }
}
