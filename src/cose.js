// COSE_Key encoding for the credential public key embedded in attested
// credential data. Only ES256 / P-256 is emitted (the near-universal passkey
// algorithm), but the labels are spelled out for readability.

import { encode, decodeFirst } from "./cbor.js";

// COSE key common + EC2 parameter labels (RFC 9052 / RFC 9053).
const COSE_KTY = 1;
const COSE_ALG = 3;
const COSE_EC2_CRV = -1;
const COSE_EC2_X = -2;
const COSE_EC2_Y = -3;

const KTY_EC2 = 2;
const ALG_ES256 = -7;
const CRV_P256 = 1;

/** Build the canonical CBOR COSE_Key for a P-256 public key. */
export function encodeCoseEs256(x, y) {
  const map = new Map([
    [COSE_KTY, KTY_EC2],
    [COSE_ALG, ALG_ES256],
    [COSE_EC2_CRV, CRV_P256],
    [COSE_EC2_X, Buffer.from(x)],
    [COSE_EC2_Y, Buffer.from(y)],
  ]);
  return encode(map);
}

/** Decode a COSE_Key back to a readable object (used by verification/tests). */
export function decodeCose(bytes) {
  const { value } = decodeFirst(Buffer.from(bytes));
  return {
    kty: value.get(COSE_KTY),
    alg: value.get(COSE_ALG),
    crv: value.get(COSE_EC2_CRV),
    x: value.get(COSE_EC2_X),
    y: value.get(COSE_EC2_Y),
  };
}
