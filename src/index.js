// passkey-fixture-generator — deterministic WebAuthn/passkey test fixtures.
// Zero runtime dependencies. Node.js >= 18.

export { VirtualAuthenticator, FLAG } from "./authenticator.js";
export { verifyRegistration, verifyAssertion, parseAuthData } from "./verify.js";
export { toB64u, fromB64u } from "./base64url.js";
export { encode as cborEncode, decodeFirst as cborDecode } from "./cbor.js";
