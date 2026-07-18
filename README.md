# passkey-fixture-generator

> Deterministic, zero-dependency WebAuthn/passkey test fixtures — so you can unit-test your backend verification without real devices.

Testing a WebAuthn relying party is awkward: the interesting logic lives on the server, but every input is produced by a hardware authenticator you can't script in CI. `passkey-fixture-generator` is a **virtual authenticator** that emits byte-for-byte reproducible registration and authentication responses — real CBOR `attestationObject`s, real `authenticatorData`, real ECDSA (ES256/P-256) signatures — that your verification code accepts exactly as it would a genuine passkey.

It runs entirely offline, has **no runtime dependencies**, and works on Node.js ≥ 18.

Built and maintained by the team behind [passkeywebauthn.com — the Passkey & WebAuthn Engineering Hub](https://www.passkeywebauthn.com).

---

## Why

- **Deterministic.** The same `seed` always produces the same credential IDs, key pairs, and challenges. Commit a fixture next to a test and it never drifts.
- **Actually valid.** Signatures are produced with Node's `crypto` over `authenticatorData ‖ SHA-256(clientDataJSON)`, exactly as the [challenge–response flow](https://www.passkeywebauthn.com/webauthn-fido2-protocol-fundamentals/the-challenge-response-authentication-flow/) specifies. They verify against the public key embedded in the attestation — a bundled reference verifier proves it, and so will yours.
- **Controllable.** Toggle the User Verified, Backup Eligible, and Backup State flags; set the signature counter; choose the AAGUID and attachment — so you can test the edge cases described in [interpreting signCount anomalies](https://www.passkeywebauthn.com/backend-verification-secure-credential-storage/debugging-and-observability/interpreting-signcount-anomalies/).

This is a **test tool**, not a security boundary — see [Security](#security-and-scope) below.

## Install

```sh
npm install --save-dev passkey-fixture-generator
# or run the CLI without installing
npx passkey-fixture-generator --help
```

## Library usage

```js
import { VirtualAuthenticator, verifyRegistration, verifyAssertion } from "passkey-fixture-generator";

const authenticator = new VirtualAuthenticator({ seed: "test-user-1" });

// 1. Registration (attestation) — feed reg.credential to your registration endpoint.
const reg = authenticator.register({
  rpId: "example.com",
  origin: "https://example.com",
  user: { id: "user-123", name: "alice", displayName: "Alice" },
});

// 2. Authentication (assertion) — feed asr.credential to your login endpoint.
const asr = authenticator.authenticate({
  credentialId: reg.credentialId,
  rpId: "example.com",
  origin: "https://example.com",
  userHandle: "user-123",
});
```

`reg.credential` and `asr.credential` are shaped exactly like the objects a browser returns from `navigator.credentials.create()` / `.get()` after the usual base64url serialization, so they drop straight into a request body:

```jsonc
{
  "id": "…",
  "rawId": "…",
  "type": "public-key",
  "response": {
    "clientDataJSON": "…",
    "attestationObject": "…"   // or authenticatorData + signature for an assertion
  },
  "clientExtensionResults": {}
}
```

Each call also returns decoded convenience fields (`credentialId`, `publicKeyJwk`, `coseKey`, `challenge`, `flags`, `signCount`) so your test can assert against them.

### Verifying in a test

The package ships a small reference verifier — handy as a self-check and as a readable example of what a relying party does:

```js
import { verifyRegistration, verifyAssertion } from "passkey-fixture-generator";

const { ok, publicKeyJwk } = verifyRegistration({
  credential: reg.credential,
  expectedChallenge: reg.challenge,
  expectedOrigin: "https://example.com",
  expectedRpId: "example.com",
});

const result = verifyAssertion({
  credential: asr.credential,
  publicKeyJwk,
  expectedChallenge: asr.challenge,
  expectedOrigin: "https://example.com",
  expectedRpId: "example.com",
});
// result.ok === true
```

### API

| Export | Description |
|--------|-------------|
| `new VirtualAuthenticator({ seed, aaguid?, attachment?, credentialIdLength? })` | A deterministic software authenticator. |
| `.register({ rpId, origin?, user?, challenge?, signCount?, uv?, be?, bs?, index? })` | Emit a registration (attestation, `fmt: none`) response. |
| `.authenticate({ credentialId, rpId, origin?, challenge?, userHandle?, signCount? })` | Emit an authentication (assertion) response, ES256-signed. |
| `verifyRegistration({ credential, expectedChallenge?, expectedOrigin?, expectedRpId? })` | Reference attestation check; returns `{ ok, errors, publicKeyJwk, credentialId, flags }`. |
| `verifyAssertion({ credential, publicKeyJwk, expectedChallenge?, expectedOrigin?, expectedRpId?, previousSignCount? })` | Reference assertion + signature check. |
| `parseAuthData(bytes)` | Decode `authenticatorData` to a readable object. |
| `cborEncode` / `cborDecode` | The minimal canonical-CBOR codec used internally. |

## CLI usage

```
passkey-fixture-generator <register|authenticate|pair> [options]
```

```sh
# A full round-trip pair (register + a matching assertion) for one credential
passkey-fixture-generator pair --seed test-1 --rp-id example.com --user-name alice

# Just a registration, as compact JSON, with a device-bound (non-synced) key
passkey-fixture-generator register --seed test-1 --rp-id example.com --no-backup --compact

# An assertion for a previously generated credential id
passkey-fixture-generator authenticate --seed test-1 --rp-id example.com --cred-id "AAAA…"
```

Run `passkey-fixture-generator --help` for the full flag list.

## How the fixtures are built

```mermaid
flowchart LR
  seed["seed (string)"] -->|HMAC-SHA256| credid["credential id"]
  seed -->|HMAC-SHA256| priv["P-256 private scalar"]
  priv --> keys["ES256 key pair"]
  keys --> cose["COSE_Key (CBOR)"]
  cose --> authdata["authenticatorData"]
  authdata --> att["attestationObject (fmt: none)"]
  authdata -->|sign authData ‖ SHA-256(clientDataJSON)| sig["assertion signature"]
```

Everything downstream of the seed is a pure function of it, which is what makes the output reproducible. The COSE key is encoded in CTAP2 canonical CBOR order so the bytes match what FIDO servers expect.

## Security and scope

`passkey-fixture-generator` is for **testing only**. It deliberately builds credentials whose private keys are derived from a public seed, so anyone with the seed can forge assertions — that is the point in a test, and a disaster in production. Never wire it into a real authentication path, and never accept its output outside your test suite.

It also only emits the `none` attestation format and the ES256 algorithm (the near-universal passkey case). It does not model packed/TPM/Apple attestation statements. For what real relying-party verification must check — attestation validation, challenge binding, sign-count handling, credential storage — see [Backend Verification & Secure Credential Storage](https://www.passkeywebauthn.com/backend-verification-secure-credential-storage/).

## Development

```sh
git clone https://github.com/passkeywebauthn/passkey-fixture-generator.git
cd passkey-fixture-generator
npm test
```

Tests use Node's built-in `node:test` runner, generate fixtures, and verify their signatures end-to-end — no external fixtures or network required.

## License

MIT © passkeywebauthn

---

Learn more about implementing and testing WebAuthn at [passkeywebauthn.com](https://www.passkeywebauthn.com).

## Related tools

Part of a small set of open-source WebAuthn tools:

- [passkey-inspect](https://github.com/passkeywebauthn/passkey-inspect) — decode WebAuthn payloads (attestationObject, authenticatorData, COSE keys) from the CLI or as a library.
- [webauthn-ceremony-inspector](https://github.com/passkeywebauthn/webauthn-ceremony-inspector) — a browser DevTools panel that captures and decodes live WebAuthn ceremonies.
- [rp-id-doctor](https://github.com/passkeywebauthn/rp-id-doctor) — validate your rpId, origins, and .well-known/webauthn configuration in CI.
- [authenticator-support-matrix](https://github.com/passkeywebauthn/authenticator-support-matrix) — a filterable feature matrix of platform and roaming authenticators.
- [passkey-fallback-flow-kit](https://github.com/passkeywebauthn/passkey-fallback-flow-kit) — framework-agnostic UI building blocks for passkey fallback UX.
