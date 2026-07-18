import test from "node:test";
import assert from "node:assert/strict";
import { VirtualAuthenticator, verifyRegistration, verifyAssertion } from "../src/index.js";

test("registration fixture verifies (attestation none)", () => {
  const auth = new VirtualAuthenticator({ seed: "test-1" });
  const reg = auth.register({ rpId: "example.com", origin: "https://example.com", user: { id: "u1", name: "alice" } });

  const result = verifyRegistration({
    credential: reg.credential,
    expectedChallenge: reg.challenge,
    expectedOrigin: "https://example.com",
    expectedRpId: "example.com",
  });
  assert.deepEqual(result.errors, []);
  assert.equal(result.ok, true);
  assert.equal(result.credentialId, reg.credentialId);
  assert.equal(result.flags.at, true);
  assert.equal(result.flags.uv, true);
  assert.equal(result.flags.be, true);
});

test("assertion signature verifies against the registered public key", () => {
  const auth = new VirtualAuthenticator({ seed: "test-1" });
  const reg = auth.register({ rpId: "example.com", user: { id: "u1", name: "alice" } });
  const pub = verifyRegistration({ credential: reg.credential }).publicKeyJwk;

  const asr = auth.authenticate({ credentialId: reg.credentialId, rpId: "example.com", userHandle: "u1" });
  const result = verifyAssertion({
    credential: asr.credential,
    publicKeyJwk: pub,
    expectedChallenge: asr.challenge,
    expectedOrigin: "https://example.com",
    expectedRpId: "example.com",
  });
  assert.deepEqual(result.errors, []);
  assert.equal(result.ok, true);
});

test("tampered signature fails verification", () => {
  const auth = new VirtualAuthenticator({ seed: "test-1" });
  const reg = auth.register({ rpId: "example.com", user: { id: "u1", name: "alice" } });
  const pub = verifyRegistration({ credential: reg.credential }).publicKeyJwk;
  const asr = auth.authenticate({ credentialId: reg.credentialId, rpId: "example.com" });

  // Flip a byte in the signature.
  const sig = Buffer.from(asr.credential.response.signature, "base64");
  sig[sig.length - 1] ^= 0x01;
  asr.credential.response.signature = sig.toString("base64url");

  const result = verifyAssertion({ credential: asr.credential, publicKeyJwk: pub });
  assert.equal(result.ok, false);
  assert.ok(result.errors.includes("signature verification failed"));
});

test("wrong rpId is detected", () => {
  const auth = new VirtualAuthenticator({ seed: "test-1" });
  const reg = auth.register({ rpId: "example.com", user: { id: "u1", name: "alice" } });
  const result = verifyRegistration({ credential: reg.credential, expectedRpId: "evil.com" });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.includes("rpIdHash")));
});

test("--no-uv / --no-backup style flag options clear the right bits", () => {
  const auth = new VirtualAuthenticator({ seed: "test-1" });
  const reg = auth.register({ rpId: "example.com", user: { id: "u1" }, uv: false, be: false, bs: false });
  const parsed = verifyRegistration({ credential: reg.credential });
  assert.equal(parsed.flags.uv, false);
  assert.equal(parsed.flags.be, false);
  assert.equal(parsed.flags.bs, false);
  assert.equal(parsed.flags.up, true);
});
