import test from "node:test";
import assert from "node:assert/strict";
import { VirtualAuthenticator, cborEncode, cborDecode } from "../src/index.js";

test("same seed produces byte-identical fixtures", () => {
  const a = new VirtualAuthenticator({ seed: "seed-A" }).register({ rpId: "example.com", user: { id: "u1" } });
  const b = new VirtualAuthenticator({ seed: "seed-A" }).register({ rpId: "example.com", user: { id: "u1" } });
  assert.equal(a.credentialId, b.credentialId);
  assert.deepEqual(a.credential, b.credential);
});

test("different seeds produce different credentials", () => {
  const a = new VirtualAuthenticator({ seed: "seed-A" }).register({ rpId: "example.com", user: { id: "u1" } });
  const b = new VirtualAuthenticator({ seed: "seed-B" }).register({ rpId: "example.com", user: { id: "u1" } });
  assert.notEqual(a.credentialId, b.credentialId);
});

test("a fresh authenticator with the same seed can authenticate an issued credential", () => {
  const reg = new VirtualAuthenticator({ seed: "seed-A" }).register({ rpId: "example.com", user: { id: "u1" } });
  const asr = new VirtualAuthenticator({ seed: "seed-A" }).authenticate({ credentialId: reg.credentialId, rpId: "example.com" });
  assert.equal(asr.credentialId, reg.credentialId);
  assert.ok(asr.credential.response.signature);
});

test("CBOR canonical map ordering round-trips", () => {
  const map = new Map([
    [-3, Buffer.from([9, 9])],
    [1, 2],
    [-1, 1],
    [3, -7],
    [-2, Buffer.from([8, 8])],
  ]);
  const encoded = cborEncode(map);
  // Canonical order is 1, 3, -1, -2, -3 -> first key byte is 0x01.
  assert.equal(encoded[1], 0x01);
  const { value } = cborDecode(encoded);
  assert.equal(value.get(1), 2);
  assert.equal(value.get(3), -7);
});
