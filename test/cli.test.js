import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const BIN = fileURLToPath(new URL("../bin/passkey-fixture-generator.js", import.meta.url));
const run = (args) => JSON.parse(execFileSync("node", [BIN, ...args], { encoding: "utf8" }));

test("CLI `pair` emits a verifiable register+authenticate pair", async () => {
  const out = run(["pair", "--seed", "cli-test", "--rp-id", "example.com", "--user-name", "alice"]);
  assert.ok(out.registration.credential.response.attestationObject);
  assert.ok(out.authentication.credential.response.signature);

  const { verifyRegistration, verifyAssertion } = await import("../src/index.js");
  const reg = verifyRegistration({
    credential: out.registration.credential,
    expectedRpId: "example.com",
    expectedChallenge: out.registration.challenge,
  });
  assert.equal(reg.ok, true);
  const asr = verifyAssertion({
    credential: out.authentication.credential,
    publicKeyJwk: reg.publicKeyJwk,
    expectedRpId: "example.com",
    expectedChallenge: out.authentication.challenge,
  });
  assert.equal(asr.ok, true);
});

test("CLI is deterministic across invocations", () => {
  const a = run(["register", "--seed", "cli-det", "--rp-id", "example.com", "--compact"]);
  const b = run(["register", "--seed", "cli-det", "--rp-id", "example.com", "--compact"]);
  assert.deepEqual(a.credential, b.credential);
});

test("CLI errors without required flags", () => {
  assert.throws(() => execFileSync("node", [BIN, "register"], { encoding: "utf8", stdio: "pipe" }));
});
