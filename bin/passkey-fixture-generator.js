#!/usr/bin/env node
// CLI for passkey-fixture-generator. Emits deterministic WebAuthn fixtures as JSON.

import { VirtualAuthenticator } from "../src/index.js";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const pkg = require("../package.json");

const HELP = `passkey-fixture-generator — deterministic WebAuthn/passkey test fixtures

USAGE
  passkey-fixture-generator <command> [options]

COMMANDS
  register        Emit a registration (attestation) response
  authenticate    Emit an authentication (assertion) response
  pair            Emit a register + authenticate pair for one credential

OPTIONS
  --seed <s>          Deterministic seed (required). Same seed => same keys.
  --rp-id <id>        Relying Party ID, e.g. example.com (required)
  --origin <url>      Origin. Default https://<rp-id>
  --user-id <s>       User handle (registration / pair). Default derived from rp-id + name
  --user-name <s>     User name. Default "user"
  --cred-id <b64u>    Credential ID to authenticate (authenticate command)
  --user-handle <s>   userHandle to return on the assertion
  --challenge <b64u>  Challenge. Default derived deterministically from the seed
  --sign-count <n>    Signature counter to embed. Default 0
  --index <n>         Credential slot for the RP/user. Default 0
  --aaguid <hex>      16-byte AAGUID. Default all-zero
  --attachment <a>    platform | cross-platform. Default platform
  --no-uv             Clear the User Verified flag
  --no-backup         Clear Backup Eligible/State (a device-bound, non-synced key)
  --compact           Single-line JSON output (default is pretty-printed)
  -h, --help          Show this help
  -v, --version       Show version

EXAMPLES
  passkey-fixture-generator register --seed test-1 --rp-id example.com --user-name alice
  passkey-fixture-generator pair --seed test-1 --rp-id example.com --user-name alice
  passkey-fixture-generator authenticate --seed test-1 --rp-id example.com --cred-id AAAA...

Docs and the full WebAuthn verification guide: https://www.passkeywebauthn.com
`;

function parseArgs(argv) {
  const opts = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") opts.help = true;
    else if (a === "-v" || a === "--version") opts.version = true;
    else if (a === "--compact") opts.compact = true;
    else if (a === "--no-uv") opts.uv = false;
    else if (a === "--no-backup") { opts.be = false; opts.bs = false; }
    else if (a.startsWith("--")) opts[a.slice(2)] = argv[++i];
    else opts._.push(a);
  }
  return opts;
}

function fail(msg) {
  process.stderr.write(`error: ${msg}\n\nRun with --help for usage.\n`);
  process.exit(1);
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.version) { process.stdout.write(pkg.version + "\n"); return; }
  if (opts.help || opts._.length === 0) { process.stdout.write(HELP); return; }

  const command = opts._[0];
  if (!["register", "authenticate", "pair"].includes(command)) fail(`unknown command "${command}"`);
  if (!opts.seed) fail("--seed is required");
  if (!opts["rp-id"]) fail("--rp-id is required");

  const auth = new VirtualAuthenticator({
    seed: opts.seed,
    aaguid: opts.aaguid,
    attachment: opts.attachment || "platform",
  });

  const common = {
    rpId: opts["rp-id"],
    origin: opts.origin,
    challenge: opts.challenge,
    signCount: opts["sign-count"] != null ? Number(opts["sign-count"]) : 0,
    uv: opts.uv,
    be: opts.be,
    bs: opts.bs,
  };

  let result;
  if (command === "register") {
    result = auth.register({
      ...common,
      index: opts.index != null ? Number(opts.index) : 0,
      user: { id: opts["user-id"], name: opts["user-name"] || "user" },
    });
  } else if (command === "authenticate") {
    if (!opts["cred-id"]) fail("--cred-id is required for authenticate");
    result = auth.authenticate({
      ...common,
      credentialId: opts["cred-id"],
      userHandle: opts["user-handle"],
    });
  } else {
    const reg = auth.register({
      ...common,
      index: opts.index != null ? Number(opts.index) : 0,
      user: { id: opts["user-id"], name: opts["user-name"] || "user" },
    });
    const asr = auth.authenticate({
      ...common,
      challenge: opts.challenge, // may be undefined -> derived for "get"
      credentialId: reg.credentialId,
      userHandle: opts["user-handle"] || opts["user-id"],
    });
    result = { registration: reg, authentication: asr };
  }

  process.stdout.write(JSON.stringify(result, null, opts.compact ? 0 : 2) + "\n");
}

main();
