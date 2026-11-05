// T03/T05/T11 acceptance regressions (external review C10/C13/C14/C23).
import { strict as assert } from 'node:assert';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import {
  GENESIS,
  makeLine,
  parseLineText,
  toLineText,
  verifyChain,
} from '../lib/chain.js';

let passed = 0;
const ok = (name) => { passed++; console.log(`ok - ${name}`); };

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

const rec = (sha) => ({ time: '2026-11-06T00:00:00.000Z', tool: 'bash', callId: 'c', isError: false, contentSha256: sha });

/* ---- T11: v2 digest is block-boundary safe ---- */
{
  const { contentDigestV2 } = await import('../lib/index.js');
  const ab = contentDigestV2([{ type: 'text', text: 'a' }, { type: 'text', text: 'b' }]);
  const joined = contentDigestV2([{ type: 'text', text: 'ab' }]);
  assert.notEqual(ab, joined, 'T11: [a,b] vs [ab] must differ');

  const imgA = contentDigestV2([{ type: 'image', data: 'aaa' }]);
  const imgB = contentDigestV2([{ type: 'image', data: 'bbb' }]);
  assert.notEqual(imgA, imgB, 'T11: different payloads must differ');

  // canonical stability: key order must not matter
  const k1 = contentDigestV2([{ type: 'text', text: 'x', extra: 1 }]);
  const k2 = contentDigestV2([{ extra: 1, type: 'text', text: 'x' }]);
  assert.equal(k1, k2, 'T11: key order is canonical');

  // v1 records still verify via chain (digestVersion absent = v1 semantics kept by chain)
  const l1 = makeLine(0, GENESIS, rec('a'.repeat(64)), privPem);
  const v = verifyChain([l1], pubPem);
  assert.equal(v.ok, true, 'v1-era line still verifies when signed under same key');
  ok('T11: v2 block-boundary digest, canonical keys, v1 chain compat');
}

/* ---- T03: verification failure modes are explicit ---- */
{
  // tampered record → digest mismatch
  const l1 = makeLine(0, GENESIS, rec('a'.repeat(64)), privPem);
  const l2 = makeLine(1, l1.digest, rec('b'.repeat(64)), privPem);
  const tampered = JSON.parse(toLineText(l2));
  tampered.record.contentSha256 = 'f'.repeat(64);
  const v = verifyChain([l1, parseLineText(JSON.stringify(tampered))], pubPem);
  assert.equal(v.ok, false);
  assert.equal(v.firstBad.reason, 'digest mismatch');

  // missing signature in signed mode
  const unsigned = makeLine(1, l1.digest, rec('b'.repeat(64)));
  const v2 = verifyChain([l1, unsigned], pubPem);
  assert.equal(v2.ok, false);
  assert.equal(v2.firstBad.reason, 'missing signature');

  // wrong key
  const { publicKey: other } = generateKeyPairSync('ed25519');
  const v3 = verifyChain([l1], other.export({ type: 'spki', format: 'pem' }).toString());
  assert.equal(v3.ok, false);
  assert.equal(v3.firstBad.reason, 'signature invalid');
  ok('T03: digest mismatch / missing sig / wrong key all fail loud');
}

/* ---- T05: continuation from verified tail ---- */
{
  const dir = mkdtempSync(join(tmpdir(), 'attest-t05-'));
  const ledger = join(dir, 'session.jsonl');

  // first activation writes 2 lines
  const l1 = makeLine(0, GENESIS, rec('a'.repeat(64)), privPem);
  const l2 = makeLine(1, l1.digest, rec('b'.repeat(64)), privPem);
  mkdirSync(dir, { recursive: true });
  writeFileSync(ledger, toLineText(l1) + '\n' + toLineText(l2) + '\n');

  // second activation: read + verify + resume from tail
  const lines = readFileSync(ledger, 'utf8').split('\n').filter((l) => l.trim());
  const parsed = lines.map((l) => parseLineText(l));
  const v = verifyChain(parsed, pubPem);
  assert.equal(v.ok, true, 'existing chain verifies before continuation');
  assert.equal(parsed.length, 2);

  // third line continues from verified head
  const l3 = makeLine(parsed.length, v.headDigest, rec('c'.repeat(64)), privPem);
  const all = [...parsed, l3];
  assert.equal(verifyChain(all, pubPem).ok, true, 'continued chain verifies');

  // damaged ledger REFUSES continuation
  writeFileSync(ledger, toLineText(l1) + '\n' + toLineText(l2).replace(l2.digest.slice(0, 8), 'deadbeef') + '\n');
  const broken = parseSessionSafe(ledger);
  const bv = verifyChain(broken, pubPem);
  assert.equal(bv.ok, false, 'damaged ledger fails verification');

  rmSync(dir, { recursive: true, force: true });
  ok('T05: verified tail continuation; damaged ledger refuses');
}

function parseSessionSafe(path) {
  const text = readFileSync(path, 'utf8');
  return text.split('\n').filter((l) => l.trim()).map((l) => parseLineText(l));
}

console.log(`\n${passed} passed`);
