/**
 * Pure hash chain: tamper-evident, deterministically serialized records.
 * Each line chains to the previous digest; the whole chain verifies against
 * the head digest (publish it anywhere durable) and, when signing is on,
 * against the session's ed25519 key.
 */
import { createHash } from 'node:crypto';
import { canonicalJson } from './vendor/aa-core/canonical.js';
import { signBytes, verifyBytes } from './vendor/aa-core/keys.js';

export const GENESIS = '0'.repeat(64);

/** What actually happened — the fields a custody record swears to. */
export interface CustodyRecord {
  time: string;
  tool: string;
  callId: string;
  isError: boolean;
  /** sha256 of the model-facing content, hex. */
  contentSha256: string;
  /** Commit identity bound into the chain when the call created commits. */
  commitSha?: string;
  /** Content-digest algorithm version (v1 concat, v2 canonical per-block). Absent = v1. */
  digestVersion?: number;
}

export interface ChainLine {
  seq: number;
  prevDigest: string;
  record: CustodyRecord;
  digest: string;
  /** ed25519 signature over the digest bytes, base64; absent when unsigned. */
  sig?: string;
}

export function digestOf(seq: number, prevDigest: string, record: CustodyRecord): string {
  return createHash('sha256')
    .update(canonicalJson({ seq, prevDigest, record }), 'utf8')
    .digest('hex');
}

export function makeLine(
  seq: number,
  prevDigest: string,
  record: CustodyRecord,
  privateKeyPem?: string,
): ChainLine {
  const digest = digestOf(seq, prevDigest, record);
  const line: ChainLine = { seq, prevDigest, record, digest };
  if (privateKeyPem !== undefined) {
    line.sig = signBytes(privateKeyPem, Buffer.from(digest, 'hex')).toString('base64');
  }
  return line;
}

export function toLineText(line: ChainLine): string {
  return canonicalJson(line);
}

export function parseLineText(text: string): ChainLine {
  return JSON.parse(text) as ChainLine;
}

export interface ChainVerification {
  ok: boolean;
  lines: number;
  headDigest: string;
  firstBad?: { seq: number; reason: string };
}

/** Full verification: links, digests, and (when keys provided) signatures. */
export function verifyChain(lines: ChainLine[], publicKeyPem?: string): ChainVerification {
  let prev = GENESIS;
  for (const line of lines) {
    if (line.prevDigest !== prev) {
      return { ok: false, lines: lines.length, headDigest: prev, firstBad: { seq: line.seq, reason: 'broken prev link' } };
    }
    const expected = digestOf(line.seq, line.prevDigest, line.record);
    if (line.digest !== expected) {
      return { ok: false, lines: lines.length, headDigest: prev, firstBad: { seq: line.seq, reason: 'digest mismatch' } };
    }
    if (publicKeyPem !== undefined) {
      if (line.sig === undefined) {
        return { ok: false, lines: lines.length, headDigest: prev, firstBad: { seq: line.seq, reason: 'missing signature' } };
      }
      if (!verifyBytes(publicKeyPem, Buffer.from(line.digest, 'hex'), Buffer.from(line.sig, 'base64'))) {
        return { ok: false, lines: lines.length, headDigest: prev, firstBad: { seq: line.seq, reason: 'signature invalid' } };
      }
    }
    prev = line.digest;
  }
  return { ok: true, lines: lines.length, headDigest: prev };
}
