/**
 * dsh-attest-chain — signed chain-of-custody for DeepSeek Harness sessions.
 *
 * Headless agents bypass PR gates entirely; chat UIs show what the agent said
 * it did. This plugin records what the agent actually did: every watched tool
 * result appends a hash-chained, ed25519-signed record to a durable JSONL
 * ledger. Tampering with any line breaks the chain; deleting the tail breaks
 * the published head. Zero LLM calls in the trust path.
 *
 * Family: dsh-read-guard guards what the agent READS, dsh-pr-gate gates what
 * it WRITES, dsh-attest-chain proves what it DID.
 *
 * Thin adapter: canonical-JSON determinism and the ed25519 helpers are
 * vendored from agent-attest (`npm run sync`).
 */
import type { Context } from '@deepseek-ai/cordis';
import Schema from '@deepseek-ai/schemastery';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { GENESIS, makeLine, toLineText, type ChainLine, type CustodyRecord, verifyChain, parseLineText } from './chain.js';
import { extractCommitShas } from './commits.js';
import { ensureKeys, type SessionKeyMaterial } from './keys.js';

export const name = 'dsh-attest-chain';

export interface Config {
  /** Tools whose results become custody records. */
  tools: string[];
  /** JSONL ledger path; empty string disables the plugin's writes. */
  ledgerPath: string;
  /** Directory for the session ed25519 keypair. */
  keysDir: string;
  /** Sign each record; false = digest chain only (still tamper-evident). */
  sign: boolean;
}

export const Config: Schema<Config> = Schema.object({
  tools: Schema.array(Schema.string())
    .default(['bash', 'write', 'edit', 'str_replace_editor', 'web_fetch'])
    .description('tools whose results become custody records'),
  ledgerPath: Schema.string().default('.dsh-attest-chain/session.jsonl').description('JSONL ledger path; empty disables'),
  keysDir: Schema.string().default('.dsh-attest-chain/keys').description('directory for the session keypair'),
  sign: Schema.boolean().default(true).description('ed25519-sign every record'),
});

// Harness surface restated so the plugin typechecks standalone; identical
// declarations merge cleanly inside the source checkout.
interface ToolExecView {
  readonly name: string;
  readonly callId: string;
  readonly agent?: unknown;
}

interface ToolResultView {
  readonly isError: boolean;
  readonly content: ({ type: string } & Record<string, unknown>)[];
}

declare module '@deepseek-ai/cordis' {
  interface Events {
    'tools/result': (
      exec: Readonly<ToolExecView>,
      result: Readonly<ToolResultView>,
    ) => undefined;
  }
}

/**
 * T11 (v2): canonical, block-boundary-safe content digest. Each block is
 * serialized as key-sorted JSON (type AND payload), length-prefixed, so
 * [a,b] vs [ab] and different payloads can never collide. v1 digests
 * (type+text concatenation) remain verifiable on historical records via
 * the record's digestVersion field.
 */
export function contentDigestV2(content: readonly ({ type: string } & Record<string, unknown>)[]): string {
  const hash = createHash('sha256');
  hash.update('dsh-attest-v2\n');
  for (const block of content) {
    const keys = Object.keys(block).sort();
    const canonical = keys.map((k) => k + '=' + stableStringify(block[k])).join('\u0001');
    const encoded = Buffer.from(canonical, 'utf8');
    hash.update(encoded.length.toString(16) + ':');
    hash.update(encoded);
    hash.update('\n');
  }
  return hash.digest('hex');
}

/** Key-sorted stringify with explicit null/array/object markers. */
export function stableStringify(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return '[' + value.map((v) => stableStringify(v)).join(',') + ']';
  if (typeof value === 'object') {
    const out = Object.keys(value as Record<string, unknown>).sort()
      .map((k) => JSON.stringify(k) + ':' + stableStringify((value as Record<string, unknown>)[k]));
    return '{' + out.join(',') + '}';
  }
  return JSON.stringify(value) ?? String(value);
}

function recordFor(
  exec: Readonly<ToolExecView>,
  result: Readonly<ToolResultView>,
  now: string,
): CustodyRecord {
  const text = result.content
    .filter((block): block is { type: string } & Record<string, unknown> & { text: string } =>
      typeof (block as { text?: unknown }).text === 'string')
    .map((block) => block.text)
    .join('\n');
  const commitSha = extractCommitShas(text)[0];
  return {
    time: now,
    tool: exec.name,
    callId: String(exec.callId),
    isError: result.isError,
    contentSha256: contentDigestV2(result.content),
    digestVersion: 2,
    ...(commitSha !== undefined ? { commitSha } : {}),
  };
}

export function apply(ctx: Context, config: Config) {
  if (config.ledgerPath === '') {
    console.log('[dsh-attest-chain] disabled (ledgerPath is empty)');
    return;
  }
  const watched = new Set(config.tools);
  const keys: SessionKeyMaterial | undefined = config.sign
    ? ensureKeys(config.keysDir)
    : undefined;
  console.log(
    `[dsh-attest-chain] active: custody chain for [${[...watched].join(', ')}], ` +
      `sign=${config.sign ? `ed25519:${keys?.keyid.slice(0, 16)}…` : 'off'}, ` +
      `ledger=${config.ledgerPath}`,
  );

  // T05: tail-continuation — verify the existing ledger and resume from its
  // head. A broken or truncated ledger REFUSES continuation (fail loud):
  // silently starting from GENESIS would forge a fresh chain over old data.
  let seq = 0;
  let prevDigest = GENESIS;
  try {
    const existing = readFileSync(config.ledgerPath, 'utf8');
    const lines = existing.split('\n').filter((l) => l.trim() !== '');
    const parsedLines = lines.map((l) => parseLineText(l));
    const verification = verifyChain(parsedLines, keys?.publicPem);
    if (!verification.ok) {
      throw new Error(
        'existing ledger at ' + config.ledgerPath + ' fails verification at seq ' +
        (verification.firstBad?.seq ?? '?') + ' (' + (verification.firstBad?.reason ?? '?') +
        ') — refusing to continue; move the file aside and investigate',
      );
    }
    seq = parsedLines.length;
    prevDigest = verification.headDigest;
    if (seq > 0) {
      console.log('[dsh-attest-chain] resumed from seq ' + seq + ' (head ' + verification.headDigest.slice(0, 16) + '…)');
    }
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? '';
    if (code !== 'ENOENT') {
      console.warn('[dsh-attest-chain] ' + (e as Error).message);
      throw e;
    }
    // ENOENT = fresh ledger, start from GENESIS
  }
  // Serialize appends so concurrent tool results keep strict seq order.
  let queue: Promise<void> = Promise.resolve();

  ctx.on('tools/result', (exec, result) => {
    if (!watched.has(exec.name)) return;
    const record = recordFor(exec, result, new Date().toISOString());
    const line: ChainLine = makeLine(seq, prevDigest, record, keys?.privatePem);
    seq += 1;
    prevDigest = line.digest;

    queue = queue.then(async () => {
      try {
        await mkdir(dirname(config.ledgerPath), { recursive: true });
        await appendFile(config.ledgerPath, toLineText(line) + '\n', 'utf8');
      } catch (err) {
        console.warn(`[dsh-attest-chain] ledger append failed: ${String(err)}`);
      }
    });
    return;
  });
}
