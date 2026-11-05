import Schema from '@deepseek-ai/schemastery';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { GENESIS, makeLine, toLineText, verifyChain, parseLineText } from './chain.js';
import { extractCommitShas } from './commits.js';
import { ensureKeys } from './keys.js';
export const name = 'dsh-attest-chain';
export const Config = Schema.object({
    tools: Schema.array(Schema.string())
        .default(['bash', 'write', 'edit', 'str_replace_editor', 'web_fetch'])
        .description('tools whose results become custody records'),
    ledgerPath: Schema.string().default('.dsh-attest-chain/session.jsonl').description('JSONL ledger path; empty disables'),
    keysDir: Schema.string().default('.dsh-attest-chain/keys').description('directory for the session keypair'),
    sign: Schema.boolean().default(true).description('ed25519-sign every record'),
});
/**
 * T11 (v2): canonical, block-boundary-safe content digest. Each block is
 * serialized as key-sorted JSON (type AND payload), length-prefixed, so
 * [a,b] vs [ab] and different payloads can never collide. v1 digests
 * (type+text concatenation) remain verifiable on historical records via
 * the record's digestVersion field.
 */
export function contentDigestV2(content) {
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
export function stableStringify(value) {
    if (value === null)
        return 'null';
    if (Array.isArray(value))
        return '[' + value.map((v) => stableStringify(v)).join(',') + ']';
    if (typeof value === 'object') {
        const out = Object.keys(value).sort()
            .map((k) => JSON.stringify(k) + ':' + stableStringify(value[k]));
        return '{' + out.join(',') + '}';
    }
    return JSON.stringify(value) ?? String(value);
}
function recordFor(exec, result, now) {
    const text = result.content
        .filter((block) => typeof block.text === 'string')
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
export function apply(ctx, config) {
    if (config.ledgerPath === '') {
        console.log('[dsh-attest-chain] disabled (ledgerPath is empty)');
        return;
    }
    const watched = new Set(config.tools);
    const keys = config.sign
        ? ensureKeys(config.keysDir)
        : undefined;
    console.log(`[dsh-attest-chain] active: custody chain for [${[...watched].join(', ')}], ` +
        `sign=${config.sign ? `ed25519:${keys?.keyid.slice(0, 16)}…` : 'off'}, ` +
        `ledger=${config.ledgerPath}`);
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
            throw new Error('existing ledger at ' + config.ledgerPath + ' fails verification at seq ' +
                (verification.firstBad?.seq ?? '?') + ' (' + (verification.firstBad?.reason ?? '?') +
                ') — refusing to continue; move the file aside and investigate');
        }
        seq = parsedLines.length;
        prevDigest = verification.headDigest;
        if (seq > 0) {
            console.log('[dsh-attest-chain] resumed from seq ' + seq + ' (head ' + verification.headDigest.slice(0, 16) + '…)');
        }
    }
    catch (e) {
        const code = e.code ?? '';
        if (code !== 'ENOENT') {
            console.warn('[dsh-attest-chain] ' + e.message);
            throw e;
        }
        // ENOENT = fresh ledger, start from GENESIS
    }
    // Serialize appends so concurrent tool results keep strict seq order.
    let queue = Promise.resolve();
    ctx.on('tools/result', (exec, result) => {
        if (!watched.has(exec.name))
            return;
        const record = recordFor(exec, result, new Date().toISOString());
        const line = makeLine(seq, prevDigest, record, keys?.privatePem);
        seq += 1;
        prevDigest = line.digest;
        queue = queue.then(async () => {
            try {
                await mkdir(dirname(config.ledgerPath), { recursive: true });
                await appendFile(config.ledgerPath, toLineText(line) + '\n', 'utf8');
            }
            catch (err) {
                console.warn(`[dsh-attest-chain] ledger append failed: ${String(err)}`);
            }
        });
        return;
    });
}
