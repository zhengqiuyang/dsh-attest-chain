import Schema from '@deepseek-ai/schemastery';
import { createHash } from 'node:crypto';
import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { GENESIS, makeLine, toLineText, } from './chain.js';
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
function contentDigest(content) {
    const hash = createHash('sha256');
    for (const block of content) {
        hash.update(String(block.type));
        if (typeof block.text === 'string')
            hash.update(block.text);
    }
    return hash.digest('hex');
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
        contentSha256: contentDigest(result.content),
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
    let seq = 0;
    let prevDigest = GENESIS;
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
