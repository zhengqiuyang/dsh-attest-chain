# dsh-attest-chain

> **If this helps you, please give it a star** — it helps others find it. Thanks!

Signed chain-of-custody for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (dsh) sessions.

Headless agents bypass PR gates entirely; chat UIs show what the agent *said*
it did. This plugin records what the agent actually **did**: every watched
tool result (`bash`, `write`, `edit`, `web_fetch`, …) appends a hash-chained,
ed25519-signed custody record to a durable JSONL ledger. Tamper with any line
and the chain breaks; delete the tail and it no longer matches the published
head. Zero LLM calls in the trust path.

Family: **dsh-read-guard** guards what the agent reads, **dsh-pr-gate** gates
what it writes, **dsh-attest-chain** proves what it did.

## Why now (checked 2026-10-12)

Nothing in the dsh plugin ecosystem produces tamper-evident records of agent
activity. The nearest neighbours inventory plugins (`dsh-harbor`, 24★ — a
read-only list of what's *installed*) or add LLM-based reviewing. The
in-toto-shaped lane — signed, verifiable, CI-consumable evidence of what an
agent session did — is empty. The signing core is vendored from
[agent-attest](https://github.com/zhengqiuyang/agent-attest), whose CI gate
can consume this ledger as session-side evidence.

## How it works

```
tool result ──> custody record {time, tool, callId, isError, sha256(content)}
            ──> chained: digest = sha256(canonicalJSON({seq, prevDigest, record}))
            ──> signed: ed25519 over the digest (keypair in .dsh-attest-chain/keys/)
            ──> appended: .dsh-attest-chain/session.jsonl (one line, strict order)
```

Verification is pure and offline: replay the ledger, recompute every digest,
check every link and signature. Publish the head digest (or the public key)
anywhere durable — a PR description, a CI variable — and any later comparison
detects tampering or truncation deterministically.

A keypair is generated on first run; the private half never leaves the
machine running the agent. `sign: false` runs a digest-only chain if you only
need tamper-evidence against a published head.

## Compared with qiushi-dsh-evidence-audit

The closest sibling in the awesome security category is
[qiushi-dsh-evidence-audit](https://github.com/030611/qiushi-dsh-evidence-audit) —
same idea (hash-chained local receipts over `tools/result`), deliberately
different trust posture. Pick by what you need to prove:

| | dsh-attest-chain | qiushi-dsh-evidence-audit |
|---|---|---|
| Chain | SHA-256 links **+ ed25519 signature on every record** | SHA-256 links only (explicitly not signatures) |
| What a record binds | `sha256` of the model-visible content, tool, callId, error flag | hashes of IDs and outcomes; **no digest of the content the model saw** |
| Git binding | extracts **commit SHAs from shell outputs** — the chain ties work to repo history | none |
| Tamper localization | `verifyChain()` returns the **first bad `{seq, reason}`** (broken link vs digest mismatch vs bad signature) | file-level verdict |
| Consumption | `verifyChain` is an exported API — [dsh-trust-panel](https://github.com/zhengqiuyang/dsh-trust-panel) runs it live and shows the result in the sidebar | standalone |
| Privacy stance | content digests only, never plaintext; keys stay local | hashes-only by design, POSIX 0600 receipts, no key material at all |

In short: if you want **attribution and repo-history binding** (who signed,
against which commits), attest-chain; if you want the **minimum footprint**
with zero key material, qiushi. Both are observe-only and honest about limits —
neither can prove a command ran correctly, or detect a suffix deleted before
the ledger was first published.

## Install

```sh
dsh plugin --profile default add dsh-attest-chain
```

From npm — no build step, no `allowBuilds` authorization; git installs are equally prebuilt (`lib/` ships in the repo).



## Configure

```yaml
- id: dsh-attest-chain
  name: dsh-attest-chain
  config:
    tools: [bash, write, edit, str_replace_editor, web_fetch]
    ledgerPath: .dsh-attest-chain/session.jsonl
    keysDir: .dsh-attest-chain/keys
    sign: true
```

Add `.dsh-attest-chain/` to your repository's `.gitignore` — the private key must
never be committed; the public key is what a verifier checks.

## Compatibility

- **DSH**: verified against the 0.2.x line (source snapshot 0.2.1-alpha.2); installs on any profile via `dsh plugin add` (prebuilt `lib/`, no build approval).
- **Node**: >= 20 (CI matrix: Node 20/22/24 on Ubuntu and Windows).
- **Disposable-profile evidence (2026-10-19)**: `dsh plugin --profile <fresh> add github:zhengqiuyang/dsh-attest-chain` → installed in 30s; boot shows `[dsh-attest-chain] active: …`; `dsh plugin --profile <fresh> remove dsh-attest-chain` → dependencies cleared, bundles restored.

## Develop

```sh
npm install
npm test   # syncs the vendored agent-attest core, builds, runs unit tests
```

The canonical-JSON serializer and ed25519 PEM helpers are vendored from the
sibling `agent-attest` checkout (`npm run sync`; CI runs `sync --check`).

## Roadmap

- Session-end in-toto statement envelope (full interop with agent-attest CI)
- Per-session ledgers keyed by session id
- A `verify` tool card: replay + verdict inside the Web UI
- GitHub check-run bridge: head digest posted to the PR

## Kill criteria

If dsh ships first-party signed session records, or a major plugin-adds
attestation natively, this freezes at its last working version with a
postmortem here. The signing core stays owned by agent-attest either way.
