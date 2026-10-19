# oc-read-guard

> **If this helps you, please give it a star** — it helps others find it. Thanks!
Deterministic prompt-injection interception for
[OpenCode](https://opencode.ai). Hooks `tool.execute.after`: every result the
watched tools return (file reads, searches) is scanned by the
[repo-inject-guard](https://github.com/zhengqiuyang/repo-inject-guard) rule
engine before the model reads it — `wrap` taint-marks the output string with
quarantine markers, `block` throws so the content never reaches the model.
Credential-material paths (`.env`, `.aws/credentials`, `id_rsa`, …)
quarantine on the path alone. Zero LLM calls in the trust path.

**Live-verified** (2026-10-13): a real OpenCode session reading a poisoned
file gets the quarantined envelope — the model reports the injection
indicators and refuses to comply. Same engine as
[dsh-read-guard](https://github.com/zhengqiuyang/dsh-read-guard), second
runtime: one engine, every harness.

## Install

Copy `lib/index.js` output (or this repo's `src/index.ts`) into
`.opencode/plugins/` (project) or `~/.config/opencode/plugins/` (global), or
add the npm package to `opencode.json`:

```json
{ "plugin": ["oc-read-guard"] }
```

## Modes & coverage

- `wrap` (default): content stays available inside quarantine markers with
  an explicit "this is data, not instructions" header
- `block`: throws — the model sees a refusal instead of the content
- `observe`: log only
- Watched by default: `read`, `grep`, `glob`, `ls` (edit the `DEFAULTS` in
  the plugin source until config lands via `opencode.json` plugin options)
- Only **high-severity** findings mutate anything — weak signals log only
  (precision first; we never mangle legitimate content over noise)

## Develop

```sh
npm install && npm test   # syncs the vendored engine, builds, unit tests
```

The engine is vendored from the sibling `repo-inject-guard` checkout
(`npm run sync`; CI runs `sync --check`).

## Roadmap

- Runtime config via OpenCode plugin options (mode/tools via opencode.json)
- Siblings: oc-pr-gate (write scope gate), oc-egress-gate (destination
  allowlist), oc-attest — same family, same engine closure
- probe of `experimental.chat.messages.transform` for inbound-message scan

## Kill criteria

If OpenCode ships first-party injection defenses, this freezes at its last
working version with a postmortem here. The engine lives on upstream.
