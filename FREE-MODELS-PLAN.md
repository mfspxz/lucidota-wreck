# Free Models Plan — Wreck workspace

Burn free first. Never fall back to a paid model without asking Zack.

## Hy4 Flash Free — USE FIRST FOR EVERYTHING (until ~Nov 28)
- Model: `opencode/hy4-flash-free` (Tencent Hy4 flash, via OpenCode Zen)
- Free window: ~Nov 15–28, 2026. OpenCode said "next 10 days" on Nov 18, so
  treat **Nov 28** as the safe deadline (the brief said Nov 30; docs give no
  end date). Near-unlimited usage during the window.
- 1M context. Zero-retention provider (no training on your data).
- Default model for all coding work until it dies.
- Auth REQUIRED: anonymous Zen calls return 429 FreeUsageLimitError
  (verified 2026-11-20 — the shared egress IP has no free quota left).
  Sign in at https://opencode.ai/auth and paste the key.

## Mercury 3 — BLOCKED (no new sign-ups)
- Model: `inception/mercury-3` (Inception Labs diffusion LLM, 1M context)
- 100M free tokens per new account — but Inception is NOT accepting new
  sign-ups at present (Zack, 2026-11-20). Config block is wired and ready;
  it just needs INCEPTION_API_KEY if sign-ups reopen.
- HARD DEADLINE if it comes back: Mercury API winds down Dec 28, 2026.
  Burn before then.
- Fallback IDs in config: `mercury-2.5` and `mercury-edit-2` (code).
  `mercury-2.5` is confirmed real — OpenCode's own models.dev catalogue
  lists `inception/mercury-2.5` (verified via `opencode models`,
  2026-11-20).

## K-EXAONE 2.5 — big-brain only, anytime
- Model: `exaone/k-exaone_v2.5` (LG AI Research, 750B total / 31B active,
  512K context, text-only, Korean + English)
- Free, no end date published. NONCOMMERCIAL ONLY (platform terms,
  effective Nov 9, 2026).
- API keys expire 30 days after issuance — re-issue monthly.
- Use for planning / architecture / review / hard reasoning ONLY.
  Never bulk cheap edits.
- Friendli does NOT serve K-EXAONE 2.5 (verified 2026-11-20: serverless
  list has 4 models, zero EXAONE; 2.0 deprecated on Friendli). The direct
  LG API is the only 2.5 path — needs Zack's region-gated signup.

## Friendli.ai — key valid, ZERO credits
- Key stored in gitignored `.env` as FRIENDLI_API_KEY (mode 600).
- Serverless base: https://api.friendli.ai/serverless/v1 (the /v1 path 404s).
- Verified 2026-11-20: key authenticates (models list 200, 4 models) but
  chat returns 403 "Your team has no remaining credits."
- Available serverless models: google/gemma-4-31B-it, zai-org/GLM-5.2,
  zai-org/GLM-5.3, zai-org/GLM-5.3-Flash. NO EXAONE models.
- The "free K-EXAONE until Jan 28" offer was the OLD 236B model, Jan 2026 —
  expired. It never applied to 2.5.
- $1000 credits ask in progress (founder story draft).

## NVIDIA NIM — live via CLI (NOT in opencode)
- Verified working 2026-11-20 via the vault-stored connector credential
  (surrogate auth — the real key never leaves the vault, so it CANNOT be
  an opencode env var; NIM stays on its own CLI).
- CLI: `~/workspace/skills/nvidia-nim/bin/nvidia-nim models --free-only`
  and `nvidia-nim chat --model <id> "prompt"`.
- Verified free models (2026-11-20): moonshotai/kimi-k3.1-pro,
  mistralai/mistral-large-4-1t-a52b, nvidia/nemotron-3-ultra-550b-a55b,
  minimaxai/minimax-m3.1-flash, nvidia/nemotron-3.5-lightning-30b-a3b.
- Use as the fallback brain when Hy4 is down or rate-limited.

## Usage rules
- Until ~Nov 28: Hy4 for EVERYTHING bulk, first choice.
- Dec 1–28: Mercury for everything IF sign-ups reopen, burn 100M before
  the Dec 28 death.
- Anytime: K-EXAONE for planning / architecture / review / hard reasoning
  ONLY.
- Never fall back to a paid Claude / GPT / Gemini model without asking first.

## How to switch models in OpenCode
- `/models` or Tab in the TUI; `opencode run --model <provider/model>`
  non-interactively.
- Config: `./opencode.json` (no keys in it — keys live only in env or a
  gitignored `.env`).
- If it asks to log in again after restart: `opencode auth login`, pick
  OpenCode, then paste an API key from https://opencode.ai/auth
  (free account; no browser callback — the CLI just wants the key).
