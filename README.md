# PrivanityHarmony

**Privacy & security hardening toolkit for OpenHarmony-based systems.**

A CLI that audits an OpenHarmony build/source tree against a composable hardening
baseline, produces a security score, and outputs an actionable diff report. This is
the "GrapheneOS mindset" applied to the Harmony ecosystem — as auditable tooling,
not a from-scratch OS fork.

> **Roadmap honest note:** this project does **not** claim to be "GrapheneOS for
> OpenHarmony." A faithful GrapheneOS-equivalent needs a hardware attestation /
> verified-boot root-of-trust chain that OpenHarmony devices do not yet offer at
> scale. `privanity` solves the base layer that *is* achievable and valuable:
> reproducible, auditable, shareable hardening for the OpenHarmony ecosystem.

## Why

OpenHarmony inherits telemetry, broad-by-default permissions, and configuration
that a privacy-focused user or organization may not want. There is currently no
widely-adopted, community-owned, auditable hardening baseline for it. This project
fills that gap:

- **Reproducible** — the baseline is code (YAML), diffable and versioned.
- **Auditable** — every control maps to a check + citation, so "hardened" means
  something testable, not vibes.
- **Composable** — profiles (privacy / security / enterprise / de-google) layer
  on top of each other.
- **Autonomous & self-hosted** — no SaaS, no telemetry, runs fully offline.

## What it does (v1)

```
privanity audit --target </path/to/openharmony> [--baseline profiles/security.yaml]
privanity score --target </path>
privanity diff --target </path> --baseline profiles/enterprise.yaml
privanity list-profiles
```

- **`audit`** — scans the target tree against the baseline, returns PASS/FAIL per
  control, and prints a markdown report.
- **`score`** — weighted security/privacy score (0–100) + per-category breakdown.
- **`diff`** — shows exactly which controls are un-met (the "what to fix" list).
- **`list-profiles`** — shows available built-in profiles.

## Built-in profiles

| Profile | Focus | Example controls |
|---|---|---|
| `privacy` | Telemetry off, permissions gated, updates user-controlled | no telemetry SDK, contacts/location/camera-mic deny, auto-update |
| `security` | Privacy + signing, SELinux labels, crypto RNG, strong PIN, network default-deny | signed packages, security labels, weak-RNG, restrict network |
| `enterprise` | Compliance/audit posture, lock-down, sign-off | strong auth, diagnostics off, package signing, audit trail |

Profiles are **composable** — a stricter profile carries forward the privacy
controls it needs. Add your own by dropping a YAML in `profiles/`.

## Quick start

```bash
pip install -e .
privanity list-profiles
privanity audit --target examples/sample_tree --baseline profiles/privacy.yaml
```

## Project layout

```
profiles/            # YAML hardening baselines (privacy, security, enterprise, ...)
examples/sample_tree # small synthesized tree for demo/testing the tool
tests/               # pytest suite
src/privanity/      # CLI + rules engine
```

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Abdel YOUSFI.
