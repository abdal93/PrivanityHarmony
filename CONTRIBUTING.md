# Contributing to PrivanityHarmony

Thank you for considering a contribution. This project is a community-owned,
auditable hardening toolkit for OpenHarmony, and every review makes "hardened"
mean something testable. Keeping it small, clear, and verifiable matters more
than volume.

## What's welcome
- **New audit controls** — a named check that inspects an OpenHarmony tree and
  returns `pass` / `fail` / `info`. Follow the pattern in `src/privanity/rules.py`:
  a `control_id` mapped to `{title, category, weight, check(target, cfg)}`, with
  a test that asserts both a pass-condition and a fail-condition.
- **New profiles** — drop a YAML in `profiles/` that composes existing controls
  (see `security.yaml` and `enterprise.yaml` for the layering pattern).
- **Bug fixes, docs, and tests** — always welcome.

## Before you open a PR
1. Run the suite: `pytest -v` (all must pass).
2. Smoke the CLI: `privanity audit --target examples/sample_tree` produces a
   well-formed report.
3. Add a test for any new control or behavior — no `pass`-only assertions; a
   rule that can never fail is not a check.

## Review standards
- **No fabrication** in rules — every control maps to a concrete, inspectable
  artifact (file, token, policy), never vibe.
- **Honest scope** — the README's roadmap note stands: this is hardening tooling
  for OpenHarmony, not a from-scratch GrapheneOS-equivalent (hardware
  attestation/verified-boot root-of-trust is a separate, hardware-bound effort).

## License
By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).