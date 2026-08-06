"""Command-line interface for ohm-hardener."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from . import __version__
from .rules import run_baseline, score

PROFILES_DIR = Path(__file__).resolve().parent.parent.parent / "profiles"


def _load_baseline(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _render_report(results, baseline_path: Path, target: Path) -> str:
    s = score(results)
    lines = []
    lines.append("# ohm-hardener audit report")
    lines.append("")
    lines.append(f"- **target:** `{target}`")
    lines.append(f"- **baseline:** `{baseline_path}`")
    lines.append(f"- **score:** **{s['score']}/100** (PASS {s['passed']} · FAIL {s['failed']} · INFO {s['info']})")
    lines.append("")
    lines.append("## Controls")
    lines.append("")
    lines.append("| ID | Category | Status | Title | Detail |")
    lines.append("|---|----------|--------|-------|--------|")
    for r in sorted(results, key=lambda r: (r.status != "fail", r.control_id)):
        emoji = {"pass": "✅", "fail": "❌", "info": "ℹ️"}.get(r.status, "•")
        lines.append(f"| `{r.control_id}` | {r.category} | {emoji} {r.status} | {r.title} | {r.detail} |")
    lines.append("")
    if s["by_category"]:
        lines.append("## By category")
        lines.append("")
        for cat, b in s["by_category"].items():
            lines.append(f"- **{cat}:** ✅{b['pass']} ❌{b['fail']} ℹ️{b['info']}")
        lines.append("")
    return "\n".join(lines)


def cmd_list_profiles(_args) -> int:
    if not PROFILES_DIR.exists():
        print(f"No profiles dir at {PROFILES_DIR}")
        return 1
    print("Available profiles:")
    for p in sorted(PROFILES_DIR.glob("*.yaml")):
        print(f"  - {p.stem}: {p}")
    return 0


def _target_flag(p: str) -> Path:
    return Path(p).resolve()


def cmd_audit(args) -> int:
    target = _target_flag(args.target)
    baseline = _load_baseline(Path(args.baseline))
    results = run_baseline(target, baseline, category_filter=args.category)
    if args.format == "json":
        import json
        print(json.dumps([r.__dict__ for r in results], indent=2))
    else:
        print(_render_report(results, Path(args.baseline), target))
    return 0


def cmd_score(args) -> int:
    target = _target_flag(args.target)
    baseline = _load_baseline(Path(args.baseline))
    results = run_baseline(target, baseline, category_filter=args.category)
    s = score(results)
    print(f"SCORE: {s['score']}/100 (PASS {s['passed']}, FAIL {s['failed']}, INFO {s['info']})")
    for cat, b in s["by_category"].items():
        print(f"  {cat}: PASS {b['pass']} FAIL {b['fail']} INFO {b['info']}")
    return 0


def cmd_diff(args) -> int:
    target = _target_flag(args.target)
    baseline = _load_baseline(Path(args.baseline))
    results = run_baseline(target, baseline, category_filter=args.category)
    fails = [r for r in results if r.status == "fail"]
    if not fails:
        print("No unmet controls — baseline satisfied.")
        return 0
    print(f"{len(fails)} control(s) not met:")
    for r in fails:
        print(f"  ❌ [{r.control_id}] {r.title} — {r.detail}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ohm-hardener",
                                description="OpenHarmony hardening audit toolkit")
    p.add_argument("--version", action="version", version=f"ohm-hardener {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("audit", help="run full audit against a baseline")
    pa.add_argument("--target", required=True)
    pa.add_argument("--baseline", default=str(PROFILES_DIR / "privacy.yaml"))
    pa.add_argument("--category")
    pa.add_argument("--format", choices=["markdown", "json"], default="markdown")
    pa.set_defaults(fn=cmd_audit)

    ps = sub.add_parser("score", help="print numeric security score")
    ps.add_argument("--target", required=True)
    ps.add_argument("--baseline", default=str(PROFILES_DIR / "privacy.yaml"))
    ps.add_argument("--category")
    ps.set_defaults(fn=cmd_score)

    pd = sub.add_parser("diff", help="show only unmet controls")
    pd.add_argument("--target", required=True)
    pd.add_argument("--baseline", default=str(PROFILES_DIR / "privacy.yaml"))
    pd.add_argument("--category")
    pd.set_defaults(fn=cmd_diff)

    pl = sub.add_parser("list-profiles", help="list built-in baseline profiles")
    pl.set_defaults(fn=cmd_list_profiles)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
