"""Rules engine for ohm-hardener.

Each control in a baseline YAML is a check that inspects a target OpenHarmony
source/build tree and returns pass/fail. Rules are intentionally simple and
auditable: they look for expected paths/signatures and warn on telemetry,
oversized permissions, or missing hardening artifacts.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Result:
    control_id: str
    title: str
    category: str
    status: str  # pass | fail | info
    detail: str = ""
    weight: float = 1.0


def _scan_files(root: Path, pattern: str) -> list[Path]:
    if not root.exists():
        return []
    return [p for p in root.rglob(pattern) if p.is_file()]


def _read_text(path: Path, max_bytes: int = 1_000_000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(max_bytes)
    except OSError:
        return ""


def _has_text(paths: list[Path], needles: list[str]) -> bool:
    for p in paths:
        text = _read_text(p).lower()
        if any(n in text for n in needles):
            return True
    return False


CHECKS = {
    # --- Telemetry / network disclosure -----------------------------------
    "no_telemetry_sdk": {
        "title": "No third-party analytics/telemetry SDK linkage",
        "category": "telemetry",
        "check": lambda t, cfg: (
            "pass",
            "no hims/config reporting SDK references found",
        )
        if not _scan_text_needles(t, cfg, ["analytics_sdk", "report_engine"])
        else ("fail", "found telemetry reporter references"),
    },
    "no_crash_reporting": {
        "title": "Crash/usage reporting disabled",
        "category": "telemetry",
        "check": lambda t, cfg: ("pass", "no crash reporter found") if not _scan_text_needles(
            t, cfg, ["crash_sdk", "bugreport_auto"])
        else ("fail", "crash/usage auto-report references present"),
    },
    # --- Permissions / privacy --------------------------------------------
    "contacts_off": {
        "title": "Contacts access off-by-default",
        "category": "privacy",
        "check": lambda t, cfg: _permission_default(t, cfg, "ohos.permission.READ_CONTACTS", "deny"),
    },
    "location_off": {
        "title": "Location access off-by-default",
        "category": "privacy",
        "check": lambda t, cfg: _permission_default(t, cfg, "ohos.permission.LOCATION", "deny"),
    },
    "camera_mic_off": {
        "title": "Camera/Mic off-by-default",
        "category": "privacy",
        "check": lambda t, cfg: _permission_defaults(t, cfg, ["ohos.permission.CAMERA", "ohos.permission.MICROPHONE"], "deny"),
    },
    # --- Accessory hardening artifacts -------------------------------------
    "network_profile_present": {
        "title": "Network/connection profile restrictively configured",
        "category": "network",
        "check": lambda t, cfg: ("pass", "network profile present") if _exe_profile(
            t, cfg, "network")
        else ("fail", "no restrictive network profile found"),
    },
    "disable_auto_updates": {
        "title": "Automatic background update/OTA disabled or user-controlled",
        "category": "updates",
        "check": lambda t, cfg: ("pass", "auto-update flag handled") if _scan_text_needles(
            t, cfg, ["auto_update=off", "auto_update_enabled=false"])
        else ("fail", "auto-update not explicitly disabled"),
    },
    "remove_debug_keystore": {
        "title": "No debug/test signing keys shipped",
        "category": "signing",
        "check": lambda t, cfg: ("pass", "no debug keystore found") if not _scan_paths(
            t, cfg, ["*.jks", "*.keystore", "debug.keystore"])
        else ("fail", "debug keystore present in tree"),
    },
    "usage_notice_present": {
        "title": "Privacy/usage notice included",
        "category": "docs",
        "weight": 0.5,
        "check": lambda t, cfg: ("pass", "PRIVACY.md present") if _file_exists(
            t, ["PRIVACY*.md", "privacy*.md"]) else ("fail", "no privacy notice"),
    },
    # --- additional security rules (v1.1) ---
    "signed_packages": {
        "title": "Installable packages are signed (no unsigned/self-signed baseline)",
        "category": "signing",
        "weight": 1.5,
        "check": lambda t, cfg: _check_signed(t, cfg),
    },
    "security_labels": {
        "title": "SELinux/security labels enforced (no permissive/unconfined policy)",
        "category": "security",
        "weight": 1.5,
        "check": lambda t, cfg: _check_notext(t, cfg, ["permissive", "unconfined", "setenforce 0"]),
    },
    "mtu_weak_random": {
        "title": "No weak/static PRNG seeding (crypto-grade randomness)",
        "category": "security",
        "weight": 1.0,
        "check": lambda t, cfg: _check_notext(t, cfg, ["srand(1)", "random.seed(1)", "static_seed", "insecure_rng"]),
    },
    "network_restrict": {
        "title": "Network default-deny / firewall policy restrictively configured",
        "category": "network",
        "weight": 1.5,
        "check": lambda t, cfg: _check_hastext(t, cfg, ["default_policy\": \"deny", "policy: deny", "firewalld", "ufw enable", "default: deny"]),
    },
    "disable_bg_diagnostics": {
        "title": "Background diagnostic/feedback collection disabled",
        "category": "telemetry",
        "weight": 1.0,
        "check": lambda t, cfg: _check_notext(t, cfg, ["diagnostic_feedback", "usage_report", "send_diagnostics"]),
    },
    "enforce_strong_pin": {
        "title": "Strong auth (PIN/lock) enforced (no set_none/password_policy off)",
        "category": "security",
        "weight": 1.0,
        "check": lambda t, cfg: _check_notext(t, cfg, ["password_policy\": \"none", "require_pin\": false", "lock_screen\": \"none\""]),
    },
    # --- IoT device rules ---
    "radio_default_deny": {
        "title": "Wireless radios (Wi-Fi/BT/LoRa/cell) default-deny or gated by explicit pin",
        "category": "network",
        "weight": 1.5,
        "check": lambda t, cfg: _check_iot_radio(t, cfg),
    },
    "sensor_egress_off": {
        "title": "Sensor microphones/cameras/telemetry acquisition gated off-by-default",
        "category": "privacy",
        "weight": 1.5,
        "check": lambda t, cfg: _check_iot_sensor(t, cfg),
    },
    "secure_boot_stamp": {
        "title": "Verified-boot / firmware signing configuration present (device boot chain)",
        "category": "signing",
        "weight": 2.0,
        "check": lambda t, cfg: _check_secureboot(t, cfg),
    },
    "io_telnet_disabled": {
        "title": "Telnet / unauthenticated remote management disabled",
        "category": "security",
        "weight": 1.5,
        "check": lambda t, cfg: _check_notext(t, cfg, ["telnetd", "enable_telnet\": true", "allow_noauth_ssh\": true", "unauthenticated_telnet"]),
    },
    "iot_updates_authorized": {
        "title": "Firmware OTA updates require signed/authenticated source",
        "category": "updates",
        "weight": 1.5,
        "check": lambda t, cfg: _check_authorized_ota(t, cfg),
    },
}


def _check_iot_radio(target: Path, cfg: dict) -> tuple[str, str]:
    # Look for radio/policy config: if a deny or gated policy exists → pass.
    hay = cfg.get("patterns", ["*radio*.json", "*wifi*.json", "*bt*.json", "*net*.json", "*profile*.json", "*.json", "*.conf"])
    # PASS if we find a restrictive radio policy (deny/by-pin), FAIL if we only
    # find radios configured permissive.
    text_acc = ""
    hit_file = False
    for pat in hay:
        for p in _scan_files(target, pat):
            hit_file = True
            text_acc += _read_text(p).lower()
    if not hit_file:
        return "info", "no radio policy found — treat as unverified"
    restrictive = any(tok in text_acc for tok in [
        "default_radio\": \"deny", "radios\": [\"none\"]", "wifi\": \"off\"",
        "bt\": \"off\"", "policy\": \"deny", "radio\": \"deny", "connection\": \"deny",
    ])
    permissive = any(tok in text_acc for tok in [
        "wifi\": \"on\", \"bt\": \"on\"", "radios\": \"all\"", "wifi\": \"always\"",
        "bt\": \"always\"", "radio\": \"allow", "policy\": \"allow",
    ])
    if restrictive:
        return "pass", "radio policy is deny/gated"
    if permissive:
        return "fail", "radios configured permissive (no deny/gate)"
    return "info", "radio policy ambiguous — treat as unverified"


def _check_iot_sensor(target: Path, cfg: dict) -> tuple[str, str]:
    pats = cfg.get("patterns", ["*sensor*.json", "*permission*.json", "*audio*.json", "*camera*.json", "*.json", "*.xml", "*.conf"])
    acc = ""
    hit = False
    for pat in pats:
        for p in _scan_files(target, pat):
            hit = True
            acc += _read_text(p).lower()
    if not hit:
        return "info", "no sensor/acquisition policy — treat as unverified"
    deny_toks = ["mic\": \"deny", "microphone\": \"deny", "camera\": \"deny",
                 "sensor\": \"deny", "acquisition\": \"deny", "mics\": [\"none\"]",
                 "\"recording\": \"deny\""]
    allow_toks = ["mic\": \"on", "microphone\": \"on", "camera\": \"on",
                  "sensor\": \"on", "\"recording\": \"on\""]
    if any(d in acc for d in deny_toks):
        return "pass", "sensor acquisition gated to deny"
    if any(a in acc for a in allow_toks):
        return "fail", "sensor/mic/camera configured on by default"
    return "info", "sensor policy ambiguous — treat as unverified"


def _check_secureboot(target: Path, cfg: dict) -> tuple[str, str]:
    pats = cfg.get("patterns", ["*boot*.json", "*verified*.json", "*firmware*.json", "*.cfg", "*.conf", "*.json", "*.xml"])
    acc = ""
    hit = False
    for pat in pats:
        for p in _scan_files(target, pat):
            hit = True
            acc += _read_text(p).lower()
    if not hit:
        return "info", "no boot/verified config found — treat as unverified"
    have = any(tok in acc for tok in [
        "verified_boot", "secure_boot\": true", "bootloader_locked", "secureboot",
        "firmware_sign\": true", "key_verified", "rollback_protection",
    ])
    if have:
        return "pass", "secure/verified boot configuration present"
    return "fail", "no secure/verified boot config found"


def _check_authorized_ota(target: Path, cfg: dict) -> tuple[str, str]:
    pats = cfg.get("patterns", ["*ota*.json", "*update*.json", "*.json", "*.xml", "*.conf"])
    acc = ""
    hit = False
    for pat in pats:
        for p in _scan_files(target, pat):
            hit = True
            acc += _read_text(p).lower()
    if not hit:
        return "info", "no OTA config found — treat as unverified"
    auth = any(tok in acc for tok in ["signed_ota", "ota_signature_verify", "signature_required", "ota_auth\": true"])
    open_all = any(tok in acc for tok in ["ota\": \"allow_unsigned\", \"signature_check\": false", "allow_unsigned_ota"])
    if auth:
        return "pass", "OTA updates require signed/authenticated source"
    if open_all:
        return "fail", "OTA allows unsigned/unauthenticated updates"
    return "info", "OTA policy ambiguous — treat as unverified"


def _check_signed(target: Path, cfg: dict) -> tuple[str, str]:
    pats = cfg.get("patterns", ["*.hap", "*.app", "*.pem", "*.cer", "*.zip"])
    sigfiles = _scan_files(target, "*.cer")
    certs = _scan_files(target, "*.pem")
    haps = _scan_files(target, "*.hap")
    if sigfiles or certs:
        return ("pass", f"signing certs present ({len(sigfiles) + len(certs)} found)")
    if not haps:
        return ("info", "no installable packages found — treat as unverified")
    return ("fail", "installable packages present but no signing certs found")


def _check_notext(target: Path, cfg: dict, needles: list[str]) -> tuple[str, str]:
    if _scan_text_needles(target, cfg, needles):
        return ("fail", f"weak-config token present: {needles}")
    return ("pass", "no weak-config tokens found")


def _check_hastext(target: Path, cfg: dict, needles: list[str]) -> tuple[str, str]:
    if _scan_text_needles(target, cfg, needles):
        return ("pass", "restrictive policy token present")
    return ("fail", "no restrictive policy found")


def _scan_text_needles(target: Path, cfg: dict, needles: list[str]) -> bool:
    pats = cfg.get("patterns", ["*"])
    found = False
    for pat in pats:
        files = _scan_files(target, pat)
        if _has_text(files, [n.lower() for n in needles]):
            found = True
            break
    return found


def _scan_paths(target: Path, cfg: dict, gl: list[str]) -> bool:
    any_hit = False
    for g in gl:
        if _scan_files(target, g):
            any_hit = True
    return any_hit


def _file_exists(target: Path, gl: list[str]) -> bool:
    return any(_scan_files(target, g) for g in gl)


def _permission_default(target: Path, cfg: dict, perm: str, want: str) -> tuple[str, str]:
    # looks for a permission grant text in baseline files
    pats = cfg.get("patterns", ["*permission*.json", "**.json", "*manifest*.xml", "*.xml"])
    for pat in pats:
        for p in _scan_files(target, pat):
            text = _read_text(p).lower()
            if perm.lower() in text:
                if want == "deny" and _contains_deny(text):
                    return ("pass", f"{perm} gated to {want}")
                return ("fail", f"{perm} present but not gated to {want}")
    return ("info", f"{perm} reference not found — treat as unverified")


def _permission_defaults(target: Path, cfg: dict, perms: list[str], want: str) -> tuple[str, str]:
    """Gate a group of permissions only when ALL are handled; partial = fail."""
    pats = cfg.get("patterns", ["*permission*.json", "*manifest*.xml", "*.xml", "*.json"])
    present, handled = [], []
    for perm in perms:
        pg = perm.lower()
        for pat in pats:
            for p in _scan_files(target, pat):
                text = _read_text(p).lower()
                if pg in text:
                    present.append(perm)
                    if _contains_deny(text):
                        handled.append(perm)
                    break
    if not present:
        return ("info", "permission set not referenced — treat as unverified")
    if set(present) == set(handled):
        return ("pass", f"{','.join(perms)} gated to {want}")
    return ("fail", f"unhandled: {[p for p in perms if p not in handled]}")


def _contains_deny(text: str) -> bool:
    for tok in ["deny", "denied", "reject", "forbidden", "\"off\"", "-1", "false"]:
        if tok in text:
            return True
    return False


def _exe_profile(target: Path, cfg: dict, name: str) -> bool:
    pats = cfg.get("patterns", ["*profile*.json", "*profiles*.json", "*.json"])
    found = False
    for pat in pats:
        for p in _scan_files(target, pat):
            if name in _read_text(p).lower():
                found = True
    return found


def run_baseline(target: Path, baseline: dict, category_filter: str | None = None) -> list[Result]:
    checks_def = baseline.get("controls", {})
    results: list[Result] = []
    for cid, cdef in checks_def.items():
        if cid not in CHECKS:
            continue
        meta = CHECKS[cid]
        cat = cdef.get("category", meta["category"])
        if category_filter and cat != category_filter:
            continue
        try:
            status, detail = meta["check"](target, cdef)
        except Exception as exc:  # noqa: BLE001
            status, detail = "fail", f"rule error: {exc}"
        results.append(
            Result(
                control_id=cid,
                title=cdef.get("title", meta["title"]),
                category=cat,
                status=status,
                detail=detail,
                weight=cdef.get("weight", meta.get("weight", 1.0)),
            )
        )
    return results


def score(results: list[Result]) -> dict:
    total_w = 0.0
    earned = 0.0
    for r in results:
        total_w += r.weight
        if r.status == "pass":
            earned += r.weight
    pct = round(100.0 * earned / total_w, 1) if total_w else 0.0
    by_cat: dict[str, dict] = {}
    for r in results:
        b = by_cat.setdefault(r.category, {"pass": 0, "fail": 0, "info": 0})
        b[r.status] += 1
    return {"score": pct, "passed": sum(1 for r in results if r.status == "pass"),
            "failed": sum(1 for r in results if r.status == "fail"),
            "info": sum(1 for r in results if r.status == "info"),
            "by_category": by_cat}