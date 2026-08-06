import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from privanity.rules import run_baseline, score

SAMPLE = Path(__file__).resolve().parent.parent / "examples" / "sample_tree"
BASELINE = Path(__file__).resolve().parent.parent / "profiles" / "privacy.yaml"

import yaml


def test_baseline_loads():
    b = yaml.safe_load(BASELINE.read_text())
    assert "controls" in b
    assert len(b["controls"]) >= 5


def test_privacy_controls_pass():
    b = yaml.safe_load(BASELINE.read_text())
    results = run_baseline(SAMPLE, b)
    by_id = {r.control_id: r.status for r in results}
    assert by_id["contacts_off"] == "pass"
    assert by_id["location_off"] == "pass"
    assert by_id["camera_mic_off"] == "pass"
    assert by_id["network_profile_present"] == "pass"
    assert by_id["usage_notice_present"] == "pass"


def test_telemetry_and_keystore_fail():
    b = yaml.safe_load(BASELINE.read_text())
    results = run_baseline(SAMPLE, b)
    by_id = {r.control_id: r.status for r in results}
    # the sample tree intentionally ships telemetry + a debug keystore → must FAIL
    assert by_id["no_telemetry_sdk"] == "fail"
    assert by_id["no_crash_reporting"] == "fail"
    assert by_id["remove_debug_keystore"] == "fail"


def test_score_bounds():
    b = yaml.safe_load(BASELINE.read_text())
    results = run_baseline(SAMPLE, b)
    s = score(results)
    assert 0 <= s["score"] <= 100
    assert s["passed"] + s["failed"] + s["info"] == len(results)
    assert s["passed"] == 5
    assert s["failed"] == 4


def test_security_profile_runs():
    b = yaml.safe_load(
        (Path(__file__).resolve().parent.parent / "profiles" / "security.yaml").read_text()
    )
    results = run_baseline(SAMPLE, b)
    by_id = {r.control_id: r.status for r in results}
    # new security controls should PASS against the enriched sample tree
    assert by_id["signed_packages"] == "pass"
    assert by_id["security_labels"] == "pass"
    assert by_id["network_restrict"] == "pass"
    assert by_id["enforce_strong_pin"] == "pass"
    assert by_id["mtu_weak_random"] == "pass"
    # telemetry still intentionally fails (un-hardened demo artifacts)
    assert by_id["no_telemetry_sdk"] == "fail"


def test_enterprise_profile_loads():
    b = yaml.safe_load(
        (Path(__file__).resolve().parent.parent / "profiles" / "enterprise.yaml").read_text()
    )
    results = run_baseline(SAMPLE, b)
    assert len(results) >= 6


def test_all_new_rules_defined():
    from privanity.rules import CHECKS
    for cid in ["signed_packages", "security_labels", "mtu_weak_random",
                "network_restrict", "disable_bg_diagnostics", "enforce_strong_pin"]:
        assert cid in CHECKS, f"{cid} not registered"
