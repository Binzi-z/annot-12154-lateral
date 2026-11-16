import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "logs", "auth.log")


def run(tmp_path, log=LOG):
    out = tmp_path / "out.json"
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "detector", "detector.py"), log, str(out)],
        capture_output=True, text=True,
    )
    return r, out


def load(tmp_path):
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text(encoding="utf-8"))


def test_corpus_and_labels():
    assert os.path.exists(LOG)
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        data = json.load(fh)
    assert len(data["events"]) == 2


def test_detector_runs(tmp_path):
    result = load(tmp_path)
    assert "findings" in result and "needs_review" in result


def test_findings_have_required_fields(tmp_path):
    for f in load(tmp_path)["findings"]:
        assert f.get("rule")
        assert f.get("first_seen") and f.get("last_seen")
        assert f["first_seen"] <= f["last_seen"]
        ents = f.get("entities") or {}
        assert ents.get("users") and ents.get("ips")
        chain = f.get("evidence") or []
        assert len(chain) >= 2
        # evidence is an ordered event chain with log-line references
        assert all(e.get("line") and e.get("ts") and e.get("summary") for e in chain)
        assert [e["ts"] for e in chain] == sorted(e["ts"] for e in chain)


def test_labels_all_hit(tmp_path):
    findings = load(tmp_path)["findings"]
    rules = {f["rule"] for f in findings}
    assert "lateral_movement" in rules
    assert "privilege_escalation" in rules
    lat = next(f for f in findings if f["rule"] == "lateral_movement")
    assert "dba" in lat["entities"]["users"]
    assert {"10.20.1.51", "10.20.1.52"} <= set(lat["entities"]["ips"])
    priv = next(f for f in findings if f["rule"] == "privilege_escalation")
    assert "dba" in priv["entities"]["users"]
    assert "root" in priv["entities"]["users"]


def test_zero_false_positives_on_rotation(tmp_path):
    findings = load(tmp_path)["findings"]
    # exactly the two labelled incidents; benign look-alikes stay out of findings
    assert len(findings) == 2
    flagged_ips = {ip for f in findings for ip in f["entities"]["ips"]}
    assert "10.20.1.77" not in flagged_ips  # few failures then success (benign)
    assert "10.20.1.88" not in flagged_ips  # blocked /.env, /admin probes (benign)
    flagged_users = {u for f in findings for u in f["entities"]["users"]}
    assert "bob" not in flagged_users       # normal jump-host rotation
    assert "svc-ops" not in flagged_users
    assert "ops" not in flagged_users


def test_needs_review_names_missing_asset_info(tmp_path):
    queue = load(tmp_path)["needs_review"]
    assert queue, "ambiguous look-alikes should land in needs_review"
    for entry in queue:
        assert entry.get("missing_context"), "must say which asset info is missing"
        assert entry.get("entities") and entry.get("evidence")
    review_ips = {ip for e in queue for ip in e["entities"]["ips"]}
    assert {"10.20.1.77", "10.20.1.88"} <= review_ips


def test_empty_log_yields_no_findings(tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    r, out = run(tmp_path, str(empty))
    assert r.returncode == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["findings"] == []
    assert result["needs_review"] == []
