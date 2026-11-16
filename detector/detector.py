"""Correlation detector: lateral movement & privilege escalation on shared jump hosts.

Replaces the baseline (one alert per failed password / web request) with
correlated, entity-centric findings:

* lateral_movement -- same account authenticated from >=2 distinct source IPs
  within a short window AND the logins are followed by corroborating
  post-login behaviour (sudo to root, or a root ssh login from one of those
  IPs). Normal jump-host rotation has no such follow-up and is suppressed.
* privilege_escalation -- sudo to a root shell followed shortly by a root ssh
  login from an IP the sudo-ing account used earlier.
* needs_review -- ambiguous look-alikes (a few failures then a success,
  blocked probes of sensitive paths) that cannot be decided from auth.log
  alone; each entry names the asset information that would decide it.

Output: {"findings": [...], "needs_review": [...]} where every finding has
rule, first_seen, last_seen, entities and an ordered evidence chain.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime

ASSUMED_YEAR = 2025  # syslog timestamps carry no year; only used for ISO output

LATERAL_WINDOW_SEC = 600       # two logins of one account this close = candidate pair
CORROBORATE_SEC = 900          # post-login behaviour within this confirms malice
PRIVESC_ROOT_LOGIN_SEC = 300   # root ssh login right after sudo
SESSION_LOOKBACK_SEC = 3600    # tie a root-login IP back to the sudo-ing account
FAIL_THEN_OK_WINDOW_SEC = 600  # failures followed by a success within this window
BRUTE_FORCE_MIN_FAILS = 10     # >= this many failures is its own alert, not review

SENSITIVE_PATHS = ("/.env", "/.git", "/.aws", "/admin", "/wp-admin", "/etc/passwd")
ROOT_SHELLS = ("/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash", "bash", "sh")

TS = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+(?P<msg>.*)$"
)
ACCEPT = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)")
FAILED = re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)")
SUDO = re.compile(r"sudo:\s+(?P<user>\S+)\s+:.*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$")
NGINX = re.compile(r'nginx: (?P<ip>[\d.]+) - - "(?P<path>\S+)" (?P<status>\d{3})')

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def parse(path: str) -> list[dict]:
    """Parse the log into typed events sorted by (timestamp, line)."""
    events: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for no, line in enumerate(fh, start=1):
            m = TS.match(line.rstrip("\n"))
            if not m:
                continue
            mon, day, hms = m.group("mon"), int(m.group("day")), m.group("hms")
            hh, mm, ss = (int(x) for x in hms.split(":"))
            ts = datetime(ASSUMED_YEAR, MONTHS[mon], day, hh, mm, ss)
            ev = {"line": no, "ts": ts, "host": m.group("host")}
            msg = m.group("msg")
            if (g := ACCEPT.search(msg)):
                ev.update(kind="ssh_accept", user=g.group("user"), ip=g.group("ip"))
            elif (g := FAILED.search(msg)):
                ev.update(kind="ssh_fail", user=g.group("user"), ip=g.group("ip"))
            elif (g := SUDO.search(msg)):
                ev.update(kind="sudo", user=g.group("user"),
                          target=g.group("target"), cmd=g.group("cmd").strip())
            elif (g := NGINX.search(msg)):
                ev.update(kind="web", ip=g.group("ip"), path=g.group("path"),
                          status=int(g.group("status")))
            else:
                continue
            events.append(ev)
    events.sort(key=lambda e: (e["ts"], e["line"]))
    return events


def _iso(ev: dict) -> str:
    return ev["ts"].isoformat()


def _summary(ev: dict) -> str:
    kind = ev["kind"]
    if kind == "ssh_accept":
        return f"{ev['user']} ssh login accepted from {ev['ip']} on {ev['host']}"
    if kind == "ssh_fail":
        return f"failed password for {ev['user']} from {ev['ip']} on {ev['host']}"
    if kind == "sudo":
        return f"{ev['user']} ran sudo as {ev['target']}: {ev['cmd']} on {ev['host']}"
    return f"web {ev['status']} {ev['path']} from {ev['ip']} on {ev['host']}"


def _chain(events: list[dict]) -> list[dict]:
    """Ordered evidence chain for a finding."""
    out = sorted({e["line"]: e for e in events}.values(),
                 key=lambda e: (e["ts"], e["line"]))
    return [{"line": e["line"], "ts": _iso(e), "kind": e["kind"],
             "summary": _summary(e)} for e in out]


def _finding(rule: str, severity: str, event_chain: list[dict],
             users: set[str], ips: set[str], hosts: set[str],
             note: str) -> dict:
    chain = _chain(event_chain)
    return {
        "rule": rule,
        "severity": severity,
        "first_seen": chain[0]["ts"],
        "last_seen": chain[-1]["ts"],
        "entities": {
            "users": sorted(users),
            "ips": sorted(ips),
            "hosts": sorted(hosts),
        },
        "evidence": chain,
        "note": note,
    }


def detect_lateral_movement(events: list[dict]) -> list[dict]:
    """Same account on >=2 IPs in a short window + malicious post-login behaviour."""
    accepts_by_user: dict[str, list[dict]] = {}
    for e in events:
        if e["kind"] == "ssh_accept":
            accepts_by_user.setdefault(e["user"], []).append(e)
    sudos = [e for e in events if e["kind"] == "sudo"]
    root_accepts = [e for e in events
                    if e["kind"] == "ssh_accept" and e["user"] == "root"]
    root_ip_counts: dict[str, int] = {}
    for r in root_accepts:
        root_ip_counts[r["ip"]] = root_ip_counts.get(r["ip"], 0) + 1

    findings = []
    for user, accepts in accepts_by_user.items():
        if user == "root":
            continue
        # first use of each source IP by this account: rotation happens across
        # a known set of bastions, a stolen key shows up on IPs the account
        # has never used before
        seen: set[str] = set()
        novel: dict[int, bool] = {}
        for a in accepts:
            novel[a["line"]] = a["ip"] not in seen
            seen.add(a["ip"])
        corroborated: list[dict] = []
        for i, a in enumerate(accepts):
            for b in accepts[i + 1:]:
                if (b["ts"] - a["ts"]).total_seconds() > LATERAL_WINDOW_SEC:
                    break
                if a["ip"] == b["ip"]:
                    continue
                if not (novel[a["line"]] and novel[b["line"]]):
                    continue
                # candidate pair: does anything damning happen right after?
                # (a) the account sudo's to root, or (b) root logs in from one
                # of the pair's IPs that root has never used before -- root
                # rotating across the usual bastions is normal and not evidence.
                follow = [
                    s for s in sudos
                    if s["user"] == user and s["target"] == "root"
                    and a["ts"] <= s["ts"]
                    and (s["ts"] - b["ts"]).total_seconds() <= CORROBORATE_SEC
                ]
                follow += [
                    r for r in root_accepts
                    if r["ip"] in (a["ip"], b["ip"])
                    and root_ip_counts.get(r["ip"], 0) == 1
                    and b["ts"] <= r["ts"]
                    and (r["ts"] - b["ts"]).total_seconds() <= CORROBORATE_SEC
                ]
                if follow:
                    corroborated.extend([a, b, *follow])
        if corroborated:
            findings.append(_finding(
                rule="lateral_movement",
                severity="high",
                event_chain=corroborated,
                users={user},
                ips={e["ip"] for e in corroborated if "ip" in e},
                hosts={e["host"] for e in corroborated},
                note=("account authenticated from two source IPs it had never "
                      f"used before, within {LATERAL_WINDOW_SEC // 60} min, and the "
                      "session was followed by privilege escalation / root reuse "
                      "of the same IP — consistent with lateral movement, not "
                      "jump-host rotation"),
            ))
    return findings


def detect_privilege_escalation(events: list[dict]) -> list[dict]:
    """sudo to a root shell, then a root ssh login from an IP the sudoer used."""
    accepts = [e for e in events if e["kind"] == "ssh_accept"]
    findings = []
    for s in (e for e in events if e["kind"] == "sudo"):
        if s["target"] != "root":
            continue
        is_shell = any(s["cmd"].split("/")[-1] == sh.split("/")[-1]
                       for sh in ROOT_SHELLS)
        for r in accepts:
            if r["user"] != "root" or r["ts"] < s["ts"]:
                continue
            if (r["ts"] - s["ts"]).total_seconds() > PRIVESC_ROOT_LOGIN_SEC:
                continue
            prior = [a for a in accepts
                     if a["user"] == s["user"] and a["ip"] == r["ip"]
                     and a["ts"] <= s["ts"]
                     and (s["ts"] - a["ts"]).total_seconds() <= SESSION_LOOKBACK_SEC]
            if not prior:
                continue
            chain = [prior[-1], s, r]
            findings.append(_finding(
                rule="privilege_escalation",
                severity="high" if is_shell else "medium",
                event_chain=chain,
                users={s["user"], "root"},
                ips={r["ip"]},
                hosts={e["host"] for e in chain},
                note=(f"{s['user']} sudo'd to a root shell ({s['cmd']}) and root "
                      f"was used {int((r['ts'] - s['ts']).total_seconds())}s later "
                      f"from {r['ip']}, the same source IP as {s['user']}'s session"),
            ))
    return findings


def review_queue(events: list[dict]) -> list[dict]:
    """Ambiguous look-alikes that auth.log alone cannot adjudicate."""
    queue = []
    accepts = [e for e in events if e["kind"] == "ssh_accept"]
    fails: dict[tuple[str, str], list[dict]] = {}
    for e in events:
        if e["kind"] == "ssh_fail":
            fails.setdefault((e["user"], e["ip"]), []).append(e)

    # a few failures then a success: typo, or slow password guessing?
    for (user, ip), fl in fails.items():
        if len(fl) >= BRUTE_FORCE_MIN_FAILS:
            continue
        ok = [a for a in accepts
              if a["user"] == user and a["ip"] == ip
              and a["ts"] >= fl[-1]["ts"]
              and (a["ts"] - fl[-1]["ts"]).total_seconds() <= FAIL_THEN_OK_WINDOW_SEC]
        if ok:
            chain = [*fl, ok[0]]
            entry = _finding(
                rule="needs_review",
                severity="low",
                event_chain=chain,
                users={user}, ips={ip}, hosts={e["host"] for e in chain},
                note=(f"{len(fl)} failed password(s) then a publickey success for "
                      f"'{user}' from {ip}: could be a mistyped password or slow "
                      "credential guessing"),
            )
            entry["missing_context"] = [
                "jump-host/bastion inventory (CMDB): is the source IP an authorized bastion?",
                "VPN/DHCP lease records: was the IP assigned to a known operator at that time?",
                f"MFA / device-enrollment records for account '{user}'",
            ]
            queue.append(entry)

    # blocked probes of sensitive paths: authorized scanner, or recon?
    probes: dict[str, list[dict]] = {}
    for e in events:
        if (e["kind"] == "web" and 400 <= e["status"] < 500
                and e["path"] in SENSITIVE_PATHS):
            probes.setdefault(e["ip"], []).append(e)
    for ip, hits in probes.items():
        entry = _finding(
            rule="needs_review",
            severity="low",
            event_chain=hits,
            users=set(), ips={ip}, hosts={e["host"] for e in hits},
            note=(f"{len(hits)} blocked request(s) to sensitive paths "
                  f"({', '.join(sorted({h['path'] for h in hits}))}) from {ip}: "
                  "recon or an authorized scanner"),
        )
        entry["missing_context"] = [
            "authorized vulnerability-scanner asset list",
            "CMDB record / owner for the source IP",
            "WAF or egress logs to see whether the probing continued elsewhere",
        ]
        queue.append(entry)
    return queue


def scan(path: str) -> dict:
    events = parse(path)
    findings = detect_lateral_movement(events) + detect_privilege_escalation(events)
    findings.sort(key=lambda f: f["first_seen"])
    return {"findings": findings, "needs_review": review_queue(events)}


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: detector.py <log> <out.json>")
        return 2
    result = scan(sys.argv[1])
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    print(f"{len(result['findings'])} findings, "
          f"{len(result['needs_review'])} needs_review -> {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
