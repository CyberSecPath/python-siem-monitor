"""A small, offline SIEM-style analyzer for synthetic authentication logs.

This project demonstrates defensive log analysis. It does not connect to a
network, collect real telemetry, or take action against any system.
"""
from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
import json
from pathlib import Path
from typing import Iterable

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    username: str
    source_ip: str
    event_type: str
    status: str
    details: str = ""


@dataclass(frozen=True)
class Alert:
    timestamp: str
    severity: str
    rule_id: str
    rule_name: str
    username: str
    source_ip: str
    evidence: str
    recommendation: str


def load_events(path: Path) -> list[Event]:
    """Load and validate events from a CSV file."""
    required = {"timestamp", "username", "source_ip", "event_type", "status"}
    events: list[Event] = []
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            missing = sorted(required - set(reader.fieldnames or []))
            raise ValueError(f"CSV is missing required columns: {', '.join(missing)}")
        for line_number, row in enumerate(reader, start=2):
            try:
                timestamp = datetime.strptime(row["timestamp"].strip(), TIMESTAMP_FORMAT)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid timestamp on CSV line {line_number}") from exc
            for key in required - {"timestamp"}:
                if not (row.get(key) or "").strip():
                    raise ValueError(f"Missing {key} on CSV line {line_number}")
            events.append(Event(
                timestamp=timestamp,
                username=row["username"].strip(),
                source_ip=row["source_ip"].strip(),
                event_type=row["event_type"].strip().lower(),
                status=row["status"].strip().lower(),
                details=(row.get("details") or "").strip(),
            ))
    return sorted(events, key=lambda event: event.timestamp)


def detect_suspicious_activity(
    events: Iterable[Event],
    failed_login_threshold: int = 5,
    business_start_hour: int = 7,
    business_end_hour: int = 19,
) -> list[Alert]:
    """Apply transparent rules to synthetic or authorized log data."""
    if failed_login_threshold < 2:
        raise ValueError("failed_login_threshold must be at least 2")
    if not (0 <= business_start_hour <= 23 and 1 <= business_end_hour <= 24):
        raise ValueError("Business-hour values must be valid hours")
    if business_start_hour >= business_end_hour:
        raise ValueError("business_start_hour must be earlier than business_end_hour")

    event_list = sorted(events, key=lambda event: event.timestamp)
    failures_by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in event_list:
        if event.event_type == "login" and event.status == "failure":
            failures_by_ip[event.source_ip].append(event)

    alerts: list[Alert] = []
    flagged_ips: set[str] = set()
    for ip, failures in failures_by_ip.items():
        if len(failures) >= failed_login_threshold:
            flagged_ips.add(ip)
            first = failures[0]
            alerts.append(Alert(
                timestamp=first.timestamp.strftime(TIMESTAMP_FORMAT),
                severity="HIGH",
                rule_id="AUTH-001",
                rule_name="Repeated failed logins",
                username=first.username,
                source_ip=ip,
                evidence=f"{len(failures)} failed login attempts from this IP in the input dataset.",
                recommendation="Review nearby authentication events and validate the source and account owner.",
            ))

    # Report successful logins after repeated failures from the same source.
    for event in event_list:
        if (event.event_type == "login" and event.status == "success"
                and event.source_ip in flagged_ips):
            prior_failures = [failure for failure in failures_by_ip[event.source_ip]
                              if failure.timestamp <= event.timestamp]
            if len(prior_failures) >= failed_login_threshold:
                alerts.append(Alert(
                    timestamp=event.timestamp.strftime(TIMESTAMP_FORMAT),
                    severity="HIGH",
                    rule_id="AUTH-002",
                    rule_name="Success after repeated failures",
                    username=event.username,
                    source_ip=event.source_ip,
                    evidence=f"Successful login followed {len(prior_failures)} failed attempts from the same IP.",
                    recommendation="Verify whether the login was authorized and inspect surrounding events.",
                ))

    for event in event_list:
        if (event.event_type == "login" and event.status == "success"
                and not (business_start_hour <= event.timestamp.hour < business_end_hour)):
            alerts.append(Alert(
                timestamp=event.timestamp.strftime(TIMESTAMP_FORMAT),
                severity="MEDIUM",
                rule_id="AUTH-003",
                rule_name="Login outside configured business hours",
                username=event.username,
                source_ip=event.source_ip,
                evidence=(f"Successful login at {event.timestamp:%H:%M}; configured window is "
                          f"{business_start_hour:02d}:00–{business_end_hour:02d}:00."),
                recommendation="Check user schedule, approved maintenance, and authentication context.",
            ))

        if event.event_type == "privileged_access" and event.status == "success":
            alerts.append(Alert(
                timestamp=event.timestamp.strftime(TIMESTAMP_FORMAT),
                severity="MEDIUM",
                rule_id="PRIV-001",
                rule_name="Privileged access event",
                username=event.username,
                source_ip=event.source_ip,
                evidence="A successful privileged-access event appears in the sample logs.",
                recommendation="Confirm approval and review the privileged action and its outcome.",
            ))

    return sorted(alerts, key=lambda alert: (alert.timestamp, alert.rule_id, alert.source_ip))


def write_outputs(events: list[Event], alerts: list[Alert], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    alert_fields = list(Alert.__dataclass_fields__.keys())
    with (output_dir / "alerts.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=alert_fields)
        writer.writeheader()
        writer.writerows(asdict(alert) for alert in alerts)

    (output_dir / "alerts.json").write_text(
        json.dumps([asdict(alert) for alert in alerts], indent=2) + "\n", encoding="utf-8"
    )
    counts = Counter(alert.severity for alert in alerts)
    lines = [
        "PYTHON SIEM MONITOR — INCIDENT SUMMARY",
        "=" * 42,
        f"Events analyzed: {len(events)}",
        f"Alerts generated: {len(alerts)}",
        f"High severity: {counts.get('HIGH', 0)}",
        f"Medium severity: {counts.get('MEDIUM', 0)}",
        "",
        "ALERT DETAILS",
        "-" * 42,
    ]
    if not alerts:
        lines.append("No alerts generated by the configured rules.")
    for index, alert in enumerate(alerts, start=1):
        lines.extend([
            f"{index}. [{alert.severity}] {alert.rule_id} — {alert.rule_name}",
            f"   Time: {alert.timestamp}",
            f"   User: {alert.username} | Source IP: {alert.source_ip}",
            f"   Evidence: {alert.evidence}",
            f"   Recommended investigation: {alert.recommendation}",
            "",
        ])
    lines.extend([
        "ANALYST NOTE",
        "These rule matches are leads for investigation, not proof of compromise.",
        "Validate identity, context, asset criticality, and adjacent telemetry before concluding.",
        "This lab uses synthetic data and does not connect to real systems.",
    ])
    (output_dir / "incident_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze synthetic authentication logs with simple SIEM-style rules.")
    parser.add_argument("--input", type=Path, default=Path("data/sample_auth_logs.csv"), help="Path to the input CSV")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"), help="Directory for generated reports")
    parser.add_argument("--threshold", type=int, default=5, help="Failed-login threshold per source IP (default: 5)")
    args = parser.parse_args()
    try:
        events = load_events(args.input)
        alerts = detect_suspicious_activity(events, failed_login_threshold=args.threshold)
        write_outputs(events, alerts, args.output_dir)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    counts = Counter(alert.severity for alert in alerts)
    print("Python SIEM Monitor completed.")
    print(f"Events analyzed : {len(events)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"High / Medium   : {counts.get('HIGH', 0)} / {counts.get('MEDIUM', 0)}")
    print(f"Reports saved to: {args.output_dir.resolve()}")
    for alert in alerts:
        print(f"[{alert.severity}] {alert.rule_id} {alert.rule_name} — {alert.username} @ {alert.source_ip}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
