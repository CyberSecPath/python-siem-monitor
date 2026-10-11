import csv
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from src.siem_monitor import Event, detect_suspicious_activity, load_events, write_outputs


class DetectionRuleTests(unittest.TestCase):
    def event(self, time, user="analyst", ip="192.0.2.10", kind="login", status="success"):
        return Event(datetime.strptime(time, "%Y-%m-%d %H:%M:%S"), user, ip, kind, status)

    def test_repeated_failures_generate_high_alert(self):
        events = [self.event(f"2026-10-10 08:00:{i:02d}", ip="203.0.113.9", status="failure") for i in range(5)]
        alerts = detect_suspicious_activity(events)
        self.assertIn("AUTH-001", [alert.rule_id for alert in alerts])
        self.assertEqual("HIGH", next(a.severity for a in alerts if a.rule_id == "AUTH-001"))

    def test_success_after_threshold_generates_alert(self):
        events = [self.event(f"2026-10-10 08:00:{i:02d}", ip="203.0.113.9", status="failure") for i in range(5)]
        events.append(self.event("2026-10-10 08:01:00", ip="203.0.113.9", status="success"))
        self.assertIn("AUTH-002", [alert.rule_id for alert in detect_suspicious_activity(events)])

    def test_after_hours_login_generates_medium_alert(self):
        alerts = detect_suspicious_activity([self.event("2026-10-10 23:00:00")])
        self.assertIn("AUTH-003", [alert.rule_id for alert in alerts])

    def test_normal_business_hours_login_is_not_flagged(self):
        alerts = detect_suspicious_activity([self.event("2026-10-10 10:00:00")])
        self.assertEqual([], alerts)

    def test_privileged_access_generates_alert(self):
        event = self.event("2026-10-10 10:00:00", user="root", kind="privileged_access")
        self.assertIn("PRIV-001", [alert.rule_id for alert in detect_suspicious_activity([event])])

    def test_invalid_threshold_rejected(self):
        with self.assertRaises(ValueError):
            detect_suspicious_activity([], failed_login_threshold=1)

    def test_sample_csv_loads(self):
        project_root = Path(__file__).resolve().parents[1]
        events = load_events(project_root / "data" / "sample_auth_logs.csv")
        self.assertGreater(len(events), 0)

    def test_reports_are_created(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            events = [self.event("2026-10-10 23:00:00")]
            alerts = detect_suspicious_activity(events)
            write_outputs(events, alerts, Path(temp_dir))
            self.assertTrue((Path(temp_dir) / "alerts.csv").exists())
            self.assertTrue((Path(temp_dir) / "alerts.json").exists())
            self.assertTrue((Path(temp_dir) / "incident_report.txt").exists())


if __name__ == "__main__":
    unittest.main()
