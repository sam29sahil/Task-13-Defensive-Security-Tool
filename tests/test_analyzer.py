import csv
import tempfile
import unittest
from pathlib import Path
from src.security_analyzer import analyze_events, load_events, write_report

class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            {"timestamp":"t1","username":"alice","source_ip":"192.0.2.10","status":"failed"},
            {"timestamp":"t2","username":"alice","source_ip":"192.0.2.10","status":"failed"},
            {"timestamp":"t3","username":"alice","source_ip":"192.0.2.10","status":"failed"},
            {"timestamp":"t4","username":"bob","source_ip":"198.51.100.8","status":"success"},
        ]
    def test_summary_counts(self):
        summary, _ = analyze_events(self.events, 3)
        self.assertEqual((summary["total_events"],summary["successful_logins"],summary["failed_logins"]),(4,1,3))
        self.assertEqual(summary["unique_source_ips"],2)
    def test_threshold_flags_ip_and_account(self):
        _, findings = analyze_events(self.events, 3)
        self.assertEqual({x["finding_type"] for x in findings},
            {"repeated_failures_from_ip","repeated_failures_for_account"})
    def test_threshold_can_be_changed(self):
        _, findings = analyze_events(self.events, 4)
        self.assertEqual(findings, [])
    def test_invalid_threshold(self):
        with self.assertRaises(ValueError): analyze_events(self.events, 0)
    def test_invalid_status(self):
        with self.assertRaises(ValueError): analyze_events([dict(self.events[0],status="unknown")])
    def test_invalid_ip_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"bad.csv"
            path.write_text("timestamp,username,source_ip,status\nt1,alice,nope,failed\n",encoding="utf-8")
            with self.assertRaisesRegex(ValueError,"invalid source_ip"): load_events(path)
    def test_report_is_written(self):
        _, findings=analyze_events(self.events,3)
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/"nested"/"findings.csv"
            write_report(findings,output)
            with output.open(newline="",encoding="utf-8") as handle: rows=list(csv.DictReader(handle))
            self.assertEqual(len(rows),2)
            self.assertEqual(rows[0]["threshold"],"3")

if __name__ == "__main__": unittest.main()
