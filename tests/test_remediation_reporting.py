import unittest

from src.attack_path_mapper import analyze, portfolio_metrics
from src.remediation import validate_remediation
from src.reporting import render_markdown


class RemediationReportingTests(unittest.TestCase):
    def test_missing_evidence_is_rejected(self):
        decision = validate_remediation({"change_reference": "CHG-1"})
        self.assertEqual(decision.status, "needs_evidence")
        self.assertIn("control_owner", decision.missing_evidence)

    def test_unchanged_control_state_is_invalid(self):
        evidence = {
            "change_reference": "CHG-1",
            "control_owner": "Identity",
            "before_state": "open",
            "after_state": "open",
            "validation_method": "review",
            "validation_result": "passed",
        }
        decision = validate_remediation(evidence)
        self.assertEqual(decision.status, "invalid_closure")

    def test_complete_effective_evidence_is_validated(self):
        evidence = {
            "change_reference": "CHG-1",
            "control_owner": "Identity",
            "before_state": "unrestricted",
            "after_state": "restricted",
            "validation_method": "graph reassessment",
            "validation_result": "passed",
        }
        self.assertEqual(validate_remediation(evidence).status, "validated")

    def test_report_contains_findings_and_constraints(self):
        model = {
            "starting_points": ["A"],
            "protected_targets": ["C"],
            "asset_criticality": {"C": "critical"},
            "controls": {},
            "edges": [
                {"source": "A", "target": "B", "type": "local_admin"},
                {"source": "B", "target": "C", "type": "management_access"},
            ],
        }
        findings = analyze(model)
        report = render_markdown(findings, portfolio_metrics(findings))
        self.assertIn("Defensive Attack Path Assessment", report)
        self.assertIn(findings[0]["finding_id"], report)
        self.assertIn("not proof of compromise", report)


if __name__ == "__main__":
    unittest.main()
