import unittest

from src.attack_path_mapper import (
    ModelValidationError,
    analyze,
    build_graph,
    find_paths,
    portfolio_metrics,
    score_path,
    validate_model,
)


class AttackPathMapperTests(unittest.TestCase):
    def setUp(self):
        self.model = {
            "starting_points": ["USER-01"],
            "protected_targets": ["TIER0-DC-01", "FINANCE-DB-01"],
            "asset_criticality": {"TIER0-DC-01": "critical", "FINANCE-DB-01": "high"},
            "controls": {"USER-01->APP-01": ["MFA", "device_compliance"]},
            "edges": [
                {"source": "USER-01", "target": "APP-01", "type": "authentication_trust"},
                {"source": "APP-01", "target": "ADM-01", "type": "local_admin"},
                {"source": "ADM-01", "target": "TIER0-DC-01", "type": "management_access"},
                {"source": "USER-01", "target": "FINANCE-DB-01", "type": "protected_resource_access"},
            ],
        }

    def test_find_paths_reaches_protected_target(self):
        graph = build_graph(self.model["edges"])
        paths = find_paths(graph, "USER-01", {"TIER0-DC-01"})
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0][-1]["target"], "TIER0-DC-01")

    def test_cycle_is_not_revisited(self):
        graph = build_graph([
            {"source": "A", "target": "B", "type": "network_reachability"},
            {"source": "B", "target": "A", "type": "authentication_trust"},
            {"source": "B", "target": "C", "type": "management_access"},
        ])
        paths = find_paths(graph, "A", {"C"})
        self.assertEqual(len(paths), 1)
        self.assertEqual([e["target"] for e in paths[0]], ["B", "C"])

    def test_max_depth_must_be_positive(self):
        with self.assertRaises(ValueError):
            find_paths({}, "A", {"B"}, max_depth=0)

    def test_high_impact_path_scores_high(self):
        path = [
            {"source": "A", "target": "B", "type": "privileged_group"},
            {"source": "B", "target": "C", "type": "protected_resource_access"},
        ]
        result = score_path(path, {"C": "critical"})
        self.assertGreaterEqual(result["score"], 80)
        self.assertEqual(result["severity"], "critical")

    def test_controls_reduce_risk(self):
        path = [{"source": "A", "target": "C", "type": "protected_resource_access"}]
        baseline = score_path(path, {"C": "high"})
        controlled = score_path(path, {"C": "high"}, {"A->C": ["MFA", "PAM"]})
        self.assertLess(controlled["score"], baseline["score"])
        self.assertEqual(controlled["mitigations"], ["MFA", "PAM"])

    def test_scores_are_bounded(self):
        path = [
            {"source": "A", "target": "B", "type": "privileged_group"},
            {"source": "B", "target": "C", "type": "protected_resource_access"},
            {"source": "C", "target": "D", "type": "local_admin"},
        ]
        result = score_path(path, {"D": "critical"})
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)

    def test_analyze_orders_by_risk(self):
        findings = analyze(self.model)
        scores = [finding["score"] for finding in findings]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_finding_ids_are_deterministic(self):
        first = analyze(self.model)
        second = analyze(self.model)
        self.assertEqual([f["finding_id"] for f in first], [f["finding_id"] for f in second])

    def test_attack_mapping_is_attached(self):
        findings = analyze(self.model)
        techniques = {t for finding in findings for t in finding["attack_techniques"]}
        self.assertIn("T1021", techniques)
        self.assertIn("T1005", techniques)

    def test_portfolio_metrics(self):
        metrics = portfolio_metrics(analyze(self.model))
        self.assertEqual(metrics["total_paths"], 2)
        self.assertGreaterEqual(metrics["highest_score"], 1)
        self.assertIn("TIER0-DC-01", metrics["target_distribution"])

    def test_duplicate_edge_is_rejected(self):
        model = dict(self.model)
        model["edges"] = self.model["edges"] + [dict(self.model["edges"][0])]
        with self.assertRaises(ModelValidationError):
            validate_model(model)

    def test_unknown_relationship_is_rejected(self):
        model = dict(self.model)
        model["edges"] = [{"source": "A", "target": "B", "type": "magic_access"}]
        with self.assertRaises(ModelValidationError):
            validate_model(model)

    def test_unknown_criticality_is_rejected(self):
        model = dict(self.model)
        model["asset_criticality"] = {"TIER0-DC-01": "extreme"}
        with self.assertRaises(ModelValidationError):
            validate_model(model)

    def test_missing_required_field_is_rejected(self):
        model = dict(self.model)
        model.pop("edges")
        with self.assertRaises(ModelValidationError):
            validate_model(model)

    def test_self_edge_is_rejected(self):
        model = dict(self.model)
        model["edges"] = [{"source": "A", "target": "A", "type": "network_reachability"}]
        with self.assertRaises(ModelValidationError):
            validate_model(model)


if __name__ == "__main__":
    unittest.main()
