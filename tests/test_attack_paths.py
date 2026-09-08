import unittest

from src.attack_path_mapper import analyze, build_graph, find_paths, score_path


class AttackPathMapperTests(unittest.TestCase):
    def test_find_paths_reaches_protected_target(self):
        graph = build_graph([
            {"source": "A", "target": "B", "type": "network_reachability"},
            {"source": "B", "target": "C", "type": "local_admin"},
        ])
        paths = find_paths(graph, "A", {"C"})
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0][-1]["target"], "C")

    def test_high_impact_path_scores_high(self):
        path = [
            {"source": "A", "target": "B", "type": "privileged_group"},
            {"source": "B", "target": "C", "type": "protected_resource_access"},
        ]
        result = score_path(path, {"C": 35})
        self.assertGreaterEqual(result["score"], 80)
        self.assertEqual(result["severity"], "critical")

    def test_analyze_orders_by_risk(self):
        model = {
            "starting_points": ["A"],
            "protected_targets": ["C", "D"],
            "asset_sensitivity": {"C": 40, "D": 10},
            "edges": [
                {"source": "A", "target": "B", "type": "network_reachability"},
                {"source": "B", "target": "C", "type": "management_access"},
                {"source": "A", "target": "D", "type": "network_reachability"}
            ],
        }
        findings = analyze(model)
        self.assertEqual(findings[0]["target"], "C")


if __name__ == "__main__":
    unittest.main()
