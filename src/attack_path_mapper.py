import json
import sys
from collections import defaultdict, deque
from pathlib import Path

RELATIONSHIP_RISK = {
    "network_reachability": 10,
    "local_admin": 30,
    "privileged_group": 35,
    "service_account_dependency": 20,
    "management_access": 30,
    "authentication_trust": 20,
    "protected_resource_access": 40,
}


def build_graph(edges: list[dict]) -> dict[str, list[dict]]:
    graph = defaultdict(list)
    for edge in edges:
        graph[edge["source"]].append(edge)
    return graph


def find_paths(graph: dict[str, list[dict]], start: str, targets: set[str], max_depth: int = 6) -> list[list[dict]]:
    results = []
    queue = deque([(start, [], {start})])

    while queue:
        node, path, visited = queue.popleft()
        if len(path) >= max_depth:
            continue

        for edge in graph.get(node, []):
            destination = edge["target"]
            if destination in visited:
                continue

            new_path = path + [edge]
            if destination in targets:
                results.append(new_path)
                continue

            queue.append((destination, new_path, visited | {destination}))

    return results


def score_path(path: list[dict], asset_sensitivity: dict[str, int]) -> dict:
    if not path:
        return {"score": 0, "severity": "low", "steps": 0}

    relationship_score = sum(RELATIONSHIP_RISK.get(edge.get("type"), 10) for edge in path)
    target = path[-1]["target"]
    sensitivity = asset_sensitivity.get(target, 10)
    short_path_bonus = max(0, 30 - (len(path) * 5))
    score = min(100, relationship_score + sensitivity + short_path_bonus)

    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 35:
        severity = "medium"
    else:
        severity = "low"

    return {
        "score": score,
        "severity": severity,
        "steps": len(path),
        "target": target,
        "relationships": [edge["type"] for edge in path],
    }


def analyze(model: dict) -> list[dict]:
    graph = build_graph(model["edges"])
    targets = set(model["protected_targets"])
    sensitivity = model.get("asset_sensitivity", {})
    findings = []

    for start in model["starting_points"]:
        for path in find_paths(graph, start, targets):
            finding = score_path(path, sensitivity)
            finding["start"] = start
            finding["path"] = [start] + [edge["target"] for edge in path]
            findings.append(finding)

    return sorted(findings, key=lambda x: x["score"], reverse=True)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python src/attack_path_mapper.py <attack_graph.json>")

    model = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    print(json.dumps(analyze(model), indent=2))


if __name__ == "__main__":
    main()
