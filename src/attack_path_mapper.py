import hashlib
import json
import sys
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

RELATIONSHIP_RISK = {
    "network_reachability": 8,
    "local_admin": 28,
    "privileged_group": 32,
    "service_account_dependency": 18,
    "management_access": 26,
    "authentication_trust": 18,
    "protected_resource_access": 34,
    "delegated_control": 24,
    "credential_reuse": 24,
}
ALLOWED_RELATIONSHIPS = frozenset(RELATIONSHIP_RISK)
ALLOWED_CRITICALITY = {"low": 5, "medium": 15, "high": 25, "critical": 35}
ATTACK_MAPPING = {
    "network_reachability": "T1046",
    "local_admin": "T1078",
    "privileged_group": "T1098",
    "service_account_dependency": "T1078.002",
    "management_access": "T1021",
    "authentication_trust": "T1550",
    "protected_resource_access": "T1005",
    "delegated_control": "T1098",
    "credential_reuse": "T1078",
}


class ModelValidationError(ValueError):
    """Raised when an attack-graph model fails defensive input validation."""


@dataclass(frozen=True)
class Finding:
    finding_id: str
    start: str
    target: str
    path: tuple[str, ...]
    relationships: tuple[str, ...]
    score: int
    severity: str
    steps: int
    mitigations: tuple[str, ...]
    attack_techniques: tuple[str, ...]
    rationale: tuple[str, ...]


def _require_nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ModelValidationError(f"{field} must be a non-empty string")
    return value.strip()


def validate_model(model: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(model, dict):
        raise ModelValidationError("model must be an object")
    for field in ("starting_points", "protected_targets", "edges"):
        if field not in model:
            raise ModelValidationError(f"missing required field: {field}")
    if not isinstance(model["starting_points"], list) or not model["starting_points"]:
        raise ModelValidationError("starting_points must be a non-empty list")
    if not isinstance(model["protected_targets"], list) or not model["protected_targets"]:
        raise ModelValidationError("protected_targets must be a non-empty list")
    if not isinstance(model["edges"], list):
        raise ModelValidationError("edges must be a list")

    starts = [_require_nonempty_string(v, "starting_point") for v in model["starting_points"]]
    targets = [_require_nonempty_string(v, "protected_target") for v in model["protected_targets"]]
    if len(starts) != len(set(starts)):
        raise ModelValidationError("duplicate starting point")
    if len(targets) != len(set(targets)):
        raise ModelValidationError("duplicate protected target")

    seen_edges: set[tuple[str, str, str]] = set()
    normalized_edges = []
    for index, edge in enumerate(model["edges"]):
        if not isinstance(edge, dict):
            raise ModelValidationError(f"edge[{index}] must be an object")
        source = _require_nonempty_string(edge.get("source"), f"edge[{index}].source")
        target = _require_nonempty_string(edge.get("target"), f"edge[{index}].target")
        relation = _require_nonempty_string(edge.get("type"), f"edge[{index}].type")
        if relation not in ALLOWED_RELATIONSHIPS:
            raise ModelValidationError(f"unsupported relationship type: {relation}")
        if source == target:
            raise ModelValidationError("self-referential edges are not permitted")
        key = (source, target, relation)
        if key in seen_edges:
            raise ModelValidationError(f"duplicate edge: {source}->{target}:{relation}")
        seen_edges.add(key)
        normalized_edges.append({"source": source, "target": target, "type": relation})

    criticality = model.get("asset_criticality", {})
    if not isinstance(criticality, dict):
        raise ModelValidationError("asset_criticality must be an object")
    for asset, value in criticality.items():
        _require_nonempty_string(asset, "asset_criticality key")
        if value not in ALLOWED_CRITICALITY:
            raise ModelValidationError(f"unsupported criticality for {asset}: {value}")

    controls = model.get("controls", {})
    if not isinstance(controls, dict):
        raise ModelValidationError("controls must be an object")
    for edge_key, control_list in controls.items():
        _require_nonempty_string(edge_key, "controls key")
        if not isinstance(control_list, list) or any(not isinstance(v, str) or not v.strip() for v in control_list):
            raise ModelValidationError(f"controls[{edge_key}] must be a list of strings")

    return {
        "starting_points": starts,
        "protected_targets": targets,
        "asset_criticality": criticality,
        "controls": controls,
        "edges": normalized_edges,
    }


def build_graph(edges: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    graph: dict[str, list[dict[str, str]]] = defaultdict(list)
    for edge in edges:
        graph[edge["source"]].append(edge)
    return graph


def find_paths(
    graph: dict[str, list[dict[str, str]]],
    start: str,
    targets: set[str],
    max_depth: int = 6,
) -> list[list[dict[str, str]]]:
    if max_depth < 1:
        raise ValueError("max_depth must be at least 1")
    results: list[list[dict[str, str]]] = []
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


def _severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _control_reduction(edge: dict[str, str], controls: dict[str, list[str]]) -> tuple[int, list[str]]:
    key = f'{edge["source"]}->{edge["target"]}'
    applied = controls.get(key, [])
    return min(18, len(applied) * 6), applied


def score_path(
    path: list[dict[str, str]],
    asset_criticality: dict[str, str],
    controls: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    if not path:
        return {"score": 0, "severity": "low", "steps": 0}
    controls = controls or {}
    relationship_score = sum(RELATIONSHIP_RISK[edge["type"]] for edge in path)
    target = path[-1]["target"]
    criticality = asset_criticality.get(target, "medium")
    criticality_score = ALLOWED_CRITICALITY[criticality]
    short_path_bonus = max(0, 20 - (len(path) * 3))
    reduction = 0
    mitigations: list[str] = []
    for edge in path:
        edge_reduction, edge_controls = _control_reduction(edge, controls)
        reduction += edge_reduction
        mitigations.extend(edge_controls)
    raw_score = relationship_score + criticality_score + short_path_bonus - reduction
    score = max(0, min(100, raw_score))
    techniques = sorted({ATTACK_MAPPING[edge["type"]] for edge in path})
    rationale = [
        f"relationship risk contributes {relationship_score} points",
        f"target criticality ({criticality}) contributes {criticality_score} points",
        f"path length contributes {short_path_bonus} proximity points",
    ]
    if reduction:
        rationale.append(f"documented compensating controls reduce risk by {reduction} points")
    return {
        "score": score,
        "severity": _severity(score),
        "steps": len(path),
        "target": target,
        "relationships": [edge["type"] for edge in path],
        "mitigations": sorted(set(mitigations)),
        "attack_techniques": techniques,
        "rationale": rationale,
    }


def _finding_id(start: str, target: str, path: list[str]) -> str:
    material = "|".join([start, target, *path]).encode("utf-8")
    return "AP-" + hashlib.sha256(material).hexdigest()[:12].upper()


def analyze(model: dict[str, Any], max_depth: int = 6) -> list[dict[str, Any]]:
    normalized = validate_model(model)
    graph = build_graph(normalized["edges"])
    targets = set(normalized["protected_targets"])
    findings: list[Finding] = []
    for start in normalized["starting_points"]:
        for path in find_paths(graph, start, targets, max_depth=max_depth):
            scored = score_path(path, normalized["asset_criticality"], normalized["controls"])
            node_path = [start] + [edge["target"] for edge in path]
            findings.append(
                Finding(
                    finding_id=_finding_id(start, scored["target"], node_path),
                    start=start,
                    target=scored["target"],
                    path=tuple(node_path),
                    relationships=tuple(scored["relationships"]),
                    score=scored["score"],
                    severity=scored["severity"],
                    steps=scored["steps"],
                    mitigations=tuple(scored["mitigations"]),
                    attack_techniques=tuple(scored["attack_techniques"]),
                    rationale=tuple(scored["rationale"]),
                )
            )
    return [asdict(f) for f in sorted(findings, key=lambda item: (-item.score, item.steps, item.finding_id))]


def portfolio_metrics(findings: list[dict[str, Any]]) -> dict[str, Any]:
    severities = Counter(f["severity"] for f in findings)
    targets = Counter(f["target"] for f in findings)
    techniques = Counter(t for f in findings for t in f["attack_techniques"])
    return {
        "total_paths": len(findings),
        "critical_paths": severities["critical"],
        "high_paths": severities["high"],
        "severity_distribution": dict(sorted(severities.items())),
        "target_distribution": dict(sorted(targets.items())),
        "attack_technique_frequency": dict(sorted(techniques.items())),
        "highest_score": max((f["score"] for f in findings), default=0),
    }


def load_model(path: str | Path) -> dict[str, Any]:
    try:
        parsed = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelValidationError(f"unable to load model: {exc}") from exc
    return validate_model(parsed)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m src.attack_path_mapper <attack_graph.json>")
    model = load_model(sys.argv[1])
    findings = analyze(model)
    print(json.dumps({"metrics": portfolio_metrics(findings), "findings": findings}, indent=2))


if __name__ == "__main__":
    main()
