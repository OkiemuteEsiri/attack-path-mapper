from datetime import datetime, timezone
from typing import Any


def render_markdown(findings: list[dict[str, Any]], metrics: dict[str, Any]) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Defensive Attack Path Assessment",
        "",
        f"Generated: {generated}",
        "",
        "## Executive summary",
        "",
        f"- Total reachable protected paths: **{metrics['total_paths']}**",
        f"- Critical paths: **{metrics['critical_paths']}**",
        f"- High paths: **{metrics['high_paths']}**",
        f"- Highest contextual score: **{metrics['highest_score']}/100**",
        "",
        "## Prioritized paths",
        "",
        "| Finding | Severity | Score | Start | Protected target | Steps |",
        "|---|---:|---:|---|---|---:|",
    ]
    for finding in findings:
        lines.append(
            f"| {finding['finding_id']} | {finding['severity']} | {finding['score']} | "
            f"{finding['start']} | {finding['target']} | {finding['steps']} |"
        )

    lines.extend(["", "## Finding detail", ""])
    for finding in findings:
        lines.extend(
            [
                f"### {finding['finding_id']} — {finding['severity'].upper()}",
                "",
                f"**Path:** `{' -> '.join(finding['path'])}`",
                "",
                f"**Relationships:** {', '.join(finding['relationships'])}",
                "",
                f"**MITRE ATT&CK context:** {', '.join(finding['attack_techniques'])}",
                "",
                "**Risk rationale:**",
            ]
        )
        lines.extend(f"- {item}" for item in finding["rationale"])
        if finding["mitigations"]:
            lines.append(f"- Documented compensating controls: {', '.join(finding['mitigations'])}")
        lines.extend(
            [
                "",
                "**Recommended remediation workflow:** reduce unnecessary reachability; enforce least privilege; "
                "separate administrative tiers; harden service identities; validate MFA/PAM controls; then repeat "
                "the graph assessment using post-change evidence.",
                "",
            ]
        )

    lines.extend(
        [
            "## Interpretation constraints",
            "",
            "This report models defensive exposure from synthetic or approved graph data. A reachable path is a risk hypothesis, "
            "not proof of compromise or successful exploitation. ATT&CK references describe threat context only.",
            "",
        ]
    )
    return "\n".join(lines)
