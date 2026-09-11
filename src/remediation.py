from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RemediationDecision:
    status: str
    missing_evidence: tuple[str, ...]
    rationale: tuple[str, ...]


REQUIRED_EVIDENCE = (
    "change_reference",
    "control_owner",
    "before_state",
    "after_state",
    "validation_method",
    "validation_result",
)


def validate_remediation(evidence: dict[str, Any]) -> RemediationDecision:
    """Evaluate whether an attack-path closure has sufficient defensive evidence.

    This function never changes infrastructure. It validates an evidence package
    supplied after a separately authorized remediation activity.
    """
    if not isinstance(evidence, dict):
        raise ValueError("evidence must be an object")

    missing = tuple(
        field
        for field in REQUIRED_EVIDENCE
        if field not in evidence or not isinstance(evidence[field], str) or not evidence[field].strip()
    )
    if missing:
        return RemediationDecision(
            status="needs_evidence",
            missing_evidence=missing,
            rationale=("closure cannot be accepted until required evidence is complete",),
        )

    before = evidence["before_state"].strip().lower()
    after = evidence["after_state"].strip().lower()
    validation = evidence["validation_result"].strip().lower()

    if before == after:
        return RemediationDecision(
            status="invalid_closure",
            missing_evidence=(),
            rationale=("before_state and after_state do not demonstrate a control-state change",),
        )

    if validation not in {"passed", "pass", "effective", "validated"}:
        return RemediationDecision(
            status="ready_for_validation",
            missing_evidence=(),
            rationale=("evidence is complete but validation_result does not confirm control effectiveness",),
        )

    return RemediationDecision(
        status="validated",
        missing_evidence=(),
        rationale=(
            "required evidence is complete",
            "control state changed",
            "post-change validation confirms effectiveness",
        ),
    )
