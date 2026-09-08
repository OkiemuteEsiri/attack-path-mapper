# Attack Path Remediation and Validation Playbook

## Goal

Reduce high-impact paths by breaking the smallest number of risky relationships while preserving legitimate business access.

## Triage

Prioritize paths that combine:
- privileged or administrative relationships;
- access to Tier-0 or sensitive business assets;
- short path length;
- multiple independent starting points;
- weakly governed service or application identities.

## Control Breakpoints

### Network reachability
- Restrict unnecessary east-west communication.
- Enforce management-plane segmentation.
- Validate firewall and ACL changes with approved connectivity tests.

### Local administrative control
- Remove standing local-admin rights that are not required.
- Use just-in-time elevation or managed privileged-access workflows.
- Validate effective local group membership after remediation.

### Privileged group membership
- Remove stale or unnecessary memberships.
- Review nested-group inheritance.
- Prefer eligible/time-bound assignments where supported.
- Recalculate graph relationships after the change.

### Service-account dependency
- Reduce privilege and interactive-use capability.
- Separate identities across trust boundaries where feasible.
- Prefer managed identities and constrained delegation patterns.

### Management access
- Restrict management interfaces to dedicated administration paths.
- Require strong authentication and hardened privileged workstations where appropriate.

## Validation Sequence

1. Capture the original synthetic path and identified control break.
2. Apply the modeled remediation.
3. Remove or downgrade the affected relationship in the graph.
4. Run the path analyzer again.
5. Confirm that the target is no longer reachable from the same start point or that residual path risk is materially lower.
6. Check for alternate paths introduced or left unchanged.
7. Document residual risk and ownership.

## Reporting

A remediation-ready finding should include:
- source/start point;
- protected target;
- relationship chain;
- risk score and rationale;
- recommended control break;
- owner;
- validation evidence;
- residual path, if any.

The graph is a decision-support model, not proof that a real attacker has traversed any represented path.
