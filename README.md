# Attack Path Mapper

A defensive security-engineering project for modeling how identity, privilege, trust, and network relationships can combine into high-impact attack paths. The project uses synthetic or explicitly approved graph data, validates that data fail-closed, discovers reachable paths to protected targets, applies explainable contextual scoring, maps relationships to MITRE ATT&CK threat context, and supports evidence-based remediation closure.

The objective is not to simulate compromise. It is to help defenders answer a practical question: **which combinations of otherwise ordinary security relationships create the most important paths to break first?**

## Problem statement

Security teams often review controls individually: network reachability, local administration, privileged groups, service identities, delegated access, remote management, and authentication trust. Risk emerges when these relationships become transitive.

For example, a workstation may reach an application server; that server may depend on a reusable service identity; the service identity may hold local administration on a management host; and the management host may reach a Tier-0 system. None of those observations should automatically be treated as compromise, but together they form a defensible remediation hypothesis.

This repository demonstrates how to make that reasoning deterministic, testable, explainable, and safe.

## Architecture

```text
Synthetic / approved graph evidence
             |
             v
      Fail-closed validation
             |
             v
       Graph construction
             |
             v
   Bounded path discovery
             |
             v
 Explainable contextual scoring
             |
      +------+------+
      |             |
      v             v
ATT&CK context   Portfolio metrics
      |             |
      +------+------+
             v
  Prioritized findings/report
             |
             v
Remediation evidence validation
             |
             v
 Repeat assessment / closure
```

See [`docs/architecture-and-methodology.md`](docs/architecture-and-methodology.md) for trust boundaries, control methodology, scoring rationale, limitations, and closure requirements.

## Repository structure

```text
.github/workflows/security-ci.yml      least-privilege CI
src/attack_path_mapper.py              validation, graph traversal, scoring, metrics
src/remediation.py                     remediation evidence validation
src/reporting.py                       Markdown executive/technical reporting
data/attack_graph.json                 realistic fictional graph scenario
data/remediation_evidence.json         fictional closure-evidence package
tests/test_attack_paths.py             path/risk/input-validation tests
tests/test_remediation_reporting.py    closure/reporting tests
docs/architecture-and-methodology.md   architecture and security methodology
docs/validation-playbook.md            remediation/retest playbook
reports/example-assessment.md           recruiter-facing synthetic assessment
```

## Relationship model

Supported relationship types are intentionally defensive abstractions:

| Relationship | Security meaning |
|---|---|
| `network_reachability` | a source can reach a destination through an approved/synthetic network relationship |
| `local_admin` | an identity or system context has local administrative control |
| `privileged_group` | membership provides elevated authorization |
| `service_account_dependency` | a workload depends on a service identity |
| `management_access` | a source can administer a protected or management-plane target |
| `authentication_trust` | an authentication relationship extends access between contexts |
| `protected_resource_access` | a path terminates in direct access to sensitive data/resources |
| `delegated_control` | delegated rights extend administration to another security boundary |
| `credential_reuse` | a synthetic control weakness represents reusable authentication material |

The engine rejects unsupported relationships, duplicate edges, self-referential edges, malformed criticality values, duplicate starting points/targets, and invalid control structures.

## Risk model

Each discovered path receives a bounded **0–100 contextual score** based on:

1. relationship-risk weights;
2. protected-target criticality;
3. proximity/short-path bonus;
4. documented compensating-control reductions.

Severity bands are:

- **Critical:** 80–100
- **High:** 60–79
- **Medium:** 35–59
- **Low:** 0–34

Every finding includes the scoring rationale, traversed relationships, documented mitigations, target, number of steps, ATT&CK context, and a deterministic SHA-derived finding ID. The score is an explainable prioritization heuristic; it is **not CVSS, exploit probability, or proof of compromise**.

## Synthetic scenario

The included graph contains fictional paths from workstation, VPN-user, and development-user contexts to three protected targets:

- `TIER0-DC-01` — synthetic Tier-0 identity infrastructure;
- `FINANCE-DB-01` — synthetic critical finance database;
- `PKI-CA-01` — synthetic certificate authority.

Example modeled chains include service-account dependencies, local administration, privileged groups, reusable authentication relationships, delegated control, and management-plane access. The dataset also includes documented controls such as phishing-resistant MFA, conditional access, PAM approval, and administrative-workstation restrictions so that compensating controls influence prioritization instead of being ignored.

## MITRE ATT&CK context

ATT&CK is used as a threat-model communication layer, not as evidence that a technique occurred.

Representative mappings include:

- **T1046 — Network Service Discovery** for network-reachability exposure context;
- **T1078 / T1078.002 — Valid Accounts** for administrative and service-account trust;
- **T1021 — Remote Services** for management access;
- **T1098 — Account Manipulation** for privileged/delegated authorization changes;
- **T1550 — Use Alternate Authentication Material** for authentication-trust relationships;
- **T1005 — Data from Local System** for protected-resource access context.

## Usage

Python 3.12+ is recommended. The implementation uses only the standard library.

```bash
python -m src.attack_path_mapper data/attack_graph.json
```

Run the full unit suite:

```bash
python -m unittest discover -s tests -v
```

The command emits JSON containing portfolio metrics and prioritized findings. Reporting logic in `src/reporting.py` can render findings into Markdown for executive and technical review.

## Remediation and validation workflow

The project deliberately separates **finding generation** from **finding closure**.

```text
Confirm relationship ownership
        |
        v
Reduce reachability / trust / standing privilege
        |
        v
Harden service and administrative identities
        |
        v
Capture approved change evidence
        |
        v
Compare before vs after control state
        |
        v
Perform repeat validation
        |
        v
Re-run graph analysis
        |
        v
Close only when effectiveness is demonstrated
```

`src/remediation.py` returns one of four states:

- `needs_evidence`
- `invalid_closure`
- `ready_for_validation`
- `validated`

Required evidence includes a change reference, control owner, before/after state, validation method, and validation result. A ticket alone is not considered evidence that risk was removed.

## Testing

The repository contains unit coverage for:

- path discovery and cycle prevention;
- maximum-depth behavior;
- contextual risk scoring and score bounds;
- compensating-control reductions;
- deterministic finding IDs;
- ATT&CK mapping attachment;
- portfolio metrics;
- duplicate-edge rejection;
- unsupported relationship rejection;
- invalid criticality rejection;
- required-field validation;
- self-edge rejection;
- incomplete remediation evidence;
- invalid unchanged-control closure;
- successful evidence-based closure;
- Markdown reporting constraints.

CI compiles the source/tests, runs `unittest`, and executes the synthetic graph model. The workflow requests only `contents: read` permission.

## Security engineering design decisions

**Fail closed on graph structure.** Unknown relationship types are rejected instead of silently receiving a default risk score.

**Keep scores explainable.** Every risk decision records the factors that influenced it.

**Model controls explicitly.** MFA, PAM, device restrictions, and other documented controls reduce contextual risk rather than disappearing from the graph narrative.

**Use deterministic identifiers.** Stable finding IDs make before/after remediation comparison easier.

**Keep discovery bounded.** Per-path cycle prevention and maximum depth reduce graph explosion while keeping findings understandable.

**Separate hypothesis from evidence.** Reachability means a security relationship deserves review; it does not mean exploitation succeeded.

## Example findings and report

[`reports/example-assessment.md`](reports/example-assessment.md) documents three synthetic remediation themes:

1. application/service-identity path to Tier-0 administration;
2. privileged VPN-user path to critical finance data;
3. development/build identity path to PKI administration.

The report demonstrates risk communication, recommended control breaks, ATT&CK context, and closure criteria without representing real-world compromise.

## Skills demonstrated

This project is intended to demonstrate practical capability in:

- security graph modeling;
- identity and privilege risk analysis;
- attack-surface and attack-path reasoning;
- Python security engineering;
- deterministic risk prioritization;
- fail-closed input validation;
- MITRE ATT&CK mapping;
- remediation governance;
- evidence-based validation;
- unit testing;
- CI/CD security hygiene;
- executive and technical security reporting.

## Limitations

- Source data is synthetic; the project does not connect to AD, Entra ID, AWS, Azure, GCP, endpoint platforms, scanners, or network devices.
- Relationship weights are transparent heuristics, not empirically calibrated breach likelihood.
- Documented controls are evidence inputs rather than automatically verified infrastructure state.
- Paths longer than the configured depth can be omitted.
- The model does not evaluate exploitability, malware behavior, credential contents, or active compromise.
- ATT&CK mappings are contextual and do not indicate observed malicious execution.

## Roadmap

Potential safe extensions include:

- schema-versioned graph imports;
- control-break recommendations ranked by number of paths removed;
- before/after graph-diff reporting;
- centrality and choke-point metrics;
- risk-owner assignment and SLA tracking;
- policy-as-code checks for graph quality;
- optional visualization export formats;
- structured JSON/SARIF reporting for CI integration;
- integration adapters for sanitized, authorized inventory exports.

## Safety and ethics

All names, assets, relationships, change references, and evidence in this repository are fictional. The project performs **no scanning, exploitation, password guessing, credential extraction, ticket requesting, persistence, lateral movement, command-and-control, production targeting, or control modification**. It is a defensive security-engineering portfolio project for attack-path reasoning, prioritization, remediation design, and validation.
