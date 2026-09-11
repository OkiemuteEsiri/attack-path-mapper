# Architecture and Methodology

## Objective

This project demonstrates how a security engineering team can convert approved, synthetic identity and network relationships into defensible attack-path risk hypotheses without performing exploitation, credential collection, or live enumeration.

## Trust boundaries

1. **Input boundary** — JSON graph data is treated as untrusted and validated fail-closed.
2. **Analysis boundary** — the engine processes graph relationships entirely offline.
3. **Decision boundary** — a path is a risk hypothesis, not proof of compromise.
4. **Remediation boundary** — closure requires explicit evidence and independent post-change validation.

## Components

```text
Synthetic / approved graph data
          |
          v
  validation layer
          |
          v
 graph + path discovery
          |
          v
 contextual risk scoring
          |
          +----> ATT&CK context
          |
          v
 prioritized findings + metrics
          |
          v
 remediation evidence validator
          |
          v
 repeat assessment / closure decision
```

## Data model

A graph contains:

- `starting_points`: potential low-trust footholds or user contexts;
- `protected_targets`: systems or identities requiring heightened protection;
- `asset_criticality`: business/security impact classification;
- `controls`: documented compensating controls on specific edges;
- `edges`: authorized relationships such as reachability, administration, trust, delegated control, and protected-resource access.

The model intentionally excludes passwords, hashes, tokens, private keys, exploit payloads, command-and-control instructions, or production-specific identifiers.

## Path discovery

The engine uses bounded breadth-first traversal with per-path cycle prevention. Protected targets terminate a discovered path. The default maximum depth is six relationships to limit graph explosion and keep results explainable.

## Contextual risk model

Risk is bounded to 0–100 and combines:

- relationship risk weights;
- protected-target criticality;
- a proximity bonus for short paths;
- documented compensating-control reductions.

The score is transparent by design. Every finding records the rationale used to derive its score. It is not CVSS and should not be interpreted as exploit probability.

## MITRE ATT&CK use

ATT&CK IDs are used only as defensive threat-model context. Representative mappings include:

| Relationship | ATT&CK context | Defensive interpretation |
|---|---|---|
| network reachability | T1046 | reachable services can increase discovery/exposure paths |
| local administration | T1078 | valid administrative identities can expand impact |
| management access | T1021 | remote administrative channels increase path reachability |
| authentication trust | T1550 | reusable authentication relationships can amplify trust |
| privileged group | T1098 | privileged membership changes exposure concentration |
| protected resource access | T1005 | paths to sensitive data require strong access controls |

These mappings do not assert that a technique was executed.

## Remediation methodology

Recommended treatment sequence:

1. confirm that the graph relationship is current and correctly owned;
2. remove unnecessary reachability or trust;
3. apply least privilege to administrative and service identities;
4. isolate Tier-0 / high-value administration paths;
5. prefer managed identities or controlled credential rotation;
6. enforce MFA/PAM/device controls where applicable;
7. document the approved change;
8. capture before/after control-state evidence;
9. repeat the graph assessment;
10. close only when post-change validation demonstrates control effectiveness.

## Validation states

The remediation validator returns:

- `needs_evidence` — required evidence is incomplete;
- `invalid_closure` — the evidence does not demonstrate a state change;
- `ready_for_validation` — evidence is complete but effectiveness is not confirmed;
- `validated` — evidence is complete and the post-change result confirms effectiveness.

## Limitations

- Graph quality depends on the quality and freshness of source data.
- Relationship weights are explainable heuristics, not empirical breach probability.
- Controls are represented as documented evidence, not automatically tested infrastructure controls.
- Bounded path search can omit longer paths beyond the configured depth.
- The project deliberately does not perform live domain, cloud, endpoint, or network enumeration.
