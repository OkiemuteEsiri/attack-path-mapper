# Attack Path Mapper

A defensive security-engineering project for modeling how security relationships can combine into high-impact attack paths. The implementation uses synthetic graph data to identify paths from low-trust starting points to protected assets and then rank those paths for remediation.

## Why This Matters

Individual findings rarely describe the full risk. An exposed workstation, reusable credential relationship, delegated privilege, reachable management interface, or overly broad identity relationship may look moderate in isolation but become high impact when chained together.

This project demonstrates a safe way to convert those relationships into remediation-ready attack paths without performing exploitation.

## Repository Structure

```text
src/attack_path_mapper.py    graph traversal and path scoring
data/attack_graph.json       synthetic security relationship graph
tests/test_attack_paths.py   unit tests
docs/validation-playbook.md  remediation and retest methodology
```

## Relationship Types

Synthetic relationships can represent:

- network reachability;
- local administrative control;
- privileged group membership;
- service-account dependency;
- management-plane access;
- authentication trust;
- access to protected resources.

## Risk Model

Paths are scored using the sensitivity of the destination and the risk weights of traversed relationships. Shorter high-impact paths receive additional priority because they require fewer control failures to reach a protected objective.

The model is intentionally explainable: every score is tied back to the relationships that created it.

## ATT&CK Context

Relevant defensive context may include:

- T1078 - Valid Accounts
- T1068 - Exploitation for Privilege Escalation
- T1021 - Remote Services
- T1069 - Permission Groups Discovery
- T1087 - Account Discovery

Mappings provide threat-model context only. This repository does not claim that any ATT&CK technique occurred in a real environment.

## Usage

```bash
python src/attack_path_mapper.py data/attack_graph.json
python -m unittest discover -s tests
```

## Security Engineering Workflow

```text
Asset / Identity Inventory
      ↓
Relationship Normalization
      ↓
Graph Construction
      ↓
Path Discovery
      ↓
Risk Ranking
      ↓
Control-Break Identification
      ↓
Remediation
      ↓
Path Recalculation / Validation
```

## Safety

The graph, names, assets and relationships are fully synthetic. The project performs no scanning, exploitation, credential access, persistence, lateral movement or production targeting. Its purpose is defensive attack-surface reasoning and remediation prioritization.
