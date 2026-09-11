# Example Executive Attack Path Assessment

> Synthetic portfolio evidence only. No production environment, client, employer, credential, or real identity data is represented.

## Executive summary

The modeled environment contains multiple trust and administration chains from lower-trust user contexts to high-value identity, finance, and PKI targets. The principal security concern is not a single relationship; it is the accumulation of authentication trust, service-account dependency, local administration, delegated control, and management access across multiple control boundaries.

Priority treatment should focus on breaking the shortest high-impact paths rather than remediating graph edges independently.

## Highest-priority themes

### 1. Service identity to Tier-0 administration

`WS-EDGE-01 -> APP-SRV-01 -> SVC-APP-01 -> MGMT-SRV-01 -> TIER0-DC-01`

**Risk:** a workstation-to-application route combines service-account dependency, local administration, and management access to reach a Tier-0 target.

**Recommended treatment:** isolate the application tier, replace reusable service credentials with managed identity where feasible, remove unnecessary local-admin relationships, and enforce controlled privileged administration from dedicated management endpoints.

### 2. Privileged group to finance data

`VPN-USER-01 -> OPS-GROUP-01 -> FINANCE-DB-01`

**Risk:** privileged group membership creates a short path to a critical data system. Existing MFA and conditional-access controls reduce, but do not eliminate, concentration of privilege.

**Recommended treatment:** validate whether direct database access is operationally required; enforce just-in-time privilege; separate administration from ordinary user sessions; and monitor privileged entitlement changes.

### 3. Development identity to PKI administration

`DEV-USER-02 -> DEV-JUMP-01 -> BUILD-SVC-01 -> PKI-OPS-01 -> PKI-CA-01`

**Risk:** authentication trust, credential reuse, delegated control, and management access combine into a path from a development context to a certificate authority.

**Recommended treatment:** remove credential reuse, migrate build automation to managed credentials, restrict PKI delegation, and require dedicated privileged administration for CA management.

## Validation workflow

A path should not be closed because a change ticket exists. Closure evidence should demonstrate:

1. approved change reference and owner;
2. before-state evidence;
3. after-state evidence showing the relationship or control changed;
4. a repeatable validation method;
5. a post-change result confirming control effectiveness;
6. repeat graph analysis showing the target path is removed or materially reduced.

## MITRE ATT&CK context

Representative defensive context includes T1046 (Network Service Discovery), T1078/T1078.002 (Valid Accounts), T1021 (Remote Services), T1098 (Account Manipulation), T1550 (Use Alternate Authentication Material), and T1005 (Data from Local System). These mappings help communicate threat relevance and do not assert observed malicious activity.

## Management takeaway

The remediation objective is to reduce transitive privilege and trust. The most efficient control improvements are those that break multiple paths at once: eliminate unnecessary administration edges, isolate management planes, reduce standing privilege, harden service identities, and verify every closure with evidence and repeat analysis.
