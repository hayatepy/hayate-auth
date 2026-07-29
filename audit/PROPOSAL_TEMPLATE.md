# Proposal response template: hayate-auth v0.10.3

Use this template to respond to [`RFP.md`](RFP.md). A completed proposal may
be exchanged privately; it does not need to be committed to the public
repository. Do not include suspected vulnerabilities, credentials, customer
data, or exploit details here. Report suspected vulnerabilities through
GitHub private vulnerability reporting.

## Target acceptance

- Proposal identifier:
- Proposal date and validity period:
- Audit-pack commit reviewed:
- Review target: `v0.10.3` at
  `20dd7ae08c12051d23fdbe4b242578f800dacdfc`
- Prior immutable base: `v0.9.1` at
  `b8486cf40cfa227b44062ee41bddb4a6b74132fa`
- Source range: `v0.9.1..v0.10.3`
- Confirmed amendment: `audit/amendments/v0.10.3.toml`
- Confirm that target tags, commits, artifacts, and profiles will not be
  silently substituted:

List any target ambiguity before providing a price or schedule.

## Organization, review team, and independence

- Legal contracting entity and jurisdiction:
- Primary commercial contact:
- Primary security contact and emergency contact:
- Independence/conflict statement covering hayatepy, the maintainer, named
  reviewers, and subcontractors:
- Financial, employment, contributor, advisory, or other relevant
  relationships:
- Subcontractors and the work assigned to each:

| Named reviewer | Role | Relevant auth/OAuth/Python/edge experience | Planned allocation |
|---|---|---|---|
|  |  |  |  |

## Methodology and coverage

Describe the manual threat-model, design, and source-review method. Identify
automated tools separately; tool output does not replace manual review.

- Authentication/session review:
- OAuth 2.1 authorization-server, resource-server, client, and MCP review:
- DPoP and cryptographic/KDF review:
- SQLite/D1 atomicity, migrations, and concurrency review:
- Passkey, TOTP, magic-link, recovery, and API-key review:
- Scheme-bound cookies and trusted-proxy URL reconstruction:
- Release provenance, SBOM, dependencies, and integration guidance:
- Standards or control frameworks used:
- Adversarial tests the reviewer expects to add:

Record planned reproduction of Profiles A-D from `PROCEDURES.md`.

| Profile | Complete / partial / excluded | Environment and planned evidence | Deviation or exclusion rationale |
|---|---|---|---|
| A — SQLite and direct/ASGI HTTP |  |  |  |
| B — PostgreSQL generated DDL and upgrade |  |  |  |
| C — stable MCP Bearer on workerd/D1 |  |  |  |
| D — v0.10.3 security delta on workerd/D1 |  |  |  |

## Scope, exclusions, and required access

- Confirmed code/design scope:
- Explicit exclusions:
- Assumptions and dependencies:
- Repository or communication access required:
- Production Cloudflare configuration review: included / separately priced /
  excluded
- Production penetration testing: included / separately priced / excluded
- Test accounts, infrastructure, or maintainer time required:
- Data locations, subprocessors, and evidence-handling controls:

No production access is implied by this RFP. Access is granted separately,
least-privilege, time-bounded, and only after scope and handling terms are
agreed.

## Schedule and commercials

| Milestone | Proposed date or duration | Price and payment trigger |
|---|---|---|
| Scope confirmation and kickoff |  |  |
| Manual review and profile reproduction |  |  |
| Draft private report |  |  |
| Maintainer remediation window |  |  |
| Independent retest |  |  |
| Final report and approved public summary |  |  |

- Total price, currency, taxes, and expenses:
- Payment milestones and payment terms:
- Proposal expiry:
- Change-order and cancellation terms:
- Earliest start and reviewer availability:

## Disclosure, reporting, and evidence handling

- Encrypted private communication channel:
- Emergency notification path:
- Expected acknowledgement/response windows:
- Evidence storage, access control, retention period, and destruction:
- Proposed embargo and coordinated-disclosure terms:
- CVSS 4.0 calculation and plain-language severity process:
- Process for disputed, duplicate, accepted-risk, and informational findings:
- Process for separately labeling library defects, insecure defaults,
  documentation defects, and deployment responsibilities:

## Deliverables, retest, and publication

Confirm each deliverable or state a deviation:

- [ ] kickoff scope confirmation and exclusions
- [ ] threat-model/design review and manual source review
- [ ] Profiles A-D environment and reproduction record
- [ ] safe exploit or failing-test evidence for confirmed findings
- [ ] private report with severity, preconditions, impact, reproduction,
      remediation, and references
- [ ] one independent remediation retest
- [ ] final disposition of every finding as fixed, accepted, or unresolved
- [ ] approved public executive summary identifying v0.10.3 by tag and commit

- Retest scope, timing, included hours, and price:
- Conditions that require a separately priced retest:
- Report ownership and permitted distribution:
- Public-summary authorship, approval, and attribution:
- Whether a focused later-delta review is available and how it is priced:

## Relevant references

Provide at least two recent, relevant client references or public deliverables.
For confidential references, describe how they can be verified privately.

1.
2.

## Deviations and open questions

List every proposed change to the RFP, unresolved assumption, or question that
could change scope, price, dates, access, disclosure, or acceptance.

## Maintainer award record

This section is completed by the maintainer when accepting a proposal. Store
commercially sensitive terms and vulnerability details privately. Record the
non-sensitive subset on
[`hayate-auth#14`](https://github.com/hayatepy/hayate-auth/issues/14).

- Selected legal entity and named reviewer(s):
- Independence/conflict statement reviewed on:
- Confirmed target, scope, profiles, and exclusions:
- Production Cloudflare review and penetration-test treatment:
- Agreed price, currency, taxes, expenses, and payment milestones:
- Contract and proposal identifiers:
- Start, draft-report, remediation, retest, and final dates:
- Encrypted disclosure channel and emergency contact confirmed:
- Evidence retention/destruction and embargo terms confirmed:
- Retest and public-summary terms confirmed:
- Private report received and triaged on:
- Critical/high findings fixed and independently retested:
- Medium/low findings fixed or accepted with rationale:
- Public summary or attestation URL:
- Tracking issue update URL:
