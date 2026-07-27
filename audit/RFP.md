# Request for proposal: independent security review

## Objective

hayatepy seeks an independent application-security review of hayate-auth
v0.10.0 at commit `b885e066355196c9caeedb0819eee03fc4d119ed`,
using signed v0.9.1 as the prior review base. The goal is to identify
exploitable defects and unsafe integration assumptions before recommending
the library as the sole authentication layer for production credentials. This
is a code and design audit, not an OWASP certification engagement.

## Required qualifications and independence

The reviewer should demonstrate recent authentication/OAuth 2.1 work, Python
web security experience, and ability to assess Cloudflare Workers/D1 or an
equivalent edge runtime. The proposal must disclose financial, employment, or
maintainer relationships with hayatepy and identify the people performing the
work. Automated scanning may assist but cannot replace manual review.

## Scope and deliverables

Review the target chain in `current.toml`, `target.toml`, and
`amendments/v0.10.0.toml`, plus the boundaries in `THREAT_MODEL.md`. Inspect
the complete v0.10.0 target, with focused delta review of `v0.9.1..v0.10.0`,
including the core, SQLite/D1 adapters, OAuth client and
authorization-server modes, sessions, recovery, TOTP, magic link, passkeys,
API keys, MCP integration, revocation/introspection/consent, DPoP, release
provenance, migration DDL, and integration guidance.

Deliver:

1. A kickoff scope confirmation and list of exclusions.
2. A threat-model/design review and manual source review.
3. Reproduction of Profiles A–D in `PROCEDURES.md`, with environment records.
4. Exploit or failing-test evidence for each confirmed finding when safe.
5. A report with severity, affected base/delta/integration boundary,
   preconditions, impact, reproduction, remediation, and references.
6. One remediation review after fixes, with findings marked fixed, accepted,
   or unresolved.
7. A public executive summary after coordinated disclosure; sensitive details
   remain private until fixes are available.

Severity should use CVSS 4.0 plus a plain-language rationale. The report must
separate library vulnerabilities, insecure defaults, documentation defects,
and deployment responsibilities. Validate the selected ASVS ledger, but do
not infer coverage solely from existing tests. The final report and public
summary must identify v0.10.0 by tag and commit.

## Coordination and disclosure

Use GitHub private vulnerability reporting for suspected vulnerabilities.
Maintainers acknowledge reports within 72 hours. Agree on encrypted
communication, evidence retention/destruction, embargo length, emergency
notification, and publication wording before work begins.

## Proposal response

Include methodology, named reviewers, schedule, price and payment milestones,
conflicts, assumptions, required access, sample deliverable, retest terms, and
at least two relevant references. State whether production Cloudflare account
configuration review and penetration testing are included or priced
separately.

The engagement is commissioned only when scope, reviewer, budget, and dates
are recorded on the tracking issue. Publishing this RFP and audit pack is
preparation, not completion of the independent audit.

The acceptance gate for a production-trust recommendation is: every confirmed
critical/high finding is fixed and retested; medium/low findings are fixed or
explicitly accepted with rationale; reproduction deviations are recorded; and
the reviewer approves a public summary. Maintainer-authored tests, this pack,
and a green CI run are evidence inputs, not independent assurance.

After the initial engagement, re-scope review on every trigger listed in
`../SECURITY.md` and perform an annual threat-model/standards review. Proposals
should price a focused delta review and retest separately from a full review.
