# Implementation roadmap

## What is complete in this package

The repository now contains a working local foundation:

- scoped case creation;
- target-specific investigation plans;
- curated tool catalog and current/course-era dispositions;
- reusable search-query recipes;
- source, artifact, and source-backed claim records;
- SHA-256 hashing and a hash-chained activity ledger;
- normalized observations, entities, aliases, relationships, events, and
  derivation records;
- integrity/reference checks across every normalized record type;
- JSON, CSV, and GraphML exports;
- portable case ZIPs with per-file SHA-256 manifests and standalone
  verification;
- opt-in passive adapters for Wayback CDX, Common Crawl, RDAP, DNS-over-HTTPS,
  crt.sh, SearXNG, and a dataset-only WhatsMyName review queue;
- ExifTool, ffprobe, Tesseract, and OCRmyPDF local wrappers with
  command/version/derivation logging;
- a loopback-bound SearXNG and ArchiveBox Compose profile;
- JSON Schema Draft 2020-12 interchange definitions enforced at runtime;
- sensitivity, jurisdiction, retention, reviewer, collection-tier, and
  auditable case-status controls;
- policy-driven, non-destructive redacted JSON dissemination views;
- checksummed crash-recovery journals, atomic metadata replacement,
  cross-platform JSONL/ledger locking, and a ledger-preserving registered
  v1.0-to-v1.1-to-v1.2-to-v1.3-to-v1.4 migration chain;
- auditable legal-hold placement/release, normalized hold history, and
  hold-aware retention controls;
- bounded transient-provider retries and an opt-in provider health/status
  registry;
- strict adapter option allowlists and a hash-chained external-disclosure
  confirmation gate;
- credential-gated SecurityTrails historical DNS with normalized observations,
  preserved raw responses, and no-network unconfigured health checks;
- a local Sherlock runner constrained to one username, an explicit 25-site
  maximum allowlist, bounded timeouts, raw CSV preservation, and candidate-only
  attribution;
- reproducible A4 PDF reports, policy-first redacted PDF derivatives, rendered
  page verification, and optional Ed25519 signatures over bundle manifests;
- UTC-normalized event records and a non-destructive analysis-quality audit;
- an offline timeline/entity review page, append-only merge/split decisions,
  geolocation/media worksheets, Maltego tables, and audit dispositions;
- exact-target, expiry-limited licensed-provider approvals and revocations,
  bounded HIBP/Hunter/Censys/Companies House APIs, SecurityTrails governance,
  and a jurisdictional official-registry catalog;
- Markdown report generation;
- operating, architecture, and report templates;
- unit tests for the end-to-end case lifecycle.

This is the correct first deliverable because it remains useful even when every
external provider changes.

## Phase 1 — harden the local core (complete)

Deliverables:

- Legal-hold placement/release, normalized history, report visibility, and
  hold-aware retention controls are complete.
- Runtime JSON Schema validation, checksummed crash-recovery journaling,
  Windows `msvcrt`/POSIX `fcntl` file locking, and a registered forward
  migration chain are complete.
- Optional Ed25519 signing for the existing SHA-256 bundle manifest is
  complete; future work may integrate an organizational PKI or hardware key.
- Reproducible PDF generation and policy-minimized redacted PDFs are complete.

Acceptance:

- A second machine can open and verify an exported case without the original
  application.
- Any changed artifact, manifest record, ledger record, or broken source/claim
  reference is detected.
- Every derivative identifies its parent artifact and generating activity.

## Phase 2 — workstation integrations (complete)

Deliverables:

- Add further passive DNS-history providers if their coverage and licensing
  justify them; the initial SecurityTrails historical-DNS adapter is complete
  alongside Wayback CDX, Common Crawl, current DNS, authoritative RDAP, and
  certificate transparency.
- The optional, tightly scoped Sherlock runner and the WhatsMyName dataset-only
  manual-review queue are complete; maintain their upstream compatibility and
  site metadata.
- Every adapter now declares its allowed options and target-disclosure behavior.
  Target-disclosing runs require a separate sensitivity/authority confirmation,
  which is hash-chained before collection; absent confirmation is recorded as a
  blocked run without calling the provider.
- SearXNG, ArchiveBox, SecurityTrails, Sherlock, health checks, and all four
  local analyzer paths have an operator runbook and deterministic diagnostics.
- Additional passive-DNS providers were not added merely for quantity. The
  provider-independent model remains ready for another adapter when a stable,
  lawful, documented API offers justified coverage beyond current DNS,
  certificate transparency, authoritative RDAP, and SecurityTrails history.

Acceptance:

- All adapters emit the same normalized observation/provenance model.
- Provider errors and blocks are distinguishable from zero results.
- No adapter performs login, active scanning, password recovery, or CAPTCHA
  bypass.
- External uploads are visibly gated by a sensitivity confirmation.

Acceptance status: complete. Tests distinguish completed zero-result, failed,
and policy-blocked runs; validate normalized records and provenance; enforce
strict adapter options; and prove the disclosure gate executes before the
adapter.

## Phase 3 — analysis workbench (complete)

Deliverables:

- Offline interactive timeline and candidate entity-resolution views use
  normalized records. Merge/split commands require sourced features and keep
  every original record; views are read-only and regenerated after decisions.
- GraphML preserves explicit observed/inferred edge labels and source IDs;
  separate CSV/JSON tables support Maltego's manual table-import wizard.
- Append-only geolocation worksheets record clues, candidate locations,
  matched/mismatched features, and registered map snapshot artifact IDs.
- Append-only media worksheets record sourced reverse-search and
  earliest-appearance leads without treating search rank as provenance proof.
- Audits include contradiction, duplicate, stale-source, orphan-artifact,
  and claim-observation checks. Fingerprinted findings support append-only
  reviewer dispositions, visible suppressions, and reopening.

Acceptance:

- An analyst can trace every node, edge, and timeline item to one or more source
  IDs.
- Merges require stated evidence; undoing a merge loses no records.
- Graph visualization never silently converts inferred edges to observed facts.

Acceptance status: complete. Tests cover source traceability, explicit export
failure for unsourced legacy entities, preserved inference labels, reversible
merges without record loss, worksheet references, dispositions, migration,
and full case verification. See [the workbench runbook](ANALYSIS_WORKBENCH.md).

## Phase 4 — licensed and jurisdictional providers (complete local release)

Deliverables:

- HIBP adapter restricted to self/authorized addresses and verified domains.
- Optional Hunter, Censys, Shodan, Maltego, and approved people/business data
  providers.
- Official-registry profiles by jurisdiction, starting with the countries most
  relevant to the investigator.
- Provider-specific terms, data residency, attribution, retention, cost, and
  query-limit metadata.

Implemented in v0.9.0: HIBP account and verified-domain, Hunter domain,
Censys Platform v3 host, existing SecurityTrails historical DNS, and UK
Companies House search are bounded API adapters behind a common approval gate.
Shodan remains manual-only, Maltego uses the Phase 3 manual graph export, and
Kenya NCK/BRS, US SEC EDGAR, and GLEIF are official manual registry routes.
No general people-data-broker connector is enabled. See
[the provider runbook](LICENSED_PROVIDERS.md) for exact operational scope.

Acceptance:

- A provider cannot run until its policy profile and credentials are approved.
- High-risk queries require a recorded case authority and explicit review gate.
- Provider-derived PII follows case retention and redaction policy.

The local gate checks case retention before approval and each run; redacted
JSON/PDF derivatives omit licensed PII records and linked material. Automatic
retention deletion, authenticated two-person review, and live entitlement
checks remain Phase 5 service work. Release tests use mocked provider responses;
live credentialed calls require the operator's approved accounts.

## Phase 5 — team platform (6–12 weeks)

Deliverables:

- FastAPI or equivalent service, PostgreSQL, and encrypted object storage.
- Single sign-on, role-based case access, immutable audit events, legal holds,
  and scheduled retention/deletion.
- Review queues, annotations, assignment, approval, and report versioning.
- Worker queue for approved adapters and resource-controlled media jobs.
- Monitoring, backup/restore drills, security testing, and incident response.

Acceptance:

- Least-privilege access is demonstrated per case and artifact.
- Every API and report action is attributable to an authenticated user/service.
- Backup restoration and case-export verification are tested regularly.

## Build/buy decisions

| Capability | Start with | Build when |
|---|---|---|
| Browser evidence | Hunchly (professional) or ArchiveBox/manual capture | You have jurisdiction-specific evidence requirements or deep internal integrations. |
| Search aggregation | SearXNG plus manual major engines | You need controlled, repeatable API queries and can manage upstream terms/limits. |
| Case metadata | Included JSONL core | You need concurrent users, permissions, or millions of observations. |
| Graph analysis | Gephi/Maltego exports | Reviewers need an integrated graph with source-aware merge/split. |
| Media analysis | ExifTool, FFmpeg, Tesseract, InVID | You need batch queues, derivation tracking, or custom forensic modules. |
| Domain OSINT | RDAP/CT/archives first; Censys/Shodan optional | You have stable licensed APIs and a defined passive exposure-review program. |
| People data | Official registries and manual research | Only after legal review identifies a justified licensed source and retention model. |
| Breach exposure | HIBP with authorization/verified domains | Never build a leaked-password warehouse into the general toolbox. |

## Suggested priority

Phases 1–4 are complete as a local release. The evidence core, high-value
passive adapters,
initial historical DNS, scoped Sherlock runner, local analyzer wrappers,
workstation deployment profile, PDF/redaction workflow, and manifest signing
and source-traceable analysis workbench are implemented. Phase 4 adds the
governed licensed-provider layer and official-registry catalog. Next prioritize
Phase 5 authenticated team controls, scheduled retention, and operational
testing. Add further licensed providers only after defining the exact
intelligence questions, authority, retention, and provider policy profile.
