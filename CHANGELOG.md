# Changelog

## 0.9.0 — 2026-09-17

- Completed Phase 4 with exact-target, time-limited, ledger-backed licensed
  provider approvals, separate reviewer/actor names, run caps, revocation,
  case-retention checks, and profile-change invalidation.
- Added bounded HIBP account and verified-domain, Hunter domain, Censys
  Platform v3 host, and UK Companies House search adapters; brought the
  existing SecurityTrails adapter under the same approval gate.
- Added a jurisdictional official-registry catalog, provider terms/residency/
  attribution/retention/cost/limit profiles, and manual-only Shodan and
  export-only Maltego dispositions.
- Hardened credentialed requests to HTTPS/same-origin redirects and excluded
  licensed PII, linked evidence, and authority artifacts from redacted
  derivatives by default. Added v1.4 schema and migration, runbook, and
  fail-closed tests. No live credentialed queries were run in release tests.

## 0.8.0 — 2026-09-17

- Completed Phase 3 with an offline searchable timeline, candidate entity
  dashboard, source register, and worksheet view.
- Added evidence-backed, reversible entity merges and append-only split
  decisions, without changing any source entity or relationship.
- Added geolocation clues and candidate feature comparisons with map snapshot
  artifacts, plus typed reverse-search/earliest-appearance media leads.
- Exported source-traceable GraphML for Gephi and separate CSV/JSON node/edge
  tables for manual Maltego mapping; inferred edges retain their evidence kind.
- Added stable audit-finding fingerprints and append-only reviewer dispositions;
  suppressed findings remain visible and integrity failures cannot be hidden.
- Added extra duplicate/evidence quality checks, v1.3 schema and migration,
  runbook, examples, and adversarial lifecycle coverage.

## 0.7.0 — 2026-09-17

- Completed Phase 2 workstation integrations and their acceptance tests.
- Added a provider-layer external-disclosure gate. Target-disclosing adapters
  require `--confirm-external-disclosure`, record the reviewed case sensitivity
  in the hash-chained ledger, and create a `blocked` provider run if confirmation
  is absent.
- Classified every adapter by disclosure behavior; the dataset-only WhatsMyName
  queue remains exempt because the username is not sent to profile services.
- Added strict per-provider option allowlists so misspelled or unsupported
  options fail before a network request.
- Tightened SearXNG `time_range` and `safesearch` validation and rechecked the
  SearXNG, Common Crawl, SecurityTrails, and Sherlock integration contracts
  against current upstream documentation.
- Added adversarial tests proving that completed zero-result, failed, and
  policy-blocked runs remain distinct.
- Added the workstation integration runbook and updated all network collection
  examples for the disclosure-confirmation workflow.

## 0.6.0 — 2026-09-16

- Completed Phase 1 with auditable legal-hold placement/release, a normalized
  hold-event history, hold-aware retention changes, and report visibility.
- Enforced the published JSON Schema Draft 2020-12 case and record definitions
  on every write and during full case verification.
- Added durable, checksummed transaction journals with idempotent recovery for
  JSONL, ledger, case-state, and staged artifact publication operations.
- Added POSIX `fcntl` and Windows `msvcrt` inter-process locking backends.
- Added a registered v1.0-to-v1.1-to-v1.2 migration chain that preserves all
  prior ledger entries.
- Added orphan artifact/payload detection, artifact size verification, new CLI
  recovery/governance commands, and adversarial Phase 1 tests.

## 0.5.0 — 2026-09-15

- Added a local Sherlock runner that requires an explicit allowlist of at most
  25 sites, rejects broad/arbitrary options, bounds runtime, preserves CSV, and
  keeps claimed, available, blocked, invalid, and unknown outcomes distinct.
- Added deterministic A4 PDF reports with repeated headings, classification,
  source-aware registers, stable metadata, and page numbering.
- Added policy-first redacted PDFs rebuilt from minimized case data rather than
  unsafe visual overlays.
- Added detached Ed25519 bundle-manifest signatures with bundle, manifest, and
  public-key fingerprints plus independent verification.
- Added atomic binary report writes and optional `reportlab` packaging support.

## 0.4.0 — 2026-09-15

- Added credential-gated SecurityTrails historical DNS collection for A, AAAA,
  MX, NS, SOA, and TXT records with bounded page and observation limits.
- Added normalized `dns.history` observations while preserving the original
  provider response as a hashed artifact.
- Kept credentials out of URLs and case data by accepting the API key only
  through `SECURITYTRAILS_API_KEY`.
- Added no-network unconfigured health behavior and tests that distinguish an
  empty historical result from provider/API failure.

## 0.3.0 — 2026-09-15

- Added atomic metadata replacement, synchronized Unix case writes, and a
  ledger-preserving v1.0-to-v1.1 migration.
- Added bounded provider retries, explicit health probes, and provider health
  history; controlled live probes distinguish degraded services from empty
  results.
- Added OCRmyPDF derivatives and verified all four local analyzer paths using
  synthetic artifacts.
- Added UTC-normalized event times while retaining the original time value and
  precision.
- Added a non-destructive quality audit for duplicates, conflicts, stale
  sources, orphan artifacts, inference review, provider failures, and claim
  observation gaps.

## 0.2.0 — 2026-09-15

- Added normalized observations, entities, relationships, events,
  derivations, and provider-run records.
- Added governance metadata, auditable status transitions, and closed-case
  write protection.
- Added JSON, CSV, GraphML, redacted JSON, and manifest-backed portable ZIP
  exports.
- Added opt-in Wayback CDX, Common Crawl, RDAP, DNS-over-HTTPS, crt.sh,
  SearXNG, and WhatsMyName adapters.
- Added local ExifTool, ffprobe, and Tesseract wrappers with derivative
  provenance.
- Added Draft 2020-12 schemas, optional local SearXNG/ArchiveBox deployment,
  local capability checks, and expanded lifecycle/provider tests.

## 0.1.0 — 2026-09-14

- Added transcript topic map, operating standard, architecture, curated tool
  catalog, query recipes, target workflows, evidence-first case lifecycle,
  chained ledger, artifact hashing, claims, reports, and initial tests.
