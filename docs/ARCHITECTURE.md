# Architecture

## Design goal

Build a durable investigation workbench in which collection providers can be
replaced without changing the case model. The central object is not “a tool
result”; it is a dated observation from a named source, optionally preserved as
an artifact, used to support or challenge an analytic claim.

## Layers

```text
Questions and legal scope
        ↓
Target workflow and query recipes
        ↓
Provider adapters (search, archives, APIs, local analyzers)
        ↓
Normalized observations + entities + relationships + artifacts
        ↓
Corroboration, timelines, graph analysis, confidence, alternatives
        ↓
Reports, source register, limitations, and integrity verification
```

### 1. Governance layer

Every case records purpose, authority, target type, target, owner, creation
time, sensitivity, jurisdictions, retention, reviewers, collection tier, and
legal-hold state. Hold placement and release require a reason and authority,
produce normalized append-only events, and are reflected in the hash-chained
case state. A future team service should add protected-person flags and
role-scoped approvals.

### 2. Planning layer

The included workflows cover `person`, `organization`, `domain`, `username`,
`email`, `media`, `location`, `social`, and `event`. Plans state collection
questions, sequence, stop conditions, and review gates. Query recipes produce
links without making requests, which keeps the human in control of searches
that may expose sensitive values to providers.

### 3. Provider layer

Implement each external service behind an adapter with the same contract:

```text
validate(seed, scope) -> validation result
collect(seed, scope, cursor) -> observations + next cursor
healthcheck() -> status, version, checked_at
provenance() -> provider, endpoint, query, terms reference, request time
```

Adapters should be disabled by default until credentials, terms, rate limits,
data residency, and permitted target types are configured. Prefer documented
APIs over browser scraping. A provider failure must never corrupt a case or
silently become a “not found” conclusion.

Every target-disclosing adapter is gated in the provider layer by an explicit
sensitivity/authority confirmation. A successful confirmation is hash-chained
before the request; an absent confirmation produces a normalized `blocked`
provider run without calling the adapter. The dataset-only WhatsMyName path is
classified separately because it downloads public site metadata without
sending the case username to profile services. Unsupported provider options
are rejected before network activity.

The Phase 4 licensed-provider gate adds an exact target, permitted authority
basis, preserved authorization artifact where applicable, distinct named
reviewer/actor, current profile digest, expiry, run cap, credential presence,
and case-retention check. One run is reserved under the case lock before any
licensed request. Approval and revocation are append-only case records. The
local CLI cannot authenticate the named people; Phase 5 must provide SSO and
enforced role separation. Credentialed requests require HTTPS and stay on the
same origin across redirects. See [licensed providers](LICENSED_PROVIDERS.md).

Suggested adapter groups:

- Search: SearXNG, Brave Search API, and manual Google/Bing links.
- Archives: Wayback CDX, Common Crawl index, and local ArchiveBox.
- Username: WhatsMyName dataset, Sherlock, and optional Maigret.
- Media: ExifTool, ffprobe, Tesseract/OCRmyPDF, and InVID-assisted manual work.
- Domains: ICANN RDAP, DNS resolvers, certificate transparency, urlscan search,
  Censys, Shodan, and passive SpiderFoot profiles.
- Business: official national registries, GLEIF, OpenCorporates as a locator,
  SEC EDGAR, UK Companies House, and OCCRP Aleph where authorized.
- Social: native public search and official/approved APIs only.
- Exposure: HIBP for self/authorized addresses or verified organizational
  domains; no password-returning provider in the default product.

### 4. Case and evidence layer

The included core uses JSON/JSONL and ordinary files so that a case remains
readable without the application. Production can index these records into
SQLite or PostgreSQL, but the export format should remain open.

Minimum observation model:

| Field | Meaning |
|---|---|
| `observation_id` | Stable internal identifier. |
| `case_id` | Owning case. |
| `source_id` | Logged source record. |
| `observed_at` | When the source says the event/content existed, if known. |
| `accessed_at` | When the investigator accessed it, always UTC. |
| `collector` | Human or adapter responsible for collection. |
| `query` | Exact query or input used. |
| `value` | Normalized observed value. |
| `artifact_id` | Preserved original/capture, if any. |
| `derived_from` | Parent artifact/observation for OCR, keyframes, transforms, etc. |
| `status` | Observed, unavailable, conflicting, retracted, or superseded. |

The current CLI implements cases, sources, observations, entities, aliases,
typed observed/inferred relationships, events, artifacts, explicit derivation
links, claims, provider runs, a chained ledger, integrity checks, portable
exports, and reports. These records use a lightweight mapping to the W3C PROV
concepts of Entity, Activity, and Agent while remaining readable JSONL.

Phase 3 extends the append-only case format with `resolutions.jsonl` for
source-backed merge/split decisions, `worksheets.jsonl` for location and media
assessments, and `audit_reviews.jsonl` for reviewer dispositions. The HTML
workbench is a local, read-only derivative, not an evidence source or an
unrecorded decision channel. Graph and workbench rendering refuse unsourced
nodes instead of inventing provenance; inference labels remain explicit in
GraphML and the separate Maltego-ready interchange tables.

Phase 4 adds `provider_approvals.jsonl` for approved/revoked decisions. Raw
licensed responses stay in the controlled case, while redacted JSON/PDF
derivatives omit PII-profile provider records and linked evidence by default.
Full case bundles and graph exports remain sensitive and need separate
authorization before dissemination.

Every case/record mutation is validated against the published Draft 2020-12
schemas. A checksummed transaction journal makes JSONL/ledger, case-state, and
artifact publication operations idempotently recoverable after interruption.
The case lock uses `fcntl` on POSIX and `msvcrt` on Windows. Verification
reports pending journals, orphan payloads/files, schema violations, hash or
size mismatches, state/ledger divergence, and broken references.

### 5. Analysis layer

Entity resolution must be evidence-based. Suggested match features include a
stable platform ID, verified domain, unique outbound link, exact reused image
hash, independently matching location/time, public cross-link, and distinctive
biographical attributes. Name, username, display picture similarity, shared IP,
and graph proximity alone are insufficient.

Use a three-part analytic record:

- Observation: what a source directly shows.
- Inference: the reasoning that connects observations.
- Claim: the assessed conclusion, confidence, alternatives, and cited sources.

Graph exports should use typed nodes and edges such as `person`, `account`,
`organization`, `domain`, `document`, `location`, and `event`, with edge fields
for source ID, observed time, confidence, and whether the edge is observed or
inferred. Export GraphML for Gephi and CSV/JSON for Maltego or other systems.

### 6. Reporting layer

Reports should lead with the intelligence question and answer, then scope,
method, assessed claims, evidence, timeline/graph where useful, contradictions,
limitations, and appendices. Every material claim must resolve to logged source
IDs. Reports should be cut off at a stated UTC time and redact unrelated PII.
The optional ReportLab renderer produces deterministic A4 PDFs directly from
the normalized full or policy-minimized snapshot. Redacted PDFs are rebuilt
from filtered data and never created by applying visual overlays. Detached
Ed25519 metadata signs the exact bundle manifest and records the bundle,
manifest, and public-key hashes without modifying the evidence ZIP.

## Recommended technology stack

### Included core

- Python 3.11+ plus the standards-based `jsonschema` validator.
- JSON and JSONL for transparent, diffable records.
- SHA-256 artifact hashes and a hash-chained activity ledger.
- Markdown and deterministic PDF for durable reports and templates.

### Open-source workstation additions

- The included Docker Compose profile for locally bound optional services.
- SearXNG for metasearch; ArchiveBox for preservation.
- PostgreSQL for multi-user metadata; encrypted object storage for artifacts.
- DuckDB/Polars for local bulk analysis and Parquet interchange.
- ExifTool, FFmpeg/ffprobe, Tesseract, and OCRmyPDF for local media/documents.
- QGIS for spatial analysis; Gephi for large graph exploration.
- SpiderFoot only with reviewed passive profiles.

### Professional additions

- Hunchly for browser capture and court-oriented audit exports.
- Maltego for entity/relationship exploration and licensed connectors.
- A secret manager rather than `.env` files for API keys.
- Single sign-on, role-based access, audit logs, retention automation,
  immutable/versioned backups, and separate production/test provider accounts.

## Deployment profiles

### Profile A — solo analyst

Dedicated OS user or VM, full-disk encryption, separate browser profiles,
password manager, the CLI, local evidence capture, and encrypted backups. This
is the correct starting point for most users.

### Profile B — open-source lab

Add locally bound containers for SearXNG and ArchiveBox, local analyzers, and
optional passive SpiderFoot. Do not expose administration interfaces to an
untrusted network. Keep provider secrets outside images and source control.

### Profile C — team platform

Use a server API and web UI backed by PostgreSQL and encrypted object storage.
Enforce per-case roles, two-person approval for sensitive collection, automated
retention, case export, health checks, quotas, and legal/jurisdiction profiles.

## AI/LLM role

AI can assist with OCR cleanup, translation, entity suggestions, clustering,
timeline drafting, contradiction detection, and report editing. It must not be
the source of a fact. Store the model/version, prompt, input source IDs, output,
and reviewer decision as a derived analytic activity. Do not send sensitive case
data to an external model without an approved data-processing arrangement.

## Provider lifecycle management

The transcript repeatedly warns that websites disappear. Formalize that lesson:

- Store providers in a versioned catalog, never hard-code them into workflows.
- Run non-sensitive health checks and record `last_verified`.
- Track authentication, quotas, terms URL, cost, regions, and data classes.
- Mark a provider `active`, `degraded`, `retired`, or `prohibited`.
- Maintain at least two providers for critical capabilities.
- Distinguish “provider unavailable” from “no result.”

## Authoritative references used for this design

Reviewed 2026-09-14:

- [Berkeley Protocol on Digital Open Source Investigations](https://www.ohchr.org/sites/default/files/2022-04/OHCHR_BerkeleyProtocol.pdf)
- [W3C PROV-O](https://www.w3.org/TR/prov-o/)
- [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final)
- [SearXNG search API](https://docs.searxng.org/dev/search_api.html)
- [ArchiveBox documentation](https://docs.archivebox.io/)
- [Wayback CDX server](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server)
- [Common Crawl: Get Started](https://commoncrawl.org/get-started)
- [Hunchly evidence guide](https://support.hunch.ly/article/55-1-hunchly-evidence-introduction)
- [ExifTool documentation](https://exiftool.org/exiftool_pod.html)
- [InVID-WeVerify plugin](https://weverify.eu/verification-plugin/)
- [ICANN RDAP](https://www.icann.org/rdap/)
- [HIBP API v3](https://haveibeenpwned.com/API/v3)
- [Sherlock](https://github.com/sherlock-project/sherlock)
- [Maigret](https://github.com/soxoj/maigret)
- [WhatsMyName](https://github.com/WebBreacher/WhatsMyName)
- [urlscan Search API](https://docs.urlscan.io/apis/urlscan-openapi/search)
- [Censys Platform API transition guide](https://docs.censys.com/docs/platform-api-transition-guide)
- [Maltego documentation](https://docs.maltego.com/)
- [OpenCorporates API](https://api.opencorporates.com/documentation/API-Reference)
- [SEC EDGAR APIs](https://www.sec.gov/search-filings/edgar-application-programming-interfaces)
