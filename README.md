# OSINT Toolbox

A reusable, evidence-first OSINT workbench derived from the methods in
`transcript.txt` and updated for a modern, provider-independent workflow.

The package does two things:

1. It provides a safe, lightweight command-line core for case setup,
   query planning, source logging, artifact hashing, observation/entity/
   relationship/timeline analysis, claim tracking, integrity verification,
   portable exports, and Markdown/PDF reporting.
2. It provides a curated architecture and tool catalog for adding search,
   archives, media verification, geolocation, public records, passive technical
   reconnaissance, graph analysis, and approved commercial services.

The default package is deliberately passive. It does **not** automate account
login, password reset, credential stuffing/spraying, leaked-password searches,
deceptive engagement, bypassing access controls, or intrusive scanning.

## Quick start

The core requires Python 3.11+ and installs the standards-based `jsonschema`
runtime validator.

Install the built release from this package directory:

```bash
python3 -m pip install dist/osint_toolbox-0.9.0-py3-none-any.whl
osint-toolbox --version
```

Install the optional deterministic PDF renderer when PDF output is required:

```bash
python3 -m pip install 'reportlab>=4.2,<5'
python3 -m pip install dist/osint_toolbox-0.9.0-py3-none-any.whl
```

The wheel and source archive SHA-256 values are recorded in `dist/SHA256SUMS`.

For editable development from the source tree:

```bash
python3 -m pip install -e .
osint-toolbox doctor
osint-toolbox catalog --topic evidence
osint-toolbox list-recipes
```

Create a case only after documenting authority and purpose:

```bash
osint-toolbox init-case \
  --title "Example organization exposure review" \
  --purpose "Identify publicly exposed organizational information" \
  --authority "Written authorization dated 2026-09-14" \
  --target-type organization \
  --target "Example Organization" \
  --sensitivity confidential \
  --jurisdiction Kenya \
  --reviewer "Review Analyst" \
  --retention-until 2027-09-14 \
  --output cases
```

Generate a collection plan and safe search links:

```bash
osint-toolbox plan cases/CASE-DIRECTORY
osint-toolbox query web.name-context \
  --param 'name=Example Organization' \
  --param 'context=annual report' \
  --engine google
```

Licensed passive APIs now require a recorded, exact-target approval, a
credential, and per-run external-disclosure confirmation. See the
[Phase 4 provider runbook](docs/LICENSED_PROVIDERS.md) before enabling one;
the default package makes no licensed-provider requests.

Record sources, preserve artifacts, make source-backed claims, and verify the
case:

```bash
osint-toolbox add-source cases/CASE-DIRECTORY \
  --url 'https://example.org/about' \
  --title 'Official about page' \
  --topic organization \
  --reliability primary \
  --credibility high

osint-toolbox add-artifact cases/CASE-DIRECTORY ./capture.png \
  --source-url 'https://example.org/about' \
  --topic evidence

osint-toolbox add-claim cases/CASE-DIRECTORY \
  --statement 'The organization publicly lists Nairobi as its headquarters.' \
  --confidence high \
  --source-id SRC-REPLACE-WITH-ID

osint-toolbox verify cases/CASE-DIRECTORY
osint-toolbox audit cases/CASE-DIRECTORY --stale-days 365
osint-toolbox report cases/CASE-DIRECTORY
osint-toolbox set-status cases/CASE-DIRECTORY review \
  --note 'Collection complete; submitted for independent review'
```

Cases in `closed` or `archived` state reject new sources, artifacts, analytic
records, provider runs, and local analyzer output. Reopening requires another
reasoned, hash-chained `set-status` transition.

Cases created by the earlier schema can be migrated without replacing their
original ledger entries:

```bash
osint-toolbox upgrade-case cases/CASE-DIRECTORY --actor analyst-name
```

Place and release legal holds only under recorded authority. An active hold
freezes retention changes but does not prevent authorized analysis or archival
status changes:

```bash
osint-toolbox place-legal-hold cases/CASE-DIRECTORY \
  --reason 'Preserve material responsive to matter 2026-17' \
  --authority 'Counsel instruction dated 2026-09-16' \
  --actor custodian-name
osint-toolbox legal-hold-status cases/CASE-DIRECTORY

osint-toolbox release-legal-hold cases/CASE-DIRECTORY \
  --reason 'Counsel confirmed the matter is concluded' \
  --authority 'Release instruction dated 2027-03-01' \
  --actor custodian-name
osint-toolbox set-retention cases/CASE-DIRECTORY 2030-03-01 \
  --note 'Post-hold retention approved by records management'
```

All case state and JSONL mutations use a durable transaction journal. Normal
commands refuse to write while an interrupted transaction exists; inspect and
complete it idempotently with:

```bash
osint-toolbox recover-case cases/CASE-DIRECTORY --actor analyst-name
osint-toolbox verify cases/CASE-DIRECTORY
```

Record normalized analysis objects and create interoperable exports:

```bash
osint-toolbox add-observation cases/CASE-DIRECTORY \
  --source-id SRC-REPLACE-WITH-ID \
  --kind domain.registration-date \
  --value '2020-01-01T00:00:00Z'

osint-toolbox add-entity cases/CASE-DIRECTORY \
  --type domain \
  --label example.org \
  --source-id SRC-REPLACE-WITH-ID \
  --role resolved \
  --confidence high

osint-toolbox export cases/CASE-DIRECTORY json
osint-toolbox export cases/CASE-DIRECTORY csv
osint-toolbox export cases/CASE-DIRECTORY graphml
osint-toolbox export cases/CASE-DIRECTORY maltego
osint-toolbox workbench cases/CASE-DIRECTORY
osint-toolbox bundle cases/CASE-DIRECTORY
osint-toolbox verify-bundle cases/CASE-DIRECTORY/reports/CASE-ID.zip
```

The offline workbench includes searchable timeline, entity-resolution,
worksheet, and source views. Use `resolve-entities` for sourced merge/split
decisions, `record-worksheet` for geolocation/media assessments, and
`review-finding` for audit dispositions. See the example-driven
[analysis workbench guide](docs/ANALYSIS_WORKBENCH.md) for commands, source
traceability, export mappings, and limitations.

Optionally sign the exact `MANIFEST.json` bytes inside a verified bundle using
an Ed25519 private key. Keep private keys outside case directories and source
control. If the key is encrypted, load its password into
`OSINT_SIGNING_KEY_PASSWORD` from an approved secret manager:

```bash
openssl genpkey -algorithm ED25519 -aes-256-cbc -out signing-private.pem
openssl pkey -in signing-private.pem -pubout -out signing-public.pem

osint-toolbox sign-bundle CASE-ID.zip signing-private.pem
osint-toolbox verify-signature \
  CASE-ID.zip \
  CASE-ID.zip.signature.json \
  signing-public.pem
```

Verification is meaningful only when the public key or its fingerprint was
distributed through a separately trusted channel.

For dissemination, copy and edit `templates/redaction-policy.json`, review all
fields and IDs, then generate a derived minimized view without changing the
controlled case:

```bash
osint-toolbox redact cases/CASE-DIRECTORY ./my-redaction-policy.json
osint-toolbox report-pdf cases/CASE-DIRECTORY
osint-toolbox redact-pdf cases/CASE-DIRECTORY ./my-redaction-policy.json
```

The redacted JSON and PDF are explicitly labeled as incomplete and record the
policy SHA-256 in the case ledger. The PDF is rebuilt from the minimized data
model; it never uses unsafe visual overlays on an existing PDF. These outputs
are not substitutes for human review of free text, URLs, media, or indirect
identifiers.

Provider collection is always explicit. Review the exact target, case
sensitivity, authority, and options. Target-disclosing adapters require both
the network acknowledgment and the separate sensitivity acknowledgment:

```bash
osint-toolbox providers
osint-toolbox collect cases/CASE-DIRECTORY rdap \
  --target example.org \
  --confirm-external-disclosure \
  --execute
```

The bundled passive adapters cover Wayback CDX, Common Crawl indexing,
authoritative RDAP discovery, current single-type DNS-over-HTTPS, crt.sh,
SearXNG, and a dataset-only WhatsMyName manual-review queue. An optional
Sherlock runner refuses broad all-site searches and requires an explicit
allowlist of at most 25 sites. The licensed layer adds bounded HIBP,
SecurityTrails, Hunter, Censys, and UK Companies House queries only after an
exact-target approval and credential check. See [provider adapters](docs/PROVIDERS.md)
and the [licensed-provider runbook](docs/LICENSED_PROVIDERS.md).

Run a narrowly scoped username check only after confirming the case authority
and the selected sites' terms:

```bash
osint-toolbox collect cases/CASE-DIRECTORY sherlock \
  --target example_user \
  --option sites=GitHub,Reddit \
  --option timeout=10 \
  --option max_runtime=120 \
  --confirm-external-disclosure \
  --execute
```

Sherlock results are retained as candidate, unavailable, or inconclusive site
checks. Even a `Claimed` result requires manual identity verification.

When running without installation, prefix commands with `PYTHONPATH=src
python3 -m osint_toolbox`.

## What is included

- [Transcript topic map](docs/TRANSCRIPT_TOPIC_MAP.md) — the course divided
  into topics, methods, tools, and modern dispositions.
- [Architecture](docs/ARCHITECTURE.md) — layers, data model, integrations,
  deployment profiles, and design decisions.
- [Operating standard](docs/OPERATING_STANDARD.md) — authority, minimization,
  collection, corroboration, evidence, reporting, and safety rules.
- [Implementation roadmap](docs/IMPLEMENTATION_ROADMAP.md) — phased path from
  the included local core to a full team platform.
- [Provider guide](docs/PROVIDERS.md) — supported passive adapters, options,
  limitations, and interpretation rules.
- [Workstation integration runbook](docs/WORKSTATION_INTEGRATIONS.md) — setup,
  sensitivity confirmation, health checks, dependencies, and troubleshooting.
- [Tool catalog](src/osint_toolbox/data/tools.json) — current and course-era
  tools with status, access model, risk, and recommended role.
- [Query recipes](src/osint_toolbox/data/query_recipes.json) — reusable search
  patterns that generate links but do not send requests.
- [Target workflows](src/osint_toolbox/data/workflows.json) — checklists for
  people, organizations, domains, usernames, media, locations, social accounts,
  and events.
- [Templates](templates/) — case brief, source assessment, and final report.
- [Local services profile](deploy/README.md) — loopback-bound optional SearXNG
  and ArchiveBox containers.
- [Open interchange schemas](schemas/README.md) — Draft 2020-12 schemas for
  case metadata and normalized JSONL records.
- [Analysis workbench guide](docs/ANALYSIS_WORKBENCH.md) — timeline, entity
  review, location/media worksheets, audit dispositions, and graph export.

## Case structure

```text
CASE-.../
├── case.json
├── investigation-plan.md
├── ledger.jsonl
├── sources.jsonl
├── observations.jsonl
├── entities.jsonl
├── relationships.jsonl
├── events.jsonl
├── derivations.jsonl
├── claims.jsonl
├── artifacts.jsonl
├── provider_runs.jsonl
├── legal_holds.jsonl
├── resolutions.jsonl
├── worksheets.jsonl
├── audit_reviews.jsonl
├── artifacts/
├── notes/
└── reports/
```

The ledger is hash-chained. Artifacts are copied into the case and SHA-256
hashed. `verify` detects artifact changes, a broken ledger chain, JSONL/ledger
divergence, duplicate record IDs, and missing source/entity/artifact references.
It also runs the published Draft 2020-12 schemas at write and verification time,
detects unregistered artifact files, and reports pending recovery journals.
`bundle` creates a portable ZIP with a manifest containing the size and SHA-256
of every included file; `verify-bundle` validates it without the original
installation. This is an integrity aid, not a digital signature, legal advice,
or a substitute for the forensic acquisition/evidence-management process
required by your jurisdiction.

## Local analyzers

If installed on the workstation, ExifTool, ffprobe, Tesseract, and OCRmyPDF can
analyze a preserved artifact without uploading it. Metadata JSON, OCR text, or
a searchable-PDF derivative becomes a new hashed artifact, and the tool,
version, sanitized command, parent, and child are logged:

```bash
osint-toolbox analyzers
osint-toolbox analyze cases/CASE-DIRECTORY ART-REPLACE-WITH-ID exiftool
osint-toolbox analyze cases/CASE-DIRECTORY ART-REPLACE-WITH-ID tesseract
osint-toolbox analyze cases/CASE-DIRECTORY ART-REPLACE-WITH-ID ocrmypdf
```

## Recommended deployment profiles

- **Solo/core:** this CLI, a dedicated browser profile, Hunchly or manual
  capture, encrypted case storage, ExifTool, and the InVID-WeVerify plugin.
- **Open-source workstation:** core plus the included SearXNG/ArchiveBox
  Compose profile, ExifTool,
  OCRmyPDF/Tesseract, FFmpeg, Sherlock/WhatsMyName, SpiderFoot in passive
  profiles, QGIS, and Gephi.
- **Professional/team:** core plus Hunchly, Maltego, licensed data providers,
  centralized encrypted storage, role-based access, immutable backups, and a
  documented review/approval process.

Read [OPERATING_STANDARD.md](docs/OPERATING_STANDARD.md) before adding live
provider integrations.
