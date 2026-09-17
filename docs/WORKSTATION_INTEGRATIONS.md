# Workstation integration runbook

This runbook covers the completed Phase 2 workstation profile: passive
providers, local analyzers, health checks, SearXNG/ArchiveBox, optional
SecurityTrails and Sherlock, and the external-disclosure gate. It assumes an
authorized case already exists.

## 1. Included integration boundary

The workstation profile includes:

- passive Wayback CDX, Common Crawl, RDAP, DNS-over-HTTPS, certificate
  transparency, and configured SearXNG collection;
- optional authenticated SecurityTrails historical DNS;
- a locally executed, explicitly allowlisted Sherlock runner;
- a WhatsMyName dataset-only candidate queue;
- local ExifTool, ffprobe, Tesseract, and OCRmyPDF analysis;
- loopback-bound SearXNG and ArchiveBox services; and
- explicit provider health checks using reserved, non-sensitive targets.

It does not automate login, active scanning, password recovery, CAPTCHA bypass,
private-content access, contact, or collection from illicit datasets.

## 2. Install and diagnose

Use Python 3.11 or newer in a dedicated virtual environment. Install the wheel
and the PDF extra only if PDF reports are required:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install dist/osint_toolbox-0.7.0-py3-none-any.whl
python3 -m pip install 'reportlab>=4.2,<5'
osint-toolbox doctor
osint-toolbox doctor --json
```

On Windows, activate with `.venv\Scripts\activate` instead. The core package
does not install system executables. Install only the tools needed for the
approved workflow and confirm that `doctor` finds them on `PATH`:

| Capability | Executable | Required |
|---|---|---|
| Container services | `docker` with Compose | Optional |
| Metadata | `exiftool` | Optional |
| Audio/video metadata | `ffprobe` | Optional |
| Image OCR | `tesseract` | Optional |
| Searchable-PDF derivative | `ocrmypdf` | Optional |
| PDF text verification | `pdftotext` | Recommended for PDF QA |
| Scoped username checks | `sherlock` | Optional |
| Bundle signatures | `openssl` | Optional |

`doctor` is offline. It checks the Python version, packaged resources, file-lock
backend, executables, Python libraries, Docker Compose, and local SearXNG
configuration; it never probes a provider.

## 3. External-disclosure decision

`--execute` acknowledges that network activity will occur.
`--confirm-external-disclosure` separately records that the operator reviewed
the case sensitivity, authority, target/query, provider terms, and necessity.
Both are required for adapters that transmit a target or query.

```text
Does the adapter send the case target/query to another service?
├── Yes → review sensitivity and authority
│         ├── approved → add --confirm-external-disclosure and --execute
│         └── not approved → do not run; use a local/manual alternative
└── No  → --execute is still required for dataset download
```

The provider layer enforces the gate, including for Python callers. Missing
confirmation produces a `blocked` provider run and does not invoke the adapter.
Successful confirmation is hash-chained before collection and is referenced in
the resulting source notes. The current exemption is WhatsMyName: it downloads
the public site dataset without transmitting the case username. Opening a
generated profile URL later is a new disclosure decision.

No current adapter uploads an artifact. ExifTool, ffprobe, Tesseract, and
OCRmyPDF operate locally. Any future file-upload adapter must use the same gate
and must not be enabled for sensitive material without separate policy review.

## 4. Provider configuration

List adapters and their disclosure classification:

```bash
osint-toolbox providers
```

Every collection option is allowlisted. A misspelled or unsupported option
fails before network activity. See [PROVIDERS.md](PROVIDERS.md) for the full
option matrix and examples.

### SearXNG and ArchiveBox

Follow [the local services guide](../deploy/README.md). Copy the example
SearXNG settings, replace the placeholder secret, review pinned container image
versions, and keep both ports bound to loopback. The SearXNG JSON format must
remain enabled.

SearXNG is local infrastructure, but configured engines can receive the search
query. The external-disclosure confirmation is therefore still required.
ArchiveBox is intentionally manual: add only approved URLs, then register its
exported capture or WARC with `add-artifact`.

### SecurityTrails

Load the key from an approved secret manager into
`SECURITYTRAILS_API_KEY`. Do not place it in an option, `.env` file, case note,
URL, report, or shell command. The adapter sends it in the authentication
header and never stores it in case data.
Since Phase 4, historical-DNS collection also needs an exact-target,
time-limited approval under `asset-authorized`; see
[licensed providers](LICENSED_PROVIDERS.md).

### Sherlock

Install the official `sherlock-project` package in the workstation environment
and confirm `sherlock --version` works. Every run must name 1–25 sites. The
wrapper does not expose broad search, proxy, browser-opening, arbitrary JSON,
response-dump, similar-username, or NSFW expansion flags. It bounds per-site
and total runtime and treats every claimed username as an unverified candidate.

## 5. Health checks

Health checks are never implicit and use reserved targets rather than case
targets:

```bash
osint-toolbox provider-health rdap --execute
osint-toolbox provider-health searxng \
  --option base_url=http://127.0.0.1:8080 \
  --execute
osint-toolbox provider-health all --option timeout=8 --execute
```

The default `provider-status.json` stores the latest state and the most recent
100 checks. `healthy` means a bounded test returned parseable output;
`degraded` records an endpoint or response failure; `unconfigured` means a
required local executable, URL, or credential is absent. Health never proves
coverage or correctness for a case query.
Licensed providers report `configured-unprobed` when a credential is present;
health checks make no licensed API calls or spend credits.

## 6. Local analysis

Preserve the source artifact before analysis, then run only the required local
tool:

```bash
osint-toolbox analyzers
osint-toolbox analyze CASE-DIRECTORY ART-REPLACE-WITH-ID exiftool
osint-toolbox analyze CASE-DIRECTORY ART-REPLACE-WITH-ID ffprobe
osint-toolbox analyze CASE-DIRECTORY ART-REPLACE-WITH-ID tesseract
osint-toolbox analyze CASE-DIRECTORY ART-REPLACE-WITH-ID ocrmypdf
```

Each analyzer output becomes a new hashed artifact. The parent, child, tool,
version, and sanitized command are recorded as a derivation. Originals are not
modified.

## 7. Outcome semantics

Provider-run states are intentionally distinct:

| State | Meaning | Permitted conclusion |
|---|---|---|
| `completed`, observations > 0 | Valid response produced records | Review and corroborate the records |
| `completed`, observations = 0 | Valid response contained no normalized results | No result in that response at that time |
| `failed` | Validation, configuration, network, process, or parsing failed | Provider outcome is unknown |
| `blocked` | Required disclosure confirmation was absent | Provider did not run |

Never report `failed` or `blocked` as “not found.” Preserve the raw response for
completed runs and verify important findings against an original or independent
source.

## 8. Troubleshooting

- `confirm-external-disclosure` error: review the exact target, case sensitivity,
  authority, terms, and necessity; do not add the flag mechanically.
- `Unsupported ... option`: run `osint-toolbox providers`, consult the provider
  matrix, and correct the option name. Unknown options are never ignored.
- SearXNG HTTP 403: enable JSON in `search.formats`, verify the base URL, and
  rerun the explicit health check.
- SecurityTrails `unconfigured`: load `SECURITYTRAILS_API_KEY` into the process
  environment from the approved secret manager.
- Sherlock `unconfigured`: install the official package and make its executable
  visible on `PATH`.
- Provider `degraded`: keep the failure record, inspect the error, observe rate
  limits, and retry only when justified. Do not convert the failure to an empty
  result.
- Analyzer unavailable: install the executable, rerun `doctor`, and do not
  substitute an unreviewed upload service for sensitive material.

## 9. Phase 2 verification

From an editable development checkout with dependencies installed:

```bash
python3 -m unittest discover -s tests -v
python3 -m build
python3 -m zipfile -t dist/osint_toolbox-0.7.0-py3-none-any.whl
python3 -m tarfile -t dist/osint_toolbox-0.7.0.tar.gz
```

Acceptance requires tests proving normalized provenance, strict options,
bounded provider behavior, secret non-disclosure, explicit health checks,
dataset-only isolation, and different records for completed zero-result,
failed, and blocked runs. Run `verify` on any case used for an integration test.

## 10. Upstream compatibility references

Reviewed 2026-09-17:

- [SearXNG Search API](https://docs.searxng.org/dev/search_api.html)
- [Common Crawl Index Server](https://index.commoncrawl.org/)
- [SecurityTrails DNS history by record type](https://docs.securitytrails.com/reference/dns-history-by-record-type-old-1)
- [Sherlock project](https://github.com/sherlock-project/sherlock)
- [WhatsMyName project](https://github.com/WebBreacher/WhatsMyName)

Recheck upstream interfaces before changing a pinned workstation environment or
publishing a new release.
