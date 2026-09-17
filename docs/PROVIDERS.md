# Provider adapters

Provider collection is disabled unless the operator passes `--execute`. Each
successful run creates a source record, preserves the unmodified response as a
hashed artifact, emits normalized observations, and writes a provider-run
record to the hash-chained ledger. A failed run is recorded as a failure, never
as a zero-result conclusion.

Adapters that send the case target or query to another service also require
`--confirm-external-disclosure`. The provider layer enforces this requirement,
so direct Python calls cannot bypass it. Confirmation records the provider,
target, case sensitivity, actor, and UTC time in the hash-chained ledger before
the adapter executes. Without confirmation, no adapter request runs and a
`blocked` provider-run record is written. The flag confirms that a review took
place; it does not create legal authority.

Licensed adapters also require a time-limited, exact-target approval and
environment credential. See [the Phase 4 runbook](LICENSED_PROVIDERS.md) for
the approval command, authority bases, retention rules, and provider terms.

HTTP requests are bounded to 20 MiB and use a 30-second default timeout. The
client retries transient connection failures, HTTP 429, and HTTP 5xx responses
at most twice, honoring numeric `Retry-After` values up to 10 seconds. It does
not retry permanent 4xx failures or bypass rate controls.

## Available adapters

| Adapter | Input | Network behavior | Disclosure | Allowed options |
|---|---|---|---|---|
| `wayback` | URL or domain | One Wayback CDX index query | Target sent externally | `match_type`, `from`, `to`, `limit`, `timeout` |
| `commoncrawl` | URL pattern or domain | Catalog lookup, then one crawl-index query | Target sent externally | `index`, `match_type`, `limit`, `timeout` |
| `rdap` | Domain | IANA bootstrap lookup, then authoritative RDAP query | Target sent externally | `timeout` |
| `dns` | Domain | One Google Public DNS-over-HTTPS query | Target sent externally | `record_type`, `dnssec`, `timeout` |
| `securitytrails` | Domain | One authenticated historical-DNS page | Target sent externally; approval required | `record_type`, `page`, `limit`, `timeout` |
| `crtsh` | Domain | One public crt.sh JSON query | Target sent externally | `include_subdomains`, `limit`, `timeout` |
| `searxng` | Search query | One configured SearXNG JSON request | Query may reach configured engines | `base_url`, `categories`, `language`, `time_range`, `safesearch`, `limit`, `timeout` |
| `sherlock` | Username | Runs the local CLI against 1–25 explicitly named sites | Username sent to selected sites | `sites` (required), `timeout`, `max_runtime` |
| `whatsmyname` | Username | Downloads the WhatsMyName dataset only | Username not transmitted | `limit`, `include_nsfw`, `timeout` |
| `hibp-account` | Email | One authorized breach-name lookup | Target sent externally; approval required | `timeout` |
| `hibp-domain` | Verified domain | Subscriber-domain check and breach lookup | Target sent externally; approval required | `limit`, `timeout` |
| `hunter-domain` | Organization domain | One bounded professional-email search | Target sent externally; approval required | `limit`, `timeout` |
| `censys-host` | Public IP | One passive Platform v3 host lookup | Target sent externally; approval required | `timeout` |
| `companies-house` | UK company name | One bounded official-register search | Target sent externally; approval required | `limit`, `timeout` |

Unknown options are rejected before network activity. `time_range` for SearXNG
is limited to `day`, `month`, or `year`; `safesearch` is limited to `0`, `1`,
or `2`.

List the installed adapters:

```bash
osint-toolbox providers
```

Probe one adapter with a non-sensitive reserved test target and update a local
status registry:

```bash
osint-toolbox provider-health rdap --execute
osint-toolbox provider-health all --option timeout=8 --execute
osint-toolbox provider-health searxng \
  --option base_url=http://127.0.0.1:8080 \
  --execute
```

Health checks never run implicitly. The default `provider-status.json` keeps
the latest state per provider and the most recent 100 checks. A healthy result
only confirms that the endpoint returned parseable JSON; it does not prove
completeness, correctness, coverage, or availability for another query.

Examples:

```bash
osint-toolbox collect CASE-DIRECTORY wayback \
  --target example.org \
  --option from=2020 \
  --option to=2026 \
  --option limit=250 \
  --confirm-external-disclosure \
  --execute

osint-toolbox collect CASE-DIRECTORY commoncrawl \
  --target example.org \
  --option match_type=domain \
  --option limit=100 \
  --confirm-external-disclosure \
  --execute

osint-toolbox collect CASE-DIRECTORY rdap \
  --target example.org \
  --confirm-external-disclosure \
  --execute

osint-toolbox collect CASE-DIRECTORY dns \
  --target example.org \
  --option record_type=MX \
  --confirm-external-disclosure \
  --execute

# First record an exact-target approval and export SECURITYTRAILS_API_KEY
# from an approved secret manager. See LICENSED_PROVIDERS.md.
osint-toolbox collect CASE-DIRECTORY securitytrails \
  --target example.org \
  --option record_type=A \
  --option page=1 \
  --option limit=100 \
  --confirm-external-disclosure \
  --execute

osint-toolbox collect CASE-DIRECTORY crtsh \
  --target example.org \
  --option include_subdomains=true \
  --confirm-external-disclosure \
  --execute

osint-toolbox collect CASE-DIRECTORY searxng \
  --target 'Example Organization annual report' \
  --option base_url=http://127.0.0.1:8080 \
  --option safesearch=1 \
  --confirm-external-disclosure \
  --execute

osint-toolbox collect CASE-DIRECTORY sherlock \
  --target example_user \
  --option sites=GitHub,Reddit \
  --option timeout=10 \
  --option max_runtime=120 \
  --confirm-external-disclosure \
  --execute

osint-toolbox collect CASE-DIRECTORY whatsmyname \
  --target example_user \
  --option limit=200 \
  --execute
```

WhatsMyName does not require the disclosure-confirmation flag because the
adapter downloads only the public dataset and constructs candidate URLs
locally. Opening those URLs later is a separate disclosure decision.

## Interpretation rules

- A search result, archive index row, certificate name, or matching username is
  a lead, not an identity attribution.
- Certificate-transparency records show certificate issuance history, not
  current ownership or a live host.
- RDAP fields may be redacted or privacy-proxied and must be interpreted under
  the registry's response notices.
- SecurityTrails history is provider-derived and coverage varies by plan,
  record type, retention window, and page. A completed run with zero normalized
  observations means that the returned `records` list was empty; an HTTP or API
  error is recorded as a failed provider run instead.
- WhatsMyName observations are marked `candidate-unverified`. The adapter does
  not contact profile sites. A human must open relevant candidates and evaluate
  stable IDs, cross-links, content, time, location, and contrary evidence.
- Sherlock refuses all-site runs, similar-username expansion, proxies, browser
  opening, response dumping, and arbitrary upstream flags. It runs one ASCII
  username against an explicit allowlist of no more than 25 sites. The original
  CSV is preserved, while claimed, available, WAF/blocked, invalid, and unknown
  outcomes remain distinguishable. A claimed result is only a candidate lead.
- SearXNG output is an aggregation layer. Preserve and assess the original page
  before using a result in a claim.
- `completed` with zero observations means the provider returned a valid empty
  result. `failed` means validation, configuration, execution, or response
  parsing failed. `blocked` means policy prevented execution. Never collapse
  these states into “not found.”

## Data minimization

Use the smallest result limit that answers the intelligence question. Avoid
collecting unrelated personal information. Do not add authentication cookies,
session tokens, password-reset workflows, CAPTCHA bypass, or active scanning to
these adapters.

Sherlock contacts its project update/data endpoints and each explicitly named
profile service. Review the upstream manifest, site terms, case authority, and
rate limits first. Keep the site list as small as possible, stop when services
signal blocking or rate limits, and manually corroborate every positive result.

Keep `SECURITYTRAILS_API_KEY` in the process environment or an approved secret
manager. Do not put it in `--option`, a checked-in `.env` file, a case note, or
the shell command itself. The included `.gitignore` excludes `.env` variants as
a last-resort safeguard, not as a substitute for secret management. Historical
DNS queries send the requested domain and record type to SecurityTrails, so run
them only when the case authority and provider terms permit that disclosure.

The same approval gate applies to HIBP, Hunter, Censys, and Companies House.
Credentialed health checks do not contact those APIs or spend credits. Full
case exports preserve licensed responses and may contain PII; use the redacted
JSON/PDF workflow and review free text before sharing.

Authoritative and project references reviewed for this release:

- [Wayback CDX server](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server)
- [Common Crawl index server](https://index.commoncrawl.org/)
- [Google Public DNS JSON API](https://developers.google.com/speed/public-dns/docs/doh/json)
- [SecurityTrails API overview](https://docs.securitytrails.com/docs/overview)
- [SecurityTrails DNS history by record type](https://docs.securitytrails.com/reference/dns-history-by-record-type-old-1)
- [IANA RDAP bootstrap registries](https://www.iana.org/assignments/rdap-dns/)
- [ICANN RDAP](https://www.icann.org/rdap)
- [SearXNG search API](https://docs.searxng.org/dev/search_api.html)
- [WhatsMyName dataset and schema](https://github.com/WebBreacher/WhatsMyName)
- [Sherlock official repository and CLI](https://github.com/sherlock-project/sherlock)
- [Sherlock installation guidance](https://sherlockproject.xyz/installation)
- [Certificate Transparency](https://certificate.transparency.dev/)

The crt.sh JSON query interface is a useful community service but is not treated
as a stable contractual API. Preserve raw responses and expect changes or
temporary unavailability.
