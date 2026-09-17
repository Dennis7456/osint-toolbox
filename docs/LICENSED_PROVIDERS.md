# Licensed providers and official registries

Phase 4 adds a local, fail-closed approval layer for bounded, passive API
queries. It is a control workflow, not a grant of legal authority or a managed
credential service. Live provider queries were not run during release testing;
contract, subscription, and account entitlements must be checked by the
operator before first use.

## What is enabled

| Provider | Query | Required authority | Credential variable | Calls per run |
|---|---|---|---|---|
| `hibp-account` | One email, breach names only | Self, or documented consent | `HIBP_API_KEY` | 1 |
| `hibp-domain` | One verified domain, breach aliases | Verified domain in subscriber account | `HIBP_API_KEY` | 1 verification + 1 lookup |
| `hunter-domain` | One domain, at most 25 email leads | Organization-authorized | `HUNTER_API_KEY` | 1 |
| `censys-host` | One globally routable IP, indexed host summary | Asset-authorized | `CENSYS_PAT` | 1 |
| `securitytrails` | One domain, one historical DNS type/page | Asset-authorized | `SECURITYTRAILS_API_KEY` | 1 |
| `companies-house` | One UK company-name search, at most 50 candidates | Business research | `COMPANIES_HOUSE_API_KEY` | 1 |

These adapters do not search leaked passwords, perform active scans, send
outreach, automate login, or bypass registry access controls. HIBP domain
queries check the subscriber's verified-domain list before requesting breach
aliases. HIBP 404 is recorded as a bounded zero result, not proof of safety.
Company-name and professional-email results remain unverified candidates.

`shodan` is a manual-only policy profile: its documented API places the key in
a URL query parameter, so this release does not make a Shodan request.
`maltego` is an export-only profile: `export-maltego` creates source-aware graph
tables for reviewed manual import, without using a Transform Hub connector.
No general people-data-broker adapter is enabled. A future adapter needs a
specific lawful purpose, jurisdictional review, API contract, and regression
tests before being added.

## Approval workflow

1. Create a case with a real purpose, authority, sensitivity, future
   `retention_until` date, and `approved-licensed` collection tier. For
   consent/organization/asset authority, preserve
   the written authority with `add-artifact` and retain its ID.
2. Read the installed profile and current provider terms. Confirm where data
   can be processed, attribution requirements, retention, price/credits, and
   query limits under the actual account contract. The bundled catalog is a
   review prompt, not a substitute for current terms.
3. Have a different named reviewer approve the exact target, basis, reason,
   expiry, and run cap. The reviewer records specific residency and cost notes.
4. Set the credential through an approved secret manager into the process
   environment; never place it in command arguments, the repository, case
   notes, or an unencrypted `.env` file.
5. Explicitly confirm external disclosure and execution for each query.
   Approval, disclosure confirmation, and run reservation are ledger events.
   A blocked/failed run is not a negative finding.
6. Revoke the approval when the purpose ends or consent is withdrawn. Review
   and delete controlled copies when the case retention period ends, subject to
   legal hold and local records policy. Automatic deletion is Phase 5 work.

Example using a self-owned address (replace paths, address, people, expiry,
and review notes; obtain a legitimate HIBP subscription first):

```bash
osint-toolbox provider-policy hibp-account
osint-toolbox approve-provider CASE-DIRECTORY hibp-account \
  --target me@example.org --basis self \
  --reason 'Self-owned breach exposure review' \
  --reviewer 'Independent reviewer' --actor 'Collector' \
  --expires-at 2026-10-01T12:00:00Z --max-runs 1 \
  --terms-reviewed --data-residency-accepted --cost-acknowledged \
  --data-residency-note 'Approved under our data-transfer review' \
  --cost-note 'One query within the approved subscription'

osint-toolbox collect CASE-DIRECTORY hibp-account \
  --target me@example.org --confirm-external-disclosure --execute

osint-toolbox revoke-provider-approval CASE-DIRECTORY APP-REPLACE-WITH-ID \
  --reason 'Review complete'
```

Use `osint-toolbox provider-policy` for all profiles and
`osint-toolbox registries --jurisdiction KE` (or `UK`, `US`, `GLOBAL`) for
official registry routes. Credentialed health checks are deliberately
no-network: they report `unconfigured` or `configured-unprobed`; they never
spend credits or disclose a test target. Queries reject missing or locally
malformed credentials, unknown options, missing/expired/revoked approvals,
policy-profile changes,
non-matching targets, exhausted run caps, missing case retention, and missing
disclosure/execute acknowledgments before a provider request. A reservation
is consumed even if the request fails, preventing retries from silently
exceeding the authorized cap. Credentialed HTTP calls require HTTPS and refuse
cross-origin redirects.

The local CLI records reviewer and actor names but cannot authenticate them;
the two-person check is a procedural attestation. Phase 5 must enforce real
user identities, roles, and approval separation. The local vault must be
protected by filesystem permissions and full-disk encryption; credentials
are never intentionally written into the case.

## Handling and dissemination

The original case stores raw provider responses as hashed artifacts and is a
sensitive evidence vault. Full JSON, CSV, ZIP, GraphML, Maltego tables, local
workbench, and unredacted reports can disclose PII; share only under case
authority. The template redacted JSON/PDF path removes licensed-provider PII
runs, approvals, raw-response artifact records, linked observations/claims,
and authority-artifact records. Free-text narratives and independently
entered records still require human review. Redacted derivatives are not
complete evidence packages and do not delete raw artifacts from the vault.

## Jurisdictional registry routes

The registry catalog starts with the [Nursing Council of Kenya licence-status
portal](https://osp.nckenya.com/LicenseStatus), [Kenya Business Registration
Service](https://brs.ecitizen.go.ke/), [UK Companies House](https://find-and-update.company-information.service.gov.uk/),
[US SEC EDGAR](https://www.sec.gov/search-filings), and
[GLEIF LEI search](https://search.gleif.org/). Only Companies House has an
in-tool API adapter. NCK, BRS, SEC, and GLEIF are manual routes: preserve an
authorized extract as a case artifact, follow each portal's access rules, and
do not infer identity solely from a name match. Kenya BRS may require an
account and fee; the toolbox does not automate it.

## Provider documentation to review before approval

- [HIBP API](https://haveibeenpwned.com/API/v3) and [terms](https://haveibeenpwned.com/TermsOfUse)
- [Hunter API](https://hunter.io/api-documentation) and [terms](https://hunter.io/terms-of-service)
- [Censys Platform API](https://docs.censys.com/reference/get-started) and [terms](https://censys.com/terms-of-service/)
- [SecurityTrails API](https://docs.securitytrails.com/docs/overview) and [quota guidance](https://docs.securitytrails.com/docs/quotas-rate-limits)
- [Companies House search API](https://developer-specs.company-information.service.gov.uk/companies-house-public-data-api/reference/search/search-companies), [authentication](https://developer.company-information.service.gov.uk/authentication), and [guidelines](https://developer.company-information.service.gov.uk/developer-guidelines)
- [Shodan API](https://developer.shodan.io/api) and [terms](https://static.shodan.io/legal/terms.html)
- [Maltego table import](https://docs.maltego.com/en/support/solutions/articles/15000010797-import-graph-from-table) and [license](https://www.maltego.com/license-agreement/)
