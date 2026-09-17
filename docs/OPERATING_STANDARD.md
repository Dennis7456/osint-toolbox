# Operating standard

## 1. Authorization and necessity

Before collection, write down:

- the intelligence question and decision it supports;
- the legal/contractual authority;
- named targets, jurisdictions, sources, and date range;
- permitted collection tiers and prohibited actions;
- sensitive-data categories that may be encountered;
- retention, dissemination, and deletion rules;
- escalation contacts for legal, safety, and imminent-harm issues.

Publicly reachable does not automatically mean appropriate to collect, retain,
combine, or publish. Apply necessity, proportionality, platform terms, privacy
law, intellectual-property rules, and professional ethics.

## 2. Collection tiers

| Tier | Activity | Default |
|---|---|---|
| 0 | Offline analysis of supplied files and existing case data. | Allowed in scope. |
| 1 | Passive public search, official registries, public archives, and documented public APIs. | Allowed in scope. |
| 2 | Authenticated access to content legitimately available to an approved research account. | Requires policy and platform review. |
| 3 | Sensitive databases, precise personal data, monitoring, or services needing verified control. | Written approval and enhanced handling. |
| 4 | Contact, account recovery, private groups, on-site activity, drones, active network testing, or any action that may notify/affect the subject. | Separate explicit authorization; excluded from default automation. |
| 5 | Access-control bypass, credential attacks, malware, unlawful interception, impersonation, or acquisition of illicit datasets. | Prohibited by this package. |

## 3. Research identities and environment

Use a dedicated investigator account, browser profile, and device/VM when
separation is necessary. Do not mix personal contacts, cookies, cloud sync, or
phone address books with case activity. Do not create a persona that copies a
real person. Deceptive engagement, false connection requests, and private-group
access are not default OSINT activities and require specialized legal and
ethical review.

Protect the environment with full-disk encryption, screen locking, patched
software, least privilege, a password manager, multi-factor authentication,
approved VPN/network policy, and encrypted backups. Store API secrets in a
secret manager and never in source control, screenshots, or case reports.

Before a provider sends a target or query outside the workstation, review the
case sensitivity, authority, provider terms, and necessity. Pass
`--confirm-external-disclosure` only after that review. This flag is a recorded
operator attestation, not a substitute for authorization or a data-processing
agreement.

## 4. Source and artifact collection

For every material source record:

1. Exact source URL or official record identifier.
2. Page/document title and publisher.
3. Exact query or path used to reach it.
4. UTC access time and displayed publication/event time.
5. Collector and tool/version.
6. Reliability and credibility assessment.
7. Unannotated capture or original file where appropriate.
8. SHA-256 for every saved artifact.
9. Notes on authentication, personalization, locale, missing context, and known
   transformations.

Preserve originals read-only. Create OCR, crops, translations, keyframes, and
enhancements as separate derivatives and record the parent artifact hash and
command/tool used.

## 5. Source assessment

Assess two dimensions separately:

- Reliability: Is it a primary record/first-party observation, a secondary
  report, or an unknown/aggregated source?
- Credibility: Is this particular information high, medium, low, or unknown
  credibility given proximity, internal consistency, incentives, date, and
  corroboration?

Search-result snippets, AI summaries, repeated reposts, popularity, and graph
centrality are discovery aids, not independent evidence.

## 6. Entity resolution

Do not merge people/accounts/organizations because of a name or username alone.
Keep candidates separate and compare independent attributes. Strong indicators
include official cross-links, stable platform identifiers, a verified domain,
unique contact details lawfully published in both places, exact reused media
with matching context, or several dated biographical facts.

Record negative evidence and contradictions. Absence from a source means only
“not observed in that source at that time,” not non-existence.

## 7. Confidence

- High: multiple independent, credible sources or a decisive primary record;
  important alternatives have been tested.
- Medium: evidence is consistent and reasonably corroborated but a meaningful
  gap or alternative remains.
- Low: plausible lead supported by limited, indirect, old, or conflicting data.

Confidence belongs to a claim, not to a person or entire case. State what would
raise or lower it.

## 8. Special safeguards

### Breach exposure

Use HIBP or an approved enterprise provider for self-owned/authorized email
addresses or verified organizational domains. Retain breach names, dates, data
classes, and source attribution when necessary. Do not retrieve, crack, test,
or store passwords in the default case system.

### Social media

Prefer native search and documented APIs. Do not bypass privacy controls,
CAPTCHAs, blocks, or rate limits. Relationships inferred from follows, likes,
replies, co-location, or common hashtags require context. Avoid collecting
unrelated networks, minors, or sensitive content.

### Location

Use the least precise location that answers the question. Do not publish a
vulnerable person's real-time or home location without a documented necessity
and safety decision. Remote map analysis does not authorize physical
surveillance, trespass, or drone operations.

### Images and video

Hash the original before processing. Distinguish depicted time, file metadata
time, publication time, and capture time. Reverse-image and AI-geolocation
matches generate candidates only. Check crop, context, earliest known public
appearance, edits, reflections, weather, and landmark consistency.

### Personal data

Collect the minimum necessary. Mask phone numbers, addresses, emails, dates of
birth, identity numbers, and family details in working views and reports when
the full value is unnecessary. Apply higher review to minors, medical data,
protected characteristics, financial data, and precise residence/location.

## 9. Reporting and review

Separate fact, inference, allegation, and unknown. Cite every material claim.
Include scope, authority, cut-off time, method, limitations, contradictory
evidence, alternate explanations, and confidence. A second analyst should review
high-impact identity, location, fraud, misconduct, or threat claims.

Before dissemination:

- run `osint-toolbox verify`;
- verify links and primary documents still support the claims;
- redact unrelated PII and secrets;
- label sensitive appendices;
- record recipients and purpose;
- export the source and artifact registers with the report when appropriate.

For PDF dissemination, use `redact-pdf` to rebuild the document from the
policy-minimized case snapshot. Do not cover sensitive text with rectangles or
other visual overlays: underlying text or objects may remain extractable.
Render and inspect every final page, extract its text for a second check, and
manually review free text, URLs, indirect identifiers, metadata, and filenames.

When authenticity is required, sign the bundle manifest with `sign-bundle`
and verify it with `verify-signature`. Protect the private key separately from
the case and distribute the public-key fingerprint through a trusted channel.
A valid signature proves possession of the corresponding key and unchanged
signed manifest bytes; it does not establish that the evidence or analysis is
correct.

## 10. Retention and closure

At closure, set a retention/deletion date, remove temporary downloads and API
caches, revoke case-specific credentials, document unresolved risks, preserve
required audit material, and securely dispose of data no longer justified.

Before changing retention or disposing of any case material, run
`legal-hold-status`. Place a hold with a documented reason and authority as soon
as preservation is required. While it is active, do not shorten, clear, or
otherwise change retention and do not delete evidence, exports, logs, or
backups. Release the hold only from documented authority; record the release
reason and then apply the approved post-hold retention date.

If `verify` reports a pending crash-recovery transaction, stop case writes and
run `recover-case` from a protected copy. Review any orphan transaction payload
or unregistered artifact manually; never treat it as safely disposable merely
because it is not yet in the ledger.
