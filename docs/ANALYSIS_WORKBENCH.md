# Phase 3 analysis workbench

The workbench is a local, read-only HTML view of a case. It does not call a
provider, upload evidence, or silently change a record. The CLI records
decisions in append-only JSONL and the hash-chained ledger; regenerate the page
after each change. Keep case files and the generated page in approved storage.

## Start or migrate

```bash
osint-toolbox upgrade-case cases/CASE-DIRECTORY
osint-toolbox verify cases/CASE-DIRECTORY
osint-toolbox workbench cases/CASE-DIRECTORY
```

The generated `reports/workbench.html` has searchable timeline, candidate
entities, relationships, source register, and worksheet views. Open it locally
in a browser. A date-only event stays date-only; a timezone-aware timestamp is
normalized to UTC. Every displayed node, edge, and event must cite at least
one registered source ID. If an older case has an unsourced entity, graph and
workbench generation fail explicitly. Review the original evidence and create
a correctly sourced replacement entity; do not edit the historical JSONL row.

The source links on the page are external links and initiate a network request
only when clicked. Map snapshot links point to registered, hashed local
artifacts. The HTML page is a derivative: store/disclose it under the case
sensitivity rules; use `verify` and a signed bundle for preservation.

## Candidate entity resolution

Two same-name entities are only candidates. A merge is an analyst decision,
not a mutation of the source entities or a claim that all other edges were
observed. Cite one or more specific, sourced features. Each feature is a JSON
object with `description` and `source_ids`; all its IDs must also appear in
the decision-level `--source-id` values.

```bash
osint-toolbox resolve-entities cases/CASE-DIRECTORY merge ENT-FIRST ENT-SECOND \
  --source-id SRC-EVIDENCE \
  --feature '{"description":"Independent matching registration number","source_ids":["SRC-EVIDENCE"]}' \
  --reason 'Registration and address independently corroborated' \
  --analyst reviewer-name

osint-toolbox resolve-entities cases/CASE-DIRECTORY split ENT-FIRST ENT-SECOND \
  --source-id SRC-EVIDENCE \
  --reverses-id RES-MERGE-ID \
  --reason 'Follow-up evidence disproves this particular merge' \
  --analyst reviewer-name
```

The split reverses exactly one active merge. When other merges still connect
the same entities, the group may remain connected; examine each decision. No
entity, source, relationship, or previous decision is deleted. The workbench
shows active merge evidence and the merge ID to reverse.

## Geolocation and media worksheets

Copy [geolocation-worksheet.example.json](../templates/geolocation-worksheet.example.json)
or [media-provenance-worksheet.example.json](../templates/media-provenance-worksheet.example.json),
replace *every* placeholder ID with an existing case ID, and record the
completed JSON:

```bash
osint-toolbox record-worksheet cases/CASE-DIRECTORY ./location-review.json \
  --analyst reviewer-name
osint-toolbox record-worksheet cases/CASE-DIRECTORY ./media-review.json \
  --analyst reviewer-name
osint-toolbox workbench cases/CASE-DIRECTORY
```

First use `add-source` for the original media, map service, and each important
reverse-search/earliest-appearance result. Use `add-artifact` for the media
and for captured map snapshots; put the artifact IDs in `artifact_ids` and
`map_artifact_ids`. The geolocation worksheet requires clues and at least one
candidate with separate matched and mismatched features. The media worksheet
requires typed `reverse-search` and/or `earliest-appearance` leads with URL,
observed date/time, source IDs, and notes. A lead is not proof of origin; the
earliest result *found* is not necessarily the first publication. Each clue,
lead, match, and mismatch has explicit source IDs. Worksheets are append-only:
record a new worksheet for a corrected assessment and explain the correction
in its `assessment`; both versions remain.

## Quality audit and reviewer decisions

```bash
osint-toolbox audit cases/CASE-DIRECTORY --stale-days 365
osint-toolbox review-finding cases/CASE-DIRECTORY FINGERPRINT false-positive \
  --reason 'Separate source captures of distinct organizations' \
  --reviewer reviewer-name --stale-days 365
osint-toolbox audit cases/CASE-DIRECTORY --stale-days 365
```

Copy the 64-character `fingerprint` from `reports/quality-audit.json`.
Dispositions: `accepted`, `deferred`, `false-positive`, `resolved`, and
`reopened`. The latest decision is shown with its reviewer and reason; older
decisions remain in `audit_reviews.jsonl`. False-positive/resolved findings
are marked `suppressed` but never removed from audit output. Reopen to restore
one. Integrity failures cannot be suppressed. Fingerprints are based on
category and record IDs, not volatile finding numbers or source age. If the
finding changes its supporting record set or vanishes, review the new audit
instead of applying a stale disposition. Checks include duplicate sources,
observations, and entities; conflicting observations; stale sources; claims
without normalized observations or with only withdrawn evidence; unlinked
artifacts; unsourced entities; and high-confidence inferred edges. These are
review prompts, not automated findings of fact.

## Graph interoperability

```bash
osint-toolbox export cases/CASE-DIRECTORY graphml
osint-toolbox export cases/CASE-DIRECTORY maltego
```

Open `reports/case-graph.graphml` in Gephi. It preserves `source_ids`,
`confidence`, `evidence_kind`, typed edges, and each node's
`resolution_group`. Gephi's [GraphML import documentation](https://docs.gephi.org/desktop/User_Manual/Import/GraphML_Format/)
documents node/edge attributes. Do not relabel `inferred` as `observed` in a
visualization or use an active resolution group as a substitute for original
entity IDs.

`reports/maltego-export/` contains `entities.csv`, `links.csv`, and
`graph.json`, with stable IDs, original evidence kinds, and source IDs. Import
the CSV tables with explicit entity and link column mappings using Maltego's
[Import Graph from Table wizard](https://docs.maltego.com/en/support/solutions/articles/15000010797-import-graph-from-table).
The CSV/JSON are mapping-friendly interchange tables, **not** a native Maltego
graph file or an automatically configured mapping. Check the link preview and
turn off unwanted auto-created links before accepting the import. CSV cells
that start with spreadsheet formula characters are text-prefixed to avoid
formula execution; `graph.json` retains original field values.

`export json` and `export csv` also include the three new datasets. Redaction
rules must explicitly address `resolutions`, `worksheets`, and `audit_reviews`
before sharing their sensitive free text.
