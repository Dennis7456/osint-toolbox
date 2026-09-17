# Open interchange schemas

The schemas use JSON Schema Draft 2020-12. `case.schema.json` describes the
case metadata document. `record.schema.json` accepts any record stored in the
case JSONL datasets. Validate each non-empty JSONL line independently.

The command-line application validates these exact schemas before each write
and during `verify`. It also enforces identifiers, hash chains, artifact hashes,
legal-hold transitions, and cross-record references, which JSON Schema alone
cannot establish. A valid schema record is therefore necessary but not
sufficient for a valid case; always run `osint-toolbox verify` as well.

Schema version `1.4` is append-oriented. Published records should not be edited
in place. Corrections should be represented by a new record/status plus an
auditable ledger event. `upgrade-case` follows the registered migration chain
from v1.0 through v1.1, v1.2, and v1.3 to v1.4 without rewriting prior ledger
entries. It adds append-only provider approval/revocation decisions to the
Phase 3 resolution, worksheet, and audit-review datasets.
