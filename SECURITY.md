# Security and credential handling

Do not put case evidence, access tokens, provider keys, database passwords,
private signing keys, encryption keys or production backups in this repository.
The ignore rules are preventative only: they do not remove already tracked files.

Before each push, run an installed, reviewed Gitleaks release:

```sh
gitleaks git . --redact=100 --log-opts=--all
gitleaks dir . --redact=100
```

The supplied pre-commit configuration can be enabled with `pre-commit install`.
CI scans full reachable history and the working tree. Enable GitHub secret
scanning and push protection in repository settings where available. A local
clean scan cannot guarantee that every GitHub detector will produce no alerts.
Do not suppress a genuine finding with an allowlist. Test cryptographic keys
are generated at runtime; example configuration contains no usable credentials.

If a genuine credential is found in any commit, revoke/rotate it immediately,
then remove it from current files. Coordinate history cleanup with repository
collaborators; a later deletion commit does not remove the original exposure.
Do not paste secret values into issues or scan reports. Report only the rule,
file, line and commit using fully redacted output.

Report vulnerabilities privately to the repository owner, preferably through
GitHub private vulnerability reporting if enabled. Do not include live tokens,
private evidence or personal information in a public issue.

## Trust boundaries

- Local CLI use trusts the current OS account and its case directories. It is
  not a multi-tenant API or an authentication boundary.
- Team clients use verified OIDC access tokens. `TeamService` enforces case
  permissions, independent reviews, retention and job policy. Database and
  object-store access is privileged and must never be exposed as a client tool.
- Run the API/worker with a non-owner PostgreSQL role. Apply schema migrations
  with a separate owner account; never give the runtime account superuser or
  schema-owner privileges. Audit rows are append-only to the runtime account;
  database/host administrators can still subvert the system. Store external,
  immutable backup/checkpoint copies to detect rollback of an entire database.
- Object encryption protects stored content. Case metadata and audit identities
  reside in PostgreSQL: use encrypted disks/backups and TLS for remote database
  connections. Keys are separate from backups; keep recovery copies in a secret
  manager. A separate backup key is supported and recommended.
- Collected content is untrusted. Downloads are attachments, never rendered
  active HTML in the API origin. AI integrations, if added later, must treat
  source content as data, never as authorization or executable instructions.
- Media tools need patched binaries and a dedicated restricted worker account.
  Limits and protocol restrictions are defense in depth, not an OS sandbox.
  The deployment runbook specifies network/filesystem isolation requirements.

See [team operations](docs/TEAM_SERVICE.md) for deployment gates and incident
response, and [validation](docs/PHASE5_VALIDATION.md) for the release evidence.
