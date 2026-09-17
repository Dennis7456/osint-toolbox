# Team service (Phase 5)

## Supported deployment and architecture

Version 1.0.0 adds an optional, single-host team service. Use Linux/POSIX for
workers; the local CLI remains usable without team dependencies. PostgreSQL
16+ holds metadata, reviews and jobs; a dedicated local directory holds AES-GCM
encrypted evidence. API and worker must share that directory and encryption key.
Multiple API/worker processes on the same host are supported through database
locks. Multi-host object replication, automatic local-case migration and a team
web UI are not included.

`team_api.py` authenticates HTTP and translates requests. `team_service.py`
validates every public operation, checks case permissions, enforces review and
retention, and publishes evidence. `team_store.py` is privileged persistence;
do not call it from a future client adapter to bypass the service. Local and
team collectors use the common `application.execute_collection` boundary with
their respective durable authorization checks. No MCP configuration is needed.

## Installation and configuration

Install a verified release wheel with the `team` extra, or develop from the
locked source checkout:

```sh
uv sync --locked --all-extras
uv run osint-team --help
```

Required settings:

| Variable | Meaning |
|---|---|
| `OSINT_TEAM_DATABASE_URL` | Dedicated PostgreSQL database/schema connection; use `sslmode=verify-full` for a remote server. |
| `OSINT_TEAM_OBJECT_ROOT` | Absolute, service-owned, mode-0700 evidence directory outside the repository. |
| `OSINT_TEAM_OBJECT_KEY` | Base64 encoding of 32 cryptographically random bytes. |
| `OSINT_TEAM_OIDC_ISSUER` | Exact HTTPS issuer for access tokens. |
| `OSINT_TEAM_OIDC_AUDIENCE` | Audience dedicated to this API, not an ID-token client audience. |
| `OSINT_TEAM_OIDC_JWKS_URL` | HTTPS JWKS URL on the configured issuer origin. |
| `OSINT_TEAM_ADMIN_SUBS` | Comma-separated trusted administrator subject IDs. |
| `OSINT_TEAM_WORKER_SUB` | Dedicated audit identity, default `service:worker`; never an administrator or case member. |
| `OSINT_TEAM_BACKUP_KEY` | Optional separate base64 32-byte backup encryption key; otherwise the object key is used. |

Database URL, object key and backup key also support a `_FILE` suffix for
mounted secrets. Do not set both forms. Provision keys through a secret manager;
do not put real values in source files, command-line arguments or shell history.
Loss of the object key makes evidence unrecoverable. With a separate backup key,
both keys are needed for a full restoration. Current object format uses a single
key; rotation requires an offline, verified re-encryption/migration procedure.

1. Create a dedicated schema owner and a separate non-superuser runtime login.
   The runtime login must not own the schema, belong to the owner role, or have
   `CREATE` on the database/schema. Do not use a general-purpose shared database.
2. Set configuration using the owner connection and run `osint-team init-db`.
   This migrates the prototype schema to version 2. Old unproven collection jobs
   are failed closed and require a newly submitted/reviewed request.
3. Run `osint-team grant-runtime --role osint_runtime` as the owner. The role
   must already exist; passwords are provisioned separately, not by this command.
4. Switch API/worker configuration to the runtime connection. Run
   `osint-team check`, `osint-team verify-audit`, and `osint-team verify-storage`.
5. Start the API on loopback behind a TLS reverse proxy:

```sh
uvicorn osint_toolbox.team_api:create_app --factory --host 127.0.0.1 --port 8090 --no-access-log
osint-team worker
```

Configure the proxy to enforce trusted hosts, TLS, request timeouts, a 20 MiB
body limit, per-identity/IP rate limits and bounded concurrency. Do not log
Authorization headers, request bodies or query strings. Keep `/healthz` and
`/readyz` private to monitoring. OIDC verification supports RS256 access tokens
with issuer, audience, subject, expiry and issue-time checks. No anonymous
research, auto-enrollment, password login or token issuance is provided.

The examples in `deploy/systemd` supervise the API, worker and retention timer.
Review paths, account names, secret mounts, hardening and resource budgets before
installing them. They are not installed automatically. Isolate media workers
from unrelated files and credentials, deny unnecessary outbound traffic, and
keep ffprobe/ExifTool patched. ffprobe excludes network/playlist formats and
ExifTool disables user config; these controls do not replace OS isolation.

## Permissions and API behavior

| Role | Access |
|---|---|
| Viewer | Case metadata, annotations/work and approved reports. No raw evidence or collection jobs. |
| Analyst | Evidence upload/download, annotations/work, job requests and report drafts. |
| Reviewer | Analyst access plus independent job/report review and assignment. |
| Owner | Reviewer access plus case membership, legal holds, retention and complete exports. |
| Administrator | Create cases and access all cases/metrics; independent-review rules still apply. |

Authenticated subjects come from the access token, never a request field.
Removing a case member takes effect on the next service operation and at job
execution/result-publication checks. An external request already sent cannot be
recalled. Administrators are separately configured, so removing a membership
does not revoke an administrator; remove their configured subject and revoke
IdP access as part of offboarding.

An administrator can retrieve `/openapi.json`; public documentation endpoints
are disabled. The API includes cases, members, objects, annotations, work,
review queues, jobs, reports, legal holds, retention, audit and exports. List
endpoints accept `limit` (1–500) and `offset` (0–100000). All responses are
non-cacheable; raw artifacts are attachment-only octet streams.

## Collection jobs

Submit `POST /cases/{case_id}/jobs` with `kind`, `provider`, `target`, `options`
and `disclosure_confirmed`. Provider jobs are limited to `rdap`, `dns`, `crtsh`,
`wayback` and `commoncrawl`; the target must exactly match the case scope.
Media jobs use `kind=media`, `provider=ffprobe` or `exiftool`, and an original
case `source_object_id`, without a target or arbitrary options.

Supply an `Idempotency-Key` header (8–128 safe characters) when retrying job
submission. Reusing it with the same request returns the same job; a changed
request returns 409. Keys are scoped to case and authenticated requester.
Every request starts pending; another reviewer must approve it. There is no
standing or self-approval. The worker rechecks current roles, disclosure,
scope and retention before execution and before saving results.

- `GET /cases/{case_id}/jobs/{job_id}` returns status and the result object ID.
- Read the result through the authenticated object endpoint. The result includes
  collection time, collector/reviewer identities, provider, tool version, source
  URL/assessment, raw-object hash and normalized records. Zero results are a
  completed outcome, never a substituted error.
- `POST .../cancel` invalidates a pending/approved/running job. It fences late
  result writes; it cannot undo already issued provider requests.
- `POST .../retry` is available to the original requester for failed jobs with
  fewer than three executions and returns the job to independent review.
  There is no automatic whole-job retry after uncertain external execution.
  The existing bounded provider HTTP retries remain in place.

Workers have 15-minute leases and a 14-minute wall-clock deadline. Expired
leases fail closed and stale workers cannot publish. A supervisor restarts
crashed processes. Media subprocesses additionally have 45-second wall-clock,
30-second CPU, 1 GiB address-space and 2 MiB output limits. Provider responses
and individual stored objects are capped at 20 MiB. Defaults cap each case at
1,000 objects, 512 MiB and 100 outstanding jobs. Complete exports are bounded
at 100 MiB and 1,000 objects; larger cases need a deliberate streaming-export
extension, not an unbounded memory allocation.

## Retention, backup and recovery

Run `osint-team retention-once` daily (the supplied timer does this). Dates use
UTC consistently and expire at the start of the specified date. Legal holds
prevent deletion and freeze retention changes. Expired cases cannot acquire
new content even when held. Retention serializes with case writes and holds,
commits a tombstone and metadata minimization first, then deletes ciphertext.
An interrupted purge resumes next run; deleted cases cannot be reopened by an
in-flight worker. Audit identities/hashes remain under the separate audit policy.

```sh
osint-team backup /secure/backups/reviewed-snapshot.otb
osint-team verify-backup /secure/backups/reviewed-snapshot.otb
osint-team restore-drill /secure/backups/reviewed-snapshot.otb --target-object-root /secure/drill/objects
```

Set the restore connection through `OSINT_TEAM_RESTORE_DATABASE_URL` or its
`_FILE` variant. The target must be a genuinely separate, empty database and an
empty, non-overlapping object directory. The drill does not destroy or recreate
the source or target database. Only restore trusted backups: a PostgreSQL dump
contains executable SQL. Failed drills leave the target for diagnosis; create
a new empty target for the next drill. Never use a production database as a
drill target.

Backup takes an application-wide maintenance lock, verifies evidence/audit,
dumps only the application schema, copies registered ciphertext and encrypts a
manifested archive. Writes may briefly wait or return 503 during the snapshot.
The supported archive limit is 10 GiB; for larger deployments design database
PITR plus coordinated object snapshots. Keep backup encryption keys separate
from archives. Backups do not include roles, IdP settings, key material or OS
configuration. Reapply runtime grants after restore.

Store copies off-host with immutability/versioning and a documented retention
schedule. Verify each backup; perform and record a restore drill at least
monthly and after migrations. Restored audit chains, every active object, and
case export checksums are checked. Before opening a restored service, reconcile
legal holds, revocations and deletion decisions newer than the snapshot.

## Monitoring and incident response

Monitor readiness, supervisor restarts, failed/expired jobs, queue growth,
pending purges, free disk, database connections, backup age and restore-drill
age. `/metrics` is administrator-only and contains counts, not case content.
Worker logs contain job IDs and error classifications, never raw provider errors.
Run integrity verification during a maintenance window; orphan objects from a
hard process kill are reported, not automatically destroyed.

For suspected exposure: stop collection, revoke affected IdP/provider access,
isolate the service, preserve relevant audit/checkpoint copies, determine the
scope, rotate compromised credentials/keys through a reviewed recovery plan,
restore only verified backups, and document the incident before resuming.

## Production acceptance gates

The code release is not proof that a particular deployment is secure. Before
real cases: configure and test your IdP, runtime DB role, TLS proxy, host/media
isolation, encrypted database volume, rate limits, monitoring/alerts, off-host
backups, key recovery and restore drill. Run representative load tests and
review provider terms and jurisdictional authority. No live deployment, cloud
resource, provider subscription or GitHub setting is created by this package.
