# Local optional services

This Compose profile runs SearXNG and ArchiveBox on the workstation loopback
interface only. Neither service is required by the OSINT Toolbox core.

## Before starting

1. Install a current Docker Engine/Desktop with Compose.
2. Copy `searxng/settings.example.yml` to `searxng/settings.yml`, then replace
   the placeholder `server.secret_key` with a long random value. The resulting
   file is ignored by Git.
3. For repeatable or production use, set `SEARXNG_IMAGE` and
   `ARCHIVEBOX_IMAGE` to reviewed, pinned image tags or digests instead of the
   moving `latest` defaults.
4. Review both projects' current configuration and upstream terms. Search
   engines may rate-limit or block an instance.

Start and inspect the services:

```bash
cd deploy
docker compose config
docker compose up -d
docker compose ps
```

SearXNG will be at `http://127.0.0.1:8080` and ArchiveBox at
`http://127.0.0.1:8000`. Configure the adapter without placing the address in
source control:

```bash
export OSINT_SEARXNG_URL='http://127.0.0.1:8080'
osint-toolbox collect CASE-DIRECTORY searxng \
  --target 'Example Organization annual report' \
  --option safesearch=1 \
  --confirm-external-disclosure \
  --execute
```

Create the first ArchiveBox administrator interactively:

```bash
docker compose run --rm archivebox init --setup
```

ArchiveBox is intentionally not called automatically by the CLI. Submit only
URLs within the case authority, then import its exported capture or WARC using
`add-artifact`. The Compose file disables public index, snapshot, and add views.

## Security boundaries

- Both ports bind to `127.0.0.1`; do not change that without authentication,
  TLS, network controls, and a threat-model review.
- Container isolation is not a substitute for an isolated investigation VM.
- Treat ArchiveBox data volumes as case evidence and encrypt/backup them under
  the same retention policy.
- Keep API keys and provider credentials out of Compose files, shell history,
  artifacts, and the case ledger.

Current upstream references:

- [SearXNG container installation](https://docs.searxng.org/admin/installation-docker.html)
- [SearXNG search API](https://docs.searxng.org/dev/search_api.html)
- [ArchiveBox installation](https://docs.archivebox.io/latest/Install/)
