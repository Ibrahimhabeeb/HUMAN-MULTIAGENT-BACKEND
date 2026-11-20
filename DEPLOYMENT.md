# Host Secure Coding Room

This setup runs the frontend, FastAPI API and PostgreSQL on one Linux VPS. Caddy serves the built frontend and
provides HTTPS; `/api` goes to the API on the private Docker network. The API calls the configured external AI
provider. No model weights or GPU are required on the VPS.

## What runs where

```text
Participant browser -> HTTPS / Caddy -> built React frontend
                                  -> /api -> FastAPI -> PostgreSQL
                                                   -> external model API
                                                   -> private runner -> disposable test container
```

Only ports 80 and 443 are published. PostgreSQL and the test broker have no public ports. The API has no Docker
socket. Each test container receives only a copy of one job's files, runs as a nonroot user with no network,
dropped capabilities, a read-only root filesystem, bounded temporary storage, CPU, memory and PID limits, and
is removed after execution. The private broker alone can access Docker. The broker has no database credentials,
AI keys, or workspace volumes. Ordinary containers share the host kernel: this is a controlled study deployment,
not a general-purpose public code-execution service.

The runner admits one execution and up to four waiting requests, with a 120-second queue deadline. Each job has
a 60-second pytest deadline, 384 MiB memory limit, 0.5 CPU and at most 64 processes. Both the provided tests and
the hidden security assessment use it. If the runner is unavailable, production reports an error and never
falls back to running participant Python inside the API container. Neither test process can modify the saved
submission. Unit and security outcomes refer to the same final snapshot at Finish part.

Workspace writes have a 2 MiB aggregate file budget, checked before saves and snapshots. Saves, renames, deletes
and final capture are coordinated per workspace, with a fresh completion check after acquiring the lock. Snapshots
and test-job admission are bounded. A final submission records pending assessment before tests start, so its
frozen code remains recoverable if the API restarts during assessment.

## 1. Server and repositories

Start with Ubuntu LTS and Docker Engine plus the Compose plugin. A 2 GB machine is a pilot starting point;
check actual memory use and concurrent study sessions before recruitment. Build before starting the services,
because the Node/Monaco build needs extra memory. Choose a UK/EU location suitable for the study's data handling.
The management wrapper builds services sequentially, and the frontend build caps the Node.js heap at 1 GiB.

Install Docker using its [Ubuntu instructions](https://docs.docker.com/engine/install/ubuntu/), then verify:

```bash
docker version
docker compose version
```

Keep these repositories beside each other and use their reviewed `main` commits:

```text
secure-coding-room/
  backend/
  human-agent-frontend/
```

The frontend build context in `compose.yaml` is `../human-agent-frontend`. Clone the existing backend and
frontend repositories into these names, then work from `backend/`. Git access for private repositories is
separate from GoDaddy delegation; keep repository credentials on the server private.

## 2. Production settings

```bash
cp .env.production.example .env.production
chmod 600 .env.production
openssl rand -hex 32
openssl rand -hex 32
stat -c '%g' /var/run/docker.sock
```

Edit `.env.production`. Use the two different random hex values for `POSTGRES_PASSWORD` and `RUNNER_TOKEN`,
and the socket group number for `DOCKER_GID`. Hex avoids URL-escaping problems in the database connection string.
Set `LLM_MODEL` and `LLM_API_KEY` to the intended provider/model. Set `DOMAIN` to the exact subdomain, for example
`securecoding.greengamingexchange.se`, without `https://` or a path. Set `TLS_EMAIL` to the certificate contact.
Replace every example value before starting. Nothing in this file is sent into the frontend build or test jobs.

The Compose file explicitly selects production mode, PostgreSQL, persistent absolute directories, allowed hosts,
the private runner and disabled public API documentation. The backend refuses missing production configuration.
The existing `.env` and local database are not used by this stack. Runtime exports remain in the private data
volume; they are not web-served. Keep one API worker/replica: pre-consent state is deliberately memory-only and
its lock is process-local. Consented tokens are stored as hashes in PostgreSQL and survive API restarts;
pre-consent tabs may need to start again after a restart. Pending setup sessions expire after two hours.

## 3. Domain and HTTPS

In GoDaddy's DNS for `greengamingexchange.se`, add an **A** record named `securecoding` with the VPS's public IPv4
address. Leave TTL at its default. The resulting address is `https://securecoding.greengamingexchange.se`.
If IPv6 is configured and reachable on the server, an AAAA record can also be added. Caddy obtains and renews
the HTTPS certificate once DNS points to the server and ports 80/443 are reachable.

In the VPS provider firewall allow TCP 80/443 publicly and restrict SSH (22) to the intended administrator's IP.
Do not publish 8000, 5432 or 9000. Domain-only GoDaddy access is enough when the VPS is hosted elsewhere.
No DNS record or cloud resource is created by these project files.

## 4. Build and start

```bash
bash deploy/manage.sh --profile tools build
bash deploy/manage.sh up -d
bash deploy/manage.sh ps
bash deploy/manage.sh logs --tail=80 api runner frontend
curl --fail https://securecoding.greengamingexchange.se/api/ready
```

The tools profile builds the fixed sandbox image; it does not need to stay running. The normal `up` starts the
database, broker, API and proxy. PostgreSQL becomes healthy before the API starts. The API applies the existing
Alembic migration chain, including all analysis views, then synchronises questionnaire definitions. Startup is
idempotent and inserts no participants or example results. The new server starts with an empty study database.
Use the existing data only if a deliberate migration is needed; do not copy local study data into a fresh study
deployment unintentionally.

Confirm the start page, consent, both study modes, editor saves, chat streaming, test results, part-two handoff
and questionnaire submission in separate tabs. Confirm API session isolation and that normal test errors are
shown cleanly. Run a pilot with the real model configuration and inspect CPU/RAM before scheduling participants.
Set spending controls with the AI provider. Hosting charges and model usage are separate.

## 5. Database, exports and analysis

PostgreSQL tables and analysis views use the existing Alembic migrations. Both code artifacts and database rows
are necessary to reproduce a study session. Named volumes `postgres_data` and `study_data` persist across
container rebuilds and restarts. The Caddy volumes retain certificates. A normal update is:

```bash
bash deploy/backup.sh
# Update both repositories to their reviewed main commits, while no participant is working.
bash deploy/manage.sh --profile tools build
bash deploy/manage.sh up -d
```

Do not use `docker compose down --volumes` on study data. Changing the PostgreSQL password in the environment
does not change an already initialised database password; use a deliberate database password rotation.

Export from the deployed database into its private results directory:

```bash
bash deploy/manage.sh exec -T -w /data api python /app/export.py
bash deploy/manage.sh exec -T api python /app/analyze_results.py --input /data/results --output /data/results/analysis/study
```

For pilot-only output, add `--include-pilots` to export and `--pilots` to analysis, using an output directory such
as `/data/results/analysis/pilot`. Copy exports to a private local folder over SSH or `docker compose cp`; never
place them under the frontend's `/srv`. Export and analysis exclude `SYN` sample identifiers. The old sample
generator and generated sample reports are removed; automated test fixtures remain isolated from study data.
The labelled OWASP benchmark case material in `evaluation/` is separate technical evaluation and is not packaged
in the running application.

After an interrupted Finish request, run the private recovery command between participant sessions, after
in-flight final assessments have stopped:

```bash
bash deploy/manage.sh exec -T api python /app/assess_submissions.py
# Explicitly retry error/timeout assessments after fixing an infrastructure problem:
bash deploy/manage.sh exec -T api python /app/assess_submissions.py --retry-errors
```

It uses the original final snapshot and skips successful assessments. It does not reopen the participant's code
or change their answers. A nonzero `needs_attention` count includes invalid code, timeouts, unavailable runner
results or missing legacy snapshots; inspect those outcomes rather than interpreting them as passing tests.

## 6. Backup and restore

`bash deploy/backup.sh` briefly stops the API, writes a PostgreSQL custom-format dump and a compressed copy of
the workspace/snapshot/export volume, then restarts the API. Run it between participant sessions. By default
the files go into Git-ignored `backups/<UTC timestamp>/`; copy them off the VPS to private backup storage. This
also protects against deleting the VPS or losing its disk. Check the dump and archive before depending on them.

To restore a chosen backup on a prepared stack, stop the API, restore the database dump to the `study` database
using `pg_restore`, and restore `study-files.tar.gz` into the API's `/data` volume. Keep the matching application
commits. Only then start the API and verify readiness and a known workspace. Restore database and files together.

## 7. Troubleshooting

- Broker unhealthy: ensure the sandbox image was built, Docker is running, and `DOCKER_GID` matches the socket.
- API unhealthy: inspect its startup logs for missing settings, PostgreSQL connection or migration errors.
- HTTPS unavailable: check the A record, any existing AAAA record, and inbound 80/443. Use the exact `DOMAIN`.
- Tests unavailable: inspect broker logs. Production never silently substitutes local execution.
- Tight memory: inspect `docker stats`, reduce simultaneous sessions, or resize the VPS. Configured limits bound
  jobs, not overall application capacity. Default service limits plus a sandbox can approach a 2 GB machine's RAM.
- Restarts during consent: one API worker is required; pending, unconsented setup is memory-only.

Production access logs are disabled by default. Operational Docker logs are rotated and can contain errors and
security-state changes; handle them as study data. No synthetic data, local credentials, local database, code
workspaces or exports are included in either production image.
