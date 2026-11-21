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

## 8. Manual CD through GitHub Actions

The backend repository owns one **Deploy production** workflow for both repositories. It runs only when
started from the Actions tab on `main`; a merge does not deploy automatically. Run it between participant
sessions. The initial server setup above, a working HTTPS hostname, and the private `.env.production` file
are prerequisites. This version targets the existing x86-64 Ubuntu VPS and uses a dedicated root SSH key.

The workflow selects the backend commit and the frontend's `main` commit once. It requires successful
push-to-main CI runs for those exact commits, builds all four images on GitHub, and transfers their compressed
Docker archive and a checksum/config-digest manifest over SSH. There is no registry account or token to configure.
The 2 GB VPS loads the images; it does not compile the frontend during CD.

Image verification compares the SHA-256 of the saved image configuration, which includes the layer identities,
and requires `linux/amd64`. Docker's classic image store and containerd store can report different `.Id` values
for the same image, so those store-specific IDs are retained for diagnostics rather than compared across hosts.
The server streams a fresh export of the loaded tags to verify their configurations before maintenance starts;
it does not keep another archive in memory or on disk. The uploaded archive checksum is also checked.
After changing the release helper, start a new workflow on the merged `main` commit. Re-running an older
workflow uses its older helper and manifest format.

The selector authenticates GitHub API lookups with the automatic `GITHUB_TOKEN`, including public frontend
lookups, to avoid the smaller anonymous rate limit shared by a runner's network address. Temporary network
and server errors have bounded retries; HTTP errors report the endpoint and status without exposing tokens
or response bodies. Rate-limit failures are not retried before the server's reset/delay.

If GitHub denies cross-repository access, add an optional backend **repository secret** named
`FRONTEND_READ_TOKEN`: a fine-grained token restricted to the frontend repository with **Contents: read**
and **Actions: read**. It is used only for frontend metadata/CI reads. This is a repository secret because
the selection job runs before the production environment; the four production SSH secrets remain unchanged.

### Configure deployment access once

In the backend repository, create **Settings → Environments → production**. Under deployment branches,
select **Selected branches and tags** and allow the branch **main** only. Keep deployment secrets in that
environment, not in workflow source. A required reviewer is optional; manual dispatch already gives control
over release timing. If working alone, do not enable Prevent self-review alongside a required self-approval.

Generate a dedicated deployment key on your laptop, using a new filename:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/secure_coding_room_actions -C "secure-coding-room-actions" -N ""
```

If that filename already exists, keep it and choose another filename. Add the new public `.pub` key as a
separate line in the server's `/root/.ssh/authorized_keys`, keeping the existing login key. An authorized-key
`restrict` option can disable forwarding and PTY access while allowing the noninteractive deployment commands.
The key grants administrative access to this VPS: use it only for this deployment and keep the environment
restricted to `main`. Do not replace or reuse your ordinary laptop login key.

Add these four **environment secrets**:

| Secret | Value |
| --- | --- |
| `DEPLOY_HOST` | Droplet's public IPv4 or SSH hostname, without a scheme |
| `DEPLOY_USER` | `root` for this server setup |
| `DEPLOY_SSH_KEY` | Contents of the new private key, copied directly into GitHub's secret editor |
| `DEPLOY_KNOWN_HOSTS` | Verified server host-key line: `SERVER_IP ssh-ed25519 PUBLIC_HOST_KEY` |

Obtain the server's public host key through your existing trusted SSH session or the DigitalOcean console:

```bash
cat /etc/ssh/ssh_host_ed25519_key.pub
```

Use its key type and public key after the server IP in `DEPLOY_KNOWN_HOSTS`. This is the server host key,
separate from the new deployment login key. Host verification is enforced; the workflow does not trust a
fresh network key scan or disable host checking. The example uses SSH port 22. GitHub-hosted runners must be
able to reach it; an IP-restricted firewall needs an appropriate runner/network arrangement first.

The server needs Docker/Compose, Git, Python 3.11+, curl, gzip and systemd. Ubuntu 24.04 supplies the system
Python; no extra Python packages are needed by the release helper. Model keys, database passwords and runner
tokens remain in the server's `.env.production`. They are not transferred to GitHub for deployment.

### Release and inspect the result

After merging the CD PR and waiting for both repositories' main CI runs to pass, open the backend repository's
**Actions → Deploy production → Run workflow**, selecting `main`. One workflow builds and releases the pair;
there is no second frontend deployment button. Concurrent deployments are queued rather than cancelled.

The server job runs under systemd and takes a host lock, so losing the SSH connection does not terminate it
or allow another release to run concurrently. Cancelling the GitHub run also leaves an already launched
server job running; inspect its recorded state before starting another release. It checks tracked files are unchanged, loads and verifies the
images before downtime, stops frontend/API/runner, ends their disposable test jobs, and backs up PostgreSQL
and `/data`. PostgreSQL stays running. The backup contains the prior commits, Compose configuration, image
IDs/tags and migration revision. Both backup archives are checked before application code is switched.

The checkouts move to the selected detached commits. An ignored `.release.env` records the selected image
tags and commits; `deploy/manage.sh` reads it after `.env.production`. Production credentials are preserved.
The selected test image is tagged as `secure-coding-room-tests:local` before the runner starts, so the required
image is always included. Services start with `--no-build --pull never`; ordinary releases retain all named
volumes and do not update PostgreSQL's major version.

Success requires healthy services, an actual isolated pytest smoke run, the HTTPS frontend, and `/api/ready`.
The GitHub run summary records the deployed pair and URL. Private server details are stored under:

```text
/opt/secure-coding-room/incoming/RUN_ID-ATTEMPT/state.json
/opt/secure-coding-room/incoming/RUN_ID-ATTEMPT/deployment.log
/opt/secure-coding-room/backend/backups/release-RUN_ID-ATTEMPT/
```

### Failure and recovery

A preflight or image-loading failure leaves the current application running. Once maintenance has started,
a failure stops the application services and keeps the database, backup and previous images. It never deletes
study volumes, resets a Git checkout over tracked edits, automatically downgrades a schema, or starts old code
against a possibly upgraded database. An incomplete backup has no `BACKUP_COMPLETE` marker.

Inspect the recorded stage and private log before retrying. If returning to an earlier release, use
`previous.json` and the saved Compose/release settings with the matching database/files backup described in
section 6. Database/file restoration is an explicit administrative operation; it is not attempted automatically.
Keep backup copies in private off-server storage. Do not prune previous images or remove incoming archives
until recovery is no longer needed; these files use server disk space and are not automatically deleted.

Source: [GitHub manual workflows](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow),
[deployment environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).
