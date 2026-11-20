#!/usr/bin/env bash
set -euo pipefail
umask 077
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
destination="${1:-$root/backups}/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p -- "$destination"
compose=(bash "$root/deploy/manage.sh")
# Pause writes so database rows and code files describe the same backup point.
"${compose[@]}" stop api
trap '"${compose[@]}" up -d api' EXIT
"${compose[@]}" exec -T db pg_dump -U study -d study -Fc > "$destination/database.dump"
"${compose[@]}" run --rm --no-deps -T --entrypoint tar api -C /data -czf - . > "$destination/study-files.tar.gz"
git -C "$root" rev-parse HEAD > "$destination/backend-commit.txt"
printf 'Saved database and study files to %s\n' "$destination"
