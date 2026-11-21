#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
settings=(--env-file "$root/.env.production")
if [[ -f "$root/.release.env" ]]; then
  settings+=(--env-file "$root/.release.env")
fi
exec docker compose --parallel 1 --project-directory "$root" "${settings[@]}" -f "$root/compose.yaml" "$@"
