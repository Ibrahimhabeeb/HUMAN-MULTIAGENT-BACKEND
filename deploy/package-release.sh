#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
backend_sha="${1:?Backend commit required}"
frontend_sha="${2:?Frontend commit required}"
frontend="${3:?Frontend source directory required}"
destination="${4:?Release directory required}"
[[ "$backend_sha" =~ ^[0-9a-f]{40}$ && "$frontend_sha" =~ ^[0-9a-f]{40}$ ]] || exit 1
umask 077
mkdir -p -- "$destination"

# Build on GitHub; the small production server only loads the finished images.
docker build --platform linux/amd64 -t "secure-coding-room-api:$backend_sha" -f "$root/Dockerfile" "$root"
docker build --platform linux/amd64 -t "secure-coding-room-runner:$backend_sha" -f "$root/deploy/Dockerfile.runner" "$root"
docker build --platform linux/amd64 -t "secure-coding-room-tests:$backend_sha" -f "$root/deploy/Dockerfile.tests" "$root"
docker build --platform linux/amd64 -t "secure-coding-room-frontend:$frontend_sha" "$frontend"
docker save "secure-coding-room-api:$backend_sha" "secure-coding-room-runner:$backend_sha" \
  "secure-coding-room-tests:$backend_sha" "secure-coding-room-frontend:$frontend_sha" \
  | gzip -1 > "$destination/images.tar.gz"
python3 "$root/deploy/deploy_release.py" manifest "$destination" "$backend_sha" "$frontend_sha"
cp -- "$root/deploy/deploy_release.py" "$destination/deploy_release.py"
