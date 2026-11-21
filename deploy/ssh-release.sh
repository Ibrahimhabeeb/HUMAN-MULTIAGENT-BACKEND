#!/usr/bin/env bash
set -euo pipefail
destination="${1:?Release directory required}"
: "${DEPLOY_HOST:?Set the production DEPLOY_HOST secret}"
: "${DEPLOY_USER:?Set the production DEPLOY_USER secret}"
: "${DEPLOY_SSH_KEY:?Set the production DEPLOY_SSH_KEY secret}"
: "${DEPLOY_KNOWN_HOSTS:?Set the verified DEPLOY_KNOWN_HOSTS secret}"
: "${BACKEND_SHA:?Backend commit required}"
: "${FRONTEND_SHA:?Frontend commit required}"
[[ "$DEPLOY_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || exit 1
[[ "$DEPLOY_USER" == root ]] || { echo 'This deployment requires the root account on the study VPS.' >&2; exit 1; }
[[ "$BACKEND_SHA" =~ ^[0-9a-f]{40}$ && "$FRONTEND_SHA" =~ ^[0-9a-f]{40}$ ]] || exit 1
release_id="${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
[[ "$release_id" =~ ^[0-9]+-[0-9]+$ ]] || exit 1
incoming="/opt/secure-coding-room/incoming/$release_id"
unit="secure-coding-room-release-$release_id"
umask 077
ssh_directory="$(mktemp -d "${RUNNER_TEMP:?}/secure-coding-room-ssh.XXXXXX")"
trap 'rm -f -- "$ssh_directory/key" "$ssh_directory/known_hosts"; rmdir -- "$ssh_directory"' EXIT
printf '%s\n' "$DEPLOY_SSH_KEY" > "$ssh_directory/key"
printf '%s\n' "$DEPLOY_KNOWN_HOSTS" > "$ssh_directory/known_hosts"
ssh-keygen -y -P '' -f "$ssh_directory/key" > /dev/null
options=(-i "$ssh_directory/key" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes
  -o "UserKnownHostsFile=$ssh_directory/known_hosts" -o ConnectTimeout=15
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3)
server="$DEPLOY_USER@$DEPLOY_HOST"
ssh "${options[@]}" "$server" "mkdir -p -m 700 '$incoming'"
scp "${options[@]}" "$destination/images.tar.gz" "$destination/manifest.json" \
  "$destination/deploy_release.py" "$server:$incoming/"
# systemd owns this job, so disconnecting the SSH session does not terminate deployment.
ssh "${options[@]}" "$server" "systemd-run --unit='$unit' --property=Type=exec --property=RuntimeMaxSec=20min /usr/bin/python3 '$incoming/deploy_release.py' deploy '$incoming' '$BACKEND_SHA' '$FRONTEND_SHA'"
for ((attempt=0; attempt<240; attempt++)); do
  state="$(ssh "${options[@]}" "$server" "if systemctl is-failed --quiet '$unit'; then printf failed; else python3 '$incoming/deploy_release.py' status '$incoming'; fi" || true)"
  case "$state" in
    complete)
      site="$(ssh "${options[@]}" "$server" "python3 '$incoming/deploy_release.py' site '$incoming'")"
      curl --fail --silent --show-error --max-time 20 --retry 5 --retry-delay 5 --retry-all-errors "$site/api/ready"
      printf '\nDeployed backend %s and frontend %s\n' "$BACKEND_SHA" "$FRONTEND_SHA"
      printf '### Production release\n\nBackend: `%s`\n\nFrontend: `%s`\n\nSite: %s\n' \
        "$BACKEND_SHA" "$FRONTEND_SHA" "$site" >> "${GITHUB_STEP_SUMMARY:?}"
      exit 0 ;;
    failed)
      echo "Deployment failed. On the server, inspect $incoming/state.json and $incoming/deployment.log. Backups are retained." >&2
      exit 1 ;;
  esac
  sleep 5
done
echo "Stopped waiting. Check systemctl status $unit and $incoming/state.json before starting another release." >&2
exit 1
