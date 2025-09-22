#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/home/lab/softsec-tatou"
cd "$REPO_DIR"

# prevent overlapping runs
LOCK=/tmp/repo-sync.lock
exec 9>"$LOCK"
flock -n 9 || exit 0

prev=$(git rev-parse HEAD)
git fetch --all --prune
git reset --hard origin/21-automate-deployment # TODO change to origin/main
new=$(git rev-parse HEAD)

# nothing changed → exit
[[ "$prev" == "$new" ]] && exit 0

# files that should trigger a compose reload if updated
changed=$(git diff --name-only "$prev" "$new" || true)
if echo "$changed" | grep -qE \
'(^docker-compose\.ya?ml$|^compose\.prod\.ya?ml$|^grafana/|^db/tatou\.sql$|^Platform_specifications\.md$|^promtail|^loki|^README\.md$)'; then
  # Apply new compose/config. Use the prod overlay so server uses registry image.
  docker compose -f docker-compose.prod.yml up -d
fi

# optional: clean dangling images (watchtower also cleans if enabled)
docker image prune -f >/dev/null 2>&1 || true
