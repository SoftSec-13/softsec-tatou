#!/usr/bin/env bash
set -euo pipefail

RETENTION_DAYS=7            # days to keep
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/docker-volumes}"
VOLUMES="${VOLUMES:-}"          # optional comma‑separated allowlist
TS="$(date +%Y%m%d-%H%M%S)"

mkdir -p "$BACKUP_ROOT"

if [ -z "$VOLUMES" ]; then
  mapfile -t VOL_LIST < <(docker volume ls -q)
else
  IFS=',' read -r -a VOL_LIST <<< "$VOLUMES"
fi

for vol in "${VOL_LIST[@]}"; do
  [ -z "$vol" ] && continue
  out_dir="$BACKUP_ROOT/$vol"
  mkdir -p "$out_dir"
  archive="$out_dir/${vol}-${TS}.tar.gz"
  echo "[INFO] $(date -Is) Backing up $vol -> $archive"
  # Use lightweight alpine image; create gzip compressed tar
  docker run --rm \
    -v "${vol}":/src:ro \
    -v "$out_dir":/dst \
    alpine:3.20 \
    sh -c "cd /src && tar -czf /dst/$(basename "$archive") ."
done

# Prune old
find "$BACKUP_ROOT" -type f -name '*.tar.gz' -mtime +"$RETENTION_DAYS" -print -delete
echo "[INFO] $(date -Is) Done"
