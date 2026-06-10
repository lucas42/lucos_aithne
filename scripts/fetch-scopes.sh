#!/usr/bin/env bash
# fetch-scopes.sh — extract canonical scopes.yaml from the lucos_auth_scopes image.
#
# The image reference is single-sourced from the Dockerfile (the FROM … AS scopes
# line), so updating the digest in one place keeps build + local dev in sync.
#
# Usage:
#   ./scripts/fetch-scopes.sh           # from repo root
#   go generate ./...                   # via //go:generate directive in main.go
#
# The resulting scopes.yaml is gitignored; run this script (or go generate) before
# any local go build / go test invocation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKERFILE="$REPO_ROOT/Dockerfile"

# Single-source the pinned image reference from the Dockerfile.
# Matches: FROM lucas42/lucos_auth_scopes:<tag>@sha256:<digest> AS scopes
SCOPES_IMAGE=$(grep -E '^FROM lucas42/lucos_auth_scopes' "$DOCKERFILE" | awk '{print $2}')

if [[ -z "$SCOPES_IMAGE" ]]; then
  echo "fetch-scopes: ERROR — could not find 'FROM lucas42/lucos_auth_scopes' line in $DOCKERFILE" >&2
  exit 1
fi

echo "fetch-scopes: fetching scopes.yaml from $SCOPES_IMAGE"

# Pass a dummy command: FROM scratch images have no default CMD, so docker create
# requires one even though we never run the container — we only use docker cp.
CID=$(docker create "$SCOPES_IMAGE" /scopes.yaml)
docker cp "$CID:/scopes.yaml" "$REPO_ROOT/scopes.yaml"
docker rm "$CID" > /dev/null

echo "fetch-scopes: wrote $REPO_ROOT/scopes.yaml"
