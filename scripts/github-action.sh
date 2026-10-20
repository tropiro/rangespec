#!/usr/bin/env bash

# GitHub Action boundary for repository-owned RangeSpec manifests. This script
# intentionally performs validation and fingerprinting only; it cannot execute
# target actions or contact a model provider.

set -euo pipefail

fail() {
  echo "RANGESPEC_ACTION_ERROR: $1" >&2
  exit 1
}

action_root="${GITHUB_ACTION_PATH:?GITHUB_ACTION_PATH is required}"
workspace="${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
output_file="${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
manifest_input="${RANGESPEC_INPUT_MANIFEST:-}"
execution_ready="${RANGESPEC_INPUT_EXECUTION_READY:-false}"
evaluation_time="${RANGESPEC_INPUT_AT:-}"

[[ -n "$manifest_input" ]] || fail "The manifest input is required."
[[ "$manifest_input" != /* ]] || fail "The manifest path must be relative to the repository."
[[ "$execution_ready" == "true" || "$execution_ready" == "false" ]] || \
  fail "execution-ready must be either true or false."

workspace="$(cd "$workspace" && pwd -P)"
manifest_candidate="$workspace/$manifest_input"
[[ -f "$manifest_candidate" ]] || fail "The manifest file does not exist."
manifest="$(realpath "$manifest_candidate")"

case "$manifest" in
  "$workspace"/*) ;;
  *) fail "The manifest must remain inside the checked-out repository." ;;
esac

validate=(
  uv run --frozen --project "$action_root" rangespec validate "$manifest"
)

if [[ "$execution_ready" == "true" ]]; then
  validate+=(--execution-ready)
fi

if [[ -n "$evaluation_time" ]]; then
  validate+=(--at "$evaluation_time")
fi

"${validate[@]}"
fingerprint="$(
  uv run --frozen --project "$action_root" rangespec fingerprint "$manifest"
)"

[[ "$fingerprint" =~ ^[0-9a-f]{64}$ ]] || fail "RangeSpec returned an invalid fingerprint."
echo "fingerprint=$fingerprint" >> "$output_file"
echo "RANGESPEC_FINGERPRINT: $fingerprint"
