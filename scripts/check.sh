#!/usr/bin/env bash

set -uo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

failures=0

run_check() {
  local name="$1"
  shift
  if "$@"; then
    echo "PASS: $name"
  else
    echo "FAIL: $name" >&2
    failures=$((failures + 1))
  fi
}

verify_fingerprint() {
  local expected actual
  expected="$(tr -d '[:space:]' < examples/gateway-valid.sha256)"
  actual="$(uv run --frozen --all-extras rangespec fingerprint examples/gateway-valid.json)"
  [[ "$actual" == "$expected" ]]
}

verify_github_action() {
  local action_output action_log action_workspace escape_log escape_workspace expected actual
  action_output="$build_directory/action-output"
  action_log="$build_directory/action-log"
  action_workspace="$build_directory/action-workspace"
  expected="$(tr -d '[:space:]' < examples/gateway-valid.sha256)"
  mkdir -p "$action_workspace/range"
  cp examples/gateway-valid.json "$action_workspace/range/authorized-test.json"

  GITHUB_ACTION_PATH="$project_root" \
  GITHUB_WORKSPACE="$action_workspace" \
  GITHUB_OUTPUT="$action_output" \
  RANGESPEC_INPUT_MANIFEST="range/authorized-test.json" \
  RANGESPEC_INPUT_EXECUTION_READY="true" \
  RANGESPEC_INPUT_AT="2026-10-08T20:00:00Z" \
    ./scripts/github-action.sh >"$action_log"

  actual="$(sed -n 's/^fingerprint=//p' "$action_output")"
  [[ "$actual" == "$expected" ]] || return 1
  grep -Fq "VALID execution-ready" "$action_log" || return 1
  grep -Fq "RANGESPEC_FINGERPRINT: $expected" "$action_log" || return 1

  escape_workspace="$build_directory/escape-workspace"
  escape_log="$build_directory/escape-log"
  mkdir -p "$escape_workspace"
  ln -s "$project_root/examples/gateway-valid.json" "$escape_workspace/outside.json"
  if GITHUB_ACTION_PATH="$project_root" \
    GITHUB_WORKSPACE="$escape_workspace" \
    GITHUB_OUTPUT="$action_output" \
    RANGESPEC_INPUT_MANIFEST="outside.json" \
    RANGESPEC_INPUT_EXECUTION_READY="false" \
    RANGESPEC_INPUT_AT="" \
      ./scripts/github-action.sh >"$escape_log" 2>&1; then
    return 1
  fi
  grep -Fq "must remain inside" "$escape_log"
}

verify_action_metadata() {
  bash -n scripts/github-action.sh || return 1
  grep -Fq "using: composite" action.yml || return 1
  grep -Fq "permissions:" examples/workflows/rangespec.yml || return 1
  grep -Fq "contents: read" examples/workflows/rangespec.yml
}

verify_built_package() {
  local wheel virtual_environment
  wheel="$(find "$build_directory" -maxdepth 1 -name '*.whl' -print -quit)"
  [[ -n "$wheel" ]] || return 1
  virtual_environment="$build_directory/installed"
  uv venv --python 3.13 "$virtual_environment" >/dev/null
  uv pip install --python "$virtual_environment/bin/python" "$wheel" >/dev/null
  "$virtual_environment/bin/rangespec" schema >/dev/null
  "$virtual_environment/bin/rangespec" validate \
    examples/gateway-valid.json \
    --execution-ready \
    --at 2026-10-08T20:00:00Z >/dev/null
}

run_check "lockfile is current" uv lock --check
run_check "environment sync" uv sync --frozen --all-extras --dev
run_check "format" uv run --frozen --all-extras ruff format --check .
run_check "lint" uv run --frozen --all-extras ruff check .
run_check "types" uv run --frozen --all-extras mypy
run_check "tests" uv run --frozen --all-extras pytest

build_directory="$(mktemp -d)"
cleanup() {
  rm -rf "$build_directory"
}
trap cleanup EXIT
run_check "package build" uv build --out-dir "$build_directory"
run_check "installed wheel" verify_built_package
run_check "stable example fingerprint" verify_fingerprint
run_check "GitHub Action metadata" verify_action_metadata
run_check "GitHub Action entrypoint" verify_github_action

run_check \
  "execution-ready example" \
  uv run --frozen --all-extras rangespec validate \
    examples/gateway-valid.json \
    --execution-ready \
    --at 2026-10-08T20:00:00Z
run_check \
  "local advisory example" \
  uv run --frozen --all-extras rangespec review \
    examples/gateway-valid.json \
    --provider local

if [[ "$failures" -ne 0 ]]; then
  echo "RangeSpec verification failed: $failures check(s) failed." >&2
  exit 1
fi

echo "RangeSpec verification passed."
