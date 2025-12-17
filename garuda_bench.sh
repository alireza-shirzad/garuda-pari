#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_PATH="$ROOT_DIR/garuda-bench/Cargo.toml"

BASE_FEATURES="${BASE_FEATURES:-}"
GARUDA_FEATURE="${GARUDA_FEATURE:-gr1cs}"

case "$GARUDA_FEATURE" in
  gr1cs|r1cs) ;;
  *)
    echo "GARUDA_FEATURE must be \"gr1cs\" or \"r1cs\" (got: $GARUDA_FEATURE)" >&2
    exit 1
    ;;
esac

join_features() {
  local extra="${1:-}"

  if [[ -n "$BASE_FEATURES" && -n "$extra" ]]; then
    echo "${BASE_FEATURES},${extra}"
  elif [[ -n "$BASE_FEATURES" ]]; then
    echo "${BASE_FEATURES}"
  else
    echo "${extra}"
  fi
}

run_bench() {
  local bench="$1"
  local extra_features="${2:-}"
  local features
  features="$(join_features "$extra_features")"

  if [[ -n "$features" ]]; then
    echo "Running ${bench} (features: ${features})"
    RAYON_NUM_THREADS=1 cargo bench --manifest-path "$MANIFEST_PATH" --bench "$bench" --features "$features"
  else
    echo "Running ${bench}"
    RAYON_NUM_THREADS=1 cargo bench --manifest-path "$MANIFEST_PATH" --bench "$bench"
  fi
}

common_benches=(
  aadhaar-garuda
  aadhaar-spartan
  aadhaar-groth16
  random-garuda
  random-garuda-addition
  random-spartan
  random-spartan-ccs
  random-spartan-ccs-addition
  random-spartan-addition
  aptos-garuda
  aptos-groth16
  aptos-spartan
  rescue-hyperplonk
)

gr1cs_benches=(
  random-garuda-gr1cs
  random-garuda-gr1cs-addition
  rescue-spartan-ccs
  rescue-spartan-nizk-ccs
)

r1cs_benches=(
  rescue-spartan-r1cs
  rescue-spartan-nizk-r1cs
)

for bench in "${common_benches[@]}"; do
  run_bench "$bench"
done

run_bench "rescue-garuda" "$GARUDA_FEATURE"

for bench in "${gr1cs_benches[@]}"; do
  run_bench "$bench" "gr1cs"
done

for bench in "${r1cs_benches[@]}"; do
  run_bench "$bench" "r1cs"
done
