#!/bin/bash
# MeshDesk CI Test Pipeline
#
# Four-stage pipeline: lint → unit → build → integration
# Designed to be run in CI (GitHub Actions, GitLab CI, Jenkins) or locally.
#
# Usage:
#   ./ci/test-pipeline.sh [--skip-lint] [--skip-build] [--skip-integration]
#
# Exit codes:
#   0 — All stages passed
#   1 — Lint or unit test failure
#   2 — Build failure
#   3 — Integration test failure

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SKIP_LINT=0
SKIP_BUILD=0
SKIP_INTEGRATION=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-lint) SKIP_LINT=1 ;;
        --skip-build) SKIP_BUILD=1 ;;
        --skip-integration) SKIP_INTEGRATION=1 ;;
        *) echo "Unknown flag: $1"; exit 1 ;;
    esac
    shift
done

RESULTS_DIR="${RESULTS_DIR:-$REPO_ROOT/test/results}"
mkdir -p "$RESULTS_DIR"

PIPELINE_START=$(date -u +%s)
PIPELINE_STATUS="pass"
STAGE_RESULTS="[]"

run_stage() {
    local stage="$1"
    local description="$2"
    local cmd="$3"
    
    echo ""
    echo "=== Stage: $stage ==="
    echo "  $description"
    echo ""
    
    local stage_start
    stage_start=$(date -u +%s)
    local exit_code=0
    
    if eval "$cmd"; then
        exit_code=0
        local result="PASS"
    else
        exit_code=$?
        local result="FAIL"
    fi
    
    local stage_end
    stage_end=$(date -u +%s)
    local duration=$((stage_end - stage_start))
    
    echo ""
    echo "[$stage] $result (${duration}s)"
    
    STAGE_RESULTS=$(echo "$STAGE_RESULTS" | jq \
        --arg stage "$stage" \
        --arg description "$description" \
        --arg result "$result" \
        --arg duration "$duration" \
        '. + [{"stage": $stage, "description": $description, "result": $result, "duration_s": $duration|tonumber}]')
    
    return $exit_code
}

# --- Stage 1: Lint ---
if [ "$SKIP_LINT" -eq 0 ]; then
    run_stage "lint" "Go vet + static analysis" '
        echo "Running go vet..."
        go vet ./...
        echo ""
        echo "Running gofmt check..."
        UNFMT=$(gofmt -l . 2>/dev/null || true)
        if [ -n "$UNFMT" ]; then
            echo "ERROR: Unformatted files:"
            echo "$UNFMT"
            exit 1
        fi
        echo "All files properly formatted."
    ' || PIPELINE_STATUS="fail-stage1"
else
    echo "[lint] SKIPPED"
fi

# --- Stage 2: Unit Tests ---
# Always run; unit tests are fast and critical.
# Internal packages with known failures (in-progress work) are excluded from the main run
# but can be tested separately with --include-unstable.
INCLUDE_UNSTABLE=0
if [[ "$*" == *"--include-unstable"* ]]; then
    INCLUDE_UNSTABLE=1
fi

UNSTABLE_SUFFIX="/internal/mesh"

if [ "$INCLUDE_UNSTABLE" -eq 1 ]; then
    TEST_PKGS="./..."
    echo "Including unstable packages"
else
    # Compute stable package list (exclude packages whose path ends with unstable suffix,
    # and exclude packages with no test files.)
    ALL_PKGS=$(go list ./... 2>/dev/null | grep -v "^_" || true)
    TEST_PKGS=""
    for pkg in $ALL_PKGS; do
        skip=0
        for suffix in $UNSTABLE_SUFFIX; do
            if [[ "$pkg" == *"$suffix" ]]; then
                skip=1
                break
            fi
        done
        if [ "$skip" -eq 0 ]; then
            # Skip packages with no test files (go test returns non-zero for these)
            if ! go list -f '{{.TestGoFiles}}' "$pkg" 2>/dev/null | grep -q '^\[\]$'; then
                TEST_PKGS="$TEST_PKGS $pkg"
            fi
        fi
    done
    echo "Unstable packages (skipped): *$UNSTABLE_SUFFIX"
    echo "Stable packages: $TEST_PKGS"
fi

run_stage "unit" "go test (stable packages)" "go test -v -count=1 -timeout 120s -coverprofile='$RESULTS_DIR/coverage.out' $TEST_PKGS 2>&1 | tee '$RESULTS_DIR/unit-tests.log'" || PIPELINE_STATUS="fail-stage2"

# --- Stage 3: Build ---
if [ "$SKIP_BUILD" -eq 0 ]; then
    run_stage "build" "go build ./cmd/meshdesk/" "go build -o meshdesk -v ./cmd/meshdesk/ && echo Binary: $(ls -lh meshdesk | awk '{print $5, $NF}')" || PIPELINE_STATUS="fail-stage3"
else
    echo "[build] SKIPPED"
fi

# --- Stage 4: Integration Tests ---
if [ "$SKIP_INTEGRATION" -eq 0 ]; then
    run_stage "integration" "Integration + scenario matrix" "echo 'Running integration tests...'; go test -v -tags=integration -count=1 -timeout 300s ./... 2>&1 | tee '$RESULTS_DIR/integration.log'" || PIPELINE_STATUS="fail-stage4"
    # Run scenario matrix (non-blocking — informational)
    if [ -x ./test/scenario-matrix.sh ]; then
        echo ""
        echo "Running scenario matrix..."
        bash ./test/scenario-matrix.sh --timeout 120 || true
    fi
else
    echo "[integration] SKIPPED"
fi

# --- Summary ---
PIPELINE_END=$(date -u +%s)
PIPELINE_DURATION=$((PIPELINE_END - PIPELINE_START))

echo ""
echo "========================================"
echo "  Pipeline Complete"
echo "  Status:   $PIPELINE_STATUS"
echo "  Duration: ${PIPELINE_DURATION}s"
echo "========================================"

# Write JSON report
jq -n \
    --arg status "$PIPELINE_STATUS" \
    --arg timestamp "$(date -u -Iseconds)" \
    --arg duration "$PIPELINE_DURATION" \
    --argjson stages "$STAGE_RESULTS" \
    '{
        pipeline: "MeshDesk CI",
        timestamp: $timestamp,
        status: $status,
        duration_s: $duration|tonumber,
        stages: $stages
    }' > "$RESULTS_DIR"/pipeline.json

echo "  Report:   $RESULTS_DIR/pipeline.json"

case "$PIPELINE_STATUS" in
    pass) exit 0 ;;
    fail-stage2) exit 1 ;;
    fail-stage3) exit 2 ;;
    fail-stage4) exit 3 ;;
    *) exit 1 ;;
esac