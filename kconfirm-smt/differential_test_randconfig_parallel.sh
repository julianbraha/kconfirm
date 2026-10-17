#!/usr/bin/env bash
# Differential test 2: is the model over-constrained?
#
# Every configuration generated Linux' randconfig is checked
# against the SMT model. All outputs are preserved:
# - generated configurations
# - seeds
# - randconfig output
# - kconfirm-smt output
# - SAT/UNSAT status
# - base SMT model and evaluated macros (generated once per invocation)
#   saved as differential-results/model.smt2 and differential-results/macros.txt
#
# usage (from kconfirm-smt/):
#   bash generate_random_seeds.sh 2000 > random-seeds.txt
#   JOBS=4 bash differential_test_randconfig_parallel.sh [RUNS] [SEEDS_FILE] [SOLVER_TIMEOUT_MS]
#
# Uses the first RUNS seeds in file order, including duplicates.
# Defaults: RUNS=1000, SEEDS_FILE=random-seeds.txt (or $SEEDS_FILE),
# JOBS=4, SOLVER_TIMEOUT_MS=0 (no timeout). Each worker owns an isolated
# Kbuild output directory, reused across its assigned iterations.
#
# environment:
#   LINUX   kernel source tree      (default: evaluation/linux-randconfig)
#   BINARY  kconfirm-smt binary     (default: ../target/release/kconfirm-smt relative to this script)
#   ARCH    architecture to test    (default: x86_64)

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || exit 2

LINUX="${LINUX:-evaluation/linux-randconfig}"
BINARY="${BINARY:-$SCRIPT_DIR/../target/release/kconfirm-smt}"
ARCH="${ARCH:-x86_64}"

RUNS="${1:-1000}"
SEEDS_FILE="${2:-${SEEDS_FILE:-random-seeds.txt}}"
SOLVER_TIMEOUT_MS="${3:-${SOLVER_TIMEOUT_MS:-0}}"
JOBS="${JOBS:-4}"

# Load once so both directions can reuse exactly the same recorded seed list.
if [ "$#" -gt 3 ]; then
    echo "usage: $0 [RUNS] [SEEDS_FILE] [SOLVER_TIMEOUT_MS]" >&2
    exit 2
fi
if [[ ! "$JOBS" =~ ^[1-9][0-9]*$ ]] || (( ${#JOBS} > 8 )); then
    echo "error: JOBS must be a positive integer" >&2
    exit 2
fi
if [ ! -f "$SEEDS_FILE" ] || [ ! -r "$SEEDS_FILE" ]; then
    echo "error: seed file not readable: $SEEDS_FILE (generate it with generate_random_seeds.sh)" >&2
    exit 2
fi
if ! mapfile -t seeds < "$SEEDS_FILE"; then
    echo "error: failed to read seed file: $SEEDS_FILE" >&2
    exit 2
fi
seed_count="${#seeds[@]}"
if [ "$seed_count" -eq 0 ]; then
    echo "error: seed file is empty: $SEEDS_FILE" >&2
    exit 2
fi
if [[ ! "$RUNS" =~ ^[1-9][0-9]*$ ]] ||
   (( ${#RUNS} > ${#seed_count} )) || (( RUNS > seed_count )); then
    echo "error: RUNS must be between 1 and $seed_count (seeds available in $SEEDS_FILE)" >&2
    exit 2
fi
for index in "${!seeds[@]}"; do
    seed="${seeds[index]}"
    if [[ ! "$seed" =~ ^(0|[1-9][0-9]{0,9})$ ]] || (( seed > 4294967295 )); then
        echo "error: $SEEDS_FILE:$((index + 1)): expected a decimal seed in 0..4294967295" >&2
        exit 2
    fi
done

if [ ! -x "$BINARY" ]; then
    echo "error: kconfirm-smt binary not found at $BINARY (build it, or set BINARY=)" >&2
    exit 2
fi

# A fresh kernel checkout needs the lexer and parser generators to build conf.
# Fail before cloning Linux or exporting a model when the tools are missing.
missing_tools=()
for tool in make flex bison; do
    command -v "$tool" >/dev/null 2>&1 || missing_tools+=("$tool")
done
if [ "${#missing_tools[@]}" -ne 0 ]; then
    echo "error: required commands not found: ${missing_tools[*]}" >&2
    echo "Enter the project's development shell with 'nix develop', or install the missing tools." >&2
    exit 2
fi

LINUX_REPO="git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
LINUX_BRANCH="v7.2.10"

RESULTS_DIR="${RESULTS_DIR:-differential-results}"
ITERATIONS_DIR="$RESULTS_DIR/iterations"
FAILURES_DIR="$RESULTS_DIR/failures"
WORKERS_DIR="$RESULTS_DIR/workers"
MODEL_FILE="$RESULTS_DIR/model.smt2"
PREPROC_FILE="$RESULTS_DIR/macros.txt"

# Clone Linux v7.2.10 if missing
if [ ! -d "$LINUX/.git" ]; then
    echo "Linux source tree not found at $LINUX"
    echo "Cloning Linux $LINUX_BRANCH..."

    mkdir -p "$(dirname "$LINUX")"

    git clone \
        --depth 1 \
        --branch "$LINUX_BRANCH" \
        "$LINUX_REPO" \
        "$LINUX"

    if [ $? -ne 0 ]; then
        echo "error: failed to clone Linux $LINUX_BRANCH" >&2
        exit 2
    fi
fi


LINUX="$(realpath "$LINUX")" || exit 2
BINARY="$(realpath "$BINARY")" || exit 2
mkdir -p "$ITERATIONS_DIR" "$FAILURES_DIR" "$WORKERS_DIR" || exit 2
RESULTS_DIR="$(realpath "$RESULTS_DIR")" || exit 2
ITERATIONS_DIR="$RESULTS_DIR/iterations"
FAILURES_DIR="$RESULTS_DIR/failures"
WORKERS_DIR="$RESULTS_DIR/workers"
MODEL_FILE="$RESULTS_DIR/model.smt2"
PREPROC_FILE="$RESULTS_DIR/macros.txt"

printf '%s\n' "${seeds[@]:0:RUNS}" > "$RESULTS_DIR/seeds.txt" || exit 2


#
# Save metadata
#
{
    echo "differential testing evaluation"
    echo "date: $(date -Iseconds)"
    echo

    echo "linux:"
    echo "$LINUX"

    echo "linux branch:"
    echo "$LINUX_BRANCH"

    echo "linux commit:"
    git -C "$LINUX" rev-parse HEAD 2>/dev/null || echo "unknown"

    echo
    echo "binary:"
    echo "$BINARY"

    echo "arch:"
    echo "$ARCH"

    echo "runs:"
    echo "$RUNS"
    echo "workers: $JOBS"
    echo "solver timeout ms: $SOLVER_TIMEOUT_MS"

    echo "seed source: $SEEDS_FILE"
    echo "selected seeds: $RESULTS_DIR/seeds.txt"
    echo "model constraints: $MODEL_FILE"
    echo "preprocessed macros: $PREPROC_FILE"

    echo
    echo "compiler:"
    cc --version 2>/dev/null || true

    echo
    echo "environment:"
    env | sort

} > "$RESULTS_DIR/metadata.txt"

# Build once per invocation, so prior results cannot supply a stale model.
if ! ARCH="$ARCH" "$BINARY" \
    --linux "$LINUX" \
    --output-smt-lib "$MODEL_FILE" \
    --solver-timeout-ms "$SOLVER_TIMEOUT_MS" \
    --dump-preproc "$PREPROC_FILE" \
    > "$RESULTS_DIR/model.log" 2>&1 || [ ! -s "$MODEL_FILE" ] || [ ! -s "$PREPROC_FILE" ]; then
    echo "error: model generation failed; see $RESULTS_DIR/model.log" >&2
    exit 2
fi
if grep -Eq 'Preprocessed macros: [0-9]+ evaluated, [1-9][0-9]* unresolved' "$RESULTS_DIR/model.log"; then
    echo "error: model has unresolved macros; see $RESULTS_DIR/model.log" >&2
    exit 2
fi


# Clear selected statuses before launching workers so interrupted runs cannot
# inherit successful results from an earlier invocation in this directory.
for ((i = 1; i <= RUNS; i++)); do
    iteration_name=$(printf '%06d-seed%s' "$i" "${seeds[i - 1]}")
    iteration_dir="$ITERATIONS_DIR/$iteration_name"
    mkdir -p "$iteration_dir" || exit 2
    rm -f "$iteration_dir/status.txt" "$iteration_dir/randconfig.config" \
        "$iteration_dir/runtime.txt" || exit 2
done

worker() {
    local worker_id="$1"
    local build_dir="$WORKERS_DIR/worker-$worker_id/build"
    local i seed iteration_name iteration_dir cfg randconfig_status model_status
    local start_ns end_ns
    local status kept

    mkdir -p "$build_dir" || return 1

    # Static round-robin assignment guarantees unique worker ownership of O=.
    for ((i = worker_id; i <= RUNS; i += JOBS)); do
        seed="${seeds[i - 1]}"
        iteration_name=$(printf '%06d-seed%s' "$i" "$seed")
        iteration_dir="$ITERATIONS_DIR/$iteration_name"
        cfg="$iteration_dir/randconfig.config"
        printf '%s\n' "$seed" > "$iteration_dir/seed.txt" || return 1

        # Absolute paths avoid make -C path surprises. Retain partial output
        # for diagnosis, but never check it as a valid config after a failure.
        KCONFIG_SEED="$seed" KCONFIG_CONFIG="$cfg" \
            make -C "$LINUX" ARCH="$ARCH" O="$build_dir" randconfig \
            > "$iteration_dir/randconfig.log" 2>&1
        randconfig_status=$?
        printf '%s\n' "$randconfig_status" > "$iteration_dir/randconfig.exit-status"
        if (( randconfig_status != 0 )) || [[ ! -s "$cfg" ]]; then
            printf '%s\n' 'FAILED_RANDCONFIG' > "$iteration_dir/status.txt" || return 1
            echo "[$i/$RUNS] FAILED_RANDCONFIG (seed $seed); see $iteration_dir/randconfig.log" >&2
            continue
        fi

        # Load the shared base model and add only this iteration's inputs.
        start_ns=$(date +%s%N)
        ARCH="$ARCH" "$BINARY" \
            --load-model "$MODEL_FILE" \
            --add-config-constraints "$cfg" \
            --solver-timeout-ms "$SOLVER_TIMEOUT_MS" \
            > "$iteration_dir/kconfirm.log" 2>&1
        model_status=$?
        end_ns=$(date +%s%N)
        printf '%s\n' "$((end_ns - start_ns))" > "$iteration_dir/runtime.txt"
        printf '%s\n' "$model_status" > "$iteration_dir/kconfirm.exit-status"

        if (( model_status == 0 )); then
            status="SAT"
        elif grep -qi 'solver returned unknown' "$iteration_dir/kconfirm.log"; then
            status="TIMEOUT"
        elif (( model_status == 1 )) &&
             grep -qi 'solver result: Unsat' "$iteration_dir/kconfirm.log"; then
            status="UNSAT"
        else
            status="MODEL_FAILED"
        fi
        printf '%s\n' "$status" > "$iteration_dir/status.txt" || return 1

        if [[ "$status" == "UNSAT" || "$status" == "MODEL_FAILED" ]]; then
            # Include iteration number so duplicate seeds never overwrite evidence.
            kept="$FAILURES_DIR/randconfig-$iteration_name"
            cp "$cfg" "$kept.config" || return 1
            cp "$iteration_dir/kconfirm.log" "$kept.log" || return 1
        fi
        echo "[$i/$RUNS] $status (seed $seed)"
    done
}

pids=()
for ((w = 1; w <= JOBS && w <= RUNS; w++)); do
    worker "$w" &
    pids+=("$!")
done
worker_error=0
for pid in "${pids[@]}"; do
    wait "$pid" || worker_error=1
done

# Workers cannot update parent-shell counters. Count archived results instead.
pass=0
fail=0
model_fail=0
randconfig_fail=0
timeouts=0
missing=0
for ((i = 1; i <= RUNS; i++)); do
    iteration_name=$(printf '%06d-seed%s' "$i" "${seeds[i - 1]}")
    status_file="$ITERATIONS_DIR/$iteration_name/status.txt"
    status="MISSING"
    [[ ! -f "$status_file" ]] || status=$(< "$status_file")
    case "$status" in
        SAT) ((pass += 1)) ;;
        UNSAT) ((fail += 1)) ;;
        TIMEOUT) ((timeouts += 1)) ;;
        MODEL_FAILED) ((model_fail += 1)) ;;
        FAILED_RANDCONFIG) ((randconfig_fail += 1)) ;;
        *) ((missing += 1)) ;;
    esac
done

{
    echo
    echo "differential testing complete"
    echo "date: $(date -Iseconds)"
    echo "linux commit:"
    git -C "$LINUX" rev-parse HEAD 2>/dev/null || echo "unknown"
    echo
    echo "total runs: $RUNS"
    echo "workers: $JOBS"
    echo "solver timeout ms: $SOLVER_TIMEOUT_MS"
    echo "sat: $pass"
    echo "unsat: $fail"
    echo "timeouts: $timeouts"
    echo "model failures: $model_fail"
    echo "randconfig failures: $randconfig_fail"
    echo "missing results: $missing"
    echo "model constraints: $MODEL_FILE"
    echo "preprocessed macros: $PREPROC_FILE"
} | tee "$RESULTS_DIR/run.log"

# Preserve setup/execution errors as exit 2, disagreements and inconclusive
# timeouts as exit 1, and return success only when every run is SAT.
if (( worker_error != 0 || model_fail != 0 || randconfig_fail != 0 || missing != 0 )); then
    exit 2
fi
[[ "$fail" -eq 0 && "$timeouts" -eq 0 ]]
