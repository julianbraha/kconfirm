#!/usr/bin/env bash
# Differential test: generated SMT witnesses versus Linux Kconfig.
# Usage: JOBS=4 bash differential_test_model_config_parallel.sh [RUNS] [SEEDS_FILE] [SOLVER_TIMEOUT_MS]
# Each worker owns one persistent, isolated Kbuild output directory.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || exit 2
LINUX="${LINUX:-evaluation/linux-model}"
BINARY="${BINARY:-$SCRIPT_DIR/../target/release/kconfirm-smt}"
ARCH="${ARCH:-x86_64}"
RUNS="${1:-1000}"
SEEDS_FILE="${2:-${SEEDS_FILE:-random-seeds.txt}}"
SOLVER_TIMEOUT_MS="${3:-${SOLVER_TIMEOUT_MS:-0}}"
JOBS="${JOBS:-4}"

if (( $# > 3 )); then
    echo "usage: $0 [RUNS] [SEEDS_FILE] [SOLVER_TIMEOUT_MS]" >&2
    exit 2
fi
if [[ ! "$JOBS" =~ ^[1-9][0-9]*$ ]] || (( ${#JOBS} > 8 )); then
    echo "error: JOBS must be a positive integer" >&2
    exit 2
fi
if [[ ! -f "$SEEDS_FILE" || ! -r "$SEEDS_FILE" ]]; then
    echo "error: seed file not readable: $SEEDS_FILE" >&2
    exit 2
fi
if ! mapfile -t seeds < "$SEEDS_FILE"; then
    echo "error: failed to read seed file: $SEEDS_FILE" >&2
    exit 2
fi
seed_count="${#seeds[@]}"
if (( seed_count == 0 )); then
    echo "error: seed file is empty: $SEEDS_FILE" >&2
    exit 2
fi
if [[ ! "$RUNS" =~ ^[1-9][0-9]*$ ]] ||
   (( ${#RUNS} > ${#seed_count} )) || (( RUNS > seed_count )); then
    echo "error: RUNS must be between 1 and $seed_count" >&2
    exit 2
fi
for index in "${!seeds[@]}"; do
    seed="${seeds[index]}"
    if [[ ! "$seed" =~ ^(0|[1-9][0-9]{0,9})$ ]] || (( seed > 4294967295 )); then
        echo "error: $SEEDS_FILE:$((index + 1)): expected a decimal seed in 0..4294967295" >&2
        exit 2
    fi
done

LINUX_REPO="git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
LINUX_BRANCH="v7.2.10"
MACRO_CACHE="${MACRO_CACHE:-}"
RESULTS_DIR="${RESULTS_DIR:-reverse-differential-results}"
ITERATIONS_DIR="$RESULTS_DIR/iterations"
FAILURES_DIR="$RESULTS_DIR/failures"
WORKERS_DIR="$RESULTS_DIR/workers"
MODEL_FILE="$RESULTS_DIR/model.smt2"
PREPROC_FILE="$RESULTS_DIR/macros.txt"

macro_args=()
if [[ -n "$MACRO_CACHE" ]]; then
    if [[ ! -f "$MACRO_CACHE" || ! -r "$MACRO_CACHE" || ! -s "$MACRO_CACHE" ]]; then
        echo "error: MACRO_CACHE must name a readable, nonempty macro dump: $MACRO_CACHE" >&2
        exit 2
    fi
    MACRO_CACHE="$(realpath "$MACRO_CACHE")" || exit 2
    macro_args=(--load-preproc "$MACRO_CACHE")
fi

if [[ ! -d "$LINUX/.git" ]]; then
    echo "Linux source tree not found at $LINUX"
    echo "Cloning Linux $LINUX_BRANCH..."
    mkdir -p "$(dirname "$LINUX")"
    git clone --depth 1 --branch "$LINUX_BRANCH" "$LINUX_REPO" "$LINUX" || exit 2
fi
LINUX="$(realpath "$LINUX")" || exit 2
BINARY="$(realpath "$BINARY")" || exit 2
if [[ ! -x "$BINARY" ]]; then
    echo "error: kconfirm-smt binary not executable at $BINARY" >&2
    exit 2
fi

mkdir -p "$ITERATIONS_DIR" "$FAILURES_DIR" "$WORKERS_DIR" || exit 2
RESULTS_DIR="$(realpath "$RESULTS_DIR")" || exit 2
ITERATIONS_DIR="$RESULTS_DIR/iterations"
FAILURES_DIR="$RESULTS_DIR/failures"
WORKERS_DIR="$RESULTS_DIR/workers"
MODEL_FILE="$RESULTS_DIR/model.smt2"
PREPROC_FILE="$RESULTS_DIR/macros.txt"
printf '%s\n' "${seeds[@]:0:RUNS}" > "$RESULTS_DIR/seeds.txt" || exit 2

{
    echo "reverse differential testing evaluation"
    echo "date: $(date -Iseconds)"
    echo
    echo "linux: $LINUX"
    echo "binary: $BINARY"
    echo "arch: $ARCH"
    echo "runs: $RUNS"
    echo "workers: $JOBS"
    echo "solver timeout ms: $SOLVER_TIMEOUT_MS"
    echo "seed source: $SEEDS_FILE"
    echo "selected seeds: $RESULTS_DIR/seeds.txt"
    echo "model constraints: $MODEL_FILE"
    echo "preprocessed macros: $PREPROC_FILE"
    echo "macro input: ${MACRO_CACHE:-fresh evaluation}"
    echo
    echo "kernel commit:"
    git -C "$LINUX" rev-parse HEAD 2>/dev/null || echo "unknown"
    echo
    echo "compiler:"
    cc --version 2>/dev/null || true
    echo
    echo "environment:"
    env | sort
} > "$RESULTS_DIR/metadata.txt"

# Generate base model and shared macro dump once, before parallel work.
if ! ARCH="$ARCH" "$BINARY" \
    --linux "$LINUX" \
    --output-smt-lib "$MODEL_FILE" \
    --solver-timeout-ms "$SOLVER_TIMEOUT_MS" \
    --dump-preproc "$PREPROC_FILE" \
    "${macro_args[@]}" \
    > "$RESULTS_DIR/model.log" 2>&1 ||
    [[ ! -s "$MODEL_FILE" || ! -s "$PREPROC_FILE" ]]; then
    echo "error: model generation failed; see $RESULTS_DIR/model.log" >&2
    exit 2
fi
if grep -Eq 'Preprocessed macros: [0-9]+ evaluated, [1-9][0-9]* unresolved' "$RESULTS_DIR/model.log"; then
    echo "error: model has unresolved macros; see $RESULTS_DIR/model.log" >&2
    exit 2
fi

# Each worker gets a private Kbuild output tree. Kconfig tools built here are
# reused across that worker's iterations, without concurrent access.
worker() {
    local worker_id="$1"
    local build_dir="$WORKERS_DIR/worker-$worker_id/build"
    local i seed iteration_name iteration_dir work witness constraints preproc
    local start_ns end_ns model_status kconfig_status kconfig_output recomputed
    local changed_count status

    mkdir -p "$build_dir" || return 1

    # Static round-robin assignment guarantees unique worker ownership of O=.
    for ((i = worker_id; i <= RUNS; i += JOBS)); do
        seed="${seeds[i - 1]}"
        iteration_name=$(printf '%06d-seed%s' "$i" "$seed")
        iteration_dir="$ITERATIONS_DIR/$iteration_name"
        mkdir -p "$iteration_dir" || return 1
        printf '%s\n' "$seed" > "$iteration_dir/seed.txt"

        work=$(mktemp -d) || return 1
        witness="$iteration_dir/witness.config"
        constraints="$iteration_dir/constraints.smt2"
        preproc="$iteration_dir/macros.txt"

        start_ns=$(date +%s%N)
        ARCH="$ARCH" "$BINARY" \
            --linux "$LINUX" \
            --output-config "$witness" \
            --output-smt-lib "$constraints" \
            --seed "$seed" \
            --solver-timeout-ms "$SOLVER_TIMEOUT_MS" \
            --load-preproc "$PREPROC_FILE" \
            --dump-preproc "$preproc" \
            > "$iteration_dir/model.log" 2>&1
        model_status=$?
        end_ns=$(date +%s%N)
        printf '%s\n' "$((end_ns - start_ns))" > "$iteration_dir/runtime.txt"

        if (( model_status != 0 )) ||
           [[ ! -s "$witness" || ! -s "$constraints" || ! -s "$preproc" ]]; then
            if grep -qi 'solver returned unknown' "$iteration_dir/model.log"; then
                status="TIMEOUT"
            else
                status="MODEL_FAILED"
            fi
            printf '%s\n' "$status" > "$iteration_dir/status.txt"
            if [[ "$status" != "TIMEOUT" ]]; then
                cp "$iteration_dir/model.log" "$FAILURES_DIR/model-${iteration_name}.log"
            fi
            echo "[$i/$RUNS] $status (seed $seed)"
            rm -rf "$work"
            continue
        fi

        recomputed="$work/recomputed.config"
        cp "$witness" "$recomputed"
        cp "$recomputed" "$iteration_dir/recomputed.before.config"

        # Absolute KCONFIG_CONFIG and O= paths avoid make -C path surprises.
        kconfig_output=$(
            KCONFIG_WARN_CHANGED_INPUT=1 \
            KCONFIG_CONFIG="$recomputed" \
            make -C "$LINUX" ARCH="$ARCH" O="$build_dir" olddefconfig 2>&1
        )
        kconfig_status=$?
        printf '%s\n' "$kconfig_output" > "$iteration_dir/kconfig.log"
        cp "$recomputed" "$iteration_dir/recomputed.config"

        if (( kconfig_status != 0 )) ||
           grep -q 'user-provided values changed' <<< "$kconfig_output"; then
            printf '%s\n' 'CHANGED' > "$iteration_dir/status.txt"
            cp "$witness" "$FAILURES_DIR/witness-${iteration_name}.config"
            cp "$recomputed" "$FAILURES_DIR/witness-${iteration_name}.recomputed.config"
            cp "$iteration_dir/kconfig.log" "$FAILURES_DIR/witness-${iteration_name}.log"
            changed_count=$(grep -c '^  CONFIG_' <<< "$kconfig_output" || true)
            echo "[$i/$RUNS] CHANGED (seed $seed): $changed_count values"
        else
            printf '%s\n' 'SUCCESS' > "$iteration_dir/status.txt"
            echo "[$i/$RUNS] success (seed $seed)"
        fi
        rm -rf "$work"
    done
}

# Start one long-lived process per worker. All workers run concurrently.
pids=()
for ((w = 1; w <= JOBS && w <= RUNS; w++)); do
    worker "$w" &
    pids+=("$!")
done
worker_error=0
for pid in "${pids[@]}"; do
    wait "$pid" || worker_error=1
done

# Background workers cannot update counters in the parent shell.
pass=0
fail=0
model_fail=0
timeouts=0
for ((i = 1; i <= RUNS; i++)); do
    seed="${seeds[i - 1]}"
    iteration_name=$(printf '%06d-seed%s' "$i" "$seed")
    status_file="$ITERATIONS_DIR/$iteration_name/status.txt"
    status="MISSING"
    [[ ! -f "$status_file" ]] || status=$(< "$status_file")
    case "$status" in
        SUCCESS) ((pass += 1)) ;;
        CHANGED) ((fail += 1)) ;;
        TIMEOUT) ((timeouts += 1)) ;;
        MODEL_FAILED) ((model_fail += 1)); ((fail += 1)) ;;
        *) ((model_fail += 1)); ((fail += 1)) ;;
    esac
done

{
    echo
    echo "reverse differential testing complete"
    echo "date: $(date -Iseconds)"
    echo "total runs: $RUNS"
    echo "workers: $JOBS"
    echo "solver timeout ms: $SOLVER_TIMEOUT_MS"
    echo "successes: $pass"
    echo "failures: $fail"
    echo "model failures: $model_fail"
    echo "timeouts: $timeouts"
    echo "model constraints: $MODEL_FILE"
    echo "preprocessed macros: $PREPROC_FILE"
    echo "macro input: ${MACRO_CACHE:-fresh evaluation}"
} | tee "$RESULTS_DIR/run.log"

# Timed-out runs are inconclusive, so they still prevent a successful exit.
[[ "$fail" -eq 0 && "$timeouts" -eq 0 && "$worker_error" -eq 0 ]]
