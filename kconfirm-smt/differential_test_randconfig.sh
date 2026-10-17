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
#   bash differential_test_randconfig.sh [RUNS] [SEEDS_FILE] [SOLVER_TIMEOUT_MS]
#
# Uses the first RUNS seeds in file order, including duplicates.
# Defaults: RUNS=1000, SEEDS_FILE=random-seeds.txt (or $SEEDS_FILE),
# SOLVER_TIMEOUT_MS=0 (no timeout). Solver invocation runtimes are saved in
# nanoseconds in each iteration's runtime.txt, including timed-out checks.
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

# Load once so both directions can reuse exactly the same recorded seed list.
if [ "$#" -gt 3 ]; then
    echo "usage: $0 [RUNS] [SEEDS_FILE] [SOLVER_TIMEOUT_MS]" >&2
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

RESULTS_DIR="differential-results"
ITERATIONS_DIR="$RESULTS_DIR/iterations"
FAILURES_DIR="$RESULTS_DIR/failures"
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


mkdir -p "$ITERATIONS_DIR"
mkdir -p "$FAILURES_DIR"

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


pass=0
fail=0
timeouts=0


for i in $(seq 1 "$RUNS"); do

    seed="${seeds[i - 1]}"

    iteration_name="$(printf '%06d-seed%s' "$i" "$seed")"
    iteration_dir="$ITERATIONS_DIR/$iteration_name"
    mkdir -p "$iteration_dir" || exit 2
    rm -f "$iteration_dir/status.txt" "$iteration_dir/randconfig.config" \
        "$iteration_dir/runtime.txt" || exit 2

    cfg="$(mktemp)" || exit 2


    # Generate Linux randconfig
    randconfig_output="$(
        KCONFIG_SEED="$seed" \
        KCONFIG_CONFIG="$cfg" \
        make -C "$LINUX" ARCH="$ARCH" randconfig 2>&1
    )"
    randconfig_status=$?

    printf '%s\n' "${seed:-unknown}" \
        > "$iteration_dir/seed.txt"


    # Save randconfig generation output
    printf '%s\n' "$randconfig_output" \
        > "$iteration_dir/randconfig.log"
    printf '%s\n' "$randconfig_status" > "$iteration_dir/randconfig.exit-status"



    if [ "$randconfig_status" -ne 0 ] || [ ! -s "$cfg" ]; then

        echo "FAILED_RANDCONFIG" \
            > "$iteration_dir/status.txt"

        if [ "$randconfig_status" -ne 0 ]; then
            echo "[$i/$RUNS] make randconfig failed (exit $randconfig_status); see $iteration_dir/randconfig.log" >&2
        else
            echo "[$i/$RUNS] randconfig produced no configuration; see $iteration_dir/randconfig.log" >&2
        fi
        cat "$iteration_dir/randconfig.log" >&2

        # Keep partial output for diagnosis, but never check it as a valid config.
        if [ -s "$cfg" ]; then
            cp "$cfg" "$iteration_dir/randconfig.config"
        fi

        rm -f "$cfg"
        exit 2
    fi


    cp "$cfg" \
        "$iteration_dir/randconfig.config"



    # Load the saved base model and add only this iteration's inputs.
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

        pass=$((pass + 1))

        echo "SAT" \
            > "$iteration_dir/status.txt"

        echo "[$i/$RUNS] SAT (seed ${seed:-unknown})"

    elif grep -qi 'solver returned unknown' "$iteration_dir/kconfirm.log"; then
        timeouts=$((timeouts + 1))
        echo "TIMEOUT" > "$iteration_dir/status.txt"
        echo "[$i/$RUNS] TIMEOUT (seed $seed)"

    elif (( model_status == 1 )) &&
         grep -qi 'solver result: Unsat' "$iteration_dir/kconfirm.log"; then

        fail=$((fail + 1))

        echo "UNSAT" \
            > "$iteration_dir/status.txt"


        kept="$FAILURES_DIR/randconfig-$iteration_name"

        cp "$cfg" \
            "$kept.config"

        cp "$iteration_dir/kconfirm.log" \
            "$kept.log"


        echo "[$i/$RUNS] UNSAT (seed ${seed:-unknown}) -> kept $kept"

    else
        echo "MODEL_FAILED" > "$iteration_dir/status.txt"
        echo "[$i/$RUNS] model check failed; see $iteration_dir/kconfirm.log" >&2
        rm -f "$cfg"
        exit 2
    fi


    rm -f "$cfg"

done


# Summary
{
    echo
    echo "differential testing complete"
    echo "date: $(date -Iseconds)"
    echo "linux commit:"
    git -C "$LINUX" rev-parse HEAD 2>/dev/null || echo "unknown"
    echo
    echo "total runs: $RUNS"
    echo "solver timeout ms: $SOLVER_TIMEOUT_MS"
    echo "sat: $pass"
    echo "unsat: $fail"
    echo "timeouts: $timeouts"
    echo "model constraints: $MODEL_FILE"
    echo "preprocessed macros: $PREPROC_FILE"

} | tee "$RESULTS_DIR/run.log"


# Timed-out runs are inconclusive, so they still prevent a successful exit.
[[ "$fail" -eq 0 && "$timeouts" -eq 0 ]]
