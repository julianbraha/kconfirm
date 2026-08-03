#!/usr/bin/env bash
# Differential test 1: is the model under-constrained?
#
# Every solution generated to the model and rendered as
# a configuration file is checked against the real Linux
# Kconfig interpreter. All outputs are preserved:
#
# - preserves every generated witness
# - preserves every exported SMT model
# - preserves every seed
# - preserves all model and kconfig logs
# - preserves all recomputed configs
# - preserves metadata and run summary
#
# usage: ./reverse_differential_test_eval.sh [RUNS]

set -u

LINUX="${LINUX:-evaluation/linux}"
BINARY="${BINARY:-target/release/kconfirm-smt}"
ARCH="${ARCH:-x86_64}"

RUNS="${1:-1000}"

LINUX_REPO="git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
LINUX_BRANCH="v7.2-rc3"

MACRO_CACHE="${MACRO_CACHE:-.reverse-macros-cache.$ARCH.txt}"

RESULTS_DIR="reverse-differential-results"
ITERATIONS_DIR="$RESULTS_DIR/iterations"
FAILURES_DIR="$RESULTS_DIR/failures"

# Clone Linux v7.2-rc3 if missing
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

if [ ! -x "$BINARY" ]; then
    echo "error: kconfirm-smt binary not found at $BINARY (build it, or set BINARY=)" >&2
    exit 2
fi


# Save evaluation metadata
{
    echo "reverse differential testing evaluation"
    echo "date: $(date -Iseconds)"
    echo
    echo "linux: $LINUX"
    echo "binary: $BINARY"
    echo "arch: $ARCH"
    echo "runs: $RUNS"
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


pass=0
fail=0
model_fail=0

for i in $(seq 1 "$RUNS"); do

    seed=$((RANDOM * 32768 + RANDOM))

    iteration_name=$(printf "%06d-seed%s" "$i" "$seed")
    iteration_dir="$ITERATIONS_DIR/$iteration_name"

    mkdir -p "$iteration_dir"

    echo "$seed" > "$iteration_dir/seed.txt"

    work="$(mktemp -d)"
    witness="$work/witness.config"
    constraints="$work/constraints.smt2"

    if [ -s "$MACRO_CACHE" ]; then
        macro_args=(--load-preproc "$MACRO_CACHE")
    else
        macro_args=(--dump-preproc "$MACRO_CACHE")
    fi


    # Generate witness from SMT model
    if ! ARCH="$ARCH" "$BINARY" \
        --linux "$LINUX" \
        --output-config "$witness" \
        --output-smt-lib "$constraints" \
        --seed "$seed" \
        "${macro_args[@]}" \
        > "$work/model.log" 2>&1 || [ ! -s "$witness" ] || [ ! -s "$constraints" ]; then

        model_fail=$((model_fail + 1))
        fail=$((fail + 1))

        cp "$work/model.log" "$iteration_dir/model.log"

        echo "MODEL_FAILED" > "$iteration_dir/status.txt"

        cp "$work/model.log" \
            "$FAILURES_DIR/model-seed$seed.log"

        echo "[$i/$RUNS] MODEL FAILED (seed $seed)"

        rm -rf "$work"
        continue
    fi


    cp "$work/model.log" "$iteration_dir/model.log"
    cp "$witness" "$iteration_dir/witness.config"
    cp "$constraints" "$iteration_dir/constraints.smt2"


    # Run real kconfig
    recomputed="$work/recomputed.config"

    cp "$witness" "$recomputed"

    cp "$recomputed" "$iteration_dir/recomputed.before.config"


    kconfig_output="$(
        KCONFIG_WARN_CHANGED_INPUT=1 \
        KCONFIG_CONFIG="$recomputed" \
        make -C "$LINUX" ARCH="$ARCH" olddefconfig 2>&1
    )"

    kconfig_status=$?


    printf '%s\n' "$kconfig_output" \
        > "$iteration_dir/kconfig.log"

    cp "$recomputed" "$iteration_dir/recomputed.config"


    #
    # Detect disagreement
    #
    if [ "$kconfig_status" -ne 0 ] || \
       printf '%s' "$kconfig_output" | grep -q "user-provided values changed"; then

        fail=$((fail + 1))

        echo "CHANGED" > "$iteration_dir/status.txt"

        cp "$witness" \
            "$FAILURES_DIR/witness-seed$seed.config"

        cp "$recomputed" \
            "$FAILURES_DIR/witness-seed$seed.recomputed.config"

        cp "$iteration_dir/kconfig.log" \
            "$FAILURES_DIR/witness-seed$seed.log"


        changed_count="$(
            printf '%s' "$kconfig_output" |
            grep -c '^  CONFIG_'
        )"

        echo "[$i/$RUNS] CHANGED (seed $seed): $changed_count values"

    else

        pass=$((pass + 1))

        echo "SUCCESS" > "$iteration_dir/status.txt"

        echo "[$i/$RUNS] success (seed $seed)"

    fi


    rm -rf "$work"

done


# Summary
{
    echo
    echo "reverse differential testing complete"
    echo "date: $(date -Iseconds)"
    echo "total runs: $RUNS"
    echo "successes: $pass"
    echo "failures: $fail"
    echo "model failures: $model_fail"
    echo "macro cache: $MACRO_CACHE"
} | tee "$RESULTS_DIR/run.log"


[ "$fail" -eq 0 ]
