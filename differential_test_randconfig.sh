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
#
# usage:
#   ./differential_test_eval.sh [RUNS]
#
# environment:
#   LINUX   kernel source tree      (default: evaluation/linux)
#   BINARY  kconfirm-smt binary     (default: target/release/kconfirm-smt)
#   ARCH    architecture to test    (default: x86_64)

set -u

LINUX="${LINUX:-evaluation/linux}"
BINARY="${BINARY:-target/release/kconfirm-smt}"
ARCH="${ARCH:-x86_64}"

RUNS="${1:-1000}"

LINUX_REPO="git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
LINUX_BRANCH="v7.2-rc3"

RESULTS_DIR="differential-results"
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

    echo
    echo "compiler:"
    cc --version 2>/dev/null || true

    echo
    echo "environment:"
    env | sort

} > "$RESULTS_DIR/metadata.txt"


pass=0
fail=0


for i in $(seq 1 "$RUNS"); do

    cfg="$(mktemp --suffix=.config)"


    # Generate Linux randconfig
    randconfig_output="$(
        KCONFIG_CONFIG="$cfg" \
        make -C "$LINUX" ARCH="$ARCH" randconfig 2>&1
    )"


    seed="$(
        printf '%s' "$randconfig_output" |
        grep -o 'KCONFIG_SEED=[0-9xA-Fa-f]*' |
        head -1
    )"

    seed="${seed#KCONFIG_SEED=}"


    iteration_name="$(printf "%06d-seed%s" "$i" "${seed:-unknown}")"
    iteration_dir="$ITERATIONS_DIR/$iteration_name"

    mkdir -p "$iteration_dir"


    printf '%s\n' "${seed:-unknown}" \
        > "$iteration_dir/seed.txt"


    # Save randconfig generation output
    printf '%s\n' "$randconfig_output" \
        > "$iteration_dir/randconfig.log"



    if [ ! -s "$cfg" ]; then

        echo "FAILED_RANDCONFIG" \
            > "$iteration_dir/status.txt"

        echo "[$i/$RUNS] randconfig produced no configuration"

        rm -f "$cfg"
        exit 2
    fi


    cp "$cfg" \
        "$iteration_dir/randconfig.config"



    # Check with kconfirm-smt
    if ARCH="$ARCH" "$BINARY" \
        --linux "$LINUX" \
        --add-constraints "$cfg" \
        > "$iteration_dir/kconfirm.log" 2>&1
    then

        pass=$((pass + 1))

        echo "SAT" \
            > "$iteration_dir/status.txt"

        echo "[$i/$RUNS] SAT (seed ${seed:-unknown})"

    else

        fail=$((fail + 1))

        echo "UNSAT" \
            > "$iteration_dir/status.txt"


        kept="$FAILURES_DIR/randconfig-${seed:-run$i}"

        cp "$cfg" \
            "$kept.config"

        cp "$iteration_dir/kconfirm.log" \
            "$kept.log"


        echo "[$i/$RUNS] UNSAT (seed ${seed:-unknown}) -> kept $kept"

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
    echo "sat: $pass"
    echo "unsat: $fail"

} | tee "$RESULTS_DIR/run.log"


[ "$fail" -eq 0 ]
