#!/usr/bin/env bash
# Compare kconfirm and Kismet for unmet dependency bug detection.
# - uses kismet from kmax v4.10, Linux v6.19.9, and evaluates on x86.
# Due to their implementation differences:
#   kconfirm creates a single model for x86,
#   Kismet creates two models for i386 and x86_64.
#
# Setup on Ubuntu 24.04, from the repository root:
#   sudo apt update
#   sudo apt install -y build-essential git curl ca-certificates pkg-config \
#     flex bison bc perl pahole libssl-dev libelf-dev libcurl4-openssl-dev \
#     python3-dev python3-venv gawk time
#   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
#     sh -s -- -y --profile minimal --default-toolchain stable
#   . "$HOME/.cargo/env"
#   python3 -m venv evaluation/kismet-venv
#   . evaluation/kismet-venv/bin/activate
#   python -m pip install --upgrade pip setuptools wheel
#   CFLAGS=-std=gnu17 python -m pip install 'kmax==4.10'
#   export KISMET_PYTHON="$VIRTUAL_ENV/bin/python3"
#   export TIME_BINARY=/usr/bin/time
#
# Alternative Setup with Nix: `nix develop .#kismet`
#
# To run from the repository root:
#   cargo build --release --locked -p kconfirm-cli
#   bash kconfirm-cli/evaluate_unmet_dependencies.sh
#
# Settings: LINUX=evaluation/linux-unmet, KMAX=evaluation/kmax,
# BINARY=target/release/kconfirm-cli, RESULTS_DIR=evaluation/unmet-dependencies,
# KISMET_PROCESSES=16,
# TIMEOUT_SECONDS=3600 (0 means unlimited), WITNESSES=1.
# After all runs finish, unmet dependency pairs (selector-selectee) are
#   deduplicated across architectures to consolidated/kconfirm.tsv and consolidated/kismet.tsv.
# Each TSV line contains selector<TAB>selectee, without a header.

set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LINUX="$(realpath -m -- "${LINUX:-evaluation/linux-unmet}")"
KMAX="$(realpath -m -- "${KMAX:-evaluation/kmax}")"
BINARY="$(realpath -- "${BINARY:-$SCRIPT_DIR/../target/release/kconfirm-cli}")"
RESULTS_DIR="$(realpath -m -- "${RESULTS_DIR:-evaluation/unmet-dependencies}")"
# Preserve a virtualenv interpreter's symlink.
KISMET_PYTHON="$(realpath -s -- "$(command -v "${KISMET_PYTHON:-python3}")")"
TIME_BINARY="${TIME_BINARY:-$(type -P time)}"
KISMET_PROCESSES="${KISMET_PROCESSES:-16}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-3600}"
WITNESSES="${WITNESSES:-1}"
LINUX_COMMIT=4a2b0ed2ac7abe9743e1559d212075a0ebac96b3
KMAX_RELEASE=v4.10
arch=x86

mkdir -p -- "$(dirname -- "$RESULTS_DIR")"
mkdir -- "$RESULTS_DIR"
trap 'echo FAILED > "$RESULTS_DIR/status.txt"' ERR
echo RUNNING > "$RESULTS_DIR/status.txt"
PROVENANCE_DIR="$RESULTS_DIR/provenance"
mkdir -p "$PROVENANCE_DIR/kmax-source" "$RESULTS_DIR/linux" "$RESULTS_DIR/bin"
cp -- "$BINARY" "$PROVENANCE_DIR/kconfirm-cli"
cp -- "${BASH_SOURCE[0]}" "$PROVENANCE_DIR/"

if [ ! -d "$KMAX" ]; then
    git clone --depth 1 --branch "$KMAX_RELEASE" https://github.com/paulgazz/kmax.git "$KMAX"
fi
KMAX_COMMIT="$(git -C "$KMAX" rev-parse "refs/tags/$KMAX_RELEASE^{commit}")"
if [ ! -d "$LINUX" ]; then
    git clone --depth 1 --branch v6.19.9 \
        https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git "$LINUX"
fi

git -C "$KMAX" archive "$KMAX_COMMIT" | tar -xf - -C "$PROVENANCE_DIR/kmax-source"
git -C "$LINUX" archive "$LINUX_COMMIT" | tar -xf - -C "$RESULTS_DIR/linux"
LINUX_SOURCE="$RESULTS_DIR/linux"
{
    date -Iseconds
    printf '%s\n' "linux commit: $LINUX_COMMIT" "kmax release: $KMAX_RELEASE" "kmax commit: $KMAX_COMMIT" \
        "kconfirm commit: $(git -C "$SCRIPT_DIR/.." rev-parse HEAD)" "binary: $BINARY" \
        "architectures: $arch" "kismet processes: $KISMET_PROCESSES" \
        "kismet python: $KISMET_PYTHON" "timeout seconds: $TIMEOUT_SECONDS" \
        "witnesses: $WITNESSES"
} > "$RESULTS_DIR/metadata.txt"
sha256sum "$PROVENANCE_DIR/kconfirm-cli" > "$PROVENANCE_DIR/sha256sums.txt"

export PATH="$RESULTS_DIR/bin:$PATH" PYTHONPATH="$PROVENANCE_DIR/kmax-source"
export LC_ALL=C LANG=C TZ=UTC RUST_LOG=info MAKEFLAGS=-j1
export PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
for tool in kextractlinux kclause; do
    printf '#!/usr/bin/env bash\nexec %q %q "$@"\n' \
        "$KISMET_PYTHON" "$PROVENANCE_DIR/kmax-source/kmax/$tool" > "$RESULTS_DIR/bin/$tool"
    chmod +x "$RESULTS_DIR/bin/$tool"
done
# Kismet's nested workers need fork, including on Python 3.14.
cat > "$RESULTS_DIR/bin/kismet.py" <<'PY'
import multiprocessing, runpy, sys
if __name__ == '__main__':
    multiprocessing.set_start_method('fork')
    script = sys.argv.pop(1)
    sys.argv[0] = script
    runpy.run_path(script, run_name='__main__')
PY

parse_findings() {
    local tool="$1" directory="$2"
    if [ "$tool" = kconfirm ]; then
        # kconfirm can return zero after an analysis or preprocessing failure.
        awk '/Preprocessed macros:.*[1-9][0-9]* unresolved/ { exit 1 }' "$directory/stderr.log"
        awk '
            /^FATAL|\[(failed_parse|failed_model)\]/ { exit 1 }
            /\[unmet_dependency\]/ {
                sub(/:$/, "", $5); sub(/^CONFIG_/, "", $5); sub(/^CONFIG_/, "", $8)
                print $5 "\t" $8
            }
        ' "$directory/stdout.log" > "$directory/pairs.tsv"
    else
        awk -F, '
            { sub(/\r$/, "") }
            $5 == "0" && $6 == "UNMET_ALARM" {
                sub(/^CONFIG_/, "", $3); sub(/^CONFIG_/, "", $2); print $3 "\t" $2
            }
        ' "$directory/summary.csv" > "$directory/pairs.tsv"
    fi
}

run_job() {
    local tool="$1" variant="$2" relative_dir="iterations/$arch/$1-$2"
    local directory="$RESULTS_DIR/$relative_dir"
    local metrics alarms
    local -a command
    mkdir -p "$directory/tmp"
    if [ "$tool" = kconfirm ]; then
        command=("$PROVENANCE_DIR/kconfirm-cli" --confirm --linux-dir-path "$LINUX_SOURCE"
            --arch "$arch" --enable-check unmet_dependency --disable-check select_visible)
        [ "$WITNESSES" -eq 0 ] || command+=(--output-witness-dir "$directory/witnesses")
    else
        command=("$KISMET_PYTHON" "$RESULTS_DIR/bin/kismet.py" "$PROVENANCE_DIR/kmax-source/kmax/kismet"
            --linux-ksrc "$LINUX_SOURCE" --arch "$variant" --formulas "$directory/formulas"
            --test-cases-dir "$directory/witnesses" --summary-csv "$directory/summary.csv"
            --summary-txt "$directory/summary.txt" --processes "$KISMET_PROCESSES"
            --no-verification --verbose)
        [ "$WITNESSES" -eq 1 ] || command+=(--no-test-case-generation)
    fi
    command=(env "PATH=$PATH" "PYTHONPATH=$PYTHONPATH" "ARCH=$variant"
        "TMPDIR=$directory/tmp" "${command[@]}")
    {
        printf '#!/usr/bin/env bash\n# Run in the Nix evaluation shell.\ncd -- %q\nexec ' "$directory"
        printf '%q ' "${command[@]}"
        printf '\n'
    } > "$directory/command.sh"
    printf '%s,%s,%s,%s\n' "$arch" "$tool" "$variant" "$relative_dir" >> "$RESULTS_DIR/plan.csv"
    echo "Running $tool $variant"
    date -Iseconds > "$directory/started.txt"
    (
        cd "$directory"
        "$TIME_BINARY" -f '%e,%U,%S,%M' -o resources.csv \
            timeout --kill-after=5 "$TIMEOUT_SECONDS" "${command[@]}"
    ) > "$directory/stdout.log" 2> "$directory/stderr.log"
    date -Iseconds > "$directory/finished.txt"
    parse_findings "$tool" "$directory"
    metrics="$(cat "$directory/resources.csv")"
    printf '%s\n' "${metrics%%,*}" > "$directory/runtime.txt"
    alarms="$(wc -l < "$directory/pairs.tsv")"
    echo SUCCESS > "$directory/status.txt"
    printf '%s,%s,%s,SUCCESS,0,%s,%s,%s\n' "$arch" "$tool" "$variant" \
        "$metrics" "$alarms" "$relative_dir" >> "$RESULTS_DIR/summary.csv"
    echo "SUCCESS: $relative_dir" | tee -a "$RESULTS_DIR/run.log"
}

consolidate_findings() {
    local directory="$RESULTS_DIR/consolidated" tool
    mkdir -p "$directory"
    for tool in kconfirm kismet; do
        sort -u "$RESULTS_DIR/iterations/"*/"$tool-"*/pairs.tsv > "$directory/$tool.tsv"
        awk '{ sum += $1 } END { printf "%.2f\n", sum }' \
            "$RESULTS_DIR/iterations/"*/"$tool-"*/runtime.txt > "$directory/$tool.runtime.txt"
    done
    comm -12 "$directory/kconfirm.tsv" "$directory/kismet.tsv" > "$directory/shared.tsv"
    comm -23 "$directory/kconfirm.tsv" "$directory/kismet.tsv" > "$directory/kconfirm-only.tsv"
    comm -13 "$directory/kconfirm.tsv" "$directory/kismet.tsv" > "$directory/kismet-only.tsv"
    echo 'status,kconfirm_pairs,kismet_pairs,shared,kconfirm_only,kismet_only,kconfirm_wall_seconds,kismet_wall_seconds' > "$RESULTS_DIR/comparison.csv"
    printf 'COMPLETE,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(wc -l < "$directory/kconfirm.tsv")" "$(wc -l < "$directory/kismet.tsv")" \
        "$(wc -l < "$directory/shared.tsv")" "$(wc -l < "$directory/kconfirm-only.tsv")" \
        "$(wc -l < "$directory/kismet-only.tsv")" "$(cat "$directory/kconfirm.runtime.txt")" \
        "$(cat "$directory/kismet.runtime.txt")" >> "$RESULTS_DIR/comparison.csv"
}

# Read the full run sequence before the analyses start, in case this file changes.
{
    echo 'source_arch,tool,tool_arch,directory' > "$RESULTS_DIR/plan.csv"
    echo 'source_arch,tool,tool_arch,status,exit_code,wall_seconds,user_seconds,system_seconds,max_rss_kib,reported_alarms,directory' > "$RESULTS_DIR/summary.csv"
    run_job kconfirm x86
    run_job kismet i386
    run_job kismet x86_64
    consolidate_findings
    echo COMPLETE > "$RESULTS_DIR/status.txt"
    echo "Results: $RESULTS_DIR"
}
