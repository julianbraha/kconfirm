
#!/usr/bin/env python3

import argparse
from pathlib import Path
import re

import numpy as np
import matplotlib.pyplot as plt


DATASETS = {
    "Differential": Path("differential-results"),
    "Reverse": Path("reverse-differential-results"),
}

TIMEOUT = 1800  # seconds


def load_runtimes(directory):
    values = []
    timeouts = 0

    paths = sorted(directory.glob("iterations/*/runtime.txt"))

    for path in paths:
        try:
            runtime = int(path.read_text().strip()) / 1e9

            if runtime >= TIMEOUT:
                timeouts += 1
            else:
                values.append(runtime)

        except (ValueError, OSError) as e:
            print(f"Skipping {path}: {e}")

    return np.array(values), timeouts


def load_solver_runtimes(directory):
    values = []
    unknowns = 0
    missing = 0

    for iteration in sorted(directory.glob("iterations/*")):
        if not iteration.is_dir():
            continue

        # Differential checks log to kconfirm.log; reverse checks to model.log.
        path = iteration / "kconfirm.log"
        if not path.exists():
            path = iteration / "model.log"

        try:
            log = path.read_text()
        except (OSError, UnicodeError) as e:
            print(f"Skipping solver measurement in {iteration}: {e}")
            missing += 1
            continue

        result = re.search(r"Solver result: (Sat|Unsat|Unknown)\b", log)
        if result and result.group(1) == "Unknown":
            unknowns += 1
            continue

        # Use the precise measurement rather than the rounded seconds field.
        runtime = re.search(r"Solver runtime \(ns\): (\d+)\b", log)
        if result and runtime:
            values.append(int(runtime.group(1)) / 1e9)
        else:
            missing += 1

    print(f"Solver measurements missing or incomplete: {missing:,}")
    return np.array(values), unknowns


def print_stats(name, x, timeouts, solver=False):
    total = len(x) + timeouts

    print(f"\n{name}")
    print("=" * 45)
    print(f"Total runs:       {total:,}")
    print(f"Completed runs:   {len(x):,}")

    if total:
        label = "Unknown results" if solver else "Timeouts"
        print(f"{label}:         {timeouts:,} "
              f"({100 * timeouts / total:.2f}%)")

    if len(x) == 0:
        print("No completed measurements.")
        return

    excluded = "unknown results" if solver else "timeouts"
    print(f"\nRuntime statistics (excluding {excluded})")
    print("-" * 45)

    print(f"Mean:             {np.mean(x):.4f} s")
    print(f"Median:           {np.median(x):.4f} s")

    if len(x) > 1:
        print(f"Std. deviation:   {np.std(x, ddof=1):.4f} s")

    print(f"Minimum:          {np.min(x):.4f} s")
    print(f"Maximum:          {np.max(x):.4f} s")

    for p in (25, 75, 90, 95, 99):
        print(f"P{p:<2}:              {np.percentile(x, p):.4f} s")

    print("\nRuntime thresholds")
    print("-" * 45)

    for threshold in (1, 5, 10, 30, 60, 300, 600):
        count = np.sum(x < threshold)
        percentage = 100 * count / len(x)
        print(f"< {threshold:3d} s:          {count:,} ({percentage:.2f}%)")


def plot_histogram(name, x, prefix):
    fig, ax = plt.subplots(figsize=(7, 4))

    ax.hist(x, bins=60, alpha=0.75, edgecolor="black")

    ax.axvline(
        np.mean(x),
        linestyle="--",
        label=f"Mean: {np.mean(x):.2f} s",
    )

    ax.axvline(
        np.median(x),
        linestyle=":",
        label=f"Median: {np.median(x):.2f} s",
    )

    ax.set_xlabel("Runtime (seconds)")
    ax.set_ylabel("Number of runs")
    ax.set_title(f"{name} runtime distribution")
    ax.legend()

    fig.tight_layout()

    fig.savefig(f"{prefix}-histogram.pdf", bbox_inches="tight")
    fig.savefig(f"{prefix}-histogram.png", dpi=200, bbox_inches="tight")

    plt.close(fig)


def plot_boxplot(name, x, prefix):
    fig, ax = plt.subplots(figsize=(5, 4))

    ax.boxplot(
        [x],
        showfliers=True,
        showmeans=True,
    )
    ax.set_xticks([1], [name])

    ax.set_ylabel("Runtime (seconds)")
    ax.set_title(f"{name} runtime boxplot")

    fig.tight_layout()

    fig.savefig(f"{prefix}-boxplot.pdf", bbox_inches="tight")
    fig.savefig(f"{prefix}-boxplot.png", dpi=200, bbox_inches="tight")

    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Plot wall-clock and solver runtimes.")
    parser.add_argument(
        "data_root", nargs="?", type=Path, default=Path("."),
        help="Directory containing differential-results and reverse-differential-results",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    for name, directory in DATASETS.items():
        directory = args.data_root / directory
        runtimes, timeouts = load_runtimes(directory)

        print_stats(f"{name} wall-clock", runtimes, timeouts)

        if len(runtimes):
            prefix = args.output_dir / name.lower()
            plot_histogram(f"{name} wall-clock", runtimes, prefix)
            plot_boxplot(f"{name} wall-clock", runtimes, prefix)
            print(f"\nSaved {prefix}-histogram.pdf/png")
            print(f"Saved {prefix}-boxplot.pdf/png")

        solver_runtimes, unknowns = load_solver_runtimes(directory)
        print_stats(f"{name} solver", solver_runtimes, unknowns, solver=True)

        if len(solver_runtimes):
            prefix = args.output_dir / f"{name.lower()}-solver"
            plot_histogram(f"{name} solver", solver_runtimes, prefix)
            plot_boxplot(f"{name} solver", solver_runtimes, prefix)

            print(f"\nSaved {prefix}-histogram.pdf/png")
            print(f"Saved {prefix}-boxplot.pdf/png")


if __name__ == "__main__":
    main()
