# kconfirm-lib

[![crates.io](https://img.shields.io/crates/v/kconfirm-lib.svg)](https://crates.io/crates/kconfirm-lib)
[![docs.rs](https://docs.rs/kconfirm-lib/badge.svg)](https://docs.rs/kconfirm-lib)
[![license](https://img.shields.io/badge/license-GPL--2.0--only-blue.svg)](https://github.com/julianbraha/kconfirm/blob/main/LICENSE)

The analysis engine behind [**kconfirm**](https://github.com/julianbraha/kconfirm), a static
checker for the [Kconfig](https://www.kernel.org/doc/html/latest/kbuild/kconfig-language.html)
configuration language used by the Linux kernel, coreboot, U-Boot, BusyBox, and many other
projects.

`kconfirm-lib` takes parsed Kconfig (from [`nom-kconfig`](https://crates.io/crates/nom-kconfig)),
builds a symbol table of every `config` option across files and architectures, and runs a set of
checks, such as for dead code, select-visible misuse and more. Findings from this crate
have resulted in [accepted patches to the Linux
kernel](https://github.com/julianbraha/kconfirm#submitted-patches-linux), coreboot, U-Boot, and
others.

If you just want to run the analyzer, use the [`kconfirm-cli`](https://github.com/julianbraha/kconfirm)
binary. This crate is for reusing the underlying analysis in your own tooling.

## What it detects

Each check is identified by a [`Check`] variant and a stable string id (returned by
[`Check::as_str`] and accepted by [`parse_check`]). Checks are opt-in: you enable the ones you
want on an [`AnalysisArgs`] value.

| String id                 | Check                          | Severity | Description |
|---------------------------|--------------------------------|----------|-------------|
| `dead_default`            | `Check::DeadDefault`           | Warning  | A `default` that can never be reached because an earlier one always takes priority. |
| `duplicate_default`       | `Check::DuplicateDefault`      | Warning  | A `default` value/condition pair that repeats an earlier one. |
| `duplicate_default_value` | `Check::DuplicateDefaultValue` | Style    | Multiple `default`s with the same value but different conditions (hint: combine with `||`). |
| `dead_select`             | `Check::DeadSelect`            | Warning  | A conditional `select` made unreachable by an unconditional `select` of the same symbol. |
| `duplicate_select`        | `Check::DuplicateSelect`       | Warning  | A repeated `select` of the same symbol (and condition). |
| `select_visible`          | `Check::SelectVisible`         | Warning  | A `select` of a *visible* option; prefer `depends on` or `imply`. |
| `dead_imply`              | `Check::DeadImply`             | Warning  | A conditional `imply` made unreachable by an unconditional `imply` of the same symbol. |
| `duplicate_imply`         | `Check::DuplicateImply`        | Warning  | A repeated `imply` of the same symbol (and condition). |
| `dead_range`              | `Check::DeadRange`             | Warning  | A conditional `range` made unreachable by an unconditional `range`. |
| `duplicate_range`         | `Check::DuplicateRange`        | Warning  | A repeated `range` with the same bounds (and condition). |
| `reverse_range`           | `Check::ReverseRange`          | Warning  | A `range` whose lower bound is greater than its upper bound. No valid value exists. |
| `duplicate_dependency`    | `Check::DuplicateDependency`   | Warning  | A dependency listed more than once for the same option. |
| `constant_condition`      | `Check::ConstantCondition`     | Warning  | An `if` condition that is already implied by a dependency, so it is always true or false. |
| `ungrouped_attribute`     | `Check::UngroupedAttribute`    | Style    | Attributes of the same kind that are not kept contiguous. |
| `dead_link`               | `Check::DeadLink`              | Warning  | A URL in `help` text that does not resolve (issues a network request — see below). |
| `failed_parse`            | `Check::FailedParse`           | Fatal    | Emitted internally when `nom-kconfig` cannot parse an input. |

## Installation

```toml
[dependencies]
kconfirm-lib = "0.9"
nom-kconfig = "0.10" # needed to construct the parser input
```

Or:

```sh
cargo add kconfirm-lib nom-kconfig
```

### System requirements

This crate depends on [`curl`](https://crates.io/crates/curl) (used by the `dead_link` check),
which links against the system's TLS stack. On most Linux distributions you will need **OpenSSL**
and **pkg-config** available at build time — e.g. `libssl-dev` and `pkg-config` on Debian/Ubuntu,
or `openssl-devel` and `pkgconf-pkg-config` on Fedora.

The minimum supported Rust version is **1.85.0** (uses the 2024 edition).

## Quick start

Run a few checks against a single Kconfig file and print the results:

```rust,no_run
use kconfirm_lib::{check_kconfig, print_findings, AnalysisArgs, Check};
use nom_kconfig::{KconfigFile, KconfigInput};

fn main() -> std::io::Result<()> {
    // Point at the project root and the entry-point Kconfig file within it
    // (commonly "Kconfig" or "Config.in"). 
    let kconfig_file = KconfigFile::new("path/to/project".into(), "Kconfig".into());
    let contents = kconfig_file.read_to_string()?;
    let input = KconfigInput::new_extra(&contents, kconfig_file);

    // Enable the checks you care about. `AnalysisArgs` starts empty.
    let mut args = AnalysisArgs::new();
    args.enable_check(Check::DeadDefault);
    args.enable_check(Check::DuplicateDependency);
    args.enable_check(Check::ReverseRange);

    // The `Option<String>` is an architecture-specific config option name,
    // used for Linux multi-arch analysis. Use None for the root Kconfig.
    let findings = check_kconfig(args, vec![(None, input)]);

    // Sorts, de-duplicates across architectures, and prints to stdout.
    print_findings(findings);
    Ok(())
}
```

## Working with findings

[`check_kconfig`] returns a `Vec<`[`Finding`]`>`. Rather than calling [`print_findings`], you can
inspect each finding's public fields to integrate the results into your own tooling (e.g. CI output
or JSON):

```rust,no_run
# use kconfirm_lib::Finding;
# let findings: Vec<Finding> = Vec::new();
for finding in &findings {
    println!(
        "{:?} [{}] {:?} ({:?}): {}",
        finding.severity,        // Severity: Style < Warning < Error < Fatal
        finding.check.as_str(),  // stable string id, e.g. "reverse_range"
        finding.symbol,          // Option<String>: the affected config option
        finding.arch,            // Option<String>: affected arch, None = all
        finding.message,         // human-readable description
    );
}
```

[`Severity`] is ordered (`Style < Warning < Error < Fatal`), so findings can be filtered or sorted
by priority.

## Multi-file and multi-architecture analysis

[`check_kconfig`] accepts a `Vec<(Option<String>, KconfigInput)>`. Each entry is one root Kconfig
file paired with the name of the architecture-specific config option it belongs to. This models
the Linux kernel, where the same option can be redefined per architecture: pass the top-level
`Kconfig` with `None`, and each `arch/<arch>/Kconfig` with `Some("X86")`, `Some("ARM64")`, and so
on. The symbol table is shared across all inputs, so identical findings across architectures are collapsed into a single line by [`print_findings`] (e.g. `[x86, arm64]`).

## Feature flags

- `coreboot` *(off by default)* — enables coreboot-specific parsing extensions in `nom-kconfig`.
  Enable it when analyzing coreboot Kconfig:

  ```toml
  kconfirm-lib = { version = "0.9", features = ["coreboot"] }
  ```

## Lower-level API

For callers that need finer control than [`check_kconfig`], the building blocks are public:

- [`analyze`] — traverse already-parsed `nom-kconfig` entries for one architecture, populating a
  [`SymbolTable`] and returning per-definition findings.
- [`SymbolTable`], [`TypeInfo`], [`AttributeDef`], [`ChoiceData`] — the data model describing every
  `config` option, its merged attributes across partial definitions, and `choice` blocks.

## Related crates

- [`kconfirm-cli`](https://github.com/julianbraha/kconfirm) — the command-line front end.
- [`kconfirm-linux`](https://github.com/julianbraha/kconfirm) — for Linux-kernel source-specific quirks.
- [`nom-kconfig`](https://crates.io/crates/nom-kconfig) — the Kconfig parser this crate builds on,
  by [Yann Prono](https://mcdostone.github.io/).

## License

Licensed under [GPL-2.0-only](https://github.com/julianbraha/kconfirm/blob/main/LICENSE).

[`check_kconfig`]: https://docs.rs/kconfirm-lib/latest/kconfirm_lib/fn.check_kconfig.html
[`analyze`]: https://docs.rs/kconfirm-lib/latest/kconfirm_lib/fn.analyze.html
[`print_findings`]: https://docs.rs/kconfirm-lib/latest/kconfirm_lib/fn.print_findings.html
[`parse_check`]: https://docs.rs/kconfirm-lib/latest/kconfirm_lib/fn.parse_check.html
[`AnalysisArgs`]: https://docs.rs/kconfirm-lib/latest/kconfirm_lib/struct.AnalysisArgs.html
[`Finding`]: https://docs.rs/kconfirm-lib/latest/kconfirm_lib/struct.Finding.html
[`Severity`]: https://docs.rs/kconfirm-lib/latest/kconfirm_lib/enum.Severity.html
[`Check`]: https://docs.rs/kconfirm-lib/latest/kconfirm_lib/enum.Check.html
[`Check::as_str`]: https://docs.rs/kconfirm-lib/latest/kconfirm_lib/enum.Check.html#method.as_str
[`SymbolTable`]: https://docs.rs/kconfirm-lib/latest/kconfirm_lib/struct.SymbolTable.html
[`TypeInfo`]: https://docs.rs/kconfirm-lib/latest/kconfirm_lib/struct.TypeInfo.html
[`AttributeDef`]: https://docs.rs/kconfirm-lib/latest/kconfirm_lib/struct.AttributeDef.html
[`ChoiceData`]: https://docs.rs/kconfirm-lib/latest/kconfirm_lib/struct.ChoiceData.html
