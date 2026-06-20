// SPDX-License-Identifier: GPL-2.0-only
#![doc = include_str!("../README.md")]
mod analyze;
mod checks;
mod dead_links;
pub mod output;
mod symbol_table;

use nom_kconfig::{
    Entry,
    KconfigInput,
    parse_kconfig, //
};

pub use analyze::analyze;
pub use checks::{
    AnalysisArgs,
    Check,
    parse_check, //
};
use checks::{
    check_select_visible,
    check_variable_info, //
};
pub use output::{
    Finding,
    Severity,
    print_findings, //
};
pub use symbol_table::*;

/// Runs the specified checks on raw Kconfig files.
/// In the case of Linux, architectures can be specified in the
/// `kconfig_files` argument.
///
/// # Examples
///
/// ## Analyze a Kconfig tree
/// ```no_run
/// use kconfirm_lib::{check_kconfig, print_findings, AnalysisArgs, Check};
/// use nom_kconfig::{KconfigFile, KconfigInput};
///
/// # fn main() -> std::io::Result<()> {
/// let mut checks = AnalysisArgs::new();
/// checks.enable_check(Check::SelectVisible);
///
/// // Load the root Kconfig of the project under analysis.
/// let kconfig_file = KconfigFile::new("linux".into(), "Kconfig".into());
/// let contents = kconfig_file.read_to_string()?;
/// let input = KconfigInput::new_extra(&contents, kconfig_file);
///
/// // Pair each input with an optional architecture-specific config option
/// // (e.g. `Some("X86".to_string())` for `arch/x86/Kconfig`); use `None` when
/// // the input is not architecture-specific.
/// let findings = check_kconfig(checks, vec![(None, input)]);
/// print_findings(findings);
/// # Ok(())
/// # }
/// ```
pub fn check_kconfig(
    args: AnalysisArgs,
    kconfig_files: Vec<(Option<String>, KconfigInput)>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut symbol_table = SymbolTable::new();

    for (arch_config_option, kconfig_file) in kconfig_files {
        match parse_kconfig(kconfig_file) {
            Ok(parsed) => {
                let entries: Vec<Entry> = parsed.1.entries;
                findings.extend(analyze(
                    &args,
                    &mut symbol_table,
                    arch_config_option,
                    entries,
                ));
            }
            Err(e) => {
                findings.push(Finding {
                    severity: Severity::Fatal,
                    check: Check::FailedParse,
                    symbol: None,
                    message: format!("Failed to parse kconfig, error is: {}", e),
                    arch: None,
                });
            }
        }
    }

    for (var_symbol, type_info) in &symbol_table.raw {
        for (arch_specific, redefinitions) in &type_info.attribute_defs {
            for (_definition_condition, info) in redefinitions {
                findings.extend(check_variable_info(&args, var_symbol, arch_specific, info));
            }
        }

        if args.is_enabled(Check::SelectVisible) {
            findings.extend(check_select_visible(var_symbol, type_info));
        }
    }

    findings
}
