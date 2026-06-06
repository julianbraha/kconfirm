// SPDX-License-Identifier: GPL-2.0-only
use nom_kconfig::{
    Entry,
    KconfigInput,
    parse_kconfig, //
};

pub mod output;
use output::*;

pub mod symbol_table;
use symbol_table::*;

mod dead_links;

mod checks;
pub use checks::{
    AnalysisArgs,
    Check,
    check_select_visible,
    check_variable_info,
    parse_check, //
};

mod analyze;
use analyze::analyze;

/// Runs the specified checks on raw Kconfig files.
/// In the case of Linux, architectures can be specified in the
/// `kconfig_files` argument.
///
/// # Examples
///
/// ## Analyze Linux (x86 architecture)
/// ```
/// let mut my_checks = AnalysisArgs::new();
/// my_checks.enable_check(Check::SelectVisible);
/// let root_kconfig_path = PathBuf::from("Kconfig");
/// let root_kconfig_file = KconfigFile::new(linux_source_dir, root_kconfig_path);
/// let kconfig_input = KconfigInput::new_extra(&root_kconfig_file.read_to_string()?, root_kconfig_file);
/// let x86_arch = String::from(X86);
/// let kconfig_files = vec![Some(x86_arch), kconfig_input];
/// let findings = check_kconfig(my_checks, root_kconfig_file);
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
