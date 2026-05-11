// SPDX-License-Identifier: GPL-2.0-only
pub mod output;
use output::*;

pub mod symbol_table;
use symbol_table::*;

mod dead_links;

mod checks;
pub use checks::{AnalysisArgs, Check, check_variable_info, parse_check};

mod analyze;
use analyze::*;

use log::error;
use nom_kconfig::Entry;

use nom_kconfig::{KconfigInput, parse_kconfig};

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
                error!("FATAL: failed to parse kconfig, error is {:?}", e);
                panic!();
            }
        }
    }

    for (var_symbol, type_info) in &symbol_table.raw {
        for (arch_specific, redefinitions) in &type_info.variable_info {
            for (_definition_condition, info) in redefinitions {
                findings.extend(check_variable_info(&args, var_symbol, arch_specific, info));
            }
        }
    }

    findings
}
