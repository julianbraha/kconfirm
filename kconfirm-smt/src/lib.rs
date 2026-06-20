use kconfirm_lib::{AnalysisArgs, Check, Finding, Severity, SymbolTable, analyze};
use kconfirm_linux::collect_kconfig_root_files;

use nom_kconfig::{Entry, KconfigInput, parse_kconfig};
use std::path::PathBuf;
use z3::ast::Bool as z3_bool;
use z3::ast::Int as z3_int;
use z3::ast::String as z3_string;

use crate::kconfig_to_smt::model_kconfig_type;

mod kconfig_to_smt;

pub fn model_kconfig(path: PathBuf) {
    let all_archs: Vec<String> = kconfirm_linux::ALL_ARCHITECTURES
        .into_iter()
        .map(|x| x.to_owned())
        .collect();
    let kconfig_files = collect_kconfig_root_files(all_archs, path).unwrap();
    let kconfig_inputs: Vec<(Option<String>, KconfigInput)> = kconfig_files
        .iter()
        .map(|kconfig| {
            let kconfig_input =
                KconfigInput::new_extra(&kconfig.file_contents, kconfig.kconfig_file.clone());
            (Some(kconfig.arch_config_option.clone()), kconfig_input)
        })
        .collect();

    let mut findings = Vec::new();
    let mut symbol_table = SymbolTable::new();

    for (arch_config_option, kconfig_file) in kconfig_inputs {
        match parse_kconfig(kconfig_file) {
            Ok(parsed) => {
                let entries: Vec<Entry> = parsed.1.entries;

                let args = AnalysisArgs::new();

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

    // convert the kconfig types to z3 types
    for (symbol, mut kconfig_type_info) in symbol_table.raw {
        let kconfig_type = kconfig_type_info.kconfig_type;

        if let Some(t) = kconfig_type {
            let z3_type = model_kconfig_type(symbol, &t);
            kconfig_type_info.z3_type = Some(z3_type);
        }
    }
}
