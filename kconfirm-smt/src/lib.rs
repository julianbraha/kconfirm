use nom_kconfig::{Entry, KconfigInput, parse_kconfig};
use std::path::PathBuf;
use z3::DeclKind::PbAtLeast;
use z3::ast::Bool as z3_bool;
use z3::ast::Int as z3_int;
use z3::ast::String as z3_string;

use kconfig_to_smt::model_kconfig_type;
use kconfirm_lib::{AnalysisArgs, Check, Finding, Severity, SymbolTable, analyze};
use kconfirm_linux::collect_kconfig_root_files;

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
    for (symbol, kconfig_type_info) in &mut symbol_table.raw {
        //let kconfig_type = kconfig_type_info.kconfig_type;

        if let Some(t) = &kconfig_type_info.kconfig_type {
            let z3_type = model_kconfig_type(symbol, t);
            kconfig_type_info.z3_type = Some(z3_type);
        }
    }

    // convert the dependencies to z3 expressions
    for (symbol, type_info) in symbol_table.raw.clone() {
        for (arch, config_definitions) in type_info.attribute_defs {
            for (config_definition_condition, attributes) in config_definitions {
                // convert the kconfig dependencies into a z3 formula
                assert!(attributes.kconfig_dependencies.len() == 1); // should have desugared
                let kconfig_dependencies = &attributes.kconfig_dependencies[0];
                let z3_dependencies = kconfig_to_smt::model_kconfig_or_expr(
                    &symbol_table.raw,
                    kconfig_dependencies.to_owned(),
                );

                let selects = attributes.selects;
                todo!("need to model select conditions as z3");

                /*
                 * notes on visibility:
                 * 1. is affected by its prompt.
                 * 2. NOT affected by 'if..endif'
                 * 3. is affected by choice and menu (i think)
                 */
                let visibility = attributes.visibility;
                todo!("can a desugaring pass simplify visibility to a single condition?");

                let defaults = attributes.kconfig_defaults;
                let implies = attributes.implies;
                todo!("need to use the visibility condition with implies and defaults");

                // only matters for int, hex
                // TODO: alarm is this is used for other types!
                let ranges = attributes.kconfig_ranges;
                todo!("find the range bound conversion code from the old version of this");
            }
        }
    }
}
