use kconfirm_desugar::desugar_kconfig;
use nom_kconfig::{Entry, KconfigInput, entry::Source, parse_kconfig};
use std::path::PathBuf;
use z3::DeclKind::PbAtLeast;
use z3::Solver;
use z3::SortKind::Bool;
use z3::ast::Bool as z3_bool;
use z3::ast::Int as z3_int;
use z3::ast::String as z3_string;

use kconfig_to_smt::model_kconfig_type;
use kconfirm_lib::{AnalysisArgs, Check, Finding, Severity, SymbolTable, analyze};
use kconfirm_linux::ALL_ARCHITECTURES;
use kconfirm_linux::collect_kconfig_root_files;

use crate::kconfig_to_smt::model_kconfig_or_expr;

mod kconfig_to_smt;

pub fn model_kconfig(path: PathBuf) {
    /*let all_archs: Vec<String> = kconfirm_linux::ALL_ARCHITECTURES
        .into_iter()
        .map(|x| x.to_owned())
        .collect();
    let kconfig_files = collect_kconfig_root_files(all_archs, path).unwrap();*/

    // NOTE: just x86 for now
    let ENABLED_ARCH = String::from("x86");
    let kconfig_files = collect_kconfig_root_files(vec![ENABLED_ARCH.clone()], path).unwrap();
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
                // run the desugaring passes before constructing the symbol table
                let source = Source {
                    kconfigs: vec![parsed.1],
                };
                let entries: Vec<Entry> = desugar_kconfig(source);

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

    let solver = Solver::new();

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
        let mut all_enabled_conditions: Vec<z3_bool> = Vec::new();

        // here we add the constraint that this option (symbol) implies whatever it selects in kconfig
        //
        // this loop is for handling all of the current config option's attributes
        for (arch, config_definitions) in type_info.attribute_defs {
            for (config_definition_condition, attributes) in config_definitions {
                /*
                 * enabling the option implies its dependencies are satisfied(and it's visible OR that's a default) OR it's selected
                 *
                 */

                /*
                 * we might need two implications for select?
                 * 1. enabling the selector IMPLIES its selectee (we can definitely make this a constraint!)
                 * 2. if the selectee is enabled, then it must have been because it was selected, or visible&dependencies/nonvisible&default
                 *
                 * if we don't do 1:
                 * - then the selectee just doesn't have to be enabled when the selector is enabled.
                 * if we don't do 2:
                 * - then there is no unmet dependency support.
                 *
                 * enabling the dependency doesn't imply its dependents.
                 * but enabling the dependent might imply its dependencies (if no unmet-dep bug)
                 *
                 */

                let selects = attributes.selects;

                let selector_enabled = type_info
                    .z3_type
                    .expect("already converted all kconfig types to z3")
                    .enabled();

                for (selectee, select_condition) in selects {
                    match symbol_table.raw.get(&selectee) {
                        None => panic!(
                            "selectee does not exist under any architecture: {}",
                            selectee
                        ),
                        Some(selectee_type_info) => {
                            let selectee_enabled = selectee_type_info
                                .z3_type
                                .as_ref()
                                .expect("already converted all kconfig types to z3")
                                .enabled();

                            // conditional select
                            if let Some(sel_cond) = select_condition {
                                let select_condition_z3 =
                                    model_kconfig_or_expr(&symbol_table.raw, sel_cond)
                                        .expect("dunno why this is an option")
                                        .enabled();

                                let selector_enabled_and_select_condition_true =
                                    z3_bool::and(&[selector_enabled.clone(), select_condition_z3]);

                                solver.assert(
                                    selector_enabled_and_select_condition_true
                                        .implies(selectee_enabled),
                                );
                            } else {
                                // unconditional select
                                solver.assert(selector_enabled.implies(selectee_enabled));
                            }
                        }
                    }
                }

                // convert the kconfig dependencies into a z3 formula.
                // kconfirm-desugar combines all dependencies into a single
                // condition, so there is at most one here.
                let z3_dependencies = attributes
                    .kconfig_dependencies
                    .as_ref()
                    .and_then(|deps| {
                        kconfig_to_smt::model_kconfig_or_expr(&symbol_table.raw, deps.to_owned())
                    })
                    .expect("why is this an option");

                // get the selected-by constraint (we will OR-this with the dependencies)

                /*
                 * notes on visibility:
                 * 1. is affected by its prompt.
                 * 2. NOT affected by 'if..endif'
                 * 3. is affected by choice and menu (i think)
                 */
                let visibility = attributes.visibility;
                todo!("can a desugaring pass simplify visibility to a single condition?");

                //let visible_and_depends_sat =

                let defaults = attributes.kconfig_defaults;
                let implies = attributes.implies;
                todo!("need to use the visibility condition with implies and defaults");

                // only matters for int, hex
                // TODO: alarm is this is used for other types!
                let ranges = attributes.kconfig_ranges;
                todo!("find the range bound conversion code from the old version of this");
            }
        }

        // this loop is for handling the current config option's selectors
        for (selector, archs_and_conditions) in type_info.selected_by {
            // config X
            //    selects Y (if Z)
            //
            // becomes z3 assertions:
            //
            // conditional: X.enabled() && Z -> Y
            // unconditional: X.enabled() -> Y

            let selector_z3 = symbol_table
                .raw
                .get(&selector)
                .expect("selector exists (not a dangling reference)")
                .z3_type
                .as_ref()
                .expect("already converted all kconfig types to z3");

            let selector_enabled = selector_z3.enabled();
            for (arch, select_condition) in archs_and_conditions {
                if arch.clone() == Some(ENABLED_ARCH.clone()) || arch.clone() == None {
                    // conditional select: combine the selector's enablement condition with select condition
                    if let Some(cond) = select_condition {
                        let select_condition_z3 =
                            model_kconfig_or_expr(&symbol_table.raw, cond.clone());
                        all_enabled_conditions.push(z3_bool::and(&[
                            selector_enabled.clone(),
                            (select_condition_z3.unwrap().enabled()), // actually we expect this to be a z3_bool
                        ]))
                    } else {
                        // unconditional select under the current architecture
                        all_enabled_conditions.push(selector_enabled.clone());
                    }
                }
            }
        }

        // so now "all_enablement_conditions" includes selectors
        // we also need dependencies && [visible / defaults]
    }
}
