use kconfirm_desugar::desugar_kconfig;
use kconfirm_lib::Z3Types;
use nom_kconfig::{Entry, KconfigInput, entry::Source, parse_kconfig};
use std::collections::HashMap;
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

    let mut new_symtab = HashMap::new();

    // convert the kconfig types to z3 types
    for (symbol, kconfig_type_info) in &mut symbol_table.raw {
        //let kconfig_type = kconfig_type_info.kconfig_type;

        if let Some(t) = &kconfig_type_info.kconfig_type {
            let z3_type = model_kconfig_type(symbol, t);
            //kconfig_type_info.z3_type = Some(z3_type);

            let mut new_kconfig_type_info = kconfig_type_info.clone();
            new_kconfig_type_info.z3_type = Some(z3_type);
            new_symtab.insert(symbol.clone(), new_kconfig_type_info);
        } else {
            println!("symbol doesn't have a kconfig type!");
            //panic!("symbol doesn't have a kconfig type:{}", symbol);
            //symbol_table.raw.remove(symbol);
        }
    }

    drop(symbol_table.raw);

    // convert the dependencies to z3 expressions
    for (symbol, type_info) in new_symtab.clone() {
        //symbol_table.raw.clone() {
        let mut all_enabled_conditions: Vec<z3_bool> = Vec::new();

        let z3_type = type_info
            .z3_type
            .expect("already converted all kconfig types to z3");

        println!("enabling current symbol:{:?}", z3_type);
        let cur_symbol_enabled_z3 = z3_type.enabled();

        // we're going to set all of these in the upcoming loop
        let mut visibility_z3 = None; // if this remains None (never gets set to Some) then it's never visible
        let mut dependencies_z3 = None; // if this remains None then it has no dependencies (always sat)
        let mut selected_by_z3 = Vec::new(); // if this remains None then it has no selectors
        let mut implied_by_z3 = Vec::new(); // if this remains None then it has no impliors
        //let mut defaults_z3 = None; // if this remains None then it has no defaults

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

                // just an alias for the selector-selectee context
                let selector_enabled = cur_symbol_enabled_z3.clone();

                for (selectee, select_condition) in selects {
                    match new_symtab.get(&selectee) {
                        // symbol_table.raw.get(&selectee) {
                        None => {
                            println!("selectee does not exist: {}", selectee);
                            continue; // onto the next selectee
                        }
                        Some(selectee_type_info) => {
                            // the selectee exists (is defined for this arch, is not a dangling reference):
                            if let Some(selectee_z3) = selectee_type_info.z3_type.as_ref() {
                                println!(
                                    "enabling selectee:{:?}",
                                    selectee_type_info.z3_type.as_ref()
                                );
                                let selectee_enabled = selectee_z3.enabled();
                                // conditional select
                                if let Some(sel_cond) = select_condition {
                                    let select_condition_z3 =
                                        model_kconfig_or_expr(&new_symtab, sel_cond) //&symbol_table.raw, sel_cond)
                                            ;

                                    let selector_enabled_and_select_condition_true =
                                        z3_bool::and(&[
                                            selector_enabled.clone(),
                                            select_condition_z3,
                                        ]);

                                    solver.assert(
                                        selector_enabled_and_select_condition_true
                                            .implies(selectee_enabled),
                                    );
                                } else {
                                    // unconditional select
                                    solver.assert(selector_enabled.implies(selectee_enabled));
                                }
                            } else {
                                continue; // onto the next selectee
                            }
                        }
                    }
                }

                // convert the kconfig dependencies into a z3 formula.
                // kconfirm-desugar combines all dependencies into a single
                // condition, so there is at most one here.
                dbg!(&attributes.kconfig_dependencies);
                let z3_dependencies = attributes.kconfig_dependencies.as_ref().map(
                    |deps| kconfig_to_smt::model_kconfig_or_expr(&new_symtab, deps.to_owned()), //&symbol_table.raw, deps.to_owned())
                );

                // get the selected-by constraint (we will OR-this with the dependencies)

                /*
                 * notes on visibility:
                 * 1. is affected by its prompt.
                 * 2. NOT affected by 'if..endif'
                 * 3. is affected by choice and menu (i think)
                 */
                let visibility = attributes.visibility;

                if visibility.is_none() {
                    dbg!(&visibility);
                }

                match visibility {
                    // Visibility:None means that it has no prompt (always invisible)

                    // Visibility:None means that it has no prompt (always invisible)
                    // - TODO: affected by implies and defaults
                    None => {
                        // visibility stays none for now...
                        // NOTE: the prompt could be in a second partial definition in the next iteration of the loop
                    }

                    Some(vis) => {
                        let vis_z3 = kconfig_to_smt::model_kconfig_or_expr(&new_symtab, vis); //&symbol_table.raw, vis);
                        visibility_z3 = Some(vis_z3.clone());
                        all_enabled_conditions.push(vis_z3);
                    }
                }

                match z3_dependencies {
                    // dependencies:None means that it has no dependencies (always satisfied)
                    None => {
                        // dependencies stays none for now...
                        // NOTE: the dependencies could be in a second partial definition in the next iteration of the loop
                    }

                    Some(dep) => {
                        dependencies_z3 = Some(dep);
                    }
                }

                // NOTE: IMPLY IS PRIORITIZED OVER DEFAULT
                //[ DEPS && !VIS ] -> implies or defaults (which takes priority?)
                //todo!("i think we need to be capturing the impliers in the implyees entries, like we do for select. let's see...");
                let defaults = attributes.kconfig_defaults;
                let implies = attributes.implies;
                //todo!("need to use the visibility condition with implies and defaults");

                // only matters for int, hex
                // TODO: alarm is this is used for other types!
                let ranges = attributes.kconfig_ranges;
                //todo!("find the range bound conversion code from the old version of this");
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

            let selector_z3 = //symbol_table.raw
                new_symtab
                .get(&selector)
                .expect("selector exists (not a dangling reference)")
                .z3_type
                .as_ref()
                .expect("already converted all kconfig types to z3");

            println!("enabling selector:{:?}", selector_z3);
            let selector_enabled = selector_z3.enabled();
            for (arch, select_condition) in archs_and_conditions {
                if arch.clone() == Some(ENABLED_ARCH.clone()) || arch.clone() == None {
                    // conditional select: combine the selector's enablement condition with select condition
                    if let Some(cond) = select_condition {
                        let select_condition_z3 = model_kconfig_or_expr(&new_symtab, cond.clone()); //&symbol_table.raw, cond.clone());

                        // selected_by vector no longer empty here:
                        selected_by_z3.push(select_condition_z3.clone());

                        all_enabled_conditions.push(z3_bool::and(&[
                            selector_enabled.clone(),
                            select_condition_z3, // actually we expect this to be a z3_bool
                        ]))
                    } else {
                        // unconditional select under the current architecture
                        all_enabled_conditions.push(selector_enabled.clone());
                    }
                }
            }
        }

        // this loop is for handling all config options that imply the current option
        for (implicator, archs_and_conditions) in type_info.implied_by {
            // config X
            //    imply Y (if Z)
            //
            // becomes z3 assertions:
            //
            // conditional: X.enabled() && Z -> Y
            // unconditional: X.enabled() -> Y

            let implicator_z3 = new_symtab
                .get(&implicator)
                .expect("selector exists (not a dangling reference)")
                .z3_type
                .as_ref()
                .expect("already converted all kconfig types to z3");

            let implicator_enabled = implicator_z3.enabled();
            for (arch, imply_condition) in archs_and_conditions {
                if arch.clone() == Some(ENABLED_ARCH.clone()) || arch.clone() == None {
                    // conditional select: combine the selector's enablement condition with select condition
                    if let Some(cond) = imply_condition {
                        let imply_condition_z3 = model_kconfig_or_expr(&new_symtab, cond.clone()); //&symbol_table.raw, cond.clone());

                        // selected_by vector no longer empty here:
                        implied_by_z3.push(imply_condition_z3.clone());

                        all_enabled_conditions.push(z3_bool::and(&[
                            implicator_enabled.clone(),
                            imply_condition_z3, // actually we expect this to be a z3_bool
                        ]))
                    } else {
                        // unconditional select under the current architecture
                        all_enabled_conditions.push(implicator_enabled.clone());
                    }
                }
            }
        }

        // so now "all_enablement_conditions" includes selectors
        // we also need dependencies && [visible / defaults]

        // at this point, all_enabled_conditions is full of all the possible situations where
        //    the current config option can be enabled. need to OR them together with the enabled expression.

        let at_least_one_enabled_condition = z3_bool::or(&all_enabled_conditions);

        let enabled_when_a_condition_met =
            cur_symbol_enabled_z3.implies(at_least_one_enabled_condition);
        solver.assert(enabled_when_a_condition_met);
    }

    dbg!(solver.check());
}
