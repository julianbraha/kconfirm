// SPDX-License-Identifier: GPL-2.0-only
pub mod output;
use output::*;

pub mod symbol_table;
use symbol_table::*;

mod dead_links;

mod analyze;
use analyze::*;

use log::{error, info};
use nom_kconfig::Entry;
use nom_kconfig::Symbol;
use nom_kconfig::attribute::AndExpression;
use nom_kconfig::attribute::Atom;
use nom_kconfig::attribute::Expression;
use nom_kconfig::attribute::Term;
use nom_kconfig::{KconfigInput, parse_kconfig};
use std::collections::HashSet;

#[derive(Clone)]
pub struct AnalysisArgs {
    // check for duplicate default values
    pub check_style: bool,

    // check for dead links in the help texts
    pub check_dead_links: bool,
}

// TODO: caller of check_kconfig makes this call:
//
//  `let kconfig_files = collect_kconfig_root_files(linux_root);`

pub fn check_kconfig(
    args: AnalysisArgs,
    kconfig_files: Vec<(Option<String>, KconfigInput)>, // for linux, the config options in the kconfig file all depend on the architecture's config option
) -> Vec<Finding> {
    // will store detected kconfig issues, to be printed one line at a time at the end
    let mut findings = Vec::new();

    let mut symbol_table = SymbolTable::new();

    for (arch_config_option, kconfig_file) in kconfig_files {
        let kconfig_parse_result = parse_kconfig(kconfig_file);

        // process the kconfig entries that we parsed from the root kconfig file:
        if let Ok(parsed_kconfig_file) = kconfig_parse_result {
            let entries: Vec<Entry> = parsed_kconfig_file.1.entries;

            match arch_config_option {
                Some(aco) => {
                    let arch_config_option_expression = Expression::Term(AndExpression::Term(
                        Term::Atom(Atom::Symbol(Symbol::NonConstant(aco.to_owned()))),
                    ));
                    info!("aco: {}", aco);
                    for entry in entries {
                        let cur_findings = entry_processor(
                            &args,
                            &mut symbol_table,
                            entry,
                            Vec::new(),
                            Vec::new(),
                            Vec::from([arch_config_option_expression.clone()]), // every config option in the arch kconfig file depends on the arch config option
                            false, // we don't start in a choice.
                        );

                        findings.extend(cur_findings);
                    }
                }
                None => {
                    for entry in entries {
                        let cur_findings = entry_processor(
                            &args,
                            &mut symbol_table,
                            entry,
                            Vec::new(),
                            Vec::new(),
                            Vec::new(),
                            false, // we don't start in a choice.
                        );
                        findings.extend(cur_findings);
                    }
                }
            }
        } else if let Err(e) = kconfig_parse_result {
            error!("FATAL: failed to parse kconfig, error is {:?}", e);
        }
    }

    let inner_symtab = symbol_table.raw;

    let mut all_vars = Vec::new();

    for type_info_ref in inner_symtab.iter() {
        let var_symbol = type_info_ref.0;
        all_vars.push(var_symbol.clone());

        for kconfig_redefinition in &type_info_ref.1.variable_info {
            let mut all_dependencies =
                HashSet::with_capacity(kconfig_redefinition.kconfig_dependencies.len());
            for dep in &kconfig_redefinition.kconfig_dependencies {
                if is_duplicate(&mut all_dependencies, dep.to_string()) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: "duplicate_dependency",
                        symbol: Some(var_symbol.clone()),
                        message: format!("duplicate dependency on {:?}", dep.to_string()),
                    });
                }
            }

            let mut all_range_conditions = HashSet::new();

            // TODO: consider an optional check for multiple ranges of the same value, but different conditions (style lint)
            let mut already_unconditional_range = false;
            for range in &kconfig_redefinition.kconfig_ranges {
                // check for ranges that follow and unconditional one
                if already_unconditional_range {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: "dead_range",
                        symbol: Some(var_symbol.clone()),
                        message: format!("dead range of {:?}", range),
                    });
                }

                // check for multiple ranges with the same condition
                if let Some(f) = range.r#if.clone() {
                    if is_duplicate(&mut all_range_conditions, f.to_string()) {
                        findings.push(Finding {
                            severity: Severity::Warning,
                            check: "dead_range",
                            symbol: Some(var_symbol.clone()),
                            message: format!("dead range of {:?}", range),
                        });
                    }
                }

                if range.r#if.is_none() {
                    already_unconditional_range = true;
                }
            }

            let mut all_selects = HashSet::with_capacity(kconfig_redefinition.selects.len());

            // TODO: cleanup this code (especially the clones, and the if-handling)
            for select in &kconfig_redefinition.selects {
                let select_var = select.clone().0;
                if let Some(select_cond) = &select.1 {
                    if is_duplicate(&mut all_selects, (select_var, select_cond.to_string())) {
                        findings.push(Finding {
                            severity: Severity::Warning,
                            check: "duplicate_select",
                            symbol: Some(var_symbol.clone()),
                            message: format!("duplicate select of {:?}", select),
                        });
                    }
                } else {
                    // style check:
                    //       - select X if Y
                    //       - select X if Z
                    //         (could just be `select X if Y || Z`)

                    if is_duplicate(&mut all_selects, (select_var, String::new())) {
                        findings.push(Finding {
                            severity: Severity::Warning,
                            check: "duplicate_select",
                            symbol: Some(var_symbol.clone()),
                            message: format!("duplicate select of {:?}", select),
                        });
                    }
                }
            }

            let mut already_unconditional_default = false;

            // TODO: do we want to use the `with_capacity` initializer with `kconfig_redefinition.kconfig_defaults`?
            let mut all_default_ifs = HashSet::new();

            // only used when style checks are enabled, consider wrapping this in Option
            let mut all_default_vals = HashSet::new();

            for default_and_if in &kconfig_redefinition.kconfig_defaults {
                if already_unconditional_default {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: "dead_default",
                        symbol: Some(var_symbol.clone()),
                        message: format!(
                            "dead default of {}",
                            default_and_if.expression.to_string()
                        ),
                    });
                }

                if args.check_style {
                    let default_val = default_and_if.expression.to_string();

                    if is_duplicate(&mut all_default_vals, default_val.to_string()) {
                        findings.push(Finding {
                            severity: Severity::Style,
                            check: "duplicate_default_value",
                            symbol: Some(var_symbol.clone()),
                            message: format!("duplicate default value of {:?}", default_val),
                        });
                    }
                }

                let default_cond = &default_and_if.r#if;

                // TODO: can we use a reference to default_cond?
                if let Some(d) = default_cond {
                    // OrExpression doesn't implement `Eq` so we convert it to a string first.

                    if is_duplicate(&mut all_default_ifs, d.to_string()) {
                        findings.push(Finding {
                            severity: Severity::Warning,
                            check: "duplicate_default",
                            symbol: Some(var_symbol.clone()),
                            message: format!("duplicate default condition of {:?}", d),
                        });
                    }
                }

                let unconditional_default = default_cond.is_none();

                if unconditional_default {
                    already_unconditional_default = true;
                }
            }
        }
    }
    findings
}
