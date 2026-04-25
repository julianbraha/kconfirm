// SPDX-License-Identifier: GPL-2.0-only
pub mod output;
use output::*;

pub mod symbol_table;
use symbol_table::*;

mod dead_links;

mod analyze;
use analyze::*;

use log::error;
use nom_kconfig::Entry;

use nom_kconfig::{KconfigInput, parse_kconfig};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Check {
    Style,     // check for duplicate default values, and ungrouped attributes
    DeadLinks, // check for dead links in the help texts
    DuplicateDependency,
    DeadRange,
    DeadSelect,
    DuplicateSelect,
    DeadDefault,
    DuplicateDefault,
}

pub fn parse_check(name: &str) -> Option<Check> {
    match name {
        "style" => Some(Check::Style),
        "dead_links" => Some(Check::DeadLinks),
        "duplicate_dependency" => Some(Check::DuplicateDependency),
        "dead_range" => Some(Check::DeadRange),
        "dead_select" => Some(Check::DeadSelect),
        "duplicate_select" => Some(Check::DuplicateSelect),
        "dead_default" => Some(Check::DeadDefault),
        "duplicate_default" => Some(Check::DuplicateDefault),
        _ => None,
    }
}

#[derive(Clone)]
pub struct AnalysisArgs {
    // check for duplicate default values
    pub enabled_checks: HashSet<Check>,
}

impl AnalysisArgs {
    pub fn is_enabled(&self, check: Check) -> bool {
        self.enabled_checks.contains(&check)
    }
}

pub fn check_kconfig(
    args: AnalysisArgs,
    kconfig_files: Vec<(Option<String>, KconfigInput)>, // for linux, the config options in the kconfig file are only defined if the architecture's config option is enabled
) -> Vec<Finding> {
    // will store detected kconfig issues, to be printed one line at a time at the end
    let mut findings = Vec::new();

    let mut symbol_table = SymbolTable::new();

    for (arch_config_option, kconfig_file) in kconfig_files {
        let kconfig_parse_result = parse_kconfig(kconfig_file);

        // process the kconfig entries that we parsed from the root kconfig file:
        if let Ok(parsed_kconfig_file) = kconfig_parse_result {
            let entries: Vec<Entry> = parsed_kconfig_file.1.entries;

            let cur_findings = analyze(&args, &mut symbol_table, arch_config_option, entries);
            findings.extend(cur_findings);
        } else if let Err(e) = kconfig_parse_result {
            error!("FATAL: failed to parse kconfig, error is {:?}", e);
            panic!();
        }
    }

    let inner_symtab = symbol_table.raw;

    let mut all_vars = Vec::new();

    for (var_symbol, type_info_ref) in inner_symtab.iter() {
        all_vars.push(var_symbol.clone());

        for (arch_specific, kconfig_redefinitions) in &type_info_ref.variable_info {
            // NOTE: the definition condition is currently unused, but will be needed for SMT solving later.
            for (_definition_condition, kconfig_redefinition) in kconfig_redefinitions {
                let mut all_dependencies =
                    HashSet::with_capacity(kconfig_redefinition.kconfig_dependencies.len());
                for dep in &kconfig_redefinition.kconfig_dependencies {
                    if is_duplicate(&mut all_dependencies, dep.to_string()) {
                        let message = if let Some(cur_arch) = &arch_specific {
                            format!(
                                "duplicate dependency on {:?} for architecture {:?}",
                                dep.to_string(),
                                cur_arch
                            )
                        } else {
                            format!("duplicate dependency on {:?}", dep.to_string())
                        };

                        findings.push(Finding {
                            severity: Severity::Warning,
                            check: "duplicate_dependency",
                            symbol: Some(var_symbol.clone()),
                            message,
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
                        if all_selects.contains(&(select_var.clone(), String::new())) {
                            findings.push(Finding {
                                severity: Severity::Warning,
                                check: "dead_select",
                                symbol: Some(var_symbol.clone()),
                                message: format!("dead select of {:?}", select),
                            });
                        }

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
                            message: format!("dead default of {}", default_and_if.expression),
                        });
                    }

                    if args.is_enabled(Check::Style) {
                        let default_val = default_and_if.expression.to_string();

                        if is_duplicate(&mut all_default_vals, default_val.to_string()) {
                            findings.push(Finding {
                                severity: Severity::Style,
                                check: "duplicate_default_value",
                                symbol: Some(var_symbol.clone()),
                                message: format!("duplicate default value of {:?}; consider combining the conditions with a logical-or: ||", default_val),
                            });
                        }
                    }

                    let default_cond = &default_and_if.r#if;

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
    }
    findings
}
