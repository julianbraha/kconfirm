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
    DuplicateRange,
    DuplicateSelect,
    DeadDefault,
    DuplicateDefault,
}

impl Check {
    pub fn as_str(self) -> &'static str {
        match self {
            Check::Style => "style",
            Check::DeadLinks => "dead_links",
            Check::DuplicateDependency => "duplicate_dependency",
            Check::DuplicateRange => "dead_range",
            Check::DuplicateSelect => "duplicate_select",
            Check::DeadDefault => "dead_default",
            Check::DuplicateDefault => "duplicate_default",
        }
    }
}

pub fn parse_check(name: &str) -> Option<Check> {
    match name {
        "style" => Some(Check::Style),
        "dead_links" => Some(Check::DeadLinks),
        "duplicate_dependency" => Some(Check::DuplicateDependency),
        "dead_range" => Some(Check::DuplicateRange),
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

fn check_duplicate_dependencies(
    var_symbol: &str,
    info: &VariableInfo,
    arch_specific: &Option<String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for dep in &info.kconfig_dependencies {
        if is_duplicate(&mut seen, dep.to_string()) {
            let message = match arch_specific {
                Some(arch) => format!(
                    "duplicate dependency on {:?} for architecture {:?}",
                    dep.to_string(),
                    arch
                ),
                None => format!("duplicate dependency on {:?}", dep.to_string()),
            };
            findings.push(Finding {
                severity: Severity::Warning,
                check: Check::DuplicateDependency.as_str(),
                symbol: Some(var_symbol.to_owned()),
                message,
            });
        }
    }

    findings
}

fn check_dead_ranges(var_symbol: &str, info: &VariableInfo) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen_conditions = HashSet::new();
    let mut already_unconditional = false;

    for range in &info.kconfig_ranges {
        if already_unconditional {
            findings.push(Finding {
                severity: Severity::Warning,
                check: Check::DuplicateRange.as_str(),
                symbol: Some(var_symbol.to_owned()),
                message: format!("dead range of {:?}", range),
            });
            continue;
        }

        if let Some(cond) = range.r#if.clone() {
            if is_duplicate(&mut seen_conditions, cond.to_string()) {
                findings.push(Finding {
                    severity: Severity::Warning,
                    check: Check::DuplicateRange.as_str(),
                    symbol: Some(var_symbol.to_owned()),
                    message: format!("dead range of {:?}", range),
                });
            }
        } else {
            already_unconditional = true;
        }
    }

    findings
}

fn check_duplicate_selects(var_symbol: &str, info: &VariableInfo) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for select in &info.selects {
        let select_var = select.0.clone();

        match &select.1 {
            Some(cond) => {
                // A conditional select is dead if the same var is already selected unconditionally.
                if seen.contains(&(select_var.clone(), String::new())) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: "dead_select",
                        symbol: Some(var_symbol.to_owned()),
                        message: format!("dead select of {:?}", select),
                    });
                }

                if is_duplicate(&mut seen, (select_var, cond.to_string())) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: Check::DuplicateSelect.as_str(),
                        symbol: Some(var_symbol.to_owned()),
                        message: format!("duplicate select of {:?}", select),
                    });
                }
            }
            None => {
                if is_duplicate(&mut seen, (select_var, String::new())) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: Check::DuplicateSelect.as_str(),
                        symbol: Some(var_symbol.to_owned()),
                        message: format!("duplicate select of {:?}", select),
                    });
                }
            }
        }
    }

    findings
}

fn check_defaults(var_symbol: &str, info: &VariableInfo, style_enabled: bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen_conditions = HashSet::new();
    let mut seen_values = HashSet::new();
    let mut already_unconditional = false;

    for default in &info.kconfig_defaults {
        let val_str = default.expression.to_string();

        if already_unconditional {
            findings.push(Finding {
                severity: Severity::Warning,
                check: Check::DeadDefault.as_str(),
                symbol: Some(var_symbol.to_owned()),
                message: format!("dead default of {}", default.expression),
            });
        }

        if style_enabled {
            if default.r#if.is_some() && is_duplicate(&mut seen_values, val_str.clone()) {
                findings.push(Finding {
                    severity: Severity::Style,
                    check: "duplicate_default_value",
                    symbol: Some(var_symbol.to_owned()),
                    message: format!(
                        "duplicate default value of {:?}; consider combining the conditions with a logical-or: ||",
                        val_str
                    ),
                });
            }
        }

        match &default.r#if {
            Some(cond) => {
                if is_duplicate(&mut seen_conditions, cond.to_string()) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: Check::DuplicateDefault.as_str(),
                        symbol: Some(var_symbol.to_owned()),
                        message: format!("duplicate default condition of {:?}", cond),
                    });
                }
            }
            None => {
                already_unconditional = true;
            }
        }
    }

    findings
}

fn check_variable_info(
    args: &AnalysisArgs,
    var_symbol: &str,
    arch_specific: &Option<String>,
    info: &VariableInfo,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if args.is_enabled(Check::DuplicateDependency) {
        findings.extend(check_duplicate_dependencies(
            var_symbol,
            info,
            arch_specific,
        ));
    }

    if args.is_enabled(Check::DuplicateRange) {
        findings.extend(check_dead_ranges(var_symbol, info));
    }

    if args.is_enabled(Check::DuplicateSelect) {
        findings.extend(check_duplicate_selects(var_symbol, info));
    }

    if args.is_enabled(Check::DeadDefault)
        || args.is_enabled(Check::DuplicateDefault)
        || args.is_enabled(Check::Style)
    {
        findings.extend(check_defaults(
            var_symbol,
            info,
            args.is_enabled(Check::Style),
        ));
    }

    findings
}

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
