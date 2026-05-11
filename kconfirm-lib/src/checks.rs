// SPDX-License-Identifier: GPL-2.0-only
use crate::{
    output::{Finding, Severity},
    symbol_table::AttributeDef,
};
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
            Check::DuplicateRange => "duplicate_range",
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
        "duplicate_range" => Some(Check::DuplicateRange),
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

pub fn check_variable_info(
    args: &AnalysisArgs,
    var_symbol: &str,
    arch_specific: &Option<String>,
    info: &AttributeDef,
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
        findings.extend(check_duplicate_ranges(var_symbol, info));
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

fn is_duplicate<T: Eq + std::hash::Hash>(set: &mut HashSet<T>, key: T) -> bool {
    !set.insert(key)
}

fn check_duplicate_dependencies(
    var_symbol: &str,
    info: &AttributeDef,
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

fn check_duplicate_ranges(var_symbol: &str, info: &AttributeDef) -> Vec<Finding> {
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

fn check_duplicate_selects(var_symbol: &str, info: &AttributeDef) -> Vec<Finding> {
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

fn check_defaults(var_symbol: &str, info: &AttributeDef, style_enabled: bool) -> Vec<Finding> {
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
