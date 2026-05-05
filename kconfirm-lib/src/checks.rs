use nom_kconfig::attribute::Expression;

// SPDX-License-Identifier: GPL-2.0-only
use crate::{
    output::{Finding, Severity},
    symbol_table::{AttributeDef, TypeInfo},
};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Check {
    FailedParse,
    UngroupedAttribute, // check for duplicate default values, and ungrouped attributes
    DeadLink,           // check for dead links in the help texts
    SelectVisible,
    // need SMT solving before we can detect select-undefineds
    //SelectUndefined,
    DuplicateDependency,
    DuplicateRange,
    DuplicateSelect,
    DeadDefault,
    DeadCondition,
    DuplicateDefault,
    DuplicateDefaultValue,
}

impl Check {
    pub fn as_str(self) -> &'static str {
        match self {
            Check::FailedParse => "failed_parse",
            Check::UngroupedAttribute => "ungrouped_attribute",
            Check::DeadLink => "dead_links",
            Check::SelectVisible => "select_visible",
            Check::DuplicateDependency => "duplicate_dependency",
            Check::DuplicateRange => "duplicate_range",
            Check::DuplicateSelect => "duplicate_select",
            Check::DeadDefault => "dead_default",
            Check::DeadCondition => "dead_condition",
            Check::DuplicateDefault => "duplicate_default",
            Check::DuplicateDefaultValue => "duplicate_default_value",
        }
    }
}

pub fn parse_check(name: &str) -> Option<Check> {
    match name {
        "failed_parse" => Some(Check::FailedParse),
        "ungrouped_attribute" => Some(Check::UngroupedAttribute),
        "dead_links" => Some(Check::DeadLink),
        "select_visible" => Some(Check::SelectVisible),
        "duplicate_dependency" => Some(Check::DuplicateDependency),
        "duplicate_range" => Some(Check::DuplicateRange),
        "duplicate_select" => Some(Check::DuplicateSelect),
        "dead_default" => Some(Check::DeadDefault),
        "dead_condition" => Some(Check::DeadCondition),
        "duplicate_default" => Some(Check::DuplicateDefault),
        "duplicate_default_value" => Some(Check::DuplicateDefaultValue),
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

pub fn check_dead_conditions(
    arch: &Option<String>,
    findings: &mut Vec<Finding>,
    symbol: &str,
    kconfig_dependencies: &[Expression],
    attribute_conditions: Vec<&Expression>,
    context: &str,
) {
    for attribute_condition in attribute_conditions.into_iter() {
        if kconfig_dependencies.contains(attribute_condition) {
            let message = format!(
                "dead {} condition 'if {}' for config option: {}, this condition is a dependency and will always be true",
                context,
                attribute_condition.to_string(),
                symbol,
            );
            findings.push(Finding {
                severity: Severity::Warning,
                check: Check::DeadCondition,
                symbol: Some(symbol.to_owned()),
                arch: arch.to_owned(),
                message,
            });
        }
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
            arch_specific,
            var_symbol,
            info,
        ));
    }

    if args.is_enabled(Check::DuplicateRange) {
        findings.extend(check_duplicate_ranges(arch_specific, var_symbol, info));
    }

    if args.is_enabled(Check::DuplicateSelect) {
        findings.extend(check_duplicate_selects(arch_specific, var_symbol, info));
    }

    if args.is_enabled(Check::DuplicateDefaultValue) {
        findings.extend(check_defaults(arch_specific, var_symbol, info, args));
    }

    if args.is_enabled(Check::DeadDefault) {
        findings.extend(check_defaults(arch_specific, var_symbol, info, args));
    }

    if args.is_enabled(Check::DuplicateDefault) {
        findings.extend(check_defaults(
            arch_specific,
            var_symbol,
            info,
            args, // duplicate default values is a style check
        ));
    }

    findings
}

// TODO: also check if a config option in one arch unconditionally references a config option that only exists in another arch (need SMT for this first)
pub fn check_select_visible(var_symbol: &str, info: &TypeInfo) -> Vec<Finding> {
    let mut findings = Vec::new();

    // only interested in the options that are selected
    if info.selected_by.is_empty() {
        return Vec::new();
    }

    for (selector, select_info) in &info.selected_by {
        for (arch, _cond) in select_info {
            // NOTE: we don't care if the select is conditional or unconditional, just the selectee's visibility

            // at this point, we know that `selector` unconditionally selects `var_symbol`
            // now, we need to check if `var_symbol` is unconditionally visible

            let message = format!(
                "{} selects the visible {}; consider using 'depends on' or 'imply' instead",
                selector, var_symbol
            );

            // match the architecture that the select happens under with the architecture of the unconditional visibility
            match info.attribute_defs.get(arch) {
                None => {
                    // there's no config option definition specifically under the architecture that this config option gets selected,
                    // so let's check if it's defined for all archs (arch-independent)
                    if let Some(no_arch_attribute_def) = info.attribute_defs.get(&None) {
                        for (if_conditions, attributes) in no_arch_attribute_def {
                            if if_conditions.is_empty() && attributes.visibility.is_empty() {
                                // empty visiblity means that it is unconditionally visible, within the current arch (assuming arch is not `None`)

                                findings.push(Finding {
                                    severity: Severity::Warning,
                                    check: Check::SelectVisible,
                                    symbol: Some(selector.to_owned()),
                                    message: message.clone(),
                                    arch: arch.to_owned(),
                                });
                            }
                        }
                    }
                }
                Some(cur_arch_attribute_def) => {
                    for (if_conditions, attributes) in cur_arch_attribute_def {
                        if if_conditions.is_empty() && attributes.visibility.is_empty() {
                            // empty visiblity means that it is unconditionally visible, within the current arch (assuming arch is not `None`)

                            findings.push(Finding {
                                severity: Severity::Warning,
                                check: Check::SelectVisible,
                                symbol: Some(selector.to_owned()),
                                message: message.clone(),
                                arch: arch.to_owned(),
                            });
                        }
                    }
                }
            }
        }
    }

    findings
}

fn is_duplicate<T: Eq + std::hash::Hash>(set: &mut HashSet<T>, key: T) -> bool {
    !set.insert(key)
}

fn check_duplicate_dependencies(
    arch_specific: &Option<String>,
    var_symbol: &str,
    info: &AttributeDef,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for dep in &info.kconfig_dependencies {
        if is_duplicate(&mut seen, dep.to_string()) {
            let message = format!("duplicate dependency on {}", dep.to_string());
            findings.push(Finding {
                severity: Severity::Warning,
                check: Check::DuplicateDependency,
                symbol: Some(var_symbol.to_owned()),
                message,
                arch: arch_specific.to_owned(),
            });
        }
    }

    findings
}

fn check_duplicate_ranges(
    arch: &Option<String>,
    var_symbol: &str,
    info: &AttributeDef,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen_conditions = HashSet::new();
    let mut already_unconditional = false;

    for range in &info.kconfig_ranges {
        if already_unconditional {
            findings.push(Finding {
                severity: Severity::Warning,
                check: Check::DuplicateRange,
                symbol: Some(var_symbol.to_owned()),
                message: format!("dead range of {:?}", range),
                arch: arch.to_owned(),
            });
            continue;
        }

        if let Some(cond) = range.r#if.clone() {
            if is_duplicate(&mut seen_conditions, cond.to_string()) {
                findings.push(Finding {
                    severity: Severity::Warning,
                    check: Check::DuplicateRange,
                    symbol: Some(var_symbol.to_owned()),
                    message: format!("dead range of {:?}", range),
                    arch: arch.to_owned(),
                });
            }
        } else {
            already_unconditional = true;
        }
    }

    findings
}

fn check_duplicate_selects(
    arch: &Option<String>,
    var_symbol: &str,
    info: &AttributeDef,
) -> Vec<Finding> {
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
                        check: Check::DuplicateSelect,
                        symbol: Some(var_symbol.to_owned()),
                        message: format!("dead select of {:?}", select.0),
                        arch: arch.to_owned(),
                    });
                }

                let cond_str = cond.to_string();
                if is_duplicate(&mut seen, (select_var, cond_str.clone())) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: Check::DuplicateSelect,
                        symbol: Some(var_symbol.to_owned()),
                        message: format!(
                            "duplicate select of {:?} with condition {}",
                            select.0, cond_str
                        ),
                        arch: arch.to_owned(),
                    });
                }
            }
            None => {
                if is_duplicate(&mut seen, (select_var, String::new())) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: Check::DuplicateSelect,
                        symbol: Some(var_symbol.to_owned()),
                        message: format!("duplicate select of {:?}", select.0),
                        arch: arch.to_owned(),
                    });
                }
            }
        }
    }

    findings
}

#[allow(clippy::collapsible_if)]
fn check_defaults(
    arch: &Option<String>,
    var_symbol: &str,
    info: &AttributeDef,
    args: &AnalysisArgs,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen_conditions = HashSet::new();
    let mut seen_values = HashSet::new();
    let mut already_unconditional = false;

    for default in &info.kconfig_defaults {
        let val_str = default.expression.to_string();

        if already_unconditional && args.is_enabled(Check::DeadDefault) {
            findings.push(Finding {
                severity: Severity::Warning,
                check: Check::DeadDefault,
                symbol: Some(var_symbol.to_owned()),
                message: format!("dead default of {}", val_str),
                arch: arch.to_owned(),
            });
        }

        if args.is_enabled(Check::DuplicateDefaultValue) {
            if default.r#if.is_some() && is_duplicate(&mut seen_values, val_str.clone()) {
                findings.push(Finding {
                    severity: Severity::Style,
                    check: Check::DuplicateDefaultValue,
                    symbol: Some(var_symbol.to_owned()),
                    message: format!(
                        "duplicate default value of {}; consider combining the conditions with a logical-or: ||",
                        val_str
                    ),
                    arch: arch.to_owned(),
                });
            }
        }

        match &default.r#if {
            Some(cond) => {
                if is_duplicate(&mut seen_conditions, cond.to_string()) {
                    if is_duplicate(&mut seen_values, val_str.clone()) {
                        if args.is_enabled(Check::DuplicateDefault) {
                            findings.push(Finding {
                                severity: Severity::Warning,
                                check: Check::DuplicateDefault,
                                symbol: Some(var_symbol.to_owned()),
                                message: format!("duplicate default condition of {:?}", cond),
                                arch: arch.to_owned(),
                            });
                        }
                    } else {
                        if args.is_enabled(Check::DeadDefault) {
                            findings.push(Finding {
                                severity: Severity::Warning,
                                check: Check::DeadDefault,
                                symbol: Some(var_symbol.to_owned()),
                                message: format!("dead default of {}", val_str),
                                arch: arch.to_owned(),
                            });
                        }
                    }
                }
            }
            None => {
                already_unconditional = true;
            }
        }
    }

    findings
}
