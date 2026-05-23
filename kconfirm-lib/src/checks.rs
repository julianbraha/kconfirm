// SPDX-License-Identifier: GPL-2.0-only
use log::error;
use nom_kconfig::attribute::AndExpression;
use nom_kconfig::attribute::Expression;
use nom_kconfig::attribute::Term;
use nom_kconfig::attribute::range::RangeBound;
use std::collections::HashSet;
use std::num::ParseIntError;

use crate::output::Finding;
use crate::output::Severity;
use crate::symbol_table::AttributeDef;
use crate::symbol_table::TypeInfo;

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
    DeadRange,
    DuplicateSelect,
    DeadSelect,
    DeadDefault,
    ConstantCondition,
    DuplicateDefault,
    DuplicateDefaultValue,
    DuplicateImply,
    DeadImply,
    ReverseRange,
}

impl Check {
    pub fn as_str(self) -> &'static str {
        match self {
            Check::FailedParse => "failed_parse",
            Check::UngroupedAttribute => "ungrouped_attribute",
            Check::DeadLink => "dead_link",
            Check::SelectVisible => "select_visible",
            Check::DuplicateDependency => "duplicate_dependency",
            Check::DuplicateRange => "duplicate_range",
            Check::DeadRange => "dead_range",
            Check::DuplicateSelect => "duplicate_select",
            Check::DeadSelect => "dead_select",
            Check::DeadDefault => "dead_default",
            Check::ConstantCondition => "constant_condition",
            Check::DuplicateDefault => "duplicate_default",
            Check::DuplicateDefaultValue => "duplicate_default_value",
            Check::DuplicateImply => "duplicate_imply",
            Check::DeadImply => "dead_imply",
            Check::ReverseRange => "reverse_range",
        }
    }
}

pub fn parse_check(name: &str) -> Option<Check> {
    match name {
        "failed_parse" => Some(Check::FailedParse),
        "ungrouped_attribute" => Some(Check::UngroupedAttribute),
        "dead_link" => Some(Check::DeadLink),
        "select_visible" => Some(Check::SelectVisible),
        "duplicate_dependency" => Some(Check::DuplicateDependency),
        "duplicate_range" => Some(Check::DuplicateRange),
        "duplicate_select" => Some(Check::DuplicateSelect),
        "dead_select" => Some(Check::DeadSelect),
        "dead_default" => Some(Check::DeadDefault),
        "constant_condition" => Some(Check::ConstantCondition),
        "duplicate_default" => Some(Check::DuplicateDefault),
        "duplicate_default_value" => Some(Check::DuplicateDefaultValue),
        "duplicate_imply" => Some(Check::DuplicateImply),
        "dead_imply" => Some(Check::DeadImply),
        "reverse_range" => Some(Check::ReverseRange),
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct AnalysisArgs {
    // check for duplicate default values
    pub enabled_checks: HashSet<Check>,
}

impl AnalysisArgs {
    pub fn is_enabled(&self, check: Check) -> bool {
        self.enabled_checks.contains(&check)
    }
}

// returns an Error if a hex range bound cannot be parsed as an u64
pub fn check_reverse_ranges(
    arch: &Option<String>,
    var_symbol: &str,
    info: &AttributeDef,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for range in &info.kconfig_ranges {
        // returns an Error if a hex range bound cannot be parsed as an u64
        fn range_bound_to_int(range_bound: &RangeBound) -> Result<i128, ParseIntError> {
            match range_bound {
                RangeBound::Number(b) => {
                    return Ok(b.to_owned() as i128);
                }
                RangeBound::Hex(b_str) => {
                    let trimmed = b_str.trim_start_matches("0x").trim_start_matches("0X");

                    return i128::from_str_radix(trimmed, 16);
                }
                RangeBound::Symbol(_) => {
                    // TODO: need SMT solving for this case
                    //       for now, the caller is expected not to pass these cases.
                    unreachable!("not handling variable ranges until SMT solving");
                }
            }
        }

        if matches!(range.lower_bound, RangeBound::Symbol(_))
            || matches!(range.upper_bound, RangeBound::Symbol(_))
        {
            // not handling these cases until SMT solving.
            // don't return though, because we stil want to check the other ranges.
            continue;
        }

        let maybe_lower_bound = range_bound_to_int(&range.lower_bound);
        let maybe_upper_bound = range_bound_to_int(&range.upper_bound);

        match (maybe_lower_bound, maybe_upper_bound) {
            (Ok(lower_bound), Ok(upper_bound)) => {
                if lower_bound > upper_bound {
                    let message = format!(
                        "reverse range {} for config option: {}, no value is valid",
                        range.to_string(),
                        var_symbol,
                    );
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: Check::ReverseRange,
                        symbol: Some(var_symbol.to_owned()),
                        arch: arch.to_owned(),
                        message,
                    });
                }
            }
            (Result::Err(_), _) | (_, Result::Err(_)) => {
                error!(
                    "couldn't parse hex range bound as i128 for config option: {}",
                    var_symbol
                );
                // still want to check the other range bounds
                continue;
            }
        }
    }

    findings
}

pub fn check_constant_conditions(
    arch: &Option<String>,
    var_symbol: &str,
    info: &AttributeDef,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let default_conditions: Vec<&Expression> = info
        .kconfig_defaults
        .iter()
        .filter_map(|conditional_default| conditional_default.r#if.as_ref())
        .collect();

    check_conditions(
        arch,
        &mut findings,
        &var_symbol,
        &info.kconfig_dependencies,
        default_conditions,
        "default",
    );

    let select_conditions: Vec<&Expression> = info
        .selects
        .iter()
        .filter_map(|conditional_select| conditional_select.1.as_ref())
        .collect();

    check_conditions(
        arch,
        &mut findings,
        var_symbol,
        &info.kconfig_dependencies,
        select_conditions,
        "select",
    );

    let imply_conditions: Vec<&Expression> = info
        .implies
        .iter()
        .filter_map(|imp| imp.1.as_ref())
        .collect();

    check_conditions(
        arch,
        &mut findings,
        var_symbol,
        &info.kconfig_dependencies,
        imply_conditions,
        "imply",
    );

    let range_conditions: Vec<&Expression> = info
        .kconfig_ranges
        .iter()
        .filter_map(|conditional_range| conditional_range.r#if.as_ref())
        .collect();

    check_conditions(
        arch,
        &mut findings,
        var_symbol,
        &info.kconfig_dependencies,
        range_conditions,
        "range",
    );

    fn check_conditions(
        arch: &Option<String>,
        findings: &mut Vec<Finding>,
        symbol: &str,
        kconfig_dependencies: &[Expression],
        attribute_conditions: Vec<&Expression>,
        context: &str,
    ) {
        for attribute_condition in attribute_conditions.into_iter() {
            // check if the attribute condition is contained
            if kconfig_dependencies.contains(attribute_condition) {
                let message = format!(
                    "constant {} condition 'if {}' for config option: {}, this condition is a dependency and will always be true",
                    context,
                    attribute_condition.to_string(),
                    symbol,
                );
                findings.push(Finding {
                    severity: Severity::Warning,
                    check: Check::ConstantCondition,
                    symbol: Some(symbol.to_owned()),
                    arch: arch.to_owned(),
                    message,
                });
            }

            // check if the negative is contained
            let negative_attribute_condition = match attribute_condition {
                Expression::Term(and_expression) => {
                    match and_expression {
                        AndExpression::Term(term) => {
                            match term {
                                Term::Not(n) => {
                                    // it's already negative, so let's check if the positive is contained
                                    Some(Expression::Term(AndExpression::Term(Term::Atom(
                                        n.to_owned(),
                                    ))))
                                }
                                Term::Atom(a) => Some(Expression::Term(AndExpression::Term(
                                    Term::Not(a.to_owned()),
                                ))),
                            }
                        }
                        _ => {
                            // do nothing
                            None
                        }
                    }
                }
                _ => {
                    // do nothing
                    None
                }
            };

            if let Some(negative) = negative_attribute_condition {
                if kconfig_dependencies.contains(&negative) {
                    let message = format!(
                        "constant {} condition 'if {}' for config option: {}, the negation of this condition is a dependency and will always be false",
                        context,
                        attribute_condition.to_string(),
                        symbol,
                    );
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: Check::ConstantCondition,
                        symbol: Some(symbol.to_owned()),
                        arch: arch.to_owned(),
                        message,
                    });
                }
            }
        }
    }
    findings
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

    if args.is_enabled(Check::DuplicateImply) {
        findings.extend(check_duplicate_implies(arch_specific, var_symbol, info));
    }

    if args.is_enabled(Check::DuplicateRange) {
        findings.extend(check_duplicate_ranges(arch_specific, var_symbol, info));
    }

    if args.is_enabled(Check::DuplicateSelect) {
        findings.extend(check_duplicate_selects(arch_specific, var_symbol, info));
    }

    if args.is_enabled(Check::ConstantCondition) {
        findings.extend(check_constant_conditions(arch_specific, var_symbol, info));
    }

    if args.is_enabled(Check::DeadDefault)
        || args.is_enabled(Check::DuplicateDefault)
        || args.is_enabled(Check::DuplicateDefaultValue)
    {
        findings.extend(check_defaults(arch_specific, var_symbol, info, args));
    }

    if args.is_enabled(Check::ReverseRange) {
        findings.extend(check_reverse_ranges(arch_specific, var_symbol, info));
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
                "selects the visible {}; consider using 'depends on' or 'imply' instead",
                var_symbol
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

fn check_duplicate_implies(
    arch: &Option<String>,
    var_symbol: &str,
    info: &AttributeDef,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // symbols implied unconditionally
    let mut unconditional: HashSet<String> = HashSet::new();

    // (symbol, condition)
    let mut conditional: HashSet<(String, String)> = HashSet::new();

    for imp in &info.implies {
        let imply_var = imp.0.clone();

        match &imp.1 {
            Some(cond) => {
                let cond_str = cond.to_string();

                // duplicate conditional imply
                if !conditional.insert((imply_var.clone(), cond_str.clone())) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: Check::DuplicateImply,
                        symbol: Some(var_symbol.to_owned()),
                        message: format!(
                            "duplicate imply of {:?} with condition {}",
                            imp.0, cond_str
                        ),
                        arch: arch.to_owned(),
                    });
                }

                // conditional imply is dead if unconditional exists
                if unconditional.contains(&imply_var) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: Check::DeadImply,
                        symbol: Some(var_symbol.to_owned()),
                        message: format!("dead imply of {:?}", imp),
                        arch: arch.to_owned(),
                    });
                }
            }

            None => {
                // duplicate unconditional imply
                if !unconditional.insert(imply_var.clone()) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: Check::DuplicateImply,
                        symbol: Some(var_symbol.to_owned()),
                        message: format!("duplicate imply of {:?}", imp),
                        arch: arch.to_owned(),
                    });
                }

                // previous conditionals with same symbol are dead
                for (sym, _) in &conditional {
                    if sym == &imply_var {
                        findings.push(Finding {
                            severity: Severity::Warning,
                            check: Check::DeadImply,
                            symbol: Some(var_symbol.to_owned()),
                            message: format!("dead imply of {:?}", imp),
                            arch: arch.to_owned(),
                        });
                    }
                }
            }
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

    // unconditional ranges by bounds
    let mut unconditional: HashSet<String> = HashSet::new();

    // (bounds, condition)
    let mut conditional: HashSet<(String, String)> = HashSet::new();

    for range in &info.kconfig_ranges {
        // uniquely identify the range bounds
        let range_key = format!("{} {}", range.lower_bound, range.upper_bound);

        match &range.r#if {
            Some(cond) => {
                let cond_str = cond.to_string();

                // duplicate conditional range
                if !conditional.insert((range_key.clone(), cond_str.clone())) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: Check::DuplicateRange,
                        symbol: Some(var_symbol.to_owned()),
                        message: format!("duplicate range {:?} with condition {}", range, cond_str),
                        arch: arch.to_owned(),
                    });
                }

                // conditional range is dead if unconditional exists
                if unconditional.contains(&range_key) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: Check::DeadRange,
                        symbol: Some(var_symbol.to_owned()),
                        message: format!("dead range of {:?}", range),
                        arch: arch.to_owned(),
                    });
                }
            }

            None => {
                // duplicate unconditional range
                if !unconditional.insert(range_key.clone()) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: Check::DeadRange,
                        symbol: Some(var_symbol.to_owned()),
                        message: format!("duplicate range {:?}", range),
                        arch: arch.to_owned(),
                    });
                }

                // previous conditionals with same bounds are dead
                for (bounds, _) in &conditional {
                    if bounds == &range_key {
                        findings.push(Finding {
                            severity: Severity::Warning,
                            check: Check::DeadRange,
                            symbol: Some(var_symbol.to_owned()),
                            message: format!("dead range of {:?}", range),
                            arch: arch.to_owned(),
                        });
                    }
                }
            }
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

    // symbols selected unconditionally
    let mut unconditional: HashSet<String> = HashSet::new();

    // (symbol, condition)
    let mut conditional: HashSet<(String, String)> = HashSet::new();

    for select in &info.selects {
        let select_var = select.0.clone();

        match &select.1 {
            Some(cond) => {
                let cond_str = cond.to_string();

                // duplicate conditional select
                if !conditional.insert((select_var.clone(), cond_str.clone())) {
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

                // conditional is dead if unconditional exists
                if unconditional.contains(&select_var) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: Check::DeadSelect,
                        symbol: Some(var_symbol.to_owned()),
                        message: format!("dead select of {:?}", select.0),
                        arch: arch.to_owned(),
                    });
                }
            }

            None => {
                // duplicate unconditional select
                if !unconditional.insert(select_var.clone()) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: Check::DuplicateSelect,
                        symbol: Some(var_symbol.to_owned()),
                        message: format!("duplicate select of {:?}", select.0),
                        arch: arch.to_owned(),
                    });
                }

                // any previous conditional selects are now dead too
                for (sym, _) in &conditional {
                    if sym == &select_var {
                        findings.push(Finding {
                            severity: Severity::Warning,
                            check: Check::DeadSelect,
                            symbol: Some(var_symbol.to_owned()),
                            message: format!("dead select of {:?}", select.0),
                            arch: arch.to_owned(),
                        });
                    }
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

        let has_real_condition = match &default.r#if {
            Some(cond) => {
                let cond_str = cond.to_string();
                !cond_str.is_empty()
            }
            None => false,
        };

        let is_value_dup = if has_real_condition {
            is_duplicate(&mut seen_values, val_str.clone())
        } else {
            false
        };

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
            if default.r#if.is_some() && is_value_dup {
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
                    if is_value_dup {
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
