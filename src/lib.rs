// SPDX-License-Identifier: GPL-2.0-only
pub mod output;
use output::*;

pub mod symbol_table;
use symbol_table::*;

mod dead_links;

mod linux;
use linux::*;

mod analyze;
use analyze::*;

use log::{debug, error, info};
use nom_kconfig::Entry;
use nom_kconfig::Symbol;
use nom_kconfig::attribute::AndExpression;
use nom_kconfig::attribute::Atom;
use nom_kconfig::attribute::Expression;
use nom_kconfig::attribute::Term;
use nom_kconfig::{KconfigFile, KconfigInput, parse_kconfig};
use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::PathBuf;

#[derive(Clone)]
pub struct AnalysisArgs {
    // check for duplicate default values
    pub check_style: bool,

    // check for dead links in the help texts
    pub check_dead_links: bool,
}

pub fn check_kconfig(args: AnalysisArgs, linux_source: PathBuf) -> io::Result<Vec<Finding>> {
    // will store detected kconfig issues,to be printed one line at a time at the end
    let mut findings = Vec::new();

    let mut symbol_table = SymbolTable::new();

    let root_linux = linux_source.clone();

    let arch_dir_path = {
        let arch_dir = linux_source.join("arch");
        PathBuf::from(arch_dir)
    };

    for entry in walkdir::WalkDir::new(arch_dir_path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();

        if path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|ext| ext.starts_with("Kconfig")) // was .eq() but we need e.g. arch/arm64/Kconfig.platforms
            .unwrap_or(false)
        {
            if path.components().any(|component| {
                component
                    .as_os_str()
                    .to_str()
                    .is_some_and(|s| s == "scripts" || s == "tools")
            }) {
                info!("NOTE: skipping the scripts dir for now...");
                continue;
            }
            let mut file = File::open(path)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;

            debug!("Opening: {}", path.display());

            //let linux_root = PathBuf::from(LINUX_SOURCE);

            let path_no_root = path.strip_prefix(&root_linux).unwrap();

            let cur_kconfig_file =
                KconfigFile::new(root_linux.clone(), PathBuf::from(path_no_root));
            let input = cur_kconfig_file.read_to_string().unwrap();
            let kconfig_parsed =
                parse_kconfig(KconfigInput::new_extra(&input, cur_kconfig_file.clone())).unwrap();
            let entries: Vec<Entry> = kconfig_parsed.1.entries;

            let arch_symbol = match path_no_root.components().nth(1).unwrap() {
                std::path::Component::Normal(n) => {
                    let arch_dir = n.to_ascii_uppercase().into_string().unwrap();
                    debug!("arch_dir: {}", arch_dir);
                    arch_dir_to_config(&arch_dir)
                }
                _ => unreachable!(),
            };

            if let Some(r#as) = arch_symbol {
                let expression = Expression::Term(AndExpression::Term(Term::Atom(Atom::Symbol(
                    Symbol::NonConstant(r#as.to_owned()),
                ))));
                for entry in entries {
                    let cur_findings = entry_processor(
                        &args,
                        &mut symbol_table,
                        entry,
                        Vec::new(),
                        Vec::new(),
                        Vec::from([expression.clone()]),
                        false, // we don't start in a choice.
                    );

                    findings.extend(cur_findings);
                }
            } else {
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
    }

    let root_kconfig_file = PathBuf::from("Kconfig"); // doesn't include the arch: arch/x86/Kconfig
    let cur_kconfig_file = KconfigFile::new(root_linux, root_kconfig_file);
    let input = cur_kconfig_file.read_to_string().unwrap();
    let kconfig_parse_result = parse_kconfig(KconfigInput::new_extra(&input, cur_kconfig_file));

    // process the kconfig entries that we parsed from the root kconfig file:
    if let Ok(parsed_kconfig_file) = kconfig_parse_result {
        let entries: Vec<Entry> = parsed_kconfig_file.1.entries;

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
    } else if let Err(e) = kconfig_parse_result {
        error!("failed to parse kconfig, error is {:?}", e);
    }

    let inner_symtab = symbol_table.raw;

    let mut all_vars = Vec::new();

    for type_info_ref in inner_symtab.iter() {
        let var_symbol = type_info_ref.0;
        all_vars.push(var_symbol.clone());

        for kconfig_redefinition in type_info_ref.1.clone().variable_info {
            let mut all_dependencies =
                HashSet::with_capacity(kconfig_redefinition.kconfig_dependencies.len());
            for dep in kconfig_redefinition.kconfig_dependencies {
                let dep_str = dep.to_string();
                if all_dependencies.contains(&dep_str) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        check: "duplicate_dependency",
                        symbol: Some(var_symbol.clone()),
                        message: format!("duplicate dependency on {:?}", dep_str),
                    });
                } else {
                    all_dependencies.insert(dep_str);
                }
            }

            let mut all_range_conditions = HashSet::new();

            // TODO: consider an optional check for multiple ranges of the same value, but different conditions (style lint)
            let mut already_unconditional_range = false;
            for range in kconfig_redefinition.kconfig_ranges {
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
                    if all_range_conditions.contains(&f.to_string()) {
                        findings.push(Finding {
                            severity: Severity::Warning,
                            check: "dead_range",
                            symbol: Some(var_symbol.clone()),
                            message: format!("dead range of {:?}", range),
                        });
                    } else {
                        all_range_conditions.insert(f.to_string());
                    }
                }

                if range.r#if.is_none() {
                    already_unconditional_range = true;
                }
            }

            let mut all_selects = HashSet::with_capacity(kconfig_redefinition.selects.len());

            // TODO: cleanup this code (especially the clones, and the if-handling)
            for select in kconfig_redefinition.selects {
                let select_var = select.clone().0;
                if let Some(select_cond) = select.clone().1 {
                    if all_selects.contains(&(select_var.clone(), select_cond.to_string())) {
                        findings.push(Finding {
                            severity: Severity::Warning,
                            check: "duplicate_select",
                            symbol: Some(var_symbol.clone()),
                            message: format!("duplicate select of {:?}", select),
                        });
                    } else {
                        all_selects.insert((select_var, select_cond.to_string()));
                    }
                } else {
                    // style check:
                    //       - select X if Y
                    //       - select X if Z
                    //         (could just be `select X if Y || Z`)
                    if all_selects.contains(&(select_var.clone(), String::new())) {
                        findings.push(Finding {
                            severity: Severity::Warning,
                            check: "duplicate_select",
                            symbol: Some(var_symbol.clone()),
                            message: format!("duplicate select of {:?}", select),
                        });
                    } else {
                        all_selects.insert((select_var, String::new()));
                    }
                }
            }

            let mut already_unconditional_default = false;

            // TODO: do we want to use the `with_capacity` initializer with `kconfig_redefinition.kconfig_defaults`?
            let mut all_default_ifs = HashSet::new();

            // only used when style checks are enabled, consider wrapping this in Option
            let mut all_default_vals = HashSet::new();

            for default_and_if in kconfig_redefinition.kconfig_defaults {
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
                    if all_default_vals.contains(&default_val) {
                        findings.push(Finding {
                            severity: Severity::Style,
                            check: "duplicate_default_value",
                            symbol: Some(var_symbol.clone()),
                            message: format!("duplicate default value of {:?}", default_val),
                        });
                    } else {
                        all_default_vals.insert(default_and_if.expression.to_string());
                    }
                }

                let default_cond = default_and_if.r#if;

                // TODO: can we use a reference to default_cond?
                if let Some(d) = default_cond.clone() {
                    // OrExpression doesn't implement `Eq` so we convert it to a string first.
                    if all_default_ifs.contains(&(d.to_string())) {
                        findings.push(Finding {
                            severity: Severity::Warning,
                            check: "duplicate_default",
                            symbol: Some(var_symbol.clone()),
                            message: format!("duplicate default condition of {:?}", d),
                        });
                    } else {
                        all_default_ifs.insert(d.to_string());
                    }
                }

                let unconditional_default = default_cond.is_none();

                if unconditional_default {
                    already_unconditional_default = true;
                }
            }
        }
    }
    Ok(findings)
}
