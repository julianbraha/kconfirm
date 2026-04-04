// SPDX-License-Identifier: GPL-2.0-only
pub mod output;
use output::*;

pub mod symbol_table;
use symbol_table::*;

pub mod dead_links;
use dead_links::*;

use log::{debug, error, info};
use nom_kconfig::Symbol;
use nom_kconfig::attribute::AndExpression;
use nom_kconfig::attribute::Atom;
use nom_kconfig::attribute::DefaultAttribute;
use nom_kconfig::attribute::Expression;
use nom_kconfig::attribute::Select;
use nom_kconfig::attribute::Term;
use nom_kconfig::attribute::r#type::Type;
use nom_kconfig::{
    Attribute::*,
    Entry::{self, *},
};
use nom_kconfig::{KconfigFile, KconfigInput, parse_kconfig};
use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::io::Read;
use std::option::Option;
use std::path::PathBuf;

#[derive(Clone)]
pub struct AnalysisArgs {
    // check for duplicate default values
    pub check_style: bool,

    // check for dead links in the help texts
    pub check_dead_links: bool,
}

// each architecture has its own directory, and config option.
// most are the same, but powerpc / ppc is not.
// this maps the directory to the config option
fn arch_dir_to_config(arch_dir: &str) -> Option<&'static str> {
    match arch_dir {
        "ARM" => Some("ARM"),
        "ARM64" => Some("ARM64"),
        "X86" => Some("X86"),
        "RISCV" => Some("RISCV"),
        "MIPS" => Some("MIPS"),
        "XTENSA" => Some("XTENSA"),
        "SPARC" => Some("SPARC"),
        "ALPHA" => Some("ALPHA"),
        "ARC" => Some("ARC"),
        "CSKY" => Some("CSKY"),
        "HEXAGON" => Some("HEXAGON"),
        "LOONGARCH" => Some("LOONGARCH"),
        "M68K" => Some("M68K"),
        "MICROBLAZE" => Some("MICROBLAZE"),
        "NIOS2" => Some("NIOS2"),
        "OPENRISC" => Some("OPENRISC"),
        "PARISC" => Some("PARISC"),
        "POWERPC" => Some("PPC"),
        "S390" => Some("S390"),
        "SH" => Some("SH"),
        "UM" => Some("UML"),

        _ => None,
    }
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
                        message: "dead default".to_string(),
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

// continually enters each entry until we reach the Configs and then translates them into z3 types/logic.
// inserts the entry into the symbol table.
// returns the config option identifier string, so that the menu choice can gather these for the mutual exclusion constraint.
pub fn entry_processor(
    args: &AnalysisArgs,
    symbol_table: &mut SymbolTable,
    entry: Entry,
    old_definedness_condition: Vec<Expression>, // pass a fresh vector on the first call (no definedness condition)
    old_visibility_condition: Vec<Expression>, // pass a fresh vector on the first call (visible by default)
    old_dependencies: Vec<Expression>, // pass a fresh vector on the first call (no dependencies)
    is_in_a_choice: bool, // this value will get passed down with each recursive call (because you could have choice->source->config/bool)
) -> Vec<Finding> {
    let mut findings = Vec::new(); // will return this later

    let cur_definedness_condition = old_definedness_condition.clone();

    // CHOICE passes down its visibility to the options inside of it.
    let mut cur_visibility_condition = old_visibility_condition.clone();

    let mut cur_dependencies = old_dependencies.clone();

    match entry {
        // MenuConfig is just a type alias of Config
        Config(c) | MenuConfig(c) => {
            let config_symbol = c.symbol;
            debug!(
                "starting to process config option `config` type: {}",
                config_symbol
            );

            let mut config_type = None;
            let mut kconfig_dependencies = Vec::new();
            let mut kconfig_selects: Vec<Select> = Vec::new();
            let mut kconfig_ranges = Vec::new();
            let mut kconfig_defaults = Vec::new();
            for attribute in c.attributes {
                match attribute {
                    Type(kconfig_type) => match kconfig_type.r#type.clone() {
                        // hybrid type definition and default
                        Type::DefBool(db) => {
                            let default_attribute: DefaultAttribute = DefaultAttribute {
                                expression: db,
                                r#if: kconfig_type.clone().r#if,
                            };

                            kconfig_defaults.push(default_attribute);
                            config_type = Some(kconfig_type);
                        }
                        Type::Bool(_b) => {
                            config_type = Some(kconfig_type);
                        }

                        // hybrid type definition and default
                        Type::DefTristate(dt) => {
                            let default_attribute: DefaultAttribute = DefaultAttribute {
                                expression: dt,
                                r#if: kconfig_type.clone().r#if,
                            };

                            kconfig_defaults.push(default_attribute);
                            config_type = Some(kconfig_type)
                        }
                        Type::Tristate(_ts) => config_type = Some(kconfig_type.clone()),
                        Type::Hex(_h) => config_type = Some(kconfig_type),
                        Type::Int(_i) => config_type = Some(kconfig_type),
                        Type::String(_s) => config_type = Some(kconfig_type),
                    },
                    DependsOn(depends_on) => {
                        kconfig_dependencies.push(depends_on);
                    }
                    Select(select) => {
                        kconfig_selects.push(select);
                    }

                    Default(default) => kconfig_defaults.push(default),
                    Help(h) => {
                        // doing nothing for menu help right now

                        if args.check_dead_links {
                            let help_links = dead_links::find_links(&h);
                            if !help_links.is_empty() {
                                debug!("help links are: {:?}", help_links);
                                for l in help_links {
                                    let link_status = check_link(&l);
                                    if link_status != LinkStatus::Ok
                                        && link_status != LinkStatus::ProbablyBlocked
                                    {
                                        findings.push(Finding {
                                            severity: Severity::Warning,
                                            check: "dead_link",
                                            symbol: Some(config_symbol.clone()),
                                            message: format!(
                                                "help text contains link {} with status {:?}",
                                                l, link_status
                                            ),
                                        });
                                    }
                                }
                            }
                        }
                    }
                    Range(r) => {
                        kconfig_ranges.push(r);
                        // NOTE: bounds are inclusive
                    }
                    Modules => {
                        // the modules attribute designates this config option as the one that determines if the `m` state is available for tristates options.

                        // just making a special note of this in the symtab for now...
                        symbol_table.modules_option = Some(config_symbol.clone());
                    }

                    Imply(_imply) => {
                        // doing nothing for imply right now

                        // TODO: may be relevant for nonvisible config options when building an SMT model...
                    }

                    // the prompt's option `if` determines "visibility"
                    Prompt(prompt) => {
                        if let Some(c) = prompt.r#if {
                            cur_visibility_condition.push(c);
                        }
                    }
                    Transitional => {
                        // doing nothing for transitional right now
                    }
                    _defconfig_list => {
                        todo!(
                            "Found a defconfig list for config option: {:?}, TODO: handle it!",
                            &config_symbol
                        );
                    }
                }
            }

            // there can be multiple entries that get merged. so we need to do the same for our symtab.
            let kconfig_type = config_type.clone().map(|c| c.r#type);

            // at the time of writing this, linux's kconfig only uses Bool inside Choice.
            // however, the kconfig documentation doesn't specify whether or not this is guaranteed to be the case.
            // we add this check to ensure that we don't cause undefined behavior in future linux versions if something changes...
            if is_in_a_choice {
                if let Some(kt) = &kconfig_type {
                    match kt {
                        Type::Bool(_) | Type::DefBool(_) => {
                            // expected in a choice...
                        }
                        _ => unreachable!("expected only bool inside choice. got {:?}", kt),
                    }
                }
            }

            // at the end, add the file's cur_dependencies to this var's invididual dependencies.
            kconfig_dependencies.extend(cur_dependencies);
            symbol_table.merge_insert_new_solved(
                config_symbol.clone(),
                kconfig_type,
                kconfig_dependencies,
                //z3_dependency,
                kconfig_ranges,
                kconfig_defaults,
                cur_visibility_condition.clone(),
                cur_definedness_condition.clone(),
                Vec::new(),
                kconfig_selects
                    .clone()
                    .into_iter()
                    .map(|sel| (sel.symbol, sel.r#if))
                    .collect(),
            );

            // need to add the select condition to the definedness condition if it exists
            for select in kconfig_selects {
                match select.r#if {
                    None => symbol_table.merge_insert_new_solved(
                        select.symbol,
                        None,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        vec![(config_symbol.clone(), cur_definedness_condition.clone())],
                        Vec::new(),
                    ),
                    Some(select_condition) => {
                        let mut select_and_definedness_condition =
                            cur_definedness_condition.clone();
                        select_and_definedness_condition.push(select_condition);

                        symbol_table.merge_insert_new_solved(
                            select.symbol,
                            None,
                            Vec::new(),
                            Vec::new(),
                            Vec::new(),
                            Vec::new(),
                            Vec::new(),
                            vec![(config_symbol.clone(), select_and_definedness_condition)],
                            Vec::new(),
                        );
                    }
                }
            }
        }
        Menu(m) => {
            // menus can set the visibility of their menu items

            let mut existing_dependencies_with_menu_dependencies = cur_dependencies.clone();
            let mut existing_visibility_with_menu_dependencies = cur_visibility_condition.clone();

            if !m.depends_on.is_empty() {
                debug!("the menu {:?} dependencies are: {:?}", m, m.depends_on);
            }

            existing_dependencies_with_menu_dependencies.extend(m.depends_on.clone());
            existing_visibility_with_menu_dependencies.extend(m.depends_on.clone());

            for inner_entry in m.entries {
                // recursive call
                let cur_findings = entry_processor(
                    args,
                    symbol_table,
                    inner_entry,
                    cur_definedness_condition.clone(),
                    existing_visibility_with_menu_dependencies.clone(),
                    existing_dependencies_with_menu_dependencies.clone(),
                    is_in_a_choice,
                );

                findings.extend(cur_findings);
            }
        }
        Choice(c) => {
            debug!("the attributes of the choice are: {:?}", c.options);
            debug!("the entries of the choice are: {:?}", c.entries);

            // we are going to add the dependencies of the choice to the dependencies of the entries.
            //   we start with the dependencies inherited from the file
            let mut existing_dependencies_with_choice_dependencies = cur_dependencies.clone();

            let mut choice_visibility_condition = None;
            let mut defaults = Vec::new();
            for attribute in c.options {
                match attribute {
                    DependsOn(depends_on) => {
                        existing_dependencies_with_choice_dependencies.push(depends_on);
                    }

                    Default(default) => {
                        defaults.push(default);
                    }

                    // the prompt's `if` determines visibility
                    Prompt(prompt) => {
                        choice_visibility_condition = prompt.r#if;
                        if let Some(i) = choice_visibility_condition.clone() {
                            cur_visibility_condition.push(i);
                        }
                    }
                    _ => debug!("skipping attribute {:?} for choice", attribute),
                }
            }

            // all of the variables in the choice menu
            //let mut contained_vars = Vec::with_capacity(c.entries.len());

            for inner_entry in c.entries {
                // just want to make sure that there's nothing unexpected in the choice (like a nested choice...)
                match &inner_entry {
                    Config(_) | Comment(_) | Source(_) => {
                        // TODO: check the comment and source for dead links
                    }
                    _ => {
                        unreachable!("unexpected thing in a choice: {:?}", inner_entry);
                    }
                }

                let cur_findings = entry_processor(
                    args,
                    symbol_table,
                    inner_entry,
                    cur_definedness_condition.clone(),
                    cur_visibility_condition.clone(),
                    existing_dependencies_with_choice_dependencies.clone(),
                    true,
                );

                findings.extend(cur_findings);

                //contained_vars.append(&mut processed_var);
            }

            let choice_data = ChoiceData {
                //inner_vars: contained_vars,
                definedness: cur_definedness_condition,
                visibility: choice_visibility_condition,
                dependencies: existing_dependencies_with_choice_dependencies,
                defaults: defaults,
            };
            symbol_table.choices.push(choice_data);
        }
        Comment(_c) => {
            // TODO: are links allowed in these comments? they don't seem to be used right now.
        }
        Source(s) => {
            let cur_entries = s.entries;

            for inner_entry in cur_entries {
                let cur_findings = entry_processor(
                    args,
                    symbol_table,
                    inner_entry,
                    cur_definedness_condition.clone(),
                    cur_visibility_condition.clone(),
                    cur_dependencies.clone(),
                    is_in_a_choice,
                );

                findings.extend(cur_findings);
            }
        }

        // this is to be treated as a dependency, not a visibility.
        If(i) => {
            let new_dependency = i.condition;

            cur_dependencies.push(new_dependency);

            for inner_entry in i.entries {
                // recursive call
                let cur_findings = entry_processor(
                    args,
                    symbol_table,
                    inner_entry,
                    cur_definedness_condition.clone(),
                    cur_visibility_condition.clone(),
                    cur_dependencies.clone(),
                    is_in_a_choice,
                );

                findings.extend(cur_findings);
            }
        }
        MainMenu(_mm) => {
            // this is just some main menu text
        }
        VariableAssignment(_va) => {
            // TODO: variable assignments are currently unsupported
        }
        Function(_f) => {
            // TODO: function definitions are currently unsupported
        }
        FunctionCall(_fc) => {
            // TODO: function call are currently unsupported
        }
    };
    findings
}
