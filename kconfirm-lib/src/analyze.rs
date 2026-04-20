// SPDX-License-Identifier: GPL-2.0-only

use crate::AnalysisArgs;
use crate::SymbolTable;
use crate::dead_links::{self, LinkStatus, check_link};
use crate::output::{Finding, Severity};
use crate::symbol_table::ChoiceData;

use log::{debug, info, warn};
use nom_kconfig::attribute::DefaultAttribute;
use nom_kconfig::attribute::Expression;
use nom_kconfig::attribute::Select;
use nom_kconfig::attribute::r#type::Type;
use nom_kconfig::entry::Choice;
use nom_kconfig::entry::Config;
use nom_kconfig::entry::If;
use nom_kconfig::entry::Menu;
use nom_kconfig::entry::Source;
use nom_kconfig::{
    Attribute::*,
    Entry::{self, *},
};
use std::collections::HashSet;
use std::option::Option;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FunctionalAttributes {
    // only tracking the attributes that affect the semantics, e.g. not help texts
    Dependencies,
    Selects,
    Implies,
    Ranges,
    Defaults,
}

struct AttributeGroupingChecker {
    current_group: Option<FunctionalAttributes>,
    finished_groups: HashSet<FunctionalAttributes>,
}

impl AttributeGroupingChecker {
    fn new() -> Self {
        Self {
            current_group: None,
            finished_groups: HashSet::new(),
        }
    }

    fn check(
        &mut self,
        group: FunctionalAttributes,
        args: &AnalysisArgs,
        findings: &mut Vec<Finding>,
        symbol: &str,
        message: String,
    ) {
        if !args.check_style {
            return;
        }

        match self.current_group {
            // still contiguous
            Some(current) if current == group => {}

            // start of group
            None => {
                self.current_group = Some(group);
            }

            Some(current) => {
                // the previous group finished
                self.finished_groups.insert(current);

                // we've already finished this group, it's ungrouped
                if self.finished_groups.contains(&group) {
                    findings.push(Finding {
                        severity: Severity::Style,
                        check: "ungrouped_attribute",
                        symbol: Some(symbol.to_string()),
                        message,
                    });
                }

                // switch to the new group
                self.current_group = Some(group);
            }
        }
    }
}

struct DeadLinkChecker {
    visited_links: HashSet<String>,
}

impl DeadLinkChecker {
    fn new() -> Self {
        Self {
            visited_links: HashSet::new(),
        }
    }

    fn check_text(
        &mut self,
        text: &str,
        args: &AnalysisArgs,
        findings: &mut Vec<Finding>,
        symbol: Option<&str>,
        context: &str,
    ) {
        if !args.check_dead_links {
            return;
        }

        let links = dead_links::find_links(text);

        if links.is_empty() {
            return;
        }

        debug!("{} links are: {:?}", context, links);

        for link in links {
            // avoid rechecking identical links
            if !self.visited_links.insert(link.clone()) {
                continue;
            }

            let status = check_link(&link);
            if status != LinkStatus::Ok && status != LinkStatus::ProbablyBlocked {
                findings.push(Finding {
                    severity: Severity::Warning,
                    check: "dead_link",
                    symbol: symbol.map(|s| s.to_string()),
                    message: format!(
                        "{} contains link {} with status {:?}",
                        context, link, status
                    ),
                });
            }
        }
    }
}

pub fn is_duplicate<T: Eq + std::hash::Hash>(set: &mut HashSet<T>, key: T) -> bool {
    !set.insert(key)
}

#[derive(Clone)]
pub struct Context {
    pub arch: Option<String>,
    pub definition_condition: Vec<Expression>,
    pub visibility: Vec<Expression>,
    pub dependencies: Vec<Expression>,
    pub in_choice: bool,
}

// TODO: write a contstructor that just takes an arch

impl Context {
    fn child(&self) -> Self {
        self.clone()
    }

    fn with_dep(mut self, dep: Expression) -> Self {
        self.dependencies.push(dep);
        self
    }

    fn with_visibility(mut self, cond: Expression) -> Self {
        self.visibility.push(cond);
        self
    }

    fn with_definition(mut self, cond: Expression) -> Self {
        self.definition_condition.push(cond);
        self
    }

    fn in_choice(mut self) -> Self {
        self.in_choice = true;
        self
    }
}

fn recurse_entries(
    args: &AnalysisArgs,
    symtab: &mut SymbolTable,
    entries: Vec<Entry>,
    ctx: Context,
    findings: &mut Vec<Finding>,
) {
    for entry in entries {
        process_entry(args, symtab, entry, ctx.clone(), findings);
    }
}

pub fn analyze(entries: Vec<Entry>, args: &AnalysisArgs) -> Vec<Finding> {
    let mut symtab = SymbolTable::new();
    let mut findings = Vec::new();

    let ctx = Context {
        arch: None,
        definition_condition: vec![],
        visibility: vec![],
        dependencies: vec![],
        in_choice: false,
    };

    recurse_entries(args, &mut symtab, entries, ctx, &mut findings);

    findings
}

fn handle_config(
    args: &AnalysisArgs,
    symtab: &mut SymbolTable,
    entry: Config,
    ctx: &Context,
    findings: &mut Vec<Finding>,
) {
    let config_symbol = entry.symbol;
    debug!(
        "starting to process config option `config` type: {}",
        config_symbol
    );

    let mut child_ctx = ctx.clone();

    let mut config_type = None;
    let mut kconfig_dependencies = Vec::new();
    let mut kconfig_selects: Vec<Select> = Vec::new();
    let mut kconfig_ranges = Vec::new();
    let mut kconfig_defaults = Vec::new();
    /*
     * style check: ungrouped attributes
     * - need to check that dependencies, selects, ranges, and defaults are each kept together.
     */

    info!("attributes are: {:?}", &entry.attributes);

    let mut attribute_grouping_checker = AttributeGroupingChecker::new();
    let mut dead_link_checker = DeadLinkChecker::new();
    for attribute in entry.attributes {
        match attribute {
            Type(kconfig_type) => match kconfig_type.r#type.clone() {
                // hybrid type definition and default
                Type::DefBool(db) => {
                    let default_attribute: DefaultAttribute = DefaultAttribute {
                        expression: db.clone(),
                        r#if: kconfig_type.clone().r#if,
                    };

                    kconfig_defaults.push(default_attribute);
                    config_type = Some(kconfig_type);

                    // NOTE: as a style, we prefer to keep the hybrid default-typedef with the standalone defaults
                    attribute_grouping_checker.check(
                        FunctionalAttributes::Defaults,
                        args,
                        findings,
                        &config_symbol,
                        format!("ungrouped default {}", db),
                    );
                }
                Type::Bool(_b) => {
                    config_type = Some(kconfig_type);
                }

                // hybrid type definition and default
                Type::DefTristate(dt) => {
                    // NOTE: as a style, we prefer to keep the hybrid default-typedef with the standalone defaults
                    attribute_grouping_checker.check(
                        FunctionalAttributes::Defaults,
                        args,
                        findings,
                        &config_symbol,
                        format!("ungrouped default {}", &dt),
                    );

                    let default_attribute: DefaultAttribute = DefaultAttribute {
                        expression: dt,
                        r#if: kconfig_type.clone().r#if,
                    };

                    kconfig_defaults.push(default_attribute);
                    config_type = Some(kconfig_type);
                }
                Type::Tristate(_ts) => config_type = Some(kconfig_type.clone()),
                Type::Hex(_h) => config_type = Some(kconfig_type),
                Type::Int(_i) => config_type = Some(kconfig_type),
                Type::String(_s) => config_type = Some(kconfig_type),
            },
            Default(default) => {
                attribute_grouping_checker.check(
                    FunctionalAttributes::Defaults,
                    args,
                    findings,
                    &config_symbol,
                    format!("ungrouped default {}", &default),
                );

                kconfig_defaults.push(default);
            }

            DependsOn(depends_on) => {
                attribute_grouping_checker.check(
                    FunctionalAttributes::Dependencies,
                    args,
                    findings,
                    &config_symbol,
                    format!("ungrouped dependency {}", &depends_on),
                );

                kconfig_dependencies.push(depends_on);
            }
            Select(select) => {
                attribute_grouping_checker.check(
                    FunctionalAttributes::Selects,
                    args,
                    findings,
                    &config_symbol,
                    format!("ungrouped select {}", &select),
                );

                kconfig_selects.push(select);
            }
            Imply(imply) => {
                // doing nothing for imply in the symtab right now

                attribute_grouping_checker.check(
                    FunctionalAttributes::Implies,
                    args,
                    findings,
                    &config_symbol,
                    format!("ungrouped imply {}", imply),
                );

                // TODO: may be relevant for nonvisible config options when building an SMT model...
            }
            // NOTE: range bounds are inclusive
            Range(r) => {
                attribute_grouping_checker.check(
                    FunctionalAttributes::Ranges,
                    args,
                    findings,
                    &config_symbol,
                    format!("ungrouped range {}", r),
                );

                kconfig_ranges.push(r);
            }
            Help(h) => {
                // doing nothing for menu help right now

                dead_link_checker.check_text(&h, args, findings, Some(&config_symbol), "help text");
            }

            Modules => {
                // the modules attribute designates this config option as the one that determines if the `m` state is available for tristates options.

                // just making a special note of this in the symtab for now...
                symtab.modules_option = Some(config_symbol.clone());
            }

            // the prompt's option `if` determines "visibility"
            Prompt(prompt) => {
                if let Some(c) = prompt.r#if {
                    child_ctx = child_ctx.with_visibility(c);
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
    if ctx.in_choice {
        if let Some(kt) = &kconfig_type {
            match kt {
                Type::Bool(_) | Type::DefBool(_) => {
                    // expected in a choice...
                }

                _ => {
                    // TODO: old versions of linux (like 5.4.4) have tristates in the choice
                    //       - u-boot also currently has hex options in the choice!
                    warn!("found something unexpected in a choice-statement: {:?}", kt);
                }
            }
        }
    }

    // at the end, add the file's cur_dependencies to this var's invididual dependencies.
    kconfig_dependencies.extend(ctx.dependencies.clone());
    symtab.merge_insert_new_solved(
        config_symbol.clone(),
        kconfig_type,
        kconfig_dependencies,
        //z3_dependency,
        kconfig_ranges,
        kconfig_defaults,
        ctx.visibility.clone(),
        ctx.arch.clone(),
        ctx.definition_condition.clone(),
        None,
        kconfig_selects
            .clone()
            .into_iter()
            .map(|sel| (sel.symbol, sel.r#if))
            .collect(),
    );

    // need to add the select condition to the definedness condition if it exists
    for select in kconfig_selects {
        match select.r#if {
            None => symtab.merge_insert_new_solved(
                select.symbol,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                ctx.arch.clone(),
                ctx.definition_condition.clone(),
                Some((config_symbol.clone(), None)),
                Vec::new(),
            ),
            Some(select_condition) => {
                symtab.merge_insert_new_solved(
                    select.symbol,
                    None,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    ctx.arch.clone(),
                    ctx.definition_condition.clone(),
                    Some((config_symbol.clone(), Some(select_condition))),
                    Vec::new(),
                );
            }
        }
    }
}

fn handle_menu(
    args: &AnalysisArgs,
    symtab: &mut SymbolTable,
    entry: Menu,
    ctx: &Context,
    findings: &mut Vec<Finding>,
) {
    // menus can set the visibility of their menu items

    let mut existing_dependencies_with_menu_dependencies = ctx.dependencies.clone();
    let mut existing_visibility_with_menu_dependencies = ctx.visibility.clone();

    if !entry.depends_on.is_empty() {
        debug!(
            "the menu {:?} dependencies are: {:?}",
            entry, entry.depends_on
        );
    }

    existing_dependencies_with_menu_dependencies.extend(entry.depends_on.clone());
    existing_visibility_with_menu_dependencies.extend(entry.depends_on.clone());

    let nested_entries = entry.entries;
    for inner_entry in nested_entries {
        // recursive call
        let cur_findings = entry_processor(
            args,
            symtab,
            inner_entry,
            ctx.arch.clone(),
            ctx.definition_condition.clone(),
            existing_visibility_with_menu_dependencies.clone(),
            existing_dependencies_with_menu_dependencies.clone(),
            ctx.in_choice,
        );

        findings.extend(cur_findings);
    }
}

fn handle_choice(
    args: &AnalysisArgs,
    symtab: &mut SymbolTable,
    entry: Choice,
    ctx: &Context,
    findings: &mut Vec<Finding>,
) {
    debug!("the attributes of the choice are: {:?}", entry.options);
    debug!("the entries of the choice are: {:?}", entry.entries);

    let mut child_ctx = ctx.clone();

    // we are going to add the dependencies of the choice to the dependencies of the entries.
    //   we start with the dependencies inherited from the file
    let mut existing_dependencies_with_choice_dependencies = child_ctx.dependencies.clone();

    let mut choice_visibility_condition = None;
    let mut defaults = Vec::new();
    for attribute in entry.options {
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
                    child_ctx = child_ctx.with_visibility(i);
                }
            }
            _ => debug!("skipping attribute {:?} for choice", attribute),
        }
    }

    // all of the variables in the choice menu
    //let mut contained_vars = Vec::with_capacity(c.entries.len());
    let nested_entries = entry.entries;
    for inner_entry in nested_entries {
        // just want to make sure that there's nothing unexpected in the choice (like a nested choice...)
        match inner_entry {
            Config(_) | Comment(_) | Source(_) => {
                // TODO: check the comment and source for dead links

                let cur_findings = entry_processor(
                    args,
                    symtab,
                    inner_entry,
                    child_ctx.arch.clone(),
                    child_ctx.definition_condition.clone(),
                    child_ctx.visibility.clone(),
                    existing_dependencies_with_choice_dependencies.clone(),
                    true,
                );

                findings.extend(cur_findings);
            }
            If(i) => {
                // if-statements within choice-statements are not present (right now) in linux, coreboot, or openwrt.
                // is present in u-boot!!!

                child_ctx = child_ctx.with_dep(i.condition.clone());
                child_ctx = child_ctx.with_definition(i.condition);

                for inner_entry in i.entries {
                    // recursive call
                    let cur_findings = entry_processor(
                        args,
                        symtab,
                        inner_entry,
                        child_ctx.arch.clone(),
                        child_ctx.definition_condition.clone(),
                        child_ctx.visibility.clone(),
                        child_ctx.dependencies.clone(),
                        child_ctx.in_choice,
                    );

                    findings.extend(cur_findings);
                }
            }
            _ => {
                unreachable!("unexpected thing in a choice: {:?}", inner_entry);
            }
        }

        //contained_vars.append(&mut processed_var);
    }

    let choice_data = ChoiceData {
        //inner_vars: contained_vars,
        arch: child_ctx.arch.clone(),
        visibility: choice_visibility_condition,
        dependencies: existing_dependencies_with_choice_dependencies,
        defaults: defaults,
    };
    symtab.choices.push(choice_data);
}

fn handle_if(
    args: &AnalysisArgs,
    symtab: &mut SymbolTable,
    entry: If,
    ctx: &Context,
    findings: &mut Vec<Finding>,
) {
    let mut child_ctx = ctx.clone();
    child_ctx = child_ctx.with_definition(entry.condition.clone());
    child_ctx = child_ctx.with_dep(entry.condition);
    let nested_entries = entry.entries;
    for inner_entry in nested_entries {
        // recursive call
        let cur_findings = entry_processor(
            args,
            symtab,
            inner_entry,
            child_ctx.arch.clone(),
            child_ctx.definition_condition.clone(),
            child_ctx.visibility.clone(),
            child_ctx.dependencies.clone(),
            child_ctx.in_choice,
        );

        findings.extend(cur_findings);
    }
}

fn handle_source(
    args: &AnalysisArgs,
    symtab: &mut SymbolTable,
    entry: Source,
    ctx: &Context,
    findings: &mut Vec<Finding>,
) {
    let sourced_kconfig = entry.entries;

    for sourced_kconfig in sourced_kconfig {
        for inner_entry in sourced_kconfig.entries {
            let cur_findings = entry_processor(
                args,
                symtab,
                inner_entry,
                ctx.arch.clone(),
                ctx.definition_condition.clone(),
                ctx.visibility.clone(),
                ctx.dependencies.clone(),
                ctx.in_choice,
            );

            findings.extend(cur_findings);
        }
    }
}

pub fn process_entry(
    args: &AnalysisArgs,
    symtab: &mut SymbolTable,
    entry: Entry,
    ctx: Context,
    findings: &mut Vec<Finding>,
) {
    match entry {
        Entry::Config(c) | Entry::MenuConfig(c) => {
            handle_config(args, symtab, c, &ctx, findings);
        }
        Entry::Menu(m) => handle_menu(args, symtab, m, &ctx, findings),
        Entry::Choice(c) => handle_choice(args, symtab, c, &ctx, findings),
        Entry::If(i) => handle_if(args, symtab, i, &ctx, findings),
        Entry::Source(s) => handle_source(args, symtab, s, &ctx, findings),
        Entry::Comment(_) => {}
        Entry::MainMenu(_) => {}
        _ => {}
    }
}

// recursively enters each entry until we reach the Configs and then translates them into z3 types/logic.
// inserts the entry into the symbol table.
// returns the config option identifier string, so that the menu choice can gather these for the mutual exclusion constraint.
pub fn entry_processor(
    args: &AnalysisArgs,
    symbol_table: &mut SymbolTable,
    entry: Entry,
    arch: Option<String>, // Some(ARCH_OPTION_NAME) if the inclusion & definition of the entry is arch-specific, 'None' o/w
    definition_condition: Vec<Expression>, // this is the condition (coming from if-statements) that determines if the config definition happens or not.
    old_visibility_condition: Vec<Expression>, // pass a fresh vector on the first call (visible by default)
    old_dependencies: Vec<Expression>, // pass a fresh vector on the first call (no dependencies)
    is_in_a_choice: bool, // this value will get passed down with each recursive call (because you could have choice->source->config/bool)
) -> Vec<Finding> {
    let mut findings = Vec::new(); // will return this later

    let mut cur_definition_condition = definition_condition.clone();

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
            /*
             * style check: ungrouped attributes
             * - need to check that dependencies, selects, ranges, and defaults are each kept together.
             */

            info!("attributes are: {:?}", &c.attributes);

            let mut attribute_grouping_checker = AttributeGroupingChecker::new();
            let mut dead_link_checker = DeadLinkChecker::new();
            for attribute in c.attributes {
                match attribute {
                    Type(kconfig_type) => match kconfig_type.r#type.clone() {
                        // hybrid type definition and default
                        Type::DefBool(db) => {
                            let default_attribute: DefaultAttribute = DefaultAttribute {
                                expression: db.clone(),
                                r#if: kconfig_type.clone().r#if,
                            };

                            kconfig_defaults.push(default_attribute);
                            config_type = Some(kconfig_type);

                            // NOTE: as a style, we prefer to keep the hybrid default-typedef with the standalone defaults
                            attribute_grouping_checker.check(
                                FunctionalAttributes::Defaults,
                                args,
                                &mut findings,
                                &config_symbol,
                                format!("ungrouped default {}", db),
                            );
                        }
                        Type::Bool(_b) => {
                            config_type = Some(kconfig_type);
                        }

                        // hybrid type definition and default
                        Type::DefTristate(dt) => {
                            // NOTE: as a style, we prefer to keep the hybrid default-typedef with the standalone defaults
                            attribute_grouping_checker.check(
                                FunctionalAttributes::Defaults,
                                args,
                                &mut findings,
                                &config_symbol,
                                format!("ungrouped default {}", &dt),
                            );

                            let default_attribute: DefaultAttribute = DefaultAttribute {
                                expression: dt,
                                r#if: kconfig_type.clone().r#if,
                            };

                            kconfig_defaults.push(default_attribute);
                            config_type = Some(kconfig_type);
                        }
                        Type::Tristate(_ts) => config_type = Some(kconfig_type.clone()),
                        Type::Hex(_h) => config_type = Some(kconfig_type),
                        Type::Int(_i) => config_type = Some(kconfig_type),
                        Type::String(_s) => config_type = Some(kconfig_type),
                    },
                    Default(default) => {
                        attribute_grouping_checker.check(
                            FunctionalAttributes::Defaults,
                            args,
                            &mut findings,
                            &config_symbol,
                            format!("ungrouped default {}", &default),
                        );

                        kconfig_defaults.push(default);
                    }

                    DependsOn(depends_on) => {
                        attribute_grouping_checker.check(
                            FunctionalAttributes::Dependencies,
                            args,
                            &mut findings,
                            &config_symbol,
                            format!("ungrouped dependency {}", &depends_on),
                        );

                        kconfig_dependencies.push(depends_on);
                    }
                    Select(select) => {
                        attribute_grouping_checker.check(
                            FunctionalAttributes::Selects,
                            args,
                            &mut findings,
                            &config_symbol,
                            format!("ungrouped select {}", &select),
                        );

                        kconfig_selects.push(select);
                    }
                    Imply(imply) => {
                        // doing nothing for imply in the symtab right now

                        attribute_grouping_checker.check(
                            FunctionalAttributes::Implies,
                            args,
                            &mut findings,
                            &config_symbol,
                            format!("ungrouped imply {}", imply),
                        );

                        // TODO: may be relevant for nonvisible config options when building an SMT model...
                    }
                    // NOTE: range bounds are inclusive
                    Range(r) => {
                        attribute_grouping_checker.check(
                            FunctionalAttributes::Ranges,
                            args,
                            &mut findings,
                            &config_symbol,
                            format!("ungrouped range {}", r),
                        );

                        kconfig_ranges.push(r);
                    }
                    Help(h) => {
                        // doing nothing for menu help right now

                        dead_link_checker.check_text(
                            &h,
                            args,
                            &mut findings,
                            Some(&config_symbol),
                            "help text",
                        );
                    }

                    Modules => {
                        // the modules attribute designates this config option as the one that determines if the `m` state is available for tristates options.

                        // just making a special note of this in the symtab for now...
                        symbol_table.modules_option = Some(config_symbol.clone());
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

                        _ => {
                            // TODO: old versions of linux (like 5.4.4) have tristates in the choice
                            //       - u-boot also currently has hex options in the choice!
                            warn!("found something unexpected in a choice-statement: {:?}", kt);
                        }
                    }
                }
            }

            // at the end, add the file's cur_dependencies to this var's invididual dependencies.
            kconfig_dependencies.extend(cur_dependencies.clone());
            symbol_table.merge_insert_new_solved(
                config_symbol.clone(),
                kconfig_type,
                kconfig_dependencies,
                //z3_dependency,
                kconfig_ranges,
                kconfig_defaults,
                cur_visibility_condition.clone(),
                arch.clone(),
                cur_definition_condition.clone(),
                None,
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
                        arch.clone(),
                        cur_definition_condition.clone(),
                        Some((config_symbol.clone(), None)),
                        Vec::new(),
                    ),
                    Some(select_condition) => {
                        symbol_table.merge_insert_new_solved(
                            select.symbol,
                            None,
                            Vec::new(),
                            Vec::new(),
                            Vec::new(),
                            Vec::new(),
                            arch.clone(),
                            cur_definition_condition.clone(),
                            Some((config_symbol.clone(), Some(select_condition))),
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
                    arch.clone(),
                    cur_definition_condition.clone(),
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
                match inner_entry {
                    Config(_) | Comment(_) | Source(_) => {
                        // TODO: check the comment and source for dead links

                        let cur_findings = entry_processor(
                            args,
                            symbol_table,
                            inner_entry,
                            arch.clone(),
                            cur_definition_condition.clone(),
                            cur_visibility_condition.clone(),
                            existing_dependencies_with_choice_dependencies.clone(),
                            true,
                        );

                        findings.extend(cur_findings);
                    }
                    If(i) => {
                        // if-statements within choice-statements are not present (right now) in linux, coreboot, or openwrt.
                        // is present in u-boot!!!

                        cur_dependencies.push(i.condition.clone());
                        cur_definition_condition.push(i.condition);

                        for inner_entry in i.entries {
                            // recursive call
                            let cur_findings = entry_processor(
                                args,
                                symbol_table,
                                inner_entry,
                                arch.clone(),
                                cur_definition_condition.clone(),
                                cur_visibility_condition.clone(),
                                cur_dependencies.clone(),
                                is_in_a_choice,
                            );

                            findings.extend(cur_findings);
                        }
                    }
                    _ => {
                        unreachable!("unexpected thing in a choice: {:?}", inner_entry);
                    }
                }

                //contained_vars.append(&mut processed_var);
            }

            let choice_data = ChoiceData {
                //inner_vars: contained_vars,
                arch,
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
            let sourced_kconfig = s.entries;

            for entry in sourced_kconfig {
                for inner_entry in entry.entries {
                    let cur_findings = entry_processor(
                        args,
                        symbol_table,
                        inner_entry,
                        arch.clone(),
                        cur_definition_condition.clone(),
                        cur_visibility_condition.clone(),
                        cur_dependencies.clone(),
                        is_in_a_choice,
                    );

                    findings.extend(cur_findings);
                }
            }
        }

        // this is to be treated as a dependency, and a condition for a config definition.
        If(i) => {
            cur_definition_condition.push(i.condition.clone());
            cur_dependencies.push(i.condition);

            for inner_entry in i.entries {
                // recursive call
                let cur_findings = entry_processor(
                    args,
                    symbol_table,
                    inner_entry,
                    arch.clone(),
                    cur_definition_condition.clone(),
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
