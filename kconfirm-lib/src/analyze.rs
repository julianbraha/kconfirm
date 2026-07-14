// SPDX-License-Identifier: GPL-2.0-only
use crate::{
    AnalysisArgs, AttributeDef, Check, SymbolTable,
    checks::unconditional_visibility,
    dead_links::{
        self,
        LinkStatus,
        check_link, //
    },
    output::{
        Finding,
        Severity, //
    },
    symbol_table::ChoiceData,
};
use log::{
    debug,
    error,
    warn, //
};
use nom_kconfig::{
    Attribute::*,
    Entry,
    attribute::{
        DefaultAttribute,
        Expression,
        Imply,
        Select,
        r#type::Type, //
    },
    entry::{
        Choice,
        Config,
        If,
        Menu,
        Source, //
    },
};
use std::{
    collections::HashSet,
    option::Option, //
};

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

    // doesn't modify `findings` if the style check is disabled
    fn check(
        &mut self,
        group: FunctionalAttributes,
        args: &AnalysisArgs,
        findings: &mut Vec<Finding>,
        symbol: &str,
        arch: &Option<String>,
        message: String,
    ) {
        if !args.is_enabled(Check::UngroupedAttribute) {
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
                        check: Check::UngroupedAttribute,
                        symbol: Some(symbol.to_string()),
                        message,
                        arch: arch.to_owned(),
                    });
                }

                // switch to the new group
                self.current_group = Some(group);
            }
        }
    }
}

/// Runs the "ungrouped attribute" style check on the raw parsed `entries`.
///
/// This must run *before* desugaring: `kconfirm-desugar` combines every
/// `depends on` of a config into a single attribute and reorders/splits others,
/// which destroys the original source grouping that this style check reports on.
/// Recurses into menus, choices, `if` blocks and sourced files, mirroring
/// [`process_entry`].
pub(crate) fn check_attribute_grouping(
    args: &AnalysisArgs,
    arch: &Option<String>,
    entries: &[Entry],
    findings: &mut Vec<Finding>,
) {
    for entry in entries {
        match entry {
            Entry::Config(config) | Entry::MenuConfig(config) => {
                check_config_grouping(args, arch, config, findings);
            }
            Entry::Menu(menu) => check_attribute_grouping(args, arch, &menu.entries, findings),
            Entry::Choice(choice) => {
                check_attribute_grouping(args, arch, &choice.entries, findings)
            }
            Entry::If(r#if) => check_attribute_grouping(args, arch, &r#if.entries, findings),
            Entry::Source(source) => {
                for sourced in &source.kconfigs {
                    check_attribute_grouping(args, arch, &sourced.entries, findings);
                }
            }
            _ => {}
        }
    }
}

// Checks that a single config's functional attributes (dependencies, selects,
// implies, ranges, defaults) are each kept contiguous in the source. The
// def_bool/def_tristate hybrid type+default forms group with the defaults.
fn check_config_grouping(
    args: &AnalysisArgs,
    arch: &Option<String>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let mut checker = AttributeGroupingChecker::new();
    for attribute in &config.attributes {
        let (group, message) = match attribute {
            Type(kconfig_type) => match &kconfig_type.r#type {
                Type::DefBool(db) => (
                    FunctionalAttributes::Defaults,
                    format!("ungrouped default {}", db),
                ),
                Type::DefTristate(dt) => (
                    FunctionalAttributes::Defaults,
                    format!("ungrouped default {}", dt),
                ),
                _ => continue,
            },
            Default(default) => (
                FunctionalAttributes::Defaults,
                format!("ungrouped default {}", default),
            ),
            DependsOn(depends_on) => (
                FunctionalAttributes::Dependencies,
                format!("ungrouped dependency {}", depends_on),
            ),
            Select(select) => (
                FunctionalAttributes::Selects,
                format!("ungrouped select {}", select),
            ),
            Imply(imply) => (
                FunctionalAttributes::Implies,
                format!("ungrouped imply {}", imply),
            ),
            Range(r) => (
                FunctionalAttributes::Ranges,
                format!("ungrouped range {}", r),
            ),
            _ => continue,
        };
        checker.check(group, args, findings, &config.symbol, arch, message);
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
        arch: &Option<String>,
        context: &str,
    ) {
        if !args.is_enabled(Check::DeadLink) {
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
                    check: Check::DeadLink,
                    symbol: symbol.map(|s| s.to_string()),
                    message: format!(
                        "{} contains link {} with status {}",
                        context,
                        link,
                        status.as_str()
                    ),
                    arch: arch.to_owned(),
                });
            }
        }
    }
}

#[derive(Clone)]
pub struct Context {
    pub arch: Option<String>,
    pub definition_condition: Vec<Expression>,
    pub in_choice: bool,
}

impl Context {
    fn with_arch(arch: Option<String>) -> Context {
        Context {
            arch,
            definition_condition: vec![],
            in_choice: false,
        }
    }

    fn child(&self) -> Self {
        self.clone()
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

/// Traverses `nom-kconfig` AST entries to construct the symbol table, and run checks on config
/// option definitions.
///
/// This function recursively processes [`Entry`] elements under a specific
/// architecture context provided by the `arch` argument. It evaluates using the checks passed in
/// the `args`, and builds up the symbol table [`SymbolTable`].
///
/// Findings from the checks are gathered and returned as an array of [`Finding`].
///
/// # Examples
///
/// ```
/// use kconfirm_lib::{analyze, AnalysisArgs, SymbolTable};
///
/// let args = AnalysisArgs::new();
/// let mut symtab = SymbolTable::new();
/// let entries = vec![]; // Populated by the nom-kconfig parser.
///
/// let findings = analyze(&args, &mut symtab, Some("x86".to_string()), entries);
/// println!("Analysis on config option definitions complete. Total warnings: {}", findings.len());
/// ```
pub fn analyze(
    args: &AnalysisArgs,
    symtab: &mut SymbolTable,
    arch: Option<String>,
    entries: Vec<Entry>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let ctx = Context::with_arch(arch);

    recurse_entries(args, symtab, entries, ctx, &mut findings);

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

    let child_ctx = ctx.child();

    let mut config_type = None;
    // kconfirm-desugar combines every `depends on` (including those inherited
    // from enclosing menus/choices/ifs) into a single condition, so a config has
    // at most one dependency expression here.
    let mut kconfig_dependencies: Option<Expression> = None;
    let mut kconfig_selects: Vec<Select> = Vec::new();
    let mut kconfig_implies: Vec<Imply> = Vec::new();
    let mut kconfig_ranges = Vec::new();
    let mut kconfig_defaults = Vec::new();
    // The visibility condition comes solely from the config's prompt: `None` if it has no
    // prompt, `Some(y)` for an unconditional prompt, or `Some(cond)` for a `prompt ... if cond`.
    let mut visibility: Option<Expression> = None;

    debug!("attributes are: {:?}", &entry.attributes);
    // The "ungrouped attribute" style check runs on the raw entries via
    // `check_attribute_grouping` (called before desugaring), because desugaring
    // reorders and combines the attributes iterated below.
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
                }
                Type::Bool(_prompt) => {
                    config_type = Some(kconfig_type);
                }

                // hybrid type definition and default
                Type::DefTristate(dt) => {
                    let default_attribute: DefaultAttribute = DefaultAttribute {
                        expression: dt,
                        r#if: kconfig_type.clone().r#if,
                    };

                    kconfig_defaults.push(default_attribute);
                    config_type = Some(kconfig_type);
                }
                Type::Tristate(_prompt) => {
                    config_type = Some(kconfig_type);
                }
                Type::Hex(_prompt) => {
                    config_type = Some(kconfig_type);
                }
                Type::Int(_prompt) => {
                    config_type = Some(kconfig_type);
                }
                Type::String(_prompt) => {
                    config_type = Some(kconfig_type);
                }
                Type::DefInt(_) | Type::DefHex(_) | Type::DefString(_) => {
                    todo!("consider handling kconfiglib extension")
                }
            },
            Default(default) => {
                kconfig_defaults.push(default);
            }

            DependsOn(depends_on) => {
                // kconfirm-desugar has already combined all `depends on`
                // attributes into a single one, so we expect to see at most one.
                debug_assert!(
                    kconfig_dependencies.is_none(),
                    "expected kconfirm-desugar to combine dependencies into one"
                );
                kconfig_dependencies = Some(depends_on.expression);
            }
            Select(select) => {
                kconfig_selects.push(select);
            }
            Imply(imply) => {
                kconfig_implies.push(imply);

                // TODO: may be relevant for nonvisible config options when building an SMT model...
            }
            // NOTE: range bounds are inclusive
            Range(r) => {
                kconfig_ranges.push(r);
            }
            Help(h) => {
                // doing nothing for menu help right now

                dead_link_checker.check_text(
                    &h,
                    args,
                    findings,
                    Some(&config_symbol),
                    &ctx.arch,
                    "help text",
                );
            }

            Modules => {
                // the modules attribute designates this config option as the one that determines if the `m` state is available for tristates options.

                // just making a special note of this in the symtab for now...
                symtab.modules_option = Some(config_symbol.clone());
            }

            // the prompt determines "visibility": an unconditional prompt is always visible (`y`),
            // while a `prompt ... if cond` is visible exactly when `cond` holds.
            Prompt(prompt) => {
                // TODO: once we have SMT solving, we can also check if the prompt condition is always true or never true (and therefore, effectively unconditional)

                visibility = Some(prompt.r#if.unwrap_or_else(unconditional_visibility));
            }
            Transitional => {
                // doing nothing for transitional right now
            }
            Optional | Visible(_) | Requires(_) | Option(_) => {
                error!("Unexpected attribute encountered: {:?}", attribute);

                if cfg!(debug_assertions) {
                    panic!();
                }
            }
        }
    }

    // there can be multiple entries that get merged. so we need to do the same for our symtab.
    let kconfig_type = config_type.clone().map(|c| c.r#type);

    // at the time of writing this, linux's kconfig only uses Bool inside Choice.
    // however, the kconfig documentation doesn't specify whether or not this is guaranteed to be the case.
    // we add this check to ensure that we don't cause undefined behavior in future linux versions if something changes...
    if child_ctx.in_choice {
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

    symtab.insert_definition(
        config_symbol.clone(),
        child_ctx.arch.clone(),
        kconfig_type,
        AttributeDef {
            kconfig_dependencies: kconfig_dependencies,
            kconfig_ranges: kconfig_ranges,
            kconfig_defaults: kconfig_defaults,
            visibility: visibility,
            selects: kconfig_selects
                .clone()
                .into_iter()
                .map(|sel| (sel.symbol, sel.r#if))
                .collect(),
            implies: kconfig_implies
                .clone()
                .into_iter()
                .map(|imply| (imply.symbol.to_string(), imply.r#if))
                .collect(),
        },
    );
    // TODO: file a github issue, imply can never imply a constant (this is technically parsing incorrectly)

    // need to add the select condition to the definedness condition if it exists
    for select in kconfig_selects {
        symtab.add_selected_by(
            select.symbol,
            child_ctx.arch.clone(),
            config_symbol.clone(),
            select.r#if,
        );
    }

    // keep track of the implier in the implied option's `implied_by` list, the same way we
    // track selectors in `selected_by`. `imply` references a `Symbol`, which we store as a
    // string like other references to config options.
    for imply in kconfig_implies {
        symtab.add_implied_by(
            imply.symbol.to_string(), // TODO: report issue on nom-kconfig, this should be a string too, I think (like select.symbol)
            child_ctx.arch.clone(),
            config_symbol.clone(),
            imply.r#if,
        );
    }
}

fn handle_menu(
    args: &AnalysisArgs,
    symtab: &mut SymbolTable,
    entry: Menu,
    ctx: &Context,
    findings: &mut Vec<Finding>,
) {
    let child_ctx = ctx.child();

    if !entry.depends_on.is_empty() {
        debug!(
            "the menu {:?} dependencies are: {:?}",
            entry, entry.depends_on
        );
    }

    // The menu's dependencies are already copied onto the contained config options by
    // kconfirm-desugar, and a config option's visibility now comes solely from its own
    // prompt, so the menu contributes nothing to the context here.
    let nested_entries = entry.entries;

    recurse_entries(args, symtab, nested_entries, child_ctx.clone(), findings);
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

    let mut child_ctx = ctx.child();
    child_ctx = child_ctx.in_choice();

    // The choice's dependencies are already copied onto the contained config
    // options by kconfirm-desugar, so we don't add them to the context here; we
    // only record them on the ChoiceData for completeness.
    let mut choice_visibility_condition = None;
    let mut dependencies = Vec::new();
    let mut defaults = Vec::new();
    for attribute in entry.options {
        match attribute {
            DependsOn(depends_on) => {
                dependencies.push(depends_on.expression);
            }

            Default(default) => {
                defaults.push(default);
            }

            // the prompt's `if` determines the choice's own visibility; contained config
            // options derive their visibility from their own prompts, not the choice's.
            Prompt(prompt) => {
                choice_visibility_condition = prompt.r#if;
            }
            _ => debug!("skipping attribute {:?} for choice", attribute),
        }
    }

    // all of the variables in the choice menu
    //let mut contained_vars = Vec::with_capacity(c.entries.len());
    let nested_entries = entry.entries;
    let nested_entries_count = (&nested_entries).len();

    let mut contained_config_symbols = Vec::with_capacity(nested_entries_count);

    for entry in &nested_entries {
        match entry {
            Entry::Config(c) => contained_config_symbols.push(c.symbol.clone()),
            Entry::Comment(_) => {}
            _ => unreachable!("unexpected entry in a choice: {:?}", entry),
        }
    }

    recurse_entries(args, symtab, nested_entries, child_ctx.clone(), findings);

    let choice_data = ChoiceData {
        //inner_vars: contained_vars,
        arch: child_ctx.arch.clone(),
        visibility: choice_visibility_condition,
        dependencies,
        defaults,
        config_options: contained_config_symbols,
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
    let mut child_ctx = ctx.child();
    // `if` entries are eliminated by kconfirm-desugar (their condition is pushed
    // onto the contained config options), so we no longer inherit it as a
    // dependency; we still record it as a definition condition.
    child_ctx = child_ctx.with_definition(entry.condition);
    let nested_entries = entry.entries;

    recurse_entries(args, symtab, nested_entries, child_ctx, findings);
}

fn handle_source(
    args: &AnalysisArgs,
    symtab: &mut SymbolTable,
    entry: Source,
    ctx: &Context,
    findings: &mut Vec<Finding>,
) {
    let sourced_kconfig = entry.kconfigs;

    for sourced_kconfig in sourced_kconfig {
        recurse_entries(args, symtab, sourced_kconfig.entries, ctx.clone(), findings);
    }
}

pub fn process_entry(
    args: &AnalysisArgs,
    symtab: &mut SymbolTable,
    entry: Entry,
    ctx: Context,
    findings: &mut Vec<Finding>,
) {
    // NOTE: in general, each handler should update the context as it encounters that construct.
    //       e.g. Context.in_choice() should be called at the start of handle_choice(), not right before call to process_entry() when a choice is found and process_entry is called
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
