//! NOTE: tests are AI slop that I generated after getting things to work.
//! TODO: review these more carefully and consider handwritten tests.
//! End-to-end tests for the public `desugar_kconfig` entry point.
//!
//! These run the whole pass pipeline on parsed Kconfig text and assert on the
//! fully desugared output.

use kconfirm_desugar::desugar_kconfig;
use nom_kconfig::{
    Attribute,
    Entry,
    KconfigInput,
    attribute::r#type::Type,
    entry::{Config, Source},
    parse_kconfig, //
};

/// Parse Kconfig text and run the full desugaring pipeline over it.
fn desugar(text: &str) -> Vec<Entry> {
    let kconfig = parse_kconfig(KconfigInput::new_extra(text, Default::default()))
        .expect("kconfig text should parse")
        .1;
    desugar_kconfig(Source {
        kconfigs: vec![kconfig],
    })
}

/// Find the desugared `config` with the given symbol.
fn config(entries: &[Entry], symbol: &str) -> Config {
    entries
        .iter()
        .find_map(|entry| match entry {
            Entry::Config(c) if c.symbol == symbol => Some(c.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no config named {symbol} in {entries:?}"))
}

/// Find the desugared `config`/`menuconfig` with the given symbol anywhere in
/// the entry tree, descending into menus and choices.
fn config_anywhere(entries: &[Entry], symbol: &str) -> Config {
    fn find(entries: &[Entry], symbol: &str) -> Option<Config> {
        entries.iter().find_map(|entry| match entry {
            Entry::Config(c) | Entry::MenuConfig(c) if c.symbol == symbol => Some(c.clone()),
            Entry::Menu(menu) => find(&menu.entries, symbol),
            Entry::Choice(choice) => find(&choice.entries, symbol),
            _ => None,
        })
    }
    find(entries, symbol).unwrap_or_else(|| panic!("no config named {symbol} in {entries:?}"))
}

fn depends_on(config: &Config) -> Vec<String> {
    config
        .attributes
        .iter()
        .filter_map(|attribute| match attribute {
            Attribute::DependsOn(expression) => Some(expression.to_string()),
            _ => None,
        })
        .collect()
}

fn defaults(config: &Config) -> Vec<String> {
    config
        .attributes
        .iter()
        .filter_map(|attribute| match attribute {
            Attribute::Default(default) => Some(default.expression.to_string()),
            _ => None,
        })
        .collect()
}

fn type_of(config: &Config) -> Type {
    config
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            Attribute::Type(config_type) => Some(config_type.r#type.clone()),
            _ => None,
        })
        .expect("config should have a type attribute")
}

#[test]
fn a_plain_config_passes_through() {
    let entries = desugar("config FOO\nbool\n");

    assert_eq!(entries.len(), 1);
    let foo = config(&entries, "FOO");
    assert!(matches!(type_of(&foo), Type::Bool(None)));
    assert!(depends_on(&foo).is_empty());
}

#[test]
fn an_if_block_becomes_a_dependency_of_its_configs() {
    let entries = desugar("if A\nconfig FOO\nbool\ndepends on B\nselect C\nendif\n");

    let foo = config(&entries, "FOO");
    // the `if A` was appended as a dependency, and combine_depends folded it
    // into the config's own `depends on`.
    assert_eq!(depends_on(&foo), vec!["B && A"]);
    // `select C` is untouched: the condition lives only in the dependency.
    let selects: Vec<String> = foo
        .attributes
        .iter()
        .filter_map(|attribute| match attribute {
            Attribute::Select(select) => Some(select.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(selects, vec!["C"]);
}

#[test]
fn a_compound_if_block_condition_survives_into_the_dependency() {
    let entries = desugar("if A && B\nconfig FOO\nbool\ndepends on X\nendif\n");

    let foo = config(&entries, "FOO");
    // distribute_if appends `depends on A && B`; combine_depends flattens the
    // AND chain into the existing dependency.
    assert_eq!(depends_on(&foo), vec!["X && A && B"]);
}

#[test]
fn a_config_inside_a_menu_inside_an_if_inherits_the_dependency() {
    let entries = desugar("if A\nmenu \"m\"\nconfig FOO\nbool\ndepends on B\nendmenu\nendif\n");

    // the `if` put its condition on the menu, and distribute_menu copied it
    // down onto the contained config, so the dependency reaches FOO too.
    let menu = match &entries[0] {
        Entry::Menu(menu) => menu,
        other => panic!("expected a menu entry, got {other:?}"),
    };
    let foo = menu
        .entries
        .iter()
        .find_map(|entry| match entry {
            Entry::Config(config) if config.symbol == "FOO" => Some(config.clone()),
            _ => None,
        })
        .expect("no config named FOO inside the menu");
    assert_eq!(depends_on(&foo), vec!["B && A"]);
}

#[test]
fn a_def_bool_inside_an_if_gains_the_condition_as_a_dependency() {
    let entries = desugar("if A\nconfig FOO\ndef_bool BAR\nendif\n");

    let foo = config(&entries, "FOO");
    assert!(matches!(type_of(&foo), Type::Bool(None)));
    assert_eq!(defaults(&foo), vec!["BAR"]);
    // the `if A` ends up as a dependency; the expanded default keeps no
    // condition of its own.
    assert_eq!(depends_on(&foo), vec!["A"]);
    let default_conditions: Vec<Option<String>> = foo
        .attributes
        .iter()
        .filter_map(|attribute| match attribute {
            Attribute::Default(default) => Some(default.r#if.as_ref().map(|c| c.to_string())),
            _ => None,
        })
        .collect();
    assert_eq!(default_conditions, vec![None]);
}

#[test]
fn def_bool_is_expanded_into_a_bool_and_a_default() {
    let entries = desugar("config FOO\ndef_bool BAR\n");

    let foo = config(&entries, "FOO");
    assert!(matches!(type_of(&foo), Type::Bool(None)));
    assert_eq!(defaults(&foo), vec!["BAR"]);
}

#[test]
fn def_tristate_with_a_condition_keeps_the_default_expression() {
    let entries = desugar("config FOO\ndef_tristate BAR && BAZ\n");

    let foo = config(&entries, "FOO");
    assert!(matches!(type_of(&foo), Type::Tristate(None)));
    assert_eq!(defaults(&foo), vec!["BAR && BAZ"]);
}

#[test]
fn def_bool_inside_a_menu_is_expanded() {
    let entries = desugar("menu \"m\"\nconfig FOO\ndef_bool BAR\nendmenu\n");

    // the config stays nested inside the menu; the def_bool is expanded anyway.
    assert!(matches!(entries[0], Entry::Menu(_)));
    let foo = config_anywhere(&entries, "FOO");
    assert!(matches!(type_of(&foo), Type::Bool(None)));
    assert_eq!(defaults(&foo), vec!["BAR"]);
}

#[test]
fn def_bool_inside_a_nested_menu_is_expanded() {
    let entries =
        desugar("menu \"outer\"\nmenu \"inner\"\nconfig FOO\ndef_bool BAR\nendmenu\nendmenu\n");

    let foo = config_anywhere(&entries, "FOO");
    assert!(matches!(type_of(&foo), Type::Bool(None)));
    assert_eq!(defaults(&foo), vec!["BAR"]);
}

#[test]
fn def_bool_on_a_menuconfig_is_expanded() {
    let entries = desugar("menuconfig FOO\ndef_bool BAR\n");

    // the entry keeps its menuconfig kind.
    assert!(matches!(entries[0], Entry::MenuConfig(_)));
    let foo = config_anywhere(&entries, "FOO");
    assert!(matches!(type_of(&foo), Type::Bool(None)));
    assert_eq!(defaults(&foo), vec!["BAR"]);
}

#[test]
fn def_bool_inside_a_choice_is_expanded() {
    let entries = desugar("choice\nprompt \"c\"\nconfig FOO\ndef_bool BAR\nendchoice\n");

    let foo = config_anywhere(&entries, "FOO");
    assert!(matches!(type_of(&foo), Type::Bool(None)));
    assert_eq!(defaults(&foo), vec!["BAR"]);
}

#[test]
fn a_typed_prompt_is_split_into_a_prompt_and_a_bare_type() {
    let entries = desugar("config FOO\nbool \"enable foo\"\ndepends on BAR\n");

    let foo = config(&entries, "FOO");
    assert!(matches!(type_of(&foo), Type::Bool(None)));
    let prompt_count = foo
        .attributes
        .iter()
        .filter(|a| matches!(a, Attribute::Prompt(_)))
        .count();
    assert_eq!(prompt_count, 1, "expected the prompt to be split out");
    // FOO is defined only once, so merge_partial_defs keeps its `depends on`.
    assert_eq!(depends_on(&foo), vec!["BAR"]);
}

#[test]
fn a_typed_prompt_inside_a_menu_is_split() {
    let entries = desugar("menu \"m\"\nconfig FOO\nbool \"enable foo\"\nendmenu\n");

    let foo = config_anywhere(&entries, "FOO");
    assert!(matches!(type_of(&foo), Type::Bool(None)));
    let prompt_count = foo
        .attributes
        .iter()
        .filter(|a| matches!(a, Attribute::Prompt(_)))
        .count();
    assert_eq!(prompt_count, 1, "expected the prompt to be split out");
}

#[test]
fn multiple_configs_are_all_preserved() {
    let entries = desugar(concat!(
        "config FOO\nbool\n",
        "config BAR\ntristate\ndepends on FOO\n",
    ));

    let symbols: Vec<_> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Config(c) => Some(c.symbol.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(symbols, vec!["FOO", "BAR"]);
}

#[test]
fn partial_definitions_are_merged_into_a_single_definition() {
    let entries = desugar(concat!(
        "config Y\nbool\n",
        "config X\nbool \"x\"\n",
        "config Y\ndepends on A\nselect B\n",
        "config Y\nprompt \"y\"\nselect A\ndepends on B\n",
    ));

    // the merged Y sits where its earliest partial definition was: before X.
    let symbols: Vec<_> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Config(c) => Some(c.symbol.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(symbols, vec!["Y", "X"]);

    let y = config(&entries, "Y");
    assert!(matches!(type_of(&y), Type::Bool(None)));
    assert!(depends_on(&y).is_empty());
    // each partial definition's dependency landed on its own attributes.
    let selects: Vec<String> = y
        .attributes
        .iter()
        .filter_map(|attribute| match attribute {
            Attribute::Select(select) => Some(select.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(selects, vec!["B if A", "A if B"]);
    let prompts: Vec<String> = y
        .attributes
        .iter()
        .filter_map(|attribute| match attribute {
            Attribute::Prompt(prompt) => Some(prompt.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(prompts, vec![r#""y" if B"#]);
}

#[test]
fn partial_definitions_are_merged_across_a_menu_boundary() {
    let entries = desugar(concat!(
        "config FOO\nbool \"foo\"\n",
        "menu \"m\"\ndepends on M\n",
        "config FOO\ndefault y\n",
        "endmenu\n",
    ));

    // the merged FOO sits where its earliest partial definition was: at top
    // level, before the (now config-less) menu.
    assert!(matches!(entries[0], Entry::Config(_)));
    let foo = config(&entries, "FOO");
    assert!(matches!(type_of(&foo), Type::Bool(None)));
    assert_eq!(defaults(&foo), vec!["y"]);
    // the menu's dependency was copied onto the definition inside the menu,
    // so after merging it conditions only that definition's default.
    let default_conditions: Vec<Option<String>> = foo
        .attributes
        .iter()
        .filter_map(|attribute| match attribute {
            Attribute::Default(default) => Some(default.r#if.as_ref().map(|c| c.to_string())),
            _ => None,
        })
        .collect();
    assert_eq!(default_conditions, vec![Some("M".to_string())]);
    assert!(depends_on(&foo).is_empty());
}

#[test]
fn a_single_definitions_depends_on_is_kept() {
    let entries = desugar("config FOO\nbool\ndefault y\ndepends on A\n");

    let foo = config(&entries, "FOO");
    // FOO is defined only once, so it is not a partial definition: the
    // dependency stays a `depends on` instead of moving onto the attributes.
    assert_eq!(depends_on(&foo), vec!["A"]);
    let default_conditions: Vec<Option<String>> = foo
        .attributes
        .iter()
        .filter_map(|attribute| match attribute {
            Attribute::Default(default) => Some(default.r#if.as_ref().map(|c| c.to_string())),
            _ => None,
        })
        .collect();
    assert_eq!(default_conditions, vec![None]);
}

#[test]
fn m_in_conditions_is_rewritten_to_m_and_modules() {
    // the `if m` block distributes onto FOO's dependencies, and the final
    // rewrite_m pass turns the constant `m` into `(m && MODULES)`. the
    // `default m` value expression keeps its raw m.
    let entries = desugar(
        "config MODULES\nbool \"mods\"\nmodules\n\
         if m\nconfig FOO\ntristate \"foo\"\ndefault m\nendif\n",
    );

    let foo = config(&entries, "FOO");
    assert_eq!(depends_on(&foo), vec!["(m && MODULES)"]);
    assert_eq!(defaults(&foo), vec!["m"]);
}

#[test]
fn m_in_conditions_is_n_without_a_modules_option() {
    let entries = desugar("config FOO\ntristate \"foo\"\ndepends on m\n");

    let foo = config(&entries, "FOO");
    assert_eq!(depends_on(&foo), vec!["n"]);
}
