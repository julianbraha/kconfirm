//! NOTE: tests are AI slop that I generated after getting things to work.
//! TODO: review these more closely and consider hand-written tests
//!
//! Unit tests for the individual desugaring passes.
//!
//! Each pass is a private module, so these tests live inside the crate and call
//! the passes' `pub` entry points directly (`visit_config`, `visit_entries`,
//! `distribute_depends`, `visit_source`).
//!
//! Inputs are built by parsing real Kconfig text with `nom_kconfig::parse_kconfig`
//! rather than hand-constructing expression trees, which keeps the tests readable
//! and exercises the same shapes the real parser produces.

use nom_kconfig::{
    Attribute,
    Entry,
    KconfigInput,
    attribute::r#type::Type,
    entry::Config,
    parse_kconfig, //
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Parse Kconfig source text into its top-level entries.
fn parse_entries(text: &str) -> Vec<Entry> {
    parse_kconfig(KconfigInput::new_extra(text, Default::default()))
        .expect("kconfig text should parse")
        .1
        .entries
}

/// Parse Kconfig text expected to contain exactly one `config` entry.
fn parse_one_config(text: &str) -> Config {
    let entries = parse_entries(text);
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one entry, got {entries:?}"
    );
    into_config(entries.into_iter().next().unwrap())
}

/// Unwrap an entry that must be a `config`.
fn into_config(entry: Entry) -> Config {
    match entry {
        Entry::Config(config) => config,
        other => panic!("expected a config entry, got {other:?}"),
    }
}

/// Unwrap an entry that must be a `menu`.
fn into_menu(entry: Entry) -> nom_kconfig::entry::Menu {
    match entry {
        Entry::Menu(menu) => menu,
        other => panic!("expected a menu entry, got {other:?}"),
    }
}

/// Unwrap an entry that must be a `choice`.
fn into_choice(entry: Entry) -> nom_kconfig::entry::Choice {
    match entry {
        Entry::Choice(choice) => choice,
        other => panic!("expected a choice entry, got {other:?}"),
    }
}

/// Render every dependency of a menu to a string, in order.
fn menu_depends_on(menu: &nom_kconfig::entry::Menu) -> Vec<String> {
    menu.depends_on
        .iter()
        .map(|dep| dep.expression.to_string())
        .collect()
}

/// Render every `depends on` attribute of a config to a string, in order.
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

/// Collect every `prompt` attribute's text, in order.
fn prompts(config: &Config) -> Vec<String> {
    config
        .attributes
        .iter()
        .filter_map(|attribute| match attribute {
            Attribute::Prompt(prompt) => Some(prompt.prompt.clone()),
            _ => None,
        })
        .collect()
}

/// Render every `default` attribute's expression, in order.
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

/// The first `Type` attribute on a config (every config option has one).
fn type_of(config: &Config) -> &Type {
    config
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            Attribute::Type(config_type) => Some(&config_type.r#type),
            _ => None,
        })
        .expect("config should have a type attribute")
}

// ---------------------------------------------------------------------------
// expand_source: flatten `source` entries into one flat list of entries
// ---------------------------------------------------------------------------
mod expand_source_tests {
    use super::*;
    use crate::expand_source::visit_source;
    use nom_kconfig::{Kconfig, entry::Source};

    fn kconfig(file: &str, entries: Vec<Entry>) -> Kconfig {
        Kconfig {
            file: file.to_string(),
            entries,
        }
    }

    #[test]
    fn flattens_the_kconfigs_of_a_source_in_order() {
        let source = Source {
            kconfigs: vec![
                kconfig(
                    "a",
                    vec![Entry::Config(parse_one_config("config FOO\nbool\n"))],
                ),
                kconfig(
                    "b",
                    vec![Entry::Config(parse_one_config("config BAR\nbool\n"))],
                ),
            ],
        };

        let entries = visit_source(source);

        let symbols: Vec<_> = entries
            .iter()
            .map(|e| into_config(e.clone()).symbol)
            .collect();
        assert_eq!(symbols, vec!["FOO", "BAR"]);
    }

    #[test]
    fn recursively_flattens_nested_sources() {
        let inner = Source {
            kconfigs: vec![kconfig(
                "inner",
                vec![Entry::Config(parse_one_config("config INNER\nbool\n"))],
            )],
        };
        let outer = Source {
            kconfigs: vec![kconfig(
                "outer",
                vec![
                    Entry::Config(parse_one_config("config OUTER\nbool\n")),
                    Entry::Source(inner),
                ],
            )],
        };

        let entries = visit_source(outer);

        let symbols: Vec<_> = entries
            .iter()
            .map(|e| into_config(e.clone()).symbol)
            .collect();
        assert_eq!(symbols, vec!["OUTER", "INNER"]);
    }

    #[test]
    fn expands_sources_nested_inside_an_if() {
        // a `source` can appear inside an `if` (or `menu`/`choice`) block; it
        // must still be flattened into that block's entries.
        let inner = Source {
            kconfigs: vec![kconfig(
                "inner",
                vec![Entry::Config(parse_one_config("config INNER\nbool\n"))],
            )],
        };
        let mut if_entry = match parse_entries("if A\nendif\n").into_iter().next().unwrap() {
            Entry::If(r#if) => r#if,
            other => panic!("expected an if entry, got {other:?}"),
        };
        if_entry.entries.push(Entry::Source(inner));

        let source = Source {
            kconfigs: vec![kconfig("outer", vec![Entry::If(if_entry)])],
        };

        let entries = visit_source(source);

        // the `if` is preserved, but the nested source is flattened into it.
        assert_eq!(entries.len(), 1);
        let if_entry = match &entries[0] {
            Entry::If(r#if) => r#if,
            other => panic!("expected an if entry, got {other:?}"),
        };
        let symbols: Vec<_> = if_entry
            .entries
            .iter()
            .map(|e| into_config(e.clone()).symbol)
            .collect();
        assert_eq!(symbols, vec!["INNER"]);
    }

    #[test]
    fn keeps_non_config_entries() {
        let source = Source {
            kconfigs: vec![kconfig(
                "a",
                parse_entries("comment \"hi\"\nconfig FOO\nbool\n"),
            )],
        };

        let entries = visit_source(source);

        assert_eq!(entries.len(), 2);
        assert!(matches!(entries[0], Entry::Comment(_)));
        assert!(matches!(entries[1], Entry::Config(_)));
    }
}

// ---------------------------------------------------------------------------
// distribute_if: push an `if` condition onto inner entries as a dependency
// ---------------------------------------------------------------------------
mod distribute_if_tests {
    use super::*;
    use crate::distribute_if::visit_entries;

    /// Render every `select` attribute (symbol plus optional condition), in order.
    fn selects(config: &Config) -> Vec<String> {
        config
            .attributes
            .iter()
            .filter_map(|attribute| match attribute {
                Attribute::Select(select) => Some(select.to_string()),
                _ => None,
            })
            .collect()
    }

    /// Render every `imply` attribute (symbol plus optional condition), in order.
    fn implies(config: &Config) -> Vec<String> {
        config
            .attributes
            .iter()
            .filter_map(|attribute| match attribute {
                Attribute::Imply(imply) => Some(imply.to_string()),
                _ => None,
            })
            .collect()
    }

    /// Render every `prompt` attribute (text plus optional condition), in order.
    fn prompt_attributes(config: &Config) -> Vec<String> {
        config
            .attributes
            .iter()
            .filter_map(|attribute| match attribute {
                Attribute::Prompt(prompt) => Some(prompt.to_string()),
                _ => None,
            })
            .collect()
    }

    /// Render every `default` attribute (expression plus optional condition), in order.
    fn default_attributes(config: &Config) -> Vec<String> {
        config
            .attributes
            .iter()
            .filter_map(|attribute| match attribute {
                Attribute::Default(default) => Some(default.to_string()),
                _ => None,
            })
            .collect()
    }

    /// The `if` condition attached to the config's type attribute, rendered.
    fn type_condition(config: &Config) -> Option<String> {
        config
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::Type(config_type) => {
                    Some(config_type.r#if.as_ref().map(|c| c.to_string()))
                }
                _ => None,
            })
            .expect("config should have a type attribute")
    }

    #[test]
    fn adds_the_if_condition_as_a_dependency_of_a_contained_config() {
        let entries = visit_entries(parse_entries(
            "if X\nconfig FOO\nbool\ndepends on A\nselect B\nimply C\ndefault y\nendif\n",
        ));

        assert_eq!(entries.len(), 1);
        let foo = into_config(entries.into_iter().next().unwrap());
        // the condition is appended as one `depends on`; every other attribute
        // is left alone.
        assert_eq!(depends_on(&foo), vec!["A", "X"]);
        assert_eq!(selects(&foo), vec!["B"]);
        assert_eq!(implies(&foo), vec!["C"]);
        assert_eq!(default_attributes(&foo), vec!["y"]);
        assert_eq!(type_condition(&foo), None);
    }

    #[test]
    fn keeps_existing_attribute_conditions_untouched() {
        let entries = visit_entries(parse_entries(
            "if A\nconfig FOO\nbool\nprompt \"p\" if E\nselect S if D\nendif\n",
        ));

        let foo = into_config(entries.into_iter().next().unwrap());
        // the attributes keep their own conditions; the `if`'s condition only
        // shows up as the appended dependency.
        assert_eq!(prompt_attributes(&foo), vec![r#""p" if E"#]);
        assert_eq!(selects(&foo), vec!["S if D"]);
        assert_eq!(depends_on(&foo), vec!["A"]);
    }

    #[test]
    fn rewrites_a_menuconfig_in_an_if_into_a_config() {
        let entries = visit_entries(parse_entries("if A\nmenuconfig FOO\nbool\nendif\n"));

        assert_eq!(entries.len(), 1);
        let foo = into_config(entries.into_iter().next().unwrap());
        assert_eq!(foo.symbol, "FOO");
        // the condition lands as a dependency, not on the attributes.
        assert_eq!(depends_on(&foo), vec!["A"]);
        assert_eq!(type_condition(&foo), None);
    }

    #[test]
    fn leaves_a_comment_inside_an_if_untouched() {
        let entries = visit_entries(parse_entries("if A\ncomment \"hi\"\nendif\n"));

        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0], Entry::Comment(_)));
    }

    #[test]
    fn nested_ifs_are_combined_with_and() {
        let entries = visit_entries(parse_entries(
            "if A\nif B\nconfig FOO\nbool\ndepends on C\nendif\nendif\n",
        ));

        let foo = into_config(entries.into_iter().next().unwrap());
        // the nested conditions are joined into one appended dependency; a
        // later pass combines it with the config's own.
        assert_eq!(depends_on(&foo), vec!["C", "A && B"]);
    }

    #[test]
    fn nested_ifs_with_and_conditions_are_combined() {
        // the AND is flattened (`A && C && B`), which is equivalent to
        // `(A && C) && B`; parentheses are only inserted around `||`.
        let entries = visit_entries(parse_entries(
            "if A && C\nif B\nconfig FOO\nbool\nendif\nendif\n",
        ));

        let foo = into_config(entries.into_iter().next().unwrap());
        assert_eq!(depends_on(&foo), vec!["A && C && B"]);
    }

    #[test]
    fn nested_ifs_with_an_or_outer_condition_are_combined_with_and() {
        // `(A || X) && B`: both the outer disjunction and the inner condition
        // must hold, so the outer `||` must be parenthesized before the `&&`.
        let entries = visit_entries(parse_entries(
            "if A || X\nif B\nconfig FOO\nbool\nendif\nendif\n",
        ));

        let foo = into_config(entries.into_iter().next().unwrap());
        assert_eq!(depends_on(&foo), vec!["(A || X) && B"]);
    }

    #[test]
    fn distributes_a_compound_if_condition() {
        let entries = visit_entries(parse_entries(
            "if A && B\nconfig FOO\nbool\ndepends on X\nendif\n",
        ));

        let foo = into_config(entries.into_iter().next().unwrap());
        assert_eq!(depends_on(&foo), vec!["X", "A && B"]);
    }

    #[test]
    #[should_panic]
    fn panics_when_a_depends_on_if_was_not_already_expanded() {
        // This pass asserts the earlier expand_depends_if pass already lowered
        // `depends on X if Y`; a leftover condition is a contract violation.
        let _ = visit_entries(parse_entries("config FOO\nbool\ndepends on X if Y\n"));
    }

    #[test]
    fn a_config_outside_an_if_is_untouched() {
        let entries = visit_entries(parse_entries(
            "config FOO\nbool\ndepends on BAR\nselect S if D\n",
        ));

        let foo = into_config(entries.into_iter().next().unwrap());
        assert_eq!(depends_on(&foo), vec!["BAR"]);
        assert_eq!(selects(&foo), vec!["S if D"]);
        assert_eq!(type_condition(&foo), None);
    }

    #[test]
    fn transforms_the_before_fixture_into_the_after_fixture() {
        let before = parse_entries(include_str!("../tests/fixtures/before_if.Kconfig"));
        let after = parse_entries(include_str!("../tests/fixtures/after_if.Kconfig"));

        assert_eq!(visit_entries(before), after);
    }

    #[test]
    fn adds_the_if_condition_to_a_contained_menu() {
        // an `if` containing a menu pushes its condition onto the menu's own
        // dependencies; the menu's inner configs inherit it in a later pass.
        let entries = visit_entries(parse_entries(
            "if A\nmenu \"m\"\ndepends on B\nconfig FOO\nbool\nendmenu\nendif\n",
        ));

        let menu = into_menu(entries.into_iter().next().unwrap());
        assert_eq!(menu_depends_on(&menu), vec!["B", "A"]);
        // the config inside the menu is untouched by distribute_if itself.
        let foo = into_config(menu.entries.into_iter().next().unwrap());
        assert!(depends_on(&foo).is_empty());
    }

    #[test]
    fn adds_the_if_condition_to_a_contained_choice() {
        // an `if` containing a choice pushes its condition onto the choice's
        // own options; the choice's inner configs inherit it in a later pass.
        let entries = visit_entries(parse_entries(
            "if A\nchoice\nconfig FOO\nbool\nendchoice\nendif\n",
        ));

        let choice = into_choice(entries.into_iter().next().unwrap());
        let choice_depends: Vec<String> = choice
            .options
            .iter()
            .filter_map(|option| match option {
                Attribute::DependsOn(dep) => Some(dep.to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(choice_depends, vec!["A"]);
        // the config inside the choice is untouched by distribute_if itself.
        let foo = into_config(choice.entries.into_iter().next().unwrap());
        assert!(depends_on(&foo).is_empty());
    }

    #[test]
    fn flattens_an_if_nested_inside_a_menu() {
        // a top-level menu is not inside an `if`, but an `if` nested within it
        // must still be flattened onto the configs it contains.
        let entries = visit_entries(parse_entries(
            "menu \"m\"\nif A\nconfig FOO\nbool\nendif\nendmenu\n",
        ));

        let menu = into_menu(entries.into_iter().next().unwrap());
        let foo = into_config(menu.entries.into_iter().next().unwrap());
        assert_eq!(depends_on(&foo), vec!["A"]);
        assert_eq!(type_condition(&foo), None);
    }
}

// ---------------------------------------------------------------------------
// distribute_menu: copy a menu's dependencies onto its contained configs
// ---------------------------------------------------------------------------
mod distribute_menu_tests {
    use super::*;
    use crate::distribute_menu::visit_entries;

    #[test]
    fn copies_menu_dependency_onto_contained_config() {
        let entries = visit_entries(parse_entries(
            "menu \"m\"\ndepends on A\nconfig FOO\nbool\ndepends on B\nendmenu\n",
        ));

        let menu = into_menu(entries.into_iter().next().unwrap());
        // the menu keeps its own dependency (used later for visibility).
        assert_eq!(menu_depends_on(&menu), vec!["A"]);
        // the contained config gains the menu's dependency in addition to its own.
        let foo = into_config(menu.entries.into_iter().next().unwrap());
        assert_eq!(depends_on(&foo), vec!["B", "A"]);
    }

    #[test]
    fn copies_dependencies_through_nested_menus() {
        let entries = visit_entries(parse_entries(
            "menu \"outer\"\ndepends on A\nmenu \"inner\"\ndepends on B\nconfig FOO\nbool\nendmenu\nendmenu\n",
        ));

        let outer = into_menu(entries.into_iter().next().unwrap());
        let inner = into_menu(outer.entries.into_iter().next().unwrap());
        let foo = into_config(inner.entries.into_iter().next().unwrap());
        // FOO inherits both the outer and the inner menu dependencies, once each.
        assert_eq!(depends_on(&foo), vec!["A", "B"]);
    }
}

// ---------------------------------------------------------------------------
// distribute_choice: copy a choice's dependencies onto its contained configs
// ---------------------------------------------------------------------------
mod distribute_choice_tests {
    use super::*;
    use crate::distribute_choice::visit_entries;

    #[test]
    fn copies_choice_dependency_onto_contained_config() {
        let entries = visit_entries(parse_entries(
            "choice\ndepends on A\nconfig FOO\nbool\nendchoice\n",
        ));

        let choice = into_choice(entries.into_iter().next().unwrap());
        let foo = into_config(choice.entries.into_iter().next().unwrap());
        assert_eq!(depends_on(&foo), vec!["A"]);
    }
}

// ---------------------------------------------------------------------------
// combine_depends: fold all `depends on` attributes into a single AND chain
// ---------------------------------------------------------------------------
mod combine_depends_tests {
    use super::*;
    use crate::combine_depends::{visit_config, visit_entries};

    #[test]
    fn combines_two_depends_on_with_and() {
        let config = visit_config(parse_one_config(
            "config FOO\nbool\ndepends on A\ndepends on B\n",
        ));

        assert_eq!(depends_on(&config), vec!["A && B"]);
    }

    #[test]
    fn combines_dependencies_of_a_config_inside_a_menu() {
        // combine_depends must recurse into menus and combine the contained
        // config's dependencies, as well as the menu's own.
        let entries = visit_entries(parse_entries(
            "menu \"m\"\ndepends on A\ndepends on B\nconfig FOO\nbool\ndepends on C\ndepends on D\nendmenu\n",
        ));

        let menu = into_menu(entries.into_iter().next().unwrap());
        assert_eq!(menu_depends_on(&menu), vec!["A && B"]);
        let foo = into_config(menu.entries.into_iter().next().unwrap());
        assert_eq!(depends_on(&foo), vec!["C && D"]);
    }

    #[test]
    fn combines_three_depends_on_with_and() {
        let config = visit_config(parse_one_config(
            "config FOO\nbool\ndepends on A\ndepends on B\ndepends on C\n",
        ));

        assert_eq!(depends_on(&config), vec!["A && B && C"]);
    }

    #[test]
    fn a_single_depends_on_is_left_alone() {
        let config = visit_config(parse_one_config("config FOO\nbool\ndepends on A\n"));

        assert_eq!(depends_on(&config), vec!["A"]);
    }

    #[test]
    fn a_config_without_depends_on_gets_none() {
        let config = visit_config(parse_one_config("config FOO\nbool\n"));

        assert!(depends_on(&config).is_empty());
    }

    #[test]
    fn an_or_clause_is_parenthesized_when_anded_with_another() {
        // Without the parentheses, `A || B` AND `C` would parse as
        // `A || (B && C)`. The combine pass must emit `(A || B) && C`.
        let config = visit_config(parse_one_config(
            "config FOO\nbool\ndepends on A || B\ndepends on C\n",
        ));

        assert_eq!(depends_on(&config), vec!["(A || B) && C"]);
    }

    #[test]
    fn keeps_other_attributes_and_the_symbol() {
        let config = visit_config(parse_one_config(
            "config FOO\nbool\ndefault y\ndepends on A\n",
        ));

        assert_eq!(config.symbol, "FOO");
        assert!(matches!(type_of(&config), Type::Bool(None)));
        assert_eq!(defaults(&config), vec!["y"]);
        assert_eq!(depends_on(&config), vec!["A"]);
    }

    #[test]
    fn emits_exactly_one_depends_on_attribute() {
        let config = visit_config(parse_one_config(
            "config FOO\nbool\ndepends on A\ndepends on B\ndepends on C\n",
        ));

        let count = config
            .attributes
            .iter()
            .filter(|a| matches!(a, Attribute::DependsOn(_)))
            .count();
        assert_eq!(count, 1);
    }
}

// ---------------------------------------------------------------------------
// expand_type_prompt: split `bool "p"` into a `prompt "p"` + a bare `bool`
// ---------------------------------------------------------------------------
mod expand_type_prompt_tests {
    use super::*;
    use crate::expand_type_prompt::visit_config;

    #[test]
    fn splits_a_bool_prompt_into_a_prompt_and_a_bare_bool() {
        let config = visit_config(parse_one_config("config FOO\nbool \"a bool\"\n"));

        assert_eq!(prompts(&config), vec!["a bool"]);
        assert!(matches!(type_of(&config), Type::Bool(None)));
    }

    #[test]
    fn splits_a_tristate_prompt_into_a_prompt_and_a_bare_tristate() {
        let config = visit_config(parse_one_config("config FOO\ntristate \"a tristate\"\n"));

        assert_eq!(prompts(&config), vec!["a tristate"]);
        assert!(matches!(type_of(&config), Type::Tristate(None)));
    }

    #[test]
    fn a_bool_without_a_prompt_is_unchanged() {
        let config = visit_config(parse_one_config("config FOO\nbool\n"));

        assert!(prompts(&config).is_empty());
        assert!(matches!(type_of(&config), Type::Bool(None)));
    }

    #[test]
    fn carries_the_visibility_condition_onto_the_split_prompt() {
        // `bool "p" if BAR` parses the `if BAR` onto the type; splitting the
        // prompt out must move that visibility condition onto the prompt.
        let config = visit_config(parse_one_config("config FOO\nbool \"a bool\" if BAR\n"));

        let prompt_conditions: Vec<String> = config
            .attributes
            .iter()
            .filter_map(|attribute| match attribute {
                Attribute::Prompt(prompt) => Some(
                    prompt
                        .r#if
                        .as_ref()
                        .map(|c| c.to_string())
                        .unwrap_or_default(),
                ),
                _ => None,
            })
            .collect();

        assert_eq!(prompt_conditions, vec!["BAR"]);
        // the bare type no longer carries the `if`.
        assert!(matches!(type_of(&config), Type::Bool(None)));
    }

    #[test]
    fn splits_a_string_prompt_and_keeps_the_string_type() {
        let config = visit_config(parse_one_config("config FOO\nstring \"a string\"\n"));

        assert_eq!(prompts(&config), vec!["a string"]);
        assert!(
            matches!(type_of(&config), Type::String(None)),
            "expected string type, got {:?}",
            type_of(&config)
        );
    }

    #[test]
    fn splits_an_int_prompt_and_keeps_the_int_type() {
        let config = visit_config(parse_one_config("config FOO\nint \"an int\"\n"));

        assert_eq!(prompts(&config), vec!["an int"]);
        assert!(
            matches!(type_of(&config), Type::Int(None)),
            "expected int type, got {:?}",
            type_of(&config)
        );
    }

    #[test]
    fn splits_a_hex_prompt_and_keeps_the_hex_type() {
        let config = visit_config(parse_one_config("config FOO\nhex \"a hex\"\n"));

        assert_eq!(prompts(&config), vec!["a hex"]);
        assert!(
            matches!(type_of(&config), Type::Hex(None)),
            "expected hex type, got {:?}",
            type_of(&config)
        );
    }

    #[test]
    fn leaves_def_bool_alone() {
        // def_bool has no prompt to extract; this pass should not touch it.
        let config = visit_config(parse_one_config("config FOO\ndef_bool BAR\n"));

        assert!(prompts(&config).is_empty());
        assert!(matches!(type_of(&config), Type::DefBool(_)));
    }
}

// ---------------------------------------------------------------------------
// expand_def_type: split `def_bool X` into a bare `bool` + `default X`
// ---------------------------------------------------------------------------
mod expand_def_type_tests {
    use super::*;
    use crate::expand_def_type::visit_config;

    #[test]
    fn expands_def_bool_into_a_bool_and_a_default() {
        let config = visit_config(parse_one_config("config FOO\ndef_bool BAR\n"));

        assert!(matches!(type_of(&config), Type::Bool(None)));
        assert_eq!(defaults(&config), vec!["BAR"]);
    }

    #[test]
    fn expands_def_tristate_into_a_tristate_and_a_default() {
        let config = visit_config(parse_one_config("config FOO\ndef_tristate BAR\n"));

        assert!(matches!(type_of(&config), Type::Tristate(None)));
        assert_eq!(defaults(&config), vec!["BAR"]);
    }

    #[test]
    fn a_plain_bool_is_unchanged() {
        let config = visit_config(parse_one_config("config FOO\nbool\n"));

        assert!(matches!(type_of(&config), Type::Bool(None)));
        assert!(defaults(&config).is_empty());
    }

    #[test]
    #[should_panic]
    fn panics_when_a_type_prompt_was_not_already_expanded() {
        // This pass asserts the earlier expand_type_prompt pass already removed
        // prompts from basic types; a leftover prompt is a contract violation.
        let _ = visit_config(parse_one_config("config FOO\nbool \"oops\"\n"));
    }
}

// ---------------------------------------------------------------------------
// expand_depends_if: fold `depends on X if Y` into `depends on X || (Y == n)`
// ---------------------------------------------------------------------------
mod expand_depends_if_tests {
    use super::*;
    use crate::expand_depends_if::{visit_config, visit_entries};

    #[test]
    fn folds_depends_on_if_into_an_or_with_the_condition_off() {
        // `(BAZ = n)` waives the dependency when BAZ is disabled. The rendered
        // operator is Kconfig's `=` (the source comment writes `==` informally).
        let config = visit_config(parse_one_config(
            "config FOO\nbool\ndepends on BAR if BAZ\n",
        ));

        assert_eq!(depends_on(&config), vec!["BAR || (BAZ = n)"]);
    }

    #[test]
    fn folds_a_negated_if_condition_into_the_enabled_case() {
        // `if !BAZ` is off exactly when BAZ is enabled, so the dependency is
        // waived when `BAZ != n`.
        let config = visit_config(parse_one_config(
            "config FOO\nbool\ndepends on BAR if !BAZ\n",
        ));

        assert_eq!(depends_on(&config), vec!["BAR || (BAZ != n)"]);
    }

    #[test]
    fn a_plain_depends_on_is_unchanged() {
        let config = visit_config(parse_one_config("config FOO\nbool\ndepends on BAR\n"));

        assert_eq!(depends_on(&config), vec!["BAR"]);
    }

    #[test]
    fn appends_the_off_condition_as_a_new_or_alternative() {
        let config = visit_config(parse_one_config(
            "config FOO\nbool\ndepends on A || B if C\n",
        ));

        assert_eq!(depends_on(&config), vec!["A || B || (C = n)"]);
    }

    #[test]
    fn expands_a_compound_and_condition() {
        // `BAZ && QUX` is off when either operand is off, so the dependency is
        // waived in both cases.
        let config = visit_config(parse_one_config(
            "config FOO\nbool\ndepends on BAR if BAZ && QUX\n",
        ));

        assert_eq!(depends_on(&config), vec!["BAR || (BAZ = n) || (QUX = n)"]);
    }

    #[test]
    fn expands_a_compound_or_condition() {
        // `BAZ || QUX` is off only when both operands are off (`&&` binds
        // tighter than `||`, so no parentheses are needed around the pair).
        let config = visit_config(parse_one_config(
            "config FOO\nbool\ndepends on BAR if BAZ || QUX\n",
        ));

        assert_eq!(depends_on(&config), vec!["BAR || (BAZ = n) && (QUX = n)"]);
    }

    #[test]
    fn expands_a_negated_compound_condition() {
        // `!(BAZ && QUX)` is off when `BAZ && QUX` is on, i.e. when both are on.
        let config = visit_config(parse_one_config(
            "config FOO\nbool\ndepends on BAR if !(BAZ && QUX)\n",
        ));

        assert_eq!(depends_on(&config), vec!["BAR || (BAZ != n) && (QUX != n)"]);
    }

    #[test]
    fn expands_a_parenthesized_condition_with_mixed_operators() {
        // `(A || B) && C` is off when the parenthesized group is off (both A
        // and B off) or when C is off.
        let config = visit_config(parse_one_config(
            "config FOO\nbool\ndepends on X if (A || B) && C\n",
        ));

        assert_eq!(
            depends_on(&config),
            vec!["X || (A = n) && (B = n) || (C = n)"]
        );
    }

    #[test]
    fn negates_a_comparison_condition() {
        // a comparison is boolean, so its off-case is the negated comparison.
        let config = visit_config(parse_one_config(
            "config FOO\nbool\ndepends on X if FOO = BAR\n",
        ));

        assert_eq!(depends_on(&config), vec!["X || (FOO != BAR)"]);
    }

    #[test]
    fn recurses_into_if_blocks() {
        // in the pipeline distribute_if has already flattened `if` entries, but
        // the pass still recurses into any it sees, so a nested config gets its
        // `depends on ... if ...` expanded either way.
        let entries = visit_entries(parse_entries(
            "if COND\nconfig FOO\nbool\ndepends on BAR if BAZ\nendif\n",
        ));

        let foo = match entries.into_iter().next().unwrap() {
            Entry::If(r#if) => into_config(r#if.entries.into_iter().next().unwrap()),
            other => panic!("expected an if entry, got {other:?}"),
        };
        assert_eq!(depends_on(&foo), vec!["BAR || (BAZ = n)"]);
    }
}

// ---------------------------------------------------------------------------
// merge_partial_defs: merge every partial definition of a symbol into one
// ---------------------------------------------------------------------------
mod merge_partial_defs_tests {
    use super::*;
    use crate::merge_partial_defs::{distribute_depends, visit_entries};

    /// Render every `select` attribute (symbol plus optional condition), in order.
    fn selects(config: &Config) -> Vec<String> {
        config
            .attributes
            .iter()
            .filter_map(|attribute| match attribute {
                Attribute::Select(select) => Some(select.to_string()),
                _ => None,
            })
            .collect()
    }

    /// Render every `imply` attribute (symbol plus optional condition), in order.
    fn implies(config: &Config) -> Vec<String> {
        config
            .attributes
            .iter()
            .filter_map(|attribute| match attribute {
                Attribute::Imply(imply) => Some(imply.to_string()),
                _ => None,
            })
            .collect()
    }

    /// Render every `prompt` attribute (text plus optional condition), in order.
    fn prompt_attributes(config: &Config) -> Vec<String> {
        config
            .attributes
            .iter()
            .filter_map(|attribute| match attribute {
                Attribute::Prompt(prompt) => Some(prompt.to_string()),
                _ => None,
            })
            .collect()
    }

    /// Render every `default` attribute (expression plus optional condition), in order.
    fn default_attributes(config: &Config) -> Vec<String> {
        config
            .attributes
            .iter()
            .filter_map(|attribute| match attribute {
                Attribute::Default(default) => Some(default.to_string()),
                _ => None,
            })
            .collect()
    }

    /// Render every `range` attribute (bounds plus optional condition), in order.
    fn range_attributes(config: &Config) -> Vec<String> {
        config
            .attributes
            .iter()
            .filter_map(|attribute| match attribute {
                Attribute::Range(range) => Some(range.to_string()),
                _ => None,
            })
            .collect()
    }

    /// The `if` condition attached to the config's type attribute, rendered.
    fn type_condition(config: &Config) -> Option<String> {
        config
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::Type(config_type) => {
                    Some(config_type.r#if.as_ref().map(|c| c.to_string()))
                }
                _ => None,
            })
            .expect("config should have a type attribute")
    }

    /// The symbols of all config/menuconfig entries, in order.
    fn config_symbols(entries: &[Entry]) -> Vec<String> {
        entries
            .iter()
            .filter_map(|entry| match entry {
                Entry::Config(config) | Entry::MenuConfig(config) => Some(config.symbol.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn merges_the_attributes_of_every_partial_definition_in_order() {
        let entries = visit_entries(parse_entries(
            "config Y\nbool\nconfig Y\nselect A\nconfig Y\ndefault y\n",
        ));

        assert_eq!(entries.len(), 1);
        let y = into_config(entries.into_iter().next().unwrap());
        assert!(matches!(type_of(&y), Type::Bool(None)));
        assert_eq!(selects(&y), vec!["A"]);
        assert_eq!(defaults(&y), vec!["y"]);
    }

    #[test]
    fn the_merged_definition_replaces_the_earliest_partial_definition() {
        let entries = visit_entries(parse_entries(
            "config Y\nbool\nconfig X\nbool\nconfig Y\nselect A\n",
        ));

        // Y's later partial definition is merged into the earliest one, so the
        // merged Y stays in front of X.
        assert_eq!(config_symbols(&entries), vec!["Y", "X"]);
        let y = into_config(entries.into_iter().next().unwrap());
        assert_eq!(selects(&y), vec!["A"]);
    }

    #[test]
    fn a_dependency_is_added_to_every_attribute_that_can_carry_a_condition() {
        let config = distribute_depends(parse_one_config(
            "config Y\nint\nprompt \"p\"\ndefault 3\nrange 1 5\nselect A\nimply B\ndepends on X\n",
        ));

        assert!(depends_on(&config).is_empty());
        assert_eq!(prompt_attributes(&config), vec![r#""p" if X"#]);
        assert_eq!(default_attributes(&config), vec!["3 if X"]);
        assert_eq!(range_attributes(&config), vec!["1 5 if X"]);
        assert_eq!(selects(&config), vec!["A if X"]);
        assert_eq!(implies(&config), vec!["B if X"]);
        assert_eq!(type_condition(&config), Some("X".to_string()));
    }

    #[test]
    fn a_dependency_is_anded_onto_an_existing_condition() {
        let config = distribute_depends(parse_one_config(
            "config Y\nbool\nselect A if C\ndepends on X\n",
        ));

        // the pre-existing condition stays first; the dependency is ANDed on.
        assert_eq!(selects(&config), vec!["A if C && X"]);
    }

    #[test]
    fn an_or_dependency_is_parenthesized_when_anded_onto_a_condition() {
        let config = distribute_depends(parse_one_config(
            "config Y\nbool\nselect A if C\nselect B\ndepends on X || W\n",
        ));

        // ANDed onto an existing condition the disjunction needs parentheses;
        // as the sole condition it is used as-is.
        assert_eq!(selects(&config), vec!["A if C && (X || W)", "B if X || W"]);
    }

    #[test]
    fn multiple_depends_on_of_one_definition_are_combined_with_and() {
        // in the pipeline combine_depends has already folded these into one,
        // but the pass combines them itself so it is correct on its own.
        let config = distribute_depends(parse_one_config(
            "config Y\nbool\nselect A\ndepends on X\ndepends on W\n",
        ));

        assert!(depends_on(&config).is_empty());
        assert_eq!(selects(&config), vec!["A if X && W"]);
    }

    #[test]
    fn a_dependency_applies_only_to_its_own_partial_definition() {
        let entries = visit_entries(parse_entries(
            "config Y\nbool\nselect A\nconfig Y\ndepends on X\nselect B\n",
        ));

        let y = into_config(entries.into_iter().next().unwrap());
        // `depends on X` conditions the second definition's select only.
        assert_eq!(selects(&y), vec!["A", "B if X"]);
        assert!(depends_on(&y).is_empty());
    }

    #[test]
    fn a_single_definition_keeps_its_depends_on() {
        // an option defined exactly once is not a partial definition: it keeps
        // its `depends on` and its attributes stay unconditioned.
        let entries = visit_entries(parse_entries("config Y\nbool\ndepends on A\nselect B\n"));

        let y = into_config(entries.into_iter().next().unwrap());
        assert_eq!(depends_on(&y), vec!["A"]);
        assert_eq!(selects(&y), vec!["B"]);
    }

    #[test]
    fn attributes_that_cannot_carry_a_condition_are_kept_unchanged() {
        let config = distribute_depends(parse_one_config(
            "config Y\nbool\ndepends on X\nhelp\n  some help text\n",
        ));

        let help_count = config
            .attributes
            .iter()
            .filter(|attribute| matches!(attribute, Attribute::Help(_)))
            .count();
        assert_eq!(help_count, 1);
        assert!(depends_on(&config).is_empty());
    }

    #[test]
    #[should_panic]
    fn panics_when_a_depends_on_if_was_not_already_expanded() {
        // This pass asserts the earlier expand_depends_if pass already lowered
        // `depends on X if Y`; a leftover condition is a contract violation.
        let _ = distribute_depends(parse_one_config("config Y\nbool\ndepends on X if C\n"));
    }

    #[test]
    fn merges_partial_definitions_inside_a_menu() {
        let entries = visit_entries(parse_entries(
            "menu \"m\"\nconfig Y\nbool\nconfig Y\nselect A\nendmenu\n",
        ));

        let menu = into_menu(entries.into_iter().next().unwrap());
        assert_eq!(config_symbols(&menu.entries), vec!["Y"]);
        let y = into_config(menu.entries.into_iter().next().unwrap());
        assert_eq!(selects(&y), vec!["A"]);
    }

    #[test]
    fn merges_partial_definitions_across_a_menu_boundary() {
        // in the pipeline distribute_menu has already copied the menu's
        // dependencies onto the contained definition, so its `depends on`
        // carries the menu context onto the attributes it contributes.
        let entries = visit_entries(parse_entries(
            "config Y\nbool\nmenu \"m\"\nconfig Y\nselect A\ndepends on M\nendmenu\n",
        ));

        // the merged definition sits where the earliest one was: at top
        // level. the menu stays behind, holding no configs.
        assert_eq!(entries.len(), 2);
        let mut entries = entries.into_iter();
        let y = into_config(entries.next().unwrap());
        let menu = into_menu(entries.next().unwrap());
        assert!(config_symbols(&menu.entries).is_empty());
        assert!(matches!(type_of(&y), Type::Bool(None)));
        assert_eq!(selects(&y), vec!["A if M"]);
        assert!(depends_on(&y).is_empty());
    }

    #[test]
    fn merges_partial_definitions_across_a_choice_boundary() {
        let entries = visit_entries(parse_entries(
            "choice\nconfig Y\nbool\nendchoice\nconfig Y\nselect A\n",
        ));

        // the earliest definition is the choice member, so the merged
        // definition stays inside the choice and Y remains a choice member.
        assert_eq!(entries.len(), 1);
        let choice = into_choice(entries.into_iter().next().unwrap());
        assert_eq!(config_symbols(&choice.entries), vec!["Y"]);
        let y = into_config(choice.entries.into_iter().next().unwrap());
        assert!(matches!(type_of(&y), Type::Bool(None)));
        assert_eq!(selects(&y), vec!["A"]);
    }

    #[test]
    fn merges_partial_definitions_from_sibling_menus() {
        let entries = visit_entries(parse_entries(
            "menu \"m1\"\nconfig Y\nbool\nendmenu\nmenu \"m2\"\nconfig Y\nselect A\nendmenu\n",
        ));

        // the merged definition lives in the first menu; the second keeps no
        // configs.
        assert_eq!(entries.len(), 2);
        let mut entries = entries.into_iter();
        let m1 = into_menu(entries.next().unwrap());
        let m2 = into_menu(entries.next().unwrap());
        assert_eq!(config_symbols(&m1.entries), vec!["Y"]);
        assert!(config_symbols(&m2.entries).is_empty());
        let y = into_config(m1.entries.into_iter().next().unwrap());
        assert_eq!(selects(&y), vec!["A"]);
    }

    #[test]
    fn a_menuconfig_merges_with_a_config_of_the_same_symbol() {
        let entries = visit_entries(parse_entries("menuconfig Y\nbool\nconfig Y\nselect A\n"));

        assert_eq!(entries.len(), 1);
        // the merged definition keeps the entry kind of the earliest one.
        let y = match entries.into_iter().next().unwrap() {
            Entry::MenuConfig(config) => config,
            other => panic!("expected a menuconfig entry, got {other:?}"),
        };
        assert_eq!(selects(&y), vec!["A"]);
    }

    #[test]
    fn keeps_non_config_entries_in_position() {
        let entries = visit_entries(parse_entries(
            "config Y\nbool\ncomment \"hi\"\nconfig Y\nselect A\n",
        ));

        assert_eq!(entries.len(), 2);
        assert!(matches!(entries[0], Entry::Config(_)));
        assert!(matches!(entries[1], Entry::Comment(_)));
    }

    #[test]
    fn transforms_the_before_fixture_into_the_after_fixture() {
        let before = parse_entries(include_str!("../tests/fixtures/before_merge.Kconfig"));
        let after = parse_entries(include_str!("../tests/fixtures/after_merge.Kconfig"));

        assert_eq!(visit_entries(before), after);
    }
}

mod eliminate_default_n_tests {
    use super::*;

    /// Render every `default` attribute of a config as `value` or `value if cond`, in order.
    fn defaults(config: &Config) -> Vec<String> {
        config
            .attributes
            .iter()
            .filter_map(|attribute| match attribute {
                Attribute::Default(default) => Some(match &default.r#if {
                    Some(condition) => format!("{} if {}", default.expression, condition),
                    None => default.expression.to_string(),
                }),
                _ => None,
            })
            .collect()
    }

    /// Collect every `select`ed symbol of a config, in order.
    fn selects(config: &Config) -> Vec<String> {
        config
            .attributes
            .iter()
            .filter_map(|attribute| match attribute {
                Attribute::Select(select) => Some(select.symbol.clone()),
                _ => None,
            })
            .collect()
    }

    /// Run the pass over the parsed text and return the single resulting config.
    fn reduce_one_config(text: &str) -> Config {
        let reduced = crate::eliminate_default_n::visit_entries(parse_entries(text));
        assert_eq!(reduced.len(), 1, "expected exactly one entry: {reduced:?}");
        into_config(reduced.into_iter().next().unwrap())
    }

    // ---------------------------------------------------------------------------
    // eliminate_default_n
    // ---------------------------------------------------------------------------

    #[test]
    fn removes_only_default_n_from_bool() {
        let config = reduce_one_config("config FOO\n\tbool \"foo\"\n\tdefault n\n");
        assert_eq!(defaults(&config), Vec::<String>::new());
    }

    #[test]
    fn removes_only_default_n_from_tristate() {
        let config = reduce_one_config("config FOO\n\ttristate \"foo\"\n\tdefault n\n");
        assert_eq!(defaults(&config), Vec::<String>::new());
    }

    #[test]
    fn removes_final_conditional_default_n() {
        // if BAR fires the value is n; if it doesn't, the fallback is n anyway
        let config = reduce_one_config("config FOO\n\tbool \"foo\"\n\tdefault n if BAR\n");
        assert_eq!(defaults(&config), Vec::<String>::new());
    }

    #[test]
    fn keeps_default_n_that_shadows_a_later_default() {
        // this `default n if BAR` fires before `default y`, so it is meaningful
        let config = reduce_one_config(
            "config FOO\n\tbool \"foo\"\n\tdefault n if BAR\n\tdefault y\n", //
        );
        assert_eq!(defaults(&config), vec!["n if BAR", "y"]);
    }

    #[test]
    fn strips_every_trailing_default_n() {
        // after the final `default n` goes, `default n if B` becomes final and goes too
        let config = reduce_one_config(
            "config FOO\n\tbool \"foo\"\n\tdefault y if A\n\tdefault n if B\n\tdefault n\n",
        );
        assert_eq!(defaults(&config), vec!["y if A"]);
    }

    #[test]
    fn keeps_default_y() {
        let config = reduce_one_config("config FOO\n\tbool \"foo\"\n\tdefault y\n");
        assert_eq!(defaults(&config), vec!["y"]);
    }

    #[test]
    fn keeps_defaults_of_non_bool_non_tristate_options() {
        // the pass only reasons about bool/tristate fallback semantics
        let config = reduce_one_config("config FOO\n\tint \"foo\"\n\tdefault n\n");
        assert_eq!(defaults(&config), vec!["n"]);
    }

    #[test]
    fn keeps_attributes_after_the_removed_default() {
        let config = reduce_one_config(
            "config FOO\n\tbool \"foo\"\n\tdefault n\n\tselect BAR\n", //
        );
        assert_eq!(defaults(&config), Vec::<String>::new());
        assert_eq!(selects(&config), vec!["BAR"]);
    }

    #[test]
    fn descends_into_containers() {
        let entries = parse_entries(
            "menu \"a menu\"\nconfig FOO\n\tbool \"foo\"\n\tdefault n\nendmenu\n", //
        );
        let reduced = crate::eliminate_default_n::visit_entries(entries);
        assert_eq!(reduced.len(), 1, "expected exactly one entry: {reduced:?}");
        let menu = match reduced.into_iter().next().unwrap() {
            Entry::Menu(menu) => menu,
            other => panic!("expected a menu entry, got {other:?}"),
        };
        let config = into_config(menu.entries.into_iter().next().unwrap());
        assert_eq!(defaults(&config), Vec::<String>::new());
    }

    #[test]
    fn removes_parenthesized_default_n() {
        let config = reduce_one_config("config FOO\n\tbool \"foo\"\n\tdefault (n)\n");
        assert_eq!(defaults(&config), Vec::<String>::new());
    }
}

mod rewrite_m_tests {
    use super::*;

    /// The single `depends on` expression of a config, rendered as text.
    fn depends_expression(config: &Config) -> String {
        let mut expressions = config.attributes.iter().filter_map(|attribute| {
            match attribute {
                Attribute::DependsOn(dep) => Some(dep.expression.to_string()),
                _ => None,
            }
        });
        let expression = expressions.next().expect("config has a depends on");
        assert_eq!(expressions.next(), None, "expected a single depends on");
        expression
    }

    /// Render every `default` attribute of a config as `value` or `value if cond`, in order.
    fn defaults(config: &Config) -> Vec<String> {
        config
            .attributes
            .iter()
            .filter_map(|attribute| match attribute {
                Attribute::Default(default) => Some(match &default.r#if {
                    Some(condition) => format!("{} if {}", default.expression, condition),
                    None => default.expression.to_string(),
                }),
                _ => None,
            })
            .collect()
    }

    /// Find the config with the given symbol anywhere in the entry tree.
    fn find_config(entries: &[Entry], symbol: &str) -> Option<Config> {
        entries.iter().find_map(|entry| match entry {
            Entry::Config(c) | Entry::MenuConfig(c) if c.symbol == symbol => Some(c.clone()),
            Entry::Menu(menu) => find_config(&menu.entries, symbol),
            Entry::Choice(choice) => find_config(&choice.entries, symbol),
            _ => None,
        })
    }

    /// Run the pass over the parsed text and return the named config.
    fn rewrite(text: &str, symbol: &str) -> Config {
        let rewritten = crate::rewrite_m::visit_entries(parse_entries(text));
        find_config(&rewritten, symbol)
            .unwrap_or_else(|| panic!("no config named {symbol} in {rewritten:?}"))
    }

    /// A tree defining a modules option (inside a menu, so the scan has to descend).
    const MODULES: &str = "menu \"general\"\nconfig MODULES\n\tbool \"mods\"\n\tmodules\nendmenu\n";

    // ---------------------------------------------------------------------------
    // rewrite_m
    // ---------------------------------------------------------------------------

    #[test]
    fn rewrites_m_in_depends_on() {
        let text = format!("{MODULES}config FOO\n\ttristate \"foo\"\n\tdepends on m\n");
        let config = rewrite(&text, "FOO");
        assert_eq!(depends_expression(&config), "(m && MODULES)");
    }

    #[test]
    fn m_becomes_n_without_a_modules_option() {
        let config = rewrite("config FOO\n\ttristate \"foo\"\n\tdepends on m\n", "FOO");
        assert_eq!(depends_expression(&config), "n");
    }

    #[test]
    fn rewrites_m_inside_a_larger_condition() {
        let text = format!("{MODULES}config FOO\n\ttristate \"foo\"\n\tdepends on BAR && (m || BAZ)\n");
        let config = rewrite(&text, "FOO");
        assert_eq!(
            depends_expression(&config),
            "BAR && ((m && MODULES) || BAZ)"
        );
    }

    #[test]
    fn default_values_keep_the_raw_m_but_their_conditions_are_rewritten() {
        let text = format!(
            "{MODULES}config FOO\n\ttristate \"foo\"\n\tdefault m\n\tdefault y if m\n"
        );
        let config = rewrite(&text, "FOO");
        assert_eq!(defaults(&config), vec!["m", "y if (m && MODULES)"]);
    }

    #[test]
    fn comparisons_keep_the_raw_m() {
        let text = format!("{MODULES}config FOO\n\ttristate \"foo\"\n\tdepends on BAR = m\n");
        let config = rewrite(&text, "FOO");
        assert_eq!(depends_expression(&config), "BAR = m");
    }

    #[test]
    fn rewrites_select_and_prompt_conditions() {
        let text = format!(
            "{MODULES}config FOO\n\ttristate\n\tprompt \"foo\" if m\n\tselect BAR if m\n"
        );
        let config = rewrite(&text, "FOO");
        let prompt_if = config
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::Prompt(prompt) => Some(prompt.r#if.as_ref().unwrap().to_string()),
                _ => None,
            })
            .expect("config has a prompt");
        assert_eq!(prompt_if, "(m && MODULES)");
        let select_if = config
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::Select(select) => Some(select.r#if.as_ref().unwrap().to_string()),
                _ => None,
            })
            .expect("config has a select");
        assert_eq!(select_if, "(m && MODULES)");
    }

    #[test]
    fn rewrites_choice_dependencies() {
        let text = format!(
            "{MODULES}choice\n\tprompt \"pick\"\n\tdepends on m\nconfig A\n\tbool \"a\"\nendchoice\n"
        );
        let rewritten = crate::rewrite_m::visit_entries(parse_entries(&text));
        let choice = rewritten
            .iter()
            .find_map(|entry| match entry {
                Entry::Choice(choice) => Some(choice.clone()),
                _ => None,
            })
            .expect("tree has a choice");
        let depends: Vec<String> = choice
            .options
            .iter()
            .filter_map(|option| match option {
                Attribute::DependsOn(dep) => Some(dep.expression.to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(depends, vec!["(m && MODULES)"]);
    }
}
