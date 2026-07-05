use nom_kconfig::{
    Attribute,
    Entry,
    attribute::{OrExpression, depends_on::DependsOn},
    entry::Config, //
};

use crate::utils::and_terms::and_expressions;

pub fn visit_entries(entries: Vec<Entry>) -> Vec<Entry> {
    let mut all_entries = Vec::new();
    for entry in entries {
        let cur_entries = visit_entry(entry);
        all_entries.extend(cur_entries);
    }
    all_entries
}

pub fn visit_entry(entry: Entry) -> Vec<Entry> {
    match entry {
        // flatten the `if`: push its condition onto every contained entry and
        // drop the `if` itself.
        Entry::If(r#if) => {
            let condition = r#if.condition;
            r#if.entries
                .into_iter()
                .flat_map(|e| distribute_dependency(e, condition.clone()))
                .collect()
        }
        // not inside an `if`, but these containers may hold nested `if`s, so we
        // still recurse to flatten those.
        Entry::Menu(mut menu) => {
            menu.entries = visit_entries(menu.entries);
            vec![Entry::Menu(menu)]
        }
        Entry::Choice(mut choice) => {
            choice.entries = visit_entries(choice.entries);
            vec![Entry::Choice(choice)]
        }
        // a config that isn't inside an `if` keeps its dependencies unchanged,
        // but the previous pass must still have expanded any `depends on X if Y`.
        Entry::Config(c) => vec![Entry::Config(assert_depends_if_expanded(c))],
        Entry::MenuConfig(c) => vec![Entry::MenuConfig(assert_depends_if_expanded(c))],
        // identity
        _ => vec![entry],
    }
}

/// Adds `condition` as a `depends on` to `entry`. For `menu`/`choice`
/// containers the condition is added to the container's own dependency list;
/// their inner config options inherit it later via the menu/choice distribution
/// passes. We still recurse into the containers here to flatten any nested
/// `if`s.
pub fn distribute_dependency(entry: Entry, condition: OrExpression) -> Vec<Entry> {
    match entry {
        Entry::Config(c) | Entry::MenuConfig(c) => {
            vec![Entry::Config(push_dependency(c, condition))]
        }
        Entry::Choice(mut choice) => {
            choice
                .options
                .push(Attribute::DependsOn(DependsOn {
                    expression: condition,
                    r#if: None,
                }));
            choice.entries = visit_entries(choice.entries);
            vec![Entry::Choice(choice)]
        }
        Entry::Menu(mut menu) => {
            menu.depends_on.push(DependsOn {
                expression: condition,
                r#if: None,
            });
            menu.entries = visit_entries(menu.entries);
            vec![Entry::Menu(menu)]
        }
        Entry::If(nested_if) => {
            // join the conditions with a logical-AND and keep flattening.
            let joined = and_expressions(condition, nested_if.condition);
            nested_if
                .entries
                .into_iter()
                .flat_map(|nested_entry| distribute_dependency(nested_entry, joined.clone()))
                .collect()
        }
        // comments and anything else have nothing to depend on.
        _ => vec![entry],
    }
}

/// Append `condition` to a config's `depends on` attributes.
pub fn push_dependency(config: Config, condition: OrExpression) -> Config {
    let mut new_c = assert_depends_if_expanded(config);
    new_c.attributes.push(Attribute::DependsOn(DependsOn {
        expression: condition,
        r#if: None,
    }));
    new_c
}

/// Assert that `expand_depends_if` already removed every `depends on X if Y`.
fn assert_depends_if_expanded(config: Config) -> Config {
    for attribute in &config.attributes {
        if let Attribute::DependsOn(dep) = attribute {
            assert!(dep.r#if.is_none());
        }
    }
    config
}
