use std::collections::HashMap;

use nom_kconfig::{
    Attribute,
    Entry,
    attribute::Expression,
    entry::Config, //
};

use crate::utils::and_terms::and_expressions;

// Merges all partial definitions of a config option into a single definition,
// placed where the earliest partial definition was — even when the partial
// definitions live in different menu/choice containers. A partial definition's
// `depends on` applies only to the attributes written in that same definition:
// it is removed and its expression is ANDed onto the `if` condition of each of
// those attributes. Because the earlier passes copied every container's
// dependencies down onto the configs it contains, a partial definition's
// `depends on` already carries its menu/choice context, so a later definition
// can be dropped from its container without losing that context. An option
// defined exactly once is not a partial definition and is kept unchanged,
// `depends on` included.
pub fn visit_entries(entries: Vec<Entry>) -> Vec<Entry> {
    let mut definition_counts: HashMap<String, usize> = HashMap::new();
    count_definitions(&entries, &mut definition_counts);

    let mut merged_attributes: HashMap<String, Vec<Attribute>> = HashMap::new();
    collect_merged_attributes(&entries, &definition_counts, &mut merged_attributes);

    rebuild(entries, &definition_counts, &mut merged_attributes)
}

/// Count every definition of each symbol, anywhere in the entry tree.
fn count_definitions(entries: &[Entry], counts: &mut HashMap<String, usize>) {
    for entry in entries {
        match entry {
            Entry::Config(config) | Entry::MenuConfig(config) => {
                *counts.entry(config.symbol.clone()).or_insert(0) += 1;
            }
            Entry::Menu(menu) => count_definitions(&menu.entries, counts),
            Entry::Choice(choice) => count_definitions(&choice.entries, counts),
            _ => {}
        }
    }
}

/// Gather the merged attribute list of every multiply defined symbol: each
/// partial definition's attributes (with its own `depends on` distributed
/// onto them) in document order, across container boundaries.
fn collect_merged_attributes(
    entries: &[Entry],
    definition_counts: &HashMap<String, usize>,
    merged_attributes: &mut HashMap<String, Vec<Attribute>>,
) {
    for entry in entries {
        match entry {
            Entry::Config(config) | Entry::MenuConfig(config)
                if definition_counts[&config.symbol] > 1 =>
            {
                let distributed = distribute_depends(config.clone());
                merged_attributes
                    .entry(distributed.symbol)
                    .or_default()
                    .extend(distributed.attributes);
            }
            Entry::Menu(menu) => {
                collect_merged_attributes(&menu.entries, definition_counts, merged_attributes)
            }
            Entry::Choice(choice) => {
                collect_merged_attributes(&choice.entries, definition_counts, merged_attributes)
            }
            _ => {}
        }
    }
}

/// Rebuild the entry tree: the earliest definition of a multiply defined
/// symbol becomes the merged definition (keeping its `config`/`menuconfig`
/// entry kind and its place in the tree), every later definition is removed
/// from its container, and everything else stays where it was.
fn rebuild(
    entries: Vec<Entry>,
    definition_counts: &HashMap<String, usize>,
    merged_attributes: &mut HashMap<String, Vec<Attribute>>,
) -> Vec<Entry> {
    let mut rebuilt = Vec::new();
    for entry in entries {
        match entry {
            Entry::Config(config) => {
                if let Some(merged) = rebuild_config(config, definition_counts, merged_attributes) {
                    rebuilt.push(Entry::Config(merged));
                }
            }
            Entry::MenuConfig(config) => {
                if let Some(merged) = rebuild_config(config, definition_counts, merged_attributes) {
                    rebuilt.push(Entry::MenuConfig(merged));
                }
            }
            Entry::Menu(mut menu) => {
                menu.entries = rebuild(menu.entries, definition_counts, merged_attributes);
                rebuilt.push(Entry::Menu(menu));
            }
            Entry::Choice(mut choice) => {
                choice.entries = rebuild(choice.entries, definition_counts, merged_attributes);
                rebuilt.push(Entry::Choice(choice));
            }
            Entry::If(_if) => {
                unreachable!("if entries should have been eliminated in a previous pass")
            }
            other => rebuilt.push(other),
        }
    }
    rebuilt
}

/// A single definition passes through unchanged, `depends on` included. The
/// first definition of a multiply defined symbol takes the full merged
/// attribute list; every later one yields `None` and is dropped.
fn rebuild_config(
    config: Config,
    definition_counts: &HashMap<String, usize>,
    merged_attributes: &mut HashMap<String, Vec<Attribute>>,
) -> Option<Config> {
    if definition_counts[&config.symbol] == 1 {
        return Some(config);
    }

    // `remove` yields the attributes exactly once, at the first occurrence;
    // the later occurrences find nothing and are dropped.
    merged_attributes
        .remove(&config.symbol)
        .map(|attributes| Config {
            symbol: config.symbol,
            attributes,
        })
}

// Removes a partial definition's `depends on` attributes and ANDs their
// expression onto the `if` condition of every remaining attribute that can
// carry one.
pub fn distribute_depends(config: Config) -> Config {
    let mut dependencies: Vec<Expression> = Vec::new();
    let mut attributes = Vec::new();
    for attribute in config.attributes {
        match attribute {
            Attribute::DependsOn(dependency) => {
                // expand_depends_if already lowered `depends on X if Y`.
                assert!(dependency.r#if.is_none());
                dependencies.push(dependency.expression);
            }
            other => attributes.push(other),
        }
    }

    // combine_depends has already folded multiple `depends on` into one, but
    // AND-combining here keeps this pass correct on its own.
    let Some(dependency) = dependencies.into_iter().reduce(and_expressions) else {
        return Config {
            symbol: config.symbol,
            attributes,
        };
    };

    Config {
        symbol: config.symbol,
        attributes: attributes
            .into_iter()
            .map(|attribute| add_attribute_condition(attribute, &dependency))
            .collect(),
    }
}

/// AND `dependency` onto a single attribute's `if` condition, keeping the
/// attribute's existing condition first when it already has one.
fn add_attribute_condition(attribute: Attribute, dependency: &Expression) -> Attribute {
    match attribute {
        Attribute::Prompt(mut prompt) => {
            prompt.r#if = Some(add_condition(prompt.r#if, dependency));
            Attribute::Prompt(prompt)
        }
        Attribute::Select(mut select) => {
            select.r#if = Some(add_condition(select.r#if, dependency));
            Attribute::Select(select)
        }
        Attribute::Imply(mut imply) => {
            imply.r#if = Some(add_condition(imply.r#if, dependency));
            Attribute::Imply(imply)
        }
        Attribute::Default(mut default) => {
            default.r#if = Some(add_condition(default.r#if, dependency));
            Attribute::Default(default)
        }
        Attribute::Range(mut range) => {
            range.r#if = Some(add_condition(range.r#if, dependency));
            Attribute::Range(range)
        }
        Attribute::Type(mut config_type) => {
            config_type.r#if = Some(add_condition(config_type.r#if, dependency));
            Attribute::Type(config_type)
        }
        Attribute::Visible(visible) => Attribute::Visible(Some(add_condition(visible, dependency))),
        Attribute::DependsOn(_) => unreachable!("depends on attributes were removed above"),
        // these attributes cannot carry an `if` condition.
        other @ (Attribute::Help(_)
        | Attribute::Modules
        | Attribute::Optional
        | Attribute::Requires(_)
        | Attribute::Option(_)
        | Attribute::Transitional) => other,
    }
}

/// `existing && dependency`, or just `dependency` when there is no existing
/// condition.
fn add_condition(existing: Option<Expression>, dependency: &Expression) -> Expression {
    match existing {
        Some(existing) => and_expressions(existing, dependency.clone()),
        None => dependency.clone(),
    }
}
