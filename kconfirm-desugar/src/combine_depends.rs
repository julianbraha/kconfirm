use nom_kconfig::{
    Attribute,
    Entry,
    attribute::{OrExpression, Term, depends_on::DependsOn},
    entry::Config, //
};

use crate::utils::and_terms::{combine_and_terms, into_and_terms};

pub fn visit_entries(entries: Vec<Entry>) -> Vec<Entry> {
    entries.into_iter().map(visit_entry).collect()
}

pub fn visit_entry(entry: Entry) -> Entry {
    match entry {
        Entry::Config(config) => Entry::Config(visit_config(config)),
        Entry::MenuConfig(config) => Entry::MenuConfig(visit_config(config)),
        Entry::Menu(mut menu) => {
            menu.depends_on = combine_depends_on(menu.depends_on);
            menu.entries = visit_entries(menu.entries);
            Entry::Menu(menu)
        }
        Entry::Choice(mut choice) => {
            choice.options = combine_choice_options(choice.options);
            choice.entries = visit_entries(choice.entries);
            Entry::Choice(choice)
        }
        Entry::If(_if) => {
            unreachable!("if entries should have been eliminated in the previous pass")
        }
        other => other,
    }
}

// combines all of the `depends on` statements with a logical AND into one attribute
pub fn visit_config(config: Config) -> Config {
    let mut transformed_attributes = Vec::new();

    let mut and_terms: Vec<Term> = Vec::new();
    for attribute in config.attributes {
        match attribute {
            Attribute::DependsOn(dep) => and_terms.extend(into_and_terms(dep.expression)),
            other => transformed_attributes.push(other),
        }
    }

    if let Some(combined) = combine_and_terms(and_terms) {
        transformed_attributes.push(Attribute::DependsOn(DependsOn {
            expression: OrExpression::Term(combined),
            r#if: None,
        }));
    }

    Config {
        attributes: transformed_attributes,
        symbol: config.symbol,
    }
}

/// Combine a list of `depends on` (e.g. a menu's `depends_on`) into a single
/// AND'd entry, or an empty list when there were none.
fn combine_depends_on(deps: Vec<DependsOn>) -> Vec<DependsOn> {
    let mut and_terms: Vec<Term> = Vec::new();
    for dep in deps {
        and_terms.extend(into_and_terms(dep.expression));
    }

    match combine_and_terms(and_terms) {
        Some(combined) => vec![DependsOn {
            expression: OrExpression::Term(combined),
            r#if: None,
        }],
        None => Vec::new(),
    }
}

/// Combine the `depends on` attributes within a choice's options into a single
/// AND'd attribute.
fn combine_choice_options(options: Vec<Attribute>) -> Vec<Attribute> {
    let mut other_options = Vec::new();

    let mut and_terms: Vec<Term> = Vec::new();
    for option in options {
        match option {
            Attribute::DependsOn(dep) => and_terms.extend(into_and_terms(dep.expression)),
            other => other_options.push(other),
        }
    }

    if let Some(combined) = combine_and_terms(and_terms) {
        other_options.push(Attribute::DependsOn(DependsOn {
            expression: OrExpression::Term(combined),
            r#if: None,
        }));
    }

    other_options
}
