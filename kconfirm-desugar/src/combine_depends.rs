use nom_kconfig::{
    Attribute,
    Entry,
    attribute::{OrExpression, Term, depends_on::DependsOn},
    entry::Config, //
};

use crate::utils::and_terms::{combine_and_terms, into_and_terms};

pub fn visit_entries(entries: Vec<Entry>) -> Vec<Entry> {
    let mut all_entries = Vec::new();
    for entry in entries {
        let cur_entries = visit_entry(entry);
        all_entries.extend(cur_entries);
    }
    all_entries
}

pub fn visit_entry(entry: Entry) -> Vec<Entry> {
    return match entry {
        Entry::Config(config) => {
            vec![Entry::Config(visit_config(config))]
        }
        Entry::If(_if) => {
            unreachable!("if entries should have been eliminated in the previous pass")
        }
        _ => vec![entry],
    };
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
