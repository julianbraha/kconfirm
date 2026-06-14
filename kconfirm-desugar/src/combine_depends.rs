use nom_kconfig::{
    Attribute,
    Entry,
    attribute::{AndExpression, OrExpression, Term},
    entry::Config, //
};

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
    let original_attributes = config.attributes;

    let mut transformed_attributes = Vec::new();

    let mut all_dependencies: Vec<AndExpression> = Vec::new();
    for attribute in original_attributes {
        match attribute {
            Attribute::DependsOn(dep) => match dep {
                OrExpression::Term(t) => {
                    all_dependencies.push(t);
                }
                OrExpression::Expression(a) => {
                    let and_expression = AndExpression::Expression(dep);
                    //all_dependencies.push(dep);
                    todo!();
                }
            },
            _ => transformed_attributes.push(attribute),
        }
    }
    transformed_attributes.push(Attribute::DependsOn(OrExpression::Expression(
        all_dependencies,
    )));

    Config {
        attributes: transformed_attributes,
        symbol: config.symbol.clone(),
    }
}
