use nom_kconfig::{
    Attribute,
    Entry,
    attribute::{AndExpression, OrExpression},
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
        Entry::If(r#if) => {
            // TODO: distribute this expression to everything that follows
            let condition = r#if.condition;

            let inner_entries = r#if.entries;

            inner_entries
                .into_iter()
                .flat_map(|e| distribute_dependency(e, condition.clone()))
                .collect()
        }
        Entry::Source(_source) => unreachable!("sources were expanded in the previous pass"),
        _ => vec![entry],
    };
}

fn join_or_expressions(c1: OrExpression, c2: OrExpression) -> OrExpression {
    match (c1, c2) {
        (OrExpression::Term(t1), OrExpression::Term(t2)) => {
            let and_expression = match (t1, t2) {
                (AndExpression::Term(tt1), AndExpression::Term(tt2)) => {
                    AndExpression::Expression(vec![tt1, tt2])
                }
                (AndExpression::Expression(tt1), AndExpression::Expression(tt2)) => {
                    let mut joined = tt1.clone();
                    joined.extend(tt2);
                    AndExpression::Expression(joined)
                }
                (AndExpression::Expression(tt1), AndExpression::Term(tt2)) => {
                    let mut joined = tt1.clone();
                    joined.push(tt2);
                    AndExpression::Expression(joined)
                }
                (AndExpression::Term(tt1), AndExpression::Expression(tt2)) => {
                    let mut joined = tt2.clone();
                    joined.push(tt1);
                    AndExpression::Expression(joined)
                }
            };
            OrExpression::Expression(vec![and_expression])
        }
        (OrExpression::Expression(t1), OrExpression::Term(t2)) => {
            let mut joined = t1.clone();
            joined.push(t2);
            OrExpression::Expression(joined)
        }
        (OrExpression::Term(t1), OrExpression::Expression(t2)) => {
            let mut joined = t2.clone();
            joined.push(t1);
            OrExpression::Expression(joined)
        }
        (OrExpression::Expression(t1), OrExpression::Expression(t2)) => {
            let mut joined = t1.clone();
            joined.extend(t2);
            OrExpression::Expression(joined)
        }
    }
}

pub fn distribute_dependency(entry: Entry, condition: OrExpression) -> Vec<Entry> {
    match entry {
        Entry::Config(c) | Entry::MenuConfig(c) => {
            let new_dependency = Attribute::DependsOn(condition);
            let new_c = visit_config(c, new_dependency);
            vec![Entry::Config(new_c)]
        }
        Entry::Choice(c) => {
            let new_dependency = Attribute::DependsOn(condition);
            let mut new_c = c.clone();

            new_c.options.push(new_dependency);
            vec![Entry::Choice(new_c)]
        }
        Entry::Comment(_) => {
            // do nothing for comment
            vec![entry.clone()]
        }

        Entry::Menu(m) => {
            let mut new_m = m.clone();
            new_m.depends_on.push(condition);

            vec![Entry::Menu(new_m)]
        }

        Entry::If(nested_if) => {
            // join the expressions with a logical-AND and make a recursive call
            let nested_condition = nested_if.condition;

            let joined = join_or_expressions(condition, nested_condition);

            let mut all_entries = Vec::with_capacity(nested_if.entries.len());
            for nested_entry in nested_if.entries {
                all_entries.extend(distribute_dependency(nested_entry, joined.clone()));
            }
            all_entries
        }
        _ => todo!("probably identity, but make sure to check this!"),
    }
}

pub fn visit_config(config: Config, new_dependency: Attribute) -> Config {
    let mut new_c = config.clone();

    new_c.attributes.push(new_dependency);
    new_c
}
