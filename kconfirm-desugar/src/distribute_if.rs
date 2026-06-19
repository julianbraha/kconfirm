use nom_kconfig::{
    Attribute,
    Entry,
    attribute::{AndExpression, OrExpression, depends_on::DependsOn},
    entry::Config, //
};

use crate::and_terms::into_and_terms;

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
        _ => vec![entry],
    };
}

/// AND two `if` conditions together (`c1 && c2`).
///
/// Nested `if` blocks mean both conditions must hold. A top-level `||` in either
/// condition is parenthesized (via [`into_and_terms`]) so it binds correctly
/// under the `&&`: joining `a || b` with `c` yields `(a || b) && c`, not the
/// wrong `a || b && c`.
fn and_conditions(c1: OrExpression, c2: OrExpression) -> OrExpression {
    let mut terms = into_and_terms(c1);
    terms.extend(into_and_terms(c2));
    // each condition contributes at least one term, so there are always >= 2.
    OrExpression::Term(AndExpression::Expression(terms))
}

pub fn distribute_dependency(entry: Entry, condition: OrExpression) -> Vec<Entry> {
    match entry {
        Entry::Config(c) | Entry::MenuConfig(c) => {
            let new_dependency = Attribute::DependsOn(DependsOn {
                expression: condition,
                r#if: None,
            });
            let new_c = visit_config(c, new_dependency);
            vec![Entry::Config(new_c)]
        }
        Entry::Choice(c) => {
            let new_dependency = Attribute::DependsOn(DependsOn {
                expression: condition,
                r#if: None,
            });
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
            new_m.depends_on.push(DependsOn {
                expression: condition,
                r#if: None,
            });

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
