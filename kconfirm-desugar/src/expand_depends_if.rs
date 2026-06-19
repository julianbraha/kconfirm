use nom_kconfig::{
    Attribute,
    Entry,
    Symbol,
    attribute::{
        depends_on::DependsOn,
        expression::{
            AndExpression, Atom, CompareExpression, CompareOperand, CompareOperator, Expression,
            OrExpression, Term,
        },
    },
    entry::Config,
    symbol::ConstantSymbol,
    tristate::Tristate, //
};

pub fn visit_entries(entries: Vec<Entry>) -> Vec<Entry> {
    let mut all_entries = Vec::new();
    for entry in entries {
        all_entries.extend(visit_entry(entry));
    }
    all_entries
}

pub fn visit_entry(entry: Entry) -> Vec<Entry> {
    match entry {
        Entry::Config(config) => vec![Entry::Config(visit_config(config))],
        Entry::MenuConfig(config) => vec![Entry::MenuConfig(visit_config(config))],
        // `depends on X if Y` can also appear on the entries nested inside these
        // containers (an `if`/`menu`/`choice` is not flattened until later
        // passes), so recurse to reach every config.
        Entry::Choice(mut choice) => {
            choice.options = choice.options.into_iter().map(expand_attribute).collect();
            choice.entries = visit_entries(choice.entries);
            vec![Entry::Choice(choice)]
        }
        Entry::Menu(mut menu) => {
            menu.depends_on = menu.depends_on.into_iter().map(expand_depends_on).collect();
            menu.entries = visit_entries(menu.entries);
            vec![Entry::Menu(menu)]
        }
        Entry::If(mut r#if) => {
            r#if.entries = visit_entries(r#if.entries);
            vec![Entry::If(r#if)]
        }
        Entry::Source(_source) => {
            unreachable!("sources should have been expanded in the previous pass")
        }
        _ => vec![entry],
    }
}

// expands 'depends on X if Y' to 'depends on X || (Y == n)'
pub fn visit_config(config: Config) -> Config {
    Config {
        symbol: config.symbol,
        attributes: config
            .attributes
            .into_iter()
            .map(expand_attribute)
            .collect(),
    }
}

/// Rewrite a `depends on X if Y` attribute; every other attribute is unchanged.
fn expand_attribute(attribute: Attribute) -> Attribute {
    match attribute {
        Attribute::DependsOn(dependency) => Attribute::DependsOn(expand_depends_on(dependency)),
        other => other,
    }
}

/// Fold the `if Y` of a `depends on X if Y` into the dependency expression,
/// yielding `depends on X || (Y == n)`. A plain `depends on X` is left as-is.
fn expand_depends_on(dependency: DependsOn) -> DependsOn {
    match dependency.r#if {
        None => dependency,
        Some(condition) => DependsOn {
            expression: or_with(dependency.expression, condition_is_off(condition)),
            r#if: None,
        },
    }
}

/// `X || disjunct`: append `disjunct` as another top-level alternative of `X`.
fn or_with(expression: Expression, disjunct: AndExpression) -> Expression {
    match expression {
        OrExpression::Term(term) => OrExpression::Expression(vec![term, disjunct]),
        OrExpression::Expression(mut terms) => {
            terms.push(disjunct);
            OrExpression::Expression(terms)
        }
    }
}

/// Build the `(Y == n)` disjunct, which holds exactly when the `if` condition
/// `Y` is disabled — so the dependency is waived in that case.
fn condition_is_off(condition: Expression) -> AndExpression {
    let symbol = match single_symbol(&condition) {
        Some(symbol) => symbol.clone(),
        None => todo!("'depends on X if Y' where Y is not a single symbol: {condition}"),
    };

    let comparison = Atom::Compare(CompareExpression {
        left: CompareOperand::Symbol(symbol),
        operator: CompareOperator::Equal,
        right: CompareOperand::Symbol(Symbol::Constant(ConstantSymbol::Tristate(Tristate::No))),
    });

    // wrap in parentheses so the dependency reads `X || (Y == n)`
    let parenthesized = Atom::Parenthesis(Box::new(OrExpression::Term(AndExpression::Term(
        Term::Atom(comparison),
    ))));
    AndExpression::Term(Term::Atom(parenthesized))
}

/// If `expression` is a single bare symbol, return it.
fn single_symbol(expression: &Expression) -> Option<&Symbol> {
    match expression {
        OrExpression::Term(AndExpression::Term(Term::Atom(Atom::Symbol(symbol)))) => Some(symbol),
        _ => None,
    }
}
