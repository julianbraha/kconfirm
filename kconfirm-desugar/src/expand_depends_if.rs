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

use crate::utils::and_terms::{and_expressions, or_expressions};

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
        // `depends on X if Y` can also appear on the entries nested inside
        // these containers (menus/choices are never flattened, and a stray
        // not-yet-flattened `if` is tolerated), so recurse to reach every config.
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
/// which becomes `depends on X || Y=n`.
///
/// A plain `depends on X` is left as-is.
fn expand_depends_on(dependency: DependsOn) -> DependsOn {
    match dependency.r#if {
        None => dependency,
        Some(condition) => DependsOn {
            expression: or_expressions(dependency.expression, condition_is_off(condition)),
            r#if: None,
        },
    }
}

/// Build the expression that holds exactly when `condition` is false (evaluates
/// to `n`), so the dependency is waived in that case. The condition is lowered
/// recursively:
/// - `Y` is false when `Y` is disabled: `(Y == n)`
/// - `!Y` is false when `Y` is enabled: `(Y != n)`
/// - `c1 && c2` is false when either operand is false
/// - `c1 || c2` is false when both operands are false
/// - a comparison is boolean: false exactly when the negated comparison holds
fn condition_is_off(condition: Expression) -> Expression {
    match condition {
        OrExpression::Term(term) => and_expression_is_off(term),
        // `c1 || c2` is off when every disjunct is off.
        OrExpression::Expression(disjuncts) => disjuncts
            .into_iter()
            .map(and_expression_is_off)
            .reduce(and_expressions)
            .expect("an or-expression has at least one disjunct"),
    }
}

/// Dual of `condition_is_off`: holds exactly when `condition` is not `n`.
fn condition_is_on(condition: Expression) -> Expression {
    match condition {
        OrExpression::Term(term) => and_expression_is_on(term),
        // `c1 || c2` is on when any disjunct (OR term) is on.
        OrExpression::Expression(disjuncts) => disjuncts
            .into_iter()
            .map(and_expression_is_on)
            .reduce(or_expressions)
            .expect("an or-expression has at least one disjunct"),
    }
}

fn and_expression_is_off(and: AndExpression) -> Expression {
    match and {
        AndExpression::Term(term) => term_is_off(term),
        // `c1 && c2` is off when any conjunct is off.
        AndExpression::Expression(conjuncts) => conjuncts
            .into_iter()
            .map(term_is_off)
            .reduce(or_expressions)
            .expect("an and-expression has at least one conjunct"),
    }
}

fn and_expression_is_on(and: AndExpression) -> Expression {
    match and {
        AndExpression::Term(term) => term_is_on(term),
        // `c1 && c2` is true when every conjunct is true.
        AndExpression::Expression(conjuncts) => conjuncts
            .into_iter()
            .map(term_is_on)
            .reduce(and_expressions)
            .expect("an and-expression has at least one conjunct"),
    }
}

fn term_is_off(term: Term) -> Expression {
    match term {
        Term::Atom(atom) => atom_is_off(atom),
        Term::Not(atom) => atom_is_on(atom),
    }
}

fn term_is_on(term: Term) -> Expression {
    match term {
        Term::Atom(atom) => atom_is_on(atom),
        Term::Not(atom) => atom_is_off(atom),
    }
}

fn atom_is_off(atom: Atom) -> Expression {
    match atom {
        // `Y` is false when it is disabled.
        Atom::Symbol(symbol) => symbol_compare(symbol, CompareOperator::Equal),
        Atom::Parenthesis(inner) => condition_is_off(*inner),
        // a comparison is boolean, so it is false exactly when its negation holds.
        Atom::Compare(comparison) => comparison_expression(negate_comparison(comparison)),

        // TODO: we now preprocess macros, this should be removable
        Atom::Macro(_) => term_expression(Term::Not(atom)),
    }
}

fn atom_is_on(atom: Atom) -> Expression {
    match atom {
        // `Y` is on when it is not disabled.
        Atom::Symbol(symbol) => symbol_compare(symbol, CompareOperator::NotEqual),
        Atom::Parenthesis(inner) => condition_is_on(*inner),
        // a comparison or macro call already is the condition itself.
        Atom::Compare(_) | Atom::Macro(_) => term_expression(Term::Atom(atom)),
    }
}

/// Build the comparison `(symbol op n)` (e.g. `(Y == n)` or `(Y != n)`).
fn symbol_compare(symbol: Symbol, operator: CompareOperator) -> Expression {
    comparison_expression(CompareExpression {
        left: CompareOperand::Symbol(symbol),
        operator,
        right: CompareOperand::Symbol(Symbol::Constant(ConstantSymbol::Tristate(Tristate::No))),
    })
}

/// Wrap the comparison in parentheses so the
/// dependency reads e.g. for depends on X if Y: `X || (Y == n)`.
fn comparison_expression(comparison: CompareExpression) -> Expression {
    let parenthesized = Atom::Parenthesis(Box::new(term_expression(Term::Atom(Atom::Compare(
        comparison,
    )))));
    term_expression(Term::Atom(parenthesized))
}

fn term_expression(term: Term) -> Expression {
    OrExpression::Term(AndExpression::Term(term))
}

fn negate_comparison(comparison: CompareExpression) -> CompareExpression {
    CompareExpression {
        left: comparison.left,
        operator: negate_operator(comparison.operator),
        right: comparison.right,
    }
}

fn negate_operator(operator: CompareOperator) -> CompareOperator {
    match operator {
        CompareOperator::Equal => CompareOperator::NotEqual,
        CompareOperator::NotEqual => CompareOperator::Equal,
        CompareOperator::GreaterThan => CompareOperator::LowerOrEqual,
        CompareOperator::LowerOrEqual => CompareOperator::GreaterThan,
        CompareOperator::LowerThan => CompareOperator::GreaterOrEqual,
        CompareOperator::GreaterOrEqual => CompareOperator::LowerThan,
    }
}
