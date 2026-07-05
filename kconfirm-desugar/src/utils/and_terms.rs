use nom_kconfig::attribute::{AndExpression, Atom, OrExpression, Term};

// if it's just a term (CONFIG or !CONFIG) or an AND of terms, then we can just AND all of those.
// but otherwise, we need to wrap it in parentheses.
// e.g. need to wrap `a || b` in parentheses to preserve the order of operations.
pub(crate) fn into_and_terms(expression: OrExpression) -> Vec<Term> {
    match expression {
        OrExpression::Term(AndExpression::Term(term)) => vec![term],
        OrExpression::Term(AndExpression::Expression(terms)) => terms,
        OrExpression::Expression(_) => {
            vec![Term::Atom(Atom::Parenthesis(Box::new(expression)))]
        }
    }
}

// fold the collected terms into one `AndExpression`, or `None` when there were
// no terms so callers don't emit an empty `depends on`.
pub(crate) fn combine_and_terms(mut terms: Vec<Term>) -> Option<AndExpression> {
    match terms.len() {
        0 => None,
        1 => Some(AndExpression::Term(terms.pop().unwrap())),
        _ => Some(AndExpression::Expression(terms)),
    }
}

// ANDs two expressions together (`c1 && c2`).
// wraps a subexpression in parentheses if it has an ||
pub(crate) fn and_expressions(c1: OrExpression, c2: OrExpression) -> OrExpression {
    let mut terms = into_and_terms(c1);
    terms.extend(into_and_terms(c2));
    // each expression contributes at least one term, so there are always >= 2.
    OrExpression::Term(AndExpression::Expression(terms))
}

// the top-level disjuncts of an expression.
pub(crate) fn into_or_terms(expression: OrExpression) -> Vec<AndExpression> {
    match expression {
        OrExpression::Term(term) => vec![term],
        OrExpression::Expression(terms) => terms,
    }
}

// ORs two expressions together (`c1 || c2`) by concatenating their disjuncts.
pub(crate) fn or_expressions(c1: OrExpression, c2: OrExpression) -> OrExpression {
    let mut disjuncts = into_or_terms(c1);
    disjuncts.extend(into_or_terms(c2));
    // each expression contributes at least one disjunct, so there are always >= 2.
    OrExpression::Expression(disjuncts)
}
