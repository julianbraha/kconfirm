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
