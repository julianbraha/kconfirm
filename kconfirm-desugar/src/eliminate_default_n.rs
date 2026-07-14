use nom_kconfig::{
    Attribute, Entry, Symbol,
    attribute::{
        AndExpression,
        Atom,
        Expression,
        OrExpression,
        Term,
        r#type::Type, //
    },
    entry::Config,
    symbol::ConstantSymbol,
    tristate::Tristate,
};

use crate::utils::map_configs::map_configs;

/// Visits every config/menuconfig, descending into menus and choices.
pub fn visit_entries(entries: Vec<Entry>) -> Vec<Entry> {
    map_configs(entries, visit_config)
}

// Removes the final `default n` (and any `default n` that becomes final as a result) from
// bool and tristate configs. These options already fall back to n when no default is active,
// so a trailing `default n` is redundant: if it is active the value is n, and if its condition
// doesn't fire, the fallback is n anyway. This holds for conditional (`default n if FOO`)
// final defaultstoo, so those are removed as well.
//
// A `default n` followed by a later default is NOT removed: it is active first and shadows the
// later default, so it is meaningful.
//
// TODO (optimization): do a more intelligent elimination of this (any "default n" can actually be removed, and all following defaults can bt removed)
// NOTE: this should actually be part of the check on dead defaults (so we also remove everything that follows a "default y", or any unconditional default)
pub fn visit_config(mut config: Config) -> Config {
    if !is_bool_or_tristate(&config) {
        return config;
    }

    while let Some(final_default_position) = config
        .attributes
        .iter()
        .rposition(|attribute| matches!(attribute, Attribute::Default(_)))
    {
        match &config.attributes[final_default_position] {
            Attribute::Default(default) if is_constant_n(&default.expression) => {
                config.attributes.remove(final_default_position);
            }
            // the final default has a non-n value; nothing left to eliminate
            _ => break,
        }
    }

    config
}

/// Whether the config option is declared as a bool or tristate. `def_bool`/`def_tristate`
/// carry their value in the type attribute rather than a `default` attribute, so they are
/// irrelevant here (and are expanded by kconfirm-desugar before this pass runs anyway).
fn is_bool_or_tristate(config: &Config) -> bool {
    config.attributes.iter().any(|attribute| match attribute {
        Attribute::Type(config_type) => {
            matches!(config_type.r#type, Type::Bool(_) | Type::Tristate(_))
        }
        _ => false,
    })
}

/// Whether the expression is the constant `n`, unwrapping parentheses and single-element
/// and/or chains. A bare `n` parses as a boolean constant, but tristate `n` constants
/// encode the same value, so both are recognized.
fn is_constant_n(expression: &Expression) -> bool {
    let and_expression = match expression {
        OrExpression::Term(and_expression) => and_expression,
        OrExpression::Expression(and_expressions) => match and_expressions.as_slice() {
            [only] => only,
            _ => return false,
        },
    };

    let term = match and_expression {
        AndExpression::Term(term) => term,
        AndExpression::Expression(terms) => match terms.as_slice() {
            [only] => only,
            _ => return false,
        },
    };

    let atom = match term {
        Term::Atom(atom) => atom,
        Term::Not(_) => return false,
    };

    match atom {
        Atom::Symbol(Symbol::Constant(constant)) => matches!(
            constant,
            ConstantSymbol::Boolean(false) | ConstantSymbol::Tristate(Tristate::No)
        ),
        Atom::Parenthesis(inner_expression) => is_constant_n(inner_expression),
        _ => false,
    }
}
