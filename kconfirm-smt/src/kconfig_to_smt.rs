use kconfirm_lib::TypeInfo;
use kconfirm_lib::Z3Types;
use nom_kconfig::Symbol;
use nom_kconfig::attribute::AndExpression;
use nom_kconfig::attribute::Atom;
use nom_kconfig::attribute::OrExpression;
use nom_kconfig::attribute::expression::CompareOperand;
use nom_kconfig::attribute::r#type::Type;
use nom_kconfig::symbol::ConstantSymbol;
use nom_kconfig::tristate::Tristate;
use std::collections::HashMap;
use std::num::ParseIntError;
use std::str::FromStr;
use z3::ast::Bool as z3_bool;
use z3::ast::Int as z3_int;
use z3::ast::String as z3_string;

pub fn model_kconfig_type(symbol: String, kconfig_type: &Type) -> Z3Types {
    match kconfig_type {
        kconfig_bool(_) | Type::DefBool(_) => {
            println!(
                "TODO: creating a z3 integer for a tristate. make sure we add the [0, 2] range constraint for this later..."
            );
            Z3Types::Integer(z3_int::new_const(symbol))
        }

        kconfig_string(s) => Z3Types::String(z3_string::new_const(symbol)),
        kconfig_int(i) => Z3Types::Integer(z3_int::new_const(symbol)),

        kconfig_hex(h) => {
            println!(
                "TODO: creating a z3 integer for a hex. make sure we convert the model's assigned value back to hex representation when writing the config"
            );
            Z3Types::Integer(z3_int::new_const(symbol))
        }

        Type::Tristate(_) | Type::DefTristate(_) => {
            println!(
                "TODO: creating a z3 integer for a tristate. make sure we add the [0, 2] range constraint for this later..."
            );
            Z3Types::Integer(z3_int::new_const(symbol))
        }
    }
}

/// Models a Kconfig int comparison as an SMT boolean expression.
fn model_kconfig_int_comparison(
    left: z3_int,
    comparison: nom_kconfig::attribute::CompareOperator,
    right: z3_int,
) -> z3_bool {
    match comparison {
        nom_kconfig::attribute::CompareOperator::GreaterThan => left.gt(right),
        nom_kconfig::attribute::CompareOperator::Equal => left.eq(right),
        nom_kconfig::attribute::CompareOperator::GreaterOrEqual => left.ge(right),
        nom_kconfig::attribute::CompareOperator::NotEqual => left.ne(right),
        nom_kconfig::attribute::CompareOperator::LowerThan => left.lt(right),
        nom_kconfig::attribute::CompareOperator::LowerOrEqual => left.le(right),
    }
}

/// Models a Kconfig string comparison as an SMT boolean expression.
fn model_kconfig_str_comparison(
    left: z3_string,
    comparison: nom_kconfig::attribute::CompareOperator,
    right: z3_string,
) -> z3_bool {
    match comparison {
        nom_kconfig::attribute::CompareOperator::Equal => left.eq(right),

        nom_kconfig::attribute::CompareOperator::NotEqual => left.ne(right),
        _ => unreachable!("assuming no other kinds of string comparison than = and !="),
    }
}

// this thing may need to return a boolean expression, but it could also be another type.
// returns a None if we don't want to handle that type of expression (caller should effectively ignore Nones)
fn model_kconfig_atom(symbol_table: &HashMap<String, TypeInfo>, atom: Atom) -> Option<Z3Types> {
    match atom {
        // descend the parse tree.
        // models a constant value or config option.
        Atom::Symbol(sym) => return Some(model_kconfig_symbol(symbol_table, sym)),

        // some sort of expression
        Atom::Parenthesis(parens_expr) => match *parens_expr {
            OrExpression::Term(term) => {
                return model_kconfig_and_expr(symbol_table, term);
            }
            OrExpression::Expression(or_expr) => {
                let expression_bool: z3_bool = model_kconfig_or_expr(symbol_table, or_expr);
                return Some(Z3Types::Bool(expression_bool));
            }
        },
        Atom::Compare(compare) => {
            let left = match compare.left {
                CompareOperand::Symbol(sym) => model_kconfig_symbol(symbol_table, sym),
                CompareOperand::Macro(_) => todo!("model compare left operand macro"),
            };

            let op = compare.operator;

            let right = match compare.right {
                CompareOperand::Symbol(sym) => model_kconfig_symbol(symbol_table, sym),
                CompareOperand::Macro(_) => todo!("model compare right operand macro"),
            };
            // early termination if the right variable is unknown

            match (left, right) {
                (Z3Types::Bool(_), _) | (_, Z3Types::Bool(_)) => {
                    todo!("model kconfig boolean comparison")
                }

                (Z3Types::Integer(i_left), Z3Types::Integer(i_right)) => {
                    return Some(Z3Types::Bool(model_kconfig_int_comparison(
                        i_left, op, i_right,
                    )));
                }

                (Z3Types::String(s_left), Z3Types::String(s_right)) => {
                    return Some(Z3Types::Bool(model_kconfig_str_comparison(
                        s_left, op, s_right,
                    )));
                }

                _ => todo!("comparisons of other types"),
            }
        }
        _ => {
            println!("NOTE: not handling functions and expressions in kconfig");
            None
        }
    }
}

/// Converts symbols (e.g. constant 'n' or config option identifiers) from Kconfig to Z3.
/// This is modeling the leaves of the parse tree.
/// - For config options, this uses Z3 variables (an instance of Z3Types)
/// - For constants:
///   1. Strings are strings
///   2. Integers an Hex are integers
///   3. Tristates and booleans are bounded integers (0 <= b <= 1 for boolean b and 0 <= t <= 2 for tristate t)
///
/// NOTE: this will retrieve type information from the symbol table for config option identifiers.
///       Expects all symbols to have been inserted into the symbol table already.
fn model_kconfig_symbol(symbol_table: &HashMap<String, TypeInfo>, sym: Symbol) -> Z3Types {
    match sym {
        // symbol is a constant value (e.g. "n")
        Symbol::Constant(c) => return model_kconfig_constant(c),
        // symbol is another kconfig option
        Symbol::NonConstant(val) => return model_kconfig_identifier(symbol_table, &val),
    }
}

/// Model a constant value as a Z3 value.
/// NOTE: booleans, tristates, and hex are all modeled as integers.
fn model_kconfig_constant(c: ConstantSymbol) -> Z3Types {
    match c {
        ConstantSymbol::Integer(i) => Z3Types::Integer(z3_int::from_i64(i)),
        ConstantSymbol::Hex(h) => {
            let hex_as_i64 = parse_hex_str_to_i64(&h).unwrap();
            Z3Types::Hex(z3_int::from_i64(hex_as_i64))
        }
        ConstantSymbol::String(s) => Z3Types::String(z3_string::from_str(&s).unwrap()),
        ConstantSymbol::Boolean(b) => match b {
            true => Z3Types::Integer(z3_int::from_u64(1)),
            false => Z3Types::Integer(z3_int::from_u64(0)),
        },
        ConstantSymbol::Tristate(t) => match t {
            Tristate::No => Z3Types::Integer(z3_int::from_u64(0)),
            Tristate::Yes => Z3Types::Integer(z3_int::from_u64(1)),
            Tristate::Module => Z3Types::Integer(z3_int::from_u64(2)),
        },
    }
}

/// Retrieves the Z3 variable for the Kconfig identifier from the symbol table.
/// If the config option doesn't exist, then it is modeled as a Z3 boolean `false`.
fn model_kconfig_identifier(symbol_table: &HashMap<String, TypeInfo>, sym: &str) -> Z3Types {
    match symbol_table.get(sym) {
        None => {
            // NOTE: there are some kconfig variables that don't have definitions (these are dangling references)
            // we replace these with a boolean false.
            return Z3Types::Bool(z3_bool::from_bool(false));
        }
        Some(dep) => match dep.z3_type.clone() {
            Some(z3t) => {
                return z3t;
            }
            None => todo!(
                "the config option has no type in the symbol table (assume boolean? check the source.)"
            ),
        },
    }
}

/// Models a Kconfig OR expression as an SMT formula (z3 bool).
fn model_kconfig_or_expr(
    symbol_table: &HashMap<String, TypeInfo>,
    or_expr: Vec<AndExpression>,
) -> z3_bool {
    let z3_bools: Vec<Z3Types> = or_expr
        .into_iter()
        .filter_map(|and_expr| model_kconfig_and_expr(symbol_table, and_expr))
        .collect();

    let or_terms_asserted_bool: Vec<z3_bool> = z3_bools
        .into_iter()
        .map(|e| match e {
            Z3Types::Bool(b) => b,
            // we are modeling booleans and tristates as integers
            // so a condition of A AND B is (A > 0) AND (B > 0)
            Z3Types::Integer(i) => i.gt(z3_int::from_u64(0)),
            _ => unreachable!("expected to only use AND() on bools"),
        })
        .collect();

    return z3_bool::or(&or_terms_asserted_bool);
}

/// Models a Kconfig AND expression as one of two cases:
/// 1. SMT term (z3 bool) if the expression has multiple nom-kconfig `term`s,
/// 2. An SMT variable if the expression has only one nom-kconfig `term`.
pub fn model_kconfig_and_expr(
    symbol_table: &HashMap<String, TypeInfo>,
    and_expr: AndExpression,
) -> Option<Z3Types> {
    return match and_expr {
        // this not really an AND. it is case 1
        AndExpression::Term(term) => model_kconfig_term(symbol_table, term),
        // this is a true AND. it is case 2
        AndExpression::Expression(terms) => {
            let and_terms: Vec<Z3Types> = terms
                .into_iter()
                .filter_map(|term| model_kconfig_term(symbol_table, term))
                .collect();

            let and_terms_bool: Vec<z3_bool> = and_terms
                .into_iter()
                .map(|and_term| match and_term {
                    Z3Types::Integer(i) => i.ge(z3_int::from_i64(1)),
                    Z3Types::Bool(b) => b,
                    _ => unreachable!("don't expect to AND nonbools/nontristate"),
                })
                .collect();

            return Some(Z3Types::Bool(z3_bool::and(&and_terms_bool)));
        }
    };
}

/// Look up a Kconfig identifier in our symbol table.
/// Returns `None` when the identifier doesn't exist. Note that, for Linux, this config option may
/// only be defined in a different architecture, or it may be a dangling reference.
fn model_kconfig_term(
    symbol_table: &HashMap<String, TypeInfo>,
    term: nom_kconfig::attribute::Term,
) -> Option<Z3Types> {
    // nom-kconfig terms can be identifier, or !identifier
    match term {
        nom_kconfig::attribute::Term::Not(n) => {
            match model_kconfig_atom(symbol_table, n)? /* return `None` if not in symtab */ {
                // if there was actually a bool, we NOT it
                Z3Types::Bool(bool) => return Some(Z3Types::Bool(bool.not())),

                // !TRISTATE is modeled here as tristate=0 (tristates are modeled as integers in SMT)
                Z3Types::Tristate(i) => return Some(Z3Types::Bool(i.eq(z3_int::from_i64(0)))),

                _ => unreachable!("assuming that nonbooleans cannot be NOT'd"),
            }
        }
        // just return the symbol table entry, if it's not NOT'd
        nom_kconfig::attribute::Term::Atom(a) => {
            return model_kconfig_atom(symbol_table, a);
        }
    }
}

/// Helper function for converting a Kconfig `hex` to Rust's i64, intended for later conversion to
/// an SMT integer.
fn parse_hex_str_to_i64(s: &str) -> Result<i64, ParseIntError> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    i64::from_str_radix(s, 16)
}
