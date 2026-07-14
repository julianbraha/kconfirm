use kconfirm_lib::TypeInfo;
use kconfirm_lib::Z3Types;
use log::{debug, warn};
use nom_kconfig::Symbol;
use nom_kconfig::attribute::AndExpression;
use nom_kconfig::attribute::Atom;
use nom_kconfig::attribute::CompareOperator;
use nom_kconfig::attribute::OrExpression;
use nom_kconfig::attribute::expression::CompareOperand;
use nom_kconfig::attribute::range::RangeBound;
use nom_kconfig::attribute::r#type::Type;
use nom_kconfig::symbol::ConstantSymbol;
use nom_kconfig::tristate::Tristate;
use std::collections::HashMap;
use std::num::ParseIntError;
use std::str::FromStr;
use z3::ast::Bool as z3_bool;
use z3::ast::Int as z3_int;
use z3::ast::String as z3_string;
use z3_ternary::Ternary;

/// Models a tristate comparison `left op right` on order-encoded pairs.
fn model_ternary_comparison(
    left: &Ternary,
    comparison: CompareOperator,
    right: &Ternary,
) -> Ternary {
    let q = match comparison {
        CompareOperator::Equal => z3_ternary::eq(left, right),
        CompareOperator::NotEqual => z3_ternary::bool_not(&z3_ternary::eq(left, right)),
        CompareOperator::LowerThan => z3_ternary::lt(left, right),
        CompareOperator::LowerOrEqual => z3_ternary::le(left, right),
        CompareOperator::GreaterThan => z3_ternary::lt(right, left),
        CompareOperator::GreaterOrEqual => z3_ternary::le(right, left),
    };
    Ternary::from_prop(&q)
}

/// Models a Kconfig int comparison. The result is the tristate `y` or `n`.
fn model_kconfig_int_comparison(
    left: z3_int,
    comparison: CompareOperator,
    right: z3_int,
) -> Ternary {
    let q = match comparison {
        CompareOperator::GreaterThan => left.gt(right),
        CompareOperator::Equal => left.eq(right),
        CompareOperator::GreaterOrEqual => left.ge(right),
        CompareOperator::NotEqual => left.ne(right),
        CompareOperator::LowerThan => left.lt(right),
        CompareOperator::LowerOrEqual => left.le(right),
    };
    Ternary::from_prop(&q)
}

/// Models a Kconfig string comparison.
fn model_kconfig_str_comparison(
    left: z3_string,
    comparison: CompareOperator,
    right: z3_string,
) -> Ternary {
    let q = match comparison {
        CompareOperator::Equal => left.eq(right),
        CompareOperator::NotEqual => left.ne(right),
        CompareOperator::LowerThan => left.str_lt(right),
        CompareOperator::LowerOrEqual => left.str_le(right),
        CompareOperator::GreaterThan => left.str_gt(right),
        CompareOperator::GreaterOrEqual => left.str_ge(right),
    };
    Ternary::from_prop(&q)
}

/// The value string of a bool/tristate: "n"/"m"/"y", as a z3
/// string, for when the other operand is a string option.
fn tri_value_string(t: &Ternary) -> z3_string {
    let value_y = z3_string::from_str("y").unwrap();
    let value_m = z3_string::from_str("m").unwrap();
    let value_n = z3_string::from_str("n").unwrap();
    t.ge_y.ite(&value_y, &t.ge_m.ite(&value_m, &value_n))
}

/// Parses a y/m/n string constant (as written in quotes in Kconfig) into the
/// corresponding constant pair.
fn tristate_constant_from_str(s: &str) -> Option<Ternary> {
    match s {
        "y" | "Y" => Some(Ternary::y()),
        "m" | "M" => Some(Ternary::m()),
        "n" | "N" => Some(Ternary::n()),
        _ => None,
    }
}

/// A comparison operand: the z3 value of a defined symbol or non-string constant,
/// a quoted constant kept as its raw text,
/// or a dangling reference which kconfig evaluates by its own name.
enum ComparisonOperand {
    Known(Z3Types),
    ConstantText(String),
    Undefined(String),
}

/// A comparison operand, following kconfig's expr_parse_string.
enum ParsedOperand {
    /// A number (constant, or an undefined name / quoted text that parses with strtoll base 0).
    NumberLit(i64),
    /// The symbolic value of an int/hex option: compared numerically.
    NumberVar(z3_int),
    /// A bool/tristate value: n/m/y parse as the numbers 0/1/2.
    Tri(Ternary),
    /// Constant text that does not parse as a number (an undefined symbol's
    /// name, or a non-numeric quoted constant): compared with strcmp.
    Text(String),
    /// The symbolic value of a string option.
    TextVar(z3_string),
}

fn parse_comparison_operand(operand: ComparisonOperand) -> ParsedOperand {
    match operand {
        ComparisonOperand::Known(Z3Types::Ternary(t)) => ParsedOperand::Tri(t),
        ComparisonOperand::Known(Z3Types::Integer(i)) => match i.as_i64() {
            Some(k) => ParsedOperand::NumberLit(k),
            None => ParsedOperand::NumberVar(i),
        },
        // a string value reaching here came from the symbol table, i.e. it is
        // the variable of a defined string option (constants arrive as
        // ConstantText)
        ComparisonOperand::Known(Z3Types::String(s)) => ParsedOperand::TextVar(s),
        ComparisonOperand::Known(Z3Types::Bool(_)) => {
            unreachable!("Z3Types::Bool is never produced for kconfig symbols")
        }
        // quoted text and undefined names go through the strtoll-base-0
        // parse: numeric text is a number, everything else compares as text
        ComparisonOperand::ConstantText(text) | ComparisonOperand::Undefined(text) => {
            match kconfig_parse_number(&text) {
                Some(k) => ParsedOperand::NumberLit(k),
                None => ParsedOperand::Text(text),
            }
        }
    }
}

/// Swaps the sides of a comparison operator: `a op b` is `b flip(op) a`.
fn flip_operator(op: CompareOperator) -> CompareOperator {
    match op {
        CompareOperator::Equal => CompareOperator::Equal,
        CompareOperator::NotEqual => CompareOperator::NotEqual,
        CompareOperator::LowerThan => CompareOperator::GreaterThan,
        CompareOperator::LowerOrEqual => CompareOperator::GreaterOrEqual,
        CompareOperator::GreaterThan => CompareOperator::LowerThan,
        CompareOperator::GreaterOrEqual => CompareOperator::LowerOrEqual,
    }
}

/// Maps kconfig's `res`-based switch: whether `left op right` holds given the
/// ordering of left relative to right.
fn ordering_holds(op: CompareOperator, ordering: std::cmp::Ordering) -> bool {
    use std::cmp::Ordering::*;
    match op {
        CompareOperator::Equal => ordering == Equal,
        CompareOperator::NotEqual => ordering != Equal,
        CompareOperator::GreaterThan => ordering == Greater,
        CompareOperator::GreaterOrEqual => ordering != Less,
        CompareOperator::LowerThan => ordering == Less,
        CompareOperator::LowerOrEqual => ordering != Greater,
    }
}

fn constant_result(holds: bool) -> Ternary {
    match holds {
        true => Ternary::y(),
        false => Ternary::n(),
    }
}

/// `value >= k` for an order-encoded bool/tristate value (0/1/2).
fn tri_ge(t: &Ternary, k: i64) -> z3_bool {
    if k <= 0 {
        z3_bool::from_bool(true)
    } else if k == 1 {
        t.ge_m.clone()
    } else if k == 2 {
        t.ge_y.clone()
    } else {
        z3_bool::from_bool(false)
    }
}

/// A bool/tristate value compared numerically against a number as a proposition.
/// Stays in boolean: the pair is the order encoding of 0/1/2.
fn tri_vs_number_literal(t: &Ternary, op: CompareOperator, k: i64) -> z3_bool {
    let equal_to_k = match k {
        0 => t.is_n(),
        1 => t.is_m(),
        2 => t.is_y(),
        _ => z3_bool::from_bool(false),
    };
    match op {
        CompareOperator::Equal => equal_to_k,
        CompareOperator::NotEqual => z3_ternary::bool_not(&equal_to_k),
        CompareOperator::GreaterOrEqual => tri_ge(t, k),
        CompareOperator::GreaterThan => tri_ge(t, k.saturating_add(1)),
        CompareOperator::LowerThan => z3_ternary::bool_not(&tri_ge(t, k)),
        CompareOperator::LowerOrEqual => z3_ternary::bool_not(&tri_ge(t, k.saturating_add(1))),
    }
}

/// A bool/tristate's value as a z3 integer (0/1/2), for numeric
/// comparison against an int/hex option's variable.
fn tri_as_int(t: &Ternary) -> z3_int {
    t.ge_y.ite(
        &z3_int::from_i64(2),
        &t.ge_m.ite(&z3_int::from_i64(1), &z3_int::from_i64(0)),
    )
}

/// Constant text compared against a bool/tristate: kconfig strcmps the text
/// with the value string "n"/"m"/"y".
fn tri_vs_text(t: &Ternary, op: CompareOperator, text: &str, text_on_left: bool) -> Ternary {
    let holds_for = |value_string: &str| -> z3_bool {
        let ordering = match text_on_left {
            true => text.as_bytes().cmp(value_string.as_bytes()),
            false => value_string.as_bytes().cmp(text.as_bytes()),
        };
        z3_bool::from_bool(ordering_holds(op.clone(), ordering))
    };
    let result = z3_ternary::bool_ite(
        &t.is_y(),
        &holds_for("y"),
        &z3_ternary::bool_ite(&t.is_m(), &holds_for("m"), &holds_for("n")),
    );
    Ternary::from_prop(&result)
}

/// Constant text compared against an int/hex option's symbolic value. The
/// text failed numeric parsing, so kconfig strcmps it with the option's
/// decimal/hex rendering.
fn text_vs_number_var(text: &str, op: CompareOperator, text_on_left: bool) -> Ternary {
    match op {
        CompareOperator::Equal => Ternary::n(),
        CompareOperator::NotEqual => Ternary::y(),
        _ => {
            let letter_initial = text
                .as_bytes()
                .first()
                .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_');
            if !letter_initial {
                warn!(
                    "ordered comparison of {text} with an int/hex option is value-dependent; approximating as {text} sorting last"
                );
            }
            let ordering = match text_on_left {
                true => std::cmp::Ordering::Greater,
                false => std::cmp::Ordering::Less,
            };
            constant_result(ordering_holds(op, ordering))
        }
    }
}

/// Models `left op right` following kconfig's __expr_calc_value.
fn model_comparison(
    left: ComparisonOperand,
    op: CompareOperator,
    right: ComparisonOperand,
) -> Ternary {
    use ParsedOperand::*;
    let left = parse_comparison_operand(left);
    let right = parse_comparison_operand(right);
    match (left, right) {
        // both sides numeric:
        (Tri(a), Tri(b)) => model_ternary_comparison(&a, op, &b),
        (Tri(t), NumberLit(k)) => Ternary::from_prop(&tri_vs_number_literal(&t, op, k)),
        (NumberLit(k), Tri(t)) => {
            Ternary::from_prop(&tri_vs_number_literal(&t, flip_operator(op), k))
        }
        (Tri(t), NumberVar(v)) => model_kconfig_int_comparison(tri_as_int(&t), op, v),
        (NumberVar(v), Tri(t)) => model_kconfig_int_comparison(v, op, tri_as_int(&t)),
        (NumberLit(a), NumberLit(b)) => constant_result(ordering_holds(op, a.cmp(&b))),
        (NumberLit(a), NumberVar(v)) => model_kconfig_int_comparison(z3_int::from_i64(a), op, v),
        (NumberVar(v), NumberLit(b)) => model_kconfig_int_comparison(v, op, z3_int::from_i64(b)),
        (NumberVar(a), NumberVar(b)) => model_kconfig_int_comparison(a, op, b),

        //strcmp fallback: non-numeric constant text on either side
        (Text(a), Text(b)) => constant_result(ordering_holds(op, a.as_bytes().cmp(b.as_bytes()))),
        (Text(a), NumberLit(k)) => constant_result(ordering_holds(
            op,
            a.as_bytes().cmp(k.to_string().as_bytes()),
        )),
        (NumberLit(k), Text(b)) => constant_result(ordering_holds(
            op,
            k.to_string().as_bytes().cmp(b.as_bytes()),
        )),
        (Text(a), Tri(t)) => tri_vs_text(&t, op, &a, true),
        (Tri(t), Text(b)) => tri_vs_text(&t, op, &b, false),
        (Text(a), NumberVar(_)) => text_vs_number_var(&a, op, true),
        (NumberVar(_), Text(b)) => text_vs_number_var(&b, op, false),

        // string options:
        (TextVar(a), TextVar(b)) => model_kconfig_str_comparison(a, op, b),
        (TextVar(v), Text(t)) => {
            model_kconfig_str_comparison(v, op, z3_string::from_str(&t).unwrap())
        }
        (Text(t), TextVar(v)) => {
            model_kconfig_str_comparison(z3_string::from_str(&t).unwrap(), op, v)
        }
        (TextVar(v), Tri(t)) => {
            warn!("numeric_vs_string_symbol: string option compared with a bool/tristate");
            model_kconfig_str_comparison(v, op, tri_value_string(&t))
        }
        (Tri(t), TextVar(v)) => {
            warn!("numeric_vs_string_symbol: bool/tristate compared with a string option");
            model_kconfig_str_comparison(tri_value_string(&t), op, v)
        }
        (TextVar(v), NumberLit(k)) => {
            warn!("numeric_vs_string_symbol: string option compared with the number {k}");
            model_kconfig_str_comparison(v, op, z3_string::from_str(&k.to_string()).unwrap())
        }
        (NumberLit(k), TextVar(v)) => {
            warn!("numeric_vs_string_symbol: number {k} compared with a string option");
            model_kconfig_str_comparison(z3_string::from_str(&k.to_string()).unwrap(), op, v)
        }
        (TextVar(_), NumberVar(_)) | (NumberVar(_), TextVar(_)) => {
            warn!(
                "numeric_vs_string_symbol: comparison between a string option and an int option is approximated"
            );
            match op {
                CompareOperator::Equal => Ternary::n(),
                CompareOperator::NotEqual => Ternary::y(),
                _ => Ternary::n(),
            }
        }
    }
}

// this thing may need to return a boolean expression, but it could also be another type.
// returns a None if we don't want to handle that type of expression (caller should effectively ignore Nones)
fn model_kconfig_atom(
    symbol_table: &HashMap<String, TypeInfo>,
    expected_type: Type,
    atom: Atom,
) -> Z3Types {
    debug!("attempting to model atom: {:?}", atom);
    match atom {
        // descend the parse tree.
        // models a constant value or config option.
        Atom::Symbol(sym) => {
            let naive_z3 = model_kconfig_symbol(symbol_table, sym.clone());
            match (expected_type.clone(), naive_z3.clone()) {
                // a bool/tristate option, or a n/m/y constant, in tristate context
                (Type::Bool(_) | Type::Tristate(_), Z3Types::Ternary(t)) => Z3Types::Ternary(t),

                // kconfig parses a hex option's values in base 16 even without
                // the 0x prefix: an unprefixed constant like `default 10` on a
                // hex option is 0x10 = 16 (ConstantSymbol::Hex constants were
                // already converted from their 0x form)
                (Type::Hex(_), Z3Types::Integer(_))
                    if matches!(&sym, Symbol::Constant(ConstantSymbol::Integer(_))) =>
                {
                    let Symbol::Constant(ConstantSymbol::Integer(decimal_digits)) = &sym else {
                        unreachable!()
                    };
                    match u64::from_str_radix(&decimal_digits.to_string(), 16) {
                        Ok(reinterpreted) => Z3Types::Integer(z3_int::from_u64(reinterpreted)),
                        Err(_) => {
                            warn!(
                                "hex constant {decimal_digits} does not reparse in base 16; evaluates to 0"
                            );
                            Z3Types::Integer(z3_int::from_i64(0))
                        }
                    }
                }

                // an int/hex option, or a numeric constant, in numeric context
                (Type::Hex(_) | Type::Int(_), Z3Types::Integer(i)) => Z3Types::Integer(i),

                // a bool/tristate value — or an undefined reference, which
                // models as the constant n — in int position: kconfig cannot
                // parse it as a number, so it contributes 0. worth linting
                // when the reference is defined.
                (Type::Hex(_) | Type::Int(_), Z3Types::Ternary(_)) => {
                    warn!("bool/tristate or undefined value used in int position evaluates to 0");
                    Z3Types::Integer(z3_int::from_i64(0))
                }

                // a numeric constant in tristate context: interpret 0/1/2 as n/m/y.
                // kconfig itself evaluates any other non-bool symbol in a
                // tristate expression to n.
                (Type::Bool(_) | Type::Tristate(_), Z3Types::Integer(i)) => match i.as_i64() {
                    Some(0) => Z3Types::Ternary(Ternary::n()),
                    Some(1) if matches!(expected_type, Type::Tristate(_)) => {
                        Z3Types::Ternary(Ternary::m())
                    }
                    Some(2) => Z3Types::Ternary(Ternary::y()),
                    _ => {
                        warn!(
                            "int {} used in tristate context evaluates to n. This is probably a bug in Kconfig usage.",
                            i
                        );
                        Z3Types::Ternary(Ternary::n())
                    }
                },

                // quoted numbers: an int option's values parse in base 10, a
                // hex option's in base 16 (with or without the 0x prefix).
                (Type::Int(_), Z3Types::String(_)) => match &sym {
                    Symbol::Constant(ConstantSymbol::String(text)) => match text.parse::<i64>() {
                        Ok(parsed) => Z3Types::Integer(z3_int::from_i64(parsed)),
                        Err(_) => {
                            warn!("non-numeric value {text:?} for an int option evaluates to 0");
                            Z3Types::Integer(z3_int::from_i64(0))
                        }
                    },
                    _ => {
                        warn!("string option {sym:?} in int position evaluates to 0");
                        Z3Types::Integer(z3_int::from_i64(0))
                    }
                },
                (Type::Hex(_), Z3Types::String(_)) => match &sym {
                    Symbol::Constant(ConstantSymbol::String(text)) => {
                        match parse_hex_str_to_u64(text) {
                            Ok(parsed) => Z3Types::Integer(z3_int::from_u64(parsed)),
                            Err(_) => {
                                warn!("non-numeric value {text:?} for a hex option evaluates to 0");
                                Z3Types::Integer(z3_int::from_i64(0))
                            }
                        }
                    }
                    _ => {
                        warn!("string option {sym:?} in hex position evaluates to 0");
                        Z3Types::Integer(z3_int::from_i64(0))
                    }
                },

                (Type::String(_), Z3Types::String(s)) => Z3Types::String(s),

                // a bare numeric token on a string option is a constant
                // symbol whose text is the value (e.g. `default 64`)
                (Type::String(_), Z3Types::Integer(i)) if i.as_i64().is_some() => {
                    let text = i.as_i64().expect("checked above").to_string();
                    Z3Types::String(z3_string::from_str(&text).unwrap())
                }

                // cross-type references in string position are rejected
                (Type::String(_), _) => {
                    warn!("non-string value in string position evaluates to \"\"");
                    Z3Types::String(z3_string::from_str("").unwrap())
                }
                // a quoted y/m/n in bool/tristate position (a quoted "m" on a
                // bool is later corrected by the option-level clamp)
                (Type::Bool(_) | Type::Tristate(_), Z3Types::String(_)) => match &sym {
                    Symbol::Constant(ConstantSymbol::String(text)) => {
                        match tristate_constant_from_str(text) {
                            Some(t) => Z3Types::Ternary(t),
                            None => {
                                warn!(
                                    "non-tristate text {text:?} in bool/tristate position evaluates to n"
                                );
                                Z3Types::Ternary(Ternary::n())
                            }
                        }
                    }
                    _ => {
                        warn!("string option {sym:?} in bool/tristate position evaluates to n");
                        Z3Types::Ternary(Ternary::n())
                    }
                },
                (
                    Type::DefString(_)
                    | Type::DefBool(_)
                    | Type::DefHex(_)
                    | Type::DefInt(_)
                    | Type::DefTristate(_),
                    _,
                ) => unreachable!("def_* should have been desugared..."),
                _ => panic!(
                    "Type error: expected type: {:?} for symbol {:?} ",
                    expected_type, naive_z3
                ),
            }
        }

        // some sort of expression
        Atom::Parenthesis(parens_expr) => {
            return model_kconfig_or_expr(symbol_table, expected_type, *parens_expr);
        }

        Atom::Compare(compare) => {
            let left = match compare.left {
                CompareOperand::Symbol(sym) => model_comparison_operand(symbol_table, sym),
                CompareOperand::Macro(_) => {
                    warn!("comparison contains a macro: the result is an unknown y/n value");
                    return Z3Types::Ternary(Ternary::from_prop(&z3_bool::fresh_const(
                        "macro_cmp",
                    )));
                }
            };
            let right = match compare.right {
                CompareOperand::Symbol(sym) => model_comparison_operand(symbol_table, sym),
                CompareOperand::Macro(_) => {
                    warn!("comparison contains a macro: the result is an unknown y/n value");
                    return Z3Types::Ternary(Ternary::from_prop(&z3_bool::fresh_const(
                        "macro_cmp",
                    )));
                }
            };
            return Z3Types::Ternary(model_comparison(left, compare.operator, right));
        }
        _ => {
            warn!("not handling functions/macros: the value is an unknown of the expected type");
            return unknown_value(&expected_type);
        }
    }
}

/// The value of an expression we cannot evaluate.
/// Create unconstrained variable of the expected type.
fn unknown_value(expected_type: &Type) -> Z3Types {
    match expected_type {
        Type::String(_) | Type::DefString(_) => {
            Z3Types::String(z3_string::fresh_const("macro_str"))
        }
        Type::Int(_) | Type::Hex(_) | Type::DefInt(_) | Type::DefHex(_) => {
            Z3Types::Integer(z3_int::fresh_const("macro_int"))
        }

        Type::Bool(_) | Type::DefBool(_) => {
            Z3Types::Ternary(Ternary::from_prop(&z3_bool::fresh_const("macro_bool")))
        }

        Type::Tristate(_) | Type::DefTristate(_) => {
            let ge_m_extra = z3_bool::fresh_const("macro_tri");
            let ge_y = z3_bool::fresh_const("macro_tri");
            Z3Types::Ternary(Ternary {
                ge_m: z3_ternary::bool_or(&ge_m_extra, &ge_y),
                ge_y,
            })
        }
    }
}

/// Converts symbols (both constants and config option identifiers) from Kconfig to Z3.
/// This is modeling the leaves of the parse tree.
/// - For config options, this uses Z3 variables (an instance of Z3Types)
/// - For constants:
///   1. Strings are strings
///   2. Ints and Hex are integers
///   3. Tristates and booleans are order-encoded pairs of booleans.
///
/// NOTE: this will retrieve type information from the symbol table for config option identifiers.
///       Expects all symbols to have been inserted into the symbol table already.
fn model_kconfig_symbol(symbol_table: &HashMap<String, TypeInfo>, sym: Symbol) -> Z3Types {
    match sym {
        // symbol is a constant value (e.g. "n")
        Symbol::Constant(c) => return model_kconfig_constant(c),
        // symbol is another kconfig option
        Symbol::NonConstant(val) => {
            return model_kconfig_identifier(symbol_table, &val);
        }
    }
}

/// Model a constant value as a Z3 value.
/// NOTE: booleans and tristates are order-encoded pairs; hex is an integer.
fn model_kconfig_constant(c: ConstantSymbol) -> Z3Types {
    match c {
        ConstantSymbol::Integer(i) => Z3Types::Integer(z3_int::from_i64(i)),
        ConstantSymbol::Hex(h) => match parse_hex_str_to_u64(&h) {
            Ok(hex_as_u64) => Z3Types::Integer(z3_int::from_u64(hex_as_u64)),
            Err(_) => {
                warn!("unparseable hex constant {h}; evaluates to 0");
                Z3Types::Integer(z3_int::from_i64(0))
            }
        },
        ConstantSymbol::String(s) => {
            // we're going to naively construct a string here, but higher up the tree we may need to convert it to one of the other types (int?)...
            Z3Types::String(z3_string::from_str(&s).unwrap())
        }
        ConstantSymbol::Boolean(b) => match b {
            true => Z3Types::Ternary(Ternary::y()),
            // boolean doesn't support m
            false => Z3Types::Ternary(Ternary::n()),
        },
        ConstantSymbol::Tristate(t) => match t {
            Tristate::No => Z3Types::Ternary(Ternary::n()),
            Tristate::Yes => Z3Types::Ternary(Ternary::y()),
            Tristate::Module => Z3Types::Ternary(Ternary::m()),
        },
    }
}

/// Models one side of a comparison.
/// NOTE: kconfig gives an undefined symbol its own name as its string value.
fn model_comparison_operand(
    symbol_table: &HashMap<String, TypeInfo>,
    sym: Symbol,
) -> ComparisonOperand {
    match sym {
        // a quoted constant keeps its raw text; whether it compares as a
        // number or as a string is decided by parse_comparison_operand
        Symbol::Constant(ConstantSymbol::String(text)) => ComparisonOperand::ConstantText(text),
        Symbol::Constant(c) => ComparisonOperand::Known(model_kconfig_constant(c)),
        Symbol::NonConstant(name) => match symbol_table.get(&name) {
            Some(info) => match info.z3_type.clone() {
                Some(z3t) => ComparisonOperand::Known(z3t),
                None => todo!(
                    "the config option has no type in the symbol table (assume boolean? check the source.)"
                ),
            },
            None => {
                debug!(
                    "comparison references undefined option {name}: it evaluates as the text {name:?}"
                );
                ComparisonOperand::Undefined(name)
            }
        },
    }
}

/// Retrieves the Z3 variable for the Kconfig identifier from the symbol table.
/// If the config option doesn't exist, it evaluates to the constant `n`
/// (logged for auditing, per the spec).
fn model_kconfig_identifier(symbol_table: &HashMap<String, TypeInfo>, sym: &str) -> Z3Types {
    match symbol_table.get(sym) {
        None => {
            // NOTE: there are some kconfig variables that don't have definitions (these are dangling references)
            // a reference to an undefined option evaluates to n
            debug!("reference to undefined option {} evaluates to n", sym);
            return Z3Types::Ternary(Ternary::n());
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

/// May need to model just a single variable, so this may be e.g. a z3 String.
/// Checks the `or_expr` using the `expected_type` (the type of the config option)
pub fn model_kconfig_or_expr(
    symbol_table: &HashMap<String, TypeInfo>,
    expected_type: Type,
    or_expr: OrExpression,
) -> Z3Types {
    debug!("attempting to model or expression: {:?}", or_expr);
    match or_expr {
        OrExpression::Term(term) => {
            return model_kconfig_and_expr(symbol_table, expected_type, term);
        }
        OrExpression::Expression(or_expr) => {
            return Z3Types::Ternary(model_kconfig_and_exprs(
                symbol_table,
                expected_type,
                or_expr,
            ));
        }
    }
}

/// Models a Kconfig OR expression as an order-encoded pair (componentwise
/// disjunction, i.e. the tristate `max`).
pub fn model_kconfig_and_exprs(
    symbol_table: &HashMap<String, TypeInfo>,
    expected_type: Type,
    or_expr: Vec<AndExpression>,
) -> Ternary {
    let operands: Vec<Ternary> = or_expr
        .into_iter()
        .map(|and_expr| {
            model_kconfig_and_expr(symbol_table, expected_type.clone(), and_expr)
                .try_into()
                .unwrap()
        })
        .collect();

    // componentwise OR (smt equivalent of the tristate max)
    return z3_ternary::or(&operands);
}

/// Models a Kconfig AND expression as one of two cases:
/// 1. an order-encoded pair if the expression has multiple nom-kconfig `term`s,
/// 2. an SMT variable if the expression has only one nom-kconfig `term`.
pub fn model_kconfig_and_expr(
    symbol_table: &HashMap<String, TypeInfo>,
    expected_type: Type,
    and_expr: AndExpression,
) -> Z3Types {
    return match and_expr {
        // this not really an AND. it is case 1
        AndExpression::Term(term) => model_kconfig_term(symbol_table, expected_type, term),
        // this is a true AND. it is case 2
        AndExpression::Expression(terms) => {
            let and_terms: Vec<Ternary> = terms
                .into_iter()
                .map(|term| {
                    model_kconfig_term(symbol_table, expected_type.clone(), term)
                        .try_into()
                        .unwrap()
                })
                .collect();
            // DEPENDS ON FOO
            // componentwise AND (smt equivalent of the tristate min)
            return Z3Types::Ternary(z3_ternary::and(&and_terms));
        }
    };
}

/// Look up a Kconfig identifier in our symbol table.
/// Returns `None` when the identifier doesn't exist. Note that, for Linux, this config option may
/// only be defined in a different architecture, or it may be a dangling reference.
fn model_kconfig_term(
    symbol_table: &HashMap<String, TypeInfo>,
    expected_type: Type,
    term: nom_kconfig::attribute::Term,
) -> Z3Types {
    debug!("attempting to model term: {:?}", term);
    // nom-kconfig terms can be identifier, or !identifier
    match term {
        // just return the symbol table entry, if it's not NOT'd
        nom_kconfig::attribute::Term::Atom(a) => {
            return model_kconfig_atom(symbol_table, expected_type, a);
        }

        nom_kconfig::attribute::Term::Not(n) => {
            let modeled = model_kconfig_atom(symbol_table, expected_type, n);
            // !e is ⟨¬e₂, ¬e₁⟩ on pairs (2 - v in the integer model)
            let pair: Ternary = modeled
                .try_into()
                .expect("NOT only used for bools, tristates, expressions");
            return Z3Types::Ternary(z3_ternary::not(&pair));
        }
    }
}

/// Models an int value expression for a default value of an int/hex option:
/// an integer constant (hex converted to base 10)
/// or a reference to another int/hex option.
/// Anything non-numeric evaluates to 0 and is logged.
pub fn model_int_value_expr(
    symbol_table: &HashMap<String, TypeInfo>,
    expected_type: Type,
    expr: OrExpression,
) -> z3_int {
    match model_kconfig_or_expr(symbol_table, expected_type, expr) {
        Z3Types::Integer(i) => i,
        other => {
            warn!("non-numeric value {other:?} in int position evaluates to 0");
            z3_int::from_i64(0)
        }
    }
}

/// Models a string value expression for a default of a string option:
/// a quoted literal or a reference to another defined string option.
/// Anything else is rejected and set "" with a lint.
pub fn model_string_value_expr(
    symbol_table: &HashMap<String, TypeInfo>,
    expr: OrExpression,
) -> z3_string {
    match model_kconfig_or_expr(symbol_table, Type::String(None), expr) {
        Z3Types::String(s) => s,
        other => {
            warn!("non-string value {other:?} in string-default position evaluates to \"\"");
            z3_string::from_str("").unwrap()
        }
    }
}

/// Models a range bound: an integer or hex constant, or a reference to another int/hex option.
/// On a hex option, kconfig parses unprefixed constant bounds in base 16, so `is_hex` reinterprets them.
/// Undefined references evaluate to 0 (logged).
pub fn model_int_bound(
    symbol_table: &HashMap<String, TypeInfo>,
    bound: &RangeBound,
    is_hex: bool,
) -> z3_int {
    match bound {
        RangeBound::Number(decimal_digits) if is_hex => {
            match u64::from_str_radix(&decimal_digits.to_string(), 16) {
                Ok(reinterpreted) => z3_int::from_u64(reinterpreted),
                Err(_) => {
                    warn!(
                        "hex range bound {decimal_digits} does not reparse in base 16; evaluates to 0"
                    );
                    z3_int::from_i64(0)
                }
            }
        }
        RangeBound::Number(value) => z3_int::from_i64(*value),
        RangeBound::Hex(text) => match parse_hex_str_to_u64(text) {
            Ok(value) => z3_int::from_u64(value),
            Err(_) => {
                warn!("unparseable hex range bound {text}; evaluates to 0");
                z3_int::from_i64(0)
            }
        },
        RangeBound::Symbol(name) => {
            match symbol_table.get(name).and_then(|info| info.z3_type.clone()) {
                Some(Z3Types::Integer(value)) => value,
                Some(_) => {
                    warn!("range bound {name} is not an int/hex option; evaluates to 0");
                    z3_int::from_i64(0)
                }
                None => {
                    warn!("range bound references undefined option {name}; evaluates to 0");
                    z3_int::from_i64(0)
                }
            }
        }
        RangeBound::Variable(name) => {
            warn!("range bound ${name} (macro) is not modeled; evaluates to 0");
            z3_int::from_i64(0)
        }
    }
}

/// Helper function for converting a Kconfig `hex` constant to Rust's u64,
/// intended for later conversion to an SMT integer.
/// Unsigned, like kconfig's own strtoull-based hex parsing: values up to 0xffffffffffffffff are legal
/// (e.g. `default 0xdead000000000000` on x86's ILLEGAL_POINTER_VALUE).
fn parse_hex_str_to_u64(s: &str) -> Result<u64, ParseIntError> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(s, 16)
}

/// Parses text as a number the way kconfig's expr_parse_string does for untyped operands:
/// `strtoll` base 0: `0x` hex, a leading `0` octal, otherwise decimal, with an optional sign, and the whole text must be consumed.
/// Returns `None` when the text is not a number, kconfig then falls back to comparing with strcmp.
fn kconfig_parse_number(text: &str) -> Option<i64> {
    let (negative, magnitude) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    // exactly one optional sign, then digits (this also rejects the empty string)
    if !magnitude.as_bytes().first()?.is_ascii_digit() {
        return None;
    }
    let value = if let Some(hex) = magnitude
        .strip_prefix("0x")
        .or_else(|| magnitude.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).ok()?
    } else if magnitude.len() > 1 && magnitude.starts_with('0') {
        i64::from_str_radix(&magnitude[1..], 8).ok()?
    } else {
        magnitude.parse::<i64>().ok()?
    };
    Some(if negative { -value } else { value })
}

/// NOTE: tests are AI slop I generated after I got everything working.
/// TODO: review these more carefully and consider handwritten tests.
#[cfg(test)]
mod tests {
    use super::*;
    use nom_kconfig::attribute::CompareOperator;
    use nom_kconfig::attribute::expression::CompareExpression;
    use z3::{SatResult, Solver};

    #[test]
    fn kconfig_parse_number_follows_strtoll_base_0() {
        assert_eq!(kconfig_parse_number("42"), Some(42));
        assert_eq!(kconfig_parse_number("0"), Some(0));
        assert_eq!(kconfig_parse_number("0x1F"), Some(31));
        assert_eq!(kconfig_parse_number("-4"), Some(-4));
        // strtoll base 0 reads a leading 0 as octal
        assert_eq!(kconfig_parse_number("010"), Some(8));
        assert_eq!(kconfig_parse_number("08"), None);
        // the whole text must be consumed
        assert_eq!(kconfig_parse_number("104_QUAD_8"), None);
        assert_eq!(kconfig_parse_number("NR_CPUS"), None);
        assert_eq!(kconfig_parse_number("hello"), None);
        assert_eq!(kconfig_parse_number(""), None);
        assert_eq!(kconfig_parse_number("-"), None);
    }

    fn symbol_table_with(name: &str, z3_type: Z3Types) -> HashMap<String, TypeInfo> {
        let mut table = HashMap::new();
        table.insert(
            name.to_string(),
            TypeInfo {
                kconfig_type: None,
                z3_type: Some(z3_type),
                selected_by: HashMap::new(),
                implied_by: HashMap::new(),
                attribute_defs: HashMap::new(),
            },
        );
        table
    }

    fn int_symbol_table(name: &str) -> (HashMap<String, TypeInfo>, z3_int) {
        let var = z3_int::new_const(name);
        let table = symbol_table_with(name, Z3Types::Integer(var.clone()));
        (table, var)
    }

    /// `depends on PANEL_PROFILE="0"` (drivers/auxdisplay/Kconfig) compares an
    /// int-typed option against a quoted number; it must model as a numeric comparison.
    #[test]
    fn int_symbol_vs_quoted_int_constant() {
        let (table, panel_profile) = int_symbol_table("PANEL_PROFILE");
        let atom = Atom::Compare(CompareExpression {
            left: CompareOperand::Symbol(Symbol::NonConstant("PANEL_PROFILE".to_string())),
            operator: CompareOperator::Equal,
            right: CompareOperand::Symbol(Symbol::Constant(ConstantSymbol::String(
                "0".to_string(),
            ))),
        });

        let modeled: Ternary = model_kconfig_atom(&table, Type::Int(None), atom)
            .try_into()
            .unwrap();

        // satisfiable when the option is 0...
        let solver = Solver::new();
        solver.assert(modeled.is_y());
        solver.assert(panel_profile.clone().eq(z3_int::from_i64(0)));
        assert_eq!(solver.check(), SatResult::Sat);

        // ...and unsatisfiable when it is not
        let solver = Solver::new();
        solver.assert(modeled.is_y());
        solver.assert(panel_profile.eq(z3_int::from_i64(5)));
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    /// Same as above with the operands flipped, exercising the (String, Integer) arm.
    #[test]
    fn quoted_int_constant_vs_int_symbol() {
        let (table, panel_profile) = int_symbol_table("PANEL_PROFILE");
        let atom = Atom::Compare(CompareExpression {
            left: CompareOperand::Symbol(Symbol::Constant(ConstantSymbol::String("0".to_string()))),
            operator: CompareOperator::NotEqual,
            right: CompareOperand::Symbol(Symbol::NonConstant("PANEL_PROFILE".to_string())),
        });

        let modeled: Ternary = model_kconfig_atom(&table, Type::Int(None), atom)
            .try_into()
            .unwrap();

        let solver = Solver::new();
        solver.assert(modeled.is_y());
        solver.assert(panel_profile.eq(z3_int::from_i64(0)));
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    /// `FOO = m` on a tristate option models as the pair equality
    /// (e₁↔f₁) ∧ (e₂↔f₂) and forces FOO's two variables to ⟨⊤,⊥⟩.
    #[test]
    fn tristate_symbol_vs_tristate_constant() {
        let (foo, ladder) = z3_ternary::new_tristate("FOO");
        let table = symbol_table_with("FOO", Z3Types::Ternary(foo.clone()));
        let atom = Atom::Compare(CompareExpression {
            left: CompareOperand::Symbol(Symbol::NonConstant("FOO".to_string())),
            operator: CompareOperator::Equal,
            right: CompareOperand::Symbol(Symbol::Constant(ConstantSymbol::Tristate(
                Tristate::Module,
            ))),
        });

        let modeled: Ternary = model_kconfig_atom(&table, Type::Tristate(None), atom)
            .try_into()
            .unwrap();

        // FOO = m and the comparison holding is satisfiable...
        let solver = Solver::new();
        solver.assert(&ladder);
        solver.assert(modeled.is_y());
        solver.assert(foo.is_m());
        assert_eq!(solver.check(), SatResult::Sat);

        // ...but FOO = y contradicts it
        let solver = Solver::new();
        solver.assert(&ladder);
        solver.assert(modeled.is_y());
        solver.assert(foo.is_y());
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    /// `!FOO && BAR` models as ⟨¬FOO₂ ∧ BAR₁, ¬FOO₁ ∧ BAR₂⟩; with FOO = m and
    /// BAR = y the result is m (the integer model's min(2-1, 2) = 1).
    #[test]
    fn not_and_expression_evaluates_like_integer_model() {
        use nom_kconfig::attribute::Term;

        let (foo, foo_ladder) = z3_ternary::new_tristate("FOO");
        let (bar, bar_ladder) = z3_ternary::new_tristate("BAR");
        let mut table = symbol_table_with("FOO", Z3Types::Ternary(foo.clone()));
        table.extend(symbol_table_with("BAR", Z3Types::Ternary(bar.clone())));

        let expr = OrExpression::Term(AndExpression::Expression(vec![
            Term::Not(Atom::Symbol(Symbol::NonConstant("FOO".to_string()))),
            Term::Atom(Atom::Symbol(Symbol::NonConstant("BAR".to_string()))),
        ]));

        let modeled: Ternary = model_kconfig_or_expr(&table, Type::Tristate(None), expr)
            .try_into()
            .unwrap();

        let solver = Solver::new();
        solver.assert(&foo_ladder);
        solver.assert(&bar_ladder);
        solver.assert(foo.is_m());
        solver.assert(bar.is_y());
        solver.assert(modeled.is_m());
        assert_eq!(solver.check(), SatResult::Sat);

        let solver = Solver::new();
        solver.assert(&foo_ladder);
        solver.assert(&bar_ladder);
        solver.assert(foo.is_m());
        solver.assert(bar.is_y());
        solver.assert(modeled.is_y());
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    fn compare_atom(left: Symbol, op: CompareOperator, right: Symbol) -> Atom {
        Atom::Compare(CompareExpression {
            left: CompareOperand::Symbol(left),
            operator: op,
            right: CompareOperand::Symbol(right),
        })
    }

    fn sym_ref(name: &str) -> Symbol {
        Symbol::NonConstant(name.to_string())
    }

    /// `depends on NR_CPUS >= 4` (mm/Kconfig) on an arch that never defines
    /// NR_CPUS (e.g. m68k, which has no SMP): kconfig gives the undefined
    /// symbol its own name as its string value, numeric parsing of the name
    /// fails, and the comparison falls back to strcmp("NR_CPUS", "4") — the
    /// name sorts after the number, so >= is y and <= is n.
    #[test]
    fn undefined_symbol_vs_number_compares_by_name() {
        let table = HashMap::new();
        let modeled = |op, k| -> Option<u8> {
            let atom = compare_atom(
                sym_ref("NR_CPUS"),
                op,
                Symbol::Constant(ConstantSymbol::Integer(k)),
            );
            let pair: Ternary = model_kconfig_atom(&table, Type::Tristate(None), atom)
                .try_into()
                .unwrap();
            pair.as_const()
        };

        assert_eq!(modeled(CompareOperator::GreaterOrEqual, 4), Some(2));
        assert_eq!(modeled(CompareOperator::GreaterThan, 4), Some(2));
        // lib/Kconfig.debug's `default y if NR_CPUS <= 128`
        assert_eq!(modeled(CompareOperator::LowerOrEqual, 128), Some(0));
        assert_eq!(modeled(CompareOperator::LowerThan, 128), Some(0));
        assert_eq!(modeled(CompareOperator::Equal, 4), Some(0));
        assert_eq!(modeled(CompareOperator::NotEqual, 4), Some(2));
    }

    /// A defined bool/tristate against a number is numeric: "n"/"m"/"y" parse
    /// as 0/1/2 (expr_parse_string), so comparing with 4 is constant and
    /// comparing with 0..2 is a threshold test on the pair.
    #[test]
    fn tristate_vs_number_is_numeric() {
        let (foo, ladder) = z3_ternary::new_tristate("TVN_FOO");
        let table = symbol_table_with("TVN_FOO", Z3Types::Ternary(foo.clone()));
        let modeled = |op, k| -> Ternary {
            let atom = compare_atom(
                sym_ref("TVN_FOO"),
                op,
                Symbol::Constant(ConstantSymbol::Integer(k)),
            );
            model_kconfig_atom(&table, Type::Tristate(None), atom)
                .try_into()
                .unwrap()
        };

        // 0/1/2 can never reach 4
        assert_eq!(
            modeled(CompareOperator::GreaterOrEqual, 4).as_const(),
            Some(0)
        );
        assert_eq!(modeled(CompareOperator::LowerThan, 4).as_const(), Some(2));
        assert_eq!(modeled(CompareOperator::Equal, 4).as_const(), Some(0));

        // TVN_FOO >= 1 is exactly the pair's "≥ m" component
        assert_eq!(modeled(CompareOperator::GreaterOrEqual, 1).ge_m, foo.ge_m);

        // TVN_FOO = 2 is exactly TVN_FOO = y
        let equals_two = modeled(CompareOperator::Equal, 2);
        let solver = Solver::new();
        solver.assert(&ladder);
        solver.assert(equals_two.is_y());
        solver.assert(foo.is_m());
        assert_eq!(solver.check(), SatResult::Unsat);

        let equals_two = modeled(CompareOperator::Equal, 2);
        let solver = Solver::new();
        solver.assert(&ladder);
        solver.assert(equals_two.is_y());
        solver.assert(foo.is_y());
        assert_eq!(solver.check(), SatResult::Sat);
    }

    /// An undefined symbol against a defined tristate strcmps the name with
    /// the value string "n"/"m"/"y": never equal, and an uppercase name sorts
    /// before all three whatever the value, so the results are constant.
    #[test]
    fn undefined_symbol_vs_tristate_compares_name_with_value_string() {
        let (foo, _ladder) = z3_ternary::new_tristate("UVT_FOO");
        let table = symbol_table_with("UVT_FOO", Z3Types::Ternary(foo));
        let modeled = |op| -> Option<u8> {
            let atom = compare_atom(sym_ref("UNDEFINED_OPT"), op, sym_ref("UVT_FOO"));
            let pair: Ternary = model_kconfig_atom(&table, Type::Tristate(None), atom)
                .try_into()
                .unwrap();
            pair.as_const()
        };

        assert_eq!(modeled(CompareOperator::Equal), Some(0));
        assert_eq!(modeled(CompareOperator::NotEqual), Some(2));
        assert_eq!(modeled(CompareOperator::LowerThan), Some(2));
        assert_eq!(modeled(CompareOperator::GreaterThan), Some(0));
    }

    /// Two undefined symbols compare their names; the same name is the same
    /// symbol, so it compares equal to itself.
    #[test]
    fn undefined_vs_undefined_compares_names() {
        let table = HashMap::new();
        let modeled = |left: &str, op, right: &str| -> Option<u8> {
            let atom = compare_atom(sym_ref(left), op, sym_ref(right));
            let pair: Ternary = model_kconfig_atom(&table, Type::Tristate(None), atom)
                .try_into()
                .unwrap();
            pair.as_const()
        };

        assert_eq!(modeled("AAA", CompareOperator::Equal, "BBB"), Some(0));
        assert_eq!(modeled("AAA", CompareOperator::NotEqual, "BBB"), Some(2));
        assert_eq!(modeled("AAA", CompareOperator::LowerThan, "BBB"), Some(2));
        assert_eq!(modeled("SAME", CompareOperator::Equal, "SAME"), Some(2));
    }

    /// IE values (int_constraints.md §2): constants (hex converted to base
    /// 10), unprefixed constants on hex options reinterpreted in base 16,
    /// int-option references, and undefined references evaluating to 0.
    #[test]
    fn int_value_expressions_and_range_bounds() {
        use nom_kconfig::attribute::Term;

        let (table, int_var) = int_symbol_table("IE_INT");

        let constant_expr = |c: ConstantSymbol| {
            OrExpression::Term(AndExpression::Term(Term::Atom(Atom::Symbol(
                Symbol::Constant(c),
            ))))
        };
        let reference_expr = |name: &str| {
            OrExpression::Term(AndExpression::Term(Term::Atom(Atom::Symbol(
                Symbol::NonConstant(name.to_string()),
            ))))
        };

        let modeled = model_int_value_expr(
            &table,
            Type::Int(None),
            constant_expr(ConstantSymbol::Integer(42)),
        );
        assert_eq!(modeled.as_i64(), Some(42));

        // a 0x-prefixed hex constant converts to base 10
        let modeled = model_int_value_expr(
            &table,
            Type::Hex(None),
            constant_expr(ConstantSymbol::Hex("0x1F".to_string())),
        );
        assert_eq!(modeled.as_i64(), Some(31));

        // an unprefixed constant on a hex option parses in base 16 (kconfig
        // reads hex values with strtoull base 16 regardless of prefix)
        let modeled = model_int_value_expr(
            &table,
            Type::Hex(None),
            constant_expr(ConstantSymbol::Integer(10)),
        );
        assert_eq!(modeled.as_i64(), Some(16));

        // a reference to a defined int option is its variable
        let modeled = model_int_value_expr(&table, Type::Int(None), reference_expr("IE_INT"));
        assert_eq!(modeled, int_var);

        // an undefined reference evaluates to 0
        let modeled = model_int_value_expr(&table, Type::Int(None), reference_expr("IE_MISSING"));
        assert_eq!(modeled.as_i64(), Some(0));

        // range bounds follow the same rules
        assert_eq!(
            model_int_bound(&table, &RangeBound::Number(12), false).as_i64(),
            Some(12)
        );
        assert_eq!(
            model_int_bound(&table, &RangeBound::Number(20), true).as_i64(),
            Some(32) // "20" in base 16
        );
        assert_eq!(
            model_int_bound(&table, &RangeBound::Hex("0xFF".to_string()), true).as_i64(),
            Some(255)
        );
        assert_eq!(
            model_int_bound(&table, &RangeBound::Symbol("IE_INT".to_string()), false),
            int_var
        );
        assert_eq!(
            model_int_bound(&table, &RangeBound::Symbol("IE_MISSING".to_string()), false).as_i64(),
            Some(0)
        );
    }

    /// SE values (string_constraints.md §7): literals, string-option refs,
    /// bare numeric tokens as their literal text, and everything else
    /// rejected to "".
    #[test]
    fn string_value_expressions() {
        use nom_kconfig::attribute::Term;

        let string_var = z3_string::new_const("SE_STR");
        let mut table = symbol_table_with("SE_STR", Z3Types::String(string_var.clone()));
        table.extend(symbol_table_with(
            "SE_INT",
            Z3Types::Integer(z3_int::new_const("SE_INT")),
        ));

        let constant_expr = |c: ConstantSymbol| {
            OrExpression::Term(AndExpression::Term(Term::Atom(Atom::Symbol(
                Symbol::Constant(c),
            ))))
        };
        let reference_expr = |name: &str| {
            OrExpression::Term(AndExpression::Term(Term::Atom(Atom::Symbol(
                Symbol::NonConstant(name.to_string()),
            ))))
        };

        // a quoted literal is itself
        let modeled = model_string_value_expr(
            &table,
            constant_expr(ConstantSymbol::String("firmware.bin".to_string())),
        );
        assert_eq!(modeled.as_string().as_deref(), Some("firmware.bin"));

        // a bare numeric token is a constant symbol whose text is the value
        let modeled = model_string_value_expr(&table, constant_expr(ConstantSymbol::Integer(64)));
        assert_eq!(modeled.as_string().as_deref(), Some("64"));

        // a reference to a defined string option is its variable
        let modeled = model_string_value_expr(&table, reference_expr("SE_STR"));
        assert_eq!(modeled, string_var);

        // cross-type and undefined references are rejected to ""
        let modeled = model_string_value_expr(&table, reference_expr("SE_INT"));
        assert_eq!(modeled.as_string().as_deref(), Some(""));
        let modeled = model_string_value_expr(&table, reference_expr("SE_MISSING"));
        assert_eq!(modeled.as_string().as_deref(), Some(""));
    }

    /// String comparisons (§2′ static mode): equality and lexicographic
    /// ordering against literals, and the SV bridge for tristate operands.
    #[test]
    fn string_option_comparisons() {
        let string_var = z3_string::new_const("SC_STR");
        let mut table = symbol_table_with("SC_STR", Z3Types::String(string_var.clone()));
        let (tri, ladder) = z3_ternary::new_tristate("SC_TRI");
        table.extend(symbol_table_with("SC_TRI", Z3Types::Ternary(tri.clone())));

        let modeled = |op, right: Symbol| -> Ternary {
            let atom = compare_atom(sym_ref("SC_STR"), op, right);
            model_kconfig_atom(&table, Type::Tristate(None), atom)
                .try_into()
                .unwrap()
        };
        let quoted = |s: &str| Symbol::Constant(ConstantSymbol::String(s.to_string()));

        // SC_STR = "x86" is satisfied exactly when the variable holds "x86"
        let equals = modeled(CompareOperator::Equal, quoted("x86"));
        let solver = Solver::new();
        solver.assert(equals.is_y());
        solver.assert(string_var.eq(z3_string::from_str("x86").unwrap()));
        assert_eq!(solver.check(), SatResult::Sat);

        let equals = modeled(CompareOperator::Equal, quoted("x86"));
        let solver = Solver::new();
        solver.assert(equals.is_y());
        solver.assert(string_var.eq(z3_string::from_str("arm").unwrap()));
        assert_eq!(solver.check(), SatResult::Unsat);

        // lexicographic ordering: "abc" < "abd"
        let less = modeled(CompareOperator::LowerThan, quoted("abd"));
        let solver = Solver::new();
        solver.assert(less.is_y());
        solver.assert(string_var.eq(z3_string::from_str("abc").unwrap()));
        assert_eq!(solver.check(), SatResult::Sat);

        // SV bridge: SC_STR = SC_TRI compares against "n"/"m"/"y"
        let equals_tri = modeled(CompareOperator::Equal, sym_ref("SC_TRI"));
        let solver = Solver::new();
        solver.assert(&ladder);
        solver.assert(equals_tri.is_y());
        solver.assert(tri.is_m());
        solver.assert(string_var.eq(z3_string::from_str("m").unwrap()));
        assert_eq!(solver.check(), SatResult::Sat);

        let equals_tri = modeled(CompareOperator::Equal, sym_ref("SC_TRI"));
        let solver = Solver::new();
        solver.assert(&ladder);
        solver.assert(equals_tri.is_y());
        solver.assert(tri.is_y());
        solver.assert(string_var.eq(z3_string::from_str("m").unwrap()));
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    /// A quoted "m" against a tristate goes through the strcmp path and lands
    /// exactly on `is_m` (strcmp with "m" is 0 only for the value m).
    #[test]
    fn tristate_vs_quoted_tristate_string() {
        let (foo, ladder) = z3_ternary::new_tristate("QTS_FOO");
        let table = symbol_table_with("QTS_FOO", Z3Types::Ternary(foo.clone()));
        let atom = compare_atom(
            sym_ref("QTS_FOO"),
            CompareOperator::Equal,
            Symbol::Constant(ConstantSymbol::String("m".to_string())),
        );
        let modeled: Ternary = model_kconfig_atom(&table, Type::Tristate(None), atom)
            .try_into()
            .unwrap();

        let solver = Solver::new();
        solver.assert(&ladder);
        solver.assert(modeled.is_y());
        solver.assert(foo.is_m());
        assert_eq!(solver.check(), SatResult::Sat);

        let solver = Solver::new();
        solver.assert(&ladder);
        solver.assert(modeled.is_y());
        solver.assert(foo.is_y());
        assert_eq!(solver.check(), SatResult::Unsat);
    }
}
