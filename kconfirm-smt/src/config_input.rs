//! For differential testing:
//! Read an external .config (e.g. from `make randconfig`) and assert its values as constraints.
//! Every configuration kconfig produces should must satisfy our model, so `check()` after
//! asserting the file's values must be Sat.

use kconfirm_lib::{TypeInfo, Z3Types};
use log::warn;
use std::collections::HashMap;
use std::str::FromStr;
use z3::Solver;
use z3::ast::Int as z3_int;
use z3::ast::String as z3_string;

use crate::assert_tracked;

/// A value read from a .config line.
#[derive(Debug, PartialEq)]
pub enum ConfigValue {
    /// `y`/`m`, or `n` from a `# CONFIG_X is not set` line: 0 = n, 1 = m, 2 = y.
    Tristate(u8),
    /// An unquoted number (decimal for int options, `0x`-prefixed for hex),
    /// kept as raw text so the base is decided by its form.
    Number(String),
    /// A quoted string, unescaped.
    Text(String),
}

/// Parses the lines of a .config into (symbol, value) pairs.
pub fn parse_dot_config(text: &str) -> Vec<(String, ConfigValue)> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim();

        // "# CONFIG_X is not set" records the explicit user value n
        if let Some(rest) = line.strip_prefix("# CONFIG_") {
            if let Some(symbol) = rest.strip_suffix(" is not set") {
                entries.push((symbol.to_string(), ConfigValue::Tristate(0)));
            }
            continue;
        }

        let Some(assignment) = line.strip_prefix("CONFIG_") else {
            continue;
        };
        let Some((symbol, raw_value)) = assignment.split_once('=') else {
            warn!("malformed .config line skipped: {line}");
            continue;
        };

        let value = if let Some(quoted) = raw_value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
        {
            ConfigValue::Text(unescape(quoted))
        } else {
            match raw_value {
                "y" => ConfigValue::Tristate(2),
                "m" => ConfigValue::Tristate(1),
                "n" => ConfigValue::Tristate(0),
                _ => ConfigValue::Number(raw_value.to_string()),
            }
        };
        entries.push((symbol.to_string(), value));
    }
    entries
}

/// Reverses the writer's escaping: `\"` and `\\` (any other escaped byte is taken literally).
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(escaped) = chars.next() {
                out.push(escaped);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Metrics of what `assert_config_inputs` did with the file's entries.
#[derive(Debug, Default)]
pub struct InputSummary {
    /// Values asserted as constraints.
    pub asserted: usize,
    /// Symbols not in the symbol table.
    pub unknown_symbols: usize,
    /// Entries whose value form does not fit the symbol's modeled type, and
    /// numbers that failed to parse.
    pub mismatched: usize,
}

/// Asserts every (symbol, value) pair against the corresponding model
/// variable, each tracked as `input:SYMBOL` so an unsat core (debug feature)
/// names the conflicting inputs.
pub fn assert_config_inputs(
    solver: &Solver,
    symbol_table: &HashMap<String, TypeInfo>,
    entries: &[(String, ConfigValue)],
) -> InputSummary {
    let mut summary = InputSummary::default();
    for (symbol, value) in entries {
        let Some(z3_type) = symbol_table
            .get(symbol)
            .and_then(|info| info.z3_type.as_ref())
        else {
            warn!("input {symbol} is not in the model; skipping it");
            summary.unknown_symbols += 1;
            continue;
        };

        let constraint = match (z3_type, value) {
            (Z3Types::Ternary(pair), ConfigValue::Tristate(v)) => match v {
                0 => pair.is_n(),
                1 => pair.is_m(),
                _ => pair.is_y(),
            },
            (Z3Types::Integer(variable), ConfigValue::Number(raw)) => {
                match parse_config_number(raw) {
                    Some(parsed) => variable.eq(parsed),
                    None => {
                        warn!("input {symbol}={raw} is not a parseable number; skipping it");
                        summary.mismatched += 1;
                        continue;
                    }
                }
            }
            (Z3Types::String(variable), ConfigValue::Text(text)) => {
                variable.eq(z3_string::from_str(text).expect("no NUL in .config values"))
            }
            (_, _) => {
                warn!(
                    "input {symbol}={value:?} does not fit the symbol's modeled type; skipping it"
                );
                summary.mismatched += 1;
                continue;
            }
        };

        assert_tracked(solver, constraint, format!("input:{symbol}"));
        summary.asserted += 1;
    }
    summary
}

/// Parses a .config number: `0x`-prefixed values are unsigned hex (kconfig
/// hex options), everything else signed decimal.
fn parse_config_number(raw: &str) -> Option<z3_int> {
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok().map(z3_int::from_u64)
    } else {
        raw.parse::<i64>().ok().map(z3_int::from_i64)
    }
}

/// NOTE: tests are AI slop I generated after I got everything working.
/// TODO: review these more carefully and consider handwritten tests.
#[cfg(test)]
mod tests {
    use super::*;
    use z3::SatResult;
    use z3::ast::Bool as z3_bool;

    #[test]
    fn parses_all_line_forms() {
        let text = r#"
# Generated by something
CONFIG_A=y
CONFIG_B=m
# CONFIG_C is not set
CONFIG_D=17
CONFIG_E=0x1A
CONFIG_F="hello"
CONFIG_G="a\"b\\c"
CONFIG_H=""
CONFIG_NEG=-4

# just a comment, not a symbol
"#;
        let entries = parse_dot_config(text);
        assert_eq!(
            entries,
            vec![
                ("A".to_string(), ConfigValue::Tristate(2)),
                ("B".to_string(), ConfigValue::Tristate(1)),
                ("C".to_string(), ConfigValue::Tristate(0)),
                ("D".to_string(), ConfigValue::Number("17".to_string())),
                ("E".to_string(), ConfigValue::Number("0x1A".to_string())),
                ("F".to_string(), ConfigValue::Text("hello".to_string())),
                ("G".to_string(), ConfigValue::Text(r#"a"b\c"#.to_string())),
                ("H".to_string(), ConfigValue::Text(String::new())),
                ("NEG".to_string(), ConfigValue::Number("-4".to_string())),
            ]
        );
    }

    fn table_with(entries: Vec<(&str, Z3Types)>) -> HashMap<String, TypeInfo> {
        entries
            .into_iter()
            .map(|(name, z3_type)| {
                (
                    name.to_string(),
                    TypeInfo {
                        kconfig_type: None,
                        z3_type: Some(z3_type),
                        selected_by: HashMap::new(),
                        implied_by: HashMap::new(),
                        attribute_defs: HashMap::new(),
                    },
                )
            })
            .collect()
    }

    #[test]
    fn asserted_inputs_pin_the_variables() {
        let (tri, ladder) = z3_ternary::new_tristate("CI_TRI");
        let boolean = z3_ternary::new_bool("CI_BOOL");
        let number = z3_int::new_const("CI_INT");
        let text = z3_string::new_const("CI_STR");
        let table = table_with(vec![
            ("CI_TRI", Z3Types::Ternary(tri.clone())),
            ("CI_BOOL", Z3Types::Ternary(boolean.clone())),
            ("CI_INT", Z3Types::Integer(number.clone())),
            ("CI_STR", Z3Types::String(text.clone())),
        ]);

        let entries = parse_dot_config(
            "CONFIG_CI_TRI=m\n# CONFIG_CI_BOOL is not set\nCONFIG_CI_INT=0x1A\nCONFIG_CI_STR=\"x\"\nCONFIG_CI_MISSING=y\n",
        );

        let solver = Solver::new();
        solver.assert(&ladder);
        let summary = assert_config_inputs(&solver, &table, &entries);
        assert_eq!(summary.asserted, 4);
        assert_eq!(summary.unknown_symbols, 1);
        assert_eq!(summary.mismatched, 0);

        // consistent with the inputs...
        assert_eq!(solver.check(), SatResult::Sat);
        let model = solver.get_model().unwrap();
        assert_eq!(model.eval(&tri.is_m(), true).unwrap().as_bool(), Some(true));
        assert_eq!(
            model.eval(&number, true).unwrap().as_i64(),
            Some(26) // 0x1A
        );

        // ...and contradictions are detected
        solver.assert(z3_bool::and(&[boolean.is_y()]));
        assert_eq!(solver.check(), SatResult::Unsat);
    }
}
