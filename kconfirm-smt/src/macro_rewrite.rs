//! Pre-processes macros in the parsed Kconfig AST, before desugaring and analysis.

use crate::macro_eval::MacroEvaluator;
use log::warn;
use nom_kconfig::Symbol;
use nom_kconfig::attribute::expression::CompareOperand;
use nom_kconfig::attribute::r#macro::Macro;
use nom_kconfig::attribute::range::RangeBound;
use nom_kconfig::attribute::r#type::Type;
use nom_kconfig::attribute::{AndExpression, Atom, Attribute, Expression, OrExpression, Term};
use nom_kconfig::entry::Entry;
use nom_kconfig::symbol::ConstantSymbol;

/// Rewrites all macro occurrences in `entries` (recursively, across sourced
/// files and containers: menus, choices, and if-blocks) to evaluated constants.
pub fn rewrite_entries(entries: Vec<Entry>, evaluator: &mut MacroEvaluator) -> Vec<Entry> {
    entries
        .into_iter()
        .map(|entry| rewrite_entry(entry, evaluator))
        .collect()
}

fn rewrite_entry(entry: Entry, ev: &mut MacroEvaluator) -> Entry {
    match entry {
        Entry::Config(mut config) => {
            config.attributes = rewrite_attributes(config.attributes, ev);
            Entry::Config(config)
        }
        Entry::MenuConfig(mut config) => {
            config.attributes = rewrite_attributes(config.attributes, ev);
            Entry::MenuConfig(config)
        }
        Entry::Choice(mut choice) => {
            choice.options = rewrite_attributes(choice.options, ev);
            choice.entries = rewrite_entries(choice.entries, ev);
            Entry::Choice(choice)
        }
        Entry::Menu(mut menu) => {
            menu.visible = menu
                .visible
                .map(|visible| visible.map(|expr| rewrite_expression(expr, ev)));
            menu.depends_on = menu
                .depends_on
                .into_iter()
                .map(|mut dep| {
                    dep.expression = rewrite_expression(dep.expression, ev);
                    dep
                })
                .collect();
            menu.entries = rewrite_entries(menu.entries, ev);
            Entry::Menu(menu)
        }
        Entry::If(mut if_block) => {
            if_block.condition = rewrite_expression(if_block.condition, ev);
            if_block.entries = rewrite_entries(if_block.entries, ev);
            Entry::If(if_block)
        }
        Entry::Source(mut source) => {
            for kconfig in &mut source.kconfigs {
                kconfig.entries = rewrite_entries(std::mem::take(&mut kconfig.entries), ev);
            }
            Entry::Source(source)
        }
        Entry::OSource(mut source) => {
            for kconfig in &mut source.kconfigs {
                kconfig.entries = rewrite_entries(std::mem::take(&mut kconfig.entries), ev);
            }
            Entry::OSource(source)
        }
        Entry::RSource(mut source) => {
            for kconfig in &mut source.kconfigs {
                kconfig.entries = rewrite_entries(std::mem::take(&mut kconfig.entries), ev);
            }
            Entry::RSource(source)
        }
        Entry::OrSource(mut source) => {
            for kconfig in &mut source.kconfigs {
                kconfig.entries = rewrite_entries(std::mem::take(&mut kconfig.entries), ev);
            }
            Entry::OrSource(source)
        }
        Entry::ConfigDefault(mut config_default) => {
            config_default.default.expression =
                rewrite_expression(config_default.default.expression, ev);
            config_default.default.r#if = config_default
                .default
                .r#if
                .map(|expr| rewrite_expression(expr, ev));
            Entry::ConfigDefault(config_default)
        }
        // comments, the main menu, and preprocessor statements themselves
        // (variable assignments, bare function calls) carry no modeled
        // expressions (identity)
        other => other,
    }
}

fn rewrite_attributes(attributes: Vec<Attribute>, ev: &mut MacroEvaluator) -> Vec<Attribute> {
    attributes
        .into_iter()
        .map(|attribute| rewrite_attribute(attribute, ev))
        .collect()
}

fn rewrite_attribute(attribute: Attribute, ev: &mut MacroEvaluator) -> Attribute {
    match attribute {
        Attribute::Prompt(mut prompt) => {
            prompt.r#if = prompt.r#if.map(|expr| rewrite_expression(expr, ev));
            Attribute::Prompt(prompt)
        }
        Attribute::DependsOn(mut depends_on) => {
            depends_on.expression = rewrite_expression(depends_on.expression, ev);
            Attribute::DependsOn(depends_on)
        }
        Attribute::Select(mut select) => {
            select.r#if = select.r#if.map(|expr| rewrite_expression(expr, ev));
            Attribute::Select(select)
        }
        Attribute::Imply(mut imply) => {
            imply.r#if = imply.r#if.map(|expr| rewrite_expression(expr, ev));
            Attribute::Imply(imply)
        }
        Attribute::Default(mut default) => {
            default.expression = rewrite_expression(default.expression, ev);
            default.r#if = default.r#if.map(|expr| rewrite_expression(expr, ev));
            Attribute::Default(default)
        }
        Attribute::Visible(visible) => {
            Attribute::Visible(visible.map(|expr| rewrite_expression(expr, ev)))
        }
        Attribute::Requires(expr) => Attribute::Requires(rewrite_expression(expr, ev)),
        Attribute::Range(mut range) => {
            range.lower_bound = rewrite_range_bound(range.lower_bound, ev);
            range.upper_bound = rewrite_range_bound(range.upper_bound, ev);
            range.r#if = range.r#if.map(|expr| rewrite_expression(expr, ev));
            Attribute::Range(range)
        }
        Attribute::Type(mut config_type) => {
            config_type.r#type = match config_type.r#type {
                Type::DefBool(expr) => Type::DefBool(rewrite_expression(expr, ev)),
                Type::DefTristate(expr) => Type::DefTristate(rewrite_expression(expr, ev)),
                Type::DefInt(expr) => Type::DefInt(rewrite_expression(expr, ev)),
                Type::DefHex(expr) => Type::DefHex(rewrite_expression(expr, ev)),
                Type::DefString(expr) => Type::DefString(rewrite_expression(expr, ev)),
                plain => plain,
            };
            config_type.r#if = config_type.r#if.map(|expr| rewrite_expression(expr, ev));
            Attribute::Type(config_type)
        }
        // help text, option flags, modules, optional, transitional: no
        // expressions (identity)
        other => other,
    }
}

fn rewrite_expression(expr: Expression, ev: &mut MacroEvaluator) -> Expression {
    match expr {
        OrExpression::Term(and) => OrExpression::Term(rewrite_and(and, ev)),
        OrExpression::Expression(ands) => {
            OrExpression::Expression(ands.into_iter().map(|and| rewrite_and(and, ev)).collect())
        }
    }
}

fn rewrite_and(and: AndExpression, ev: &mut MacroEvaluator) -> AndExpression {
    match and {
        AndExpression::Term(term) => AndExpression::Term(rewrite_term(term, ev)),
        AndExpression::Expression(terms) => AndExpression::Expression(
            terms
                .into_iter()
                .map(|term| rewrite_term(term, ev))
                .collect(),
        ),
    }
}

fn rewrite_term(term: Term, ev: &mut MacroEvaluator) -> Term {
    match term {
        Term::Atom(atom) => Term::Atom(rewrite_atom(atom, ev)),
        Term::Not(atom) => Term::Not(rewrite_atom(atom, ev)),
    }
}

fn rewrite_atom(atom: Atom, ev: &mut MacroEvaluator) -> Atom {
    match atom {
        Atom::Macro(m) => match ev.eval_macro(&m) {
            // the expansion re-lexes as a quoted token, like kconfig does (y/m/n, number, or text)
            Ok(text) => Atom::Symbol(Symbol::Constant(ConstantSymbol::String(text))),
            Err(e) => {
                warn!("macro not evaluated (stays a free unknown): {e}");
                Atom::Macro(m)
            }
        },
        Atom::Parenthesis(inner) => Atom::Parenthesis(Box::new(rewrite_expression(*inner, ev))),
        Atom::Compare(mut compare) => {
            compare.left = rewrite_compare_operand(compare.left, ev);
            compare.right = rewrite_compare_operand(compare.right, ev);
            Atom::Compare(compare)
        }
        symbol @ Atom::Symbol(_) => symbol,
    }
}

fn rewrite_compare_operand(operand: CompareOperand, ev: &mut MacroEvaluator) -> CompareOperand {
    match operand {
        CompareOperand::Macro(m) => match ev.eval_macro(&m) {
            Ok(text) => CompareOperand::Symbol(Symbol::Constant(ConstantSymbol::String(text))),
            Err(e) => {
                warn!("macro not evaluated (stays a free unknown): {e}");
                CompareOperand::Macro(m)
            }
        },
        symbol => symbol,
    }
}

fn rewrite_range_bound(bound: RangeBound, ev: &mut MacroEvaluator) -> RangeBound {
    match bound {
        RangeBound::Variable(name) => {
            // the parser stores the reference; normalize to the bare name
            let bare = name
                .strip_prefix("$(")
                .and_then(|n| n.strip_suffix(')'))
                .unwrap_or(&name);
            match ev.eval_macro(&Macro::Variable(bare.to_string())) {
                Ok(text) if text.starts_with("0x") || text.starts_with("0X") => {
                    RangeBound::Hex(text)
                }
                Ok(text) => match text.parse::<i64>() {
                    Ok(number) => RangeBound::Number(number),
                    Err(_) => {
                        warn!("range bound $({bare}) evaluated to non-numeric {text:?}");
                        RangeBound::Variable(name)
                    }
                },
                Err(e) => {
                    warn!("range bound not evaluated: {e}");
                    RangeBound::Variable(name)
                }
            }
        }
        other => other,
    }
}
