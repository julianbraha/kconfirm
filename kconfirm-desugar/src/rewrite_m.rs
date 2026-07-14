use nom_kconfig::{
    Attribute, Entry, Symbol,
    attribute::{
        AndExpression,
        Atom,
        Expression,
        OrExpression,
        Term, //
    },
    symbol::ConstantSymbol,
    tristate::Tristate,
};

// `m` becomes `(m && MODULES)`, where MODULES is the
// config option carrying the `modules` attribute. In a tree without a
// modules option, `m` in a condition becomes `n`.
//
// only conditions are rewritten: `depends on` expressions, `visible if`
// conditions, and the `if` conditions of prompts/defaults/selects/implies/
// ranges. (kconfig does not apply the rewrite to value expressions)
// NOTE: a `default m` keeps its raw `m` and is corrected by the option-level clamp,
// and comparisons compare values, so their operands also keep the raw `m`.
pub fn visit_entries(entries: Vec<Entry>) -> Vec<Entry> {
    let modules_option = find_modules_option(&entries);
    rewrite_entries(entries, modules_option.as_deref())
}

/// The symbol of the config option declaring the `modules` attribute. When a
/// tree declares more than one, the last one wins
fn find_modules_option(entries: &[Entry]) -> Option<String> {
    let mut modules_option = None;
    for entry in entries {
        match entry {
            Entry::Config(config) | Entry::MenuConfig(config) => {
                if config
                    .attributes
                    .iter()
                    .any(|attribute| matches!(attribute, Attribute::Modules))
                {
                    modules_option = Some(config.symbol.clone());
                }
            }
            Entry::Menu(menu) => {
                modules_option = find_modules_option(&menu.entries).or(modules_option);
            }
            Entry::Choice(choice) => {
                modules_option = find_modules_option(&choice.entries).or(modules_option);
            }
            Entry::If(r#if) => {
                modules_option = find_modules_option(&r#if.entries).or(modules_option);
            }
            _ => {}
        }
    }
    modules_option
}

fn rewrite_entries(entries: Vec<Entry>, modules_option: Option<&str>) -> Vec<Entry> {
    entries
        .into_iter()
        .map(|entry| rewrite_entry(entry, modules_option))
        .collect()
}

fn rewrite_entry(entry: Entry, modules_option: Option<&str>) -> Entry {
    match entry {
        Entry::Config(mut config) => {
            config.attributes = rewrite_attributes(config.attributes, modules_option);
            Entry::Config(config)
        }
        Entry::MenuConfig(mut config) => {
            config.attributes = rewrite_attributes(config.attributes, modules_option);
            Entry::MenuConfig(config)
        }
        Entry::Menu(mut menu) => {
            for dep in &mut menu.depends_on {
                dep.expression = rewrite_m_in_condition(dep.expression.clone(), modules_option);
                dep.r#if = rewrite_optional_condition(dep.r#if.take(), modules_option);
            }
            menu.entries = rewrite_entries(menu.entries, modules_option);
            Entry::Menu(menu)
        }
        Entry::Choice(mut choice) => {
            choice.options = rewrite_attributes(choice.options, modules_option);
            choice.entries = rewrite_entries(choice.entries, modules_option);
            Entry::Choice(choice)
        }
        Entry::If(_if) => {
            unreachable!("if entries should have been eliminated by distribute_if")
        }
        other => other,
    }
}

fn rewrite_attributes(attributes: Vec<Attribute>, modules_option: Option<&str>) -> Vec<Attribute> {
    attributes
        .into_iter()
        .map(|attribute| match attribute {
            Attribute::DependsOn(mut dep) => {
                dep.expression = rewrite_m_in_condition(dep.expression, modules_option);
                dep.r#if = rewrite_optional_condition(dep.r#if, modules_option);
                Attribute::DependsOn(dep)
            }
            Attribute::Prompt(mut prompt) => {
                prompt.r#if = rewrite_optional_condition(prompt.r#if, modules_option);
                Attribute::Prompt(prompt)
            }
            // a default's `if` is a condition so its value expression keeps
            // the raw `m`
            Attribute::Default(mut default) => {
                default.r#if = rewrite_optional_condition(default.r#if, modules_option);
                Attribute::Default(default)
            }
            Attribute::Select(mut select) => {
                select.r#if = rewrite_optional_condition(select.r#if, modules_option);
                Attribute::Select(select)
            }
            Attribute::Imply(mut imply) => {
                imply.r#if = rewrite_optional_condition(imply.r#if, modules_option);
                Attribute::Imply(imply)
            }
            Attribute::Range(mut range) => {
                range.r#if = rewrite_optional_condition(range.r#if, modules_option);
                Attribute::Range(range)
            }
            Attribute::Visible(condition) => {
                Attribute::Visible(rewrite_optional_condition(condition, modules_option))
            }
            other => other,
        })
        .collect()
}

fn rewrite_optional_condition(
    condition: Option<Expression>,
    modules_option: Option<&str>,
) -> Option<Expression> {
    condition.map(|expr| rewrite_m_in_condition(expr, modules_option))
}

pub fn rewrite_m_in_condition(expr: OrExpression, modules_option: Option<&str>) -> OrExpression {
    match expr {
        OrExpression::Term(and) => OrExpression::Term(rewrite_m_and(and, modules_option)),
        OrExpression::Expression(ands) => OrExpression::Expression(
            ands.into_iter()
                .map(|and| rewrite_m_and(and, modules_option))
                .collect(),
        ),
    }
}

fn rewrite_m_and(and: AndExpression, modules_option: Option<&str>) -> AndExpression {
    match and {
        AndExpression::Term(term) => AndExpression::Term(rewrite_m_term(term, modules_option)),
        AndExpression::Expression(terms) => AndExpression::Expression(
            terms
                .into_iter()
                .map(|term| rewrite_m_term(term, modules_option))
                .collect(),
        ),
    }
}

fn rewrite_m_term(term: Term, modules_option: Option<&str>) -> Term {
    match term {
        Term::Atom(atom) => Term::Atom(rewrite_m_atom(atom, modules_option)),
        Term::Not(atom) => Term::Not(rewrite_m_atom(atom, modules_option)),
    }
}

fn rewrite_m_atom(atom: Atom, modules_option: Option<&str>) -> Atom {
    match atom {
        Atom::Symbol(Symbol::Constant(ConstantSymbol::Tristate(Tristate::Module))) => {
            match modules_option {
                Some(name) => Atom::Parenthesis(Box::new(OrExpression::Term(
                    AndExpression::Expression(vec![
                        Term::Atom(Atom::Symbol(Symbol::Constant(ConstantSymbol::Tristate(
                            Tristate::Module,
                        )))),
                        Term::Atom(Atom::Symbol(Symbol::NonConstant(name.to_string()))),
                    ]),
                ))),
                None => Atom::Symbol(Symbol::Constant(ConstantSymbol::Tristate(Tristate::No))),
            }
        }
        Atom::Parenthesis(inner) => {
            Atom::Parenthesis(Box::new(rewrite_m_in_condition(*inner, modules_option)))
        }
        other => other,
    }
}
