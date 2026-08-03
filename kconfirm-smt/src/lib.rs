use kconfirm_desugar::desugar_kconfig;
use kconfirm_lib::Z3Types;
use log::{debug, error, info, warn};
use nom_kconfig::attribute::r#type::Type;
use nom_kconfig::{
    Entry,
    KconfigInput,
    entry::Source,
    parse_kconfig, //
};
use std::collections::{
    HashMap,
    HashSet, //
};
use std::path::PathBuf;
use std::str::FromStr;
use z3::{
    Model,
    SatResult,
    Solver, //
};

use z3::ast::Bool as z3_bool;
use z3::ast::Int as z3_int;
use z3::ast::String as z3_string;
use z3_ternary::Ternary;

use kconfirm_lib::{
    AnalysisArgs,
    Check,
    ChoiceData,
    Finding,
    Severity,
    SymbolTable,
    TypeInfo,
    analyze, //
};
use kconfirm_linux::collect_kconfig_root_files;

use crate::config_input::{
    assert_config_inputs,
    parse_dot_config, //
};
use crate::kconfig_to_smt::{
    model_int_bound,
    model_int_value_expr,
    model_kconfig_or_expr,
    model_string_value_expr, //
};
use crate::macro_eval::MacroEvaluator;
use crate::macro_rewrite::rewrite_entries;
use nom_kconfig::attribute::OrExpression;

mod config_input;
mod kconfig_to_smt;
mod macro_eval;
mod macro_rewrite;

/// How preprocessor macros (`$(cc-option,...)`, `$(shell,...)`, ...) get
/// their values.
pub struct MacroOptions {
    /// Use previously dumped values instead of evaluating with the host
    /// toolchain. Unlisted macros become free variables.
    pub load: Option<PathBuf>,
    /// After the tree is processed, write every evaluated value here for a
    /// later `--load`.
    pub dump: Option<PathBuf>,
    /// The value of `$(ARCH)` during evaluation.
    pub arch: String,
}

/// What to do with the model once its constraints are built.
pub enum RunMode {
    /// Export the SMT-LIB2 model and optionally generate configuration witnesses.
    Model {
        config_output: Option<PathBuf>,
        constraints_output: PathBuf,
        /// Randomize the Z3 solver's decision phases with this seed, so each
        /// run yields a different witness (for differential testing).
        seed: Option<u32>,
        /// Whether to run the unmet-dependency sweep after the main check.
        sweep: bool,
        /// Directory for unmet-dependency witnesses when `sweep` is enabled.
        witness_directory: Option<PathBuf>,
    },
    /// For differential testing: read an existing .config (e.g. from
    /// `make randconfig`), assert its values as constraints, and check that
    /// the configuration is consistent with the model.
    CheckConfig { config_input: PathBuf },
}

/// Models a condition expression (dependencies, prompt conditions, and the
/// `if` conditions of defaults/selects/implies/ranges) as a pair. kconfig's
/// rewrite of the constant `m` to `(m && MODULES)` has already been applied
/// by kconfirm-desugar.
fn model_condition(symbol_table: &HashMap<String, TypeInfo>, expr: OrExpression) -> Ternary {
    model_kconfig_or_expr(symbol_table, Type::Tristate(None), expr)
        .try_into()
        .expect("conditions model as pairs")
}

/// The dependency condition of `symbol`s definition under `arch` (falling
/// back to its arch-independent definition), modeled as a pair.
/// `y` when the definition has no dependencies.
fn definition_dependencies(
    symbol_table: &HashMap<String, TypeInfo>,
    info: &TypeInfo,
    arch: &Option<String>,
) -> Ternary {
    let definition = info
        .attribute_defs
        .get(arch)
        .or_else(|| info.attribute_defs.get(&None))
        .or_else(|| info.attribute_defs.values().next());
    match definition.and_then(|def| def.kconfig_dependencies.clone()) {
        None => Ternary::y(),
        Some(deps) => model_condition(symbol_table, deps),
    }
}

/// An int/hex option as the .config writer needs it.
struct WritableInt {
    symbol: String,
    value: z3_int,
    write_gate: z3_bool,
    is_hex: bool,
    /// The literal source text of each constant default, keyed by the
    /// canonical decimal rendering of its numeric value. kconfig's value
    /// string for a defaulted option is the *source token itself* — hex
    /// digit case included (`default 0xC0000000` reads back as 0xC0000000,
    /// `default 0xdead000000000000` as 0xdead...) — so when the model's
    /// value equals a default's value, only that literal round-trips.
    default_literals: Vec<(String, String)>,
}

/// The literal text of a plain-constant expression (a default value like
/// `0xdead000000000000`, `"0xa"`, or `17`), as kconfig would use it for the
/// option's value string. `None` for anything but a single constant atom.
fn constant_literal(expr: &OrExpression) -> Option<String> {
    use nom_kconfig::Symbol;
    use nom_kconfig::attribute::{AndExpression, Atom, Term};
    use nom_kconfig::symbol::ConstantSymbol;

    let OrExpression::Term(AndExpression::Term(Term::Atom(Atom::Symbol(Symbol::Constant(
        constant,
    ))))) = expr
    else {
        return None;
    };
    match constant {
        ConstantSymbol::Hex(text) => Some(text.clone()),
        ConstantSymbol::Integer(value) => Some(value.to_string()),
        // a quoted number: kconfig strips the quotes for the value string
        ConstantSymbol::String(text) => Some(text.clone()),
        ConstantSymbol::Boolean(_) | ConstantSymbol::Tristate(_) => None,
    }
}

/// The canonical decimal rendering of a z3 integer numeral (`None` for
/// non-constant terms), used to match model values against default literals.
fn canonical_decimal(value: &z3_int) -> Option<String> {
    value
        .as_u64()
        .map(|unsigned| unsigned.to_string())
        .or_else(|| value.as_i64().map(|signed| signed.to_string()))
}

/// An unmet-dependency query for one select.
///
/// The violation is when the selector-value is greater than the selectee's
/// dependencies' value.
struct UnmetDepCheck {
    selector: String,
    selectee: String,
    guard: z3_bool,
}

/// For debugging an unsatisfiable model.
/// Asserts `constraint` under a fresh boolean literal named `name`, so that when the model is
/// unsatisfiable, `Solver::get_unsat_core` reports the names of the constraints responsible.
fn assert_tracked(solver: &Solver, constraint: impl Into<z3_bool>, name: String) {
    #[cfg(feature = "debug")]
    {
        let tracker = z3_bool::new_const(name);
        solver.assert_and_track(constraint, &tracker);
    }
    #[cfg(not(feature = "debug"))]
    {
        let _ = name;
        solver.assert(constraint.into());
    }
}

/// Builds the model for the Kconfig tree at `path` and runs the `mode` settings on it.
/// Returns whether the final check was satisfiable.
pub fn model_kconfig(path: PathBuf, mode: RunMode, macros: MacroOptions) -> bool {
    // diverse witnesses: with a seed, the solver picks decision phases at
    // random instead of defaulting, so every seed yields a different model
    // (must be set before any solver is created)
    if let RunMode::Model {
        seed: Some(seed), ..
    } = &mode
    {
        let seed = seed.to_string();
        z3::set_global_param("smt.random_seed", &seed);
        z3::set_global_param("smt.phase_selection", "5"); // random phase
        z3::set_global_param("sat.random_seed", &seed);
        z3::set_global_param("sat.phase", "random");
    }

    // the macro evaluator: either evaluate scripts/Kconfig.include and the
    // tree's probes with the host toolchain (mirroring kconfig's
    // preprocessor), or use values provided with --load
    let mut evaluator = match &macros.load {
        Some(file) => match MacroEvaluator::from_file(file) {
            Ok(evaluator) => evaluator,
            Err(e) => {
                error!("--load: {e}");
                return false;
            }
        },
        None => MacroEvaluator::new_host(&path, &macros.arch),
    };
    /*let all_archs: Vec<String> = kconfirm_linux::ALL_ARCHITECTURES
        .into_iter()
        .map(|x| x.to_owned())
        .collect();
    let kconfig_files = collect_kconfig_root_files(all_archs, path).unwrap();*/

    // NOTE: just x86 for now

    // the symbol table tags arch-specific entries with the arch's *config option* name
    // (e.g. "X86"), not the arch directory name (e.g. "x86"), so compare against this
    let enabled_arch_config_option = kconfirm_linux::arch_dir_to_config(&macros.arch);
    let kconfig_files = collect_kconfig_root_files(vec![macros.arch], path).unwrap();

    // seed the evaluated argument-less values (cc-version, m64-flag, CC, ...)
    // into nom-kconfig's variable map: the parser substitutes $(NAME)
    // textually in every file it reads — including sourced files — exactly
    // where kconfig's lexer would have expanded them. values that could
    // change how text parses stay out and resolve at AST-rewrite time
    // instead.
    let parser_variables = evaluator.safe_parser_variables();
    let kconfig_sources: Vec<(Option<String>, String, nom_kconfig::KconfigFile)> = kconfig_files
        .iter()
        .map(|kconfig| {
            let mut kconfig_file = kconfig.kconfig_file.clone();
            kconfig_file.add_local_vars(parser_variables.clone());
            // the root file's contents were read before seeding: substitute
            // again with the full map (a second pass over already-substituted
            // text is a no-op for the earlier variables)
            let contents = kconfig_file.preprocess_content(kconfig.file_contents.clone());
            (
                Some(kconfig.arch_config_option.clone()),
                contents,
                kconfig_file,
            )
        })
        .collect();
    let kconfig_inputs: Vec<(Option<String>, KconfigInput)> = kconfig_sources
        .iter()
        .map(|(arch, contents, kconfig_file)| {
            (
                arch.clone(),
                KconfigInput::new_extra(contents, kconfig_file.clone()),
            )
        })
        .collect();

    let mut findings = Vec::new();
    let mut symbol_table = SymbolTable::new();

    for (arch_config_option, kconfig_file) in kconfig_inputs {
        match parse_kconfig(kconfig_file) {
            Ok(parsed) => {
                // rewrite evaluated macros to constants (kconfig expands
                // $(...) in its lexer; function calls with arguments could
                // not be substituted textually and are evaluated here)
                let mut kconfig_ast = parsed.1;
                kconfig_ast.entries = rewrite_entries(kconfig_ast.entries, &mut evaluator);

                // run the desugaring passes before constructing the symbol table
                let source = Source {
                    kconfigs: vec![kconfig_ast],
                };
                let entries: Vec<Entry> = desugar_kconfig(source);

                let args = AnalysisArgs::new();

                findings.extend(analyze(
                    &args,
                    &mut symbol_table,
                    arch_config_option,
                    entries,
                ));
            }
            Err(e) => {
                findings.push(Finding {
                    severity: Severity::Fatal,
                    check: Check::FailedParse,
                    symbol: None,
                    message: format!("Failed to parse kconfig, error is: {}", e),
                    arch: None,
                });
            }
        }
    }

    println!(
        "Preprocessed macros: {} evaluated, {} unresolved",
        evaluator.stats.evaluated, evaluator.stats.failed
    );
    if let Some(dump_path) = &macros.dump {
        match evaluator.dump(dump_path) {
            Ok(()) => info!("Wrote macro values to {}", dump_path.display()),
            Err(e) => error!("Failed to write {}: {e}", dump_path.display()),
        }
    }

    let solver = Solver::new();

    let mut new_symtab = HashMap::new();

    // the tristate options, so that the modules rule can be asserted for each
    // of them once the MODULES option's variable is known
    let mut tristate_pairs: Vec<(String, Ternary)> = Vec::new();

    // convert the kconfig types to z3 types.
    //
    // bool and tristate options are order-encoded as pairs of z3 booleans
    // (see z3-ternary):
    for (symbol, kconfig_type_info) in &mut symbol_table.raw {
        if let Some(t) = &kconfig_type_info.kconfig_type {
            let z3_type = match t {
                Type::Bool(_) | Type::DefBool(_) => Z3Types::Ternary(z3_ternary::new_bool(symbol)),

                Type::Tristate(_) | Type::DefTristate(_) => {
                    let (pair, ladder) = z3_ternary::new_tristate(symbol);
                    assert_tracked(&solver, ladder, format!("domain:{symbol}:ladder"));
                    tristate_pairs.push((symbol.clone(), pair.clone()));
                    Z3Types::Ternary(pair)
                }

                Type::String(_) => Z3Types::String(z3_string::new_const(symbol.as_str())),

                // int and hex options are one unbounded z3 integer each. hex
                // values are converted from base 16 to base 10 on the way in;
                // the .config writer formats them back to base 16.
                Type::Int(_) | Type::Hex(_) => Z3Types::Integer(z3_int::new_const(symbol.as_str())),

                Type::DefString(_) | Type::DefHex(_) | Type::DefInt(_) => {
                    todo!("consider supporting kconfiglib extension")
                }
            };

            let mut new_kconfig_type_info = kconfig_type_info.clone();
            new_kconfig_type_info.z3_type = Some(z3_type);
            new_symtab.insert(symbol.clone(), new_kconfig_type_info);
        } else {
            debug!("symbol doesn't have a kconfig type: {}", symbol);
            //panic!("symbol doesn't have a kconfig type:{}", symbol);
            //symbol_table.raw.remove(symbol);
        }
    }

    // TODO: really need to clean this up:
    //       was dropping the symbol table to simplify arch handling.
    drop(symbol_table.raw);

    // MODULES: the single variable of the bool MODULES option. If the tree defines
    // no MODULES option, MODULES is false (no option can be m).
    // NOTE: kconfirm-desugar has already rewritten the constant m in
    // conditions into (m && MODULES)
    let modules_enabled: z3_bool = symbol_table
        .modules_option
        .as_ref()
        .and_then(|symbol| new_symtab.get(symbol))
        .and_then(|info| info.z3_type.clone())
        .and_then(|z3_type| match z3_type {
            Z3Types::Ternary(pair) => Some(pair.gt_n()),
            _ => None,
        })
        .unwrap_or_else(|| {
            info!("no (bool/tristate) MODULES option found: treating MODULES as constant n");
            z3_bool::from_bool(false)
        });

    // modules rule: when modules are disabled, no tristate option can be m
    for (symbol, pair) in &tristate_pairs {
        assert_tracked(
            &solver,
            z3_ternary::modules_rule(pair, &modules_enabled),
            format!("domain:{symbol}:modules_rule"),
        );
    }

    // collect the choices under the enabled architecture and validate their
    // members: a member must be a bool option known to the symbol table
    // (choice_constraints.md; modern kconfig has no tristate choices). invalid
    // members are left out of the choice and keep their ordinary per-symbol
    // value constraint.
    let enabled_choices: Vec<(&ChoiceData, Vec<String>)> = symbol_table
        .choices
        .iter()
        .filter(|choice| {
            // ignore choices for other architectures
            choice.arch == Some(enabled_arch_config_option.clone()) || choice.arch.is_none()
        })
        .map(|choice| {
            let members = choice
                .config_options
                .iter()
                .filter(|member| match new_symtab.get(*member) {
                    None => {
                        error!(
                            "choice member {member} is not in the symbol table; leaving it out of its choice"
                        );
                        false
                    }
                    Some(info) => match &info.kconfig_type {
                        Some(Type::Bool(_)) | Some(Type::DefBool(_)) => true,
                        other => {
                            error!(
                                "choice member {member} is not a bool (type {other:?}); leaving it out of its choice"
                            );
                            false
                        }
                    },
                })
                .cloned()
                .collect();
            (choice, members)
        })
        .collect();

    // the value of a choice member is decided entirely by the per-choice
    // constraints (built after this loop)
    let choice_members: HashSet<String> = enabled_choices
        .iter()
        .flat_map(|(_choice, members)| members.iter().cloned())
        .collect();

    // an invisible option at n is never written to .config
    let mut writable_symbols: Vec<(String, Ternary, z3_bool)> = Vec::new();
    // for choice:
    let mut writable_members: Vec<(String, z3_bool, z3_bool)> = Vec::new();
    let mut writable_ints: Vec<WritableInt> = Vec::new();
    let mut writable_strings: Vec<(String, z3_string, z3_bool)> = Vec::new();

    // the unmet-dependency queries, one per select whose selectee has
    // dependencies; checked one at a time (as assumptions)
    let mut unmet_dep_checks: Vec<UnmetDepCheck> = Vec::new();

    // an option's selects and implies are collected from the selectee's /
    // impliee's side via the `selected_by` / `implied_by` reverse maps, and
    // become part of its value constraint; the value constraint entails the
    // forward direction (min(selector, cond) <= selectee), so no separate
    // forward implications are asserted.
    for (symbol, type_info) in new_symtab.clone() {
        let kconfig_type = type_info.clone().kconfig_type.unwrap();

        // a choice member is an ordinary bool symbol
        // but its value constraint is
        // replaced by the per-choice constraints below
        if choice_members.contains(&symbol) {
            // kconfig ignores select/imply into choice members
            for selector in type_info.selected_by.keys() {
                warn!(
                    "dead select of choice member: {selector} selects {symbol}. This is probably a bug in Kconfig usage."
                );
            }
            for implicator in type_info.implied_by.keys() {
                warn!("dead imply into choice member: {implicator} implies {symbol}");
            }
            if type_info
                .attribute_defs
                .values()
                .any(|def| !def.kconfig_defaults.is_empty())
            {
                warn!(
                    "dead default on choice member {symbol} (the choice's own defaults are the only selection mechanism)"
                );
            }
            continue;
        }

        // int/hex and string options have their own constraint shapes
        match kconfig_type {
            Type::String(_) => {
                model_string_option(
                    &solver,
                    &new_symtab,
                    &symbol,
                    &type_info,
                    &mut writable_strings,
                );
                continue;
            }
            Type::Int(_) | Type::Hex(_) => {
                model_int_option(
                    &solver,
                    &new_symtab,
                    &symbol,
                    &type_info,
                    matches!(kconfig_type, Type::Hex(_)),
                    &mut writable_ints,
                );
                continue;
            }
            _ => {}
        }

        let z3_type = type_info
            .clone()
            .z3_type
            .expect("already converted all kconfig types to z3");
        let pair: Ternary = z3_type
            .try_into()
            .expect("bool and tristate options are modeled as order-encoded pairs");

        // promote(X): the clamp's m to y promotion applies unconditionally to a
        // bool option, also to tristates when MODULES is disabled
        let promote = match kconfig_type {
            Type::Bool(_) | Type::DefBool(_) => z3_bool::from_bool(true),
            Type::Tristate(_) | Type::DefTristate(_) => z3_ternary::bool_not(&modules_enabled),
            _ => unreachable!("string/int/hex options were skipped above"),
        };

        // we're going to set all of these in the upcoming loop
        let mut prompt_visibility_z3: Option<Ternary> = None; // the prompt condition alone
        let mut dependencies_z3: Option<Ternary> = None;
        let mut has_dependencies = false; // gates the unmet-dependency queries

        let mut selected_by_z3: Vec<Ternary> = Vec::new();
        let mut implied_by_z3: Vec<Ternary> = Vec::new();
        let mut defaults_z3: Vec<(Ternary, Ternary)> = Vec::new(); // (value, condition) in declaration order

        // this loop is for handling all of the current config option's attributes.
        //
        // NOTE: the option's own `select`/`imply` attributes are not handled
        // here: each select/imply is recorded on the target option's
        // selected_by/implied_by, and handled there (below).
        for (_arch, attributes) in type_info.clone().attribute_defs {
            // convert the kconfig dependencies into a pair.
            // kconfirm-desugar combines all dependencies into a single
            // condition, so there is at most one here.
            has_dependencies = attributes.kconfig_dependencies.is_some();
            dependencies_z3 = Some(match attributes.kconfig_dependencies {
                // no dependencies are always satisfied: y
                None => Ternary::y(),
                Some(deps) => model_condition(&new_symtab, deps),
            });

            /*
             * notes on visibility:
             * 1. is affected by its prompt.
             * 2. NOT affected by 'if..endif'
             * 3. is affected by choice and menu
             */
            prompt_visibility_z3 = Some(match attributes.visibility {
                // Visibility:None means that it has no prompt (never visible)
                None => Ternary::n(),
                Some(vis) => model_condition(&new_symtab, vis),
            });

            for default_and_condition in attributes.kconfig_defaults {
                let default_value: Ternary = model_kconfig_or_expr(
                    &new_symtab,
                    kconfig_type.clone(), // expect default to be the same type as the config option
                    default_and_condition.expression,
                )
                .try_into()
                .expect("bool/tristate default values model as pairs");

                let default_condition: Ternary = match default_and_condition.r#if {
                    Some(condition) => model_condition(&new_symtab, condition),
                    // no condition is unconditional, so evaluate to y
                    None => Ternary::y(),
                };

                defaults_z3.push((default_value, default_condition));
            }

            // only matters for int, hex, which are skipped above
            // TODO: alarm if ranges are used for other types!
            let _ranges = attributes.kconfig_ranges;
        }

        // collect selects
        let mut select_edge_pulls: Vec<(String, Ternary)> = Vec::new();
        for (selector, archs_and_conditions) in type_info.selected_by {
            let selector_info = new_symtab
                .get(&selector)
                .expect("selector exists (not a dangling reference)");
            let selector_z3 = selector_info
                .z3_type
                .as_ref()
                .expect("already converted all kconfig types to z3");

            let Z3Types::Ternary(selector_pair) = selector_z3 else {
                error!("selector {selector} is not a bool/tristate; skipping its selects");
                continue;
            };

            for (arch, select_condition) in archs_and_conditions {
                if arch.clone() == Some(enabled_arch_config_option.clone()) || arch.clone() == None
                {
                    let selector_deps =
                        definition_dependencies(&new_symtab, selector_info, &arch);

                    // conditional select: combine the selector's value and its
                    // own dependencies with the select condition
                    let edge_pull = if let Some(cond) = select_condition {
                        let select_condition_z3: Ternary =
                            model_condition(&new_symtab, cond.clone());

                        z3_ternary::and(&[
                            selector_pair.clone(),
                            selector_deps,
                            select_condition_z3,
                        ])
                    } else {
                        // unconditional select under the current architecture
                        z3_ternary::and(&[selector_pair.clone(), selector_deps])
                    };

                    selected_by_z3.push(edge_pull.clone());
                    select_edge_pulls.push((selector.clone(), edge_pull));
                }
            }
        }

        // collect implies
        for (implicator, archs_and_conditions) in type_info.implied_by {
            let implicator_info = new_symtab
                .get(&implicator)
                .expect("implicator exists (not a dangling reference)");
            let implicator_z3 = implicator_info
                .z3_type
                .as_ref()
                .expect("already converted all kconfig types to z3");

            let Z3Types::Ternary(implicator_pair) = implicator_z3 else {
                error!("implicator {implicator} is not a bool/tristate; skipping its implies");
                continue;
            };

            for (arch, imply_condition) in archs_and_conditions {
                if arch.clone() == Some(enabled_arch_config_option.clone()) || arch.clone() == None
                {
                    let implicator_deps =
                        definition_dependencies(&new_symtab, implicator_info, &arch);

                    // conditional imply: combine the implicator's value and its
                    // own dependencies with the imply condition
                    if let Some(cond) = imply_condition {
                        let imply_condition_z3: Ternary =
                            model_condition(&new_symtab, cond.clone());

                        implied_by_z3.push(z3_ternary::and(&[
                            implicator_pair.clone(),
                            implicator_deps,
                            imply_condition_z3,
                        ]));
                    } else {
                        // unconditional imply under the current architecture
                        implied_by_z3
                            .push(z3_ternary::and(&[implicator_pair.clone(), implicator_deps]));
                    }
                }
            }
        }

        // select_pull(X): the max of mins for each select and its condition (n if none)
        let select_pull = z3_ternary::or(&selected_by_z3);
        // imply_pull(X): the max of mins for each imply and its condition (n if none)
        let imply_pull = z3_ternary::or(&implied_by_z3);

        let dependencies = dependencies_z3
            .expect("all variables should have had their dependencies modeled already");
        let prompt_visibility = prompt_visibility_z3
            .expect("all variables should have had their visibility modeled already");

        // keep track of visibility as its own var for .config writing afterwards
        let visibility_formula = z3_ternary::and(&[prompt_visibility, dependencies.clone()]);
        let (visibility, visibility_definition) =
            z3_ternary::define_ternary(&format!("{symbol}:vis"), &visibility_formula);
        if let Some(definition) = visibility_definition {
            assert_tracked(&solver, definition, format!("vis:{symbol}"));
        }

        // a symbol is written to the generated .config iff:
        //  it is visible or its value is not n.
        let symbol_write_gate = z3_ternary::bool_or(&visibility.gt_n(), &pair.gt_n());
        if symbol_write_gate.as_bool() != Some(false) {
            writable_symbols.push((symbol.clone(), pair.clone(), symbol_write_gate));
        }

        // active_default(X): the first default (in declaration order) whose
        // condition is active, min'd with its condition; n if none active.
        let active_default = z3_ternary::active_default(&defaults_z3);

        // untouched(X):
        // the value the option takes when the user cannot (or does not) touch it
        let untouched = z3_ternary::clamp(
            &z3_ternary::or(&[
                select_pull.clone(),
                z3_ternary::and(&[
                    dependencies.clone(),
                    z3_ternary::or(&[imply_pull, active_default]),
                ]),
            ]),
            &promote,
        );

        // the value constraint
        let lo = z3_ternary::clamp(&select_pull, &promote);
        let hi = z3_ternary::clamp(
            &z3_ternary::or(&[select_pull, visibility.clone()]),
            &promote,
        );

        let in_bounds =
            z3_ternary::bool_and(&z3_ternary::le(&lo, &pair), &z3_ternary::le(&pair, &hi));
        let untouched_eq = z3_ternary::eq(&pair, &untouched);

        let value_constraint = z3_ternary::bool_ite(&visibility.gt_n(), &in_bounds, &untouched_eq);
        assert_tracked(&solver, value_constraint, format!("value:{symbol}"));

        // unmet-dependency queries, one per select, when the selectee has
        // dependencies.
        //
        // NOTE: a BOOL selectee's dependencies at m count as fully satisfied:
        // kconfig promotes a bool's dependencies of to y.
        let warning_dependencies = match kconfig_type {
            Type::Bool(_) | Type::DefBool(_) => {
                z3_ternary::clamp(&dependencies, &z3_bool::from_bool(true))
            }
            _ => dependencies.clone(),
        };
        if has_dependencies {
            for (selector, edge_pull) in select_edge_pulls {
                let violation = z3_ternary::lt(&warning_dependencies, &edge_pull);
                if violation.as_bool() == Some(false) {
                    // can never out-pull the selectee's dependencies
                    continue;
                }
                let guard = z3_bool::new_const(format!(
                    "unmet_dep:{selector}->{symbol}:{}",
                    unmet_dep_checks.len()
                ));
                solver.assert(guard.implies(&violation));
                unmet_dep_checks.push(UnmetDepCheck {
                    selector,
                    selectee: symbol.clone(),
                    guard,
                });
            }
        }
    }

    // the per-choice constraints. the contained
    // config options are stored in the field `config_options` in declaration
    // order
    for (choice_idx, (choice, members)) in enabled_choices.iter().enumerate() {
        // check that there is 1 or fewer dependencies for the choice
        // (kconfirm-desugar should have distributed if..endif dependencies,
        // and all 'depends on' should have been combined with logical and &&)
        assert!(choice.dependencies.len() <= 1);

        if members.is_empty() {
            error!("choice {choice_idx} has no usable members; skipping it");
            continue;
        }

        // a choice has no symbol of its own, so its
        // tracked constraints are labeled by index and first member
        let choice_label = format!("choice{choice_idx}[{}]", members[0]);

        // the selection gate. the choice makes a selection whenever its
        // dependencies are satisfied (m or y), even when not visible
        // (when its prompt condition is false): the prompt effectively just
        //  decides WHO picks (the user vs the defaults/first-eligible fallback)
        let dependency_pair: Ternary = match choice.dependencies.first() {
            None => Ternary::y(), // no dependencies means the dependencies are met
            Some(choice_deps) => model_condition(&new_symtab, choice_deps.to_owned()),
        };
        let live = dependency_pair.gt_n();

        // The choice's own prompt condition (`prompt "..." if COND`)
        // is ignored here. Modern kconfig's sym_calc_choice
        // picks the first member-visible symbol with user value y. the choice
        // prompt's condition gates the UI, not the value computation.
        let mut member_vars: Vec<z3_bool> = Vec::with_capacity(members.len());
        let mut eligibilities: Vec<z3_bool> = Vec::with_capacity(members.len());
        for member in members {
            let info = new_symtab
                .get(member)
                .expect("members were validated against the symbol table");
            let member_pair: Ternary = info
                .z3_type
                .clone()
                .expect("already converted all kconfig types to z3")
                .try_into()
                .expect("bool members are modeled as pairs");
            member_vars.push(member_pair.gt_n());

            // after desugaring there is at most one attribute definition per arch
            let mut member_prompt: Option<Ternary> = None;
            let mut member_deps: Option<Ternary> = None;
            for (_arch, attributes) in &info.attribute_defs {
                member_deps = Some(match &attributes.kconfig_dependencies {
                    None => Ternary::y(),
                    Some(deps) => model_condition(&new_symtab, deps.clone()),
                });
                member_prompt = Some(match &attributes.visibility {
                    // a member is required to have a prompt; one without is
                    // statically never eligible
                    None => {
                        error!("choice member {member} has no prompt, so it can never be selected");
                        Ternary::n()
                    }
                    Some(vis) => model_condition(&new_symtab, vis.clone()),
                });
            }
            let member_prompt = member_prompt.unwrap_or_else(|| {
                error!("choice member {member} has no definition; treating it as never eligible");
                Ternary::n()
            });
            let member_deps = member_deps.unwrap_or_else(Ternary::y);

            // shared by the membership constraints, the untouched selection, and the member's write gate
            let eligibility_formula =
                z3_ternary::bool_and(&member_prompt.gt_n(), &member_deps.gt_n());
            let (eligibility, eligibility_definition) =
                z3_ternary::define_bool(&format!("{member}:eligible"), &eligibility_formula);
            if let Some(definition) = eligibility_definition {
                assert_tracked(&solver, definition, format!("eligible:{member}"));
            }
            eligibilities.push(eligibility);
        }

        // every eligible member of a live choice is written members are handled only here,
        // never in the per-symbol writer loop.
        for ((member, member_var), eligibility) in
            members.iter().zip(&member_vars).zip(&eligibilities)
        {
            let write_gate_formula =
                z3_ternary::bool_or(&z3_ternary::bool_and(&live, eligibility), member_var);
            let (write_gate, write_gate_definition) =
                z3_ternary::define_bool(&format!("{member}:write"), &write_gate_formula);
            if let Some(definition) = write_gate_definition {
                assert_tracked(&solver, definition, format!("write:{member}"));
            }
            if write_gate.as_bool() != Some(false) {
                writable_members.push((member.clone(), member_var.clone(), write_gate));
            }
        }

        // membership: an enabled member requires the choice live and itself eligible
        for ((member, member_var), eligibility) in
            members.iter().zip(&member_vars).zip(&eligibilities)
        {
            assert_tracked(
                &solver,
                z3_ternary::bool_implies(member_var, &z3_ternary::bool_and(&live, eligibility)),
                format!("{choice_label}:membership:{member}"),
            );
        }

        // at most one enabled member (this was the "sum = 2" from the old integer design)
        assert_tracked(
            &solver,
            z3_ternary::at_most_one(&member_vars),
            format!("{choice_label}:at_most_one"),
        );

        let at_least_one = z3_ternary::bool_implies(
            &z3_ternary::bool_and(&live, &z3_ternary::bool_or_all(&eligibilities)),
            &z3_ternary::bool_or_all(&member_vars),
        );
        assert_tracked(
            &solver,
            at_least_one,
            format!("{choice_label}:at_least_one"),
        );
    }

    // differential testing: assert the file's values on top of the system and
    // check consistency
    if let RunMode::CheckConfig { config_input } = &mode {
        let text = match std::fs::read_to_string(config_input) {
            Ok(text) => text,
            Err(e) => {
                error!("cannot read {}: {e}", config_input.display());
                return false;
            }
        };
        let entries = parse_dot_config(&text);
        let summary = assert_config_inputs(&solver, &new_symtab, &entries);
        info!(
            "asserted {} input values from {} ({} unknown symbols and {} type mismatches skipped)",
            summary.asserted,
            config_input.display(),
            summary.unknown_symbols,
            summary.mismatched,
        );

        info!("checking the configuration against the model...");
        let result = solver.check();
        info!("solver result: {result:?}");
        match result {
            SatResult::Sat => {
                return true;
            }
            SatResult::Unsat => {
                let unsat_core = solver.get_unsat_core();
                error!(
                    "unsat core contains {} tracked constraints:",
                    unsat_core.len()
                );
                for tracked in &unsat_core {
                    error!("  {tracked}");
                }
                return false;
            }
            SatResult::Unknown => {
                error!("solver returned unknown");
                return false;
            }
        }
    }

    let RunMode::Model {
        config_output,
        constraints_output,
        sweep,
        witness_directory,
        ..
    } = mode
    else {
        unreachable!("CheckConfig returned above");
    };

    match std::fs::write(&constraints_output, &solver.to_string()) {
        Ok(()) => info!(
            "Wrote SMT-LIB2 constraints to {}",
            constraints_output.display(),
        ),
        Err(e) => error!("failed to write {}: {e}", constraints_output.display()),
    }

    if config_output.is_none() && !sweep {
        info!("No witness output requested. Skipping satisfiability check.");
        return true;
    }

    info!("All variables and constraints added. Checking satisfiability...");
    let is_sat = solver.check();
    info!("Solver result: {is_sat:?}");
    match is_sat {
        SatResult::Sat => {
            if let Some(config_output) = &config_output {
                let model = solver.get_model().expect("a sat check produces a model");
                let config = render_config(
                    &model,
                    &writable_symbols,
                    &writable_members,
                    &writable_ints,
                    &writable_strings,
                );
                let emitted_lines = config
                    .lines()
                    .filter(|line| line.starts_with("CONFIG_") || line.starts_with("# CONFIG_"))
                    .count();

                match std::fs::write(config_output, &config) {
                    Ok(()) => info!(
                        "Random configuration generated. {emitted_lines} config lines written to {} ",
                        config_output.display(),
                    ),
                    Err(e) => error!("failed to write {}: {e}", config_output.display()),
                }
            }

            if sweep {
                let witness_directory = witness_directory
                    .as_ref()
                    .expect("--check-unmet-deps requires --output-witness-dir");
                if let Err(e) = std::fs::create_dir_all(witness_directory) {
                    error!(
                        "failed to create witness directory {}: {e}",
                        witness_directory.display()
                    );
                    return false;
                }
                info!(
                    "checking {} select edges for unmet dependencies...",
                    unmet_dep_checks.len()
                );
                let mut violated_edges = 0;
                let mut witness_names: HashSet<String> = HashSet::new();
                for check in &unmet_dep_checks {
                    match solver.check_assumptions(std::slice::from_ref(&check.guard)) {
                        SatResult::Sat => {
                            violated_edges += 1;
                            let model = solver.get_model().expect("a sat check produces a model");
                            let config = render_config(
                                &model,
                                &writable_symbols,
                                &writable_members,
                                &writable_ints,
                                &writable_strings,
                            );

                            // a selector can select the same option more than once
                            // (e.g. under different conditions): number the extras
                            let base =
                                format!("unmet_dep-{}-selects-{}", check.selector, check.selectee);
                            let mut witness_name = format!("{base}.config");
                            let mut counter = 2;
                            while !witness_names.insert(witness_name.clone()) {
                                witness_name = format!("{base}-{counter}.config");
                                counter += 1;
                            }
                            let witness_path = witness_directory.join(&witness_name);

                            match std::fs::write(&witness_path, &config) {
                                Ok(()) => error!(
                                    "Unmet dependency: {} can select {} past its dependencies; config: {}",
                                    check.selector,
                                    check.selectee,
                                    witness_path.display()
                                ),
                                Err(e) => {
                                    error!("failed to write {}: {e}", witness_path.display())
                                }
                            }
                        }
                        SatResult::Unsat => {}
                        SatResult::Unknown => error!(
                            "unmet dependency check unknown for {} -> {}",
                            check.selector, check.selectee
                        ),
                    }
                }
                info!(
                    "unmet dependency check: {violated_edges} of {} edges have a reachable violation",
                    unmet_dep_checks.len()
                );
            }

            true
        }
        SatResult::Unsat => {
            let unsat_core = solver.get_unsat_core();
            error!(
                "unsat core contains {} tracked constraints:",
                unsat_core.len()
            );
            for tracked in &unsat_core {
                error!("  {tracked}");
            }
            false
        }
        SatResult::Unknown => {
            error!("solver returned unknown: no model to write");
            false
        }
    }
}

/// Builds the constraints for one int/hex option
///
/// The option is one unbounded integer variable:
///   - dependencies unmet: the value is 0, regardless of range,
///   - deps met but non-visible: the value is the untouched value: the
///     first default whose condition is satisfied (m or y), clamped to the
///     nearest bound of the active range when it falls outside it; with no
///     active default, the active range's lower bound acts as the virtual
///     final default, else 0,
///   - visible: free within the active range, and unconstrained
///     when no range is active
///
/// Ranges follow declaration order exactly like defaults: the first range
/// whose condition is satisfied is the active one.
/// Int/hex options cannot select/imply and cannot select/imply
fn model_int_option(
    solver: &Solver,
    symbol_table: &HashMap<String, TypeInfo>,
    symbol: &str,
    type_info: &TypeInfo,
    is_hex: bool,
    writable_ints: &mut Vec<WritableInt>,
) {
    for selector in type_info.selected_by.keys() {
        warn!("dead select into int option: {selector} selects {symbol}");
    }
    for implicator in type_info.implied_by.keys() {
        warn!("dead imply into int option: {implicator} implies {symbol}");
    }

    let value: z3_int = type_info
        .z3_type
        .clone()
        .expect("already converted all kconfig types to z3")
        .try_into()
        .expect("int/hex options are modeled as z3 integers");

    let expected_type = match is_hex {
        true => Type::Hex(None),
        false => Type::Int(None),
    };

    // gather the attributes (one definition per arch, since we desugared)
    let mut dependencies: Option<Ternary> = None;
    let mut prompt: Option<Ternary> = None;
    let mut defaults: Vec<(z3_int, Ternary)> = Vec::new(); // (value, condition)
    let mut ranges: Vec<(z3_int, z3_int, Ternary)> = Vec::new(); // (lo, hi, condition)
    // (canonical decimal value, literal source text) per constant default
    let mut default_literals: Vec<(String, String)> = Vec::new();
    for (_arch, attributes) in &type_info.attribute_defs {
        dependencies = Some(match &attributes.kconfig_dependencies {
            None => Ternary::y(),
            Some(deps) => model_condition(symbol_table, deps.clone()),
        });
        prompt = Some(match &attributes.visibility {
            None => Ternary::n(),
            Some(vis) => model_condition(symbol_table, vis.clone()),
        });
        for default in &attributes.kconfig_defaults {
            let default_value = model_int_value_expr(
                symbol_table,
                expected_type.clone(),
                default.expression.clone(),
            );
            // remember the constant default's literal source text: the
            // writer emits it verbatim when the model picks this value
            // (kconfig's value string for a defaulted option is the source
            // token, hex digit case included)
            if let (Some(canonical), Some(literal)) = (
                canonical_decimal(&default_value),
                constant_literal(&default.expression),
            ) {
                default_literals.push((canonical, literal));
            }
            let condition: Ternary = match &default.r#if {
                None => Ternary::y(),
                Some(cond) => model_condition(symbol_table, cond.clone()),
            };
            defaults.push((default_value, condition));
        }
        for range in &attributes.kconfig_ranges {
            let lower = model_int_bound(symbol_table, &range.lower_bound, is_hex);
            let upper = model_int_bound(symbol_table, &range.upper_bound, is_hex);
            let condition: Ternary = match &range.r#if {
                None => Ternary::y(),
                Some(cond) => model_condition(symbol_table, cond.clone()),
            };
            ranges.push((lower, upper, condition));
        }
    }
    let dependencies = dependencies.unwrap_or_else(Ternary::y);
    let prompt = prompt.unwrap_or_else(Ternary::n);

    // dependencies at m or y both satisfy an int option
    let (deps_met, deps_definition) =
        z3_ternary::define_bool(&format!("{symbol}:dep>n"), &dependencies.gt_n());
    if let Some(definition) = deps_definition {
        assert_tracked(solver, definition, format!("dep:{symbol}"));
    }

    let (visible, visible_definition) = z3_ternary::define_bool(
        &format!("{symbol}:vis>=m"),
        &z3_ternary::bool_and(&prompt.gt_n(), &deps_met),
    );
    if let Some(definition) = visible_definition {
        assert_tracked(solver, definition, format!("vis:{symbol}"));
    }

    // ranges: like defaults, the first range whose condition is
    // satisfied (m or y) is the active one
    let mut any_range_hit = z3_bool::from_bool(false);
    let mut effective_ranges: Vec<(z3_bool, z3_int, z3_int)> = Vec::with_capacity(ranges.len());
    for (lower, upper, condition) in &ranges {
        let hit = condition.gt_n();
        let effective = z3_ternary::bool_and(&hit, &z3_ternary::bool_not(&any_range_hit));
        effective_ranges.push((effective, lower.clone(), upper.clone()));
        any_range_hit = z3_ternary::bool_or(&any_range_hit, &hit);
    }
    let range_active = any_range_hit;

    // defaults: the first default whose condition is satisfied is active
    let mut any_default_hit = z3_bool::from_bool(false);
    let mut effective_defaults: Vec<(z3_bool, z3_int)> = Vec::with_capacity(defaults.len());
    for (default_value, condition) in &defaults {
        let hit = condition.gt_n();
        let effective = z3_ternary::bool_and(&hit, &z3_ternary::bool_not(&any_default_hit));
        effective_defaults.push((effective, default_value.clone()));
        any_default_hit = z3_ternary::bool_or(&any_default_hit, &hit);
    }
    let default_hit = any_default_hit;

    // the untouched value
    let untouched = if effective_defaults.is_empty() && effective_ranges.is_empty() {
        z3_int::from_i64(0)
    } else {
        let untouched = z3_int::new_const(format!("{symbol}:untouched"));
        let mut definitions: Vec<z3_bool> = Vec::new();
        for (effective_default, default_value) in &effective_defaults {
            for (effective_range, lower, upper) in &effective_ranges {
                let fired = z3_ternary::bool_and(effective_default, effective_range);
                // an out-of-range active default clamps to the nearest bound
                definitions.push(z3_ternary::bool_implies(
                    &z3_ternary::bool_and(&fired, &default_value.lt(lower)),
                    &untouched.eq(lower),
                ));
                definitions.push(z3_ternary::bool_implies(
                    &z3_ternary::bool_and(&fired, &default_value.gt(upper)),
                    &untouched.eq(upper),
                ));
                definitions.push(z3_ternary::bool_implies(
                    &z3_ternary::bool_and_all(&[
                        fired.clone(),
                        lower.le(default_value),
                        default_value.le(upper),
                    ]),
                    &untouched.eq(default_value),
                ));
            }
            // no active range: the active default applies
            definitions.push(z3_ternary::bool_implies(
                &z3_ternary::bool_and(effective_default, &z3_ternary::bool_not(&range_active)),
                &untouched.eq(default_value),
            ));
        }
        for (effective_range, lower, _upper) in &effective_ranges {
            // no default active: the active range's lower bound is used
            definitions.push(z3_ternary::bool_implies(
                &z3_ternary::bool_and(&z3_ternary::bool_not(&default_hit), effective_range),
                &untouched.eq(lower),
            ));
        }
        definitions.push(z3_ternary::bool_implies(
            &z3_ternary::bool_and(
                &z3_ternary::bool_not(&default_hit),
                &z3_ternary::bool_not(&range_active),
            ),
            &untouched.eq(z3_int::from_i64(0)),
        ));
        assert_tracked(
            solver,
            z3_ternary::bool_and_all(&definitions),
            format!("untouched:{symbol}"),
        );
        untouched
    };

    // the value constraint
    let mut clauses = vec![
        // dependencies unmet: the value is 0, with or without range
        z3_ternary::bool_implies(
            &z3_ternary::bool_not(&deps_met),
            &value.eq(z3_int::from_i64(0)),
        ),
        // deps met but not visible: the untouched value applies
        z3_ternary::bool_implies(
            &z3_ternary::bool_and(&deps_met, &z3_ternary::bool_not(&visible)),
            &value.eq(&untouched),
        ),
    ];
    // visible: the user is free within the active range, and unconstrained
    // when no range is active
    for (effective_range, lower, upper) in &effective_ranges {
        clauses.push(z3_ternary::bool_implies(
            &z3_ternary::bool_and(&visible, effective_range),
            &z3_ternary::bool_and(&lower.le(&value), &value.le(upper)),
        ));
    }
    assert_tracked(
        solver,
        z3_ternary::bool_and_all(&clauses),
        format!("value:{symbol}"),
    );

    // written to .config when visible or non-zero
    let write_gate = z3_ternary::bool_or(&visible, &value.ne(z3_int::from_i64(0)));
    writable_ints.push(WritableInt {
        symbol: symbol.to_string(),
        value,
        write_gate,
        is_hex,
        default_literals,
    });
}

/// Builds the constraints for one string option.
///
/// The option is one string variable:
///   - when the dependencies are unmet: the value is ""
///   - when the dependencies are met but not visible: the value is the untouched value:
///     the first default whose condition is satisfied (m or y),
///     and "" when none is active,
///   - visible: free
///
/// Like int/hex, string options cannot select/imply, and cannot be selected/implied.
fn model_string_option(
    solver: &Solver,
    symbol_table: &HashMap<String, TypeInfo>,
    symbol: &str,
    type_info: &TypeInfo,
    writable_strings: &mut Vec<(String, z3_string, z3_bool)>,
) {
    for selector in type_info.selected_by.keys() {
        warn!("dead select into string option: {selector} selects {symbol}");
    }
    for implicator in type_info.implied_by.keys() {
        warn!("dead imply into string option: {implicator} implies {symbol}");
    }

    let value: z3_string = type_info
        .z3_type
        .clone()
        .expect("already converted all kconfig types to z3")
        .try_into()
        .expect("string options are modeled as z3 strings");

    // gather the attributes (definition since we desugared)
    let mut dependencies: Option<Ternary> = None;
    let mut prompt: Option<Ternary> = None;
    let mut defaults: Vec<(z3_string, Ternary)> = Vec::new(); // (value, condition)
    for (_arch, attributes) in &type_info.attribute_defs {
        if !attributes.kconfig_ranges.is_empty() {
            warn!("range on string option {symbol} is invalid kconfig; ignored");
        }
        dependencies = Some(match &attributes.kconfig_dependencies {
            None => Ternary::y(),
            Some(deps) => model_condition(symbol_table, deps.clone()),
        });
        prompt = Some(match &attributes.visibility {
            None => Ternary::n(),
            Some(vis) => model_condition(symbol_table, vis.clone()),
        });
        for default in &attributes.kconfig_defaults {
            let default_value = model_string_value_expr(symbol_table, default.expression.clone());
            let condition: Ternary = match &default.r#if {
                None => Ternary::y(),
                Some(cond) => model_condition(symbol_table, cond.clone()),
            };
            defaults.push((default_value, condition));
        }
    }
    let dependencies = dependencies.unwrap_or_else(Ternary::y);
    let prompt = prompt.unwrap_or_else(Ternary::n);

    // dependencies at m or y both satisfy a string option
    let (deps_met, deps_definition) =
        z3_ternary::define_bool(&format!("{symbol}:dep>n"), &dependencies.gt_n());
    if let Some(definition) = deps_definition {
        assert_tracked(solver, definition, format!("dep:{symbol}"));
    }

    let (visible, visible_definition) = z3_ternary::define_bool(
        &format!("{symbol}:vis>=m"),
        &z3_ternary::bool_and(&prompt.gt_n(), &deps_met),
    );
    if let Some(definition) = visible_definition {
        assert_tracked(solver, definition, format!("vis:{symbol}"));
    }

    // defaults: the first default whose condition is satisfied is active
    let mut any_default_hit = z3_bool::from_bool(false);
    let mut effective_defaults: Vec<(z3_bool, z3_string)> = Vec::with_capacity(defaults.len());
    for (default_value, condition) in &defaults {
        let hit = condition.gt_n();
        let effective = z3_ternary::bool_and(&hit, &z3_ternary::bool_not(&any_default_hit));
        effective_defaults.push((effective, default_value.clone()));
        any_default_hit = z3_ternary::bool_or(&any_default_hit, &hit);
    }
    let default_hit = any_default_hit;

    let empty = z3_string::from_str("").unwrap();

    // the untouched value: the active default's value, or "" when no default
    let untouched = if effective_defaults.is_empty() {
        empty.clone()
    } else {
        let untouched = z3_string::new_const(format!("{symbol}:untouched"));
        let mut definitions: Vec<z3_bool> = Vec::new();
        for (effective_default, default_value) in &effective_defaults {
            definitions.push(z3_ternary::bool_implies(
                effective_default,
                &untouched.eq(default_value),
            ));
        }
        definitions.push(z3_ternary::bool_implies(
            &z3_ternary::bool_not(&default_hit),
            &untouched.eq(&empty),
        ));
        assert_tracked(
            solver,
            z3_ternary::bool_and_all(&definitions),
            format!("untouched:{symbol}"),
        );
        untouched
    };

    // the value constraint:
    // - unmet deps unmet "",
    // - invisible: untouched,
    // - visible: free
    let clauses = vec![
        z3_ternary::bool_implies(&z3_ternary::bool_not(&deps_met), &value.eq(&empty)),
        z3_ternary::bool_implies(
            &z3_ternary::bool_and(&deps_met, &z3_ternary::bool_not(&visible)),
            &value.eq(&untouched),
        ),
    ];
    assert_tracked(
        solver,
        z3_ternary::bool_and_all(&clauses),
        format!("value:{symbol}"),
    );

    // write to .config when visible or non-empty
    let write_gate = z3_ternary::bool_or(&visible, &value.ne(&empty));
    writable_strings.push((symbol.to_string(), value, write_gate));
}

/// Renders a Linux .config from a satisfying model:
/// a config option and its value are written when the option's "write gate" holds:
/// visible, or enabled.
///
/// A visible symbol at n MUST be written as `# CONFIG_X is not set`.
///
/// Only an option that is invisible AND at n is left out.
fn render_config(
    model: &Model,
    writable_symbols: &[(String, Ternary, z3_bool)],
    writable_members: &[(String, z3_bool, z3_bool)],
    writable_ints: &[WritableInt],
    writable_strings: &[(String, z3_string, z3_bool)],
) -> String {
    let eval_bool = |formula: &z3_bool| -> bool {
        model
            .eval(formula, true)
            .and_then(|value| value.as_bool())
            .expect("boolean terms evaluate to constants under a completed model")
    };

    let mut lines: Vec<(String, String)> = Vec::new();

    for (symbol, pair, visible) in writable_symbols {
        if !eval_bool(visible) {
            continue;
        }
        // decode(X)
        let line = match (eval_bool(&pair.ge_m), eval_bool(&pair.ge_y)) {
            (true, true) => format!("CONFIG_{symbol}=y"),
            (true, false) => format!("CONFIG_{symbol}=m"),
            (false, false) => format!("# CONFIG_{symbol} is not set"),
            (false, true) => {
                unreachable!("{symbol} violates the ladder invariant in the model")
            }
        };
        lines.push((symbol.clone(), line));
    }

    // choice members are written only here, never in the loop above
    for (member, member_var, write_gate) in writable_members {
        if !eval_bool(write_gate) {
            continue;
        }
        let line = match eval_bool(member_var) {
            true => format!("CONFIG_{member}=y"),
            false => format!("# CONFIG_{member} is not set"),
        };
        lines.push((member.clone(), line));
    }

    // int/hex options. kconfig does not canonicalize hex digit case: the
    // value string of a defaulted (invisible) option is the default's source
    // token, and a user-provided value round-trips in whatever case it was
    // written. So when the model's value equals one of this option's
    // constant defaults, emit that default's literal verbatim; otherwise the
    // value is user-chosen (a free visible option or a range bound), for
    // which we render canonically — hex lowercase, matching how kconfig's
    // own writer (conf) renders computed values.
    for WritableInt {
        symbol,
        value,
        write_gate,
        is_hex,
        default_literals,
    } in writable_ints
    {
        if !eval_bool(write_gate) {
            continue;
        }
        let value_in_model = model
            .eval(value, true)
            .expect("model completion yields a value");

        // a default whose value the model chose: reuse its exact source text
        let literal_default = canonical_decimal(&value_in_model).and_then(|canonical| {
            default_literals
                .iter()
                .find(|(value, _)| *value == canonical)
                .map(|(_, literal)| literal.clone())
        });

        let line = if let Some(literal) = literal_default {
            format!("CONFIG_{symbol}={literal}")
        } else {
            match (value_in_model.as_i64(), is_hex) {
                (Some(value), false) => format!("CONFIG_{symbol}={value}"),
                (Some(value), true) if value >= 0 => format!("CONFIG_{symbol}=0x{value:x}"),
                (Some(value), true) => {
                    // hex options are unsigned in kconfig
                    warn!("negative value {value} for hex option {symbol}");
                    format!("CONFIG_{symbol}=-0x{:x}", value.unsigned_abs())
                }
                (None, true) if value_in_model.as_u64().is_some() => {
                    format!(
                        "CONFIG_{symbol}=0x{:x}",
                        value_in_model.as_u64().expect("checked above")
                    )
                }
                (None, _) => {
                    warn!("value of {symbol} exceeds 64 bits; writing the raw numeral");
                    format!("CONFIG_{symbol}={value_in_model}")
                }
            }
        };
        lines.push((symbol.clone(), line));
    }

    // string options: quoted, with \ and " escaped
    for (symbol, variable, write_gate) in writable_strings {
        if !eval_bool(write_gate) {
            continue;
        }
        let text = model
            .eval(variable, true)
            .and_then(|value| value.as_string())
            .expect("model completion yields string literals");
        if text.chars().any(|c| c.is_control()) {
            // a free visible string the solver picked; conf may not re-parse it
            warn!("value of string option {symbol} contains control characters");
        }
        let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
        lines.push((symbol.clone(), format!("CONFIG_{symbol}=\"{escaped}\"")));
    }

    // kconfig does not care about line order; sort for deterministic output
    lines.sort();

    let mut config = String::from("# Generated by kconfirm-smt\n");
    for (_symbol, line) in &lines {
        config.push_str(line);
        config.push('\n');
    }
    config
}

/// NOTE: tests are AI slop that I generated after I got everything working.
/// TODO: review these more carefully and consider hand-written tests.
#[cfg(test)]
mod tests {
    use super::*;
    use z3::{SatResult, Solver};

    /// The writer emits exactly the gate-true symbols, decodes pair values,
    /// and writes gated symbols at n as explicit "is not set" lines.
    #[test]
    fn render_config_writes_gated_symbols_only() {
        let solver = Solver::new();

        // a visible bool at y, a visible tristate at m, a visible bool at n
        // (must appear as "not set"), an invisible symbol at n (must not
        // appear), and an invisible-but-enabled symbol whose gate is its own
        // value (must appear)
        let foo = z3_ternary::new_bool("RC_FOO");
        let (bar, bar_ladder) = z3_ternary::new_tristate("RC_BAR");
        let baz = z3_ternary::new_bool("RC_BAZ");
        let hidden = z3_ternary::new_bool("RC_HIDDEN");
        let forced = z3_ternary::new_bool("RC_FORCED");

        solver.assert(&bar_ladder);
        solver.assert(foo.is_y());
        solver.assert(bar.is_m());
        solver.assert(baz.is_n());
        solver.assert(hidden.is_n());
        solver.assert(forced.is_y());

        let vis_true = z3_bool::from_bool(true);
        let writable_symbols = vec![
            ("RC_FOO".to_string(), foo, vis_true.clone()),
            ("RC_BAR".to_string(), bar, vis_true.clone()),
            ("RC_BAZ".to_string(), baz, vis_true.clone()),
            // invisible symbols: the gate is (constant-false vis) ∨ value>n,
            // which folds to the value itself
            ("RC_HIDDEN".to_string(), hidden.clone(), hidden.gt_n()),
            ("RC_FORCED".to_string(), forced.clone(), forced.gt_n()),
        ];

        // one member enabled, one written as "not set", and one disabled
        // member of an invisible choice (gate folds to its own value: omitted)
        let member1 = z3_bool::new_const("RC_MEMBER1");
        let member2 = z3_bool::new_const("RC_MEMBER2");
        let member3 = z3_bool::new_const("RC_MEMBER3");
        solver.assert(&member1);
        solver.assert(member2.not());
        solver.assert(member3.not());
        let writable_members = vec![
            ("RC_MEMBER1".to_string(), member1.clone(), vis_true.clone()),
            ("RC_MEMBER2".to_string(), member2, vis_true.clone()),
            ("RC_MEMBER3".to_string(), member3.clone(), member3),
        ];

        // a free visible int (decimal), a free visible hex (rendered
        // lowercase since it matches no default), an invisible-at-zero int
        // whose gate is its own non-zero test, and an invisible hex whose
        // value equals its constant default (emitted verbatim, uppercase)
        let number = z3_int::new_const("RC_NUM");
        let hex_number = z3_int::new_const("RC_HEX");
        let zero = z3_int::new_const("RC_ZERO");
        let defaulted_hex = z3_int::new_const("RC_HEX_DEFAULT");
        solver.assert(number.eq(z3_int::from_i64(17)));
        solver.assert(hex_number.eq(z3_int::from_i64(26)));
        solver.assert(zero.eq(z3_int::from_i64(0)));
        solver.assert(defaulted_hex.eq(z3_int::from_u64(0xDEAD)));
        let writable_ints = vec![
            WritableInt {
                symbol: "RC_NUM".to_string(),
                value: number,
                write_gate: vis_true.clone(),
                is_hex: false,
                default_literals: vec![],
            },
            WritableInt {
                symbol: "RC_HEX".to_string(),
                value: hex_number,
                write_gate: vis_true.clone(),
                is_hex: true,
                default_literals: vec![],
            },
            WritableInt {
                symbol: "RC_ZERO".to_string(),
                value: zero.clone(),
                write_gate: zero.ne(z3_int::from_i64(0)),
                is_hex: false,
                default_literals: vec![],
            },
            WritableInt {
                symbol: "RC_HEX_DEFAULT".to_string(),
                value: defaulted_hex.clone(),
                // invisible, but its value equals the default: written
                write_gate: defaulted_hex.ne(z3_int::from_i64(0)),
                is_hex: true,
                default_literals: vec![("57005".to_string(), "0xDEAD".to_string())],
            },
        ];

        // a visible string (with characters to escape), a visible EMPTY
        // string (must still be written as =""), and an invisible-empty
        // string whose gate is its own non-emptiness (omitted)
        let text = z3_string::new_const("RC_STR");
        let empty_visible = z3_string::new_const("RC_STR_EMPTY");
        let empty_hidden = z3_string::new_const("RC_STR_HIDDEN");
        solver.assert(text.eq(z3_string::from_str(r#"a"b\c"#).unwrap()));
        solver.assert(empty_visible.eq(z3_string::from_str("").unwrap()));
        solver.assert(empty_hidden.eq(z3_string::from_str("").unwrap()));
        let writable_strings = vec![
            ("RC_STR".to_string(), text, vis_true.clone()),
            ("RC_STR_EMPTY".to_string(), empty_visible, vis_true),
            (
                "RC_STR_HIDDEN".to_string(),
                empty_hidden.clone(),
                empty_hidden.ne(z3_string::from_str("").unwrap()),
            ),
        ];

        assert_eq!(solver.check(), SatResult::Sat);
        let model = solver.get_model().unwrap();
        let config = render_config(
            &model,
            &writable_symbols,
            &writable_members,
            &writable_ints,
            &writable_strings,
        );

        assert!(config.contains("CONFIG_RC_FOO=y\n"));
        assert!(config.contains("CONFIG_RC_BAR=m\n"));
        assert!(config.contains("# CONFIG_RC_BAZ is not set\n"));
        // invisible at n: omitted; invisible but enabled: written
        assert!(!config.contains("RC_HIDDEN"));
        assert!(config.contains("CONFIG_RC_FORCED=y\n"));
        assert!(config.contains("CONFIG_RC_MEMBER1=y\n"));
        assert!(config.contains("# CONFIG_RC_MEMBER2 is not set\n"));
        assert!(!config.contains("RC_MEMBER3"));
        assert!(config.contains("CONFIG_RC_NUM=17\n"));
        // free hex value: rendered lowercase (matches no default)
        assert!(config.contains("CONFIG_RC_HEX=0x1a\n"));
        assert!(!config.contains("RC_ZERO"));
        // value equals its default: the default's literal is emitted verbatim
        assert!(config.contains("CONFIG_RC_HEX_DEFAULT=0xDEAD\n"));
        // escaping: a"b\c is written with \" and \\
        assert!(config.contains(r#"CONFIG_RC_STR="a\"b\\c""#));
        assert!(config.contains("CONFIG_RC_STR_EMPTY=\"\"\n"));
        assert!(!config.contains("RC_STR_HIDDEN"));
    }
}
