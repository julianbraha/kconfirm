// SPDX-License-Identifier: GPL-2.0-only
use log::debug;
use nom_kconfig::attribute::DefaultAttribute;
use nom_kconfig::attribute::OrExpression;
use nom_kconfig::attribute::Range;
use nom_kconfig::attribute::Select;
use nom_kconfig::attribute::r#type::Type;
use std::collections::HashMap;
//use std::mem::Discriminant;

pub struct KconfigVarDependency {
    pub var: String,

    // NOTE: this will be None if the variable has no dependencies. will happen when we encounter an unconstrained variable e.g. that just selects other variables.
    pub dependencies: Option<nom_kconfig::attribute::Expression>, // aka `OrExpression` type
    pub selects: Vec<Select>,
    pub range: Option<Range>,
}

// NOTE: we cannot add these elements to the solver until we've processed all variables,
// because we need to know all of the selectors.
#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub kconfig_type: Option<Type>, // None when we don't know the type (it's just a dependency that popped up somewhere)

    // maps the selector to an (ARCH, select_cond)
    // - if the ARCH is None, then it's not arch-specific
    // if the select_cond is None, then it's unconditional
    pub selected_by:
        HashMap<String, Vec<(Option<String>, Option<nom_kconfig::attribute::Expression>)>>, // .0 only selects it when .1 is true.

    // there is one of these per entry (each entry expected to have a different definedness condition)
    // maps architecture option name (or none if not arch-specific) to:
    // [([condition], config definition)]
    // - NOTE: there can be multiple partial definitions under the same condition, or mutually-exclusive conditions, or a subset condition.
    pub variable_info:
        HashMap<Option<String>, Vec<(Vec<nom_kconfig::attribute::Expression>, VariableInfo)>>, // the innermost `Vec<nom_kconfig::attribute::Expression>` represents each nested condition that was reached (we will basically need to AND them all)
}

// the dependencies are a vector because we may encounter multiple over time,
//   so we won't know until the end what the condition is.
#[derive(Debug, Clone)]
pub struct VariableInfo {
    pub kconfig_dependencies: Vec<nom_kconfig::attribute::OrExpression>,
    pub kconfig_ranges: Vec<Range>,
    pub kconfig_defaults: Vec<DefaultAttribute>,
    pub visibility: Vec<nom_kconfig::attribute::OrExpression>,
    pub selects: Vec<(String, Option<nom_kconfig::attribute::Expression>)>,
}

impl TypeInfo {
    fn new_solved(
        _symbol: String,
        kconfig_type: Option<Type>,
        raw_constraints: Vec<OrExpression>,
        kconfig_ranges: Vec<Range>,
        kconfig_defaults: Vec<DefaultAttribute>,
        visibility: Vec<OrExpression>,
        arch: Option<String>,
        definition_condition: Vec<OrExpression>,
        selected_by: Option<(String, Option<nom_kconfig::attribute::Expression>)>,
        selects: Vec<(String, Option<nom_kconfig::attribute::Expression>)>,
    ) -> Self {
        let mut selected_by_map = HashMap::new();

        TypeInfo {
            kconfig_type: kconfig_type,
            selected_by: {
                if let Some(s) = selected_by {
                    selected_by_map.insert(s.0, vec![(arch.clone(), s.1)]);
                }

                selected_by_map
            },
            variable_info: {
                let mut h = HashMap::new();

                h.insert(
                    arch,
                    vec![(
                        definition_condition,
                        VariableInfo {
                            kconfig_dependencies: raw_constraints,
                            kconfig_ranges,
                            kconfig_defaults,
                            visibility,
                            selects,
                        },
                    )],
                );

                h
            },
        }
    }

    fn add_variable_info(
        &mut self,
        raw_constraints: Vec<OrExpression>,
        kconfig_ranges: Vec<Range>,
        kconfig_defaults: Vec<DefaultAttribute>,
        visibility: Vec<OrExpression>,
        arch: Option<String>,
        definition_condition: Vec<OrExpression>,
        selects: Vec<(String, Option<OrExpression>)>,
    ) {
        let existing_var_info = self.variable_info.get_mut(&arch);

        match existing_var_info {
            None => {
                self.variable_info.insert(
                    arch,
                    vec![(
                        definition_condition,
                        VariableInfo {
                            kconfig_dependencies: raw_constraints,
                            kconfig_ranges,
                            kconfig_defaults,
                            visibility,
                            selects,
                        },
                    )],
                );
            }
            Some(existing) => {
                debug!("the existing variable info is {:?}", existing);
                existing.push((
                    definition_condition,
                    VariableInfo {
                        kconfig_dependencies: raw_constraints,
                        kconfig_ranges,
                        kconfig_defaults,
                        visibility,
                        selects,
                    },
                ));
            }
        }

        /* to see what the existing type definition was:

        debug!("the existing data is: {:?}", &existing_var_info);
        if let Some(existing) = existing_var_info {
            assert!(existing.kconfig_dependencies.is_empty());
            assert!(existing.kconfig_ranges.is_empty());
            assert!(existing.kconfig_defaults.is_empty());
            assert!(existing.visibility.is_empty());
            assert!(existing.selects.is_empty());
        }
        */
    }
}

// the visibility and the dependencies will each need to be AND'd (separately)
// the defaults should each be handled separately.
pub struct ChoiceData {
    //pub inner_vars: Vec<String>,
    pub arch: Option<String>,
    pub visibility: Option<OrExpression>,
    pub dependencies: Vec<OrExpression>, // this is the menu's dependencies (and inherited dependencies from the file)
    pub defaults: Vec<DefaultAttribute>, // these are each of the conditional defaults for the choice
}

// NOTE: it might be better if TypeInfo is an enum with a single value,
//       e.g. Unsolved(kconfig_raw) and Solved(z3_ast)
pub struct SymbolTable {
    pub raw: HashMap<String, TypeInfo>,
    pub choices: Vec<ChoiceData>,
    pub modules_option: Option<String>, // None until we find the modules attribute in exactly 1 config option
}

impl SymbolTable {
    pub fn new() -> Self {
        SymbolTable {
            raw: HashMap::new(),
            choices: Vec::new(),
            modules_option: None,
        }
    }

    pub fn from_parts(
        raw: HashMap<String, TypeInfo>,
        choices: Vec<ChoiceData>,
        modules_option: Option<String>,
    ) -> Self {
        SymbolTable {
            raw,
            choices,
            modules_option,
        }
    }

    pub fn merge_insert_new_solved(
        &mut self,
        var: String,

        kconfig_type: Option<Type>,
        raw_constraints: Vec<OrExpression>,

        kconfig_ranges: Vec<Range>,
        kconfig_defaults: Vec<DefaultAttribute>,

        visibility: Vec<OrExpression>,
        arch: Option<String>,
        definition_condition: Vec<OrExpression>,
        selected_by: Option<(String, Option<nom_kconfig::attribute::Expression>)>,
        selects: Vec<(String, Option<nom_kconfig::attribute::Expression>)>,
    ) {
        let existing = self.raw.remove(&var);

        match existing {
            None => {
                self.raw.insert(
                    var.clone(),
                    TypeInfo::new_solved(
                        var,
                        kconfig_type,
                        raw_constraints,
                        kconfig_ranges,
                        kconfig_defaults,
                        visibility,
                        arch,
                        definition_condition,
                        selected_by,
                        selects,
                    ),
                );
            }

            Some(e) => {
                let mut existing_type_info = e;

                if kconfig_type.is_some() && existing_type_info.kconfig_type.is_none() {
                    existing_type_info.kconfig_type = kconfig_type;
                } else if kconfig_type.is_some() && kconfig_type != existing_type_info.kconfig_type
                {
                    // NOTE: this sometimes prints a message just because the prompt text changes, e.g. ARCH_FORCE_MAX_ORDER stays int type but sometimes adds "Maximum zone order" text
                    debug!(
                        "NOTE: different type {:?} for var {} (existing type: {:?})",
                        kconfig_type, var, existing_type_info.kconfig_type
                    );
                }

                // we always want to extend the selectors list.

                if let Some(select_info) = selected_by {
                    let existing_select_info =
                        existing_type_info.selected_by.get_mut(&select_info.0);
                    match existing_select_info {
                        None => {
                            existing_type_info
                                .selected_by
                                .insert(select_info.0, vec![(arch.clone(), select_info.1)]);
                        }
                        Some(extisting_select_info) => {
                            extisting_select_info.append(&mut vec![(arch.clone(), select_info.1)]);
                        }
                    }
                }

                /*
                 * what if we check for an existing VariableInfo with the same definedness condition,
                 * and merge this info with that one?
                 *
                 * otherwise, we can check why we're reaching this line multiple times for the same config option
                 * under the same definedness condition
                 */
                debug!("adding a variable info for var {:?}", var);
                existing_type_info.add_variable_info(
                    raw_constraints,
                    kconfig_ranges,
                    kconfig_defaults,
                    visibility,
                    arch,
                    definition_condition,
                    selects,
                );

                // TODO: options can be redefined differently under different IF-conditions, see TCP_CONG_CUBIC
                //       - has nothing to do with arch!
                //       - how do we handle these?
                //       - AND I think if they're "redefined" under the same conditions, then you just add the attributes together!

                self.raw.insert(var, existing_type_info);
            }
        };
    }
}
