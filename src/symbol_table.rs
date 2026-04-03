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

    pub selected_by: Vec<(String, Vec<nom_kconfig::attribute::Expression>)>, // .0 only selects it when .1 is true.

    // there is one of these per entry (each entry expected to have a different definedness condition)
    pub variable_info: Vec<VariableInfo>,
}

// the dependencies and definedness condition are vectors because we may encounter multiple of these over time,
//   so we never know until the very end what the condition is.
#[derive(Debug, Clone)]
pub struct VariableInfo {
    pub kconfig_dependencies: Vec<nom_kconfig::attribute::OrExpression>,
    pub kconfig_ranges: Vec<Range>,
    pub kconfig_defaults: Vec<DefaultAttribute>,
    pub visibility: Vec<nom_kconfig::attribute::OrExpression>,
    pub definedness_condition: Vec<nom_kconfig::attribute::Expression>,
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
        definedness_condition: Vec<nom_kconfig::attribute::Expression>,
        selected_by: Vec<(String, Vec<nom_kconfig::attribute::Expression>)>,
        selects: Vec<(String, Option<nom_kconfig::attribute::Expression>)>,
    ) -> Self {
        TypeInfo {
            kconfig_type: kconfig_type,
            selected_by,
            variable_info: vec![VariableInfo {
                kconfig_dependencies: raw_constraints,
                kconfig_ranges,
                kconfig_defaults,
                visibility,
                definedness_condition,
                selects,
            }],
        }
    }

    fn add_variable_info(
        &mut self,
        raw_constraints: Vec<OrExpression>,
        kconfig_ranges: Vec<Range>,
        kconfig_defaults: Vec<DefaultAttribute>,
        visibility: Vec<OrExpression>,
        definedness_condition: Vec<nom_kconfig::attribute::Expression>,
        selects: Vec<(String, Option<OrExpression>)>,
    ) {
        self.variable_info.push(VariableInfo {
            kconfig_dependencies: raw_constraints,
            kconfig_ranges,
            kconfig_defaults,
            visibility,
            definedness_condition,
            selects,
        })
    }
}

// the visibility and the dependencies will each need to be AND'd (separately)
// the defaults should each be handled separately.
pub struct ChoiceData {
    //pub inner_vars: Vec<String>,
    pub definedness: Vec<OrExpression>,
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
        definedness_condition: Vec<nom_kconfig::attribute::Expression>,
        selected_by: Vec<(String, Vec<nom_kconfig::attribute::Expression>)>,
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
                        definedness_condition,
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
                existing_type_info.selected_by.extend(selected_by);
                // we only want to use this add_variable_info when there's something different in it.
                if !raw_constraints.is_empty()
                    || !kconfig_ranges.is_empty()
                    || !kconfig_defaults.is_empty()
                    || !definedness_condition.is_empty()
                {
                    existing_type_info.add_variable_info(
                        raw_constraints,
                        kconfig_ranges,
                        kconfig_defaults,
                        visibility,
                        definedness_condition,
                        selects,
                    );
                }

                self.raw.insert(var, existing_type_info);
            }
        };
    }
}
