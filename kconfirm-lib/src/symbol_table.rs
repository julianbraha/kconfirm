// SPDX-License-Identifier: GPL-2.0-only
use log::debug;
use nom_kconfig::attribute::DefaultAttribute;
use nom_kconfig::attribute::Expression;
use nom_kconfig::attribute::OrExpression;
use nom_kconfig::attribute::Range;
use nom_kconfig::attribute::Select;
use nom_kconfig::attribute::r#type::Type;
use std::collections::HashMap;
use std::collections::hash_map;

type Arch = Option<String>;
type Cond = Option<Expression>;

pub struct KconfigVarDependency {
    pub var: String,

    // NOTE: this will be None if the variable has no dependencies. will happen when we encounter an unconstrained variable e.g. that just selects other variables.
    pub dependencies: Cond,
    pub selects: Vec<Select>,
    pub range: Option<Range>,
}

// NOTE: we cannot add these elements to the solver until we've processed all variables,
// because we need to know all of the selectors.
#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub kconfig_type: Option<Type>, // 'None' when we don't know the type (e.g. if it's a dangling reference)

    // maps the selector to an (ARCH, select_cond)
    // - if the ARCH is None, then it's not arch-specific
    // if the select_cond is None, then it's unconditional
    pub selected_by: HashMap<String, Vec<(Arch, Cond)>>, // .0 only selects it when .1 is true.

    // there is one of these per entry (each entry expected to have a different definedness condition)
    // maps architecture option name (or none if not arch-specific) to:
    // [([condition], config definition)]
    // - NOTE: there can be multiple partial definitions under the same condition, or mutually-exclusive conditions, or a subset condition.
    pub variable_info: HashMap<Arch, Vec<(Vec<Expression>, VariableInfo)>>, // the innermost `Vec<nom_kconfig::attribute::Expression>` represents each nested condition that was reached (we will basically need to AND them all)
}

// the dependencies are a vector because we may encounter multiple over time,
//   so we won't know until the end what the condition is.
#[derive(Debug, Clone)]
pub struct VariableInfo {
    pub kconfig_dependencies: Vec<OrExpression>,
    pub kconfig_ranges: Vec<Range>,
    pub kconfig_defaults: Vec<DefaultAttribute>,
    pub visibility: Vec<OrExpression>,
    pub selects: Vec<(String, Option<Expression>)>,
}

impl TypeInfo {
    fn new_empty() -> Self {
        Self {
            kconfig_type: None,
            selected_by: HashMap::new(),
            variable_info: HashMap::new(),
        }
    }

    fn insert(
        &mut self,
        kconfig_type: Option<Type>,
        raw_constraints: Vec<OrExpression>,
        kconfig_ranges: Vec<Range>,
        kconfig_defaults: Vec<DefaultAttribute>,
        visibility: Vec<OrExpression>,
        arch: Option<String>,
        definition_condition: Vec<OrExpression>,
        selected_by: Option<(String, Option<Expression>)>,
        selects: Vec<(String, Option<Expression>)>,
    ) {
        // type merge
        match (&self.kconfig_type, &kconfig_type) {
            (None, Some(_)) => self.kconfig_type = kconfig_type,
            (Some(_), Some(new)) if Some(new) != self.kconfig_type.as_ref() => {
                debug!(
                    "NOTE: different type {:?} (existing {:?})",
                    kconfig_type, self.kconfig_type
                );
            }
            _ => {}
        }

        // selected_by merge
        if let Some(sb) = selected_by {
            merge_selected_by(&mut self.selected_by, arch.clone(), sb);
        }

        // variable_info merge
        insert_variable_info(
            &mut self.variable_info,
            arch,
            definition_condition,
            VariableInfo {
                kconfig_dependencies: raw_constraints,
                kconfig_ranges,
                kconfig_defaults,
                visibility,
                selects,
            },
        );
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
        selected_by: Option<(String, Option<Expression>)>,
        selects: Vec<(String, Option<Expression>)>,
    ) {
        let entry = self.raw.entry(var.clone());

        match entry {
            hash_map::Entry::Vacant(v) => {
                let mut t = TypeInfo::new_empty();
                t.insert(
                    kconfig_type,
                    raw_constraints,
                    kconfig_ranges,
                    kconfig_defaults,
                    visibility,
                    arch,
                    definition_condition,
                    selected_by,
                    selects,
                );
                v.insert(t);
            }

            hash_map::Entry::Occupied(mut o) => {
                let t = o.get_mut();

                t.insert(
                    kconfig_type,
                    raw_constraints,
                    kconfig_ranges,
                    kconfig_defaults,
                    visibility,
                    arch,
                    definition_condition,
                    selected_by,
                    selects,
                );
            }
        }
    }
}

fn merge_selected_by(
    map: &mut HashMap<String, Vec<(Arch, Option<Expression>)>>,
    arch: Option<String>,
    selected_by: (String, Option<Expression>),
) {
    map.entry(selected_by.0)
        .or_insert_with(Vec::new)
        .push((arch, selected_by.1));
}

fn insert_variable_info(
    map: &mut HashMap<Arch, Vec<(Vec<Expression>, VariableInfo)>>,
    arch: Option<String>,
    definition_condition: Vec<Expression>,
    info: VariableInfo,
) {
    map.entry(arch)
        .or_insert_with(Vec::new)
        .push((definition_condition, info));
}
