// SPDX-License-Identifier: GPL-2.0-only
use log::debug;
use nom_kconfig::Symbol;
use nom_kconfig::attribute::{
    AndExpression,
    Atom,
    DefaultAttribute,
    Expression,
    OrExpression,
    Range,
    Term,
    r#type::Type, //
};
use nom_kconfig::symbol::ConstantSymbol;
use nom_kconfig::tristate::Tristate;
use std::collections::{
    HashMap,
    hash_map, //
};
use std::str::FromStr;
use z3::ast::Bool as z3_bool;
use z3::ast::Int as z3_int;
use z3::ast::String as z3_string;

type KconfigSymbol = String;
type Arch = Option<String>;
type Cond = Option<Expression>;

/// The visibility condition of an unconditionally-visible `config` option (one with an
/// unconditional prompt): the constant `y`. Used as the `Some(true)` value of
/// [`AttributeDef::visibility`].
pub fn unconditional_visibility() -> Expression {
    OrExpression::Term(AndExpression::Term(Term::Atom(Atom::Symbol(
        Symbol::Constant(ConstantSymbol::Tristate(Tristate::Yes)),
    ))))
}

/// All of the type info of a Kconfig symbol. Since `config` options can have their attributes
/// spread out across multiple definitions, and can also be redefined in each architecture, the
/// Vectors are used for appending more information, and the architecture is tracked in each field.
///
/// # Examples
///
/// ```
/// use kconfirm_lib::SymbolTable;
///
/// // `TypeInfo` values are produced by analysis and stored in a `SymbolTable`,
/// // keyed by the config-option name.
/// let symtab = SymbolTable::new();
/// if let Some(type_info) = symtab.raw.get("EXAMPLE_OPTION") {
///     println!("Kconfig type: {:?}", type_info.kconfig_type);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct TypeInfo {
    /// The Kconfig type, such as bool or tristate.
    /// `None` is used when the type is unknown
    /// (e.g. dangling references, or for symbols without types).
    pub kconfig_type: Option<Type>,

    /// The Z3 type.
    /// `None` is used when the kconfig type is unknown or hasn't been transformed yet.
    pub z3_type: Option<Z3Types>,

    /// Maps the selector of this symbol to the architecture and the `select` condition.
    /// If the architecture is `None`, then it's not arch-specific.
    /// If the condition is `None`, then the `select` is unconditional.
    pub selected_by: HashMap<KconfigSymbol, Vec<(Arch, Cond)>>,

    /// Maps the architecture to the various partial definitions of the `config` option with their
    /// condition expressions.
    pub attribute_defs: HashMap<Arch, Vec<(Vec<Expression>, AttributeDef)>>,
}

impl TypeInfo {
    fn new_empty() -> Self {
        Self {
            kconfig_type: None,
            z3_type: None,
            selected_by: HashMap::new(),
            attribute_defs: HashMap::new(),
        }
    }

    // TODO: we should consider having separate functions for:
    // 1. merge-inserting a redef of attributes (NOTE: the type definition is actually part of the redef, but we aren't handling type-redefinitions for now)
    // 2. selectors
    fn insert(
        &mut self,
        kconfig_type: Option<Type>,
        raw_constraints: Option<OrExpression>,
        kconfig_ranges: Vec<Range>,
        kconfig_defaults: Vec<DefaultAttribute>,
        visibility: Option<OrExpression>,
        arch: Option<String>,
        definition_condition: Vec<OrExpression>,
        selected_by: Option<(KconfigSymbol, Cond)>,
        selects: Vec<(KconfigSymbol, Cond)>,
        implies: Vec<(KconfigSymbol, Cond)>,
    ) {
        // type merge
        match (&self.kconfig_type, &kconfig_type) {
            (None, Some(_)) => self.kconfig_type = kconfig_type.clone(),
            (Some(_), Some(new)) if Some(new) != self.kconfig_type.as_ref() => {
                // TODO: not doing anything with redefined types yet.
                //       later, we will want to consider e.g. bool/def_bool the same type (and possibly int/hex?) but not bool/tristate, so we need to build out typechecking.
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

        // variable_info merge:
        //   we only want to add an attribute redefinition if the things in the attribute def aren't empty
        //   (the visibility is just additional info to capture)
        if (&kconfig_type).is_some() // we need to ensure that we have an empty definition here if the config option had a type definition
            || raw_constraints.is_some()
            || !kconfig_ranges.is_empty()
            || !kconfig_defaults.is_empty()
            || !selects.is_empty()
            || !implies.is_empty()
        {
            insert_variable_info(
                &mut self.attribute_defs,
                arch,
                definition_condition,
                AttributeDef {
                    kconfig_dependencies: raw_constraints,
                    kconfig_ranges,
                    kconfig_defaults,
                    visibility,
                    selects,
                    implies,
                },
            );
        }
    }
}

/// kconfirm's wrapper around the Z3 types that we use, so that we can refer to them in the symbol
/// table.
///
/// Kconfig `tristate`, `int`, and `hex` types are all modeled as integers in SMT.
#[derive(Clone, Debug)]
pub enum Z3Types {
    Bool(z3_bool),
    Tristate(z3_int),
    String(z3_string),
    Integer(z3_int),
    Hex(z3_int),
}

impl Z3Types {
    /// Models enabling the config option in kconfig.
    ///
    /// E.g. for bool this is `true`, for tristate (modeled as an integer `i` in range `0 <= i <= 2`)
    ///     this is `i >= 1`.
    pub fn enabled(&self) -> z3_bool {
        return match self {
            Z3Types::Bool(b) => b.eq(z3_bool::from_bool(true)),
            Z3Types::Tristate(t) => t.ge(z3_int::from_u64(1)),

            // NOTE: there is no concept of "enabling" an integer, a condition `i` is always false.
            Z3Types::Integer(i) => panic!(
                "attempted to check if an Integer {} config option is enabled! This may be a bug in kconfig!",
                i
            ),
            // NOTE: there is no concept of "enabling" an integer, a condition `i` is always false.
            Z3Types::Hex(h) => panic!(
                "attempted to check if a Hex {} config option is enabled! This may be a bug in kconfig!",
                h
            ),

            // NOTE: there is no concept of "enabling" a string, a condition `S` is always false.
            Z3Types::String(s) => panic!(
                "attempted to check if a String {} config option is enabled! This may be a bug in kconfig!",
                s
            ),
        };
    }
}

/// Keeps track of the attributes of a `config` option. Each option may have multiple, partial
/// definitions spread out throughout Kconfig, and need to be merged.
///
/// # Examples
///
/// ```
/// use kconfirm_lib::AttributeDef;
///
/// // Built up incrementally as a config option's attributes are parsed.
/// let attributes = AttributeDef {
///     kconfig_dependencies: None,
///     kconfig_ranges: vec![],
///     kconfig_defaults: vec![],
///     visibility: None,
///     selects: vec![],
///     implies: vec![],
/// };
/// assert!(attributes.kconfig_dependencies.is_none());
/// ```
#[derive(Debug, Clone)]
pub struct AttributeDef {
    /// The combined dependency condition of the `config` option, or `None` if it has no
    /// dependencies. kconfirm-desugar folds every `depends on` (including those inherited from
    /// enclosing menus/choices/ifs) into this single expression.
    pub kconfig_dependencies: Option<OrExpression>,
    /// The `range` attributes of the `config` option. Only used for the `int` and `hex` types.
    pub kconfig_ranges: Vec<Range>,
    /// The `default` attributes of the `config` option. Order is preserved from the source.
    pub kconfig_defaults: Vec<DefaultAttribute>,
    /// The visibility condition of the `config` option, derived solely from its prompt:
    /// `None` if it has no prompt, `Some(`[`unconditional_visibility`]`())` (i.e. `y`) for an
    /// unconditional prompt, or `Some(cond)` for a `prompt ... if cond`.
    pub visibility: Option<OrExpression>,
    /// The `select` attributes of the `config` option. Represents reverse dependencies in Kconfig.
    pub selects: Vec<(KconfigSymbol, Cond)>,
    /// The `imply` attributes of the `config` option.
    pub implies: Vec<(KconfigSymbol, Cond)>,
}

/// The information about a Kconfig `choice`. Not a `config` option but still has attributes that
/// are effectively passed-down to its contained `config` options. Also has its own defaults, which
/// determine the contained config option that is automatically enabled.
///
/// # Examples
///
/// ```
/// use kconfirm_lib::ChoiceData;
///
/// // Captured while traversing a `choice` block during analysis.
/// let choice_block = ChoiceData {
///     arch: Some("arm64".to_string()),
///     visibility: None,
///     dependencies: vec![],
///     defaults: vec![],
/// };
/// assert_eq!(choice_block.arch.as_deref(), Some("arm64"));
/// ```
pub struct ChoiceData {
    /// The architecture that the `choice` appears in.
    pub arch: Arch,
    /// The visibility condition of the `choice`.
    pub visibility: Cond,
    /// The list of dependencies for the `choice`. In Kconfig semantics, contained `config` options
    /// inherit these dependencies.
    pub dependencies: Vec<OrExpression>,
    /// The list of defaults for the `choice`. In Kconfig semantics, these determine which `config`
    /// option is automatically set.
    pub defaults: Vec<DefaultAttribute>,
}

/// The analyzed type information for each `config` option. Also keeps track of the special
/// `modules` option, which determines if tristate `config` options can be set to `'m'`. `choice`s
/// are also stored here, despite not technically being `config` options. Backed by a hashmap.
///
/// # Examples
///
/// ```
/// use kconfirm_lib::SymbolTable;
///
/// let symtab = SymbolTable::new();
/// assert!(symtab.raw.is_empty());
/// assert!(symtab.modules_option.is_none());
/// ```
pub struct SymbolTable {
    /// The underlying hashmap that stores the configuration options and their associated type
    /// information.
    pub raw: HashMap<KconfigSymbol, TypeInfo>,
    /// All of the `choice` entries with their information in the analyzed Kconfig.
    pub choices: Vec<ChoiceData>,
    /// The special-purpose `config` option with the `modules` attribute.
    pub modules_option: Option<KconfigSymbol>, // None until we find the modules attribute in exactly 1 config option
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
        raw: HashMap<KconfigSymbol, TypeInfo>,
        choices: Vec<ChoiceData>,
        modules_option: Option<KconfigSymbol>,
    ) -> Self {
        SymbolTable {
            raw,
            choices,
            modules_option,
        }
    }

    /// Merges a `config` option's partial definition into the symbol table.
    /// If this is the first time this method has been called for this `config` option, then a new
    /// entry into the symbol table is created.
    pub fn merge_insert_new_solved(
        &mut self,
        var: KconfigSymbol,
        kconfig_type: Option<Type>,
        raw_constraints: Option<OrExpression>,
        kconfig_ranges: Vec<Range>,
        kconfig_defaults: Vec<DefaultAttribute>,
        visibility: Option<OrExpression>,
        arch: Arch,
        definition_condition: Vec<OrExpression>,
        selected_by: Option<(KconfigSymbol, Cond)>,
        selects: Vec<(KconfigSymbol, Cond)>,
        implies: Vec<(KconfigSymbol, Cond)>,
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
                    implies,
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
                    implies,
                );
            }
        }
    }
}

/// Adds the selector `config` symbol to the `selected_by` list for this `config` option into the
/// symbol table.
fn merge_selected_by(
    map: &mut HashMap<String, Vec<(Arch, Cond)>>,
    arch: Arch,
    selected_by: (KconfigSymbol, Cond),
) {
    map.entry(selected_by.0)
        .or_default() // empty vec
        .push((arch, selected_by.1));
}

/// Inserts the type information into the symbol table.
fn insert_variable_info(
    map: &mut HashMap<Arch, Vec<(Vec<Expression>, AttributeDef)>>,
    arch: Arch,
    definition_condition: Vec<Expression>,
    info: AttributeDef,
) {
    map.entry(arch)
        .or_default() // empty vec
        .push((definition_condition, info));
}
