// SPDX-License-Identifier: GPL-2.0-only
use derive_more::TryInto;
use log::debug;

use nom_kconfig::attribute::{
    DefaultAttribute,
    Expression,
    OrExpression,
    Range,

    r#type::Type, //
};

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

/// All of the type info of a Kconfig symbol. kconfirm-desugar merges the partial definitions of
/// a `config` option into a single definition beforehand, so an option has at most one attribute
/// definition per architecture. `selected_by`/`implied_by` still accumulate one entry per
/// `select`/`imply` that references this option, since an option can be selected/implied any
/// number of times, and the architecture is tracked in each field.
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

    /// Maps the implier of this symbol to the architecture and the `imply` condition.
    /// If the architecture is `None`, then it's not arch-specific.
    /// If the condition is `None`, then the `imply` is unconditional.
    pub implied_by: HashMap<KconfigSymbol, Vec<(Arch, Cond)>>,

    /// Maps the architecture to the single (post-desugar) definition of the `config` option
    /// under that architecture.
    pub attribute_defs: HashMap<Arch, AttributeDef>,
}

impl TypeInfo {
    fn new_empty() -> Self {
        Self {
            kconfig_type: None,
            z3_type: None,
            selected_by: HashMap::new(),
            implied_by: HashMap::new(),
            attribute_defs: HashMap::new(),
        }
    }
}

/// kconfirm's wrapper around the Z3 types that we use, so that we can refer to them in the symbol
/// table.
///
/// Kconfig `bool` and `tristate` types are order-encoded as pairs of Z3 booleans
/// ([`z3_ternary::Ternary`]); `int` and `hex` are modeled as integers.
#[derive(Clone, Debug, TryInto)]
#[try_into(owned, ref)]
pub enum Z3Types {
    Bool(z3_bool), // used for expressions
    String(z3_string),
    Integer(z3_int), // models kconfig hex and actual kconfig int
    /// Models the kconfig bool and tristate types: the order-encoded pair
    /// ⟨"value ≥ m", "value = y"⟩ of Z3 booleans.
    Ternary(z3_ternary::Ternary),
}

impl Z3Types {
    /// Models enabling the config option in kconfig.
    ///
    /// E.g. for bool this is `true`, for tristate (order-encoded as a pair of booleans)
    ///     this is `value > n`, i.e. the pair's first component.
    pub fn enabled(&self) -> z3_bool {
        return match self {
            Z3Types::Bool(b) => b.eq(z3_bool::from_bool(true)),
            Z3Types::Ternary(t) => t.gt_n(),
            Z3Types::Integer(i) => i.ge(z3_int::from_u64(1)),

            // NOTE: there is no concept of "enabling" an integer, a condition `i` is always false.
            // BUT, integer options always default to 0 and will take that value when dependencies arent met (similar to disabled).
            // config options cant depend on an integer itself (only a condition checking the integer value with something specific).
            // Z3Types::Integer(i) => panic!(
            //     "attempted to enable Integer {}! This may be a bug in kconfig!",
            //     i
            // ),
            //Z3Types::Integer(i) | Z3Types::Hex(i) => i.ne(z3_int::from_i64(0)),
            // NOTE: there is no concept of "enabling" an integer, a condition `i` is always false.
            // Z3Types::Hex(h) => panic!(
            //     "attempted to enable Hex {}! This may be a bug in kconfig!",
            //     h
            // ),

            // NOTE: there is no concept of "enabling" a string, a condition `S` (without comparison to a specific value) is always false.
            // Z3Types::String(s) => panic!(
            //     "attempted to enable String {}! This may be a bug in kconfig!",
            //     s
            // ),
            // similarly to integer/hex in kconfig, strings don't have a concept of enabled" and options can't depend on strings alone (without a comparison to a specific value).
            // but, they default to the empty string, and take that value when dependencies not met."
            Z3Types::String(s) => s.ne(z3_string::from_str(&String::new()).unwrap()),
        };
    }
}

/// Keeps track of the attributes of a `config` option. An option's partial definitions, spread
/// out throughout Kconfig, have already been merged into a single definition per architecture by
/// kconfirm-desugar, so one `AttributeDef` holds all of an option's attributes under one
/// architecture.
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
    /// `None` if it has no prompt, `y` for an
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
///     config_options: vec![],
/// };
/// assert_eq!(choice_block.arch.as_deref(), Some("arm64"));
/// ```
pub struct ChoiceData {
    /// The architecture that the `choice` appears in.
    pub arch: Arch,
    /// The visibility condition of the `choice`.
    pub visibility: Cond,
    /// The list of dependencies for the `choice`. `config` options
    /// inherit these dependencies but this was already distributed in kconfirm-desugar.
    pub dependencies: Vec<OrExpression>,
    /// The list of defaults for the `choice`. In Kconfig semantics, these determine which `config`
    /// option is automatically set.
    pub defaults: Vec<DefaultAttribute>,

    /// The list of config options (with order preserved) in the choice .. endchoice block.
    /// Every option in this list should have an entry in the underlying symbol table hashmap `SymbolTable.raw`
    pub config_options: Vec<KconfigSymbol>,
}

/// The analyzed type information for each `config` option. Also keeps track of the special
/// `modules` option, which determines if tristate `config` options can be set to `m`. `choice`s
/// are also stored here.
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

    /// Records the definition of a `config` option under `arch`. Since kconfirm-desugar merges
    /// all partial definitions of a `config` option into one, this is called exactly once per
    /// (option, architecture) and panics on a second definition. The `TypeInfo` entry itself may
    /// already exist, created by a `select`/`imply` back-reference or by another architecture's
    /// definition.
    ///
    /// The Kconfig type can still be redefined across architectures: the first type seen wins,
    /// and mismatches are just logged.
    ///
    /// TODO: support running on multiple architectures at once, may need to duplicate these variables,
    /// in our constraints: e.g. X86_OPTION_NAME, ARM_OPTION_NAME
    pub fn insert_definition(
        &mut self,
        symbol: KconfigSymbol,
        arch: Arch,
        kconfig_type: Option<Type>,
        def: AttributeDef,
    ) {
        let info = self
            .raw
            .entry(symbol.clone())
            .or_insert_with(TypeInfo::new_empty);

        match (&info.kconfig_type, &kconfig_type) {
            (None, Some(_)) => info.kconfig_type = kconfig_type.clone(),
            (Some(_), Some(new)) if Some(new) != info.kconfig_type.as_ref() => {
                // TODO: not doing anything with redefined types yet.
                //       later, we will want to consider e.g. bool/def_bool the same type (and possibly int/hex?) but not bool/tristate, so we need to build out typechecking.
                debug!(
                    "NOTE: different type {:?} (existing {:?})",
                    kconfig_type, info.kconfig_type
                );
            }
            _ => {}
        }

        match info.attribute_defs.entry(arch) {
            hash_map::Entry::Vacant(slot) => {
                slot.insert(def);
            }
            hash_map::Entry::Occupied(slot) => panic!(
                "duplicate definition of {} under arch {:?}: partial definitions should have been merged in a previous pass",
                symbol,
                slot.key()
            ),
        }
    }

    /// Records that `selector` selects `symbol` (a reverse dependency), under `arch`, with the
    /// `select`'s condition. Creates `symbol`'s entry if this is the first reference to it. A
    /// `config` option can be selected any number of times, so entries accumulate.
    pub fn add_selected_by(
        &mut self,
        symbol: KconfigSymbol,
        arch: Arch,
        selector: KconfigSymbol,
        cond: Cond,
    ) {
        self.raw
            .entry(symbol)
            .or_insert_with(TypeInfo::new_empty)
            .selected_by
            .entry(selector)
            .or_default() // empty vec
            .push((arch, cond));
    }

    /// Records that `implier` implies `symbol`, under `arch`, with the `imply`'s condition.
    /// Creates `symbol`'s entry if this is the first reference to it. A `config` option can be
    /// implied any number of times, so entries accumulate.
    pub fn add_implied_by(
        &mut self,
        symbol: KconfigSymbol,
        arch: Arch,
        implier: KconfigSymbol,
        cond: Cond,
    ) {
        self.raw
            .entry(symbol)
            .or_insert_with(TypeInfo::new_empty)
            .implied_by
            .entry(implier)
            .or_default() // empty vec
            .push((arch, cond));
    }
}
