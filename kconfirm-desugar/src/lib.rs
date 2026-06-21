mod combine_depends;
mod distribute_if;
mod expand_def_type;
mod expand_depends_if;
mod expand_source;
mod expand_type_prompt;
mod utils;

use nom_kconfig::{
    Entry,
    entry::Source, //
};

pub fn desugar_kconfig(source: Source) -> Vec<Entry> {
    let entries = expand_source::visit_source(source);

    // simplifies 'depends on X if Y'
    // also asserts that there are no `source` entries
    let entries = expand_depends_if::visit_entries(entries);

    // adds the condition in the if entry's expression as a depends-on attribute to all contained entries, and removes the if entry.
    // recurses into menu/choice containers to flatten nested ifs.
    // also asserts that there are no 'depends on X if Y' attributes
    let entries = distribute_if::visit_entries(entries);

    // copies each menu's dependencies down onto the config options it contains.
    let entries = distribute_menu::visit_entries(entries);

    // copies each choice's dependencies down onto the config options it contains.
    let entries = distribute_choice::visit_entries(entries);

    // combines all of the depends-on attributes for each config option (and for
    // menu/choice containers) into a single attribute, recursively.
    // also asserts that there are no `if` entries
    let entries = combine_depends::visit_entries(entries);

    // a bit more efficient to run expand_type_prompt before expand_def_type
    let entries = expand_type_prompt::visit_entries(entries);

    // expands def_bool and def_tristate into 2 attributes: default + bool/tristate
    // also asserts that there are no more prompts in type definitions
    let entries = expand_def_type::visit_entries(entries);

    entries
}
