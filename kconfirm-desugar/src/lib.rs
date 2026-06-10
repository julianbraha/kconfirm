mod combine_depends;
mod expand_def_type;
mod expand_source;
mod expand_type_prompt;

use nom_kconfig::{
    Entry,
    entry::Source, //
};

pub fn desugar_kconfig(source: Source) -> Vec<Entry> {
    let entries = expand_source::visit_source(source);

    let entries = combine_depends::visit_entries(entries);

    // a bit more efficient to run expand_type_prompt before expand_def_type
    let entries = expand_type_prompt::visit_entries(entries);

    let entries = expand_def_type::visit_entries(entries);

    entries
}
