mod combine_depends;
mod expand_def_type;
mod expand_source;

use nom_kconfig::{
    Entry,
    entry::Source, //
};

pub fn desugar_kconfig(source: Source) -> Vec<Entry> {
    let entries = expand_source::visit_source(source);

    let entries = combine_depends::visit_entries(entries);

    let entries = expand_def_type::visit_entries(entries);

    entries
}
