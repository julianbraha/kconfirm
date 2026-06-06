mod combine_depends;
mod expand_source;

use nom_kconfig::{
    Entry,
    entry::Source, //
};

pub fn desugar_kconfig(source: Source) -> Vec<Entry> {
    let entries = expand_source::visit_source(source);

    let entries = combine_depends::visit_entries(entries);

    entries
}
