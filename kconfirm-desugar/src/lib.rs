mod combine_depends;
mod distribute_choice;
mod distribute_if;
mod distribute_menu;
mod expand_def_type;
mod expand_depends_if;
mod expand_source;
mod expand_type_prompt;
mod merge_partial_defs;
mod utils;

#[cfg(test)]
mod tests;

use nom_kconfig::{
    Entry,
    entry::Source, //
};

pub fn desugar_kconfig(source: Source) -> Vec<Entry> {
    let entries = expand_source::visit_source(source);

    // simplifies 'depends on X if Y' into a plain dependency, so the passes
    // below only ever see plain `depends on` attributes.
    // also asserts that there are no `source` entries
    let entries = expand_depends_if::visit_entries(entries);

    // adds the condition in the if entry's expression as a `depends on` of every
    // contained config, and onto the dependency list of contained menu/choice
    // containers (their inner configs inherit it via the distribution passes
    // below), then removes the if entry. recurses into containers to flatten
    // nested ifs. also asserts there are no more 'depends on X if Y' attributes.
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

    // merges all partial definitions of each config option into a single
    // definition, placed where the earliest partial definition was — merging
    // across menu/choice boundaries, since the distribution passes above
    // already copied each container's dependencies onto its configs. each
    // partial definition's `depends on` is removed and ANDed onto the `if`
    // condition of that definition's own attributes; an option defined exactly
    // once keeps its `depends on`.
    let entries = merge_partial_defs::visit_entries(entries);

    // run expand_depends_if again due to partial definition merging introducing more of them.
    // TODO: is there an ordering of passes that wouldn't require a second pass of this?
    //       im pretty sure we'd need to rework at least one of the other passes...
    let entries = expand_depends_if::visit_entries(entries);

    entries
}
