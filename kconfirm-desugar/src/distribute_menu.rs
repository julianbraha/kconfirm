use nom_kconfig::{
    Attribute,
    Entry,
    attribute::depends_on::DependsOn,
    entry::Config, //
};

/// Distributes each `menu`'s dependencies onto every `config` option it
/// contains (recursively, through nested menus and choices).
///
/// The menu keeps its own `depends_on`; we only
/// *copy* the dependencies down onto the contained config options (will be
/// combined by a later pass.)
pub fn visit_entries(entries: Vec<Entry>) -> Vec<Entry> {
    entries.into_iter().map(visit_entry).collect()
}

pub fn visit_entry(entry: Entry) -> Entry {
    match entry {
        Entry::Menu(mut menu) => {
            // every config option inside the menu inherits the menu's dependencies.
            menu.entries = add_dependencies(menu.entries, &menu.depends_on);
            // recurse so nested menus distribute their own dependencies too.
            menu.entries = visit_entries(menu.entries);
            Entry::Menu(menu)
        }
        // a choice may contain nested menus, so recurse to reach them.
        Entry::Choice(mut choice) => {
            choice.entries = visit_entries(choice.entries);
            Entry::Choice(choice)
        }
        other => other,
    }
}

/// Add each of `deps` as a `depends on` to every config option in `entries`,
/// descending through nested menus and choices.
fn add_dependencies(entries: Vec<Entry>, deps: &[DependsOn]) -> Vec<Entry> {
    entries
        .into_iter()
        .map(|entry| add_dependencies_to_entry(entry, deps))
        .collect()
}

fn add_dependencies_to_entry(entry: Entry, deps: &[DependsOn]) -> Entry {
    match entry {
        Entry::Config(c) => Entry::Config(push_dependencies(c, deps)),
        Entry::MenuConfig(c) => Entry::MenuConfig(push_dependencies(c, deps)),
        Entry::Menu(mut menu) => {
            menu.entries = add_dependencies(menu.entries, deps);
            Entry::Menu(menu)
        }
        Entry::Choice(mut choice) => {
            choice.entries = add_dependencies(choice.entries, deps);
            Entry::Choice(choice)
        }
        other => other,
    }
}

fn push_dependencies(mut config: Config, deps: &[DependsOn]) -> Config {
    for dep in deps {
        config.attributes.push(Attribute::DependsOn(dep.clone()));
    }
    config
}
