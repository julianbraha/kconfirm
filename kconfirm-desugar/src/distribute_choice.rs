use nom_kconfig::{
    Attribute,
    Entry,
    attribute::depends_on::DependsOn,
    entry::Config, //
};

/// Distributes each `choice`'s dependencies onto every `config` option it
/// contains (recursively, through nested menus and choices).
///
/// The choice keeps its own dependency `options`; we only *copy* the
/// dependencies down onto the contained config options. (Will be combined by
/// the next pass)
pub fn visit_entries(entries: Vec<Entry>) -> Vec<Entry> {
    entries.into_iter().map(visit_entry).collect()
}

pub fn visit_entry(entry: Entry) -> Entry {
    match entry {
        Entry::Choice(mut choice) => {
            let deps = depends_on_options(&choice.options);
            // every config option inside the choice inherits the choice's dependencies.
            choice.entries = add_dependencies(choice.entries, &deps);
            // recurse so nested choices distribute their own dependencies too.
            choice.entries = visit_entries(choice.entries);
            Entry::Choice(choice)
        }
        // a menu may contain nested choices, so recurse to reach them.
        Entry::Menu(mut menu) => {
            menu.entries = visit_entries(menu.entries);
            Entry::Menu(menu)
        }
        other => other,
    }
}

/// Collect the `depends on` attributes from a choice's options.
fn depends_on_options(options: &[Attribute]) -> Vec<DependsOn> {
    options
        .iter()
        .filter_map(|option| match option {
            Attribute::DependsOn(dep) => Some(dep.clone()),
            _ => None,
        })
        .collect()
}

/// Add each of `deps` as a `depends on` to every config option in `entries`,
/// descending nested menus and choices.
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
