use nom_kconfig::{Entry, entry::Config};

/// Applies `visit_config` to every `config` and `menuconfig` in `entries`,
/// descending into `menu`, `choice`, and `if` containers. Entries that cannot
/// hold a config pass through unchanged.
pub fn map_configs(entries: Vec<Entry>, visit_config: fn(Config) -> Config) -> Vec<Entry> {
    entries
        .into_iter()
        .map(|entry| map_entry_configs(entry, visit_config))
        .collect()
}

fn map_entry_configs(entry: Entry, visit_config: fn(Config) -> Config) -> Entry {
    match entry {
        Entry::Config(config) => Entry::Config(visit_config(config)),
        Entry::MenuConfig(config) => Entry::MenuConfig(visit_config(config)),
        Entry::Menu(mut menu) => {
            menu.entries = map_configs(menu.entries, visit_config);
            Entry::Menu(menu)
        }
        Entry::Choice(mut choice) => {
            choice.entries = map_configs(choice.entries, visit_config);
            Entry::Choice(choice)
        }
        Entry::If(mut r#if) => {
            r#if.entries = map_configs(r#if.entries, visit_config);
            Entry::If(r#if)
        }
        other => other,
    }
}
