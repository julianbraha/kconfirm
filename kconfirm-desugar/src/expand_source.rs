use nom_kconfig::{Entry, entry::Source};

// there is no concept of files in the desugared kconfig, so at the highest level, we just have a list of entries
pub fn visit_source(source: Source) -> Vec<Entry> {
    let mut all_entries = Vec::new();
    for kconfig in source.kconfigs {
        for entry in kconfig.entries {
            let cur_entries = visit_entry(entry);
            all_entries.extend(cur_entries);
        }
    }
    all_entries
}

pub fn visit_entry(entry: Entry) -> Vec<Entry> {
    return match entry {
        Entry::Source(source) => visit_source(source),
        // `source` can also appear inside these containers, so recurse to expand
        // any sources nested within them.
        Entry::If(mut r#if) => {
            r#if.entries = visit_entries(r#if.entries);
            vec![Entry::If(r#if)]
        }
        Entry::Menu(mut menu) => {
            menu.entries = visit_entries(menu.entries);
            vec![Entry::Menu(menu)]
        }
        Entry::Choice(mut choice) => {
            choice.entries = visit_entries(choice.entries);
            vec![Entry::Choice(choice)]
        }
        _ => vec![entry],
    };
}

fn visit_entries(entries: Vec<Entry>) -> Vec<Entry> {
    entries.into_iter().flat_map(visit_entry).collect()
}
