use nom_kconfig::{Entry, entry::Source};

// there is no concept of files in the desugared kconfig, so at the highest level, we just have a list of entries
pub fn visit_source(source: Source) -> Vec<Entry> {
    let mut all_entries = Vec::new();
    for kconfig in source.entries {
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
        _ => vec![entry],
    };
}
