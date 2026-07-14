use nom_kconfig::{
    Attribute,
    Entry,
    attribute::Expression,
    entry::Config, //
};

use crate::utils::and_terms::and_expressions;

/// Distributes each `menu`s `visible if <cond>` condition onto the *prompt
/// conditions* of every `config` option the menu contains (recursively,
/// through nested menus and choices).
///
/// Options without a prompt are untouched (identity) Those are never visible.
///
/// Must run after `expand_type_prompt`, so every prompt is a standalone
/// `Attribute::Prompt`, and before `merge_partial_defs`, which may relocate
/// a definition's attributes outside the menu.
pub fn visit_entries(entries: Vec<Entry>) -> Vec<Entry> {
    entries.into_iter().map(visit_entry).collect()
}

fn visit_entry(entry: Entry) -> Entry {
    match entry {
        Entry::Menu(mut menu) => {
            // recurse first so nested menus distribute their own conditions
            menu.entries = visit_entries(menu.entries);
            // `visible` with no condition is a plain `visible`: a no-op
            if let Some(Some(condition)) = menu.visible.clone() {
                menu.entries = add_prompt_condition(menu.entries, &condition);
            }
            Entry::Menu(menu)
        }
        // a choice may contain nested menus, so recurse to reach them
        Entry::Choice(mut choice) => {
            choice.entries = visit_entries(choice.entries);
            Entry::Choice(choice)
        }
        other => other,
    }
}

/// ANDs `condition` with the prompt condition of every config option in
/// `entries`, descending through nested menus and choices (a nested menu's
/// contents are also hidden when the outer menu is).
fn add_prompt_condition(entries: Vec<Entry>, condition: &Expression) -> Vec<Entry> {
    entries
        .into_iter()
        .map(|entry| add_condition_to_entry(entry, condition))
        .collect()
}

fn add_condition_to_entry(entry: Entry, condition: &Expression) -> Entry {
    match entry {
        Entry::Config(config) => Entry::Config(guard_prompt(config, condition)),
        Entry::MenuConfig(config) => Entry::MenuConfig(guard_prompt(config, condition)),
        Entry::Menu(mut menu) => {
            menu.entries = add_prompt_condition(menu.entries, condition);
            Entry::Menu(menu)
        }
        Entry::Choice(mut choice) => {
            // the choice's own prompt lives in its options; member prompts
            // are in the contained entries
            choice.options = choice
                .options
                .into_iter()
                .map(|attribute| guard_prompt_attribute(attribute, condition))
                .collect();
            choice.entries = add_prompt_condition(choice.entries, condition);
            Entry::Choice(choice)
        }
        other => other,
    }
}

fn guard_prompt(mut config: Config, condition: &Expression) -> Config {
    config.attributes = config
        .attributes
        .into_iter()
        .map(|attribute| guard_prompt_attribute(attribute, condition))
        .collect();
    config
}

fn guard_prompt_attribute(attribute: Attribute, condition: &Expression) -> Attribute {
    match attribute {
        Attribute::Prompt(mut prompt) => {
            prompt.r#if = Some(match prompt.r#if {
                Some(existing) => and_expressions(existing, condition.clone()),
                None => condition.clone(),
            });
            Attribute::Prompt(prompt)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom_kconfig::{KconfigInput, parse_kconfig};

    fn parse_entries_for_test(text: &str) -> Vec<Entry> {
        parse_kconfig(KconfigInput::new_extra(text, Default::default()))
            .expect("kconfig text should parse")
            .1
            .entries
    }

    /// The MEDIA_CONTROLLER shape: an option with a prompt and a default
    /// inside a `visible if` menu keeps its default reachable but gets its
    /// prompt gated.
    #[test]
    fn visible_if_gates_prompts_not_defaults() {
        let entries = parse_entries_for_test(
            "
menu \"Media core support\"
	visible if !MEDIA_SUPPORT_FILTER

config MEDIA_CONTROLLER
	bool
	prompt \"Media Controller API\"
	default MEDIA_PLATFORM_SUPPORT

config MEDIA_HELPER
	bool

endmenu
",
        );
        let rewritten = visit_entries(entries);

        let Entry::Menu(menu) = &rewritten[0] else {
            panic!("expected the menu to survive");
        };
        let Entry::Config(controller) = &menu.entries[0] else {
            panic!("expected MEDIA_CONTROLLER");
        };

        // the prompt gained the menu's condition...
        let prompt = controller
            .attributes
            .iter()
            .find_map(|a| match a {
                Attribute::Prompt(p) => Some(p),
                _ => None,
            })
            .expect("prompt survives");
        let guard = prompt.r#if.as_ref().expect("prompt now conditional");
        assert!(format!("{guard}").contains("!MEDIA_SUPPORT_FILTER"));

        // ...while the default's condition is untouched
        let default = controller
            .attributes
            .iter()
            .find_map(|a| match a {
                Attribute::Default(d) => Some(d),
                _ => None,
            })
            .expect("default survives");
        assert!(default.r#if.is_none());

        // a promptless option stays promptless
        let Entry::Config(helper) = &menu.entries[1] else {
            panic!("expected MEDIA_HELPER");
        };
        assert!(
            !helper
                .attributes
                .iter()
                .any(|a| matches!(a, Attribute::Prompt(_)))
        );
    }

    /// In pipeline order (after expand_type_prompt), a typed prompt's
    /// condition conjoins with nested menu conditions.
    #[test]
    fn pipeline_order_conjoins_typed_prompts() {
        let entries = parse_entries_for_test(
            "
menu \"outer\"
	visible if !FILTER

menu \"inner\"
	visible if ADVANCED

config FOO
	bool \"foo\" if BAR

endmenu
endmenu
",
        );
        let entries = crate::expand_type_prompt::visit_entries(entries);
        let rewritten = visit_entries(entries);

        let Entry::Menu(outer) = &rewritten[0] else {
            panic!("outer menu");
        };
        let Entry::Menu(inner) = &outer.entries[0] else {
            panic!("inner menu");
        };
        let Entry::Config(foo) = &inner.entries[0] else {
            panic!("FOO");
        };
        let prompt = foo
            .attributes
            .iter()
            .find_map(|a| match a {
                Attribute::Prompt(p) => Some(p),
                _ => None,
            })
            .expect("prompt split out");
        let guard = format!("{}", prompt.r#if.as_ref().expect("conditional"));
        assert!(guard.contains("BAR"), "kept its own condition: {guard}");
        assert!(guard.contains("ADVANCED"), "inner menu condition: {guard}");
        assert!(guard.contains("!FILTER"), "outer menu condition: {guard}");
    }
}
