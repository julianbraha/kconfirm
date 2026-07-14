use nom_kconfig::{
    Attribute,
    Entry,
    attribute::{
        Expression, Prompt,
        r#type::{
            ConfigType,
            Type::{self, Bool, Hex, Int, String, Tristate},
        },
    },
    entry::Config, //
};

use crate::utils::map_configs::map_configs;

/// Visits every config/menuconfig, descending into menus and choices.
pub fn visit_entries(entries: Vec<Entry>) -> Vec<Entry> {
    map_configs(entries, visit_config)
}

// Splits a typed prompt (e.g. `bool "pompt" if cond`) into a standalone `prompt "p" if cond`
// attribute plus a bare type (`bool`). The type's `if` condition is the prompt's
// visibility condition, so it is carried onto the split-out prompt.
pub fn visit_config(config: Config) -> Config {
    let mut transformed_attributes = Vec::new();

    for attribute in config.attributes {
        match attribute {
            Attribute::Type(ConfigType {
                r#type,
                r#if: prompt_if,
            }) => match r#type {
                Bool(prompt) => {
                    split_typed_prompt(prompt, prompt_if, Bool(None), &mut transformed_attributes)
                }
                Tristate(prompt) => split_typed_prompt(
                    prompt,
                    prompt_if,
                    Tristate(None),
                    &mut transformed_attributes,
                ),
                String(prompt) => {
                    split_typed_prompt(prompt, prompt_if, String(None), &mut transformed_attributes)
                }
                Int(prompt) => {
                    split_typed_prompt(prompt, prompt_if, Int(None), &mut transformed_attributes)
                }
                Hex(prompt) => {
                    split_typed_prompt(prompt, prompt_if, Hex(None), &mut transformed_attributes)
                }
                // def_bool, def_tristate, etc. don't carry a prompt; leave them unchanged.
                other => transformed_attributes.push(Attribute::Type(ConfigType {
                    r#type: other,
                    r#if: prompt_if,
                })),
            },
            other => transformed_attributes.push(other),
        }
    }

    Config {
        attributes: transformed_attributes,
        symbol: config.symbol,
    }
}

/// Split the standalone prompt (when present) with the visibility condition, then the type.
fn split_typed_prompt(
    prompt: Option<std::string::String>,
    prompt_if: Option<Expression>,
    bare_type: Type,
    out: &mut Vec<Attribute>,
) {
    if let Some(prompt) = prompt {
        out.push(Attribute::Prompt(Prompt {
            prompt,
            r#if: prompt_if,
        }));
    }

    out.push(Attribute::Type(ConfigType {
        r#type: bare_type,
        r#if: None,
    }));
}
