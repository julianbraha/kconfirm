use nom_kconfig::{
    Attribute,
    Entry,
    attribute::{
        Prompt,
        r#type::{
            ConfigType,
            Type::{self, Bool, Hex, Int, String, Tristate},
        },
    },
    entry::Config, //
};

pub fn visit_entries(entries: Vec<Entry>) -> Vec<Entry> {
    let mut all_entries = Vec::new();
    for entry in entries {
        let cur_entries = visit_entry(entry);
        all_entries.extend(cur_entries);
    }
    all_entries
}

pub fn visit_entry(entry: Entry) -> Vec<Entry> {
    return match entry {
        Entry::Config(config) => {
            vec![Entry::Config(visit_config(config))]
        }
        _ => vec![entry],
    };
}

// Expands def_bool and def_tristate into default+bool/tristate
pub fn visit_config(config: Config) -> Config {
    let original_attributes = config.attributes;

    let mut transformed_attributes = Vec::new();

    for attribute in original_attributes {
        match &attribute {
            Attribute::Type(t) => match &t.r#type {
                Bool(b) => {
                    let type_definition = Attribute::Type(ConfigType {
                        r#type: Type::Bool(None),
                        r#if: None,
                    });

                    if let Some(b_prompt) = b {
                        let prompt = Attribute::Prompt(Prompt {
                            prompt: b_prompt.to_owned(),
                            r#if: None,
                        });
                        transformed_attributes.push(prompt);
                    }

                    transformed_attributes.push(type_definition);
                }
                Tristate(t) => {
                    let type_definition = Attribute::Type(ConfigType {
                        r#type: Type::Tristate(None),
                        r#if: None,
                    });

                    if let Some(t_prompt) = t {
                        let prompt = Attribute::Prompt(Prompt {
                            prompt: t_prompt.to_owned(),
                            r#if: None,
                        });
                        transformed_attributes.push(prompt);
                    }

                    transformed_attributes.push(type_definition);
                }
                String(s) => {
                    let type_definition = Attribute::Type(ConfigType {
                        r#type: Type::Tristate(None),
                        r#if: None,
                    });

                    if let Some(s_prompt) = s {
                        let prompt = Attribute::Prompt(Prompt {
                            prompt: s_prompt.to_owned(),
                            r#if: None,
                        });
                        transformed_attributes.push(prompt);
                    }

                    transformed_attributes.push(type_definition);
                }
                Int(i) => {
                    let type_definition = Attribute::Type(ConfigType {
                        r#type: Type::Tristate(None),
                        r#if: None,
                    });

                    if let Some(i_prompt) = i {
                        let prompt = Attribute::Prompt(Prompt {
                            prompt: i_prompt.to_owned(),
                            r#if: None,
                        });
                        transformed_attributes.push(prompt);
                    }

                    transformed_attributes.push(type_definition);
                }
                Hex(h) => {
                    let type_definition = Attribute::Type(ConfigType {
                        r#type: Type::Tristate(None),
                        r#if: None,
                    });

                    if let Some(h_prompt) = h {
                        let prompt = Attribute::Prompt(Prompt {
                            prompt: h_prompt.to_owned(),
                            r#if: None,
                        });
                        transformed_attributes.push(prompt);
                    }

                    transformed_attributes.push(type_definition);
                }
                _ => {
                    // identity transformation
                    // def_bool, def_tristate don't have prompts
                    transformed_attributes.push(attribute);
                }
            },
            _ => transformed_attributes.push(attribute),
        }
    }

    Config {
        attributes: transformed_attributes,
        symbol: config.symbol.clone(),
    }
}
