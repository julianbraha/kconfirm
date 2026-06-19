use nom_kconfig::{
    Attribute,
    Entry,
    attribute::{
        DefaultAttribute,
        r#type::{
            ConfigType,
            Type::{
                self, Bool, DefBool, DefHex, DefInt, DefString, DefTristate, Hex, Int, String,
                Tristate,
            },
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
                DefBool(db) => {
                    let type_definition = Attribute::Type(ConfigType {
                        r#type: Type::Bool(None),
                        r#if: None,
                    });

                    let default = Attribute::Default(DefaultAttribute {
                        expression: db.to_owned(),
                        r#if: None,
                    });

                    transformed_attributes.push(type_definition);
                    transformed_attributes.push(default);
                }
                DefTristate(dt) => {
                    let type_definition = Attribute::Type(ConfigType {
                        r#type: Type::Tristate(None),
                        r#if: None,
                    });

                    let default = Attribute::Default(DefaultAttribute {
                        expression: dt.to_owned(),
                        r#if: None,
                    });

                    transformed_attributes.push(type_definition);
                    transformed_attributes.push(default);
                }
                DefString(dt) => {
                    let type_definition = Attribute::Type(ConfigType {
                        r#type: Type::String(None),
                        r#if: None,
                    });

                    let default = Attribute::Default(DefaultAttribute {
                        expression: dt.to_owned(),
                        r#if: None,
                    });

                    transformed_attributes.push(type_definition);
                    transformed_attributes.push(default);
                }
                DefInt(dt) => {
                    let type_definition = Attribute::Type(ConfigType {
                        r#type: Type::Int(None),
                        r#if: None,
                    });

                    let default = Attribute::Default(DefaultAttribute {
                        expression: dt.to_owned(),
                        r#if: None,
                    });

                    transformed_attributes.push(type_definition);
                    transformed_attributes.push(default);
                }
                DefHex(dt) => {
                    let type_definition = Attribute::Type(ConfigType {
                        r#type: Type::Hex(None),
                        r#if: None,
                    });

                    let default = Attribute::Default(DefaultAttribute {
                        expression: dt.to_owned(),
                        r#if: None,
                    });

                    transformed_attributes.push(type_definition);
                    transformed_attributes.push(default);
                }
                Bool(t) | Tristate(t) | Int(t) | Hex(t) | String(t) => {
                    // prompts should have been expanded in a previous pass
                    assert!(t.is_none());
                    // identity
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
