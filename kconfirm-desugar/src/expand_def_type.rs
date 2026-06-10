use nom_kconfig::{
    Attribute,
    Entry,
    attribute::{
        DefaultAttribute,
        r#type::{
            ConfigType,
            Type::{self, DefBool, DefTristate},
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
                _ => {
                    // identity transformation
                    transformed_attributes.push(attribute);
                } // TODO: if linux adds def_string, def_int, def_hex
            },
            _ => transformed_attributes.push(attribute),
        }
    }

    Config {
        attributes: transformed_attributes,
        symbol: config.symbol.clone(),
    }
}
