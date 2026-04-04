// SPDX-License-Identifier: GPL-2.0-only
use std::fmt;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Error, // will be used for known bugs, e.g. unmet dependencies
    Warning,
    Style,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Severity::Error => write!(f, "ERROR  "),
            Severity::Warning => write!(f, "WARNING"),
            Severity::Style => write!(f, "STYLE   "),
        }
    }
}

#[derive(Debug)]
pub struct Finding {
    pub severity: Severity,
    pub check: &'static str,
    pub symbol: Option<String>,
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.symbol {
            Some(s) => write!(
                f,
                "{} [{}] config {}: {}",
                self.severity, self.check, s, self.message
            ),
            None => write!(f, "{} [{}] {}", self.severity, self.check, self.message),
        }
    }
}
