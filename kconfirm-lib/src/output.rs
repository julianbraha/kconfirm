// SPDX-License-Identifier: GPL-2.0-only
use std::fmt;

use crate::Check;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Fatal,
    Error, // will be used for known bugs, e.g. unmet dependencies
    Warning,
    Style,
}

#[derive(Debug)]
pub struct Finding {
    pub severity: Severity,
    pub check: Check,
    pub symbol: Option<String>,
    pub message: String,
    pub arch: Option<String>,
}

impl Finding {
    fn fmt_with_arches(&self, f: &mut fmt::Formatter, arches: &[&str]) -> fmt::Result {
        let arch_part = if arches.is_empty() {
            String::new()
        } else {
            format!(" [{}]", arches.join(", "))
        };

        match &self.symbol {
            Some(s) => write!(
                f,
                "{} [{}]{} config {}: {}",
                self.severity,
                self.check.as_str(),
                arch_part,
                s,
                self.message
            ),
            None => write!(
                f,
                "{} [{}]{} {}",
                self.severity,
                self.check.as_str(),
                arch_part,
                self.message
            ),
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_with_arches(f, &[])
    }
}

pub fn print_findings(mut findings: Vec<Finding>) {
    findings.sort_by(|a, b| {
        (
            &a.severity,
            a.check.as_str(),
            &a.symbol,
            &a.message,
            &a.arch,
        )
            .cmp(&(
                &b.severity,
                b.check.as_str(),
                &b.symbol,
                &b.message,
                &b.arch,
            ))
    });

    for group in findings.chunk_by(|a, b| {
        a.severity == b.severity
            && a.check.as_str() == b.check.as_str()
            && a.symbol == b.symbol
            && a.message == b.message
    }) {
        let head = &group[0];

        let mut arches: Vec<&str> = Vec::new();
        for f in group {
            if let Some(a) = f.arch.as_deref() {
                if arches.last() != Some(&a) {
                    arches.push(a);
                }
            }
        }

        // Use a small wrapper so we can call our custom formatter via println!
        struct Wrap<'a>(&'a Finding, &'a [&'a str]);
        impl fmt::Display for Wrap<'_> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.0.fmt_with_arches(f, self.1)
            }
        }
        println!("{}", Wrap(head, &arches));
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Severity::Fatal => write!(f, "FATAL  "),
            Severity::Error => write!(f, "ERROR  "),
            Severity::Warning => write!(f, "WARNING"),
            Severity::Style => write!(f, "STYLE   "),
        }
    }
}
