// SPDX-License-Identifier: GPL-2.0-only
use crate::Check;
use std::fmt;

/// The level of severity of a [`Finding`].
///
/// Allows utilities like [`print_findings`] to sort issues by priority.
///
/// # Examples
///
/// ```
/// use kconfirm_lib::Severity;
///
/// // Ordering enables sorting alerts from most critical to stylistic.
/// assert!(Severity::Fatal > Severity::Error);
/// assert!(Severity::Warning > Severity::Style);
/// ```
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Opinionated style issues. Disabled by default.
    Style = 0,
    /// Issues that do not cause build failures, but are still unwanted.
    Warning = 1,
    /// Hard errors, such as unmet dependency bugs or cyclical dependencies.
    /// Currently unused.
    Error = 2,
    /// A critical error in the Kconfig, such as a parse failure.
    /// May prevent checks from running on the rest of the Kconfig.
    Fatal = 3,
}

/// An individual finding produced by a [`Check`] during analysis.
///
/// A `Finding` includes all of the context required to identify and categorize an instance of
/// Kconfig misuse. Individual findings are collected into a list during analysis and passed to
/// [`print_findings`] for aggregation and display.
///
/// # Examples
///
/// ```
/// use kconfirm_lib::{Check, Finding, Severity};
///
/// let alert = Finding {
///     severity: Severity::Warning,
///     check: Check::DeadLink,
///     symbol: Some("CONFIG_STAGING".to_string()),
///     message: "help text contains link to dead website".to_string(),
///     arch: Some("x86".to_string()),
/// };
///
/// // Custom `Display` formatting turns this into a scannable terminal line.
/// println!("{}", alert);
/// ```
#[derive(Debug)]
pub struct Finding {
    /// The impact level of the finding.
    pub severity: Severity,
    /// The specific check that produced the finding.
    pub check: Check,
    /// The `config` option whose definition contains the detected misuse.
    pub symbol: Option<String>,
    /// A human-readable diagnostic message, intended for use when displaying the finding to the user.
    pub message: String,
    /// The architecture affected by the finding. `None` represents a finding that affects all
    /// architectures (not arch-specific).
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

/// Sorts, aggregates, and prints check findings to stdout.
///
/// Aggregation is performed using severity, check type, symbol, and diagnostic message.
///
/// For Linux, if multiple findings are identical but occur across different target
/// architectures (the `arch` field), they are collapsed into a single printed output line with
/// the corresponding architectures grouped within brackets (e.g., `[x86, arm64]`).
///
/// # Examples
///
/// ```
/// use kconfirm_lib::{print_findings, Check, Finding, Severity};
///
/// let findings = vec![
///     Finding {
///         severity: Severity::Warning,
///         check: Check::ReverseRange,
///         symbol: Some("CONFIG_EXAMPLE".to_string()),
///         message: "reverse range, no value is valid".to_string(),
///         arch: Some("x86".to_string()),
///     },
///     Finding {
///         severity: Severity::Warning,
///         check: Check::ReverseRange,
///         symbol: Some("CONFIG_EXAMPLE".to_string()),
///         message: "reverse range, no value is valid".to_string(),
///         arch: Some("arm64".to_string()),
///     },
/// ];
///
/// // Prints:
/// // WARNING [reverse_range] [x86, arm64] config CONFIG_EXAMPLE: reverse range, no value is valid
/// print_findings(findings);
/// ```
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
