use std::path::PathBuf;

mod common;
use crate::common::count_findings;
use crate::common::run_cli_on_fixture;

#[test]
fn test_dead_links() {
    // 1 dead link
    let dead_link_path = PathBuf::from("tests/fixtures/dead_links/dead_link.Kconfig");
    let output = run_cli_on_fixture(
        &dead_link_path,
        "dead_links",
        "duplicate_default_value,ungrouped_attribute",
    );
    let findings = count_findings(&output);
    let file_name = dead_link_path.file_name().unwrap().to_string_lossy();

    assert_eq!(
        findings, 1,
        "expected 1 finding for {}, got {}:\n{}",
        file_name, findings, output
    );
    // 0 dead links
    let golden_path = PathBuf::from("tests/fixtures/golden.Kconfig");
    let output = run_cli_on_fixture(
        &golden_path,
        "dead_links",
        "duplicate_default_value,ungrouped_attribute",
    );
    let findings = count_findings(&output);
    let file_name = golden_path.file_name().unwrap().to_string_lossy();

    assert_eq!(
        findings, 0,
        "expected 0 findings for {}, got {}:\n{}",
        file_name, findings, output
    );
}
