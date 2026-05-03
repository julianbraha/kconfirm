mod common;
use crate::common::count_findings;
use crate::common::run_cli_on_fixture;

#[test]
fn test_invalid_kconfig_fixture() {
    let failed_parse_file = std::path::Path::new("tests/fixtures/failed_parse.Kconfig");

    let output = run_cli_on_fixture(
        &failed_parse_file,
        "duplicate_default_value,ungrouped_attribute",
        "dead_links",
    );
    let findings = count_findings(&output);

    let file_name = failed_parse_file.file_name().unwrap().to_string_lossy();

    assert_eq!(
        findings, 1,
        "expected 1 finding for {}, got {}:\n{}",
        file_name, findings, output
    );
}
