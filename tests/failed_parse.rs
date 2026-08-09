mod common;
use crate::common::run_cli_on_fixture;

#[test]
fn test_invalid_kconfig_fixture() {
    let failed_parse_file = std::path::Path::new("tests/fixtures/failed_parse.Kconfig");

    let output = run_cli_on_fixture(
        &failed_parse_file,
        "duplicate_default_value,ungrouped_attribute",
        "dead_link",
    );

    // the parse error of nom-kconfig spans several lines, so we count the findings by their
    // check name instead of by line, like the other tests do.
    let findings = output.matches("[failed_parse]").count();

    let file_name = failed_parse_file.file_name().unwrap().to_string_lossy();

    assert_eq!(
        findings, 1,
        "expected 1 finding for {}, got {}:\n{}",
        file_name, findings, output
    );
}
