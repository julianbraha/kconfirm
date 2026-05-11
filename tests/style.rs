use std::fs;

mod common;
use crate::common::count_findings;
use crate::common::run_cli_on_fixture;

#[test]
fn test_style_kconfig_fixtures() {
    let style_dir = std::path::Path::new("tests/fixtures/style");

    let entries = fs::read_dir(style_dir).expect("failed to read style directory");

    for entry in entries {
        let entry = entry.expect("bad dir entry");
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) != Some("Kconfig") {
            continue;
        }

        let output = run_cli_on_fixture(
            &path,
            "duplicate_default_value,ungrouped_attribute",
            "dead_links",
        );
        let findings = count_findings(&output);

        let file_name = path.file_name().unwrap().to_string_lossy();

        assert_eq!(
            findings, 1,
            "expected 1 finding for {}, got {}:\n{}",
            file_name, findings, output
        );
    }

    // Test the golden file from the parent fixtures directory
    let golden_path = std::path::Path::new("tests/fixtures/golden.Kconfig");
    let output = run_cli_on_fixture(
        &golden_path,
        "duplicate_default_value,ungrouped_attribute",
        "dead_links",
    );
    let findings = count_findings(&output);

    assert_eq!(
        findings, 0,
        "expected 0 findings for golden.Kconfig, got {}:\n{}",
        findings, output
    );
}
