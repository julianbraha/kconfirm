// a1532790b90c714ab3e51555b68d4df1539ad72b
use std::fs;
use std::process::Command;

#[test]
// system test
fn test_coreboot_kconfig_analysis_v24_12() {
    let tmp_dir = std::env::temp_dir().join("kconfirm_coreboot_test");
    let tar_path = tmp_dir.join("coreboot-26.03.tar.gz");
    let extract_dir = tmp_dir.join("coreboot-26.03");

    fs::create_dir_all(&tmp_dir).unwrap();

    // download if missing
    if !tar_path.exists() {
        let status = Command::new("curl")
            .args(["-L", "-o"])
            .arg(&tar_path)
            .arg("https://github.com/coreboot/coreboot/archive/refs/tags/26.03.tar.gz")
            .status()
            .expect("failed to run curl");

        assert!(status.success(), "download failed");
    }

    // extract if missing
    if !extract_dir.exists() {
        let status = Command::new("tar")
            .arg("-xzf")
            .arg(&tar_path)
            .arg("-C")
            .arg(&tmp_dir)
            .status()
            .expect("failed to extract");

        assert!(status.success(), "extract failed");
    }

    // run analysis via cli
    let output = Command::new("cargo")
        //.args(["run", "--quiet", "--", "--linux-path"])
        .args([
            "run",
            "-p",
            "kconfirm-cli",
            "--quiet",
            "--",
            "--coreboot-dir-path",
        ])
        .arg(&extract_dir)
        .arg("--check-style")
        // no --check-dead-links, the results vary do to forces outside our control
        // TODO: create a lighter test that there is >10 dead links or something.
        .output()
        .expect("failed to run cargo");

    assert!(
        output.status.success(),
        "analysis failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    let line_count = stdout.lines().count();

    assert!(
        line_count == 284,
        "expected 284 lines, got {}\n See output:\n{}",
        line_count,
        stdout
    );
}
