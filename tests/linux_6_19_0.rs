use std::fs;
use std::process::Command;

#[test]
// system test
fn test_linux_kconfig_analysis_v6_19() {
    let tmp_dir = std::env::temp_dir().join("kconfirm_linux_test");
    let tar_path = tmp_dir.join("linux-6.19.tar.xz");
    let extract_dir = tmp_dir.join("linux-6.19");

    fs::create_dir_all(&tmp_dir).unwrap();

    // download if missing
    if !tar_path.exists() {
        let status = Command::new("curl")
            .args(["-L", "-o"])
            .arg(&tar_path)
            .arg("https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.19.tar.xz")
            .status()
            .expect("failed to run curl");

        assert!(status.success(), "download failed");
    }

    // extract if missing
    if !extract_dir.exists() {
        let status = Command::new("tar")
            .arg("-xf")
            .arg(&tar_path)
            .arg("-C")
            .arg(&tmp_dir)
            .status()
            .expect("failed to extract");

        assert!(status.success(), "extract failed");
    }

    // run analysis via cli
    let output = Command::new("cargo")
        .args([
            "run",
            "-p",
            "kconfirm-cli",
            "--quiet",
            "--",
            "--linux-dir-path",
        ])
        .arg(&extract_dir)
        // explicitly enable style, keep dead_links disabled
        .args(["--enable", "style", "--disable", "dead_links"])
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
        line_count == 929,
        "expected 929 lines, got {}\n See output:\n{}",
        line_count,
        stdout
    );
}
