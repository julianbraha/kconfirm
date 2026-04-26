use std::process::Command;

pub fn count_findings(output: &str) -> usize {
    // assumes each finding is one line
    output.lines().count()
}

pub fn run_cli_on_fixture(path: &std::path::Path, enable: &str, disable: &str) -> String {
    let output = Command::new("cargo")
        .args(["run", "-p", "kconfirm-cli", "--quiet", "--"])
        .args(["--other-kconfig-path"])
        .arg(path)
        .args(["--enable", enable, "--disable", disable])
        .output()
        .expect("failed to run cli");

    assert!(
        output.status.success(),
        "CLI failed on {:?}:\n{}",
        path,
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).to_string()
}
