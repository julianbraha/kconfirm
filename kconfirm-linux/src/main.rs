// SPDX-License-Identifier: GPL-2.0-only
use nom_kconfig::{KconfigFile, KconfigInput};

use std::io::{self};
use std::path::PathBuf;

use kconfirm_lib::AnalysisArgs;
use kconfirm_lib::check_kconfig;
use kconfirm_lib::output::Finding;

mod linux;
use linux::*;

fn print_findings(mut findings: Vec<Finding>) {
    findings.sort_by(|a, b| {
        (&a.severity, &a.check, &a.symbol).cmp(&(&b.severity, &b.check, &b.symbol))
    });

    for f in &findings {
        println!("{}", f);
    }
}

// collects the root kconfig file, and all of the arch-specific kconfig files
fn collect_kconfig_root_files(linux_source: PathBuf) -> io::Result<Vec<LinuxKconfig>> {
    let mut all_root_kconfig_files = Vec::new();

    // add the root kconfig file
    let root_kconfig_path = PathBuf::from("Kconfig"); // doesn't include the arch: arch/x86/Kconfig
    let root_kconfig_file = KconfigFile::new(linux_source.clone(), root_kconfig_path.clone());
    let root_kconfig = LinuxKconfig {
        arch_config_option: None,
        file_contents: root_kconfig_file.read_to_string().unwrap(),
        kconfig_file: root_kconfig_file,
    };
    all_root_kconfig_files.push(root_kconfig);

    // add the arch kconfig files
    let arch_dir_path = linux_source.join("arch");
    let arch_kconfig_files = get_arch_kconfig_files(linux_source, arch_dir_path)?;
    all_root_kconfig_files.extend(arch_kconfig_files);

    Ok(all_root_kconfig_files)
}

fn main() -> io::Result<()> {
    env_logger::init();
    let analysis_args = AnalysisArgs {
        check_style: false,
        check_dead_links: false,
    };

    let linux_source = PathBuf::from("..");

    // includes the root, and the arch kconfig files
    let kconfig_files = collect_kconfig_root_files(linux_source)?;

    let kconfig_inputs = kconfig_files
        .iter()
        .map(|kconfig| {
            let kconfig_input =
                KconfigInput::new_extra(&kconfig.file_contents, kconfig.kconfig_file.clone());

            (kconfig.arch_config_option.clone(), kconfig_input)
        })
        .collect();

    let findings = check_kconfig(analysis_args, kconfig_inputs);
    print_findings(findings);

    Ok(())
}
