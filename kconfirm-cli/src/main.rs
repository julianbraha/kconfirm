// SPDX-License-Identifier: GPL-2.0-only
use clap::Parser;
use std::io::{self};
use std::path::PathBuf;

use kconfirm_lib::AnalysisArgs;
use kconfirm_lib::check_kconfig;
use kconfirm_lib::output::Finding;
use nom_kconfig::{KconfigFile, KconfigInput};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // path to the linux source directory
    #[arg(long, required = true)]
    linux_path: PathBuf,

    // check for duplicate default values (style check)
    #[arg(long)]
    check_style: bool,

    // check for dead links in the help texts
    #[arg(long)]
    check_dead_links: bool,
}

fn print_findings(mut findings: Vec<Finding>) {
    findings.sort_by(|a, b| {
        (&a.severity, &a.check, &a.symbol).cmp(&(&b.severity, &b.check, &b.symbol))
    });

    for f in &findings {
        println!("{}", f);
    }
}

fn main() -> io::Result<()> {
    env_logger::init();
    let cli_args = Args::parse();
    let analysis_args = AnalysisArgs {
        check_style: cli_args.check_style,
        check_dead_links: cli_args.check_dead_links,
    };

    let linux_source = cli_args.linux_path;

    let root_kconfig_path = PathBuf::from("Kconfig"); // doesn't include the arch: arch/x86/Kconfig
    let root_kconfig_file = KconfigFile::new(linux_source.clone(), root_kconfig_path);
    let file_contents = root_kconfig_file.read_to_string().unwrap();
    let kconfig_input = KconfigInput::new_extra(&file_contents, root_kconfig_file);

    let findings = check_kconfig(analysis_args, vec![(None, kconfig_input)]);
    print_findings(findings);

    Ok(())
}
