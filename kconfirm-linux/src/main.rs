// SPDX-License-Identifier: GPL-2.0-only
use clap::Parser;
use std::io::{self};
use std::path::PathBuf;

use nom_kconfig::KconfigInput;

use kconfirm_lib::AnalysisArgs;
use kconfirm_lib::check_kconfig;
use kconfirm_lib::output::print_findings;
use kconfirm_linux::collect_kconfig_root_files;

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

fn main() -> io::Result<()> {
    env_logger::init();
    let cli_args = Args::parse();
    let analysis_args = AnalysisArgs {
        check_style: cli_args.check_style,
        check_dead_links: cli_args.check_dead_links,
    };

    let kconfig_files = collect_kconfig_root_files(cli_args.linux_path)?;
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
