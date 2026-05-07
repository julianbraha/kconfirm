// SPDX-License-Identifier: GPL-2.0-only
use clap::Parser;
use std::collections::HashSet;
use std::io::{self};
use std::path::PathBuf;

use nom_kconfig::KconfigInput;

use kconfirm_lib::check_kconfig;
use kconfirm_lib::output::print_findings;
use kconfirm_lib::parse_check;
use kconfirm_lib::{AnalysisArgs, Check};
use kconfirm_linux::collect_kconfig_root_files;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, required = true)]
    linux_path: PathBuf,

    // enable specific checks (repeatable or comma-separated)
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    enable: Vec<String>,

    // disable specific checks
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    disable: Vec<String>,
}

fn main() -> io::Result<()> {
    env_logger::init();
    let cli_args = Args::parse();
    let mut enabled_checks: HashSet<Check> = [
        // need SMT solving before we can detect select-undefineds
        //Check::SelectUndefined,
        Check::DuplicateDependency,
        Check::DuplicateRange,
        Check::DeadRange,
        Check::DuplicateSelect,
        Check::DeadDefault,
        Check::ConstantCondition,
        Check::DuplicateDefault,
        Check::DuplicateImply,
        Check::BackwardsRange,
    ]
    .into_iter()
    .collect();

    // apply --enable
    for name in &cli_args.enable {
        if let Some(c) = parse_check(name) {
            enabled_checks.insert(c);
        }
    }

    // apply --disable
    for name in &cli_args.disable {
        if let Some(c) = parse_check(name) {
            enabled_checks.remove(&c);
        }
    }

    let analysis_args = AnalysisArgs { enabled_checks };

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
