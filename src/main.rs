// SPDX-License-Identifier: GPL-2.0-only
use clap::Parser;
use std::io::{self};
use std::path::PathBuf;

use kconfirm::AnalysisArgs;
use kconfirm::check_kconfig;
use kconfirm::output::Finding;

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

    let findings = check_kconfig(analysis_args, linux_source)?;
    print_findings(findings);

    Ok(())
}
