// SPDX-License-Identifier: GPL-2.0-only
use clap::{ArgGroup, Parser};
use log::info;
use std::fs;
use std::io;
use std::path::PathBuf;

use nom_kconfig::{KconfigFile, KconfigInput};

use kconfirm_lib::AnalysisArgs;
use kconfirm_lib::check_kconfig;
use kconfirm_lib::output::{Finding, print_findings};
use kconfirm_linux::collect_kconfig_root_files;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = None,
    group(
        ArgGroup::new("source")
            .args(["linux_path", "coreboot_path"])
            .required(true)
    )
)]
struct Args {
    // path to the linux source directory
    #[arg(long)]
    linux_path: Option<PathBuf>,

    // path to the coreboot source directory
    #[arg(long)]
    coreboot_path: Option<PathBuf>,

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

    let findings: Vec<Finding>;
    match (cli_args.linux_path, cli_args.coreboot_path) {
        (Some(linux_path), _) => {
            let kconfig_files = collect_kconfig_root_files(linux_path)?;
            let kconfig_inputs = kconfig_files
                .iter()
                .map(|kconfig| {
                    let kconfig_input = KconfigInput::new_extra(
                        &kconfig.file_contents,
                        kconfig.kconfig_file.clone(),
                    );

                    (kconfig.arch_config_option.clone(), kconfig_input)
                })
                .collect();
            findings = check_kconfig(analysis_args, kconfig_inputs);
        }
        (_, Some(coreboot_path)) => {
            let root_kconfig_path = PathBuf::from("src/Kconfig");
            let root_kconfig_file = KconfigFile::new(coreboot_path.clone(), root_kconfig_path);
            let file_contents = root_kconfig_file.read_to_string().unwrap();
            let kconfig_input = KconfigInput::new_extra(&file_contents, root_kconfig_file);
            let kconfig_inputs = vec![(None, kconfig_input)];

            let site_local_dir = coreboot_path.join("site-local");
            let site_local_kconfig = site_local_dir.join("Kconfig");

            let mut created_dir = false;
            let mut temp_kconfig = None;
            if !site_local_kconfig.exists() {
                info!(
                    "coreboot/site-local/Kconfig was missing. Attempting to create it temporarily..."
                );
                if !site_local_dir.exists() {
                    fs::create_dir(&site_local_dir)?;
                    info!("coreboot/site-local/ was created temporarily.");
                    created_dir = true;
                }

                temp_kconfig = Some(fs::File::create_new(&site_local_kconfig)?);
                info!("coreboot/site-local/Kconfig was created temporarily.");
            }

            //write!(tmpfile, "Hello World!").unwrap();
            findings = check_kconfig(analysis_args, kconfig_inputs);

            if temp_kconfig.is_some() {
                fs::remove_file(site_local_kconfig)?;
                info!("Cleaned up coreboot/site-local/Kconfig.");
            }

            if created_dir {
                fs::remove_dir(site_local_dir)?;
                info!("Cleaned up coreboot/site-local/.");
            }
        }
        _ => unreachable!("clap ensures that these arguments are mutually-exclusive"),
    }

    print_findings(findings);

    Ok(())
}
