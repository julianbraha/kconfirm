// SPDX-License-Identifier: GPL-2.0-only
use clap::{ArgGroup, Parser};
use log::{debug, error, info};
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
            .args(["linux_dir_path", "coreboot_dir_path", "other_kconfig_path"]) // NOTE: make sure to rename these strings when renaming the args
            .required(true)
    )
)]
struct Args {
    // path to the linux source directory
    #[arg(long)]
    linux_dir_path: Option<PathBuf>,

    // path to the coreboot source directory
    #[arg(long)]
    coreboot_dir_path: Option<PathBuf>,

    // pass the entry kconfig file (usually "Kconfig" or "Config.in")
    #[arg(long)]
    other_kconfig_path: Option<PathBuf>,

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
    match (
        cli_args.linux_dir_path,
        cli_args.coreboot_dir_path,
        cli_args.other_kconfig_path,
    ) {
        (Some(linux_path), None, None) => {
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

        // NOTE: seaBIOS also does the same thing (uses the directory a level above its root kconfig)
        (None, Some(coreboot_path), None) => {
            let root_kconfig_path = PathBuf::from("src/Kconfig");
            let root_kconfig_file = KconfigFile::new(coreboot_path.clone(), root_kconfig_path);
            let file_contents = root_kconfig_file.read_to_string()?;
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

            // TODO: ensure that if check_kconfig errors, then we still remove the dir and file that was created
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

        // other path
        (None, None, Some(other_kconfig_path)) => {
            // NOTE: this assumes that there is a file called "Kconfig" in the directory
            // TODO: it's "Config.in" for buildroot and busybox, consider having the user specify the file path instead of the directory
            if !other_kconfig_path.is_file() {
                error!(
                    "A directory was passed to '--other_kconfig_path'. Instead, please pass the kconfig entry file (probably 'Kconfig' or 'Config.in'."
                );
                panic!(); // TODO: create a KconfigError type that has io errors and CLI usage errors
            }

            let containing_dir = other_kconfig_path
                .parent()
                .expect("kconfig file is in a directory");
            debug!("attempting to parse using directory: {:?}", &containing_dir);
            let root_kconfig_file =
                KconfigFile::new(containing_dir.to_path_buf(), other_kconfig_path);
            let file_contents = root_kconfig_file.read_to_string().unwrap();
            let kconfig_input = KconfigInput::new_extra(&file_contents, root_kconfig_file);
            let kconfig_inputs = vec![(None, kconfig_input)];
            findings = check_kconfig(analysis_args, kconfig_inputs);
        }
        _ => unreachable!("clap ensures that these arguments are mutually-exclusive"),
    }

    print_findings(findings);

    Ok(())
}
