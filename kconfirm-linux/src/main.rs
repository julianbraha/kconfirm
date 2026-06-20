// SPDX-License-Identifier: GPL-2.0-only
use crate::getopt_ffi::Getopt;
use crate::getopt_ffi::REQUIRED_ARGUMENT;
use crate::getopt_ffi::option;
use kconfirm_lib::AnalysisArgs;
use kconfirm_lib::Check;
use kconfirm_lib::check_kconfig;
use kconfirm_lib::output::print_findings;
use kconfirm_lib::parse_check;
use kconfirm_linux::ALL_ARCHITECTURES;
use kconfirm_linux::collect_kconfig_root_files;
use nom_kconfig::KconfigInput;
use std::collections::HashSet;
use std::io;
use std::path::PathBuf;
use std::ptr;
mod getopt_ffi;

fn split_csv_arg(dst: &mut Vec<String>, value: &str) {
    dst.extend(
        value
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
    );
}

#[derive(Debug)]
pub struct Args {
    pub linux_path: PathBuf,
    pub enable_arch: Vec<String>,
    pub disable_arch: Vec<String>,
    pub enable_check: Vec<String>,
    pub disable_check: Vec<String>,
}

pub fn parse_args() -> Result<Args, String> {
    let mut linux_path: Option<PathBuf> = None;
    let mut enable_arch = Vec::new();
    let mut disable_arch = Vec::new();
    let mut enable_check = Vec::new();
    let mut disable_check = Vec::new();

    let long_options = [
        option {
            name: c"linux-path".as_ptr(),
            has_arg: REQUIRED_ARGUMENT,
            flag: ptr::null_mut(),
            val: 'l' as _,
        },
        option {
            name: c"enable-arch".as_ptr(),
            has_arg: REQUIRED_ARGUMENT,
            flag: ptr::null_mut(),
            val: 'a' as _,
        },
        option {
            name: c"disable-arch".as_ptr(),
            has_arg: REQUIRED_ARGUMENT,
            flag: ptr::null_mut(),
            val: 'x' as _,
        },
        option {
            name: c"enable-check".as_ptr(),
            has_arg: REQUIRED_ARGUMENT,
            flag: ptr::null_mut(),
            val: 'e' as _,
        },
        option {
            name: c"disable-check".as_ptr(),
            has_arg: REQUIRED_ARGUMENT,
            flag: ptr::null_mut(),
            val: 'd' as _,
        },
        option {
            name: ptr::null(),
            has_arg: 0,
            flag: ptr::null_mut(),
            val: 0,
        },
    ];

    let mut getopt = Getopt::new();

    getopt.reset();

    while let Some(result) = getopt.next(c"l:a:x:e:d:", &long_options) {
        let (opt, arg) = result?;

        match opt {
            'l' => {
                linux_path = Some(PathBuf::from(arg.unwrap()));
            }

            'a' => {
                split_csv_arg(&mut enable_arch, &arg.unwrap());
            }

            'x' => {
                split_csv_arg(&mut disable_arch, &arg.unwrap());
            }

            'e' => {
                split_csv_arg(&mut enable_check, &arg.unwrap());
            }

            'd' => {
                split_csv_arg(&mut disable_check, &arg.unwrap());
            }

            _ => {}
        }
    }

    let linux_path = linux_path.ok_or("--linux-path is required")?;

    if enable_arch.is_empty() {
        return Err("--enable-arch is required".into());
    }

    Ok(Args {
        linux_path,
        enable_arch,
        disable_arch,
        enable_check,
        disable_check,
    })
}

fn main() -> io::Result<()> {
    let cli_args = parse_args().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });
    let mut enabled_checks: HashSet<Check> = [
        Check::DuplicateDependency,
        Check::DuplicateRange,
        Check::DeadRange,
        Check::DuplicateSelect,
        Check::DeadDefault,
        Check::ConstantCondition,
        Check::DuplicateDefault,
        Check::DuplicateImply,
        Check::ReverseRange,
    ]
    .into_iter()
    .collect(); // apply --enable-check
    for name in &cli_args.enable_check {
        if let Some(c) = parse_check(name) {
            enabled_checks.insert(c);
        } else {
            eprintln!("Error: check {} does not exist", name);
            std::process::exit(1);
        }
    } // apply --disable-check
    for name in &cli_args.disable_check {
        if let Some(c) = parse_check(name) {
            enabled_checks.remove(&c);
        } else {
            eprintln!("Error: check {} does not exist", name);
            std::process::exit(1);
        }
    }
    let mut analysis_args = AnalysisArgs::new();
    for check in enabled_checks {
        analysis_args.enable_check(check);
    }
    let mut selected_arches: HashSet<String> = cli_args.enable_arch.iter().cloned().collect(); // apply --disable-arch
    for arch in &cli_args.disable_arch {
        selected_arches.remove(arch);
    }
    for desired_arch in &selected_arches {
        if !ALL_ARCHITECTURES.contains(&desired_arch.as_str()) {
            eprintln!("Error: unexpected architecture, please pass one of the following:");
            for available_arch in ALL_ARCHITECTURES {
                eprint!("{} ", available_arch);
            }
            eprintln!("");
            std::process::exit(1);
        }
    }
    let kconfig_files =
        collect_kconfig_root_files(selected_arches.into_iter().collect(), cli_args.linux_path)?;
    let kconfig_inputs: Vec<(Option<String>, KconfigInput)> = kconfig_files
        .iter()
        .map(|kconfig| {
            let kconfig_input =
                KconfigInput::new_extra(&kconfig.file_contents, kconfig.kconfig_file.clone());
            (Some(kconfig.arch_config_option.clone()), kconfig_input)
        })
        .collect();

    let findings = check_kconfig(analysis_args, kconfig_inputs);

    print_findings(findings);
    Ok(())
}
