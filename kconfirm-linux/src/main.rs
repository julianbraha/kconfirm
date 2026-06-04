// SPDX-License-Identifier: GPL-2.0-only

use kconfirm_lib::{
    AnalysisArgs,
    Check,
    check_kconfig,
    output::print_findings,
    parse_check, //
};
use kconfirm_linux::collect_kconfig_root_files;
use libc::c_char;
use libc::getopt_long;
use libc::option;
use nom_kconfig::KconfigInput;
use std::collections::HashSet;
use std::env;
use std::ffi::{
    CStr,
    CString, //
};
use std::{
    io,
    path::PathBuf,
    ptr, //
};

const NO_ARGUMENT: i32 = 0;
const REQUIRED_ARGUMENT: i32 = 1;

unsafe extern "C" {
    static mut optarg: *mut c_char;
    static mut optind: i32;
}

fn split_csv_arg(dst: &mut Vec<String>, value: &str) {
    dst.extend(
        value
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
    );
}

fn parse_args() -> Result<Args, String> {
    let mut linux_path: Option<PathBuf> = None;
    let mut enable = Vec::new();
    let mut disable = Vec::new();

    let raw_args: Vec<String> = env::args().collect();

    let cstrings: Vec<CString> = raw_args
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();

    let mut argv: Vec<*mut c_char> = cstrings.iter().map(|s| s.as_ptr() as *mut c_char).collect();

    argv.push(ptr::null_mut());

    let argc = (argv.len() - 1) as i32;

    let long_options = [
        option {
            name: c"linux-path".as_ptr() as *const c_char,
            has_arg: REQUIRED_ARGUMENT,
            flag: ptr::null_mut(),
            val: 'l' as i32,
        },
        option {
            name: c"enable".as_ptr() as *const c_char,
            has_arg: REQUIRED_ARGUMENT,
            flag: ptr::null_mut(),
            val: 'e' as i32,
        },
        option {
            name: c"disable".as_ptr() as *const c_char,
            has_arg: REQUIRED_ARGUMENT,
            flag: ptr::null_mut(),
            val: 'd' as i32,
        },
        option {
            name: ptr::null(),
            has_arg: NO_ARGUMENT,
            flag: ptr::null_mut(),
            val: 0,
        },
    ];

    unsafe {
        // reset getopt global state
        optind = 1;

        loop {
            let c = getopt_long(
                argc,
                argv.as_mut_ptr(),
                c"l:e:d:".as_ptr() as *const c_char,
                long_options.as_ptr(),
                ptr::null_mut(),
            );

            if c == -1 {
                break;
            }

            match c as u8 as char {
                'l' => {
                    let arg = CStr::from_ptr(optarg).to_string_lossy().into_owned();

                    linux_path = Some(PathBuf::from(arg));
                }

                'e' => {
                    let arg = CStr::from_ptr(optarg).to_string_lossy().into_owned();

                    split_csv_arg(&mut enable, &arg);
                }

                'd' => {
                    let arg = CStr::from_ptr(optarg).to_string_lossy().into_owned();

                    split_csv_arg(&mut disable, &arg);
                }

                '?' => {
                    return Err("invalid argument".into());
                }

                _ => {}
            }
        }
    }

    let linux_path = linux_path.ok_or("--linux-path is required")?;

    Ok(Args {
        linux_path,
        enable,
        disable,
    })
}

#[derive(Debug)]
struct Args {
    linux_path: PathBuf,
    enable: Vec<String>,
    disable: Vec<String>,
}

fn main() -> io::Result<()> {
    let cli_args = parse_args().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    let mut enabled_checks: HashSet<Check> = [
        // need SMT solving before we can detect select-undefineds
        // Check::SelectUndefined,
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
