// SPDX-License-Identifier: GPL-2.0-only

use log::{debug, info, warn};
use std::io;
//use nom_kconfig::Entry;
use nom_kconfig::KconfigFile;

//use nom_kconfig::{KconfigInput, parse_kconfig};

use std::path::PathBuf;

// each architecture has its own directory, and config option.
// most are the same, but powerpc / ppc and um / uml are not.
// this maps the directory to the config option
pub fn arch_dir_to_config(arch_dir: &str) -> String {
    match arch_dir {
        "arm" => String::from("ARM"),
        "arm64" => String::from("ARM64"),
        "x86" => String::from("X86"),
        "riscv" => String::from("RISCV"),
        "mips" => String::from("MIPS"),
        "xtensa" => String::from("XTENSA"),
        "sparc" => String::from("SPARC"),
        "alpha" => String::from("ALPHA"),
        "arc" => String::from("ARC"),
        "csky" => String::from("CSKY"),
        "hexagon" => String::from("HEXAGON"),
        "loongarch" => String::from("LOONGARCH"),
        "m68k" => String::from("M68K"),
        "microblaze" => String::from("MICROBLAZE"),
        "nios2" => String::from("NIOS2"),
        "openrisc" => String::from("OPENRISC"),
        "parisc" => String::from("PARISC"),
        "powerpc" => String::from("PPC"),
        "s390" => String::from("S390"),
        "sh" => String::from("SH"),
        "um" => String::from("UML"),

        _ => {
            warn!(
                "unexpected directory in /arch/ was a new architecture added: {} ?
                Assuming the config option is the same as the directory name...",
                arch_dir
            );
            String::from(arch_dir).to_uppercase()
        }
    }
}

pub struct LinuxKconfig {
    pub arch_config_option: Option<String>, // not used for the root kconfig
    pub kconfig_file: KconfigFile,
    pub file_contents: String,
}

// returns a 2-tuple of the arch config option and its root kconfig file
pub fn get_arch_kconfig_files(
    linux_root: PathBuf,
    arch_dir_path: PathBuf,
) -> std::io::Result<Vec<LinuxKconfig>> {
    let mut arch_kconfigs = Vec::new();

    // the Kconfig.debug files in each architecture aren't sourced, so we need to collect them and any other kconfig files recursively
    for dir_entry in walkdir::WalkDir::new(arch_dir_path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        info!("dir_entry: {:?}", dir_entry);
        let path = dir_entry.path();

        if path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|ext| ext.starts_with("Kconfig")) // was .eq() but we need e.g. arch/arm64/Kconfig.platforms
            .unwrap_or(false)
        {
            /*if path.components().any(|component| {
                component
                    .as_os_str()
                    .to_str()
                    .is_some_and(|s| s == "scripts" || s == "tools")
            }) {
                info!("NOTE: skipping the scripts dir for now...");
                continue;
            }*/

            debug!("Opening: {}", path.display());

            //let linux_root = PathBuf::from(LINUX_SOURCE);

            let path_no_root = path.strip_prefix(&linux_root).unwrap();

            let pathbuf_no_root = PathBuf::from(path_no_root);

            let cur_kconfig_file = KconfigFile::new(linux_root.clone(), pathbuf_no_root.clone());

            if let std::path::Component::Normal(n) = path_no_root.components().nth(1).unwrap() {
                let arch_dir = n.to_str().unwrap();
                debug!("arch_dir: {}", arch_dir);
                if linux_root.join("arch").join(arch_dir).is_dir() {
                    let arch_config_option = arch_dir_to_config(&arch_dir);
                    let arch_kconfig = LinuxKconfig {
                        arch_config_option: Some(arch_config_option),
                        file_contents: cur_kconfig_file.read_to_string()?,
                        kconfig_file: cur_kconfig_file,
                    };
                    arch_kconfigs.push(arch_kconfig);
                }
            };
        }
    }

    Ok(arch_kconfigs)
}

// collects the root kconfig file, and all of the arch-specific kconfig files
pub fn collect_kconfig_root_files(linux_source: PathBuf) -> io::Result<Vec<LinuxKconfig>> {
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
