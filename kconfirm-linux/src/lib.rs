// SPDX-License-Identifier: GPL-2.0-only

use log::warn;
use std::io;
use std::path::PathBuf;

use nom_kconfig::KconfigFile;

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

    for entry in walkdir::WalkDir::new(arch_dir_path)
        .max_depth(2)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();

        // filter for "Kconfig" prefix
        if !path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|n| n.starts_with("Kconfig"))
        {
            continue;
        }

        // get the arch from the path (e.g. x86 in /arch/x86/)
        let relative_path = path.strip_prefix(&linux_root).unwrap();
        let arch_dir = match relative_path.components().nth(1) {
            Some(std::path::Component::Normal(n)) => n.to_string_lossy(),
            _ => continue,
        };

        if linux_root.join("arch").join(&*arch_dir).is_dir() {
            let kconfig_file = KconfigFile::new(linux_root.clone(), relative_path.to_path_buf());
            arch_kconfigs.push(LinuxKconfig {
                arch_config_option: Some(arch_dir_to_config(&arch_dir)),
                file_contents: kconfig_file.read_to_string()?,
                kconfig_file,
            });
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
        file_contents: root_kconfig_file.read_to_string()?,
        kconfig_file: root_kconfig_file,
    };
    all_root_kconfig_files.push(root_kconfig);

    // add the arch kconfig files
    let arch_dir_path = linux_source.join("arch");
    let arch_kconfig_files = get_arch_kconfig_files(linux_source, arch_dir_path)?;
    all_root_kconfig_files.extend(arch_kconfig_files);

    Ok(all_root_kconfig_files)
}
