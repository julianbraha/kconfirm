// SPDX-License-Identifier: GPL-2.0-only
use nom_kconfig::KconfigFile;
use std::io;
use std::path::PathBuf;

pub const ALL_ARCHITECTURES: [&str; 21] = [
    "arm",
    "arm64",
    "x86",
    "riscv",
    "mips",
    "xtensa",
    "sparc",
    "alpha",
    "arc",
    "csky",
    "hexagon",
    "loongarch",
    "m68k",
    "microblaze",
    "nios2",
    "openrisc",
    "parisc",
    "powerpc",
    "s390",
    "sh",
    "um",
];

// each architecture has its own directory, and config option.
// most are the same, but powerpc / ppc and um / uml are not.
// this maps the directory to the config option
pub fn arch_dir_to_config(arch_dir: &str) -> String {
    match arch_dir {
        "powerpc" => String::from("PPC"),
        "um" => String::from("UML"),
        _ => String::from(arch_dir).to_uppercase(),
    }
}

pub struct LinuxKconfig {
    pub arch_config_option: String,
    pub kconfig_file: KconfigFile,
    pub file_contents: String,
}

// collects the root kconfig file, and all of the arch-specific kconfig files
pub fn collect_kconfig_root_files(
    archs: Vec<String>,
    linux_source: PathBuf,
) -> io::Result<Vec<LinuxKconfig>> {
    let mut all_root_kconfig_files = Vec::new();

    // add the root kconfig file
    let root_kconfig_path = PathBuf::from("Kconfig"); // doesn't include the arch: arch/x86/Kconfig
    let root_kconfig_file = KconfigFile::new(linux_source.clone(), root_kconfig_path.clone());

    for arch_dir in archs {
        let mut cur_root_kconfig_file = root_kconfig_file.clone();

        if arch_dir == "um" {
            // this is only used by the 'um' architecture to include arch/x86/um/Kconfig
            cur_root_kconfig_file.add_local_var("HEADER_ARCH", "x86");
        }

        cur_root_kconfig_file.add_local_var("SRCARCH", &arch_dir);

        let linux_kconfig = LinuxKconfig {
            arch_config_option: arch_dir_to_config(&arch_dir),
            file_contents: root_kconfig_file.read_to_string()?,
            kconfig_file: cur_root_kconfig_file,
        };

        all_root_kconfig_files.push(linux_kconfig);
    }

    Ok(all_root_kconfig_files)
}
