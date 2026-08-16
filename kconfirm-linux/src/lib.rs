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

/// The host architecture implemented by UML in the Linux tree.
///
/// The kernel's `scripts/subarch.include` normalizes both x86_64 and i386
/// hosts to `x86`. UML uses that value to expose its `64BIT` prompt, so the
/// same Kconfig tree represents both its 32-bit and 64-bit configurations.
pub const UML_SUBARCH: &str = "x86";

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

/// The kernel arch name for a `uname -m` machine string
pub fn subarch(machine: &str) -> String {
    let machine = machine.trim();
    // one arm per sed expression, in the script's order
    if machine.len() == 4 && machine.starts_with('i') && machine.ends_with("86") {
        return String::from("x86"); // s/i.86/x86/
    }
    if machine == "x86_64" {
        return String::from("x86");
    }
    if machine == "sun4u" {
        return String::from("sparc64");
    }
    if machine != "arm64" && machine.starts_with("arm") {
        return String::from("arm"); // /^arm64$/!s/arm.*/arm/
    }
    if machine == "sa110" {
        return String::from("arm");
    }
    if machine == "s390x" {
        return String::from("s390");
    }
    if machine.starts_with("ppc") {
        return String::from("powerpc");
    }
    if machine.starts_with("mips") {
        return String::from("mips");
    }
    if machine.starts_with("sh2") || machine.starts_with("sh3") || machine.starts_with("sh4") {
        return String::from("sh"); // s/sh[234].*/sh/
    }
    if machine.starts_with("aarch64") {
        return String::from("arm64");
    }
    if machine.starts_with("riscv") {
        return String::from("riscv");
    }
    if machine.starts_with("loongarch") {
        return String::from("loongarch");
    }
    String::from(machine)
}

/// Uses the `ARCH` environment variable when set
/// otherwise `uname -m`.
pub fn infer_arch() -> String {
    if let Ok(arch) = std::env::var("ARCH")
        && !arch.is_empty()
    {
        return arch;
    }
    let machine = std::process::Command::new("uname")
        .arg("-m")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .filter(|stdout| !stdout.trim().is_empty())
        .unwrap_or_else(|| String::from(std::env::consts::ARCH));
    subarch(&machine)
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
            // arch/um/Makefile exports both variables to Kconfig. HEADER_ARCH
            // selects arch/x86/um/Kconfig, while SUBARCH controls whether its
            // 64BIT option is user-selectable.
            cur_root_kconfig_file.add_local_var("HEADER_ARCH", UML_SUBARCH);
            cur_root_kconfig_file.add_local_var("SUBARCH", UML_SUBARCH);
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

#[cfg(test)]
mod tests {
    use super::subarch;

    /// The machine strings scripts/subarch.include rewrites, and a few it
    /// leaves alone.
    #[test]
    fn subarch_matches_the_kernels_sed_script() {
        for (machine, arch) in [
            ("i386", "x86"),
            ("i686", "x86"),
            ("x86_64", "x86"),
            ("sun4u", "sparc64"),
            ("armv7l", "arm"),
            ("arm64", "arm64"), // the /^arm64$/! guard
            ("sa110", "arm"),
            ("s390x", "s390"),
            ("ppc64le", "powerpc"),
            ("mips64", "mips"),
            ("sh4a", "sh"),
            ("aarch64", "arm64"),
            ("aarch64_be", "arm64"),
            ("riscv64", "riscv"),
            ("loongarch64", "loongarch"),
            // untouched by the script
            ("m68k", "m68k"),
            ("sparc64", "sparc64"),
        ] {
            assert_eq!(subarch(machine), arch, "uname -m {machine}");
        }
    }
}
