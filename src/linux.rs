// SPDX-License-Identifier: GPL-2.0-only

use std::option::Option;

// each architecture has its own directory, and config option.
// most are the same, but powerpc / ppc is not.
// this maps the directory to the config option
pub fn arch_dir_to_config(arch_dir: &str) -> Option<&'static str> {
    match arch_dir {
        "ARM" => Some("ARM"),
        "ARM64" => Some("ARM64"),
        "X86" => Some("X86"),
        "RISCV" => Some("RISCV"),
        "MIPS" => Some("MIPS"),
        "XTENSA" => Some("XTENSA"),
        "SPARC" => Some("SPARC"),
        "ALPHA" => Some("ALPHA"),
        "ARC" => Some("ARC"),
        "CSKY" => Some("CSKY"),
        "HEXAGON" => Some("HEXAGON"),
        "LOONGARCH" => Some("LOONGARCH"),
        "M68K" => Some("M68K"),
        "MICROBLAZE" => Some("MICROBLAZE"),
        "NIOS2" => Some("NIOS2"),
        "OPENRISC" => Some("OPENRISC"),
        "PARISC" => Some("PARISC"),
        "POWERPC" => Some("PPC"),
        "S390" => Some("S390"),
        "SH" => Some("SH"),
        "UM" => Some("UML"),

        _ => None,
    }
}
