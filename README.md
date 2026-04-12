<div align="center">
  <img src="assets/kconfirm.png" alt="Project Logo" width="200">
</div>

# kconfirm
A static analysis tool for the Kconfig language.

Detect dead code, dead links in help texts, and more. Unmet dependency detection (inspired by [kismet](https://dl.acm.org/doi/pdf/10.1145/3468264.3468578)) is in development. This uses SMT instead of SAT, to reduce false negatives and false positives.

# Submitted Patches

## Unmet Dependency Bugs
[2026-03-25 "ASoC: Intel: boards: fix unmet dependency on PINCTRL"](https://lore.kernel.org/all/20260325001522.1727678-1-julianbraha@gmail.com/)

## Dead Defaults

[2026-03-23 "drm: fix dead default for DRM_TTM_KUNIT_TEST"](https://lore.kernel.org/all/20260323124118.1414913-1-julianbraha@gmail.com/)

[2026-03-23 "s390: fix dead defaults for S390_MODULES_SANITY_TEST and S390_UNWIND_SELFTEST"](https://lkml.org/lkml/2026/3/23/1056)

[2026-03-22 "soc: aspeed: cleanup dead default for ASPEED_SOCINFO"](https://lkml.org/lkml/2026/3/22/591)

## Duplicate Dependencies

[2026-04-02 "stmmac: cleanup dead dependencies on STMMAC_PLATFORM and STMMAC_ETH in Kconfig"](https://lore.kernel.org/all/20260402145858.240231-1-julianbraha@gmail.com/)

[2026-03-31 "keys: cleanup dead code in Kconfig for FIPS_SIGNATURE_SELFTEST"](https://lore.kernel.org/all/20260331122214.103145-1-julianbraha@gmail.com/)

[2026-03-31 "nvmem: cleanup dead code in Kconfig"](https://lore.kernel.org/all/20260331120459.99382-1-julianbraha@gmail.com/)

[2026-03-30 "remoteproc: dead code cleanup in Kconfig for STM32_RPROC"](https://lore.kernel.org/all/20260330224545.29769-1-julianbraha@gmail.com/)

[2026-03-30 "pci: dead code cleanup in Kconfig"](https://lore.kernel.org/all/20260330214549.16157-1-julianbraha@gmail.com/)

[2026-03-30 "ppp: dead code cleanup in Kconfig"](https://lore.kernel.org/all/20260330213258.13982-1-julianbraha@gmail.com/)

[2026-03-29 "riscv: dead code cleanup in kconfig for RISCV_PROBE_VECTOR_UNALIGNED_ACCESS"](https://lore.kernel.org/all/20260329203249.563434-1-julianbraha@gmail.com/)

[2026-03-29 "net: microchip: dead code cleanup in kconfig for FDMA"](https://lore.kernel.org/all/20260329185348.526893-1-julianbraha@gmail.com/)

[2026-03-29 "media: dead code cleanup in kconfig for VIDEO_SOLO6X10"](https://lore.kernel.org/all/20260329183942.522693-1-julianbraha@gmail.com/)

[2026-03-29 "ARM: omap2: dead code cleanup in kconfig for ARCH_OMAP4"](https://lore.kernel.org/all/20260329183018.519560-1-julianbraha@gmail.com/)

## Dead Configuration Options

[2026-03-09 "serial: remove drivers for espressif esp32"](https://lore.kernel.org/all/20260309122321.1528622-1-julianbraha@gmail.com/)

## Known Dead Links

Linux 7.0-rc6 has 82 known, unique dead links in the Kconfig help texts, hand-checked from kconfirm's results.

See [findings/dead_links_7_0_rc6.txt](/findings/dead_links_7_0_rc6.txt)

# Usage

Assuming you have Rust installed:
```
# clone this repo
git clone https://github.com/julianbraha/kconfirm.git

cd kconfirm

# compile
cargo build --release

# run (for linux):
./target/release/kconfirm --linux-dir-path RELATIVE_PATH_TO_LINUX_SOURCE

# run (for coreboot):
./target/release/kconfirm --coreboot-dir-path RELATIVE_PATH_TO_COREBOOT_SOURCE
```

To enable the check for dead links in the Kconfig `help` texts:
```
# NOTE: this is very slow! It will attempt to visit every link that it finds!
./target/release/kconfirm-cli --linux-dir-path RELATIVE_PATH_TO_LINUX_SOURCE --check-dead-links
```

## Special Thanks
- [Yann Prono "Mcdostone"](https://mcdostone.github.io/) for building the [nom-kconfig](https://github.com/Mcdostone/nom-kconfig) crate for parsing `kconfig`, and continuing to support it.
- [Necip Fazil Yildiran](https://github.com/necipfazil), [Jeho Oh](https://github.com/jeho-oh), and [Paul Gazzillo](https://paulgazzillo.com/) for introducing me to the unmet dependency bug, and for their mentorship.
