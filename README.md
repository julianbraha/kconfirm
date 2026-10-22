<div align="center">
  <img src="assets/kconfirm.png" alt="Project Logo" width="200">
</div>
<p align="center"><sub><em>Logo given to me by my friend, <a href="https://www.silasvibes.com/">Silas</a></em></sub></p>

# kconfirm
A static analysis tool for the Kconfig language.

Detect dead code, unmet dependencies, and more.

# Usage

Build with Rust, OpenSSL, pkg-config, and Z3 installed, or enter the provided
development environment with `nix develop`:
```
# install missing dependencies, e.g. on Ubuntu 24.04 (or use nix develop)
sudo apt update
sudo apt install -y pkg-config libssl-dev libz3-dev z3 flex bison

# clone this repo
git clone https://github.com/julianbraha/kconfirm.git

cd kconfirm

# compile
cargo build --release -p kconfirm-cli

# run in lint mode (for linux):
./target/release/kconfirm-cli --lint --linux-dir-path RELATIVE_PATH_TO_LINUX_SOURCE

# run in lint mode (for coreboot):
./target/release/kconfirm-cli --lint --coreboot-dir-path RELATIVE_PATH_TO_COREBOOT_SOURCE
```

Choose exactly one mode:
1. `--lint` runs fast heuristic checks,
2. `--confirm` uses SMT solving for advanced checks like unmet dependencies. 

Both modes produce their findings in the same structured format.

By default, running on Linux analyzes every architecture with an `arch/<name>/Kconfig` in the source tree, sequentially. Findings are deduplicated across architectures. Use `--arch` to select particular targets:
```sh
# all architectures:
./target/release/kconfirm-cli --confirm --linux-dir-path /path/to/linux

# only x86 and arm64:
./target/release/kconfirm-cli --confirm --linux-dir-path /path/to/linux --arch x86,arm64
```

`--enable-check` and `--disable-check` accept repeated or comma-separated check IDs:

```sh
# disable the unmet dependency check:
./target/release/kconfirm-cli --confirm --linux-dir-path /path/to/linux --disable-check unmet_dependency
```

Internal checks that the SMT model is satisfiable produce random solutions to the model (witness files) and saving them is optional. Linux witnesses go under `witnesses/<arch>/`.

Note that `--confirm` mode evaluates Linux's Kconfig preprocessing using the current active toolchain in your environment. 

The `kconfirm-smt` package is available for standalone usage for exporting the model constraints, and loading or dumping preprocessing values.

To enable the check for dead links in the Kconfig `help` texts:
```
# NOTE: this is very slow! It will attempt to visit every link that it finds!
./target/release/kconfirm-cli --lint --linux-dir-path RELATIVE_PATH_TO_LINUX_SOURCE --enable-check dead_link
```

# Results from Development and Usage
For a list of patches to Linux and other projects from development and usage of `kconfirm` and `kconfirm-smt`, see:
1. [here](/findings/kconfirm.md) for `--lint` findings
2. [here](/findings/kconfirm_smt.md) for `--confirm` findings (powered by kconfirm-smt)

## Special Thanks
- [Yann Prono "Mcdostone"](https://mcdostone.github.io/) for building the [nom-kconfig](https://github.com/Mcdostone/nom-kconfig) crate for parsing `kconfig`, and continuing to support it.
- [Necip Fazil Yildiran](https://github.com/necipfazil), [Jeho Oh](https://github.com/jeho-oh), and [Paul Gazzillo](https://paulgazzillo.com/) for introducing me to the unmet dependency bug, and for their mentorship.
