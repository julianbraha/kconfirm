use std::path::PathBuf;

use kconfirm_smt::*;

fn main() {
    let linux_path = PathBuf::from("/home/julian/research/linux-next/");
    let result = model_kconfig(linux_path);
}
