mkdir evaluation
git clone --depth 1 --branch v6.19.9 git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git evaluation/linux
find evaluation/linux -type f -regex '.*/Kconfig\(\..*\)?' -exec cat {} + | wc -l > evaluation/linux_loc.txt

git clone --depth 1 --branch 26.03 https://github.com/coreboot/coreboot.git evaluation/coreboot
find evaluation/coreboot -type f -regex '.*/Kconfig\(\..*\)?' -exec cat {} + | wc -l > evaluation/coreboot_loc.txt

git clone --depth 1 --branch v2026.01 https://github.com/u-boot/u-boot.git evaluation/u-boot
find evaluation/u-boot -type f -regex '.*/Kconfig\(\..*\)?' -exec cat {} + | wc -l > evaluation/u-boot_loc.txt

git clone --depth 1 --branch r-2026-W12 https://github.com/L4Re/fiasco.git evaluation/fiasco
find evaluation/fiasco -type f -regex '.*/Kconfig\(\..*\)?' -exec cat {} + | wc -l > evaluation/fiasco_loc.txt

git clone --depth 1 --branch 1_37_0 https://git.busybox.net/busybox/ evaluation/busybox
cd evaluation/busybox
make defconfig
find . -type f -name 'Config.*' -exec cat {} + | wc -l > ../busybox_loc.txt
cd ../..

cargo build --release -p kconfirm-cli

hyperfine --warmup 3 --runs 10 --export-json evaluation/linux_times.json './target/release/kconfirm-cli --linux-dir-path evaluation/linux'
hyperfine --warmup 3 --runs 10 --export-json evaluation/coreboot_times.json './target/release/kconfirm-cli --coreboot-dir-path evaluation/coreboot'
hyperfine --warmup 3 --runs 10 --export-json evaluation/u-boot_times.json './target/release/kconfirm-cli --other-kconfig-path evaluation/u-boot/Kconfig'
hyperfine --warmup 3 --runs 10 --export-json evaluation/fiasco_times.json './target/release/kconfirm-cli --other-kconfig-path evaluation/fiasco/src/Kconfig'
hyperfine --warmup 3 --runs 10 --export-json evaluation/busybox_times.json './target/release/kconfirm-cli --other-kconfig-path evaluation/busybox/Config.in'
