# setup on ubuntu 26.04
sudo apt install git libssl-dev pkg-config make cargo
cargo install hyperfine --version 1.20.0
export PATH="$HOME/.cargo/bin:$PATH"
