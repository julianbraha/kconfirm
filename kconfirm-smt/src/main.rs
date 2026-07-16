use std::path::PathBuf;

use clap::Parser;
use kconfirm_smt::{MacroOptions, RunMode, model_kconfig};

/// SMT feature model for the Linux kernel's Kconfig.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the Linux kernel source tree
    #[arg(long)]
    linux: PathBuf,

    /// Where to write the generated witness .config (ignored with
    /// --check-config; unmet-dependency witnesses are written next to it)
    #[arg(long, default_value = "witness.config")]
    output_config: PathBuf,

    /// Where to write the SMT-LIB constraints
    #[arg(long, default_value = "constraints.smt2")]
    output_smt_lib: PathBuf,

    /// For targeted random testing: pass a partial configuration with this option,
    /// then the model will set its options as constraints, and generate random settings
    /// for the rest of the (unconstrained) options.
    ///
    /// Outputs the random configuration to witness.config by default, or you can set
    /// the --output-config path to something else.
    ///
    /// For differential testing: pass a complete .config from the real kconfig interpreter,
    /// for example, with `make randconfig`.
    ///
    /// Writes sat or unsat to stdout.
    ///
    /// Exits 0 on sat, 1 on unsat.
    #[arg(long, value_name = "FILE")]
    add_constraints: Option<PathBuf>,

    /// Randomize the Z3 solver's decision phases with this seed so each run
    /// generates a different witness configuration
    #[arg(long)]
    seed: Option<u32>,

    /// Check for unmet dependency bugs.
    #[arg(long)]
    check_unmet_deps: bool,

    /// Use macro/function values from FILE for pre-processing, instead of evaluating:
    /// scripts/Kconfig.include from the target linux source and $(...) probes
    /// with the host toolchain. Macros missing from the file stay free variables.
    ///
    /// It is expected that the user previously output these with kconfirm-smt using --dump.
    ///
    /// Use this for cross-compiling offline:
    /// e.g. first --dump-preproc the values for ARM, then --load-preproc while on x86.
    #[arg(long, value_name = "FILE")]
    load_preproc: Option<PathBuf>,

    /// After pre-processing the tree, write every evaluated macro/function value
    /// to FILE, for a later --load
    #[arg(long, value_name = "FILE")]
    dump_preproc: Option<PathBuf>,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let mode = match args.add_constraints {
        Some(config_input) => RunMode::CheckConfig { config_input },
        None => RunMode::Model {
            config_output: args.output_config,
            constraints_output: args.output_smt_lib.clone(),
            seed: args.seed,
            sweep: args.check_unmet_deps,
        },
    };
    // arch comes from the environment:
    // 1. the ARCH variable when set, otherwise
    // 2. derived from `uname -m`
    let arch = kconfirm_linux::infer_arch();
    log::info!("using arch {arch} (from $ARCH or `uname -m` if not set)");
    let macros = MacroOptions {
        load: args.load_preproc,
        dump: args.dump_preproc,
        arch,
    };

    let satisfiable = model_kconfig(args.linux, mode, macros);

    std::process::exit(if satisfiable { 0 } else { 1 });
}
