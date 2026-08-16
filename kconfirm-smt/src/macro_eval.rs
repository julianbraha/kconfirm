//! Evaluation of Kconfig preprocessor macros/functions (`$(cc-option,...)`,
//! `$(success,...)`, `$(shell,...)`, ...), matching the kernel's
//! scripts/kconfig/preprocess.c.

use log::warn;
use nom_kconfig::attribute::function::{ExpressionToken, FunctionCall, Parameter};
use nom_kconfig::attribute::r#macro::Macro;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// kconfig caps a `$(shell,...)` result at one byte under its 4096-byte
/// buffer (see preprocess.c do_shell).
const SHELL_RESULT_CAP: usize = 4095;

#[derive(Clone, Copy, PartialEq)]
enum Flavor {
    /// `:=` the value was expanded at assignment time.
    Simple,
    /// `=` the raw value is expanded at every reference, with arguments.
    Recursive,
}

struct Variable {
    flavor: Flavor,
    value: String,
}

/// Counters for reporting what happened to the tree's macros.
#[derive(Debug, Default)]
pub struct MacroStats {
    /// Calls evaluated (or found in the loaded/dumped value set).
    pub evaluated: usize,
    /// Calls that could not be evaluated and fell back to free variables.
    pub failed: usize,
}

pub struct MacroEvaluator {
    variables: HashMap<String, Variable>,
    /// The controlled environment: what the kernel Makefile would export to
    /// kconfig (CC, LD, srctree, ...). Consulted for argument-less references
    /// before the process environment, and overlaid onto the environment of
    /// `$(shell,...)` commands.
    env: HashMap<String, String>,
    /// Evaluated results keyed by the macro's reconstructed source text.
    /// Serves as the evaluation cache, the dump payload, and (in load mode)
    /// the sole source of call results.
    call_results: HashMap<String, String>,
    /// Working directory for `$(shell,...)`; `None` disables shell execution
    /// (load mode).
    shell_dir: Option<PathBuf>,
    pub stats: MacroStats,
}

impl MacroEvaluator {
    /// An evaluator for the host toolchain: bootstraps the environment the
    /// kernel Makefile would pass to kconfig, then loads (and evaluates the
    /// probes of) scripts/Kconfig.include from the tree.
    ///
    /// `arch` is the `$(ARCH)` value to evaluate under (falling back to the
    /// process environment, then `x86`)
    pub fn new_host(linux: &Path, arch: &str) -> Self {
        let linux = linux.canonicalize().unwrap_or_else(|_| linux.to_path_buf());
        let mut evaluator = MacroEvaluator {
            variables: HashMap::new(),
            env: HashMap::new(),
            call_results: HashMap::new(),
            shell_dir: Some(linux.clone()),
            stats: MacroStats::default(),
        };
        evaluator.env = evaluator.host_environment(&linux, arch);

        let include = linux.join("scripts/Kconfig.include");
        if let Err(e) = evaluator.load_kconfig_include(&include) {
            warn!(
                "could not process {}: {e}; unresolved macros will fall back to free variables",
                include.display()
            );
        }
        evaluator
    }

    /// An evaluator that only uses values from a dump file (`--load`): no
    /// shell commands are ever run, and calls missing from the file fall
    /// back to free variables.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut evaluator = MacroEvaluator {
            variables: HashMap::new(),
            env: HashMap::new(),
            call_results: HashMap::new(),
            shell_dir: None,
            stats: MacroStats::default(),
        };
        for (number, line) in text.lines().enumerate() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (kind, rest) = line
                .split_once(' ')
                .ok_or_else(|| format!("{}:{}: malformed line", path.display(), number + 1))?;
            let (key, value) = rest
                .split_once('\t')
                .ok_or_else(|| format!("{}:{}: missing tab", path.display(), number + 1))?;
            let key = unescape_field(key);
            let value = unescape_field(value);
            match kind {
                "env" => {
                    evaluator.env.insert(key, value);
                }
                "var" => {
                    evaluator.variables.insert(
                        key,
                        Variable {
                            flavor: Flavor::Simple,
                            value,
                        },
                    );
                }
                "call" => {
                    evaluator.call_results.insert(key, value);
                }
                other => {
                    return Err(format!(
                        "{}:{}: unknown entry kind {other:?}",
                        path.display(),
                        number + 1
                    ));
                }
            }
        }
        Ok(evaluator)
    }

    /// Writes the environment, the evaluated simple variables, and every
    /// evaluated call result, in the format `MacroEvaluator::from_file` reads.
    pub fn dump(&self, path: &Path) -> std::io::Result<()> {
        let mut out = String::from(
            "# kconfirm-smt macro values (load with --load)\n\
             # kind key<TAB>value, with \\t \\n \\\\ escaped\n",
        );
        let mut sections: [(&str, Vec<(&String, &String)>); 3] = [
            ("env", self.env.iter().collect()),
            (
                "var",
                self.variables
                    .iter()
                    .filter(|(_, v)| v.flavor == Flavor::Simple)
                    .map(|(k, v)| (k, &v.value))
                    .collect(),
            ),
            ("call", self.call_results.iter().collect()),
        ];
        for (kind, entries) in &mut sections {
            entries.sort();
            for (key, value) in entries {
                let _ = writeln!(out, "{kind} {}\t{}", escape_field(key), escape_field(value));
            }
        }
        std::fs::write(path, out)
    }

    /// The environment the kernel's top Makefile would export to kconfig,
    /// overridable through the real process environment. Derived values
    /// (CC_VERSION_TEXT, KERNELVERSION, PAHOLE_VERSION) are computed the way
    /// the Makefile computes them.
    fn host_environment(&mut self, linux: &Path, arch: &str) -> HashMap<String, String> {
        let mut env = HashMap::new();

        // Build tools, matching the kernel Makefile's `CC = $(CROSS_COMPILE)gcc`
        // (and likewise LD/NM/OBJCOPY). A non-empty CROSS_COMPILE selects a
        // cross toolchain for the $(cc-option)/$(as-instr)/$(ld-option)/…
        // probes and CC_VERSION_TEXT, and — as in the Makefile, whose
        // assignment overrides the environment — takes precedence over an
        // inherited CC/LD (e.g. a nix devshell's host wrapper). So
        // `CROSS_COMPILE=arm-linux-gnueabihf-` cross-compiles the probes; when
        // it is unset, an explicit CC/LD wins, else the host tool. RUSTC and
        // PAHOLE are never cross-prefixed (the Makefile does not prefix them).
        let cross_compile = std::env::var("CROSS_COMPILE").unwrap_or_default();
        let cross = (!cross_compile.is_empty()).then_some(cross_compile.as_str());
        for (name, program) in [
            ("CC", "gcc"),
            ("LD", "ld"),
            ("NM", "nm"),
            ("OBJCOPY", "objcopy"),
        ] {
            let explicit = std::env::var(name).ok();
            env.insert(
                name.to_string(),
                resolve_tool(cross, explicit.as_deref(), program),
            );
        }
        env.insert("CROSS_COMPILE".to_string(), cross_compile.clone());
        let cc = env["CC"].clone();

        let mut var = |name: &str, default: &str| {
            let value = std::env::var(name).unwrap_or_else(|_| default.to_string());
            env.insert(name.to_string(), value.clone());
            value
        };

        let rustc = var("RUSTC", "rustc");
        var("CLANG_FLAGS", "");
        var("USERCFLAGS", "");
        var("USERLDFLAGS", "");
        let pahole = var("PAHOLE", "pahole");

        // ARCH: an explicit request wins over the process environment.
        // SRCARCH is the arch *directory*, which the Makefile derives from
        // ARCH (the x86 family shares arch/x86).

        let srcarch = std::env::var("SRCARCH").unwrap_or_else(|_| match arch {
            "x86_64" | "i386" | "x86" => "x86".to_string(),
            "sparc32" | "sparc64" => "sparc".to_string(),
            "parisc64" => "parisc".to_string(),
            other => other.to_string(),
        });
        env.insert("ARCH".to_string(), arch.to_owned());
        env.insert("SRCARCH".to_string(), srcarch);
        if arch == "um" {
            // arch/um/Makefile exports the normalized host architecture.
            // Without it, `$(SUBARCH)` becomes empty and UML's 64BIT option
            // is incorrectly hidden and forced on by its default.
            env.insert(
                "SUBARCH".to_string(),
                kconfirm_linux::UML_SUBARCH.to_string(),
            );
        }
        env.insert("srctree".to_string(), linux.display().to_string());

        // CC_VERSION_TEXT: the first line of `$(CC) --version` (Makefile)
        env.insert(
            "CC_VERSION_TEXT".to_string(),
            first_line_of(linux, &format!("{cc} --version")),
        );
        env.insert(
            "RUSTC_VERSION_TEXT".to_string(),
            first_line_of(linux, &format!("{rustc} --version 2>/dev/null")),
        );
        env.insert(
            "PAHOLE_VERSION".to_string(),
            first_line_of(
                linux,
                &format!("./scripts/pahole-version.sh {pahole} 2>/dev/null"),
            ),
        );
        env.insert("KERNELVERSION".to_string(), kernel_version(linux));
        env
    }

    /// Processes scripts/Kconfig.include: make-style assignments define the
    /// helper macros (`=`) and evaluate the toolchain probes (`:=`), and
    /// top-level `$(error-if,...)` lines run for their side effect.
    fn load_kconfig_include(&mut self, path: &Path) -> Result<(), String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with("$(") {
                // a top-level call (the CC/LD existence checks): evaluate for
                // the side effect, tolerate failure
                if let Err(e) = self.expand_text(line, &[]) {
                    warn!("{}: {line}: {e}", path.display());
                }
                continue;
            }
            let Some((name, op, raw_value)) = split_assignment(line) else {
                warn!("{}: unrecognized line skipped: {line}", path.display());
                continue;
            };
            self.assign(name, op, raw_value);
        }
        Ok(())
    }

    /// A make-style assignment, mirroring the linux preprocess.c variable_add.
    fn assign(&mut self, name: &str, op: &str, raw_value: &str) {
        let (flavor, append) = match op {
            ":=" => (Flavor::Simple, false),
            "=" => (Flavor::Recursive, false),
            "+=" => (
                self.variables
                    .get(name)
                    .map(|v| v.flavor)
                    .unwrap_or(Flavor::Recursive),
                self.variables.contains_key(name),
            ),
            _ => unreachable!("split_assignment only yields the three operators"),
        };

        let new_value = match flavor {
            // a simple variable's value is expanded once, at assignment
            Flavor::Simple => match self.expand_text(raw_value, &[]) {
                Ok(expanded) => expanded,
                Err(e) => {
                    warn!("expanding {name} := {raw_value}: {e}");
                    String::new()
                }
            },
            Flavor::Recursive => raw_value.to_string(),
        };

        if append {
            let variable = self
                .variables
                .get_mut(name)
                .expect("append only when defined");
            variable.value.push(' ');
            variable.value.push_str(&new_value);
        } else {
            self.variables.insert(
                name.to_string(),
                Variable {
                    flavor,
                    value: new_value,
                },
            );
        }
    }

    /// Evaluates a parsed macro occurrence from the Kconfig AST, returning
    /// the expanded text. Results are cached (and satisfied from the cache
    /// in `--load` mode)
    pub fn eval_macro(&mut self, m: &Macro) -> Result<String, String> {
        let key = render_macro_source(m);
        if let Some(result) = self.call_results.get(&key) {
            self.stats.evaluated += 1;
            return Ok(result.clone());
        }
        match self.expand_text(&key, &[]) {
            Ok(result) => {
                self.stats.evaluated += 1;
                self.call_results.insert(key, result.clone());
                Ok(result)
            }
            Err(e) => {
                self.stats.failed += 1;
                Err(format!("{key}: {e}"))
            }
        }
    }

    /// Expands every `$(...)` reference in `text`, with `argv` as the
    /// positional arguments (`$(1)`...) of the enclosing macro body. This is
    /// the linux preprocess.c's expand_string_with_args: a `$` not followed by `(`
    /// stays literal, commas split arguments only at parenthesis-nesting
    /// depth zero, and each piece is expanded before the reference resolves.
    fn expand_text(&mut self, text: &str, argv: &[String]) -> Result<String, String> {
        let bytes = text.as_bytes();
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
                let start = i + 2;
                let mut nest = 0usize;
                let mut end = None;
                let mut splits = Vec::new(); // nest-0 comma positions
                let mut j = start;
                while j < bytes.len() {
                    match bytes[j] {
                        b'(' => nest += 1,
                        b')' => {
                            if nest == 0 {
                                end = Some(j);
                                break;
                            }
                            nest -= 1;
                        }
                        b',' if nest == 0 => splits.push(j),
                        _ => {}
                    }
                    j += 1;
                }
                let end = end.ok_or_else(|| {
                    let context: String = text[i..].chars().take(40).collect();
                    format!("unterminated reference: {context}")
                })?;

                // split into head and arguments, expanding each piece
                let mut pieces = Vec::with_capacity(splits.len() + 1);
                let mut piece_start = start;
                for split in splits.iter().chain(std::iter::once(&end)) {
                    pieces.push(self.expand_text(&text[piece_start..*split], argv)?);
                    piece_start = split + 1;
                }
                let head = pieces.remove(0);
                out.push_str(&self.resolve_clause(&head, &pieces, argv)?);
                i = end + 1;
            } else {
                let c = text[i..].chars().next().expect("in bounds");
                out.push(c);
                i += c.len_utf8();
            }
        }
        Ok(out)
    }

    /// Resolves one `$(head,args...)` reference: positional argument,
    /// kconfig-defined variable, builtin function, then (argument-less only)
    /// the environment; anything else expands to the empty string, like kconfig.
    fn resolve_clause(
        &mut self,
        head: &str,
        args: &[String],
        argv: &[String],
    ) -> Result<String, String> {
        // $(1)... — positional arguments of the enclosing macro body
        if !head.is_empty() && head.bytes().all(|b| b.is_ascii_digit()) {
            let n: usize = head.parse().map_err(|_| "argument index overflow")?;
            if n >= 1 && n <= argv.len() {
                return Ok(argv[n - 1].clone());
            }
            return Ok(String::new());
        }

        if let Some(variable) = self.variables.get(head) {
            return match variable.flavor {
                Flavor::Simple => Ok(variable.value.clone()),
                Flavor::Recursive => {
                    let body = variable.value.clone();
                    self.expand_text(&body, args)
                }
            };
        }

        match head {
            "shell" => {
                let command = args.first().cloned().unwrap_or_default();
                return self.run_shell(&command);
            }
            "info" => {
                println!("{}", args.first().cloned().unwrap_or_default());
                return Ok(String::new());
            }
            "warning-if" => {
                if args.first().map(String::as_str) == Some("y") {
                    warn!("{}", args.get(1).cloned().unwrap_or_default());
                }
                return Ok(String::new());
            }
            "error-if" => {
                // kconfig aborts; we degrade to a warning so one failed
                // toolchain check doesn't kill the whole model
                if args.first().map(String::as_str) == Some("y") {
                    warn!(
                        "kconfig error-if triggered: {}",
                        args.get(1).cloned().unwrap_or_default()
                    );
                }
                return Ok(String::new());
            }
            // no meaningful file/line context here
            "filename" => return Ok(String::new()),
            "lineno" => return Ok("0".to_string()),
            _ => {}
        }

        if args.is_empty() {
            // an argument-less reference falls back to the environment, and
            // an unset variable is the empty string — kconfig behaves the
            // same (env_expand, then "")
            if let Some(value) = self.env.get(head) {
                return Ok(value.clone());
            }
            if let Ok(value) = std::env::var(head) {
                return Ok(value.clone());
            }
            return Ok(String::new());
        }
        // a *function call* whose name is undefined means our definitions are
        // incomplete (e.g. Kconfig.include failed to load): kconfig would
        // expand to nothing and fail parsing; degrading to a free variable is
        // safer than silently pinning the caller's option to n
        Err(format!("unknown function {head:?}"))
    }

    /// Runs `$(shell,command)` like preprocess.c do_shell: `sh -c` in the
    /// tree root with the controlled environment overlaid, capturing stdout,
    /// stripping trailing newlines, and turning inner newlines into spaces.
    fn run_shell(&mut self, command: &str) -> Result<String, String> {
        let Some(dir) = &self.shell_dir else {
            return Err("shell execution disabled (--load mode)".to_string());
        };
        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(dir)
            .envs(&self.env)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|e| format!("sh: {e}"))?;

        let mut bytes = output.stdout;
        bytes.truncate(SHELL_RESULT_CAP);
        while bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        for byte in &mut bytes {
            if *byte == b'\n' {
                *byte = b' ';
            }
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// The variable/environment values that are safe to hand to nom-kconfig
    /// for textual `$(NAME)` substitution while parsing (the parser's
    /// preprocess_content replaces them anywhere in the file).
    pub fn safe_parser_variables(&self) -> HashMap<String, String> {
        let safe = |value: &str| {
            !value.is_empty()
                && !value
                    .chars()
                    .any(|c| ",()\"'$\n\t\\".contains(c) || c.is_control())
        };
        let mut out = HashMap::new();
        for (name, value) in &self.env {
            if safe(value) {
                out.insert(name.clone(), value.clone());
            }
        }
        for (name, variable) in &self.variables {
            if variable.flavor == Flavor::Simple && safe(&variable.value) {
                out.insert(name.clone(), variable.value.clone());
            }
        }
        out
    }
}

/// Resolves a build tool the way the kernel Makefile does. A non-empty
/// CROSS_COMPILE prefix selects the cross tool and overrides any inherited
/// value (the Makefile's `CC = $(CROSS_COMPILE)gcc` beats the environment);
/// otherwise an explicitly-set value wins, else the bare host program name.
fn resolve_tool(cross: Option<&str>, explicit: Option<&str>, program: &str) -> String {
    match cross {
        Some(prefix) => format!("{prefix}{program}"),
        None => explicit.unwrap_or(program).to_string(),
    }
}

/// Splits a make-style assignment line into (name, operator, raw value).
fn split_assignment(line: &str) -> Option<(&str, &str, &str)> {
    let eq = line.find('=')?;
    let (name_end, op) = match line.as_bytes().get(eq.wrapping_sub(1)) {
        Some(b':') => (eq - 1, ":="),
        Some(b'+') => (eq - 1, "+="),
        _ => (eq, "="),
    };
    let name = line[..name_end].trim();
    if name.is_empty() || name.contains(char::is_whitespace) {
        return None;
    }
    Some((name, op, line[eq + 1..].trim()))
}

/// Reconstructs a parsed macro's source text (used to expand it and as its
/// cache key). Spacing is canonicalized by the parser; that changes nothing
/// semantically for shell commands or comparisons.
pub fn render_macro_source(m: &Macro) -> String {
    match m {
        Macro::Variable(name) => format!("$({name})"),
        // the quotes around "$(...)"" belong to the surrounding syntax, not
        // the reference
        Macro::DoubleQuoted(inner) => render_macro_source(inner),
        Macro::FunctionCall(call) => render_function_source(call),
    }
}

fn render_function_source(call: &FunctionCall) -> String {
    let mut out = String::from("$(");
    out.push_str(&call.name);
    for parameter in &call.parameters {
        out.push(',');
        out.push_str(&render_parameter(parameter));
    }
    out.push(')');
    out
}

fn render_parameter(parameter: &Parameter) -> String {
    let mut out = String::new();
    for token in &parameter.tokens {
        render_token(token, &mut out);
    }
    out
}

fn render_token(token: &ExpressionToken, out: &mut String) {
    match token {
        ExpressionToken::Literal(text) => out.push_str(text),
        ExpressionToken::Variable(name) => {
            out.push_str("$(");
            out.push_str(name);
            out.push(')');
        }
        ExpressionToken::DoubleQuotes(inner) => {
            out.push('"');
            for token in inner {
                render_token(token, out);
            }
            out.push('"');
        }
        ExpressionToken::SingleQuotes(text) => {
            out.push('\'');
            out.push_str(text);
            out.push('\'');
        }
        ExpressionToken::Backtick(text) => {
            out.push('`');
            out.push_str(text);
            out.push('`');
        }
        ExpressionToken::Function(call) => out.push_str(&render_function_source(call)),
        ExpressionToken::Space => out.push(' '),
    }
}

/// The first line of a shell command's output (for CC_VERSION_TEXT and
/// friends, which the kernel Makefile computes the same way).
fn first_line_of(dir: &Path, command: &str) -> String {
    Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(dir)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .unwrap_or_default()
}

/// KERNELVERSION as the linux Makefile computes it.
fn kernel_version(linux: &Path) -> String {
    let Ok(makefile) = std::fs::read_to_string(linux.join("Makefile")) else {
        return String::new();
    };
    let mut parts: HashMap<&str, &str> = HashMap::new();
    for line in makefile.lines().take(10) {
        if let Some((name, value)) = line.split_once('=') {
            parts.insert(name.trim(), value.trim());
        }
    }
    match (
        parts.get("VERSION"),
        parts.get("PATCHLEVEL"),
        parts.get("SUBLEVEL"),
    ) {
        (Some(version), Some(patchlevel), Some(sublevel)) => format!(
            "{version}.{patchlevel}.{sublevel}{}",
            parts.get("EXTRAVERSION").copied().unwrap_or_default()
        ),
        _ => String::new(),
    }
}

fn escape_field(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
}

fn unescape_field(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// NOTE: tests are AI slop I generated after I got everything working.
/// TODO: review these more carefully and consider handwritten tests.
#[cfg(test)]
mod tests {
    use super::*;

    fn bare_evaluator() -> MacroEvaluator {
        MacroEvaluator {
            variables: HashMap::new(),
            env: HashMap::new(),
            call_results: HashMap::new(),
            shell_dir: Some(std::env::temp_dir()),
            stats: MacroStats::default(),
        }
    }

    #[test]
    fn expansion_follows_preprocess_c() {
        let mut ev = bare_evaluator();
        ev.env.insert("CC".to_string(), "gcc".to_string());

        // env fallback, and $ not followed by ( stays literal
        assert_eq!(ev.expand_text("x $(CC) $$ y", &[]).unwrap(), "x gcc $$ y");

        // recursive macros expand with positional args at reference time
        ev.assign("greet", "=", "hello $(1) and $(2)");
        assert_eq!(
            ev.expand_text("$(greet,alice,bob)", &[]).unwrap(),
            "hello alice and bob"
        );

        // nested references are protected by nesting-aware comma splitting
        ev.assign("id", "=", "$(1)");
        assert_eq!(
            ev.expand_text("$(greet,$(id,a$(comma)b),c)", &[]).unwrap(),
            // comma is not defined here: $(comma) is empty
            "hello ab and c"
        );

        // := is immediate, = is lazy
        ev.assign("now", ":=", "$(CC)");
        ev.env.insert("CC".to_string(), "clang".to_string());
        ev.assign("later", "=", "$(CC)");
        assert_eq!(ev.expand_text("$(now)/$(later)", &[]).unwrap(), "gcc/clang");

        // += appends with a space, inheriting the flavor
        ev.assign("now", "+=", "-O2");
        assert_eq!(ev.expand_text("$(now)", &[]).unwrap(), "gcc -O2");

        // an unknown argument-less reference is the empty string (like an
        // unset environment variable)...
        assert_eq!(ev.expand_text("$(NOPE_UNSET_VAR)", &[]).unwrap(), "");
        // ...but an unknown *function* is an error, so the caller can fall
        // back to a free variable instead of a silent constant
        assert!(ev.expand_text("$(nope,x)", &[]).is_err());
    }

    #[test]
    fn shell_builtin_trims_like_kconfig() {
        let mut ev = bare_evaluator();
        assert_eq!(
            ev.expand_text("$(shell,printf 'a\\nb\\n\\n')", &[])
                .unwrap(),
            "a b"
        );
        // the standard success/failure macros work end to end
        ev.assign(
            "if-success",
            "=",
            r#"$(shell,{ $(1); } >/dev/null 2>&1 && echo "$(2)" || echo "$(3)")"#,
        );
        ev.assign("success", "=", "$(if-success,$(1),y,n)");
        assert_eq!(ev.expand_text("$(success,true)", &[]).unwrap(), "y");
        assert_eq!(ev.expand_text("$(success,false)", &[]).unwrap(), "n");
    }

    #[test]
    fn comma_variable_protects_arguments() {
        let mut ev = bare_evaluator();
        ev.assign("comma", ":=", ",");
        ev.assign("id", "=", "[$(1)]");
        // $(comma) expands after argument splitting, so the comma is literal
        assert_eq!(ev.expand_text("$(id,a$(comma)b)", &[]).unwrap(), "[a,b]");
    }

    #[test]
    fn parsed_macro_evaluation_and_cache() {
        let mut ev = bare_evaluator();
        ev.env.insert("FOO".to_string(), "bar".to_string());

        let m = Macro::Variable("FOO".to_string());
        assert_eq!(ev.eval_macro(&m).unwrap(), "bar");
        assert_eq!(ev.stats.evaluated, 1);

        // quoted macros evaluate to their content
        let quoted = Macro::DoubleQuoted(Box::new(Macro::Variable("FOO".to_string())));
        assert_eq!(ev.eval_macro(&quoted).unwrap(), "bar");

        // cache hit: same source text, no re-evaluation machinery needed
        ev.env.remove("FOO");
        assert_eq!(ev.eval_macro(&m).unwrap(), "bar");
    }

    #[test]
    fn dump_load_round_trip() {
        let mut ev = bare_evaluator();
        ev.env.insert("CC".to_string(), "gcc".to_string());
        ev.assign("cc-version", ":=", "150200");
        ev.call_results
            .insert("$(success,test \"GCC\" = GCC)".to_string(), "y".to_string());

        let path = std::env::temp_dir().join(format!("kconfirm-macro-test-{}", std::process::id()));
        ev.dump(&path).unwrap();
        let mut loaded = MacroEvaluator::from_file(&path).unwrap();
        std::fs::remove_file(&path).ok();

        // loaded values resolve without a shell
        assert_eq!(
            loaded
                .eval_macro(&Macro::Variable("cc-version".to_string()))
                .unwrap(),
            "150200"
        );
        assert_eq!(loaded.env.get("CC").map(String::as_str), Some("gcc"));
        assert_eq!(
            loaded
                .call_results
                .get("$(success,test \"GCC\" = GCC)")
                .map(String::as_str),
            Some("y")
        );
        // an unknown call fails instead of running a shell
        let unknown = Macro::FunctionCall(FunctionCall {
            name: "shell".to_string(),
            parameters: vec![Parameter {
                tokens: vec![ExpressionToken::Literal("echo hi".to_string())],
            }],
        });
        assert!(loaded.eval_macro(&unknown).is_err());
    }

    #[test]
    fn assignment_line_splitting() {
        assert_eq!(split_assignment("a := b"), Some(("a", ":=", "b")));
        assert_eq!(split_assignment("a = b = c"), Some(("a", "=", "b = c")));
        assert_eq!(split_assignment("a += b"), Some(("a", "+=", "b")));
        assert_eq!(split_assignment("empty :="), Some(("empty", ":=", "")));
        assert_eq!(split_assignment("no assignment"), None);
    }

    #[test]
    fn cross_compile_derives_the_toolchain() {
        // CROSS_COMPILE set: the cross tool is used, overriding an inherited
        // CC (matching the kernel Makefile's CC = $(CROSS_COMPILE)gcc, which
        // beats a nix devshell's host CC wrapper)
        assert_eq!(
            resolve_tool(Some("arm-linux-gnueabihf-"), Some("gcc"), "gcc"),
            "arm-linux-gnueabihf-gcc"
        );
        assert_eq!(
            resolve_tool(Some("arm-none-eabi-"), None, "ld"),
            "arm-none-eabi-ld"
        );
        // no CROSS_COMPILE: an explicit tool wins, else the host default
        assert_eq!(resolve_tool(None, Some("clang"), "gcc"), "clang");
        assert_eq!(resolve_tool(None, None, "gcc"), "gcc");
    }
}
