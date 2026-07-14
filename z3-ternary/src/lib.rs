//! Order encoding of Kconfig bool/tristate values as Z3 boolean variables for solver performance.
//! Originally used integer encoding (as n=0, m=1, y=2) but this was wayyyyyy too slow (never found a solution after 12+ hours).
//!
//! Every tristate value or condition is a pair `(ge_m, ge_y)` of Boolean
//! expressions, read as:
//!
//! - `ge_m` is "value >= m" (same as value > n)
//! - `ge_y` is "value == y"
//!
//! decode: `n iff !ge_m`, `m iff ge_m AND !ge_y`, `y iff ge_y`.
//!
//! `min`/`&&` is componentwise AND, `max`/`||` is componentwise OR,
//! `!` swaps and negates the components, and the orderings `<=`/`<` are two
//! implications. Every operator preserves the ladder  `ge_y implies ge_m`,
//! which is asserted once per tristate option variable (a bool option holds it
//! at construction-time, since both components are the same variable).
//!
//! The helpers constant-fold while building: most Kconfig conditions are
//! absent or constant, so folding keeps the emitted expression near-linear to the
//! size of the actual Kconfig.

use z3::ast::Bool;

/// A tristate value in the order encoding.
/// To represent `n`: both values are false.
/// To represent `m`: ge_m=true and ge_y=false.
/// To represent `y`: ge_m=true and ge_y=true.
/// Illegal state: ge_m=false and ge_y=true.
#[derive(Debug, Clone)]
pub struct Ternary {
    /// value >= m (same thing as value > n)
    pub ge_m: Bool,
    /// value = y
    pub ge_y: Bool,
}

impl Ternary {
    /// Constant `n`.
    pub fn n() -> Self {
        Ternary {
            ge_m: Bool::from_bool(false),
            ge_y: Bool::from_bool(false),
        }
    }

    /// Constant `m`.
    /// Stays `m` even when MODULES is disabled, clamping done later.
    pub fn m() -> Self {
        Ternary {
            ge_m: Bool::from_bool(true),
            ge_y: Bool::from_bool(false),
        }
    }

    /// Constant `y`.
    pub fn y() -> Self {
        Ternary {
            ge_m: Bool::from_bool(true),
            ge_y: Bool::from_bool(true),
        }
    }

    /// Creates the ternary representation of a boolean proposition.
    pub fn from_prop(q: &Bool) -> Self {
        Ternary {
            ge_m: q.clone(),
            ge_y: q.clone(),
        }
    }

    /// `value > n`
    pub fn gt_n(&self) -> Bool {
        self.ge_m.clone()
    }

    /// `value == n` is `!ge_m`
    pub fn is_n(&self) -> Bool {
        bool_not(&self.ge_m)
    }

    /// `value == m is `ge_m AND !ge_y`.
    pub fn is_m(&self) -> Bool {
        bool_and(&self.ge_m, &bool_not(&self.ge_y))
    }

    /// `value == y` is `ge_y`.
    pub fn is_y(&self) -> Bool {
        self.ge_y.clone()
    }

    /// Decode the constant value.
    pub fn as_const(&self) -> Option<u8> {
        match (self.ge_m.as_bool()?, self.ge_y.as_bool()?) {
            (false, false) => Some(0),
            (true, false) => Some(1),
            (true, true) => Some(2),
            (false, true) => None,
        }
    }
}

/// Create the Z3 variable for a bool using our ternary representation.
pub fn new_bool(name: &str) -> Ternary {
    let b = Bool::new_const(name);
    Ternary {
        ge_m: b.clone(),
        ge_y: b,
    }
}

/// Create the ternary variable for a tristate option.
/// Caller must add the ladder constraint to the solver, and
/// also assert the `modules_rule` once the `MODULES`
/// option's variable is known.
pub fn new_tristate(name: &str) -> (Ternary, Bool) {
    let ge_m = Bool::new_const(format!("{name}>=m"));
    let ge_y = Bool::new_const(format!("{name}>=y"));
    let ladder = ge_y.implies(&ge_m);
    (Ternary { ge_m, ge_y }, ladder)
}

/// The modules rule for a tristate option: `!MODULES -> (ge_m -> ge_y)`.
/// In english, when modules are disabled the option cannot be `m`.
/// `modules_enabled` is the variable of the bool `MODULES` option.
pub fn modules_rule(t: &Ternary, modules_enabled: &Bool) -> Bool {
    bool_implies(&bool_not(modules_enabled), &bool_implies(&t.ge_m, &t.ge_y))
}

/// Tristate NOT: `!t` is `(!ge_m && !ge_y)`
/// In the old integer encoding this was 2 - t.
pub fn not(t: &Ternary) -> Ternary {
    Ternary {
        ge_m: bool_not(&t.ge_y),
        ge_y: bool_not(&t.ge_m),
    }
}

/// Tristate AND is the min() of n, m, y where y > m > n.
/// If `vars` is empty, this is `y`.
pub fn and(vars: &[Ternary]) -> Ternary {
    Ternary {
        ge_m: and_all(vars.iter().map(|v| &v.ge_m)),
        ge_y: and_all(vars.iter().map(|v| &v.ge_y)),
    }
}

/// Tristate OR is the max() of n, m, y where y > m > n.
/// If `vars` is empty, this is `n`.
pub fn or(vars: &[Ternary]) -> Ternary {
    Ternary {
        ge_m: or_all(vars.iter().map(|v| &v.ge_m)),
        ge_y: or_all(vars.iter().map(|v| &v.ge_y)),
    }
}

/// Ternary wrapper over Z3 if-then-else.
pub fn ite(cond: &Bool, then: &Ternary, r#else: &Ternary) -> Ternary {
    Ternary {
        ge_m: bool_ite(cond, &then.ge_m, &r#else.ge_m),
        ge_y: bool_ite(cond, &then.ge_y, &r#else.ge_y),
    }
}

/// The "clamp": promotes m to y.
/// i.e. "if t = m and then y else t".
/// Should be used for bools, also tristates when MODULES is disabled.
pub fn clamp(t: &Ternary, promote: &Bool) -> Ternary {
    Ternary {
        ge_m: t.ge_m.clone(),
        ge_y: bool_or(&t.ge_y, &bool_and(&t.ge_m, promote)),
    }
}

/// `a == b` as a proposition: (a.ge_m iff b.ge_m) AND (a.ge_y iff b.ge_y)
pub fn eq(a: &Ternary, b: &Ternary) -> Bool {
    bool_and(&bool_iff(&a.ge_m, &b.ge_m), &bool_iff(&a.ge_y, &b.ge_y))
}

/// a <= b iff [(a.ge_m -> b.ge_m) AND (a.ge_y -> b.ge_y)]
pub fn le(a: &Ternary, b: &Ternary) -> Bool {
    bool_and(
        &bool_implies(&a.ge_m, &b.ge_m),
        &bool_implies(&a.ge_y, &b.ge_y),
    )
}

/// a < b iff [(!a.ge_m AND b.ge_m) OR (!a.ge_y AND b.ge_y)]
pub fn lt(a: &Ternary, b: &Ternary) -> Bool {
    bool_or(
        &bool_and(&bool_not(&a.ge_m), &b.ge_m),
        &bool_and(&bool_not(&a.ge_y), &b.ge_y),
    )
}

/// walks the `(value, condition)` defaults in order and returns
/// the value of the first default whose condition is M or Y
/// (min of value with its condition)
/// value `n` if no condition is M OR Y. (Implicit default n)
pub fn active_default(defaults: &[(Ternary, Ternary)]) -> Ternary {
    let mut acc = Ternary::n();
    for (value, condition) in defaults.iter().rev() {
        let active = &condition.ge_m;
        let active_value = Ternary {
            ge_m: value.ge_m.clone(),
            ge_y: bool_and(&value.ge_y, &condition.ge_y),
        };
        acc = ite(active, &active_value, &acc);
    }
    acc
}

/// At most one of `expressions` holds. Pairwise clauses for small inputs (under 8);
/// otherwise a sequential prefix chain, which stays linear once Z3's internal
/// Tseitin conversion names the shared prefix nodes.
pub fn at_most_one(expressions: &[Bool]) -> Bool {
    const PAIRWISE_LIMIT: usize = 8;
    let mut clauses = Vec::new();
    if expressions.len() <= PAIRWISE_LIMIT {
        for i in 0..expressions.len() {
            for j in (i + 1)..expressions.len() {
                clauses.push(bool_not(&bool_and(&expressions[i], &expressions[j])));
            }
        }
    } else {
        // no expression may hold together with "some earlier expression holds"
        let mut earlier = Bool::from_bool(false);
        for f in expressions {
            clauses.push(bool_not(&bool_and(f, &earlier)));
            earlier = bool_or(&earlier, f);
        }
    }
    bool_and_all(&clauses)
}

/// A choice default is active when its condition is satisfied AND its target is
/// eligible; a satisfied-condition/ineligible-target default is skipped and
/// does not block later defaults.
/// Panics if a default's target index is out of bounds:
/// the caller resolves targets to member indices beforehand.
pub fn choice_untouched_selection(eligibilities: &[Bool], defaults: &[(usize, Bool)]) -> Vec<Bool> {
    // walk defaults
    let mut any_default_fired = Bool::from_bool(false);
    let mut effective_defaults: Vec<Vec<Bool>> = vec![Vec::new(); eligibilities.len()];
    for (target, condition_satisfied) in defaults {
        let hit = bool_and(condition_satisfied, &eligibilities[*target]);
        let effective = bool_and(&hit, &bool_not(&any_default_fired));
        effective_defaults[*target].push(effective);
        any_default_fired = bool_or(&any_default_fired, &hit);
    }

    // the fallback: the first eligible member, only when no default fired
    let no_default_fired = bool_not(&any_default_fired);
    let mut earlier_eligible = Bool::from_bool(false);
    let mut chosen = Vec::with_capacity(eligibilities.len());
    for (eligibility, mut ways) in eligibilities.iter().zip(effective_defaults) {
        let fallback = bool_and_all(&[
            eligibility.clone(),
            bool_not(&earlier_eligible),
            no_default_fired.clone(),
        ]);
        ways.push(fallback);
        chosen.push(bool_or_all(&ways));
        earlier_eligible = bool_or(&earlier_eligible, eligibility);
    }
    chosen
}

/// Conjunction (AND) of two bool expressions.
pub fn bool_and(a: &Bool, b: &Bool) -> Bool {
    match (a.as_bool(), b.as_bool()) {
        (Some(false), _) | (_, Some(false)) => Bool::from_bool(false),
        (Some(true), _) => b.clone(),
        (_, Some(true)) => a.clone(),
        _ => Bool::and(&[a.clone(), b.clone()]),
    }
}

/// Disjunction (OR) of two bool expressions.
pub fn bool_or(a: &Bool, b: &Bool) -> Bool {
    match (a.as_bool(), b.as_bool()) {
        (Some(true), _) | (_, Some(true)) => Bool::from_bool(true),
        (Some(false), _) => b.clone(),
        (_, Some(false)) => a.clone(),
        _ => Bool::or(&[a.clone(), b.clone()]),
    }
}

/// Negation (NOT) of a bool expressions.
pub fn bool_not(a: &Bool) -> Bool {
    match a.as_bool() {
        Some(b) => Bool::from_bool(!b),
        None => a.not(),
    }
}

/// Implication between bool expressions.
pub fn bool_implies(a: &Bool, b: &Bool) -> Bool {
    match (a.as_bool(), b.as_bool()) {
        (Some(false), _) | (_, Some(true)) => Bool::from_bool(true),
        (Some(true), _) => b.clone(),
        (_, Some(false)) => bool_not(a),
        _ => a.implies(b),
    }
}

/// Biconditional (IFF) between bool expressions.
pub fn bool_iff(a: &Bool, b: &Bool) -> Bool {
    match (a.as_bool(), b.as_bool()) {
        (Some(x), Some(y)) => Bool::from_bool(x == y),
        (Some(true), _) => b.clone(),
        (_, Some(true)) => a.clone(),
        (Some(false), _) => bool_not(b),
        (_, Some(false)) => bool_not(a),
        _ => a.iff(b),
    }
}

/// If-then-else over boolean expressions.
pub fn bool_ite(guard: &Bool, then: &Bool, r#else: &Bool) -> Bool {
    match guard.as_bool() {
        Some(true) => then.clone(),
        Some(false) => r#else.clone(),
        None if then == r#else => then.clone(),
        None => guard.ite(then, r#else),
    }
}

/// Conjunction (AND) of multiple bool expressions.
pub fn bool_and_all(expressions: &[Bool]) -> Bool {
    and_all(expressions.iter())
}

/// /// Disjunction (OR) of multiple bool expressions.
pub fn bool_or_all(expressions: &[Bool]) -> Bool {
    or_all(expressions.iter())
}

/// Tseitin-names a expression: creates a new bool variable `name` together
/// with the definition `name IFF expression`, which the caller must assert. The
/// variable can then be reused across constraints (structure sharing) and read
/// straight out of a model. A constant expressions passes through unchanged.
pub fn define_bool(name: &str, expression: &Bool) -> (Bool, Option<Bool>) {
    match expression.as_bool() {
        Some(_) => (expression.clone(), None),
        None => {
            let variable = Bool::new_const(name);
            let definition = variable.iff(expression);
            (variable, Some(definition))
        }
    }
}

/// Tseitin-names a ternary, bundling the definitions,
/// also the redundant ladder between the named components (which is entailed but helps propagation)
/// into a single constraint for the caller to assert.
pub fn define_ternary(name: &str, expression: &Ternary) -> (Ternary, Option<Bool>) {
    let (ge_m, definition_m) = define_bool(&format!("{name}>=m"), &expression.ge_m);
    let (ge_y, definition_y) = define_bool(&format!("{name}>=y"), &expression.ge_y);

    let mut definitions: Vec<Bool> = definition_m.into_iter().chain(definition_y).collect();
    let ladder = bool_implies(&ge_y, &ge_m);
    if ladder.as_bool().is_none() {
        definitions.push(ladder);
    }

    let definition = match definitions.is_empty() {
        true => None,
        false => Some(bool_and_all(&definitions)),
    };
    (Ternary { ge_m, ge_y }, definition)
}

fn and_all<'a>(components: impl Iterator<Item = &'a Bool>) -> Bool {
    let mut out: Vec<Bool> = Vec::new();
    for b in components {
        match b.as_bool() {
            Some(false) => return Bool::from_bool(false),
            Some(true) => continue,
            None => out.push(b.clone()),
        }
    }
    match out.len() {
        0 => Bool::from_bool(true),
        1 => out.pop().unwrap(),
        _ => Bool::and(&out),
    }
}

fn or_all<'a>(components: impl Iterator<Item = &'a Bool>) -> Bool {
    let mut out: Vec<Bool> = Vec::new();
    for b in components {
        match b.as_bool() {
            Some(true) => return Bool::from_bool(true),
            Some(false) => continue,
            None => out.push(b.clone()),
        }
    }
    match out.len() {
        0 => Bool::from_bool(false),
        1 => out.pop().unwrap(),
        _ => Bool::or(&out),
    }
}

/// NOTE: the tests are AI slop, generated once I got things to work.
/// TODO: look at these more closely, consider hand-written tests
#[cfg(test)]
mod tests {
    use super::*;
    use z3::{SatResult, Solver};

    fn t(v: u8) -> Ternary {
        match v {
            0 => Ternary::n(),
            1 => Ternary::m(),
            2 => Ternary::y(),
            _ => unreachable!(),
        }
    }

    // The re-encoding is verified operator by operator against the integer
    // model over all constant inputs; constant folding makes the results
    // literal, so no solver is needed.

    #[test]
    fn not_matches_integer_model() {
        for v in 0..=2u8 {
            assert_eq!(not(&t(v)).as_const(), Some(2 - v), "!{v}");
        }
    }

    #[test]
    fn and_or_match_min_max() {
        for a in 0..=2u8 {
            for b in 0..=2u8 {
                assert_eq!(and(&[t(a), t(b)]).as_const(), Some(a.min(b)), "{a} && {b}");
                assert_eq!(or(&[t(a), t(b)]).as_const(), Some(a.max(b)), "{a} || {b}");
            }
        }
        // empty operands take the operator's identity
        assert_eq!(and(&[]).as_const(), Some(2));
        assert_eq!(or(&[]).as_const(), Some(0));
    }

    #[test]
    fn comparisons_match_integer_model() {
        for a in 0..=2u8 {
            for b in 0..=2u8 {
                assert_eq!(eq(&t(a), &t(b)).as_bool(), Some(a == b), "{a} = {b}");
                assert_eq!(le(&t(a), &t(b)).as_bool(), Some(a <= b), "{a} <= {b}");
                assert_eq!(lt(&t(a), &t(b)).as_bool(), Some(a < b), "{a} < {b}");
            }
        }
    }

    #[test]
    fn gt_n_and_decode() {
        for v in 0..=2u8 {
            assert_eq!(t(v).gt_n().as_bool(), Some(v > 0));
            assert_eq!(t(v).is_n().as_bool(), Some(v == 0));
            assert_eq!(t(v).is_m().as_bool(), Some(v == 1));
            assert_eq!(t(v).is_y().as_bool(), Some(v == 2));
        }
    }

    #[test]
    fn clamp_promotes_m_to_y() {
        for v in 0..=2u8 {
            for promote in [false, true] {
                let expected = if v == 1 && promote { 2 } else { v };
                assert_eq!(
                    clamp(&t(v), &Bool::from_bool(promote)).as_const(),
                    Some(expected),
                    "clamp({v}, promote={promote})"
                );
            }
        }
    }

    #[test]
    fn ite_selects_branch() {
        for v in 0..=2u8 {
            for w in 0..=2u8 {
                assert_eq!(
                    ite(&Bool::from_bool(true), &t(v), &t(w)).as_const(),
                    Some(v)
                );
                assert_eq!(
                    ite(&Bool::from_bool(false), &t(v), &t(w)).as_const(),
                    Some(w)
                );
            }
        }
    }

    #[test]
    fn active_default_takes_first_fired() {
        // first default's condition is n (does not fire); the second fires
        // with condition m, so the y value is min'd down to m
        let defaults = [(t(2), t(0)), (t(2), t(1)), (t(1), t(2))];
        assert_eq!(active_default(&defaults).as_const(), Some(1));

        // no default fires
        assert_eq!(active_default(&[(t(2), t(0))]).as_const(), Some(0));
        assert_eq!(active_default(&[]).as_const(), Some(0));

        // the first fired default wins even if a later one is "bigger"
        let defaults = [(t(1), t(2)), (t(2), t(2))];
        assert_eq!(active_default(&defaults).as_const(), Some(1));
    }

    #[test]
    fn operators_preserve_ladder_on_constants() {
        // every operator result over constant inputs decodes to a value,
        // i.e. never produces the ladder-violating pair ⟨⊥,⊤⟩
        for a in 0..=2u8 {
            assert!(not(&t(a)).as_const().is_some());
            for b in 0..=2u8 {
                assert!(and(&[t(a), t(b)]).as_const().is_some());
                assert!(or(&[t(a), t(b)]).as_const().is_some());
                for promote in [false, true] {
                    assert!(clamp(&t(a), &Bool::from_bool(promote)).as_const().is_some());
                }
            }
        }
    }

    #[test]
    fn tristate_domain_and_modules_rule() {
        // ladder: ⟨⊥,⊤⟩ is not a value
        let (x, ladder) = new_tristate("X");
        let solver = Solver::new();
        solver.assert(&ladder);
        solver.assert(x.ge_y.clone());
        solver.assert(bool_not(&x.ge_m));
        assert_eq!(solver.check(), SatResult::Unsat);

        // modules disabled forbids m...
        let (x, ladder) = new_tristate("X_NO_MOD");
        let solver = Solver::new();
        solver.assert(&ladder);
        solver.assert(modules_rule(&x, &Bool::from_bool(false)));
        solver.assert(x.is_m());
        assert_eq!(solver.check(), SatResult::Unsat);

        // ...but modules enabled allows it
        let (x, ladder) = new_tristate("X_MOD");
        let solver = Solver::new();
        solver.assert(&ladder);
        solver.assert(modules_rule(&x, &Bool::from_bool(true)));
        solver.assert(x.is_m());
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn bool_option_cannot_be_m() {
        // a bool option is one variable used for both components, so X = m
        // (ge_m ∧ ¬ge_y) is contradictory by construction
        let x = new_bool("B");
        let solver = Solver::new();
        solver.assert(x.is_m());
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    #[test]
    fn n_ary_bool_helpers_fold() {
        let t = Bool::from_bool(true);
        let f = Bool::from_bool(false);
        assert_eq!(bool_and_all(&[]).as_bool(), Some(true));
        assert_eq!(bool_or_all(&[]).as_bool(), Some(false));
        assert_eq!(bool_and_all(&[t.clone(), t.clone()]).as_bool(), Some(true));
        assert_eq!(bool_and_all(&[t.clone(), f.clone()]).as_bool(), Some(false));
        assert_eq!(bool_or_all(&[f.clone(), t.clone()]).as_bool(), Some(true));
        assert_eq!(bool_or_all(&[f.clone(), f]).as_bool(), Some(false));
        // non-constant operands pass through
        let v = Bool::new_const("V");
        assert_eq!(bool_and_all(&[t.clone(), v.clone()]), v);
        assert_eq!(bool_or_all(&[Bool::from_bool(false), v.clone()]), v);
    }

    /// Exercises both the pairwise (k <= 8) and sequential (k > 8) encodings.
    fn check_at_most_one(k: usize) {
        let vars: Vec<Bool> = (0..k)
            .map(|i| Bool::new_const(format!("AMO{k}_{i}")))
            .collect();

        // two members enabled together: unsat
        let solver = Solver::new();
        solver.assert(at_most_one(&vars));
        solver.assert(&vars[0]);
        solver.assert(&vars[k - 1]);
        assert_eq!(solver.check(), SatResult::Unsat, "k={k}");

        // a single enabled member: sat
        let solver = Solver::new();
        solver.assert(at_most_one(&vars));
        solver.assert(&vars[k / 2]);
        assert_eq!(solver.check(), SatResult::Sat, "k={k}");
    }

    #[test]
    fn at_most_one_pairwise_and_sequential() {
        check_at_most_one(2);
        check_at_most_one(8);
        check_at_most_one(30);
        // trivial sizes produce no constraint
        assert_eq!(at_most_one(&[]).as_bool(), Some(true));
        assert_eq!(
            at_most_one(&[Bool::new_const("AMO_SINGLE")]).as_bool(),
            Some(true)
        );
    }

    /// Decodes a vector of constant propositions into the index of the single
    /// true one (None if all false; panics on multiple).
    fn decode_selection(chosen: &[Bool]) -> Option<usize> {
        let mut selected = None;
        for (i, c) in chosen.iter().enumerate() {
            if c.as_bool()
                .expect("constant inputs give constant selections")
            {
                assert!(selected.is_none(), "more than one member chosen");
                selected = Some(i);
            }
        }
        selected
    }

    #[test]
    fn choice_untouched_selection_follows_defaults_then_first_eligible() {
        let t = || Bool::from_bool(true);
        let f = || Bool::from_bool(false);

        // no defaults: the first eligible member wins
        let chosen = choice_untouched_selection(&[f(), t(), t()], &[]);
        assert_eq!(decode_selection(&chosen), Some(1));

        // a fired default beats the first-eligible fallback
        let chosen = choice_untouched_selection(&[t(), t(), t()], &[(2, t())]);
        assert_eq!(decode_selection(&chosen), Some(2));

        // the first firing default shadows later ones
        let chosen = choice_untouched_selection(&[t(), t(), t()], &[(1, t()), (2, t())]);
        assert_eq!(decode_selection(&chosen), Some(1));

        // a satisfied-condition default with an ineligible target is skipped,
        // not blocking: the next default fires
        let chosen = choice_untouched_selection(&[t(), f(), t()], &[(1, t()), (2, t())]);
        assert_eq!(decode_selection(&chosen), Some(2));

        // an unsatisfied-condition default is skipped too
        let chosen = choice_untouched_selection(&[t(), t()], &[(1, f())]);
        assert_eq!(decode_selection(&chosen), Some(0));

        // no default fires and nothing is eligible: no selection
        let chosen = choice_untouched_selection(&[f(), f()], &[(1, t())]);
        assert_eq!(decode_selection(&chosen), None);

        // no members: no selections
        assert!(choice_untouched_selection(&[], &[]).is_empty());
    }

    #[test]
    fn define_bool_names_formulas_and_passes_constants() {
        // constants pass through with no definition
        let (v, def) = define_bool("DEF_CONST", &Bool::from_bool(true));
        assert_eq!(v.as_bool(), Some(true));
        assert!(def.is_none());

        // a named formula: the variable tracks the formula in every model
        let a = Bool::new_const("DEF_A");
        let b = Bool::new_const("DEF_B");
        let formula = bool_and(&a, &b);
        let (v, def) = define_bool("DEF_AB", &formula);
        assert!(v.as_bool().is_none());

        let solver = Solver::new();
        solver.assert(def.expect("non-constant formulas get a definition"));
        solver.assert(&v);
        solver.assert(bool_not(&a));
        // v forced true but its definition a ∧ b is falsified
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    #[test]
    fn define_ternary_names_components_with_ladder() {
        // fully constant pairs pass through
        let (pair, def) = define_ternary("DEFT_CONST", &Ternary::m());
        assert_eq!(pair.as_const(), Some(1));
        assert!(def.is_none());

        // a non-constant pair gets named components and keeps its value
        let (x, x_ladder) = new_tristate("DEFT_X");
        let (named, def) = define_ternary("DEFT_XVIS", &x);
        let solver = Solver::new();
        solver.assert(&x_ladder);
        solver.assert(def.expect("non-constant pairs get a definition"));
        solver.assert(x.is_m());
        solver.assert(named.is_y());
        assert_eq!(solver.check(), SatResult::Unsat);

        let solver = Solver::new();
        solver.assert(&x_ladder);
        let (named, def) = define_ternary("DEFT_XVIS2", &x);
        solver.assert(def.unwrap());
        solver.assert(x.is_m());
        solver.assert(named.is_m());
        assert_eq!(solver.check(), SatResult::Sat);
    }
}
