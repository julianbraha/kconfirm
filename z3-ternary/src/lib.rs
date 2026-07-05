use z3::ast::{Bool, Int};

/// Returns the boolean as a Z3 Integer with lower and upper bounds with disallowed middle to be added to the solver as constraints.
pub fn new_bool(name: &str) -> (Int, Bool, Bool, Bool) {
    let tri = Int::new_const(name);

    let lower_bound = tri.ge(0);
    let upper_bound = tri.le(2);
    let excluded_middle = tri.ne(1);
    (tri, lower_bound, upper_bound, excluded_middle)
}

/// Returns the tristate as a Z3 Integer with lower and upper bounds to be added to the solver as constraints.
pub fn new_tristate(name: &str) -> (Int, Bool, Bool) {
    let tri = Int::new_const(name);

    let lower_bound = tri.ge(0);
    let upper_bound = tri.le(2);
    (tri, lower_bound, upper_bound)
}

/// Negates the tristate/bool:
///     2 - 1 = 1 (tristate-only)
///     2 - 0 = 2
///     2 - 2 = 0
pub fn not(var: &Int) -> Int {
    2 - var
}

/// Returns the minimum of the integers in `vars`.
/// This is equivalent to a logical `&&`.
pub fn min(vars: &[Int]) -> Int {
    vars.iter()
        .fold(Int::from_i64(2), |acc, x| acc.le(x).ite(&acc, x))
}

/// Alias of `min`
pub fn and(vars: &[Int]) -> Int {
    min(vars)
}

/// Returns the maximum of the integers in `vars`.
/// This is equivalent to a logical `||`.
pub fn max(vars: &[Int]) -> Int {
    vars.iter()
        .fold(Int::from_i64(0), |acc, x| acc.ge(x).ite(&acc, x))
}

/// Alias of `max`
pub fn or(vars: &[Int]) -> Int {
    max(vars)
}

/// left-to-right: e.g. X implies Y
pub fn implies(x: &Int, y: &Int) -> Bool {
    x.le(y)
}
