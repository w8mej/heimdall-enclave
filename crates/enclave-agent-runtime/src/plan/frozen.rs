//! Frozen dialect definition and AST static validation (FS-704 §8.2.1, GAP-18).
//!
//! DEFECT-F-69: every rule is enforced on the parsed AST
//! ([`crate::plan::ast_check`]). The per-line text checks below only give
//! early, specific error codes for `load` / `import` / `while`, which the
//! parser rejects anyway; they can only add rejections, never admit a plan.

use enclave_core::error::EnclaveResult;
use enclave_core::profile::Profile;
use enclave_core::{err, fail};
use starlark::syntax::{AstModule, Dialect};

use crate::plan::ast_check::check_plan;

/// Build the frozen dialect for `EnclaveStarlarkV1`.
pub fn frozen_dialect() -> Dialect {
    let mut d = Dialect::Standard;
    d.enable_load = false;
    d.enable_top_level_stmt = true;
    d
}

/// Static check information for tool calls extracted from plan AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanToolCall {
    /// Target server (a string literal in the plan).
    pub server: String,
    /// Target tool name (a string literal in the plan).
    pub tool_name: String,
    /// Number of arguments.
    pub arity: usize,
}

/// Validate source code against the frozen dialect rules.
pub fn validate_frozen_plan(source: &str, profile: Profile) -> EnclaveResult<Vec<PlanToolCall>> {
    parse_frozen_plan(source, profile).map(|(calls, _)| calls)
}

/// Validate and parse once: the returned AST is exactly the one validated,
/// so the evaluator runs what the checks saw.
pub fn parse_frozen_plan(
    source: &str,
    profile: Profile,
) -> EnclaveResult<(Vec<PlanToolCall>, AstModule)> {
    parse_frozen_plan_with_guard(source, profile, |_| Ok(()))
}

/// Parse once, then apply the caller's AST guard before the recursive frozen
/// visitor. Live execution must establish its work bounds before that walk;
/// the standalone API retains its existing validation order and dialect.
pub(crate) fn parse_frozen_plan_with_guard(
    source: &str,
    profile: Profile,
    guard: impl FnOnce(&AstModule) -> EnclaveResult<()>,
) -> EnclaveResult<(Vec<PlanToolCall>, AstModule)> {
    reject_forbidden_lines(source)?;
    let ast = AstModule::parse("plan.star", source.to_string(), &frozen_dialect())
        .map_err(|e| err!(EINVAL, "STARLARK_PARSE_ERROR", "{e}"))?;
    guard(&ast)?;
    let calls = check_plan(ast.statement(), profile == Profile::L3)?;
    Ok((calls, ast))
}

/// Early diagnostics only (the parser and the AST walk are authoritative).
fn reject_forbidden_lines(source: &str) -> EnclaveResult<()> {
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("load(") || trimmed.starts_with("load ") {
            fail!(EINVAL, "STARLARK_LOAD_FORBIDDEN");
        }
        if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
            fail!(EINVAL, "STARLARK_IMPORT_FORBIDDEN");
        }
        if trimmed.starts_with("while ") || trimmed.starts_with("while(") {
            fail!(EINVAL, "STARLARK_WHILE_FORBIDDEN");
        }
    }
    Ok(())
}
