//! Starlark plan interpreter for agent workflows (FS-704 §8.2.1, GAP-18).
//!
//! DEFECT-F-65: the interpreter validates a plan, runs the static Cedar
//! pre-check and evaluates it. The standalone entry has no authority and
//! fails closed at tool dispatch. The authenticated service entry dispatches
//! each reached call through the live [`crate::pdp::Pdp::authorize`].
//! Standalone `tool_call(...)` fails closed with
//! `EPERM PLAN_TOOL_DISPATCH_UNWIRED` (`ERR_IFC_SEALED_ABORT` in L3). References are built only by the
//! runtime from MAC-verified heap envelopes ([`PlanRef::from_heap`]); a plan
//! cannot construct a `Ref` or choose its labels.

use enclave_core::error::{EnclaveError, EnclaveResult};
use starlark::any::ProvidesStaticType;
use enclave_core::fail;
use enclave_core::profile::{ActionClass, Profile};
use serde::{Deserialize, Serialize};
use starlark::environment::{Globals, GlobalsBuilder, Module};
use starlark::eval::Evaluator;
use starlark::starlark_module;
use starlark::syntax::AstModule;
use starlark::values::{Value, ValueLike};
use starlark::ErrorKind;

use crate::cedar_engine::CedarEngine;
use crate::heap::CapabilityHeap;
use crate::plan::ast_check::is_reserved_name;
use crate::plan::frozen::{parse_frozen_plan, parse_frozen_plan_with_guard, PlanToolCall};
use crate::plan::ref_value::PlanRef;
use crate::registry::ToolRegistry;
use super::arguments::Argument;

/// Only the authenticated service can provide this authority-bearing context.
pub(crate) trait PlanRuntime {
    /// Effect-free whole-AST eligibility, including unreachable branches.
    /// Passing conveys no authority to dispatch any individual call.
    fn precheck(&self, calls: &[PlanToolCall]) -> EnclaveResult<()>;
    fn call(&self, server: &str, tool: &str, args: Argument) -> EnclaveResult<PlanRef>;
    fn cancelled(&self) -> bool;
}

#[derive(ProvidesStaticType)]
struct LiveContext<'a> { runtime: &'a dyn PlanRuntime }

struct SilentPrint;
impl starlark::PrintHandler for SilentPrint {
    fn println(&self, _text: &str) -> starlark::Result<()> { Ok(()) }
}

#[derive(Debug)]
struct LiveCallError(EnclaveError);
impl std::fmt::Display for LiveCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}
impl std::error::Error for LiveCallError {}


/// Plan evaluation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanResult {
    /// Return value string or summary.
    pub return_value: String,
    /// Number of `tool_call` sites that passed the static Cedar pre-check.
    /// None of them was dispatched (DEFECT-F-65).
    pub prechecked_tool_calls: usize,
}

/// Plan evaluation context.
pub struct PlanExecutionContext<'a> {
    /// Security profile.
    pub profile: Profile,
    /// Capability heap: the only source of `Ref` values and their labels.
    pub heap: &'a CapabilityHeap,
    /// Tool registry / depot lock.
    pub registry: &'a ToolRegistry,
    /// Active Cedar engine.
    pub cedar: &'a CedarEngine,
    /// `(binding name, heap handle)`: each handle is bound in the plan's
    /// module as a `Ref` whose label is read from the verified envelope.
    pub initial_handles: Vec<(String, String)>,
    /// Fuel budget (default 10,000).
    pub fuel_budget: u64,
}

impl<'a> std::fmt::Debug for PlanExecutionContext<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlanExecutionContext")
            .field("profile", &self.profile)
            .field("initial_handles", &self.initial_handles)
            .field("fuel_budget", &self.fuel_budget)
            .finish()
    }
}

/// Error a native builtin raises when a plan reaches `tool_call(...)`.
#[derive(Debug)]
struct ToolDispatchRefused;

impl std::fmt::Display for ToolDispatchRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PLAN_TOOL_DISPATCH_UNWIRED")
    }
}

impl std::error::Error for ToolDispatchRefused {}

/// How an evaluation ended.
enum EvalOutcome {
    Value(String),
    FuelExhausted,
    /// The tick limit could not be installed (e.g. a zero budget).
    FuelUnset(String),
    ToolDispatchRefused,
    LiveFailure(EnclaveError),
    Error(String),
}

/// EnclaveStarlarkV1 plan evaluation engine.
#[derive(Debug, Default)]
pub struct EnclaveStarlarkV1;

impl EnclaveStarlarkV1 {
    /// Create a new interpreter.
    pub fn new() -> Self {
        Self
    }

    /// Validate, pre-check and evaluate an agent plan under the frozen dialect.
    pub fn execute(source: &str, ctx: &mut PlanExecutionContext<'_>) -> EnclaveResult<PlanResult> {
        let sealed = ctx.profile == Profile::L3;
        // DEFECT-F-69: parse once; the AST evaluated is the AST validated.
        let (tool_calls, ast) = match parse_frozen_plan(source, ctx.profile) {
            Ok(v) => v,
            Err(_) if sealed => fail!(EPERM, "ERR_IFC_SEALED_ABORT"),
            Err(e) => return Err(e),
        };
        Self::static_precheck(&tool_calls, ctx)?;
        let refs = Self::bind_refs(ctx.heap, &ctx.initial_handles)?;
        let return_value = match Self::evaluate(ast, &refs, ctx.fuel_budget, None) {
            EvalOutcome::Value(v) => v,
            EvalOutcome::ToolDispatchRefused if sealed => fail!(EPERM, "ERR_IFC_SEALED_ABORT"),
            EvalOutcome::ToolDispatchRefused => fail!(
                EPERM,
                "PLAN_TOOL_DISPATCH_UNWIRED",
                "plans cannot dispatch tools; use AuthorizeToolCall (Pdp::authorize)"
            ),
            EvalOutcome::FuelExhausted => fail!(EINVAL, "ERR_IFC_FUEL_EXHAUSTED"),
            EvalOutcome::FuelUnset(e) => fail!(EINVAL, "ERR_IFC_FUEL_BUDGET", "{e}"),
            EvalOutcome::LiveFailure(e) => return Err(e),
            EvalOutcome::Error(_) if sealed => fail!(EPERM, "ERR_IFC_SEALED_ABORT"),
            EvalOutcome::Error(e) => fail!(EIO, "STARLARK_EVAL_ERROR", "{e}"),
        };
        Ok(PlanResult {
            return_value,
            prechecked_tool_calls: tool_calls.len(),
        })
    }

    /// Check every branch before evaluation, then authorize each reached call
    /// through the live PDP. Eligibility never performs a hardware ceremony.
    pub(crate) fn execute_live(
        source: &str,
        profile: Profile,
        refs: &[(String, PlanRef)],
        fuel_budget: u64,
        runtime: &dyn PlanRuntime,
    ) -> EnclaveResult<String> {
        let result = (|| {
            super::live_check::preflight(source)?;
            let (calls, ast) = parse_frozen_plan_with_guard(source, profile, |ast| {
                super::live_check::check(ast.statement(), refs)
            })?;
            let mut seen = std::collections::HashSet::new();
            for (name, _) in refs {
                if !is_identifier(name) || is_reserved_name(name) || !seen.insert(name) {
                    fail!(EINVAL, "PLAN_BINDING_NAME");
                }
            }
            runtime.precheck(&calls)?;
            match Self::evaluate(ast, refs, fuel_budget, Some(&LiveContext { runtime })) {
                EvalOutcome::Value(v) if v.len() <= 64 * 1024 => Ok(v),
                EvalOutcome::Value(_) => fail!(E2BIG, "PLAN_RESULT_BOUNDS"),
                EvalOutcome::FuelExhausted => fail!(EINVAL, "ERR_IFC_FUEL_EXHAUSTED"),
                EvalOutcome::FuelUnset(_) => fail!(EINVAL, "ERR_IFC_FUEL_BUDGET"),
                EvalOutcome::LiveFailure(e) => Err(e),
                EvalOutcome::ToolDispatchRefused => fail!(EPERM, "PLAN_TOOL_DISPATCH_UNWIRED"),
                // Never return interpreter traces that might interpolate values.
                EvalOutcome::Error(_) => fail!(EINVAL, "STARLARK_EVAL_ERROR"),
            }
        })();
        if profile == Profile::L3 && result.is_err() { fail!(EPERM, "ERR_IFC_SEALED_ABORT"); }
        result
    }

    /// Static Cedar pre-check for every named tool of class `>= A2`, using the
    /// lock's resource (name, sink clearance, namespace) and the active profile.
    fn static_precheck(
        calls: &[PlanToolCall],
        ctx: &PlanExecutionContext<'_>,
    ) -> EnclaveResult<()> {
        for call in calls {
            let tool = ctx.registry.resolve(&call.server, &call.tool_name);
            if tool.resource.action_class < ActionClass::A2 {
                continue;
            }
            if ctx
                .cedar
                .authorize_static("principal_plan", &tool.resource, ctx.profile)
            {
                continue;
            }
            if ctx.profile == Profile::L3 {
                fail!(EPERM, "ERR_IFC_SEALED_ABORT");
            }
            fail!(
                EACCES,
                "ERR_IFC_STATIC_CEDAR_DENIED",
                "tool {}:{} requires prior authorization",
                call.server,
                call.tool_name
            );
        }
        Ok(())
    }

    /// Build the plan's `Ref` bindings from the heap (labels from the verified
    /// envelope). Unknown, wiped or tampered handles fail `HANDLE_FORGERY`.
    fn bind_refs(
        heap: &CapabilityHeap,
        handles: &[(String, String)],
    ) -> EnclaveResult<Vec<(String, PlanRef)>> {
        let mut seen = std::collections::HashSet::new();
        handles
            .iter()
            .map(|(name, handle)| {
                if !is_identifier(name) || is_reserved_name(name) || !seen.insert(name.as_str()) {
                    fail!(EINVAL, "PLAN_BINDING_NAME", "{name:?}");
                }
                Ok((name.clone(), PlanRef::from_heap(heap, handle)?))
            })
            .collect()
    }

    fn evaluate(ast: AstModule, refs: &[(String, PlanRef)], fuel_budget: u64, live: Option<&LiveContext<'_>>) -> EvalOutcome {
        let globals = Self::build_globals();
        Module::with_temp_heap(|module| {
            for (name, r) in refs {
                let v = module.heap().alloc(r.clone());
                module.set(name, v);
            }
            let silent = SilentPrint;
            let mut eval = Evaluator::new(&module);
            if let Some(live) = live {
                eval.extra = Some(live);
                eval.set_print_handler(&silent);
                eval.set_check_cancelled(Box::new(|| live.runtime.cancelled()));
                if eval.set_max_heap_size(2 * 1024 * 1024).is_err()
                    || eval.set_max_callstack_size(64).is_err() {
                    return EvalOutcome::Error("PLAN_RESOURCE_LIMIT".into());
                }
            }
            // DEFECT-F-69: never evaluate without a fuel limit.
            if let Err(e) = eval.set_max_tick_count(fuel_budget) {
                return EvalOutcome::FuelUnset(e.to_string());
            }
            match eval.eval_module(ast, &globals) {
                Ok(_) if live.is_some() && eval.heap().peak_allocated_bytes()
                    + eval.frozen_heap().allocated_bytes() > 2 * 1024 * 1024 =>
                    EvalOutcome::Error("PLAN_RESOURCE_LIMIT".into()),
                Ok(v) if live.is_some() => live_return(v),
                Ok(v) => EvalOutcome::Value(v.to_string()),
                // DEFECT-F-68: fuel exhaustion is read from the evaluator's
                // tick counter, never inferred from error text.
                Err(_) if eval.get_total_tick_count() > fuel_budget => EvalOutcome::FuelExhausted,
                Err(e) => classify(e),
            }
        })
    }

    /// Standard globals plus the authority-sensitive tool builtin.
    fn build_globals() -> Globals {
        let mut builder = GlobalsBuilder::standard();
        register_enclave_builtins(&mut builder);
        builder.build()
    }
}

// Never recursively format attacker-aliased containers (e.g. [x,x] chains).
fn live_return(value:Value<'_>)->EvalOutcome {
    if let Some(reference)=value.downcast_ref::<PlanRef>() {
        return EvalOutcome::Value(reference.to_string());
    }
    if matches!(value.get_type(), "NoneType"|"bool"|"int"|"float"|"string") {
        if value.unpack_str().is_some_and(|text|text.len()>64*1024) {
            return EvalOutcome::LiveFailure(enclave_core::err!(E2BIG,"PLAN_RESULT_BOUNDS"));
        }
        return EvalOutcome::Value(value.to_string());
    }
    EvalOutcome::LiveFailure(enclave_core::err!(EINVAL,"PLAN_RESULT_SCALAR_OR_REF_REQUIRED"))
}

fn classify(e: starlark::Error) -> EvalOutcome {
    if let ErrorKind::Native(inner) = e.kind() {
        if let Some(error) = inner.downcast_ref::<LiveCallError>() { return EvalOutcome::LiveFailure(error.0.clone()); }
        if inner.downcast_ref::<ToolDispatchRefused>().is_some() {
            return EvalOutcome::ToolDispatchRefused;
        }
    }
    EvalOutcome::Error(e.to_string())
}

/// `[A-Za-z_][A-Za-z0-9_]*`.
fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

#[starlark_module]
fn register_enclave_builtins(builder: &mut GlobalsBuilder) {
    /// `tool_call(server, tool_name, args)` uses only a service-owned live
    /// context. The standalone evaluator fails closed without that authority.
    fn tool_call<'v>(
        #[starlark(require = pos)] server: &str,
        #[starlark(require = pos)] tool_name: &str,
        #[starlark(require = pos)] args: Value<'v>,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<PlanRef> {
        let Some(context) = eval.extra.and_then(|e| e.downcast_ref::<LiveContext>()) else {
            return Err(ToolDispatchRefused.into());
        };
        let result = Argument::extract(args).and_then(|args| context.runtime.call(server, tool_name, args));
        result.map_err(|error| LiveCallError(EnclaveError::new(error.errno, &error.reason)).into())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn f68_interpreter_never_prints_evaluation_errors() {
        let src = include_str!("interpreter.rs");
        for m in [
            concat!("eprint", "ln!"),
            concat!("print", "ln!"),
            concat!("dbg", "!"),
        ] {
            assert!(!src.contains(m), "{m} found in interpreter.rs");
        }
    }
}
