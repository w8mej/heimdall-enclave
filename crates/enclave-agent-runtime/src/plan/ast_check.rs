//! AST-based frozen-dialect enforcement (DEFECT-F-69).
//!
//! The plan's parsed AST, not its text, decides every rule. The walk is an
//! exhaustive `match` over the starlark-rust node types, so a node kind added
//! by a library upgrade fails to compile here instead of being skipped.
//!
//! * Dynamic reflection (`getattr`, `setattr`, `hasattr`, `dir`) is refused
//!   wherever the name is *read*, so aliasing (`g = getattr`) and spacing
//!   (`getattr (x)`) are caught.
//! * Reserved names (builtins the rules depend on) can never be rebound
//!   (assignment, `def`, parameter, loop or comprehension variable), so
//!   `range` and `tool_call` always resolve to the builtins.
//! * `tool_call` is recognised only as the direct callee of a call whose
//!   server and tool are positional string literals; any other use of the
//!   name is refused. Text in strings and comments is never a call.
//! * `L3`: every `for` must iterate `range(N)` with a literal `0 <= N <= 16`;
//!   comprehensions are refused by node type.

use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use starlark::syntax::ast::{
    ArgumentP, AssignTargetP, AstAssignTarget, AstExpr, AstLiteral, AstParameter, AstStmt,
    AstTypeExpr, ClauseP, ExprP, ForClause, ParameterP, StmtP,
};
use starlark_syntax::lexer::TokenInt;

use crate::plan::frozen::PlanToolCall;

/// Maximum literal `range(N)` bound in `L3`.
pub const L3_MAX_RANGE: i32 = 16;

/// Names whose meaning the rules rely on; a plan may read but never bind them.
pub const RESERVED_NAMES: &[&str] = &[
    "tool_call",
    "declassify_enum",
    "range",
    "getattr",
    "setattr",
    "hasattr",
    "dir",
];

const REFLECTION: &[&str] = &["getattr", "setattr", "hasattr", "dir"];

/// Whether `name` is reserved (also applied to runtime-bound `Ref` names).
pub fn is_reserved_name(name: &str) -> bool {
    RESERVED_NAMES.contains(&name)
}

/// Walk `stmt` and return every statically named tool call.
pub fn check_plan(stmt: &AstStmt, l3: bool) -> EnclaveResult<Vec<PlanToolCall>> {
    let mut w = Walker {
        l3,
        calls: Vec::new(),
    };
    w.stmt(stmt)?;
    Ok(w.calls)
}

struct Walker {
    l3: bool,
    calls: Vec<PlanToolCall>,
}

impl Walker {
    fn stmt(&mut self, s: &AstStmt) -> EnclaveResult<()> {
        match &s.node {
            StmtP::Break | StmtP::Continue | StmtP::Pass => Ok(()),
            StmtP::Return(e) => e.as_ref().map_or(Ok(()), |e| self.expr(e)),
            StmtP::Expression(e) => self.expr(e),
            StmtP::Assign(a) => {
                self.target(&a.lhs)?;
                if let Some(t) = &a.ty {
                    self.type_expr(t)?;
                }
                self.expr(&a.rhs)
            }
            StmtP::AssignModify(t, _, e) => {
                self.target(t)?;
                self.expr(e)
            }
            StmtP::Statements(v) => v.iter().try_for_each(|s| self.stmt(s)),
            StmtP::If(c, b) => {
                self.expr(c)?;
                self.stmt(b)
            }
            StmtP::IfElse(c, b) => {
                self.expr(c)?;
                self.stmt(&b.0)?;
                self.stmt(&b.1)
            }
            StmtP::For(f) => {
                self.loop_bound(&f.over)?;
                self.target(&f.var)?;
                self.expr(&f.over)?;
                self.stmt(&f.body)
            }
            StmtP::Def(d) => {
                self.bind(&d.name.node.ident)?;
                d.params.iter().try_for_each(|p| self.param(p))?;
                if let Some(t) = &d.return_type {
                    self.type_expr(t)?;
                }
                self.stmt(&d.body)
            }
            StmtP::Load(_) => fail!(EINVAL, "STARLARK_LOAD_FORBIDDEN"),
        }
    }

    fn expr(&mut self, e: &AstExpr) -> EnclaveResult<()> {
        match &e.node {
            ExprP::Call(f, args) => self.call(f, &args.args),
            ExprP::Identifier(id) => self.read(&id.node.ident),
            ExprP::Literal(_) => Ok(()),
            ExprP::Tuple(v) | ExprP::List(v) => v.iter().try_for_each(|x| self.expr(x)),
            ExprP::Dict(v) => v.iter().try_for_each(|(k, x)| {
                self.expr(k)?;
                self.expr(x)
            }),
            ExprP::Dot(x, _)
            | ExprP::Not(x)
            | ExprP::Minus(x)
            | ExprP::Plus(x)
            | ExprP::BitNot(x) => self.expr(x),
            ExprP::Index(b) => self.exprs(&[&b.0, &b.1]),
            ExprP::Index2(b) => self.exprs(&[&b.0, &b.1, &b.2]),
            ExprP::If(b) => self.exprs(&[&b.0, &b.1, &b.2]),
            ExprP::Op(a, _, b) => self.exprs(&[a, b]),
            ExprP::Slice(x, a, b, c) => {
                self.expr(x)?;
                [a, b, c]
                    .into_iter()
                    .flatten()
                    .try_for_each(|y| self.expr(y))
            }
            ExprP::Lambda(l) => {
                l.params.iter().try_for_each(|p| self.param(p))?;
                self.expr(&l.body)
            }
            ExprP::ListComprehension(x, first, rest) => self.comprehension(&[x], first, rest),
            ExprP::DictComprehension(kv, first, rest) => {
                self.comprehension(&[&kv.0, &kv.1], first, rest)
            }
            ExprP::FString(f) => f.node.expressions.iter().try_for_each(|x| self.expr(x)),
        }
    }

    fn exprs(&mut self, v: &[&AstExpr]) -> EnclaveResult<()> {
        v.iter().try_for_each(|x| self.expr(x))
    }

    fn comprehension(
        &mut self,
        body: &[&AstExpr],
        first: &ForClause,
        rest: &[ClauseP<starlark::syntax::ast::AstNoPayload>],
    ) -> EnclaveResult<()> {
        if self.l3 {
            fail!(
                EINVAL,
                "L3_COMPREHENSION_FORBIDDEN",
                "L3 iteration must be a `for` over a literal range"
            );
        }
        self.target(&first.var)?;
        self.expr(&first.over)?;
        for c in rest {
            match c {
                ClauseP::For(f) => {
                    self.target(&f.var)?;
                    self.expr(&f.over)?;
                }
                ClauseP::If(x) => self.expr(x)?,
            }
        }
        self.exprs(body)
    }

    fn call(
        &mut self,
        f: &AstExpr,
        args: &[starlark::syntax::ast::AstArgument],
    ) -> EnclaveResult<()> {
        let is_tool_call = matches!(&f.node, ExprP::Identifier(id) if id.node.ident == "tool_call");
        if is_tool_call {
            self.record_tool_call(args)?;
        } else {
            self.expr(f)?;
        }
        args.iter().try_for_each(|a| self.expr(a.node.expr()))
    }

    fn record_tool_call(
        &mut self,
        args: &[starlark::syntax::ast::AstArgument],
    ) -> EnclaveResult<()> {
        if args
            .iter()
            .any(|a| !matches!(a.node, ArgumentP::Positional(_)))
        {
            fail!(
                EINVAL,
                "PLAN_TOOL_CALL_ARGS",
                "tool_call takes positional arguments only"
            );
        }
        let lit = |i: usize| match args.get(i).map(|a| &a.node.expr().node) {
            Some(ExprP::Literal(AstLiteral::String(s))) => Some(s.node.clone()),
            _ => None,
        };
        let (Some(server), Some(tool_name)) = (lit(0), lit(1)) else {
            fail!(
                EINVAL,
                "PLAN_TOOL_CALL_NON_LITERAL",
                "tool_call server and tool must be string literals"
            );
        };
        self.calls.push(PlanToolCall {
            server,
            tool_name,
            arity: args.len(),
        });
        Ok(())
    }

    /// A name in read position.
    fn read(&mut self, name: &str) -> EnclaveResult<()> {
        if REFLECTION.contains(&name) {
            fail!(EINVAL, "STARLARK_DYNAMIC_ATTR_FORBIDDEN", "{name}");
        }
        if name == "tool_call" {
            fail!(
                EINVAL,
                "PLAN_TOOL_CALL_INDIRECT",
                "tool_call may only be called directly"
            );
        }
        Ok(())
    }

    /// A name in binding position.
    fn bind(&mut self, name: &str) -> EnclaveResult<()> {
        if is_reserved_name(name) {
            fail!(EINVAL, "PLAN_RESERVED_NAME_REBOUND", "{name}");
        }
        Ok(())
    }

    fn target(&mut self, t: &AstAssignTarget) -> EnclaveResult<()> {
        match &t.node {
            AssignTargetP::Tuple(v) => v.iter().try_for_each(|x| self.target(x)),
            AssignTargetP::Index(b) => self.exprs(&[&b.0, &b.1]),
            AssignTargetP::Dot(x, _) => self.expr(x),
            AssignTargetP::Identifier(id) => self.bind(&id.node.ident),
        }
    }

    fn param(&mut self, p: &AstParameter) -> EnclaveResult<()> {
        match &p.node {
            ParameterP::Slash | ParameterP::NoArgs => Ok(()),
            ParameterP::Normal(id, ty, default) => {
                self.bind(&id.node.ident)?;
                if let Some(t) = ty {
                    self.type_expr(t)?;
                }
                default.as_ref().map_or(Ok(()), |d| self.expr(d))
            }
            ParameterP::Args(id, ty) | ParameterP::KwArgs(id, ty) => {
                self.bind(&id.node.ident)?;
                ty.as_ref().map_or(Ok(()), |t| self.type_expr(t))
            }
        }
    }

    fn type_expr(&mut self, t: &AstTypeExpr) -> EnclaveResult<()> {
        self.expr(&t.node.expr)
    }

    /// `L3`: the iterable must be exactly `range(<int literal 0..=16>)`.
    fn loop_bound(&self, over: &AstExpr) -> EnclaveResult<()> {
        if !self.l3 {
            return Ok(());
        }
        let ExprP::Call(f, args) = &over.node else {
            fail!(EINVAL, "L3_UNBOUNDED_LOOP", "loops in L3 must use range(N)");
        };
        if !matches!(&f.node, ExprP::Identifier(id) if id.node.ident == "range") {
            fail!(EINVAL, "L3_UNBOUNDED_LOOP", "loops in L3 must use range(N)");
        }
        let n = match args.args.as_slice() {
            [a] => match &a.node {
                ArgumentP::Positional(e) => match &e.node {
                    ExprP::Literal(AstLiteral::Int(i)) => match &i.node {
                        TokenInt::I32(n) => Some(*n),
                        TokenInt::BigInt(_) => Some(i32::MAX),
                    },
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        };
        match n {
            None => fail!(
                EINVAL,
                "L3_DYNAMIC_LOOP_BOUND",
                "loop bound must be one static integer"
            ),
            Some(n) if !(0..=L3_MAX_RANGE).contains(&n) => {
                fail!(
                    EINVAL,
                    "L3_LOOP_BOUND_EXCEEDED",
                    "max range in L3 is {L3_MAX_RANGE}"
                )
            }
            Some(_) => Ok(()),
        }
    }
}
