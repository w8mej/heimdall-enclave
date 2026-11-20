/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Biba Integrity Noninterference & Dynamic Agent Graph Execution Proofs
Normative Specification: FS-704 §8.1, §8.2.1, & ADVERSARIAL_SPEC_REVIEW_2026-11-04 §10.3
-/

import Enclave.Lattice

namespace Enclave

/-- Capability heap handle reference (OPA/Cedar/Starlark SSA pointer) -/
abbrev Handle := Nat


/-- AST structural arguments: function identifiers, SQL skeletons, schema elements -/
inductive ASTStructuralArg where
  | Ident : String → ASTStructuralArg
  | Op : String → List ASTStructuralArg → ASTStructuralArg
  | SchemaField : String → ASTStructuralArg
  | TypeAnnotation : String → ASTStructuralArg


/-- Literal slot references that hold dynamic values isolated from structural grammar -/
structure LiteralSlot where
  handle : Handle


/-- A verified tool call invocation emitted by the Starlark runtime -/
structure ToolCall where
  tool_id : String
  structural_args : List ASTStructuralArg
  literal_slots : List LiteralSlot


/-- Capability heap holding byte arrays and security classifications -/
structure CapHeap where
  lookup : Handle → List UInt8
  label : Handle → SecurityLabel

/-- Verified Starlark AST containing tool calls and Endorse() escalation gates -/
structure VerifiedStarlarkAST where
  tool_calls : List ToolCall
  endorseGates : List Handle


/-- Observable trace entry consisting of (tool_id, structural arguments) -/
def StructuralTraceEntry := String × List ASTStructuralArg


/-- Execution result containing the observable structural trace and declassified payloads -/
structure ExecutionResult where
  structuralToolTrace : List StructuralTraceEntry
  dataPayloads : List (List UInt8)

/-- Operational evaluator: evaluates a verified AST over a capability heap -/
def evalPlan (plan : VerifiedStarlarkAST) (env : CapHeap) : ExecutionResult :=
  { structuralToolTrace := plan.tool_calls.map (fun tc => (tc.tool_id, tc.structural_args))
  , dataPayloads := plan.tool_calls.flatMap (fun tc => tc.literal_slots.map (fun s => env.lookup s.handle)) }

/-- Legacy static projection identity. This helper does not establish data-dependent structural safety. -/
theorem static_plan_projection_independent
    (plan : VerifiedStarlarkAST)
    (env₁ env₂ : CapHeap)
    (_h_agree_trusted : ∀ h, (env₁.label h).integrity ≤ IntegLevel.T2 → env₁.lookup h = env₂.lookup h)
    (_h_no_endorse : plan.endorseGates = []) :
    (evalPlan plan env₁).structuralToolTrace = (evalPlan plan env₂).structuralToolTrace := by
  rfl

/--
Corollary 1.1 (Static projection index equality):
The stored structural skeleton is independent of the heap by definition.
This identity does not establish SQL/command injection prevention or execution
of the production interpreter. The checked data-dependent model is below.
-/
theorem static_projection_index_equal
    (plan : VerifiedStarlarkAST)
    (env₁ env₂ : CapHeap)
    (h_agree : ∀ h, (env₁.label h).integrity ≤ IntegLevel.T2 → env₁.lookup h = env₂.lookup h)
    (h_no_gates : plan.endorseGates = []) :
    ∀ idx, (evalPlan plan env₁).structuralToolTrace.get? idx =
           (evalPlan plan env₂).structuralToolTrace.get? idx := by
  intro idx
  rw [static_plan_projection_independent plan env₁ env₂ h_agree h_no_gates]


/-! # Dynamic Agent Interaction Graph Calculus & Operational Noninterference -/

/-- Dynamic argument expression evaluated directly against the capability heap -/
inductive DynamicArgExpr where
  | Const : List UInt8 → DynamicArgExpr
  | HeapRef : Handle → DynamicArgExpr
  | Concat : DynamicArgExpr → DynamicArgExpr → DynamicArgExpr


/-- Inductive typing judgement: an expression is safe at integrity level bound -/
inductive DynamicExprSafeAt (env : CapHeap) (bound : IntegLevel) : DynamicArgExpr → Prop where
  | const (b : List UInt8) : DynamicExprSafeAt env bound (DynamicArgExpr.Const b)
  | heapRef (h : Handle) (h_le : (env.label h).integrity ≤ bound) :
      DynamicExprSafeAt env bound (DynamicArgExpr.HeapRef h)
  | concat (e1 e2 : DynamicArgExpr)
      (h1 : DynamicExprSafeAt env bound e1)
      (h2 : DynamicExprSafeAt env bound e2) :
      DynamicExprSafeAt env bound (DynamicArgExpr.Concat e1 e2)

/-- Operational evaluator for dynamic argument expressions inspecting CapHeap -/
def evalDynamicArg (env : CapHeap) : DynamicArgExpr → List UInt8
  | DynamicArgExpr.Const b => b
  | DynamicArgExpr.HeapRef h => env.lookup h
  | DynamicArgExpr.Concat e1 e2 => evalDynamicArg env e1 ++ evalDynamicArg env e2

/-- Low-equivalence of capability heaps up to trusted integrity bound (e.g. T2) -/
def HeapLowEquiv (env₁ env₂ : CapHeap) (bound : IntegLevel) : Prop :=
  ∀ h, (env₁.label h).integrity ≤ bound → env₁.lookup h = env₂.lookup h

/--
Theorem 1.2 (Dynamic Expression Noninterference):
For any dynamic argument expression that references only handles with integrity ≤ bound,
evaluating the expression yields bitwise identical byte sequences across any two
heaps that agree on trusted values.
-/
theorem dynamic_expr_noninterference
    (env₁ env₂ : CapHeap)
    (bound : IntegLevel)
    (h_equiv : HeapLowEquiv env₁ env₂ bound)
    (e : DynamicArgExpr)
    (h_safe : DynamicExprSafeAt env₁ bound e) :
    evalDynamicArg env₁ e = evalDynamicArg env₂ e := by
  induction h_safe with
  | const b => rfl
  | heapRef h h_le =>
    dsimp [evalDynamicArg]
    exact h_equiv h h_le
  | concat e1 e2 _ _ ih1 ih2 =>
    dsimp [evalDynamicArg]
    rw [ih1, ih2]

/-- Dynamic Agent Tool Call with heap-evaluated arguments -/
structure DynamicAgentToolCall where
  tool_id : String
  structural_args : List ASTStructuralArg
  dynamic_args : List DynamicArgExpr


/-- An execution trace event emitted by dynamic tool invocation -/
structure DynamicTraceEvent where
  tool_id : String
  structural_args : List ASTStructuralArg
  evaluated_args : List (List UInt8)


/-- Evaluate a dynamic tool call over a capability heap -/
def evalDynamicToolCall (env : CapHeap) (call : DynamicAgentToolCall) : DynamicTraceEvent := {
  tool_id := call.tool_id,
  structural_args := call.structural_args,
  evaluated_args := call.dynamic_args.map (evalDynamicArg env)
}

/-- Evaluate an entire sequence of dynamic agent tool calls -/
def evalDynamicPlan (env : CapHeap) (calls : List DynamicAgentToolCall) : List DynamicTraceEvent :=
  calls.map (evalDynamicToolCall env)

/--
Theorem 1.3 (Dynamic Agent Graph Noninterference):
Evaluating a sequence of dynamic tool calls over two low-equivalent heaps produces
identical structural tool invocations and identical evaluated argument payloads
for all arguments verified to be safe at the trusted integrity bound.
-/
theorem dynamic_agent_graph_noninterference
    (env₁ env₂ : CapHeap)
    (bound : IntegLevel)
    (h_equiv : HeapLowEquiv env₁ env₂ bound)
    (calls : List DynamicAgentToolCall)
    (h_all_safe : ∀ c ∈ calls, ∀ arg ∈ c.dynamic_args, DynamicExprSafeAt env₁ bound arg) :
    evalDynamicPlan env₁ calls = evalDynamicPlan env₂ calls := by
  unfold evalDynamicPlan
  apply List.map_congr_left
  intro call hcall
  unfold evalDynamicToolCall
  congr 1
  apply List.map_congr_left
  intro arg harg
  exact dynamic_expr_noninterference env₁ env₂ bound h_equiv arg (h_all_safe call hcall arg harg)

/--
Theorem 1.4 (Prompt Injection Isolation Across Dynamic Graphs):
Even if untrusted prompt data (T3) in the heap is arbitrarily mutated by an adversary,
the sequence of emitted tool targets, structural command names, and trusted payload
parameters remains bitwise invariant.
-/
theorem prompt_injection_structural_invariance
    (env₁ env₂ : CapHeap)
    (calls : List DynamicAgentToolCall)
    (h_equiv : HeapLowEquiv env₁ env₂ IntegLevel.T2)
    (h_safe : ∀ c ∈ calls, ∀ arg ∈ c.dynamic_args, DynamicExprSafeAt env₁ IntegLevel.T2 arg) :
    (evalDynamicPlan env₁ calls).map (fun ev => (ev.tool_id, ev.structural_args)) =
    (evalDynamicPlan env₂ calls).map (fun ev => (ev.tool_id, ev.structural_args)) := by
  have h_plan_eq := dynamic_agent_graph_noninterference env₁ env₂ IntegLevel.T2 h_equiv calls h_safe
  rw [h_plan_eq]

-- A data-dependent structural language. There is no endorsement operation in
-- this subset. A checker, rather than a supplied safety proof, admits each read.
def checkStructuralExpr (env : CapHeap) : DynamicArgExpr → Bool
  | .Const _ => true
  | .HeapRef h => decide ((env.label h).integrity ≤ IntegLevel.T2)
  | .Concat a b => checkStructuralExpr env a && checkStructuralExpr env b

theorem checked_structural_expr_safe (env : CapHeap) (e : DynamicArgExpr)
    (h : checkStructuralExpr env e = true) : DynamicExprSafeAt env IntegLevel.T2 e := by
  induction e with
  | Const bytes => exact .const bytes
  | HeapRef handle =>
    exact .heapRef handle (by simpa [checkStructuralExpr] using h)
  | Concat a b iha ihb =>
    simp only [checkStructuralExpr, Bool.and_eq_true] at h
    exact .concat a b (iha h.1) (ihb h.2)

structure StructuralDataCall where
  target : DynamicArgExpr
  grammarArgs : List DynamicArgExpr

def checkStructuralCalls (env : CapHeap) (calls : List StructuralDataCall) : Bool :=
  calls.all (fun c => checkStructuralExpr env c.target && c.grammarArgs.all (checkStructuralExpr env))

def evaluatedStructuralTrace (env : CapHeap) (calls : List StructuralDataCall) :=
  calls.map (fun c => (evalDynamicArg env c.target, c.grammarArgs.map (evalDynamicArg env)))

/-- Checked, heap-dependent targets and grammar arguments are invariant to T3
payload changes. This proves the model checker enforces the needed read discipline;
it does not establish that the production interpreter executes this language. -/
theorem starlark_biba_noninterference (env₁ env₂ : CapHeap)
    (calls : List StructuralDataCall)
    (h_equiv : HeapLowEquiv env₁ env₂ IntegLevel.T2)
    (h_checked : checkStructuralCalls env₁ calls = true) :
    evaluatedStructuralTrace env₁ calls = evaluatedStructuralTrace env₂ calls := by
  simp only [checkStructuralCalls, List.all_eq_true, Bool.and_eq_true] at h_checked
  unfold evaluatedStructuralTrace
  apply List.map_congr_left
  intro call hc
  have hs := h_checked call hc
  have ht := dynamic_expr_noninterference env₁ env₂ IntegLevel.T2 h_equiv call.target
    (checked_structural_expr_safe env₁ call.target hs.1)
  have ha : call.grammarArgs.map (evalDynamicArg env₁) = call.grammarArgs.map (evalDynamicArg env₂) := by
    apply List.map_congr_left
    intro arg harg
    exact dynamic_expr_noninterference env₁ env₂ IntegLevel.T2 h_equiv arg
      (checked_structural_expr_safe env₁ arg (hs.2 arg harg))
  rw [ht, ha]

end Enclave
