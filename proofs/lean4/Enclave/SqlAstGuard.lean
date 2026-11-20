/-
Copyright (c) 2026 Enterprise Enclave Authors. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Abstract SQL AST predicates and model database-state preservation.
No parser extraction/refinement relation links this model to the Python example;
there is no Rust SQL guard or production SQL wrapper in this repository (F132).
The SELECT semantics below returns the input state by definition and does not
model SQLite, filesystem effects, tool authority, database functions or limits.
-/

namespace Enclave

/-- Pure SQL expressions for filtering -/
inductive SqlExpr where
  | LitNat : Nat → SqlExpr
  | LitString : String → SqlExpr
  | Col : String → SqlExpr
  | Eq : SqlExpr → SqlExpr → SqlExpr
  deriving Repr

/-- SQL statement AST covering DQL, DML, DDL, and administrative pragmas -/
inductive SqlStmt where
  | Select : List String → String → Option SqlExpr → SqlStmt
  | Insert : String → List String → List SqlExpr → SqlStmt
  | Update : String → List (String × SqlExpr) → Option SqlExpr → SqlStmt
  | Delete : String → Option SqlExpr → SqlStmt
  | Attach : String → String → SqlStmt
  | Pragma : String → Option String → SqlStmt
  | MultiStmt : List SqlStmt → SqlStmt
  deriving Repr

/--
Static Read-Only SQL AST Guard implementing ADR-014 and FS-704 §5.2:
1. Permits ONLY single SELECT statements with explicit non-empty, non-wildcard column projections.
2. Deterministically REJECTS all DML (INSERT, UPDATE, DELETE), DDL/schema modifications,
   ATTACH DATABASE filesystem escapes, PRAGMAs, and multi-statement chained queries.
-/
def isReadOnlySql : SqlStmt → Bool
  | SqlStmt.Select cols _ _ =>
    !cols.isEmpty && !cols.contains "*"
  | SqlStmt.Insert _ _ _ => false
  | SqlStmt.Update _ _ _ => false
  | SqlStmt.Delete _ _ => false
  | SqlStmt.Attach _ _ => false
  | SqlStmt.Pragma _ _ => false
  | SqlStmt.MultiStmt _ => false

/-- Abstract SQLite database state: mapping from table name and row ID to column-value records -/
def DbState := String → Nat → List (String × String)

/-- Operational semantic evaluation of SQL statements over database state -/
def evalSql (db : DbState) : SqlStmt → Option (DbState × List (List (String × String)))
  | SqlStmt.Select _ _ _ =>
    -- Pure query: returns current state unaltered alongside projected rows
    some (db, [])
  | SqlStmt.Insert table _ _ =>
    -- State-modifying operation: alters table records
    let modified_db : DbState := fun t r => if t == table then [("status", "inserted")] else db t r
    some (modified_db, [])
  | SqlStmt.Update table _ _ =>
    let modified_db : DbState := fun t r => if t == table then [("status", "updated")] else db t r
    some (modified_db, [])
  | SqlStmt.Delete table _ =>
    let modified_db : DbState := fun t r => if t == table then [] else db t r
    some (modified_db, [])
  | SqlStmt.Attach _ _ => none
  | SqlStmt.Pragma _ _ => none
  | SqlStmt.MultiStmt _ => none

/--
Theorem 14.1 (SQL Guard Rejects Mutations & Attach Escapes):
All state-modifying operations (Insert, Update, Delete), schema escapes (Attach),
administrative overrides (Pragma), and multi-statement injection vectors are
strictly rejected by the SQL AST guard.
-/
theorem sql_guard_rejects_mutations (stmt : SqlStmt)
    (h_mut : (∃ tbl cols vals, stmt = SqlStmt.Insert tbl cols vals) ∨
             (∃ tbl assigns cond, stmt = SqlStmt.Update tbl assigns cond) ∨
             (∃ tbl cond, stmt = SqlStmt.Delete tbl cond) ∨
             (∃ path alias, stmt = SqlStmt.Attach path alias) ∨
             (∃ name val, stmt = SqlStmt.Pragma name val) ∨
             (∃ stmts, stmt = SqlStmt.MultiStmt stmts)) :
    isReadOnlySql stmt = false := by
  rcases h_mut with (⟨tbl, cols, vals, rfl⟩ |
                     ⟨tbl, assigns, cond, rfl⟩ |
                     ⟨tbl, cond, rfl⟩ |
                     ⟨path, alias, rfl⟩ |
                     ⟨name, val, rfl⟩ |
                     ⟨stmts, rfl⟩) <;> rfl

/--
Theorem 14.2 (Database State Immutability):
For any query accepted by the SQL AST guard, execution preserves the database state
bitwise identically: queries are guaranteed to have zero side effects on stored data.
-/
theorem db_state_immutability (stmt : SqlStmt) (db db' : DbState)
    (rows : List (List (String × String)))
    (h_guard : isReadOnlySql stmt = true)
    (h_eval : evalSql db stmt = some (db', rows)) :
    db' = db := by
  cases stmt with
  | Select cols tbl cond =>
    dsimp [evalSql] at h_eval
    cases h_eval
    rfl
  | Insert _ _ _ =>
    dsimp [isReadOnlySql] at h_guard
    contradiction
  | Update _ _ _ =>
    dsimp [isReadOnlySql] at h_guard
    contradiction
  | Delete _ _ =>
    dsimp [isReadOnlySql] at h_guard
    contradiction
  | Attach _ _ =>
    dsimp [isReadOnlySql] at h_guard
    contradiction
  | Pragma _ _ =>
    dsimp [isReadOnlySql] at h_guard
    contradiction
  | MultiStmt _ =>
    dsimp [isReadOnlySql] at h_guard
    contradiction

/--
Theorem 14.3 (Filesystem Containment / Attach Impossibility):
The SQL AST guard strictly forbids ATTACH DATABASE statements, preventing directory
escape or out-of-sandbox SQLite database creation.
-/
theorem filesystem_containment (path alias : String) :
    isReadOnlySql (SqlStmt.Attach path alias) = false := by
  rfl

/--
Theorem 14.4 (Wildcard Projection Rejection):
Wildcard column projections (`SELECT *`) are strictly rejected to enforce explicit,
least-privilege schema projections.
-/
theorem wildcard_projection_rejected (table : String) (cond : Option SqlExpr) :
    isReadOnlySql (SqlStmt.Select ["*"] table cond) = false := by
  dsimp [isReadOnlySql]
  rfl

end Enclave
