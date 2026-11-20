#!/usr/bin/env python3
"""
SQL AST Guard for the v1.0/v2.0 Python Architectural Simulation (remediates F-037).

A hand-written tokenizer + recursive-descent parser for the small read-only SQL subset that
the mock MCP tools are allowed to issue. It replaces every substring check (`"select *" in q`,
`contains(sql, "update")`) that previously masqueraded as "SQL AST inspection".

Accepted grammar (case-insensitive keywords; identifiers are exact tokens, so `updated_at`
is an identifier and never the keyword UPDATE):

    statement   := SELECT [DISTINCT] proj_list FROM table [[AS] alias]
                   [WHERE expr] [ORDER BY order_list] [LIMIT int] [';'] EOF
    proj_list   := proj (',' proj)*
    proj        := column | func '(' column ')'          -- func in COUNT/MIN/MAX/SUM/AVG/LOWER/UPPER/LENGTH
    column      := ident | ident '.' ident                -- '*' and 't.*' are rejected
    expr        := or_expr ; or_expr := and_expr (OR and_expr)* ; and_expr := not_expr (AND not_expr)*
    not_expr    := [NOT] predicate
    predicate   := '(' expr ')' | operand [cmp operand | [NOT] IN '(' literal_list ')'
                   | IS [NOT] NULL | [NOT] LIKE string | [NOT] BETWEEN operand AND operand]
    operand     := column | literal ; literal := string | number | NULL | TRUE | FALSE

Rejected outright: comments (`--`, `/* */`), multiple statements, '*', sub-queries, UNION /
INTERSECT / EXCEPT, ATTACH / DETACH / PRAGMA, any DML/DDL keyword, JOINs, unknown tables or
columns, and LIMIT > max_limit. When LIMIT is absent it is injected.

This is a SIMULATION control for the mock schema. There is no production Rust
SQL parser or UID 704 WASI SQL wrapper in this repository. The Lean SqlAstGuard
module is an independent abstract model, not verification of this parser or a
Rust enforcement path. Adding a production SQL tool requires an explicitly
specified schema, policy, database authority and enforced runtime wrapper.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

MAX_LIMIT = 50

# Mock schema allowlist (table -> columns). Unknown tables/columns fail closed.
DEFAULT_SCHEMA: Dict[str, Set[str]] = {
    "customers": {
        "id",
        "customer_id",
        "name",
        "email",
        "ssn",
        "credit_card",
        "phone",
        "dob",
        "zip",
        "medical_notes",
        "account_balance",
        "notes",
        "tier",
        "created_at",
        "updated_at",
        "deleted_at",
        "is_deleted",
    },
    "tickets": {
        "ticket_id",
        "customer_id",
        "subject",
        "status",
        "backdrop_url",
        "created_at",
        "updated_at",
        "is_deleted",
    },
}

ALLOWED_FUNCS = {"COUNT", "MIN", "MAX", "SUM", "AVG", "LOWER", "UPPER", "LENGTH"}

# Keywords that are never permitted anywhere in an accepted statement.
FORBIDDEN_KEYWORDS = {
    "UNION",
    "INTERSECT",
    "EXCEPT",
    "ATTACH",
    "DETACH",
    "PRAGMA",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "ALTER",
    "CREATE",
    "REPLACE",
    "GRANT",
    "REVOKE",
    "TRUNCATE",
    "VACUUM",
    "REINDEX",
    "INTO",
    "WITH",
    "JOIN",
    "VALUES",
    "EXEC",
    "EXECUTE",
    "CALL",
    "MERGE",
    "UPSERT",
    "RECURSIVE",
    "LOAD_EXTENSION",
    "OUTFILE",
    "DUMPFILE",
}
KEYWORDS = {
    "SELECT",
    "DISTINCT",
    "FROM",
    "WHERE",
    "ORDER",
    "BY",
    "ASC",
    "DESC",
    "LIMIT",
    "AS",
    "AND",
    "OR",
    "NOT",
    "IN",
    "IS",
    "NULL",
    "LIKE",
    "BETWEEN",
    "TRUE",
    "FALSE",
} | FORBIDDEN_KEYWORDS


class SQLGuardError(ValueError):
    """Raised when a statement is outside the accepted read-only subset."""


@dataclass
class Token:
    kind: str  # KW, IDENT, NUM, STR, OP, PUNCT, EOF
    value: str
    pos: int


_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<comment>--|/\*)
  | (?P<str>'(?:[^']|'')*')
  | (?P<qident>"(?:[^"]|"")+")
  | (?P<num>\d+(?:\.\d+)?)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op><=|>=|<>|!=|=|<|>)
  | (?P<punct>[(),.;*])
    """,
    re.VERBOSE,
)


def tokenize(sql: str) -> List[Token]:
    if not isinstance(sql, str) or not sql.strip():
        raise SQLGuardError("empty query")
    if len(sql) > 4096:
        raise SQLGuardError("query exceeds 4096 characters")
    tokens: List[Token] = []
    pos = 0
    while pos < len(sql):
        m = _TOKEN_RE.match(sql, pos)
        if not m:
            raise SQLGuardError(f"illegal character {sql[pos]!r} at offset {pos}")
        kind = m.lastgroup
        text = m.group(kind)
        if kind == "comment":
            raise SQLGuardError("SQL comments are forbidden")
        if kind == "ws":
            pass
        elif kind == "ident":
            up = text.upper()
            tokens.append(
                Token(
                    "KW" if up in KEYWORDS else "IDENT",
                    up if up in KEYWORDS else text,
                    pos,
                )
            )
        elif kind == "qident":
            tokens.append(Token("IDENT", text[1:-1].replace('""', '"'), pos))
        elif kind == "str":
            tokens.append(Token("STR", text[1:-1].replace("''", "'"), pos))
        elif kind == "num":
            tokens.append(Token("NUM", text, pos))
        elif kind == "op":
            tokens.append(Token("OP", text, pos))
        else:
            tokens.append(Token("PUNCT", text, pos))
        pos = m.end()
    tokens.append(Token("EOF", "", len(sql)))
    for t in tokens:
        if t.kind == "KW" and t.value in FORBIDDEN_KEYWORDS:
            raise SQLGuardError(f"forbidden keyword {t.value}")
        if t.kind == "PUNCT" and t.value == "*":
            raise SQLGuardError("wildcard '*' projection is forbidden")
    return tokens


@dataclass
class SelectAST:
    distinct: bool
    projections: List[
        Tuple[Optional[str], str, Optional[str]]
    ]  # (qualifier, column, func)
    table: str
    alias: Optional[str]
    has_where: bool
    order_by: List[Tuple[str, str]]
    limit: Optional[int]


@dataclass
class Verdict:
    valid: bool
    reason: str
    statement_kind: str = "unknown"
    table: Optional[str] = None
    columns: List[str] = field(default_factory=list)
    limit: Optional[int] = None
    normalized_sql: Optional[str] = None
    sql_sha256: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "statement_kind": self.statement_kind,
            "table": self.table,
            "columns": self.columns,
            "limit": self.limit,
            "normalized_sql": self.normalized_sql,
            "sql_sha256": self.sql_sha256,
        }


class _Parser:
    def __init__(self, tokens: List[Token], schema: Dict[str, Set[str]]):
        self.t = tokens
        self.i = 0
        self.schema = schema
        self.table: Optional[str] = None
        self.alias: Optional[str] = None
        self.pending_cols: List[Tuple[Optional[str], str]] = []

    def peek(self, k: int = 0) -> Token:
        return self.t[min(self.i + k, len(self.t) - 1)]

    def next(self) -> Token:
        tok = self.t[self.i]
        self.i += 1
        return tok

    def accept(self, kind: str, value: Optional[str] = None) -> Optional[Token]:
        tok = self.peek()
        if tok.kind == kind and (value is None or tok.value == value):
            return self.next()
        return None

    def expect(self, kind: str, value: Optional[str] = None) -> Token:
        tok = self.accept(kind, value)
        if tok is None:
            got = self.peek()
            raise SQLGuardError(
                f"expected {value or kind} at offset {got.pos}, got {got.value or got.kind!r}"
            )
        return tok

    # --- grammar -------------------------------------------------------------------------
    def statement(self) -> SelectAST:
        self.expect("KW", "SELECT")
        distinct = bool(self.accept("KW", "DISTINCT"))
        projections = [self.projection()]
        while self.accept("PUNCT", ","):
            projections.append(self.projection())
        self.expect("KW", "FROM")
        if self.peek().kind == "PUNCT" and self.peek().value == "(":
            raise SQLGuardError("sub-queries are forbidden")
        table = self.expect("IDENT").value
        if table not in self.schema:
            raise SQLGuardError(f"table {table!r} is not on the allowlist")
        self.table = table
        if self.accept("KW", "AS"):
            self.alias = self.expect("IDENT").value
        elif self.peek().kind == "IDENT":
            self.alias = self.next().value
        if self.peek().kind == "PUNCT" and self.peek().value == ",":
            raise SQLGuardError("multi-table FROM lists are forbidden")
        has_where = False
        if self.accept("KW", "WHERE"):
            has_where = True
            self.expr()
        order_by: List[Tuple[str, str]] = []
        if self.accept("KW", "ORDER"):
            self.expect("KW", "BY")
            order_by.append(self.order_item())
            while self.accept("PUNCT", ","):
                order_by.append(self.order_item())
        limit = None
        if self.accept("KW", "LIMIT"):
            limit = int(self.expect("NUM").value.split(".")[0])
        self.accept("PUNCT", ";")
        if self.peek().kind != "EOF":
            raise SQLGuardError(
                "trailing tokens after statement (multi-statement input is forbidden)"
            )
        for qual, col in self.pending_cols:
            self.check_column(qual, col)
        return SelectAST(
            distinct, projections, table, self.alias, has_where, order_by, limit
        )

    def projection(self) -> Tuple[Optional[str], str, Optional[str]]:
        tok = self.peek()
        if (
            tok.kind == "IDENT"
            and self.peek(1).kind == "PUNCT"
            and self.peek(1).value == "("
        ):
            func = self.next().value.upper()
            if func not in ALLOWED_FUNCS:
                raise SQLGuardError(f"function {func} is not allowed")
            self.expect("PUNCT", "(")
            qual, col = self.column()
            self.expect("PUNCT", ")")
            return qual, col, func
        qual, col = self.column()
        return qual, col, None

    def column(self) -> Tuple[Optional[str], str]:
        first = self.expect("IDENT").value
        if self.accept("PUNCT", "."):
            second = self.expect("IDENT").value
            self.pending_cols.append((first, second))
            return first, second
        self.pending_cols.append((None, first))
        return None, first

    def check_column(self, qual: Optional[str], col: str) -> None:
        assert self.table is not None
        if qual is not None and qual not in (self.table, self.alias):
            raise SQLGuardError(f"unknown table qualifier {qual!r}")
        if col not in self.schema[self.table]:
            raise SQLGuardError(f"column {col!r} is not on the {self.table} allowlist")

    def order_item(self) -> Tuple[str, str]:
        _, col = self.column()
        direction = "ASC"
        if self.accept("KW", "DESC"):
            direction = "DESC"
        else:
            self.accept("KW", "ASC")
        return col, direction

    def expr(self) -> None:
        self.and_expr()
        while self.accept("KW", "OR"):
            self.and_expr()

    def and_expr(self) -> None:
        self.not_expr()
        while self.accept("KW", "AND"):
            self.not_expr()

    def not_expr(self) -> None:
        self.accept("KW", "NOT")
        self.predicate()

    def predicate(self) -> None:
        if self.accept("PUNCT", "("):
            if self.peek().kind == "KW" and self.peek().value == "SELECT":
                raise SQLGuardError("sub-queries are forbidden")
            self.expr()
            self.expect("PUNCT", ")")
            return
        self.operand()
        if self.accept("OP"):
            self.operand()
            return
        negated = bool(self.accept("KW", "NOT"))
        if self.accept("KW", "IN"):
            self.expect("PUNCT", "(")
            if self.peek().kind == "KW" and self.peek().value == "SELECT":
                raise SQLGuardError("sub-queries are forbidden")
            self.literal()
            while self.accept("PUNCT", ","):
                self.literal()
            self.expect("PUNCT", ")")
            return
        if self.accept("KW", "LIKE"):
            self.expect("STR")
            return
        if self.accept("KW", "BETWEEN"):
            self.operand()
            self.expect("KW", "AND")
            self.operand()
            return
        if not negated and self.accept("KW", "IS"):
            self.accept("KW", "NOT")
            self.expect("KW", "NULL")
            return
        raise SQLGuardError(f"incomplete predicate at offset {self.peek().pos}")

    def operand(self) -> None:
        tok = self.peek()
        if tok.kind in ("STR", "NUM") or (
            tok.kind == "KW" and tok.value in ("NULL", "TRUE", "FALSE")
        ):
            self.next()
            return
        if tok.kind == "IDENT":
            self.column()
            return
        raise SQLGuardError(
            f"unexpected token {tok.value or tok.kind!r} at offset {tok.pos}"
        )

    def literal(self) -> None:
        tok = self.peek()
        if tok.kind in ("STR", "NUM") or (tok.kind == "KW" and tok.value == "NULL"):
            self.next()
            return
        raise SQLGuardError(f"IN list may contain literals only (offset {tok.pos})")


def validate_select(
    sql: str,
    max_records: int = MAX_LIMIT,
    schema: Optional[Dict[str, Set[str]]] = None,
    max_limit: int = MAX_LIMIT,
) -> Verdict:
    """Validate `sql`; return a Verdict. Never raises for bad input."""
    digest = (
        hashlib.sha256(sql.encode("utf-8")).hexdigest()
        if isinstance(sql, str)
        else None
    )
    try:
        if (
            not isinstance(max_records, int)
            or isinstance(max_records, bool)
            or not 1 <= max_records <= max_limit
        ):
            raise SQLGuardError(f"max_records must be an integer in 1..{max_limit}")
        ast = _Parser(tokenize(sql), schema or DEFAULT_SCHEMA).statement()
        if ast.limit is not None and ast.limit > max_limit:
            raise SQLGuardError(f"LIMIT {ast.limit} exceeds ceiling {max_limit}")
        effective_limit = min(ast.limit or max_records, max_records)
        body = sql.strip().rstrip(";").strip()
        if ast.limit is not None:
            body = re.sub(r"(?i)\s+LIMIT\s+\d+\s*$", "", body)
        normalized = f"{body} LIMIT {effective_limit}"
        return Verdict(
            True,
            "SELECT validated by recursive-descent AST guard",
            "select",
            ast.table,
            [c for _, c, _ in ast.projections],
            effective_limit,
            normalized,
            digest,
        )
    except SQLGuardError as exc:
        return Verdict(False, str(exc), sql_sha256=digest)


if __name__ == "__main__":
    for q in [
        "SELECT id, updated_at FROM customers",
        "SELECT  * FROM customers",
        "SELECT customer_id, updated_at, deleted_at FROM customers LIMIT 10",
    ]:
        print(q, "->", validate_select(q, 10).as_dict())
