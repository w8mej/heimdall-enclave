#!/usr/bin/env python3
"""
Reference Mock Customer Database (v1.0 Python Architectural Simulation)

SIMULATION ONLY — synthetic records, no real personal data.

Remediates F-037: the query connection is locked read-only twice over —
  1. `PRAGMA query_only = ON`, and
  2. a `sqlite3.Connection.set_authorizer` callback that permits only SELECT/READ and an
     allowlist of pure functions, denying INSERT/UPDATE/DELETE/ATTACH/PRAGMA/DDL even if a
     statement somehow bypasses `depot/sql_guard.py`.
Every query is additionally re-validated by `sql_guard.validate_select` (defence in depth).
"""

import sqlite3
import uuid
from typing import Any, Dict, List

try:  # package import (python -m / verify-enclave.sh)
    from depot.sql_guard import DEFAULT_SCHEMA, validate_select
except ImportError:  # direct execution: python3 depot/mock_customer_db.py
    from sql_guard import DEFAULT_SCHEMA, validate_select  # type: ignore

_ALLOWED_FUNCTIONS = {
    "count",
    "min",
    "max",
    "sum",
    "avg",
    "lower",
    "upper",
    "length",
    "like",
}


class ReadOnlyViolation(PermissionError):
    pass


def _read_only_authorizer(action, arg1, arg2, db_name, trigger):
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ):
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION and (arg2 or "").lower() in _ALLOWED_FUNCTIONS:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


class MockCustomerDatabase:
    """Shared-cache in-memory SQLite database pre-populated with synthetic customer records."""

    def __init__(self):
        uri = f"file:depot_mock_{uuid.uuid4().hex}?mode=memory&cache=shared"
        # Writer connection: used once for schema + seed, kept open so the memory DB persists.
        self._seed_conn = sqlite3.connect(uri, uri=True)
        self._init_db(self._seed_conn)
        # Query connection: read-only by PRAGMA + authorizer.
        self.conn = sqlite3.connect(uri, uri=True)
        self.conn.execute("PRAGMA query_only = ON")
        self.conn.set_authorizer(_read_only_authorizer)

    @staticmethod
    def _init_db(conn: sqlite3.Connection) -> None:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE customers (
                id INTEGER PRIMARY KEY,
                customer_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                ssn TEXT NOT NULL,
                credit_card TEXT NOT NULL,
                phone TEXT NOT NULL,
                dob TEXT,
                zip TEXT,
                account_balance REAL NOT NULL,
                notes TEXT,
                medical_notes TEXT,
                tier TEXT,
                created_at TEXT,
                updated_at TEXT,
                deleted_at TEXT,
                is_deleted INTEGER DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE tickets (
                ticket_id TEXT PRIMARY KEY, customer_id TEXT, subject TEXT, status TEXT,
                backdrop_url TEXT, created_at TEXT, updated_at TEXT, is_deleted INTEGER DEFAULT 0
            )
        """)
        seed = [
            (
                1001,
                "CUST_1001",
                "Alice Johnson",
                "alice.johnson@corporate.example",
                "111-22-3333",
                "4111111111111111",
                "+1-415-555-0101",
                "1984-05-12",
                "94107",
                12500.50,
                "VIP enterprise tier. Call back on +1 (415) 555-0101.",
                "Patient was diagnosed with bipolar disorder.",
                "vip",
                "2025-01-02",
                "2026-10-01",
                None,
                0,
            ),
            (
                1002,
                "CUST_1002",
                "Robert Martinez",
                "robert.m@corporate.example",
                "222334444",
                "5500000000000004",
                "+1-415-555-0102",
                "1979-11-30",
                "10001",
                430.00,
                "Inquired about API token limits.",
                "History of cardiac arrhythmia.",
                "std",
                "2025-02-11",
                "2026-09-14",
                None,
                0,
            ),
            (
                1003,
                "CUST_1003",
                "Sarah Connor",
                "s.connor@cyberdyne.example",
                "333-44-5555",
                "378282246310005",
                "+1-415-555-0103",
                "1965-08-29",
                "90210",
                98200.00,
                "High security clearance account.",
                None,
                "vip",
                "2025-03-21",
                "2026-08-30",
                "2026-10-31",
                1,
            ),
        ]
        cur.executemany(
            "INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", seed
        )
        cur.execute(
            "INSERT INTO tickets VALUES ('T-1','CUST_1001','Login issue','open','https://example.invalid/b.png','2026-10-01','2026-10-02',0)"
        )
        conn.commit()

    def execute_query(self, query: str, max_records: int = 10) -> List[Dict[str, Any]]:
        """Re-validate with the AST guard, then execute on the read-only connection."""
        verdict = validate_select(query, max_records, DEFAULT_SCHEMA)
        if not verdict.valid:
            raise ReadOnlyViolation(
                f"query rejected by SQL AST guard: {verdict.reason}"
            )
        cur = self.conn.cursor()
        cur.execute(verdict.normalized_sql)
        columns = [desc[0] for desc in cur.description]
        rows = cur.fetchmany(max_records)
        return [dict(zip(columns, row)) for row in rows]

    def execute_raw_unvalidated(self, query: str):
        """TEST HOOK ONLY: bypasses sql_guard to prove the SQLite authorizer still blocks writes."""
        return self.conn.execute(query).fetchall()


if __name__ == "__main__":
    print("SIMULATION ONLY — synthetic customer records.")
    db = MockCustomerDatabase()
    results = db.execute_query(
        "SELECT customer_id, tier FROM customers WHERE account_balance > 1000", 10
    )
    print(f"Mock DB initialized. Sample records retrieved: {len(results)}")
    for r in results:
        print(f" - {r['customer_id']} ({r['tier']})")
    try:
        db.execute_raw_unvalidated("DELETE FROM customers")
        raise SystemExit("FAIL: write was not blocked")
    except sqlite3.DatabaseError as exc:
        print(f"Read-only authorizer blocked write: {exc}")
