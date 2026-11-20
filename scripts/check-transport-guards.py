#!/usr/bin/env python3
"""Fail-closed shallow translation of selected current Rust guards to Lean.

Trusted Python frontend, NOT a verified Rust parser. Only the fixed signatures,
first executable guards, selected primitive expressions and exact complete helper
shapes below are supported. Unknown syntax/duplicates/pre-guard statements fail.
Namespace crypto tails are intentionally outside this prefix proof. Input lengths
are native usize/u64; c_int is signed 32-bit, supported usize is 64-bit.
"""

import argparse
import ast
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    "crates/enclave-crypto/src/namespace.rs",
    "crates/enclave-swarm-syncd/src/transport/ohttp_fetch.rs",
    "crates/enclave-core/src/power.rs",
    "crates/enclave-swarm-syncd/src/streaming.rs",
    "crates/enclave-swarm-syncd/src/config.rs",
)
OUTPUT = "proofs/lean4/Enclave/TransportGuardSource.lean"
TOKEN = re.compile(
    r'//[^\n]*|/\*.*?\*/|b?"(?:\\.|[^"\\])*"|b\'(?:\\.|[^\'\\])*\'|'
    r"\d[\d_]*|[A-Za-z_][A-Za-z_0-9]*|::|->|=>|!=|==|<=|>=|&&|\|\||\.\.=|\S",
    re.S,
)


def tokens(text):
    result = []
    for match in TOKEN.finditer(text):
        token = match.group()
        if token.startswith("/*") and "/*" in token[2:]:
            raise ValueError("nested block comments unsupported")
        if token.startswith(("//", "/*")):
            continue
        result.append(token)
    if any(
        t in ("r", "br", "cr")
        and i + 1 < len(result)
        and (result[i + 1] == "#" or result[i + 1].startswith('"'))
        for i, t in enumerate(result)
    ):
        raise ValueError("raw strings unsupported by the shallow source lexer")
    return result


def require(actual, expected, context):
    if actual != tokens(expected):
        raise ValueError(f"unsupported source shape: {context}")


def strip_trailing_param_comma(ts):
    """Normalize optional Rust trailing comma before ')' in fn parameter lists."""
    return [
        t
        for i, t in enumerate(ts)
        if not (t == "," and i + 1 < len(ts) and ts[i + 1] == ")")
    ]


def function(source, name, signature):
    ts = tokens(source)
    starts = [i for i in range(len(ts) - 1) if ts[i : i + 2] == ["fn", name]]
    if len(starts) != 1:
        raise ValueError(f"expected unique function {name}, got {len(starts)}")
    start = starts[0]
    brace = ts.index("{", start)
    require(strip_trailing_param_comma(ts[start:brace]), signature, name + " signature")
    depth = 1
    end = brace + 1
    while end < len(ts) and depth:
        depth += (ts[end] == "{") - (ts[end] == "}")
        end += 1
    if depth:
        raise ValueError(f"unclosed function {name}")
    return ts[brace + 1 : end - 1]


def prefix(body, failure, tail=None):
    if not body or body[0] != "if":
        raise ValueError("guard must be first executable statement")
    brace = body.index("{")
    end = body.index("}", brace)
    require(body[brace + 1 : end], failure, "guard failure")
    if tail is not None:
        require(body[end + 1 :], tail, "helper return/tail")
    return body[1:brace]


# Expressions are typed; primitive spellings are recognized as complete token
# sequences, never substring replacement. Operators are parsed with precedence.
class Expression:
    PREC = {
        "||": 1,
        "&&": 2,
        "==": 3,
        "!=": 3,
        "<": 3,
        ">": 3,
        "<=": 3,
        ">=": 3,
        "+": 4,
        "-": 4,
        "%": 5,
        "*": 5,
    }

    def __init__(self, ts, atoms, constant_arithmetic=False, guarded_remainder=False):
        self.ts, self.pos = ts, 0
        self.constant_arithmetic = constant_arithmetic
        self.guarded_remainder = guarded_remainder
        self.atoms = sorted(
            [(tokens(k), v) for k, v in atoms.items()], key=lambda pair: -len(pair[0])
        )

    def parse(self, minimum=0):
        if self.pos == len(self.ts):
            raise ValueError("incomplete guard expression")
        token = self.ts[self.pos]
        if token == "!":
            self.pos += 1
            value, kind = self.parse(6)
            if kind != "bool":
                raise ValueError("nonboolean negation")
            left = (f"(!{value})", "bool")
        elif token == "(":
            self.pos += 1
            left = self.parse()
            if self.pos == len(self.ts) or self.ts[self.pos] != ")":
                raise ValueError("unclosed expression")
            self.pos += 1
        elif token.isdigit() or re.fullmatch(r"\d[\d_]*", token):
            left = (str(int(token.replace("_", ""))), "num")
            self.pos += 1
        else:
            for spelling, value in self.atoms:
                if self.ts[self.pos : self.pos + len(spelling)] == spelling:
                    left = value
                    self.pos += len(spelling)
                    break
            else:
                raise ValueError(
                    "unknown expression atom: " + " ".join(self.ts[self.pos :])
                )
        while self.pos < len(self.ts) and self.ts[self.pos] in self.PREC:
            op = self.ts[self.pos]
            precedence = self.PREC[op]
            if precedence < minimum:
                break
            self.pos += 1
            right, right_kind = self.parse(precedence + 1)
            value, kind = left
            if op in ("||", "&&"):
                if kind != "bool" or right_kind != "bool":
                    raise ValueError("nonboolean connective")
                left = (f"({value} {op} {right})", "bool")
            else:
                if kind not in ("num", right_kind) and right_kind != "num":
                    raise ValueError("mixed numeric kinds")
                if kind == "bool" or right_kind == "bool":
                    raise ValueError("unsupported boolean comparison")
                if op in ("==", "!=", "<", ">", "<=", ">="):
                    symbol = {"==": "=", "!=": "≠", "<=": "≤", ">=": "≥"}.get(op, op)
                    left = (f"decide ({value} {symbol} {right})", "bool")
                else:
                    if op == "%" and not self.guarded_remainder:
                        raise ValueError("unguarded partial remainder unsupported")
                    if op in ("+", "-", "*") and not self.constant_arithmetic:
                        raise ValueError("dynamic machine arithmetic unsupported")
                    left = (
                        f"({value} {op} {right})",
                        right_kind if kind == "num" else kind,
                    )
        return left

    def complete(self, kind):
        value, actual = self.parse()
        if self.pos != len(self.ts) or actual not in (kind, "num"):
            raise ValueError("unsupported expression tail/type")
        return value


def expression(ts, atoms, kind="bool", guarded_remainder=False):
    return Expression(ts, atoms, kind == "nat", guarded_remainder).complete(kind)


def constant(source, name, kind, atoms, values):
    ts = tokens(source)
    found = [i for i in range(len(ts) - 4) if ts[i : i + 3] == ["const", name, ":"]]
    if len(found) != 1:
        raise ValueError("missing/duplicate constant " + name)
    i = found[0]
    require(ts[i : i + 5], f"const {name}: {kind} =", name)
    expr = ts[i + 5 : ts.index(";", i)]

    def evaluate(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            result = node.value
        elif isinstance(node, ast.Name) and node.id in values:
            result = values[node.id]
        elif isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Sub, ast.Mult)
        ):
            left, right = evaluate(node.left), evaluate(node.right)
            result = (
                left + right
                if isinstance(node.op, ast.Add)
                else left - right if isinstance(node.op, ast.Sub) else left * right
            )
        else:
            raise ValueError("unsupported constant expression")
        if not 0 <= result <= 18446744073709551615:
            raise ValueError("constant machine arithmetic overflow/underflow")
        return result

    values[name] = evaluate(ast.parse(" ".join(expr), mode="eval").body)
    return expression(expr, atoms, "nat")


def derive(root=ROOT):
    namespace, query, power, streaming, config = [
        (root / p).read_text() for p in SOURCES
    ]
    lines = [
        "import Enclave.RustGuardSemantics",
        "",
        "/-! Generated by scripts/check-transport-guards.py --write.",
        "Only the selected guard fragment is translated; see its trust boundary. -/",
        "namespace Enclave.TransportGuardSource",
        "open Enclave.RustGuardSemantics",
        "",
    ]
    constants = {}
    constant_values = {}
    for rust, lean in (
        ("LEAF_SIZE", "leafSize"),
        ("CHUNK_OVERHEAD", "chunkOverhead"),
        ("KEY_RECORD_SIZE", "keyRecordSize"),
        ("PLAINTEXT_SIZE", "plaintextSize"),
    ):
        value = constant(namespace, rust, "usize", constants, constant_values)
        lines.append(f"def {lean} : Nat := {value}")
        constants[rust] = (lean, "nat")
    lines += [
        f'def diskReserve : Nat := {constant(streaming, "DISK_RESERVE", "u64", {}, {})}',
        "",
    ]
    atoms = dict(constants)
    for rust, lean in (
        ("plain", "plain"),
        ("bytes", "cipher"),
        ("wrapped_key", "record"),
        ("sep", "sep"),
        ("prf", "prf"),
    ):
        atoms[rust + ".len()"] = (lean, "nat")
        atoms[rust + ".is_empty()"] = (f"decide ({lean} = 0)", "bool")
    atoms["final_chunk"] = ("final_chunk", "bool")
    specs = [
        (
            "encrypt_chunk",
            "fn encrypt_chunk(dek:&SecretKey32,root:&[u8;32],index:u64,final_chunk:bool,plain:&[u8])->EnclaveResult<(Vec<u8>,Vec<u8>)>",
            'fail!(EINVAL,"NAMESPACE_CHUNK_LENGTH");',
            "encryptReject",
            "(plain : Nat) (final_chunk : Bool)",
            None,
        ),
        (
            "decrypt_chunk",
            "fn decrypt_chunk(dek:&SecretKey32,root:&[u8;32],index:u64,final_chunk:bool,bytes:&[u8],wrapped_key:&[u8])->EnclaveResult<Zeroizing<Vec<u8>>>",
            'fail!(EACCES,"NAMESPACE_CHUNK_LENGTH");',
            "decryptReject",
            "(cipher record : Nat) (final_chunk : Bool)",
            None,
        ),
        (
            "custody_kek",
            "fn custody_kek(sep:&[u8],prf:&[u8],namespace:&str,wrapping_epoch:u64)->EnclaveResult<SecretKey32>",
            'fail!(EACCES,"NAMESPACE_CUSTODY_SHARES");',
            "custodyReject",
            "(sep prf : Nat)",
            None,
        ),
    ]
    for name, signature, fail, lean, params, tail in specs:
        guard = prefix(function(namespace, name, signature), fail, tail)
        lines.append(f"def {lean} {params} : Bool :=\n  {expression(guard, atoms)}")
    query_atoms = {
        "got": ("got", "int"),
        "got as usize": ("(usize64 got)", "nat"),
        "capacity": ("capacity", "nat"),
        "item": ("item", "nat"),
    }
    guard = prefix(
        function(
            query,
            "complete_query_bytes",
            "fn complete_query_bytes(got:libc::c_int,capacity:usize,item:usize)->EnclaveResult<usize>",
        ),
        'fail!(EIO,"KERNEL_FD_QUERY_FAILED","incomplete descriptor enumeration: {got}/{capacity}");',
        "Ok(got as usize)",
    )
    # The fragment has a partial Rust operation. Preserve its evaluation order:
    # negative casts and remainder-by-zero must never become evaluated paths.
    require(
        guard,
        "got <= 0 || got as usize >= capacity || item == 0 || got as usize % item != 0",
        "enumeration short-circuit dominance",
    )
    lines.append(
        f"def enumerationReject (got : Int) (capacity item : Nat) : Bool :=\n  {expression(guard, query_atoms, guarded_remainder=True)}"
    )
    guard = prefix(
        function(
            query,
            "require_query_length",
            "fn require_query_length(result:libc::c_int,got:usize,expected:usize)->EnclaveResult<()>",
        ),
        'fail!(EIO,"KERNEL_FD_QUERY_FAILED","failed or short socket query: {result}/{got}/{expected}");',
        "Ok(())",
    )
    lines.append(
        "def queryReject (result : Int) (got expected : Nat) : Bool :=\n  "
        + expression(
            guard,
            {
                "result": ("result", "int"),
                "got": ("got", "nat"),
                "expected": ("expected", "nat"),
            },
        )
    )
    # Byte predicates are fixed primitive forms. Altering their token spelling is
    # unsupported, rather than silently translating a different Rust predicate.
    validate_atoms = {
        "self.namespace.is_empty()": ("decide (ns.length = 0)", "bool"),
        "self.namespace.len()": ("ns.length", "nat"),
        'self.namespace.bytes().all(|b|b.is_ascii_alphanumeric() || b"._-".contains(&b))': (
            "ns.all namespaceByte",
            "bool",
        ),
        "self.epoch": ("epoch", "nat"),
        "self.wrapping_epoch": ("wrapping_epoch", "nat"),
        "self.envelope_hex.len()": ("envelope.length", "nat"),
        "self.envelope_hex.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))": (
            "envelope.all lowercaseHexByte",
            "bool",
        ),
    }
    lines += [
        "def namespaceByte (b : UInt8) : Bool :=\n  asciiAlphanumeric b || decide (b.toNat = 46 ∨ b.toNat = 95 ∨ b.toNat = 45)",
        "def lowercaseHexByte (b : UInt8) : Bool :=\n  asciiDigit b || decide (97 ≤ b.toNat ∧ b.toNat ≤ 102)",
    ]
    guard = prefix(
        function(namespace, "validate", "fn validate(&self)->EnclaveResult<()>"),
        'fail!(EINVAL,"NAMESPACE_KEY_SHAPE");',
        "Ok(())",
    )
    lines.append(
        "def envelopeReject (ns envelope : List UInt8) (epoch wrapping_epoch : Nat) : Bool :=\n  "
        + expression(guard, validate_atoms)
    )
    body = function(
        power,
        "start_for_profile",
        "fn start_for_profile<T>(profile:crate::profile::Profile,start:impl FnOnce()->EnclaveResult<T>)->EnclaveResult<Option<T>>",
    )
    # Preserve the selected arm, result/error payload and exactly one call.
    matching = []
    for profile in ("L1", "L2", "L3"):
        shape = f"match start() {{ Ok(monitor)=>Ok(Some(monitor)), Err(_) if profile==crate::profile::Profile::{profile}=>Ok(None), Err(error)=>Err(error), }}"
        if body == tokens(shape):
            matching.append(profile.lower())
    if len(matching) != 1:
        raise ValueError("unsupported monitor match/callback shape")
    lines += [
        "def startForProfile {ε α : Type} (profile : Profile) (observation : Except ε α) : Except ε (Option α) :=",
        "  match observation with",
        "  | .ok monitor => .ok (some monitor)",
        f"  | .error error => if profile = .{matching[0]} then .ok none else .error error",
    ]
    body = function(
        streaming,
        "required_disk",
        "fn required_disk(outstanding:u64,extra:u64)->EnclaveResult<u64>",
    )
    require(
        body,
        'DISK_RESERVE.checked_add(outstanding).and_then(|n|n.checked_add(extra)).ok_or_else(||err!(E2BIG,"ADMISSION_DISK_RESERVE"))',
        "checked disk arithmetic",
    )
    lines += [
        "def requiredDisk (outstanding extra : Nat) : Except Failure Nat :=",
        "  match (checked64 diskReserve outstanding).bind (fun n => checked64 n extra) with",
        "  | some n => .ok n",
        '  | none => .error ⟨"E2BIG", "ADMISSION_DISK_RESERVE"⟩',
    ]
    body = function(
        config, "write", "fn write(&mut self,bytes:&[u8])->std::io::Result<usize>"
    )
    require(
        body,
        'if bytes.len() as u64 > self.expected.saturating_sub(self.bytes.len() as u64) { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"signed target length exceeded")); } self.bytes.extend_from_slice(bytes); Ok(bytes.len())',
        "bounded append",
    )
    lines += [
        "def boundedWrite {α : Type} (current incoming : List α) (expected : Nat) : Except Failure (List α × Nat) :=",
        "  if incoming.length > expected - current.length then",
        '    .error ⟨"InvalidData", "signed target length exceeded"⟩',
        "  else .ok (current ++ incoming, incoming.length)",
    ]
    for name, params, guard, success, errno, reason, typ in (
        (
            "encryptPrefix",
            "(plain : Nat) (final_chunk : Bool)",
            "encryptReject plain final_chunk",
            "()",
            "EINVAL",
            "NAMESPACE_CHUNK_LENGTH",
            "Unit",
        ),
        (
            "decryptPrefix",
            "(cipher record : Nat) (final_chunk : Bool)",
            "decryptReject cipher record final_chunk",
            "()",
            "EACCES",
            "NAMESPACE_CHUNK_LENGTH",
            "Unit",
        ),
        (
            "custodyPrefix",
            "(sep prf : Nat)",
            "custodyReject sep prf",
            "()",
            "EACCES",
            "NAMESPACE_CUSTODY_SHARES",
            "Unit",
        ),
        (
            "completeQuery",
            "(got : Int) (capacity item : Nat)",
            "enumerationReject got capacity item",
            "usize64 got",
            "EIO",
            "KERNEL_FD_QUERY_FAILED",
            "Nat",
        ),
        (
            "exactQuery",
            "(result : Int) (got expected : Nat)",
            "queryReject result got expected",
            "()",
            "EIO",
            "KERNEL_FD_QUERY_FAILED",
            "Unit",
        ),
        (
            "validateEnvelope",
            "(ns envelope : List UInt8) (epoch wrapping_epoch : Nat)",
            "envelopeReject ns envelope epoch wrapping_epoch",
            "()",
            "EINVAL",
            "NAMESPACE_KEY_SHAPE",
            "Unit",
        ),
    ):
        lines += [
            f"def {name} {params} : Except Failure {typ} :=",
            f'  if {guard} then .error ⟨"{errno}", "{reason}"⟩ else .ok ({success})',
        ]
    lines += ["", "end Enclave.TransportGuardSource", ""]
    return "\n".join(lines)


def check(root=ROOT):
    expected = derive(root)
    if (root / OUTPUT).read_text() != expected:
        raise ValueError(
            "source-derived transport guards differ; review source, regenerate explicitly, reprove"
        )
    paths = (*SOURCES, OUTPUT, "scripts/check-transport-guards.py")
    return {
        "status": "PASS",
        "scope": "Trusted shallow translation of selected guard fragments; not universal Rust refinement.",
        "source_sha256": {
            p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in paths
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="explicit reviewed regeneration; never used by gate",
    )
    args = parser.parse_args()
    if args.write:
        (ROOT / OUTPUT).write_text(derive())
    else:
        print(json.dumps(check(), indent=2, sort_keys=True))
