#!/usr/bin/env python3
"""Offline SRE §1.3 burn-rate aggregation; no collection, notifications or attestation.

Input: strict JSONL minute buckets, with exactly these numeric/enumerated fields:
{"schema":1,"metric":"policy_evaluation","minute":1800000000,"total":100,"bad":1,"unknown":0}
A policy evaluation is bad above 45us (objective 99%); a swarm_sync event is bad
on synchronization failure (objective 99.9%). Classifying/collecting events and
authenticating their source remain the external producer's responsibility.
Exit 0: supplied windows complete and clear; 1: firing or incomplete; 2: invalid.
"""

import argparse
import hashlib
import json
import os
import re
import stat
from collections import defaultdict
from pathlib import Path

MAX_BYTES = 16 * 1024 * 1024
MAX_LINE_BYTES = 1024
MAX_RECORDS = 10000
MAX_COUNT = 10**15
HORIZON_S = 72 * 3600
METRICS = {"policy_evaluation": 100, "swarm_sync": 1000}  # 1 / error budget
# Long seconds, short seconds, exact threshold numerator/denominator, severity.
TIERS = [
    (3600, 300, 72, 5, "SEV-1"),
    (21600, 1800, 6, 1, "SEV-1"),
    (86400, 7200, 3, 1, "SEV-2"),
    (259200, 21600, 1, 1, "SEV-3"),
]
FIELDS = {"schema", "metric", "minute", "total", "bad", "unknown"}


class InvalidInput(ValueError):
    pass


def integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidInput("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def reject_constant(_value):
    raise InvalidInput("NONFINITE_JSON_NUMBER")


def parse_stream(source, as_of):
    """Read a bounded binary stream; reject ambiguity instead of dropping rows."""
    if not integer(as_of, HORIZON_S, 2**63 - 1) or as_of % 60:
        raise InvalidInput("INVALID_AS_OF_MINUTE")
    raw = source.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise InvalidInput("INPUT_BYTES_LIMIT")
    lines = raw.splitlines()
    if len(lines) > MAX_RECORDS:
        raise InvalidInput("INPUT_RECORD_LIMIT")
    records, seen = [], set()
    for line in lines:
        if not line or len(line) > MAX_LINE_BYTES:
            raise InvalidInput("INVALID_LINE_LENGTH")
        try:
            row = json.loads(
                line.decode("utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            ValueError,
        ) as error:
            if isinstance(error, InvalidInput):
                raise
            raise InvalidInput("INVALID_JSON") from None
        if not isinstance(row, dict) or set(row) != FIELDS:
            raise InvalidInput("INVALID_RECORD_FIELDS")
        if (
            type(row["schema"]) is not int
            or row["schema"] != 1
            or not isinstance(row["metric"], str)
            or row["metric"] not in METRICS
        ):
            raise InvalidInput("INVALID_SCHEMA_OR_METRIC")
        if (
            not integer(row["minute"], as_of - HORIZON_S, as_of - 60)
            or row["minute"] % 60
        ):
            raise InvalidInput("INVALID_BUCKET_MINUTE")
        if any(
            not integer(row[key], 0, MAX_COUNT) for key in ("total", "bad", "unknown")
        ):
            raise InvalidInput("INVALID_COUNTER")
        if row["bad"] + row["unknown"] > row["total"]:
            raise InvalidInput("COUNTERS_EXCEED_TOTAL")
        key = row["metric"], row["minute"]
        if key in seen:
            raise InvalidInput("DUPLICATE_METRIC_MINUTE")
        seen.add(key)
        records.append(row)
    return records, hashlib.sha256(raw).hexdigest()


def read_input(path, as_of):
    """Require a stable regular file; a FIFO or symlink must not block ingestion."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise InvalidInput("INPUT_NOT_REGULAR")
        if before.st_size > MAX_BYTES:
            raise InvalidInput("INPUT_BYTES_LIMIT")
        records, digest = parse_stream(source, as_of)
        after = os.fstat(source.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise InvalidInput("INPUT_CHANGED")
        return records, digest


def window(rows, as_of, seconds, budget_inverse):
    selected = [row for row in rows if as_of - seconds <= row["minute"] < as_of]
    expected = seconds // 60
    total = sum(row["total"] for row in selected)
    bad = sum(row["bad"] for row in selected)
    unknown = sum(row["unknown"] for row in selected)
    covered = len(selected) == expected
    reasons = []
    if not covered:
        reasons.append("MISSING_BUCKETS")
    if not total:
        reasons.append("NO_EVENTS")
    if unknown:
        reasons.append("UNKNOWN_OUTCOMES")
    # With all minute buckets present, unknown outcomes have a known denominator;
    # known bad / total is a sound lower bound. Missing minutes have no bounded
    # event denominator, so even a lower-bound burn claim would be unsupported.
    evaluable = covered and total > 0
    return {
        "seconds": seconds,
        "expected_buckets": expected,
        "observed_buckets": len(selected),
        "total": total,
        "bad": bad,
        "unknown": unknown,
        "complete": not reasons,
        "reasons": reasons,
        "burn_lower_bound": (
            {"numerator": bad * budget_inverse, "denominator": total}
            if evaluable
            else None
        ),
    }


def breaches(observation, numerator, denominator):
    value = observation["burn_lower_bound"]
    return (
        value is not None
        and value["numerator"] * denominator >= value["denominator"] * numerator
    )


def aggregate(records, as_of):
    by_metric = defaultdict(list)
    for row in records:
        by_metric[row["metric"]].append(row)
    metrics = {}
    for metric, budget_inverse in METRICS.items():
        spans = sorted(
            {span for long_s, short_s, *_ in TIERS for span in (long_s, short_s)}
        )
        windows = {
            str(span): window(by_metric[metric], as_of, span, budget_inverse)
            for span in spans
        }
        decisions = []
        for long_s, short_s, numerator, denominator, severity in TIERS:
            long, short = windows[str(long_s)], windows[str(short_s)]
            fires = breaches(long, numerator, denominator) and breaches(
                short, numerator, denominator
            )
            complete = long["complete"] and short["complete"]
            state = "FIRING" if fires else ("CLEAR" if complete else "UNKNOWN")
            decisions.append(
                {
                    "long_seconds": long_s,
                    "short_seconds": short_s,
                    "threshold": {"numerator": numerator, "denominator": denominator},
                    "severity": severity,
                    "state": state,
                    "complete": complete,
                }
            )
        metrics[metric] = {
            "objective": {
                "numerator": budget_inverse - 1,
                "denominator": budget_inverse,
            },
            "windows": windows,
            "decisions": decisions,
        }
    incomplete = any(
        not observation["complete"]
        for metric in metrics.values()
        for observation in metric["windows"].values()
    )
    firing = any(
        decision["state"] == "FIRING"
        for metric in metrics.values()
        for decision in metric["decisions"]
    )
    return {
        "schema": 1,
        "status": "ATTENTION" if firing else ("INCOMPLETE" if incomplete else "CLEAR"),
        "complete": not incomplete,
        "firing": firing,
        "as_of_unix_s": as_of,
        "window_convention": "[as_of - duration, as_of), aligned 60-second buckets",
        "specification": "docs/SRE_RUNBOOKS.md section 1.3",
        "scope": "offline arithmetic over caller-supplied counters; no source authentication, load acceptance, notification or release approval",
        "data_quality_alert": incomplete,
        "metrics": metrics,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument(
        "--as-of",
        required=True,
        type=int,
        help="Exclusive aligned Unix minute endpoint",
    )
    parser.add_argument(
        "--kind", required=True, choices=["fixture", "supplied-observations"]
    )
    parser.add_argument(
        "--revision",
        required=True,
        help="Caller-supplied measured candidate commit (40 lowercase hex)",
    )
    args = parser.parse_args(argv)
    try:
        if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
            raise InvalidInput("INVALID_REVISION")
        records, digest = read_input(args.input, args.as_of)
        report = aggregate(records, args.as_of)
        report.update(
            input_sha256=digest,
            record_count=len(records),
            data_kind=args.kind,
            supplied_revision=args.revision,
            attribution="caller supplied; neither authenticity nor measurement provenance verified",
        )
        print(json.dumps(report, sort_keys=True))
        return 1 if report["firing"] or not report["complete"] else 0
    except (InvalidInput, OSError) as error:
        # Do not echo potentially sensitive source text, paths or arguments.
        code = str(error) if isinstance(error, InvalidInput) else "INPUT_IO_ERROR"
        print(json.dumps({"schema": 1, "status": "INVALID", "error": code}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
