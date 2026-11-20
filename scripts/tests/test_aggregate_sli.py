#!/usr/bin/env python3
"""Meaningful offline window/hostile-input checks; no production telemetry claim."""

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/aggregate-sli.py"
spec = importlib.util.spec_from_file_location("aggregate_sli", SCRIPT)
sli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sli)
AS_OF = 1800000000  # aligned minute
REVISION = "a" * 40


def bucket(metric="policy_evaluation", minute=AS_OF - 60, total=1000, bad=0, unknown=0):
    return dict(
        schema=1, metric=metric, minute=minute, total=total, bad=bad, unknown=unknown
    )


def encode(records):
    return b"".join(
        json.dumps(row, separators=(",", ":")).encode() + b"\n" for row in records
    )


def history(policy_bad=0, swarm_bad=0, total=1000, minutes=4320):
    return [
        bucket(metric, AS_OF - 60 * (i + 1), total, bad)
        for metric, bad in [
            ("policy_evaluation", policy_bad),
            ("swarm_sync", swarm_bad),
        ]
        for i in range(minutes)
    ]


class AggregateSli(unittest.TestCase):
    def parse(self, raw):
        return sli.parse_stream(io.BytesIO(raw), AS_OF)[0]

    def test_complete_clear_history_and_exact_objective_mapping(self):
        records = self.parse(encode(history()))
        report = sli.aggregate(records, AS_OF)
        self.assertEqual(report["status"], "CLEAR")
        self.assertTrue(report["complete"])
        self.assertFalse(report["data_quality_alert"])
        self.assertTrue(
            all(
                d["state"] == "CLEAR"
                for metric in report["metrics"].values()
                for d in metric["decisions"]
            )
        )
        self.assertEqual(
            report["metrics"]["swarm_sync"]["objective"],
            {"numerator": 999, "denominator": 1000},
        )

    def test_threshold_equality_fires_without_float_rounding(self):
        # 144/1000 policy failures divided by .01 budget is exactly14.4.
        report = sli.aggregate(history(policy_bad=144), AS_OF)
        decision = report["metrics"]["policy_evaluation"]["decisions"][0]
        self.assertEqual(decision["state"], "FIRING")
        self.assertEqual(decision["threshold"], {"numerator": 72, "denominator": 5})
        below = sli.aggregate(history(policy_bad=143), AS_OF)
        self.assertEqual(
            below["metrics"]["policy_evaluation"]["decisions"][0]["state"], "CLEAR"
        )

    def test_long_and_short_both_required(self):
        records = history()
        # Most of the preceding hour failed, but newest5minutes recovered.
        for row in records:
            if (
                row["metric"] == "policy_evaluation"
                and AS_OF - 3600 <= row["minute"] < AS_OF - 300
            ):
                row["bad"] = 1000
        first = sli.aggregate(records, AS_OF)["metrics"]["policy_evaluation"][
            "decisions"
        ][0]
        self.assertEqual(first["state"], "CLEAR")
        # A brief new spike has a hot5minute window but a below-threshold hour.
        for row in records:
            row["bad"] = (
                1000
                if row["metric"] == "policy_evaluation" and row["minute"] >= AS_OF - 300
                else 0
            )
        first = sli.aggregate(records, AS_OF)["metrics"]["policy_evaluation"][
            "decisions"
        ][0]
        self.assertEqual(first["state"], "CLEAR")

    def test_missing_minute_prevents_green_and_burn_claim(self):
        records = history(policy_bad=1000)
        records = [
            row
            for row in records
            if not (
                row["metric"] == "policy_evaluation" and row["minute"] == AS_OF - 60
            )
        ]
        metric = sli.aggregate(records, AS_OF)["metrics"]["policy_evaluation"]
        self.assertFalse(metric["windows"]["300"]["complete"])
        self.assertIsNone(metric["windows"]["300"]["burn_lower_bound"])
        self.assertEqual(metric["decisions"][0]["state"], "UNKNOWN")

    def test_unknown_outcomes_cannot_clear_or_hide_provable_breach(self):
        records = history()
        records[0]["unknown"] = 1
        report = sli.aggregate(records, AS_OF)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertTrue(report["data_quality_alert"])
        self.assertEqual(
            report["metrics"]["policy_evaluation"]["decisions"][0]["state"], "UNKNOWN"
        )
        for row in records:
            if row["metric"] == "policy_evaluation":
                row.update(bad=500, unknown=500)
        report = sli.aggregate(records, AS_OF)
        self.assertEqual(report["status"], "ATTENTION")
        self.assertFalse(report["complete"])
        self.assertEqual(
            report["metrics"]["policy_evaluation"]["decisions"][0]["state"], "FIRING"
        )

    def test_zero_event_and_empty_input_are_unknown(self):
        for records in [[], history(total=0)]:
            report = sli.aggregate(records, AS_OF)
            self.assertEqual(report["status"], "INCOMPLETE")
            self.assertFalse(report["firing"])
            self.assertIn(
                "NO_EVENTS",
                report["metrics"]["policy_evaluation"]["windows"]["300"]["reasons"],
            )

    def test_half_open_window_excludes_older_boundary_and_keeps_start(self):
        rows = [
            bucket(minute=AS_OF - 360),
            bucket(minute=AS_OF - 300),
            bucket(minute=AS_OF - 60),
        ]
        result = sli.window(rows, AS_OF, 300, 100)
        self.assertEqual(result["observed_buckets"], 2)
        self.assertEqual(result["total"], 2000)

    def test_duplicate_overlap_offgrid_and_future_buckets_refused(self):
        cases = [
            encode([bucket(), bucket()]),
            encode([bucket(minute=AS_OF - 61)]),
            encode([bucket(minute=AS_OF)]),
            encode([bucket(minute=AS_OF - sli.HORIZON_S - 60)]),
        ]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(sli.InvalidInput):
                self.parse(raw)

    def test_malformed_fields_types_nonfinite_and_counter_bounds_refused(self):
        cases = [
            b'{"schema":1,"schema":1}\n',
            b"NaN\n",
            b'{"total":Infinity}\n',
            b"[]\n",
            b"\xff\n",
        ]
        for changes in [
            dict(metric=[]),
            dict(metric="unapproved"),
            dict(total=True),
            dict(bad=-1),
            dict(total=1, bad=1, unknown=1),
            dict(total=sli.MAX_COUNT + 1),
            dict(extra="secret payload"),
            dict(schema=True),
        ]:
            row = bucket()
            row.update(changes)
            cases.append(encode([row]))
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(sli.InvalidInput):
                self.parse(raw)

    def test_bounded_bytes_lines_and_records(self):
        with patch.object(sli, "MAX_BYTES", 10), self.assertRaisesRegex(
            sli.InvalidInput, "INPUT_BYTES_LIMIT"
        ):
            self.parse(b"x" * 11)
        with self.assertRaisesRegex(sli.InvalidInput, "INVALID_LINE_LENGTH"):
            self.parse(b"x" * (sli.MAX_LINE_BYTES + 1))
        with patch.object(sli, "MAX_RECORDS", 1), self.assertRaisesRegex(
            sli.InvalidInput, "INPUT_RECORD_LIMIT"
        ):
            self.parse(encode([bucket(), bucket()]))

    def test_regular_stable_input_required(self):
        (ROOT / "target").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="sli-input-", dir=ROOT / "target"
        ) as directory:
            folder = Path(directory)
            path = folder / "input.jsonl"
            path.write_bytes(encode([bucket()]))
            link = folder / "link.jsonl"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                sli.read_input(link, AS_OF)
            fifo = folder / "fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(sli.InvalidInput, "INPUT_NOT_REGULAR"):
                sli.read_input(fifo, AS_OF)
            parser = sli.parse_stream

            def changed(source, as_of):
                result = parser(source, as_of)
                with path.open("ab") as destination:
                    destination.write(b"\n")
                return result

            with patch.object(sli, "parse_stream", changed), self.assertRaisesRegex(
                sli.InvalidInput, "INPUT_CHANGED"
            ):
                sli.read_input(path, AS_OF)

    def test_cli_exit_status_hash_attribution_and_no_payload_echo(self):
        (ROOT / "target").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="sli-fixture-", dir=ROOT / "target"
        ) as directory:
            path = Path(directory) / "buckets.jsonl"

            def run(raw):
                path.write_bytes(raw)
                result = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        str(SCRIPT),
                        str(path),
                        "--as-of",
                        str(AS_OF),
                        "--kind",
                        "fixture",
                        "--revision",
                        REVISION,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return result, json.loads(result.stdout)

            result, report = run(encode(history()))
            self.assertEqual(result.returncode, 0)
            self.assertEqual(report["data_kind"], "fixture")
            self.assertEqual(report["supplied_revision"], REVISION)
            self.assertEqual(len(report["input_sha256"]), 64)
            result, report = run(b"")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(report["status"], "INCOMPLETE")
            result, report = run(b'{"payload":"SECRET_DO_NOT_ECHO"}\n')
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("SECRET_DO_NOT_ECHO", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
