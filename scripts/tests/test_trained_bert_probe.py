"""Offline refusals for the closed pretrained-checkpoint preparation tool."""

import importlib.util
import json
import struct
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "trained_bert_probe", Path(__file__).resolve().parents[1] / "phase4-trained-bert.py"
)
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)

METADATA = {
    "cls.predictions.decoder.weight": "bert.embeddings.word_embeddings.weight",
    "format": "pt",
    "cls.predictions.decoder.bias": "cls.predictions.bias",
}


def encoded(header, payload=b""):
    body = json.dumps(header).encode()
    return struct.pack("<Q", len(body)) + body + payload


class TrainedBertRefusalTests(unittest.TestCase):
    def test_pin_refuses_any_unverified_payload(self):
        with self.assertRaisesRegex(ValueError, "checkpoint pin"):
            PROBE.load_tensors(b"different trusted-looking checkpoint")

    def test_oversized_header_is_rejected_before_json_or_tensor_allocation(self):
        for declared in [65537, 2**64 - 1, 100]:
            with self.subTest(declared=declared):
                with self.assertRaisesRegex(ValueError, "header bound"):
                    PROBE.load_tensors(
                        struct.pack("<Q", declared) + b"{}", verify_pin=False
                    )

    def test_duplicate_and_nonobject_headers_are_rejected(self):
        raw = b'{"__metadata__":{},"__metadata__":{}}'
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            PROBE.load_tensors(struct.pack("<Q", len(raw)) + raw, verify_pin=False)
        with self.assertRaisesRegex(ValueError, "header object"):
            PROBE.load_tensors(encoded([]), verify_pin=False)

    def test_remote_code_and_arbitrary_tensor_vocabulary_are_not_accepted(self):
        header = {
            "__metadata__": METADATA,
            "custom.operator": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
        }
        with self.assertRaisesRegex(ValueError, "tensor vocabulary"):
            PROBE.load_tensors(encoded(header, b"\0" * 4), verify_pin=False)
        header["__metadata__"] = {"auto_map": "execute.some_code"}
        with self.assertRaisesRegex(ValueError, "checkpoint metadata"):
            PROBE.load_tensors(encoded(header), verify_pin=False)

    def test_exact_shapes_and_offsets_are_checked_before_reading_float_data(self):
        header = {"__metadata__": METADATA}
        cursor = 0
        for name, shape in PROBE.shapes().items():
            import math

            length = 4 * math.prod(shape)
            header[name] = {
                "dtype": "F32",
                "shape": shape,
                "data_offsets": [cursor, cursor + length],
            }
            cursor += length
        name = next(iter(PROBE.shapes()))
        original = header[name]
        for replacement in [
            dict(original, shape=[128, 30522]),
            dict(original, dtype="F16"),
            dict(original, data_offsets=[False, 4]),
            dict(original, data_offsets=[0, 2**63]),
        ]:
            header[name] = replacement
            with self.subTest(replacement=replacement):
                with self.assertRaises(ValueError):
                    PROBE.load_tensors(encoded(header), verify_pin=False)

    def test_reference_refuses_padding_length_and_invalid_token_inputs(self):
        for token_ids in [
            [0] * 7,
            [0] * 9,
            [0] * 7 + [30522],
            [0] * 7 + [-1],
            [0] * 7 + [True],
            [0] * 7 + [1.0],
        ]:
            with self.subTest(token_ids=token_ids):
                with self.assertRaisesRegex(ValueError, "eight valid token IDs"):
                    PROBE.reference({}, token_ids)

    def test_export_does_not_admit_unrecognized_graph_operations(self):
        graph = PROBE.Graph({})
        with self.assertRaises(KeyError):
            graph.add("unsafe", ["tokens"], "custom", b"")


if __name__ == "__main__":
    unittest.main()
