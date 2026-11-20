"""Offline closed-architecture and hostile-header checks; no MLX import."""

import importlib.util
import math
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "trained_mlx_probe", Path(__file__).resolve().parents[1] / "phase4-trained-mlx.py"
)
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


def fixture():
    result = {"__metadata__": {"format": "pt"}}
    offset = 0
    for name, shape in PROBE.expected_shapes().items():
        length = 2 * math.prod(shape)
        result[name] = {
            "dtype": "BF16",
            "shape": shape,
            "data_offsets": [offset, offset + length],
        }
        offset += length
    return result, offset


class TrainedMlxRefusalTests(unittest.TestCase):
    def test_exact_closed_architecture_accepts_valid_full_extent_inventory(self):
        header, size = fixture()
        self.assertEqual(len(PROBE.validate_header(header, size)), 272)

    def test_missing_and_extra_operators_or_tensors_are_refused(self):
        for change in ["missing", "extra"]:
            header, size = fixture()
            if change == "missing":
                del header["model.layers.29.self_attn.q_proj.weight"]
            else:
                header["custom.python_operator"] = {}
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError, "tensor vocabulary"):
                    PROBE.validate_header(header, size)

    def test_wrong_dtype_head_shape_or_boolean_dimensions_refused(self):
        for replacement in [
            {"dtype": "F16"},
            {"shape": [576, 192]},
            {"shape": [True, 576]},
        ]:
            header, size = fixture()
            header["model.layers.0.self_attn.k_proj.weight"].update(replacement)
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(ValueError, "dtype or shape"):
                    PROBE.validate_header(header, size)

    def test_overlapping_gap_and_unindexed_extents_cannot_hide_weight_data(self):
        for delta in [-2, 2]:
            header, size = fixture()
            key = "model.layers.0.input_layernorm.weight"
            header[key]["data_offsets"] = [
                value + delta for value in header[key]["data_offsets"]
            ]
            with self.subTest(delta=delta):
                with self.assertRaisesRegex(ValueError, "overlap or gap"):
                    PROBE.validate_header(header, size)
        header, size = fixture()
        with self.assertRaisesRegex(ValueError, "unindexed"):
            PROBE.validate_header(header, size + 2)

    def test_negative_boolean_and_out_of_range_offsets_refused(self):
        for offsets in [[-2, 1150], [False, 1152], [0, 2**63]]:
            header, size = fixture()
            header["model.layers.0.input_layernorm.weight"]["data_offsets"] = offsets
            with self.subTest(offsets=offsets):
                with self.assertRaises(ValueError):
                    PROBE.validate_header(header, size)

    def test_metadata_cannot_request_model_defined_code(self):
        header, size = fixture()
        header["__metadata__"] = {"format": "pt", "auto_map": "upstream.execute"}
        with self.assertRaisesRegex(ValueError, "metadata"):
            PROBE.validate_header(header, size)

    def test_duplicate_json_keys_refused(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            PROBE.unique([("dtype", "BF16"), ("dtype", "F32")])


if __name__ == "__main__":
    unittest.main()
