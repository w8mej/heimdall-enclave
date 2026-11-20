"""Offline closed multimodal parser, image layout and hostile-input checks."""

import importlib.util
import math
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "trained_smolvlm_probe",
    Path(__file__).resolve().parents[1] / "phase4-trained-smolvlm.py",
)
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


def fixture():
    result = {"__metadata__": {"format": "pt"}}
    cursor = 0
    for name, shape in PROBE.expected_shapes().items():
        size = 2 * math.prod(shape)
        result[name] = {
            "dtype": "BF16",
            "shape": shape,
            "data_offsets": [cursor, cursor + size],
        }
        cursor += size
    return result, cursor


class TrainedSmolVlmTests(unittest.TestCase):
    def test_full_distinct_vision_connector_untied_head_inventory(self):
        header, size = fixture()
        self.assertEqual(PROBE.validate_header(header, size), 471)
        self.assertEqual(header["lm_head.weight"]["shape"], [49280, 576])
        self.assertEqual(
            header["model.connector.modality_projection.proj.weight"]["shape"],
            [576, 12288],
        )

    def test_missing_vision_and_reused_tied_text_shapes_are_refused(self):
        for variant in ["vision_missing", "tied_vocab", "wrong_connector"]:
            header, size = fixture()
            if variant == "vision_missing":
                del header["model.vision_model.encoder.layers.11.mlp.fc2.weight"]
            elif variant == "tied_vocab":
                header["lm_head.weight"]["shape"] = [49152, 576]
            else:
                header["model.connector.modality_projection.proj.weight"]["shape"] = [
                    576,
                    768,
                ]
            with self.subTest(variant=variant):
                with self.assertRaises(ValueError):
                    PROBE.validate_header(header, size)

    def test_hidden_overlap_and_trailing_payload_refused(self):
        header, size = fixture()
        key = "model.vision_model.embeddings.patch_embedding.bias"
        header[key]["data_offsets"] = [x - 2 for x in header[key]["data_offsets"]]
        with self.assertRaisesRegex(ValueError, "overlap/gap"):
            PROBE.validate_header(header, size)
        header, size = fixture()
        with self.assertRaisesRegex(ValueError, "unindexed"):
            PROBE.validate_header(header, size + 2)

    def test_scalar_reference_checks_chw_patch_order_and_rgb_normalization(self):
        # An RGB image with only red=255 and other channels=0 normalizes to
        # [red+1,green-1,blue-1]. Separate channel probes catch HWC/CHW swaps.
        rgb = bytes([255, 0, 0]) * (512 * 512)
        weights = [[0.0] * 768 for _ in range(8)]
        weights[0][0] = 1.0
        weights[1][256] = 1.0
        weights[2][512] = 1.0
        self.assertEqual(
            PROBE.scalar_patch(rgb, weights, [0.0] * 8),
            [1.0, -1.0, -1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        )
        with self.assertRaises(ValueError):
            PROBE.scalar_patch(rgb[:-1], weights, [0.0] * 8)

    def test_pixel_shuffle_preserves_four_rows_and_columns_in_spatial_order(self):
        self.assertEqual(
            PROBE.shuffle_patch_indices(0),
            [0, 1, 2, 3, 32, 33, 34, 35, 64, 65, 66, 67, 96, 97, 98, 99],
        )
        self.assertEqual(
            PROBE.shuffle_patch_indices(9),
            [
                132,
                133,
                134,
                135,
                164,
                165,
                166,
                167,
                196,
                197,
                198,
                199,
                228,
                229,
                230,
                231,
            ],
        )
        self.assertEqual(PROBE.shuffle_patch_indices(63)[-1], 1023)
        for invalid in [-1, 64, True, 1.0]:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    PROBE.shuffle_patch_indices(invalid)

    def test_fixed_owned_images_are_distinct_bounded_and_not_arbitrary_decoding(self):
        a, b = PROBE.owned_rgb(0), PROBE.owned_rgb(1)
        self.assertEqual(len(a), 512 * 512 * 3)
        self.assertEqual(len(b), len(a))
        self.assertNotEqual(a, b)
        self.assertTrue(all(x + y == 255 for x, y in zip(a[:1000], b[:1000])))
        with self.assertRaises(ValueError):
            PROBE.owned_rgb(2)


if __name__ == "__main__":
    unittest.main()
