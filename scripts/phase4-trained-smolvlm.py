#!/usr/bin/env python3
"""Closed selected SmolVLM CPU probe on two owned fixed512RGB synthetic images.

No upstream executable code, arbitrary image decoding or production admission.
Full screenshot preprocessing/chat templates/quality/JEPA/erasure remain absent.
"""

import argparse
import hashlib
import importlib.util
import json
import math
import platform
import sys
import time
from pathlib import Path

HELPER_SPEC = importlib.util.spec_from_file_location(
    "owned_trained_mlx", Path(__file__).with_name("phase4-trained-mlx.py")
)
HELPER = importlib.util.module_from_spec(HELPER_SPEC)
HELPER_SPEC.loader.exec_module(HELPER)
REVISION = "d039ab0d4b9311b617e8ffec1d06c8464364aeb3"
WEIGHT_BYTES = 513028808
WEIGHT_SHA256 = "74dea5904032e5ae99a2e0eef5179e6ac0f1dedc3ab0c7c2a5d4d387c843203e"
SUPPORT_PINS = {
    "config.json": "b70fb4bfde88df9eeebc9d8ff523733b8bf70d6c9b06c610325960e06ae9db52",
    "tokenizer.json": "5ece781dc8d2b2f3e2f289ca0ae50b17cfc27dd27bfe7971bb8241e0b964331a",
    "preprocessor_config.json": "6cb6e36d6fcb88ca1502c4a26750715dc3e7dedddc9a8f17b27d8d167d1457e7",
    "processor_config.json": "e7bff42da73ae9eec9042ef20e066e11f1ee20f025358ff79131e3c0fb549b46",
}
TEXT_IDS = [19556, 905]  # Explicit Hello/Ġworld; no chat-template quality claim.


def expected_shapes():
    result = {
        name.replace("model.", "model.text_model.", 1): shape
        for name, shape in HELPER.expected_shapes().items()
    }
    result["model.text_model.embed_tokens.weight"] = [49280, 576]
    result["lm_head.weight"] = [49280, 576]
    result["model.connector.modality_projection.proj.weight"] = [576, 12288]
    p = "model.vision_model."
    result.update(
        {
            p + "embeddings.patch_embedding.weight": [768, 3, 16, 16],
            p + "embeddings.patch_embedding.bias": [768],
            p + "embeddings.position_embedding.weight": [1024, 768],
            p + "post_layernorm.weight": [768],
            p + "post_layernorm.bias": [768],
        }
    )
    for layer in range(12):
        prefix = p + f"encoder.layers.{layer}."
        for norm in ["layer_norm1", "layer_norm2"]:
            result[prefix + norm + ".weight"] = [768]
            result[prefix + norm + ".bias"] = [768]
        for name in ["q_proj", "k_proj", "v_proj", "out_proj"]:
            result[prefix + "self_attn." + name + ".weight"] = [768, 768]
            result[prefix + "self_attn." + name + ".bias"] = [768]
        result[prefix + "mlp.fc1.weight"] = [3072, 768]
        result[prefix + "mlp.fc1.bias"] = [3072]
        result[prefix + "mlp.fc2.weight"] = [768, 3072]
        result[prefix + "mlp.fc2.bias"] = [768]
    return result


def validate_header(header, payload_bytes):
    if not isinstance(header, dict) or header.get("__metadata__") != {"format": "pt"}:
        raise ValueError("checkpoint metadata")
    expected = expected_shapes()
    if set(header) - {"__metadata__"} != set(expected):
        raise ValueError("closed471tensor vocabulary")
    intervals = []
    for name, shape in expected.items():
        item = header[name]
        if (
            not isinstance(item, dict)
            or set(item) != {"dtype", "shape", "data_offsets"}
            or item["dtype"] != "BF16"
            or item["shape"] != shape
            or any(type(n) is not int for n in item["shape"])
        ):
            raise ValueError("tensor shape/dtype")
        offsets = item["data_offsets"]
        if (
            not isinstance(offsets, list)
            or len(offsets) != 2
            or any(type(n) is not int for n in offsets)
        ):
            raise ValueError("tensor offsets")
        start, end = offsets
        if start < 0 or end > payload_bytes or end - start != 2 * math.prod(shape):
            raise ValueError("tensor extent")
        intervals.append((start, end))
    cursor = 0
    for start, end in sorted(intervals):
        if start != cursor:
            raise ValueError("tensor overlap/gap")
        cursor = end
    if cursor != payload_bytes:
        raise ValueError("unindexed weight bytes")
    return len(expected)


def inspect(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != WEIGHT_BYTES:
        raise ValueError("bounded regular checkpoint")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    if digest.hexdigest() != WEIGHT_SHA256:
        raise ValueError("checkpoint SHA256")
    with path.open("rb") as stream:
        length = int.from_bytes(stream.read(8), "little")
        if not 2 <= length <= 65536:
            raise ValueError("header bound")
        header = json.loads(stream.read(length), object_pairs_hook=HELPER.unique)
    return validate_header(header, WEIGHT_BYTES - 8 - length)


def owned_rgb(variant):
    if variant not in [0, 1]:
        raise ValueError("two owned image variants only")
    # Byte-exact RGB512² content; no external decoder, resizing or image library.
    return bytes(
        component
        for y in range(512)
        for x in range(512)
        for component in (
            (x % 256, y % 256, (x + y) % 256)
            if variant == 0
            else (255 - x % 256, 255 - y % 256, 255 - (x + y) % 256)
        )
    )


def scalar_patch(rgb, weights, bias):
    if len(rgb) != 512 * 512 * 3 or len(weights) != 8 or len(bias) != 8:
        raise ValueError("scalar patch bounds")
    patch = [
        (rgb[(y * 512 + x) * 3 + c] / 255.0 - 0.5) / 0.5
        for c in range(3)
        for y in range(16)
        for x in range(16)
    ]
    if any(len(row) != 768 for row in weights):
        raise ValueError("patch projection shape")
    return [
        sum(a * b for a, b in zip(patch, row)) + offset
        for row, offset in zip(weights, bias)
    ]


def shuffle_patch_indices(output_token):
    if type(output_token) is not int or not 0 <= output_token < 64:
        raise ValueError("shuffle tile bound")
    tile_y, tile_x = divmod(output_token, 8)
    return [
        (tile_y * 4 + dy) * 32 + tile_x * 4 + dx for dy in range(4) for dx in range(4)
    ]


def execute(path, site):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("native arm64MLX required")
    if not site.is_absolute() or not site.is_dir() or site.is_symlink():
        raise ValueError("explicit pinnedMLXsite")
    pins = site / "mcpmac-wheel-pins.json"
    if pins.stat().st_size > 65536:
        raise ValueError("wheel provenance bound")
    if {row.get("sha256") for row in json.loads(pins.read_text())} != HELPER.WHEELS:
        raise ValueError("wheel pins")
    sys.path.insert(0, str(site))
    import mlx.core as mx

    mx.set_default_device(mx.cpu)
    started = time.monotonic()
    weights = mx.load(str(path), format="safetensors")
    if set(weights) != set(expected_shapes()):
        raise ValueError("loaded vocabulary")
    for name, shape in expected_shapes().items():
        value = weights[name]
        if list(value.shape) != shape or value.dtype != mx.bfloat16:
            raise ValueError("loaded dtype/shape")
        if not bool(mx.all(mx.isfinite(value)).item()):
            raise ValueError("nonfinite trained weights")

    def linear(x, name, bias=False):
        output = x @ weights[name + ".weight"].astype(mx.float32).T
        return output + weights[name + ".bias"].astype(mx.float32) if bias else output

    def layer_norm(x, name):
        mean = mx.mean(x, axis=-1, keepdims=True)
        centered = x - mean
        return centered * mx.rsqrt(
            mx.mean(centered * centered, axis=-1, keepdims=True) + 1e-6
        ) * weights[name + ".weight"].astype(mx.float32) + weights[
            name + ".bias"
        ].astype(
            mx.float32
        )

    def rms_norm(x, name):
        return (
            x
            * mx.rsqrt(mx.mean(x * x, axis=-1, keepdims=True) + 1e-5)
            * weights[name].astype(mx.float32)
        )

    scalar_errors = []
    image_hashes = []
    connector_checks = []

    def vision(rgb):
        image_hashes.append(hashlib.sha256(rgb).hexdigest())
        # HWC bytes to NCHW; exact512RGB avoids general resize/split/pad policy.
        image = (
            mx.array(list(rgb), dtype=mx.float32)
            .reshape(1, 512, 512, 3)
            .transpose(0, 3, 1, 2)
        )
        image = (image / 255.0 - 0.5) / 0.5
        patches = (
            image.reshape(1, 3, 32, 16, 32, 16)
            .transpose(0, 2, 4, 1, 3, 5)
            .reshape(1, 1024, 768)
        )
        p = "model.vision_model."
        patch_weight = (
            weights[p + "embeddings.patch_embedding.weight"]
            .astype(mx.float32)
            .reshape(768, 768)
        )
        patch_bias = weights[p + "embeddings.patch_embedding.bias"].astype(mx.float32)
        x = patches @ patch_weight.T + patch_bias
        actual = x[0, 0, :8].tolist()
        reference = scalar_patch(
            rgb, patch_weight[:8].tolist(), patch_bias[:8].tolist()
        )
        error = max(abs(a - b) for a, b in zip(actual, reference))
        scalar_errors.append(error)
        if error > 2e-4:
            raise ValueError("scalar first-patch projection reference")
        x = (
            x
            + weights[p + "embeddings.position_embedding.weight"].astype(mx.float32)[
                None, :, :
            ]
        )
        mx.eval(x)
        for layer in range(12):
            prefix = p + f"encoder.layers.{layer}."
            z = layer_norm(x, prefix + "layer_norm1")
            q = (
                linear(z, prefix + "self_attn.q_proj", True)
                .reshape(1, 1024, 12, 64)
                .transpose(0, 2, 1, 3)
            )
            k = (
                linear(z, prefix + "self_attn.k_proj", True)
                .reshape(1, 1024, 12, 64)
                .transpose(0, 2, 1, 3)
            )
            v = (
                linear(z, prefix + "self_attn.v_proj", True)
                .reshape(1, 1024, 12, 64)
                .transpose(0, 2, 1, 3)
            )
            pieces = []
            for first in range(0, 1024, 128):
                scores = (q[:, :, first : first + 128, :] @ k.swapaxes(-1, -2)) * 0.125
                piece = mx.softmax(scores, axis=-1) @ v
                mx.eval(piece)
                pieces.append(piece)
            context = (
                mx.concatenate(pieces, axis=2)
                .transpose(0, 2, 1, 3)
                .reshape(1, 1024, 768)
            )
            x = x + linear(context, prefix + "self_attn.out_proj", True)
            z = layer_norm(x, prefix + "layer_norm2")
            z = linear(z, prefix + "mlp.fc1", True)
            z = (
                0.5
                * z
                * (1 + mx.tanh(math.sqrt(2 / math.pi) * (z + 0.044715 * z * z * z)))
            )
            x = x + linear(z, prefix + "mlp.fc2", True)
            mx.eval(x)
        x = layer_norm(x, p + "post_layernorm")
        # Four adjacent columns per row, then four adjacent rows per tile;
        # channel order is [dy,dx,vision_channel], matching Idefics3 connector.
        shuffled = (
            x.reshape(1, 8, 4, 8, 4, 768)
            .transpose(0, 1, 3, 2, 4, 5)
            .reshape(1, 64, 12288)
        )
        # Independent explicit tile indexing checks against original vision rows.
        for tile in [0, 9, 63]:
            expected = []
            for source in shuffle_patch_indices(tile):
                expected.extend(x[0, source, :].tolist())
            observed = shuffled[0, tile, :].tolist()
            if observed != expected:
                raise ValueError("pixel shuffle spatial ordering")
        output = linear(shuffled, "model.connector.modality_projection.proj")
        mx.eval(output)
        row = shuffled[0, 0, :].tolist()
        matrix = (
            weights["model.connector.modality_projection.proj.weight"][:4]
            .astype(mx.float32)
            .tolist()
        )
        reference = [sum(a * b for a, b in zip(row, column)) for column in matrix]
        error = max(abs(a - b) for a, b in zip(output[0, 0, :4].tolist(), reference))
        connector_checks.append(error)
        if error > 2e-3:
            raise ValueError("scalar modality projection reference")
        if not bool(mx.all(mx.isfinite(output)).item()):
            raise ValueError("nonfinite image embeddings")
        return output

    def rope(x):
        inverse = mx.power(
            mx.array(100000.0, dtype=mx.float32),
            -mx.arange(0, 64, 2, dtype=mx.float32) / 64.0,
        )
        angles = mx.arange(x.shape[-2], dtype=mx.float32)[:, None] * inverse[None, :]
        cosine, sine = (
            mx.cos(angles)[None, None, :, :],
            mx.sin(angles)[None, None, :, :],
        )
        first, second = x[..., :32], x[..., 32:]
        return mx.concatenate(
            [first * cosine - second * sine, second * cosine + first * sine], axis=-1
        )

    def text(image_embeddings, ids):
        if not 2 <= len(ids) <= 4 or any(
            type(n) is not int or not 0 <= n < 49280 for n in ids
        ):
            raise ValueError("text token bound")
        p = "model.text_model."
        embedding = weights[p + "embed_tokens.weight"]
        # Exactly64image placeholders are replaced by64image embeddings. The
        # two explicit text tokens follow the view; no general processor claim.
        x = mx.concatenate(
            [
                embedding[mx.array([1], dtype=mx.int32)].astype(mx.float32)[None, :, :],
                image_embeddings,
                embedding[mx.array(ids, dtype=mx.int32)].astype(mx.float32)[None, :, :],
            ],
            axis=1,
        )
        n = x.shape[1]
        mask = mx.arange(n)[:, None] >= mx.arange(n)[None, :]
        for layer in range(30):
            prefix = p + f"layers.{layer}."
            z = rms_norm(x, prefix + "input_layernorm.weight")
            q = (
                linear(z, prefix + "self_attn.q_proj")
                .reshape(1, n, 9, 64)
                .transpose(0, 2, 1, 3)
            )
            k = (
                linear(z, prefix + "self_attn.k_proj")
                .reshape(1, n, 3, 64)
                .transpose(0, 2, 1, 3)
            )
            v = (
                linear(z, prefix + "self_attn.v_proj")
                .reshape(1, n, 3, 64)
                .transpose(0, 2, 1, 3)
            )
            q, k = rope(q), mx.repeat(rope(k), 3, axis=1)
            v = mx.repeat(v, 3, axis=1)
            scores = (q @ k.swapaxes(-1, -2)) * 0.125
            probabilities = mx.softmax(
                mx.where(mask, scores, mx.array(-1e9, dtype=mx.float32)), axis=-1
            )
            context = (probabilities @ v).transpose(0, 2, 1, 3).reshape(1, n, 576)
            x = x + linear(context, prefix + "self_attn.o_proj")
            z = rms_norm(x, prefix + "post_attention_layernorm.weight")
            gate = linear(z, prefix + "mlp.gate_proj")
            x = x + linear(
                gate * mx.sigmoid(gate) * linear(z, prefix + "mlp.up_proj"),
                prefix + "mlp.down_proj",
            )
            mx.eval(x)
        final = rms_norm(x[:, -1, :], p + "norm.weight")
        result = linear(final, "lm_head")[0]
        mx.eval(result)
        if not bool(mx.all(mx.isfinite(result)).item()):
            raise ValueError("nonfinite VLM logits")
        return result

    image_a = vision(owned_rgb(0))
    image_b = vision(owned_rgb(1))
    image_difference = float(mx.max(mx.abs(image_a - image_b)).item())
    if image_difference < 1e-4:
        raise ValueError("image embedding insensitivity")
    logits_a = text(image_a, TEXT_IDS)
    logits_b = text(image_b, TEXT_IDS)
    logit_difference = float(mx.max(mx.abs(logits_a - logits_b)).item())
    if logit_difference < 1e-4:
        raise ValueError("image-conditioned output insensitivity")
    generated = [int(mx.argmax(logits_a).item())]
    next_logits = text(image_a, TEXT_IDS + generated)
    generated.append(int(mx.argmax(next_logits).item()))
    return {
        "status": "PASS_BOUNDED_TRAINED_VLM",
        "trained_checkpoint_executed": True,
        "model_revision": REVISION,
        "checkpoint_sha256": WEIGHT_SHA256,
        "tensor_count": 471,
        "compute_device": "MLX CPU",
        "vision_layers": 12,
        "decoder_layers": 30,
        "input_rgb_sha256": image_hashes,
        "image_shape": [512, 512, 3],
        "image_tokens_per_view": 64,
        "scalar_patch_projection_max_errors": scalar_errors,
        "scalar_connector_max_errors": connector_checks,
        "shuffle_reference_tiles": [0, 9, 63],
        "image_embedding_max_difference": image_difference,
        "image_conditioned_logit_max_difference": logit_difference,
        "explicit_text_token_ids": TEXT_IDS,
        "generated_token_ids": generated,
        "elapsed_execution_seconds": time.monotonic() - started,
        "resource_acceptance": False,
        "production_adapter_wired": False,
        "browser_actuation_wired": False,
        "jepa_contract_satisfied": False,
        "full_model_browser_gate_accepted": False,
        "limitations": [
            "Owned exact512RGB fixtures only; no arbitrary screenshot decoding/resize/split/pad/masking/preprocessor acceptance.",
            "Fixed multimodal64image positions and2explicittext IDs; no full processor/chat template or semantic quality acceptance.",
            "Independent scalar checks cover patch/connector and spatial order, not end-to-end vision-language reference equivalence.",
            "No browser observation/DOM-AX authorization/action pipeline, production class admission, JEPA predictor/cost/MPC companions, interruption/erasure or installed/resource acceptance.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--support", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--site", type=Path)
    parser.add_argument("--footprint-library", type=Path)
    args = parser.parse_args()
    count = inspect(args.checkpoint)
    support = {
        name: HELPER.pinned_json(args.support / name, pin, 4 * 1024**2)
        for name, pin in SUPPORT_PINS.items()
    }
    config = support["config.json"]
    pre = support["preprocessor_config.json"]
    if (
        config.get("model_type") != "idefics3"
        or config.get("image_token_id") != 49190
        or config.get("scale_factor") != 4
        or config["vision_config"]["hidden_size"] != 768
        or config["vision_config"]["num_hidden_layers"] != 12
        or config["vision_config"]["layer_norm_eps"] != 1e-6
        or config["vision_config"]["hidden_act"] != "gelu_pytorch_tanh"
        or config["text_config"]["tie_word_embeddings"] is not False
        or support["processor_config.json"].get("image_seq_len") != 64
        or pre.get("image_mean") != [0.5] * 3
        or pre.get("image_std") != [0.5] * 3
        or pre.get("rescale_factor") != 1 / 255
    ):
        raise ValueError("fixed Idefics3 configuration")
    vocabulary = support["tokenizer.json"]["model"]["vocab"]
    if any(
        vocabulary.get(word) != token
        for word, token in [("Hello", 19556), ("Ġworld", 905)]
    ):
        raise ValueError("explicit text token provenance")
    if not args.execute:
        print(
            json.dumps(
                {
                    "status": "PASS_PINNED_VLM_INSPECTION",
                    "tensors": count,
                    "checkpoint_sha256": WEIGHT_SHA256,
                    "trained_checkpoint_executed": False,
                },
                indent=2,
            )
        )
        return
    if not args.site or not args.footprint_library:
        raise ValueError("explicit pinnedsite/SDKlibrary required")
    observer = HELPER.Footprint(args.footprint_library.resolve())
    observer.thread.start()
    record = {}
    try:
        record = execute(args.checkpoint.resolve(), args.site.resolve())
    except Exception as error:
        record = {
            "status": "FAIL",
            "error": str(error),
            "trained_checkpoint_executed": False,
        }
    finally:
        record.update(observer.finish())
    print(json.dumps(record, indent=2, allow_nan=False))
    if record["status"] != "PASS_BOUNDED_TRAINED_VLM":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
