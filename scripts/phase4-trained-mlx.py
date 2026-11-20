#!/usr/bin/env python3
"""Strict selected SmolLM2 checkpoint inspection and bounded actual MLX CPU probe.

This closed Llama implementation executes no upstream model-defined code. It is
a standalone experiment, not the production adapter or full model acceptance.
Use python -I -S and the explicit task-owned pinned MLX wheel site for --execute.
"""

import argparse
import ctypes
import hashlib
import json
import math
import platform
import sys
import threading
import time
from pathlib import Path

REVISION = "12fd25f77366fa6b3b4b768ec3050bf629380bac"
CHECKPOINT_BYTES = 269060552
CHECKPOINT_SHA256 = "5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c"
CONFIG_SHA256 = "8eb740e8bbe4cff95ea7b4588d17a2432deb16e8075bc5828ff7ba9be94d982a"
TOKENIZER_SHA256 = "9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c"
WHEELS = {
    "60ba41564e8b5018c9d8a5f8ce7a5aaf70c96d8dd98c1a54b854cbada362d471",
    "8019b2db622599267d66cc168b2f0dbf5af929790a6c3b3913e00eabc42a7947",
}
PROMPT = [
    1,
    19556,
    905,
]  # Explicit [<|im_start|>, Hello, Ġworld], not a chat template/tokenizer.


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def expected_shapes():
    result = {"model.embed_tokens.weight": [49152, 576], "model.norm.weight": [576]}
    for layer in range(30):
        prefix = f"model.layers.{layer}."
        for key, shape in {
            "input_layernorm.weight": [576],
            "post_attention_layernorm.weight": [576],
            "self_attn.q_proj.weight": [576, 576],
            "self_attn.k_proj.weight": [192, 576],
            "self_attn.v_proj.weight": [192, 576],
            "self_attn.o_proj.weight": [576, 576],
            "mlp.gate_proj.weight": [1536, 576],
            "mlp.up_proj.weight": [1536, 576],
            "mlp.down_proj.weight": [576, 1536],
        }.items():
            result[prefix + key] = shape
    return result


def validate_header(header, data_bytes):
    if not isinstance(header, dict) or header.get("__metadata__") != {"format": "pt"}:
        raise ValueError("checkpoint metadata")
    vocabulary = {name: item for name, item in header.items() if name != "__metadata__"}
    expected = expected_shapes()
    if set(vocabulary) != set(expected):
        raise ValueError("closed tensor vocabulary")
    intervals = []
    for name, shape in expected.items():
        item = vocabulary[name]
        if (
            not isinstance(item, dict)
            or set(item) != {"shape", "dtype", "data_offsets"}
            or item["dtype"] != "BF16"
            or item["shape"] != shape
            or any(type(x) is not int for x in item["shape"])
        ):
            raise ValueError("tensor dtype or shape")
        offsets = item["data_offsets"]
        if (
            not isinstance(offsets, list)
            or len(offsets) != 2
            or any(type(x) is not int for x in offsets)
        ):
            raise ValueError("tensor offsets")
        start, end = offsets
        if start < 0 or end > data_bytes or end - start != 2 * math.prod(shape):
            raise ValueError("tensor extent")
        intervals.append((start, end))
    cursor = 0
    for first, last in sorted(intervals):
        if first != cursor:
            raise ValueError("tensor overlap or gap")
        cursor = last
    if cursor != data_bytes:
        raise ValueError("unindexed checkpoint bytes")
    return vocabulary


def inspect_checkpoint(path):
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size != CHECKPOINT_BYTES
    ):
        raise ValueError("bounded regular checkpoint")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != CHECKPOINT_SHA256:
        raise ValueError("checkpoint pin")
    with path.open("rb") as source:
        header_size = int.from_bytes(source.read(8), "little")
        if not 2 <= header_size <= 65536:
            raise ValueError("header bound")
        header = json.loads(source.read(header_size), object_pairs_hook=unique)
    return validate_header(header, CHECKPOINT_BYTES - 8 - header_size)


def pinned_json(path, pin, limit):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("bounded support file")
    blob = path.read_bytes()
    if hashlib.sha256(blob).hexdigest() != pin:
        raise ValueError("support pin")
    return json.loads(blob, object_pairs_hook=unique)


def validate_config(config):
    expected = {
        "architectures": ["LlamaForCausalLM"],
        "model_type": "llama",
        "hidden_size": 576,
        "intermediate_size": 1536,
        "num_attention_heads": 9,
        "num_key_value_heads": 3,
        "num_hidden_layers": 30,
        "vocab_size": 49152,
        "rope_theta": 100000,
        "rope_scaling": None,
        "rms_norm_eps": 1e-5,
        "hidden_act": "silu",
        "tie_word_embeddings": True,
        "attention_bias": False,
        "mlp_bias": False,
        "rope_interleaved": False,
        "pretraining_tp": 1,
    }
    if any(config.get(key) != value for key, value in expected.items()):
        raise ValueError("unsupported Llama configuration")


class Footprint:
    """SDK-sized native sampler; its 5ms samples are not an independent peak."""

    def __init__(self, path):
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise ValueError("explicit owned SDK footprint library required")
        self.library = ctypes.CDLL(str(path))
        self.query = self.library.mcpmac_probe_self_footprint
        self.query.argtypes = [ctypes.POINTER(ctypes.c_uint64)]
        self.query.restype = ctypes.c_int
        self.stop = threading.Event()
        self.maximum = self.count = self.unknown = 0
        self.thread = threading.Thread(target=self.sample, daemon=True)

    def sample(self):
        while not self.stop.is_set():
            value = ctypes.c_uint64()
            if self.query(ctypes.byref(value)) == 0:
                self.count += 1
                self.maximum = max(self.maximum, value.value)
            else:
                self.unknown += 1
            self.stop.wait(0.005)

    def finish(self):
        self.stop.set()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError("sampler did not stop")
        return {
            "sampled_max_physical_footprint_bytes": self.maximum,
            "physical_footprint_samples": self.count,
            "physical_footprint_unknown_samples": self.unknown,
            "sampled_48MiB_cap_exceeded": self.maximum > 48 * 1024**2,
            "sampling_limit": "Self SDK TASK_VM_INFO5ms samples; not independent, complete child/cache accounting or guaranteed peak.",
        }


def execute(checkpoint, site):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("selected pinned MLX native arm64 runner required")
    if not site.is_absolute() or not site.is_dir() or site.is_symlink():
        raise ValueError("explicit owned MLX site required")
    wheel_file = site / "mcpmac-wheel-pins.json"
    if wheel_file.stat().st_size > 65536:
        raise ValueError("wheel provenance bound")
    provenance = json.loads(wheel_file.read_text())
    if {row.get("sha256") for row in provenance} != WHEELS:
        raise ValueError("pinned MLX wheel provenance")
    sys.path.insert(0, str(site))
    import mlx.core as mx

    mx.set_default_device(mx.cpu)
    weights = mx.load(str(checkpoint), format="safetensors")
    if set(weights) != set(expected_shapes()):
        raise ValueError("loaded tensor vocabulary")
    for name, shape in expected_shapes().items():
        if list(weights[name].shape) != shape or weights[name].dtype != mx.bfloat16:
            raise ValueError("loaded tensor shape/dtype")
    # Execute finite checks over the actual loaded tensors, not just metadata.
    for name, value in weights.items():
        if not bool(mx.all(mx.isfinite(value)).item()):
            raise ValueError("nonfinite trained weights: " + name)

    def norm(x, name):
        return (
            x
            * mx.rsqrt(mx.mean(x * x, axis=-1, keepdims=True) + 1e-5)
            * weights[name].astype(mx.float32)
        )

    def linear(x, name):
        return x @ weights[name].astype(mx.float32).T

    def rope(x):
        n = x.shape[-2]
        positions = mx.arange(n, dtype=mx.float32)
        inverse = mx.power(
            mx.array(100000.0, dtype=mx.float32),
            -mx.arange(0, 64, 2, dtype=mx.float32) / 64.0,
        )
        angles = positions[:, None] * inverse[None, :]
        cosine, sine = (
            mx.cos(angles)[None, None, :, :],
            mx.sin(angles)[None, None, :, :],
        )
        first, second = x[..., :32], x[..., 32:]
        return mx.concatenate(
            [first * cosine - second * sine, second * cosine + first * sine], axis=-1
        )

    # Independent scalar check of actual first-block RMSNorm and Q projection.
    embedding = weights["model.embed_tokens.weight"][PROMPT[0]].astype(mx.float32)
    norm_weight = weights["model.layers.0.input_layernorm.weight"].astype(mx.float32)
    query_weight = weights["model.layers.0.self_attn.q_proj.weight"].astype(mx.float32)
    values = embedding.tolist()
    gamma = norm_weight.tolist()
    inverse = 1 / math.sqrt(sum(x * x for x in values) / 576 + 1e-5)
    scalar = [x * inverse * g for x, g in zip(values, gamma)]
    normalized = norm(embedding, "model.layers.0.input_layernorm.weight")
    observed = linear(normalized, "model.layers.0.self_attn.q_proj.weight")[:8].tolist()
    expected = [
        sum(a * b for a, b in zip(scalar, row)) for row in query_weight[:8].tolist()
    ]
    projection_error = max(abs(a - b) for a, b in zip(observed, expected))
    if projection_error > 1e-4:
        raise ValueError("scalar first-block projection reference")

    def forward(ids):
        if not 1 <= len(ids) <= 8 or any(
            type(x) is not int or not 0 <= x < 49152 for x in ids
        ):
            raise ValueError("bounded token IDs")
        n = len(ids)
        x = weights["model.embed_tokens.weight"][mx.array(ids, dtype=mx.int32)].astype(
            mx.float32
        )[None, :, :]
        mask = mx.arange(n)[:, None] >= mx.arange(n)[None, :]
        for layer in range(30):
            p = f"model.layers.{layer}."
            z = norm(x, p + "input_layernorm.weight")
            q = (
                linear(z, p + "self_attn.q_proj.weight")
                .reshape(1, n, 9, 64)
                .transpose(0, 2, 1, 3)
            )
            k = (
                linear(z, p + "self_attn.k_proj.weight")
                .reshape(1, n, 3, 64)
                .transpose(0, 2, 1, 3)
            )
            v = (
                linear(z, p + "self_attn.v_proj.weight")
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
            x = x + linear(context, p + "self_attn.o_proj.weight")
            z = norm(x, p + "post_attention_layernorm.weight")
            gate = linear(z, p + "mlp.gate_proj.weight")
            z = (gate * mx.sigmoid(gate)) * linear(z, p + "mlp.up_proj.weight")
            x = x + linear(z, p + "mlp.down_proj.weight")
            mx.eval(x)  # Bound graph lifetime; not a secure-erasure claim.
        result = (
            norm(x, "model.norm.weight")
            @ weights["model.embed_tokens.weight"].astype(mx.float32).T
        )
        mx.eval(result)
        if not bool(mx.all(mx.isfinite(result)).item()):
            raise ValueError("nonfinite trained-model output")
        return result

    started = time.monotonic()
    full = forward(PROMPT)
    prefix = forward(PROMPT[:1])
    causal_error = float(mx.max(mx.abs(full[0, 0, :] - prefix[0, 0, :])).item())
    if causal_error > 2e-3:
        raise ValueError("future-token causal refusal failed")
    ids = list(PROMPT)
    generated = []
    summaries = []
    for step in range(2):
        logits = full if step == 0 else forward(ids)
        last = logits[0, -1, :]
        token = int(mx.argmax(last).item())
        generated.append(token)
        ids.append(token)
        summaries.append(
            {
                "generated_id": token,
                "winning_logit": float(last[token].item()),
                "min_logit": float(mx.min(last).item()),
                "max_logit": float(mx.max(last).item()),
            }
        )
    return {
        "status": "PASS_BOUNDED_TRAINED_GENERATOR",
        "trained_checkpoint_executed": True,
        "model_revision": REVISION,
        "checkpoint_sha256": CHECKPOINT_SHA256,
        "compute_device": "MLX CPU",
        "prompt_token_ids": PROMPT,
        "generated_token_ids": generated,
        "steps": summaries,
        "scalar_first_projection_max_error": projection_error,
        "causal_prefix_max_logit_error": causal_error,
        "elapsed_execution_seconds": time.monotonic() - started,
        "layers_executed_per_forward": 30,
        "full_model_gate_accepted": False,
        "resource_acceptance": False,
        "production_adapter_wired": False,
        "limitations": [
            "No KV cache or production tokenizer/chat-template adapter; at most8fixed token IDs and2greedy outputs.",
            "Scalar reference checks first-block projection; causal prefix test is structural. Full independent end-to-end reference and quality/calibration remain absent.",
            "No execution-class admission, interruption/erasure, installed or48MiB-cap acceptance.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--tokenizer", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--site", type=Path)
    parser.add_argument("--footprint-library", type=Path)
    args = parser.parse_args()
    vocabulary = inspect_checkpoint(args.checkpoint)
    validate_config(pinned_json(args.config, CONFIG_SHA256, 16384))
    tokenizer = pinned_json(args.tokenizer, TOKENIZER_SHA256, 3 * 1024**2)
    if tokenizer["model"]["type"] != "BPE" or any(
        tokenizer["model"]["vocab"].get(word) != token
        for word, token in [("<|im_start|>", 1), ("Hello", 19556), ("Ġworld", 905)]
    ):
        raise ValueError("fixed-token provenance")
    if not args.execute:
        print(
            json.dumps(
                {
                    "status": "PASS_PINNED_CHECKPOINT_INSPECTION",
                    "tensors": len(vocabulary),
                    "checkpoint_sha256": CHECKPOINT_SHA256,
                    "checkpoint_bytes": CHECKPOINT_BYTES,
                    "trained_checkpoint_executed": False,
                },
                indent=2,
            )
        )
        return
    if not args.site or not args.footprint_library:
        raise ValueError("explicit pinned site and SDK footprint library required")
    observer = Footprint(args.footprint_library.resolve())
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
    if record["status"] != "PASS_BOUNDED_TRAINED_GENERATOR":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
