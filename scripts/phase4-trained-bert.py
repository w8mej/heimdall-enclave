#!/usr/bin/env python3
"""Prepare one pinned, trained BERT encoder for a standalone CPU CoreML probe.

Standard library only; never imports upstream model code, pickle or conversion
frameworks. This is NOT production adapter admission, calibration, arbitrary
tokenization, a resource-policy waiver or erasure/installed acceptance.
"""

import argparse
import hashlib
import json
import math
import shutil
import struct
import sys
import time
import urllib.request
from array import array
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_REVISION = "30b0a37ccaaa32f332884b96992754e246e48c5f"
MODEL_SHA256 = "7fb69ad9f6866d8983183c930e33828f326470bf6ad8bbb2ad4ed957a92e9414"
MODEL_BYTES = 17739144
MODEL_URL = (
    "https://huggingface.co/google/bert_uncased_L-2_H-128_A-2/resolve/"
    + MODEL_REVISION
    + "/model.safetensors"
)
SUPPORT = (
    ROOT / "docs/remediation/phase1-20261113/evidence/closure/"
    "model-selection/google--bert_uncased_L-2_H-128_A-2"
)
SUPPORT_PINS = {
    "config.json": "508e1f01aae55d73355cbdd82609be2f43ba5a0d3428837adbe56cf8391f8b39",
    "vocab.txt": "07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3",
}
SEQUENCE = 8
WIDTH = 128
RESERVE = 4 * 1024**3


def pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def shapes():
    result = {
        "bert.embeddings.word_embeddings.weight": [30522, 128],
        "bert.embeddings.position_embeddings.weight": [512, 128],
        "bert.embeddings.token_type_embeddings.weight": [2, 128],
        "bert.embeddings.LayerNorm.weight": [128],
        "bert.embeddings.LayerNorm.bias": [128],
        "bert.pooler.dense.weight": [128, 128],
        "bert.pooler.dense.bias": [128],
        "cls.predictions.bias": [30522],
        "cls.predictions.transform.dense.weight": [128, 128],
        "cls.predictions.transform.dense.bias": [128],
        "cls.predictions.transform.LayerNorm.weight": [128],
        "cls.predictions.transform.LayerNorm.bias": [128],
        "cls.seq_relationship.weight": [2, 128],
        "cls.seq_relationship.bias": [2],
    }
    for i in range(2):
        prefix = f"bert.encoder.layer.{i}."
        for suffix, shape in {
            "attention.self.query.weight": [128, 128],
            "attention.self.key.weight": [128, 128],
            "attention.self.value.weight": [128, 128],
            "attention.output.dense.weight": [128, 128],
            "intermediate.dense.weight": [512, 128],
            "output.dense.weight": [128, 512],
            "attention.self.query.bias": [128],
            "attention.self.key.bias": [128],
            "attention.self.value.bias": [128],
            "attention.output.dense.bias": [128],
            "intermediate.dense.bias": [512],
            "output.dense.bias": [128],
            "attention.output.LayerNorm.weight": [128],
            "attention.output.LayerNorm.bias": [128],
            "output.LayerNorm.weight": [128],
            "output.LayerNorm.bias": [128],
        }.items():
            result[prefix + suffix] = shape
    return result


def load_tensors(blob, *, verify_pin=True):
    if len(blob) > MODEL_BYTES or len(blob) < 10:
        raise ValueError("checkpoint size")
    if verify_pin and (
        len(blob) != MODEL_BYTES or hashlib.sha256(blob).hexdigest() != MODEL_SHA256
    ):
        raise ValueError("checkpoint pin")
    size = int.from_bytes(blob[:8], "little")
    if size < 2 or size > 65536 or size > len(blob) - 8:
        raise ValueError("header bound")
    header = json.loads(blob[8 : 8 + size], object_pairs_hook=pairs_unique)
    if not isinstance(header, dict):
        raise ValueError("header object")
    metadata = header.pop("__metadata__", {})
    if metadata != {
        "cls.predictions.decoder.weight": "bert.embeddings.word_embeddings.weight",
        "format": "pt",
        "cls.predictions.decoder.bias": "cls.predictions.bias",
    }:
        raise ValueError("checkpoint metadata")
    expected = shapes()
    if set(header) != set(expected):
        raise ValueError("checkpoint tensor vocabulary")
    intervals, tensors = [], {}
    for name, shape in expected.items():
        item = header[name]
        if not isinstance(item, dict) or set(item) != {
            "shape",
            "dtype",
            "data_offsets",
        }:
            raise ValueError("tensor fields")
        offsets = item["data_offsets"]
        if (
            item["dtype"] != "F32"
            or item["shape"] != shape
            or any(type(x) is not int for x in item["shape"])
            or not isinstance(offsets, list)
            or len(offsets) != 2
            or any(type(x) is not int for x in offsets)
        ):
            raise ValueError("tensor shape/dtype/offset type")
        first, last = offsets
        if (
            first < 0
            or last - first != math.prod(shape) * 4
            or last > len(blob) - 8 - size
        ):
            raise ValueError("tensor offsets")
        intervals.append((first, last))
        values = array("f")
        values.frombytes(blob[8 + size + first : 8 + size + last])
        if sys.byteorder != "little":
            values.byteswap()
        if any(not math.isfinite(x) for x in values):
            raise ValueError("nonfinite tensor")
        tensors[name] = values
    cursor = 0
    for first, last in sorted(intervals):
        if first != cursor:
            raise ValueError("noncontiguous/overlapping tensor")
        cursor = last
    if cursor != len(blob) - 8 - size:
        raise ValueError("unindexed tensor bytes")
    return tensors


def varint(value):
    if type(value) is not int or value < 0:
        raise ValueError("nonnegative integer required")
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def integer(field, value):
    return varint(field << 3) + varint(value)


def data(field, value):
    if isinstance(value, str):
        value = value.encode("ascii")
    return varint((field << 3) | 2) + varint(len(value)) + value


def dimensions(field, values):
    return b"".join(integer(field, value) for value in values)


def floats(values):
    result = array("f", values)
    if sys.byteorder != "little":
        result.byteswap()
    return data(1, result.tobytes())  # WeightParams.floatValue, packed float32.


def feature(name, shape):
    kind = dimensions(1, shape) + integer(2, 65568)  # FLOAT32.
    return data(1, name) + data(3, data(5, kind))


class Graph:
    # Field identities verified against pinned CoreML8.3 schema provenance.
    OPS = {
        "embeddingND": 1040,
        "loadConstantND": 1070,
        "addBroadcastable": 880,
        "layerNormalization": 1350,
        "batchedMatmul": 1045,
        "reshapeStatic": 1140,
        "transpose": 985,
        "multiplyBroadcastable": 900,
        "softmaxND": 950,
        "gelu": 795,
    }

    def __init__(self, tensors):
        self.tensors = tensors
        self.layers = []
        self.observations = []

    def add(self, name, inputs, op, parameters):
        if any(row["name"] == name for row in self.observations):
            raise ValueError("duplicate layer")
        layer = data(1, name) + b"".join(data(2, x) for x in inputs) + data(3, name)
        self.layers.append(layer + data(self.OPS[op], parameters))
        self.observations.append({"name": name, "protobuf_op": op})
        return name

    def constant(self, name, shape, values):
        return self.add(
            name, [], "loadConstantND", dimensions(1, shape) + data(2, floats(values))
        )

    def linear(self, name, x, parameter):
        weight_shape = shapes()[parameter + ".weight"]
        output, width = weight_shape
        # BERT row-major [output,input] equals the CoreML [input,output]
        # matrix's documented column-major serialization, without transposition.
        params = (
            integer(5, width)
            + integer(6, output)
            + integer(7, 1)
            + data(8, floats(self.tensors[parameter + ".weight"]))
            + data(9, floats(self.tensors[parameter + ".bias"]))
        )
        return self.add(name, [x], "batchedMatmul", params)

    def norm(self, name, x, parameter):
        params = (
            integer(1, WIDTH)
            + varint((2 << 3) | 5)
            + struct.pack("<f", 1e-12)
            + data(3, floats(self.tensors[parameter + ".weight"]))
            + data(4, floats(self.tensors[parameter + ".bias"]))
        )
        return self.add(name, [x], "layerNormalization", params)

    def build(self):
        word = self.tensors["bert.embeddings.word_embeddings.weight"]
        # EmbeddingND stores [embeddingSize,vocabSize], unlike BERT [vocabSize,width].
        transposed = array("f")
        for channel in range(WIDTH):
            transposed.extend(word[channel::WIDTH])
        embedded = self.add(
            "token_embedding",
            ["tokens"],
            "embeddingND",
            integer(1, 30522) + integer(2, WIDTH) + data(20, floats(transposed)),
        )
        position = self.tensors["bert.embeddings.position_embeddings.weight"]
        types = self.tensors["bert.embeddings.token_type_embeddings.weight"]
        offsets = self.constant(
            "position_and_type0",
            [SEQUENCE, WIDTH],
            [position[i] + types[i % WIDTH] for i in range(SEQUENCE * WIDTH)],
        )
        x = self.add("embedding_sum", [embedded, offsets], "addBroadcastable", b"")
        x = self.norm("embedding_norm", x, "bert.embeddings.LayerNorm")
        scale = self.constant("attention_scale", [1], [1 / math.sqrt(64)])
        for layer in range(2):
            prefix = f"bert.encoder.layer.{layer}."
            label = f"block{layer}_"
            heads = {}
            for qkv in ["query", "key", "value"]:
                v = self.linear(label + qkv, x, prefix + "attention.self." + qkv)
                v = self.add(
                    label + qkv + "_reshape",
                    [v],
                    "reshapeStatic",
                    dimensions(1, [SEQUENCE, 2, 64]),
                )
                heads[qkv] = self.add(
                    label + qkv + "_heads", [v], "transpose", dimensions(1, [1, 0, 2])
                )
            scores = self.add(
                label + "scores",
                [heads["query"], heads["key"]],
                "batchedMatmul",
                integer(2, 1),
            )
            scores = self.add(
                label + "scaled_scores", [scores, scale], "multiplyBroadcastable", b""
            )
            probabilities = self.add(
                label + "probabilities", [scores], "softmaxND", integer(1, 2)
            )
            context = self.add(
                label + "context", [probabilities, heads["value"]], "batchedMatmul", b""
            )
            context = self.add(
                label + "context_transpose",
                [context],
                "transpose",
                dimensions(1, [1, 0, 2]),
            )
            context = self.add(
                label + "context_flat",
                [context],
                "reshapeStatic",
                dimensions(1, [SEQUENCE, WIDTH]),
            )
            attention = self.linear(
                label + "attention_out", context, prefix + "attention.output.dense"
            )
            residual = self.add(
                label + "attention_residual", [x, attention], "addBroadcastable", b""
            )
            normalized = self.norm(
                label + "attention_norm",
                residual,
                prefix + "attention.output.LayerNorm",
            )
            intermediate = self.linear(
                label + "intermediate", normalized, prefix + "intermediate.dense"
            )
            activated = self.add(
                label + "exact_gelu", [intermediate], "gelu", integer(1, 0)
            )
            output = self.linear(label + "output", activated, prefix + "output.dense")
            residual = self.add(
                label + "output_residual", [normalized, output], "addBroadcastable", b""
            )
            x = self.norm(label + "output_norm", residual, prefix + "output.LayerNorm")
        description = data(1, feature("tokens", [SEQUENCE, 1])) + data(
            10, feature(x, [SEQUENCE, WIDTH])
        )
        network = b"".join(data(1, layer) for layer in self.layers) + integer(5, 1)
        return integer(1, 4) + data(2, description) + data(500, network), x


def reference(tensors, token_ids):
    if len(token_ids) != SEQUENCE or any(
        type(x) is not int or not 0 <= x < 30522 for x in token_ids
    ):
        raise ValueError("exactly eight valid token IDs required")

    def linear(rows, prefix):
        output, width = shapes()[prefix + ".weight"]
        weight, bias = tensors[prefix + ".weight"], tensors[prefix + ".bias"]
        columns = [weight[i * width : (i + 1) * width] for i in range(output)]
        return [
            [
                sum(a * b for a, b in zip(row, column)) + bias[i]
                for i, column in enumerate(columns)
            ]
            for row in rows
        ]

    def norm(rows, prefix):
        gamma, beta = tensors[prefix + ".weight"], tensors[prefix + ".bias"]
        result = []
        for row in rows:
            mean = sum(row) / WIDTH
            inverse = 1 / math.sqrt(sum((x - mean) ** 2 for x in row) / WIDTH + 1e-12)
            result.append(
                [(x - mean) * inverse * g + b for x, g, b in zip(row, gamma, beta)]
            )
        return result

    def add(a, b):
        return [[x + y for x, y in zip(u, v)] for u, v in zip(a, b)]

    word = tensors["bert.embeddings.word_embeddings.weight"]
    position = tensors["bert.embeddings.position_embeddings.weight"]
    types = tensors["bert.embeddings.token_type_embeddings.weight"]
    x = [
        [
            word[token * WIDTH + j] + position[i * WIDTH + j] + types[j]
            for j in range(WIDTH)
        ]
        for i, token in enumerate(token_ids)
    ]
    x = norm(x, "bert.embeddings.LayerNorm")
    for layer in range(2):
        p = f"bert.encoder.layer.{layer}."
        q, k, v = [
            linear(x, p + "attention.self." + name)
            for name in ["query", "key", "value"]
        ]
        contexts = [[] for _ in token_ids]
        for head in range(2):
            lo, hi = head * 64, (head + 1) * 64
            for row, query in enumerate(q):
                scores = [
                    sum(a * b for a, b in zip(query[lo:hi], key[lo:hi])) / 8
                    for key in k
                ]
                maximum = max(scores)
                probabilities = [math.exp(score - maximum) for score in scores]
                denominator = sum(probabilities)
                probabilities = [score / denominator for score in probabilities]
                contexts[row].extend(
                    sum(probabilities[j] * v[j][c] for j in range(SEQUENCE))
                    for c in range(lo, hi)
                )
        attention = norm(
            add(x, linear(contexts, p + "attention.output.dense")),
            p + "attention.output.LayerNorm",
        )
        intermediate = linear(attention, p + "intermediate.dense")
        activated = [
            [0.5 * value * (1 + math.erf(value / math.sqrt(2))) for value in row]
            for row in intermediate
        ]
        x = norm(
            add(attention, linear(activated, p + "output.dense")),
            p + "output.LayerNorm",
        )
    if any(not math.isfinite(value) for row in x for value in row):
        raise ValueError("nonfinite reference")
    return [value for row in x for value in row]


def reserve(extra=0):
    if shutil.disk_usage(ROOT).free < RESERVE + extra:
        raise RuntimeError("less than 4GiB reserve plus bounded artifact allowance")


def fetch(path):
    reserve(MODEL_BYTES + 40 * 1024**2)
    if path.exists():
        return
    temporary = path.with_suffix(".partial")
    if temporary.exists():
        raise ValueError(
            "prior partial artifact preserved; choose a fresh output directory"
        )
    digest, total = hashlib.sha256(), 0
    if not MODEL_URL.startswith("https://"):
        raise ValueError(f"unsupported URL scheme: {MODEL_URL}")
    with urllib.request.urlopen(
        MODEL_URL, timeout=45
    ) as response, temporary.open(  # nosec B310: scheme verified https:// above
        "xb"
    ) as output:
        while block := response.read(1024 * 1024):
            total += len(block)
            if total > MODEL_BYTES:
                raise ValueError("oversized artifact")
            digest.update(block)
            output.write(block)
    if total != MODEL_BYTES or digest.hexdigest() != MODEL_SHA256:
        raise ValueError("download pin mismatch; partial artifact retained")
    temporary.rename(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "target/phase4-trained-bert"
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Fetch only the immutable pinned safetensors artifact",
    )
    args = parser.parse_args()
    directory = args.output.resolve()
    directory.relative_to(ROOT / "target")
    reserve(60 * 1024**2)
    directory.mkdir(parents=True, exist_ok=True)
    checkpoint = directory / "model.safetensors"
    if args.fetch:
        fetch(checkpoint)
    if (
        checkpoint.is_symlink()
        or not checkpoint.is_file()
        or checkpoint.stat().st_size != MODEL_BYTES
    ):
        raise ValueError("expected bounded regular pinned checkpoint")
    started = time.monotonic()
    tensors = load_tensors(checkpoint.read_bytes())
    for name, pin in SUPPORT_PINS.items():
        if hashlib.sha256((SUPPORT / name).read_bytes()).hexdigest() != pin:
            raise ValueError("support-file pin")
    config = json.loads((SUPPORT / "config.json").read_text())
    for key, expected in {
        "hidden_size": 128,
        "intermediate_size": 512,
        "num_attention_heads": 2,
        "num_hidden_layers": 2,
        "hidden_act": "gelu",
        "layer_norm_eps": 1e-12,
        "vocab_size": 30522,
        "type_vocab_size": 2,
        "max_position_embeddings": 512,
    }.items():
        if config.get(key) != expected:
            raise ValueError("unsupported configuration")
    vocab = (SUPPORT / "vocab.txt").read_text().splitlines()
    if len(vocab) != 30522 or len(set(vocab)) != len(vocab):
        raise ValueError("vocabulary shape")
    graph = Graph(tensors)
    model, output_name = graph.build()
    model_path = directory / "bert8.mlmodel"
    model_path.write_bytes(model)
    cases = []
    for words in [
        ["[CLS]", "the", "cat", "sat", "on", "the", "mat", "[SEP]"],
        ["[CLS]", "a", "dog", "ran", "to", "the", "park", "[SEP]"],
    ]:
        ids = [vocab.index(word) for word in words]
        cases.append(
            {"wordpieces": words, "token_ids": ids, "expected": reference(tensors, ids)}
        )
    if (
        max(abs(a - b) for a, b in zip(cases[0]["expected"], cases[1]["expected"]))
        < 1e-3
    ):
        raise ValueError("reference did not distinguish inputs")
    record = {
        "schema": 1,
        "model_revision": MODEL_REVISION,
        "checkpoint_sha256": MODEL_SHA256,
        "checkpoint_bytes": MODEL_BYTES,
        "checkpoint_independently_byte_verified": True,
        "model_sha256": hashlib.sha256(model).hexdigest(),
        "model_bytes": len(model),
        "sequence": SEQUENCE,
        "width": WIDTH,
        "output_name": output_name,
        "layers": graph.observations,
        "cases": cases,
        "absolute_tolerance": 2e-3,
        "relative_tolerance": 2e-3,
        "preparation_seconds": time.monotonic() - started,
        "support_sha256": {
            n: hashlib.sha256((SUPPORT / n).read_bytes()).hexdigest()
            for n in ["config.json", "vocab.txt"]
        },
        "limitations": [
            "Fixed8token encoder only; segment0, all-token attention, dropout disabled.",
            "Explicit wordpieces; general tokenizer, pooled/MLM/NSP heads and calibration not exported.",
            "Unused pretrained pooler/head tensors verified but not used by this encoder.",
            "Scalar reference uses float64 arithmetic; CoreML float32 tolerance is explicit.",
            "Standalone development probe; no production adapter, class admission, resource or erasure acceptance.",
        ],
    }
    (directory / "probe.json").write_text(
        json.dumps(record, indent=2, allow_nan=False) + "\n"
    )
    print(
        json.dumps(
            {k: v for k, v in record.items() if k not in {"cases", "layers"}}, indent=2
        )
    )


if __name__ == "__main__":
    main()
