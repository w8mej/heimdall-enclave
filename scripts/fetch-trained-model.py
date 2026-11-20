#!/usr/bin/env python3
"""Fetch/verify only the selected immutable, hash-pinned model artifacts.

Bytes are downloaded and verified only: no upstream executable code, no
unpickling, no dependency installation and no model execution. The RWKV-7
checkpoint is a `.pth` (zip + pickle); it is converted separately by
scripts/convert-rwkv7.py, which never runs pickled code.
Existing failed partials are preserved. All output stays in this repo's target/.
"""

import argparse
import hashlib
import json
import shutil
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODELS = {
    "bert": (
        "google/bert_uncased_L-2_H-128_A-2",
        "30b0a37ccaaa32f332884b96992754e246e48c5f",
        17739144,
        "7fb69ad9f6866d8983183c930e33828f326470bf6ad8bbb2ad4ed957a92e9414",
        "phase4-trained-bert",
    ),
    "smollm2": (
        "HuggingFaceTB/SmolLM2-135M-Instruct",
        "12fd25f77366fa6b3b4b768ec3050bf629380bac",
        269060552,
        "5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c",
        "phase4-trained-mlx",
    ),
    "smolvlm": (
        "HuggingFaceTB/SmolVLM-256M-Instruct",
        "d039ab0d4b9311b617e8ffec1d06c8464364aeb3",
        513028808,
        "74dea5904032e5ae99a2e0eef5179e6ac0f1dedc3ab0c7c2a5d4d387c843203e",
        "phase4-trained-smolvlm",
    ),
    "rwkv7": (
        "BlinkDL/rwkv-7-world",
        "2c0ebae3b3a784e690e3d46bf545ecf44deceb10",
        382195690,
        "60c98129b9529963bff2c164b8ab4bd17c19332ae06dc2dcae32aa3a3739295a",
        "rwkv7-0.1b",
        "RWKV-x070-World-0.1B-v2.8-20241210-ctx4096.pth",
    ),
    "qwen3": (
        "Qwen/Qwen3-0.6B",
        "c1899de289a04d12100db370d81485cdf75e47ca",
        1503300328,
        "f47f71177f32bcd101b7573ec9171e6a57f4f4d31148d38e382306f42996874b",
        "qwen3-0.6b",
    ),
    "eagle3": (
        "GavinLucky/SGLang-EAGLE3-Qwen3-0.6B-SpecForge",
        "5fe9c43a50078119bfa38e5f30969475be314315",
        112090960,
        "cd1b033ea6e147b00c5089ece598a43f8dca186252a270c59dfa19778c57c60c",
        "eagle3-qwen3-0.6b",
    ),
    "vjepa2": (
        "facebook/vjepa2-vitl-fpc64-256",
        "b3c1679b7c34d3255ef3547f27c7b226aefab26f",
        1303947864,
        "25466aef85727d16546c6cf8c99f12fcfad9cbca8225d45f23685e2e025b786b",
        "vjepa2-vitl",
    ),
    # Primary entry is shard 1; the remaining shards are in SHARDS.
    "llada": (
        "GSAI-ML/LLaDA-8B-Instruct",
        "08b83a6feb34df1a6011b80c3c00c7563e963b07",
        2109747184,
        "ff6699df9635a267fb4ac801ea8012d39b21bb22ed290d5a57128521b889c230",
        "llada-8b-instruct",
        "model-00001-of-00006.safetensors",
    ),
}
# Further weight shards of a sharded checkpoint: (name, length, sha256).
SHARDS = {
    "llada": [
        (
            "model-00002-of-00006.safetensors",
            2948598128,
            "b8ddf571b47f57ce654913877f3625d2c7b9a4c3f81cb6f41f6c3055473b0281",
        ),
        (
            "model-00003-of-00006.safetensors",
            2986883656,
            "8347db2fd61a3b5bad2970c2f83ecb84b93632e276a41ca169dcc5efae15462c",
        ),
        (
            "model-00004-of-00006.safetensors",
            2952797224,
            "93d8706872e7432d5cd40c9a61f9f9d270c101828cef2adaf27c67743d3dcf1a",
        ),
        (
            "model-00005-of-00006.safetensors",
            2919239128,
            "ff5f765eb7ec8bfdbe3b962a9e920d71de43d55e04eb4844710c0efcc8855092",
        ),
        (
            "model-00006-of-00006.safetensors",
            2113931792,
            "f25d4cc57b24a79a840d49c3b25d9a22dd5caf3a9766f591e4625377901194e2",
        ),
    ],
}
# Small companion files fetched next to the weights: (name, length, sha256).
EXTRAS = {
    "qwen3": [
        (
            "config.json",
            726,
            "660db3b73d788119c04535e48cf9be5f55bc3100841a718637ae695b442f27dd",
        ),
        (
            "tokenizer.json",
            11422654,
            "aeb13307a71acd8fe81861d94ad54ab689df773318809eed3cbe794b4492dae4",
        ),
    ],
    "eagle3": [
        (
            "config.json",
            800,
            "594b3e76df85edef549a73673a9e3fb11730290cccc218c44c027175bb5c1f5e",
        )
    ],
    "vjepa2": [
        (
            "config.json",
            785,
            "3dec96fe962e94e569182d3a7b9ef0dd74b6b8c89c337a428e43e10d593e70c9",
        )
    ],
    "llada": [
        (
            "config.json",
            1385,
            "5f99fefe855fdb5100bb6cadb57bdb09fae723ad54811f95c00ecacf29d58a6a",
        ),
        (
            "tokenizer.json",
            6098988,
            "071eb20fe7bd601550b1b7838ff696d6c93b88f51257f753303d3df23163c381",
        ),
        (
            "tokenizer_config.json",
            51692,
            "b9a6102c39a4f42f47f0d63fc6cee58a2381199d90f2a4f39b3f6871f32b4119",
        ),
        (
            "special_tokens_map.json",
            747,
            "e9f1f0f6fa133da3169ae69b1969c51cced047a900050893d7a0711c6bd063aa",
        ),
        (
            "generation_config.json",
            128,
            "00b3d1ffda2ca0a45633deb52ca4413dda046e7c94e9b05b73ed4a565b0677b3",
        ),
        (
            "model.safetensors.index.json",
            24941,
            "28b4ec27206e42e7ade630450e6ce618bd197acf34d35120e8e86d2bb910a408",
        ),
    ],
}
FLOOR = 4 * 1024**3
# Download deadline: 600 s, or the time at 2 MiB/s for larger files.
MIN_DEADLINE_S = 600
MIN_RATE = 2 * 1024**2


def inspect(path, length, pin):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != length:
        raise ValueError("expected bounded regular artifact")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    if digest.hexdigest() != pin:
        raise ValueError("artifact SHA256 mismatch")


def fetch_small(model, revision, folder, name, length, pin, offline):
    path = ROOT / "target" / folder / name
    if not path.exists():
        if offline:
            raise ValueError(f"offline {name} missing")
        url = f"https://huggingface.co/{model}/resolve/{revision}/{name}"
        if not url.startswith("https://"):
            raise ValueError(f"unsupported URL scheme: {url}")
        with urllib.request.urlopen(
            url, timeout=45
        ) as response:  # nosec B310: scheme verified https:// above
            data = response.read(length + 1)
        if len(data) != length or hashlib.sha256(data).hexdigest() != pin:
            raise ValueError(f"{name} integrity mismatch")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
    inspect(path, length, pin)
    return str(path.relative_to(ROOT))


def fetch_large(model, revision, path, length, pin, offline):
    """Download one pinned weight file with a bounded deadline and disk reserve."""
    url = f"https://huggingface.co/{model}/resolve/{revision}/{path.name}"
    if path.is_symlink():
        raise ValueError("symlink artifact refused")
    if not path.exists():
        if offline:
            raise ValueError("offline artifact missing")
        if shutil.disk_usage(ROOT).free < FLOOR + length + 100 * 1024**2:
            raise RuntimeError(
                "4GiB reserve plus artifact and100MiB allowance unavailable"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        partial = path.with_suffix(".partial")
        if partial.exists():
            raise ValueError("prior partial preserved; select a fresh output")
        deadline = max(MIN_DEADLINE_S, length / MIN_RATE)
        started = time.monotonic()
        digest, total = hashlib.sha256(), 0
        if not url.startswith("https://"):
            raise ValueError(f"unsupported URL scheme: {url}")
        with urllib.request.urlopen(
            url, timeout=45
        ) as response, partial.open(  # nosec B310: scheme verified https:// above
            "xb"
        ) as stream:
            while block := response.read(1024 * 1024):
                if time.monotonic() - started > deadline:
                    raise TimeoutError("bounded download deadline")
                if total + len(block) > length:
                    raise ValueError("download length exceeds pin")
                if shutil.disk_usage(ROOT).free < FLOOR + len(block):
                    raise RuntimeError("4GiB reserve")
                total += len(block)
                digest.update(block)
                stream.write(block)
        if total != length or digest.hexdigest() != pin:
            raise ValueError("download integrity mismatch; partial preserved")
        partial.rename(path)
    inspect(path, length, pin)
    return url


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", choices=MODELS)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--offline", action="store_true", help="Verify existing bytes without network"
    )
    args = parser.parse_args()
    model, revision, length, pin, folder, *named = MODELS[args.model]
    filename = named[0] if named else "model.safetensors"
    path = (args.output or ROOT / "target" / folder / filename).absolute()
    path.parent.resolve().relative_to(ROOT / "target")
    started = time.monotonic()
    url = fetch_large(model, revision, path, length, pin, args.offline)
    shards = []
    for name, shard_length, shard_pin in SHARDS.get(args.model, []):
        fetch_large(
            model, revision, path.parent / name, shard_length, shard_pin, args.offline
        )
        shards.append(str((path.parent / name).relative_to(ROOT)))
    extras = [
        fetch_small(model, revision, folder, *extra, args.offline)
        for extra in EXTRAS.get(args.model, [])
    ]
    print(
        json.dumps(
            {
                "status": "PASS_BYTE_VERIFIED",
                "model": model,
                "revision": revision,
                "extras": extras,
                "shards": shards,
                "url": url,
                "path": str(path.relative_to(ROOT)),
                "bytes": length,
                "sha256": pin,
                "executed_model": False,
                "elapsed_seconds": time.monotonic() - started,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
