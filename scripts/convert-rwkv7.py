#!/usr/bin/env python3
"""Convert the pinned RWKV-7 `.pth` checkpoint into an `mlx_rwkv7_v1` artifact.

The `.pth` is a zip holding a pickle (`data.pkl`) plus raw tensor storages.
Pickle is code, so it is never given to `pickle.load` with real globals:
`RestrictedUnpickler.find_class` maps exactly three names to inert local
stubs (an ordered dict, a tensor descriptor and a bf16 storage tag) and
refuses everything else. No torch import, no upstream code, no network.

Inputs are hash-pinned: the checkpoint (scripts/fetch-trained-model.py rwkv7)
and the RWKV World vocabulary `rwkv_vocab_v20230424.txt` from the `rwkv`
0.8.32 wheel. Vocabulary lines are Python literals; they are parsed with
`ast.literal_eval`, which evaluates literals only.

The artifact is one safetensors file: the upstream tensors unchanged (bf16,
upstream names) plus metadata:
  enclave_adapter.backend         = mlx_rwkv7_v1
  enclave_adapter.rwkv7.config    = closed config JSON
  enclave_adapter.tokenizer       = {"type":"rwkv_world_trie_v1","tokens":[hex...]}
                                    (index = id; id 0 is end-of-text, empty)

Usage: convert-rwkv7.py CHECKPOINT.pth VOCAB.txt OUTPUT.safetensors
"""

import ast
import hashlib
import io
import json
import pickle
import sys
import zipfile
from pathlib import Path

CHECKPOINT_SHA256 = "60c98129b9529963bff2c164b8ab4bd17c19332ae06dc2dcae32aa3a3739295a"
VOCAB_SHA256 = "8324476023347dec2964625ccb2075c864d250a9c6d9a74f36daba628de8c008"
MAX_PICKLE = 1 << 20


class Storage:
    """bf16 storage tag; holds only the zip entry key."""

    def __init__(self, key: str, numel: int):
        self.key, self.numel = key, numel


class TensorRef:
    """What `_rebuild_tensor_v2` would build, as plain data."""

    def __init__(self, storage, offset, size, stride, requires_grad, hooks, *rest):
        if (
            not isinstance(storage, Storage)
            or requires_grad
            or rest not in ((), (None,))
            or hooks != {}
        ):
            raise ValueError("unexpected tensor rebuild arguments")
        expected, step = [], 1
        for dim in reversed(size):
            expected.insert(0, step)
            step *= dim
        if list(stride) != expected and step > 1:
            raise ValueError("non-contiguous tensor refused")
        self.storage, self.offset, self.shape = storage, offset, list(size)
        self.numel = step


def bf16_storage_tag():
    raise ValueError("storage type is a tag, never called")


ALLOWED = {
    ("collections", "OrderedDict"): dict,
    ("torch._utils", "_rebuild_tensor_v2"): TensorRef,
    ("torch", "BFloat16Storage"): bf16_storage_tag,
}


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        try:
            return ALLOWED[(module, name)]
        except KeyError:
            raise pickle.UnpicklingError(f"refused global {module}.{name}") from None

    def persistent_load(self, pid):
        kind, storage_type, key, location, numel = pid
        if (
            kind != "storage"
            or storage_type is not bf16_storage_tag
            or location != "cpu"
        ):
            raise pickle.UnpicklingError("refused storage")
        return Storage(str(key), int(numel))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def read_tensors(checkpoint: Path):
    with zipfile.ZipFile(checkpoint) as archive:
        pickles = [n for n in archive.namelist() if n.endswith("/data.pkl")]
        if len(pickles) != 1:
            raise ValueError("expected one data.pkl")
        root = pickles[0][: -len("data.pkl")]
        if archive.read(root + "byteorder") != b"little":
            raise ValueError("big-endian checkpoint refused")
        info = archive.getinfo(pickles[0])
        if info.file_size > MAX_PICKLE:
            raise ValueError("pickle too large")
        state = RestrictedUnpickler(io.BytesIO(archive.read(info))).load()
        if not isinstance(state, dict) or not all(
            isinstance(v, TensorRef) for v in state.values()
        ):
            raise ValueError("expected a flat tensor dict")
        tensors = {}
        for name, ref in state.items():
            raw = archive.read(root + "data/" + ref.storage.key)
            if len(raw) != ref.storage.numel * 2:
                raise ValueError(f"{name}: storage length")
            start = ref.offset * 2
            end = start + ref.numel * 2
            if end > len(raw):
                raise ValueError(f"{name}: tensor exceeds storage")
            tensors[name] = (ref.shape, raw[start:end])
    return tensors


def read_vocab(path: Path):
    tokens = {0: b""}
    for line in path.read_text(encoding="utf-8").splitlines():
        idx = int(line[: line.index(" ")])
        literal = ast.literal_eval(line[line.index(" ") : line.rindex(" ")].strip())
        token = literal.encode("utf-8") if isinstance(literal, str) else literal
        if not isinstance(token, bytes) or len(token) != int(line[line.rindex(" ") :]):
            raise ValueError(f"vocab line {idx}")
        if idx in tokens:
            raise ValueError(f"duplicate id {idx}")
        tokens[idx] = token
    count = max(tokens) + 1
    if sorted(tokens) != list(range(count)):
        raise ValueError("vocab ids are not contiguous")
    return [tokens[i].hex() for i in range(count)]


def config_from(tensors):
    vocab, hidden = tensors["emb.weight"][0]
    heads, head_size = tensors["blocks.0.att.r_k"][0]
    layers = 1 + max(int(k.split(".")[1]) for k in tensors if k.startswith("blocks."))
    ffn = tensors["blocks.0.ffn.key.weight"][0][0]
    if heads * head_size != hidden:
        raise ValueError("head geometry")
    return {
        "hidden": hidden,
        "layers": layers,
        "heads": heads,
        "head_size": head_size,
        "ffn": ffn,
        "vocab": vocab,
    }


def main():
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    checkpoint, vocab_path, output = map(Path, sys.argv[1:])
    if sha256(checkpoint) != CHECKPOINT_SHA256:
        raise ValueError("checkpoint SHA256 mismatch")
    if sha256(vocab_path) != VOCAB_SHA256:
        raise ValueError("vocabulary SHA256 mismatch")
    tensors = read_tensors(checkpoint)
    config = config_from(tensors)
    vocab = read_vocab(vocab_path)
    if len(vocab) > config["vocab"]:
        raise ValueError("vocabulary larger than the embedding")
    header, offset = {}, 0
    for name in sorted(tensors):
        shape, raw = tensors[name]
        header[name] = {
            "dtype": "BF16",
            "shape": shape,
            "data_offsets": [offset, offset + len(raw)],
        }
        offset += len(raw)
    header["__metadata__"] = {
        "enclave_adapter.backend": "mlx_rwkv7_v1",
        "enclave_adapter.rwkv7.config": json.dumps(
            config, sort_keys=True, separators=(",", ":")
        ),
        "enclave_adapter.tokenizer": json.dumps(
            {"type": "rwkv_world_trie_v1", "tokens": vocab}, separators=(",", ":")
        ),
    }
    encoded = json.dumps(header, separators=(",", ":")).encode()
    encoded += b" " * (-len(encoded) % 8)
    with output.open("xb") as stream:
        stream.write(len(encoded).to_bytes(8, "little"))
        stream.write(encoded)
        for name in sorted(tensors):
            stream.write(tensors[name][1])
    print(
        json.dumps(
            {
                "status": "PASS_CONVERTED",
                "output": str(output),
                "sha256": sha256(output),
                "tensors": len(tensors),
                "config": config,
                "vocab_tokens": len(vocab),
                "executed_pickle_code": False,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
