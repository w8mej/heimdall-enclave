"""Record golden RWKV-7 outputs with the independent `rwkv` 0.8.32 reference.

Usage: golden-rwkv7.py RWKV_PKG_DIR CHECKPOINT.pth ARTIFACT.safetensors OUT.json
  RWKV_PKG_DIR  the `rwkv/` package directory extracted from the pinned wheel
                rwkv-0.8.32-py3-none-any.whl (sha256 d3f05948...67c1)

Checks first that torch's own restricted loader (`weights_only=True`) reads
the upstream `.pth` to exactly the tensors in the converted artifact, then
runs the reference `RWKV_x070` on CPU in float32 over the artifact's tensors
(its `torch.load` is redirected to them) and its TRIE_TOKENIZER.
"""

import hashlib
import json
import os
import sys

os.environ.update(RWKV_V7_ON="1", RWKV_JIT_ON="1", RWKV_CUDA_ON="0")
import torch  # noqa: E402
from safetensors.torch import load_file  # noqa: E402

pkg, checkpoint, artifact, out = sys.argv[1:5]
WHEEL_FILES = {
    "model.py": None,
    "rwkv_tokenizer.py": None,
    "rwkv_vocab_v20230424.txt": "8324476023347dec2964625ccb2075c864d250a9c6d9a74f36daba628de8c008",
}


def digest(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


for name, pin in WHEEL_FILES.items():
    if pin and digest(os.path.join(pkg, name)) != pin:
        raise SystemExit(f"{name} drifted")

converted = load_file(artifact)
upstream = torch.load(checkpoint, map_location="cpu", weights_only=True, mmap=True)
assert sorted(upstream) == sorted(converted), "tensor names differ"
for name, tensor in upstream.items():
    assert tensor.dtype == converted[name].dtype and torch.equal(
        tensor, converted[name]
    ), name
del upstream

sys.path.insert(0, os.path.dirname(os.path.abspath(pkg)))
import rwkv.model as reference  # noqa: E402
from rwkv.rwkv_tokenizer import TRIE_TOKENIZER  # noqa: E402

real_load = torch.load
torch.load = lambda path, *a, **k: (
    dict(converted) if path == "converted.pth" else real_load(path, *a, **k)
)
model = reference.RWKV(model="converted", strategy="cpu fp32")
torch.load = real_load
tok = TRIE_TOKENIZER(os.path.join(pkg, "rwkv_vocab_v20230424.txt"))

texts = [
    "Hello world",
    "hello",
    " Hello, world!",
    "The quick brown fox jumps over the lazy dog.",
    '{"priority":"urgent"}',
    "naïve café — 東京 🚀",
    "  leading spaces\n\nand\ttabs",
    "1234567890 3.14159",
    "",
    "\x00\x01 control",
    "User: hi\n\nAssistant:",
]
tokenizer_cases = [{"text": t, "ids": tok.encode(t)} for t in texts]
prompts = {
    "capital": "The capital of France is",
    "chat_ticket": "User: Classify the support ticket priority as routine, important, urgent or critical."
    " Ticket: Production database is down and customers cannot log in.\n\nAssistant:",
}


def state_summary(state, layers):
    rows = []
    for i in range(layers):
        att_x, kv, ffn_x = state[i * 3], state[i * 3 + 1], state[i * 3 + 2]
        rows.append(
            {
                "layer": i,
                "att_x_prev_head": [round(v, 6) for v in att_x[:4].tolist()],
                "kv_flat_head": [round(v, 6) for v in kv.flatten()[:4].tolist()],
                "kv_sum": round(float(kv.sum()), 4),
                "ffn_x_prev_sum": round(float(ffn_x.sum()), 4),
            }
        )
    return rows


logit_cases, greedy_cases = [], []
with torch.no_grad():
    for name, text in prompts.items():
        ids = tok.encode(text)
        seq_logits, seq_state = model.forward(ids, None)
        one_logits = None
        state = None
        for t in ids:
            one_logits, state = model.forward([t], state)
        assert one_logits is not None, name
        assert torch.allclose(seq_logits, one_logits, atol=2e-3), name
        top = torch.topk(one_logits, 10)
        logit_cases.append(
            {
                "name": name,
                "text": text,
                "ids": ids,
                "last_top10_ids": top.indices.tolist(),
                "last_top10_logits": [round(v, 5) for v in top.values.tolist()],
                "state": state_summary(state, model.n_layer),
            }
        )
        new, logits = [], one_logits
        for _ in range(24):
            t = int(torch.argmax(logits))
            if t == 0:
                break
            new.append(t)
            logits, state = model.forward([t], state)
        greedy_cases.append(
            {
                "name": name,
                "ids": ids,
                "greedy_new_ids": new,
                "greedy_text": tok.decode(new),
            }
        )

json.dump(
    {
        "schema": 1,
        "producer": "rwkv 0.8.32 RWKV_x070 cpu fp32 TorchScript (independent reference)",
        "torch": torch.__version__,
        "checkpoint": {
            "repo": "BlinkDL/rwkv-7-world",
            "revision": "2c0ebae3b3a784e690e3d46bf545ecf44deceb10",
            "file": os.path.basename(checkpoint),
            "sha256": digest(checkpoint),
        },
        "artifact_sha256": digest(artifact),
        "conversion_matches_torch_weights_only_load": True,
        "state_layout": "per layer: att_x_prev[C], att_kv[H,N_v,N_k], ffn_x_prev[C]",
        "tokenizer": tokenizer_cases,
        "logits": logit_cases,
        "greedy": greedy_cases,
    },
    open(out, "w"),
    indent=1,
    ensure_ascii=False,
)
print(json.dumps(greedy_cases, ensure_ascii=False)[:800])
