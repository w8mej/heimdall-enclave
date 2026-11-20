"""Record golden Qwen3-0.6B + EAGLE-3 outputs.

Usage: golden-qwen3-eagle3.py QWEN3_DIR HEAD_DIR OUT.json
  run with PYTHONPATH holding transformers 4.51.3, huggingface_hub 0.30.2 and
  safetensors 0.4.5 unpacked from their pinned wheels:
    transformers-4.51.3-py3-none-any.whl     fd327963...8e83
    huggingface_hub-0.30.2-py3-none-any.whl  68ff0596...1e28
    safetensors-0.4.5-cp310-...arm64.whl     23fc9b4e...ad27

Target: transformers `Qwen3ForCausalLM` in float32 (independent reference).
Tokenizer: the `tokenizers` library over the pinned tokenizer.json.
Draft: the SpecForge `LlamaForCausalLMEagle3` forward (sgl-project/SpecForge
@ ac2e362e, specforge/modeling/draft/llama3_eagle.py) restated in plain
torch, fed the target features SGLang/SpecForge capture by default: the
outputs of target layers 1, 13 and 24 (HF hidden_states[2], [14], [25]).
The draft's independent check is its acceptance rate against the target,
and the speculative run must reproduce plain greedy decoding exactly.
"""

import hashlib
import json
import sys

import torch
from safetensors.torch import load_file
from tokenizers import Tokenizer
from transformers import Qwen3ForCausalLM

qwen_dir, head_dir, out = sys.argv[1:4]
torch.manual_seed(0)
tok = Tokenizer.from_file(f"{qwen_dir}/tokenizer.json")
target = Qwen3ForCausalLM.from_pretrained(
    qwen_dir, local_files_only=True, torch_dtype=torch.float32
).eval()
head = {
    k: v.float() if v.is_floating_point() else v
    for k, v in load_file(f"{head_dir}/model.safetensors").items()
}
head_cfg = json.load(open(f"{head_dir}/config.json"))
CAPTURE = [2, 14, 25]
END = {tok.token_to_id("<|im_end|>"), tok.token_to_id("<|endoftext|>")}
EPS, THETA, HEADS, KV, HD = head_cfg["rms_norm_eps"], head_cfg["rope_theta"], 16, 8, 128


def encode(text):
    return tok.encode(text, add_special_tokens=False).ids


def target_pass(ids):
    with torch.no_grad():
        o = target(torch.tensor([ids]), output_hidden_states=True)
    feats = torch.cat([o.hidden_states[i][0] for i in CAPTURE], dim=-1)
    return o.logits[0], feats


def rms(x, w):
    return w * (x * torch.rsqrt(x.pow(2).mean(-1, keepdim=True) + EPS))


def rope(x, positions):
    inv = 1.0 / (THETA ** (torch.arange(0, HD, 2, dtype=torch.float32) / HD))
    freqs = positions[:, None].float() * inv[None, :]
    emb = torch.cat((freqs, freqs), dim=-1)
    cos, sin = emb.cos()[:, None, :], emb.sin()[:, None, :]
    half = torch.cat((-x[..., HD // 2 :], x[..., : HD // 2]), dim=-1)
    return x * cos + half * sin


def draft_layer(emb, hid):
    p = "midlayer."
    residual = hid
    x = torch.cat(
        (
            rms(emb, head[p + "input_layernorm.weight"]),
            rms(hid, head[p + "hidden_norm.weight"]),
        ),
        dim=-1,
    )
    n = x.shape[0]
    pos = torch.arange(n)
    q = rope((x @ head[p + "self_attn.q_proj.weight"].T).view(n, HEADS, HD), pos)
    k = rope((x @ head[p + "self_attn.k_proj.weight"].T).view(n, KV, HD), pos)
    v = (x @ head[p + "self_attn.v_proj.weight"].T).view(n, KV, HD)
    k, v = (t.repeat_interleave(HEADS // KV, dim=1) for t in (k, v))
    a = torch.nn.functional.scaled_dot_product_attention(
        q.transpose(0, 1), k.transpose(0, 1), v.transpose(0, 1), is_causal=True
    )
    h = (
        residual
        + a.transpose(0, 1).reshape(n, HEADS * HD)
        @ head[p + "self_attn.o_proj.weight"].T
    )
    m = rms(h, head[p + "post_attention_layernorm.weight"])
    act = torch.nn.functional.silu(m @ head[p + "mlp.gate_proj.weight"].T) * (
        m @ head[p + "mlp.up_proj.weight"].T
    )
    return h + act @ head[p + "mlp.down_proj.weight"].T


def draft_chain(ctx, feats, k):
    """ctx = committed ids c_0..c_m; feats = target features for 0..m-1."""
    embed = target.model.embed_tokens.weight
    with torch.no_grad():
        emb = embed[torch.tensor(ctx[1:])]
        hid = feats[: len(ctx) - 1] @ head["fc.weight"].T
        chain, first_top = [], None
        for step in range(k):
            g = draft_layer(emb, hid)
            logits = rms(g[-1], head["norm.weight"]) @ head["lm_head.weight"].T
            d = int(torch.argmax(logits))
            if step == 0:
                top = torch.topk(logits, 5)
                first_top = {
                    "draft_ids": top.indices.tolist(),
                    "logits": [round(v, 4) for v in top.values.tolist()],
                }
            t = d + int(head["d2t"][d])
            chain.append(t)
            emb = torch.cat((emb, embed[t][None]), dim=0)
            hid = torch.cat((hid, g[-1][None]), dim=0)
    return chain, first_top


def speculative(prompt, n_tokens, k):
    logits, feats = target_pass(prompt)
    ctx = prompt + [int(torch.argmax(logits[-1]))]
    produced, accepted_lengths = [ctx[-1]], []
    while len(produced) < n_tokens and ctx[-1] not in END:
        drafts, _ = draft_chain(ctx, feats, k)
        logits, feats = target_pass(ctx + drafts)
        preds = logits[len(ctx) - 1 :].argmax(-1).tolist()
        j = 0
        while j < k and drafts[j] == preds[j]:
            j += 1
        new = drafts[:j] + [preds[j]]
        accepted_lengths.append(j)
        ctx += new
        produced += new
    return produced[:n_tokens], accepted_lengths


texts = [
    "Hello world",
    "hello",
    " Hello, world!",
    "The quick brown fox jumps over the lazy dog.",
    '{"priority":"urgent"}',
    "naïve café — 東京 🚀",
    "café (decomposed e-acute)",
    "  leading spaces\n\nand\ttabs\r\n",
    "1234567890 3.14159",
    "",
    "<|im_start|>user\nhi<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n",
]
tokenizer_cases = [{"text": t, "ids": encode(t)} for t in texts]
specials = {
    t: tok.token_to_id(t)
    for t in ["<|endoftext|>", "<|im_start|>", "<|im_end|>", "<think>", "</think>"]
}
chat = (
    "<|im_start|>user\nClassify the support ticket priority as routine, important, urgent or critical. "
    "Reply with one word. Ticket: Production database is down and customers cannot log in.<|im_end|>\n"
    "<|im_start|>assistant\n<think>\n\n</think>\n\n"
)
prompts = {"capital": "The capital of France is", "chat_ticket": chat}

cases = []
for name, text in prompts.items():
    ids = encode(text)
    logits, feats = target_pass(ids)
    top = torch.topk(logits[-1], 10)
    greedy, ctx = [], list(ids)
    for _ in range(24):
        lg, _ = target_pass(ctx)
        t = int(torch.argmax(lg[-1]))
        if t in END:
            break
        greedy.append(t)
        ctx.append(t)
    first = int(torch.argmax(logits[-1]))
    chain, first_top = draft_chain(ids + [first], feats, 3)
    spec, accepted = speculative(ids, 24, 3)
    plain = greedy[:24]
    assert [t for t in spec if t not in END][
        : len(plain)
    ] == plain, f"{name}: speculative != greedy"
    cases.append(
        {
            "name": name,
            "text": text,
            "ids": ids,
            "last_top10_ids": top.indices.tolist(),
            "last_top10_logits": [round(v, 5) for v in top.values.tolist()],
            "features_last": [
                {
                    "layer_output": i - 1,
                    "head": [
                        round(v, 5) for v in feats[-1, j * 1024 : j * 1024 + 4].tolist()
                    ],
                    "sum": round(float(feats[-1, j * 1024 : (j + 1) * 1024].sum()), 3),
                }
                for j, i in enumerate(CAPTURE)
            ],
            "greedy_new_ids": greedy,
            "greedy_text": tok.decode(greedy),
            "draft_after_first": {
                "context_last": first,
                "chain": chain,
                "first_step_top5": first_top,
            },
            "speculative_accepted_lengths": accepted,
        }
    )

# Capture control: the chosen features must out-accept shifted, distant and
# zeroed features on chat text (the head was trained on ShareGPT chat).
control_prompt = encode(
    "<|im_start|>user\nWrite a short paragraph about the history of the Roman Empire."
    "<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"
)
control, real_pass = {}, target_pass
for label, layers, zero in (
    ("2,14,25", [2, 14, 25], False),
    ("1,13,24", [1, 13, 24], False),
    ("10,20,27", [10, 20, 27], False),
    ("zeroed", [2, 14, 25], True),
):
    CAPTURE[:] = layers
    if zero:

        def target_pass(ids):
            r = real_pass(ids)
            return (r[0], torch.zeros_like(r[1]))

    _, acc = speculative(control_prompt, 48, 3)
    target_pass = real_pass
    control[label] = {
        "rounds": len(acc),
        "mean_accepted_of_3": round(sum(acc) / len(acc), 3),
    }
CAPTURE[:] = [2, 14, 25]
assert (
    max(control, key=lambda k: control[k]["mean_accepted_of_3"]) == "2,14,25"
), control


def digest(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


json.dump(
    {
        "schema": 1,
        "producer": "transformers 4.51.3 Qwen3ForCausalLM float32 + SpecForge EAGLE-3 draft forward in torch",
        "torch": torch.__version__,
        "capture_hidden_state_indices": CAPTURE,
        "target": {
            "repo": "Qwen/Qwen3-0.6B",
            "revision": "c1899de289a04d12100db370d81485cdf75e47ca",
            "model_sha256": digest(f"{qwen_dir}/model.safetensors"),
            "tokenizer_sha256": digest(f"{qwen_dir}/tokenizer.json"),
        },
        "draft": {
            "repo": "GavinLucky/SGLang-EAGLE3-Qwen3-0.6B-SpecForge",
            "revision": "5fe9c43a50078119bfa38e5f30969475be314315",
            "model_sha256": digest(f"{head_dir}/model.safetensors"),
        },
        "capture_control": control,
        "special_tokens": specials,
        "tokenizer": tokenizer_cases,
        "cases": cases,
    },
    open(out, "w"),
    indent=1,
    ensure_ascii=False,
)
for c in cases:
    print(
        c["name"],
        repr(c["greedy_text"]),
        "draft chain",
        c["draft_after_first"]["chain"],
        "accepted",
        c["speculative_accepted_lengths"],
    )
