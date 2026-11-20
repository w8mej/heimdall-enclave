"""Record golden SmolLM2 outputs with the independent transformers reference.
Local files only; built-in Llama class; no remote code."""

import hashlib
import json
import sys

import torch
from transformers import LlamaForCausalLM, PreTrainedTokenizerFast

src, out = sys.argv[1], sys.argv[2]
torch.manual_seed(0)
tok = PreTrainedTokenizerFast(tokenizer_file=f"{src}/tokenizer.json")
model = LlamaForCausalLM.from_pretrained(
    src, local_files_only=True, torch_dtype=torch.float32, trust_remote_code=False
).eval()
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
]
tokenizer_cases = [
    {"text": t, "ids": tok.encode(t, add_special_tokens=False)} for t in texts
]
specials = {
    t: tok.convert_tokens_to_ids(t)
    for t in ["<|im_start|>", "<|im_end|>", "<|endoftext|>"]
}
prompts = {
    "hello_world": [1, 19556, 905],
    "chat_capital": tok.encode(
        "<|im_start|>user\nWhat is the capital of France?<|im_end|>\n<|im_start|>assistant\n",
        add_special_tokens=False,
    ),
}
logit_cases, greedy_cases = [], []
with torch.no_grad():
    for name, ids in prompts.items():
        logits = model(torch.tensor([ids])).logits[0]
        last = logits[-1]
        top = torch.topk(last, 10)
        logit_cases.append(
            {
                "name": name,
                "ids": ids,
                "last_top10_ids": top.indices.tolist(),
                "last_top10_logits": [round(v, 5) for v in top.values.tolist()],
                "per_position_argmax": logits.argmax(-1).tolist(),
            }
        )
        g = model.generate(
            torch.tensor([ids]),
            max_new_tokens=24,
            do_sample=False,
            eos_token_id=specials["<|im_end|>"],
        )
        new = g[0, len(ids) :].tolist()
        greedy_cases.append(
            {
                "name": name,
                "ids": ids,
                "greedy_new_ids": new,
                "greedy_text": tok.decode(new),
            }
        )


def digest(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


json.dump(
    {
        "schema": 1,
        "producer": "transformers LlamaForCausalLM float32 (independent reference)",
        "transformers": __import__("transformers").__version__,
        "torch": torch.__version__,
        "checkpoint": {
            "repo": "HuggingFaceTB/SmolLM2-135M-Instruct",
            "revision": "12fd25f77366fa6b3b4b768ec3050bf629380bac",
            "model_sha256": digest(f"{src}/model.safetensors"),
            "tokenizer_sha256": digest(f"{src}/tokenizer.json"),
            "config_sha256": digest(f"{src}/config.json"),
        },
        "special_tokens": specials,
        "tokenizer": tokenizer_cases,
        "logits": logit_cases,
        "greedy": greedy_cases,
    },
    open(out, "w"),
    indent=1,
    ensure_ascii=False,
)
print(json.dumps(greedy_cases, ensure_ascii=False)[:600])
