"""Record golden LLaDA-8B-Instruct tokenizer ids.

Usage: golden-llada-tokenizer.py LLADA_DIR OUT.json
  LLADA_DIR holds the pinned tokenizer.json (scripts/fetch-trained-model.py
  llada). Reference: the Hugging Face `tokenizers` library (version recorded
  in the output) loading that file as data; no publisher code runs.

Cases target where LLaDA's Llama-3-style split differs from Qwen2's:
contractions, digit runs, newline runs, whitespace runs, NFC composition,
CJK, emoji and punctuation runs.
"""

import hashlib
import json
import sys

import tokenizers
from tokenizers import Tokenizer

CASES = [
    "Hello, world!",
    "I'll say it's what we'd've done. DON'T, Won't, y'all",
    "Order 12345 shipped on 2026-11-18 at 09:30.",
    "line one\nline two\n\n\nline five\r\n",
    "tabs\tand   spaces     end   ",
    "Café vs Café: éé",
    "漢字とかな混じり文",
    "emoji \U0001f600\U0001f680 and flags \U0001f1fa\U0001f1f8",
    '{"priority":"urgent"}',
    "!!!??? ... --- *** ((()))",
    "   leading spaces",
    "<|startoftext|>a<|endoftext|>",
]
SPECIALS = [
    "<|startoftext|>",
    "<|endoftext|>",
    "<|mdm_mask|>",
    "<|eot_id|>",
    "<|start_header_id|>",
    "<|end_header_id|>",
]


def main() -> None:
    llada_dir, out = sys.argv[1:3]
    path = f"{llada_dir}/tokenizer.json"
    tok = Tokenizer.from_file(path)
    cases = []
    for text in CASES:
        ids = tok.encode(text, add_special_tokens=False).ids
        cases.append(
            {
                "text": text,
                "ids": ids,
                "decoded": tok.decode(ids, skip_special_tokens=False),
            }
        )
    specials = {
        name: tok.token_to_id(name)
        for name in SPECIALS
        if tok.token_to_id(name) is not None
    }
    with open(path, "rb") as stream:
        digest = hashlib.sha256(stream.read()).hexdigest()
    golden = {
        "reference": f"tokenizers {getattr(tokenizers, '__version__', 'unknown')}",
        "tokenizer_sha256": digest,
        "vocab": tok.get_vocab_size(with_added_tokens=True),
        "cases": cases,
        "special_tokens": specials,
    }
    with open(out, "w", encoding="utf-8") as stream:
        json.dump(golden, stream, ensure_ascii=False, indent=1)
        stream.write("\n")


if __name__ == "__main__":
    main()
