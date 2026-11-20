"""Record golden V-JEPA 2 ViT-L encoder outputs with transformers 4.53.3.

Usage: golden-vjepa2.py VJEPA2_DIR OUT.json
  run with PYTHONPATH holding transformers 4.53.3 (wheel 5aba81c9...7c75),
  huggingface_hub 0.30.2 and safetensors 0.4.5 unpacked from pinned wheels.

Input contract shared with the enclave (`vjepa2-v1` worker mode): one
256x256 8-bit grey frame, replicated to RGB, scaled to [0, 1], normalised
with the checkpoint's ImageNet mean/std, given as a single frame (the model
repeats it to fill its 2-frame tubelet). The latent is the mean over the
256 tokens of the encoder's final LayerNorm output.
"""

import hashlib
import json
import sys

import torch
from transformers import VJEPA2Model

src, out = sys.argv[1:3]
MEAN, STD = [0.485, 0.456, 0.406], [0.229, 0.224, 0.225]
model = VJEPA2Model.from_pretrained(
    src, local_files_only=True, torch_dtype=torch.float32
).eval()


def frames():
    _, x = torch.meshgrid(torch.arange(256), torch.arange(256), indexing="ij")
    ui = torch.full((256, 256), 235, dtype=torch.int64)
    ui[0:32, :] = 40  # title bar
    ui[64:96, 32:224] = 200  # text field
    ui[160:192, 96:160] = 30  # button
    ui[168:184, 112:144] = 250  # button label
    return {
        "gradient": (x % 256).to(torch.uint8),
        "ui_mock": ui.to(torch.uint8),
        "flat_91": torch.full((256, 256), 91, dtype=torch.uint8),
        "flat_64": torch.full((256, 256), 64, dtype=torch.uint8),
    }


def pixel_values(gray):
    g = gray.float() / 255.0
    rgb = torch.stack([(g - m) / s for m, s in zip(MEAN, STD)])  # [3, 256, 256]
    return rgb[None, None]  # [B=1, T=1, C, H, W]


cases = []
with torch.no_grad():
    for name, gray in frames().items():
        tokens = model.encoder(
            pixel_values_videos=pixel_values(gray)
        ).last_hidden_state[0]
        pooled = tokens.mean(0)
        cases.append(
            {
                "name": name,
                "pixels_sha256": hashlib.sha256(gray.numpy().tobytes()).hexdigest(),
                "pooled_head": [round(v, 6) for v in pooled[:8].tolist()],
                "pooled_sum": round(float(pooled.sum()), 4),
                "pooled_norm": round(float(pooled.norm()), 5),
                "token0_head": [round(v, 6) for v in tokens[0, :4].tolist()],
                "token137_head": [round(v, 6) for v in tokens[137, :4].tolist()],
            }
        )


def digest(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


json.dump(
    {
        "schema": 1,
        "producer": "transformers 4.53.3 VJEPA2Model.encoder float32 (independent reference)",
        "torch": torch.__version__,
        "checkpoint": {
            "repo": "facebook/vjepa2-vitl-fpc64-256",
            "revision": "b3c1679b7c34d3255ef3547f27c7b226aefab26f",
            "model_sha256": digest(f"{src}/model.safetensors"),
        },
        "input": "256x256 grey u8 -> RGB, /255, ImageNet mean/std, one frame (repeated to the tubelet)",
        "cases": cases,
    },
    open(out, "w"),
    indent=1,
)
for c in cases:
    print(c["name"], c["pooled_norm"], c["pooled_head"][:3])
