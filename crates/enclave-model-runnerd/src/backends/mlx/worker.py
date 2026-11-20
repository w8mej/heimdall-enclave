"""Closed MLX CPU bigram compute worker. Apache-2.0 repository source.

Only fixed-size float tensor data and one-byte indices arrive on private pipes.
No model-defined Python, pickle, filesystem model import or arbitrary graph is
accepted. Framework/prover internals and physical erasure remain separate gates.
"""

import math
import struct
import sys

if len(sys.argv) != 2:
    raise SystemExit(2)
sys.path.insert(0, sys.argv[1])
import mlx.core as mx

mx.set_default_device(mx.cpu)
raw = sys.stdin.buffer.read(256 * 256 * 4)
if len(raw) != 256 * 256 * 4:
    raise SystemExit(3)
weights = struct.unpack("<65536f", raw)
if not all(math.isfinite(value) for value in weights):
    raise SystemExit(4)
table = mx.array(weights, dtype=mx.float32).reshape((256, 256))
mx.eval(table)
del raw, weights
sys.stdout.buffer.write(b"MLX1")
sys.stdout.buffer.flush()
while True:
    request = sys.stdin.buffer.read(1)
    if not request:
        break
    # Perform the actual causal one-hot x weight-matrix product through MLX;
    # results are not obtained by indexing a Python/Rust reference table.
    one_hot = mx.array(
        [float(index == request[0]) for index in range(256)], dtype=mx.float32
    )
    result = one_hot @ table
    mx.eval(result)
    values = result.tolist()
    if len(values) != 256 or not all(math.isfinite(value) for value in values):
        raise SystemExit(5)
    sys.stdout.buffer.write(struct.pack("<256f", *values))
    sys.stdout.buffer.flush()
