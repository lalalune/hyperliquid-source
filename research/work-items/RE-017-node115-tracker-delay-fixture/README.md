# RE-017 #115 tracker-delay checkpoint fixture word

[The named MessagePack path](../RE-017-node115-replay-delay-checkpoint-read/README.md) ties `exchange.advt.adu` to decoded Exchange offset `+0x23b8`. [#7218](https://github.com/lalalune/hyperliquid-source/pull/7218) locates its compact copy at `+0x3ed8`. This fixture bridges those coordinates for an independently supplied field token and stages a decoded image usable by the [compact assembler](https://github.com/lalalune/hyperliquid-source/pull/7375). The input fixture must be exactly `0x27a8` bytes at the requested height and match its expected digest.

The raw float64 marker `0xcb` dispatches via table `0x77b6c8` to `0x342328a`. The decoder requires eight payload bytes, swaps their byte order, and returns tag 9. A distinct check at `0x46f3d49..0x46f3da6` accepts positive finite words, including subnormals, and preserves either sign of zero. Negative nonzero values and nonfinite words take the rejection edge. The verifier checks these instructions and compares their unsigned arithmetic predicate to the projection across deterministic bit patterns. Accepted inputs are staged without re-encoding via the host floating-point format.

A known absent whole tracker instead supplies the default positive zero. The earlier reader identifies a separate missing-field path for a present tracker without `adu`. The CLI requires the caller to choose the whole-tracker absence case explicitly or provide one complete `0xcb` token. It does not read the surrounding map or establish how a token was extracted. Other native token types are outside this fixture projection.

From the repository root:

```sh
packet=research/work-items/RE-017-node115-tracker-delay-fixture
python3 -B "$packet/verify.py"
python3 -B "$packet/test_project.py"
python3 -B "$packet/project.py" decoded.bin --sha256 EXPECTED_DIGEST --height H \
  --adu-f64-hex cb3ff0000000000000 > staged-decoded.bin
```

The real offline log includes the decoder verifier, focused tests, and composition with the compact assembler. The compositions use synthetic input and a supplied EVM constructor block. They do not establish successful full checkpoint decoding, live timer behavior, or H/H+1 root parity. No captured instructions are executed.
