# RE-009 node #115 checkpoint hardfork hash tracker fields

A named checkpoint carries two different fields spelled `h`. This packet recovers the one at `exchange.advt.h`: a policy boolean and an optional 32-byte digest. A height-indexed quorum digest belongs to a separate `exchange.advt.qrs` row. A restored hardfork tracker may need both the boolean and the optional value to represent the checkpoint faithfully.

Target is Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source baseline is `2da45cb0a761cff6b478e40421699857d87a94df`. Coordinates are ELF virtual addresses. The [tracker wire packet](../serialization-hash-quorum-state-wire-115/README.md) recovered the sixth outer field and left its value helper stubbed. The [checkpoint reader](../RE-017-node115-replay-delay-checkpoint-read/README.md) establishes the surrounding `exchange.advt` object and tracker staging, and the [hash signature record](../RE-017-hash-signature-record-115/README.md) supplies runtime context for the distinct policy and stored value bytes.

## Selected writer

- `0x4214408` calls `0x4308e50` with tracker `+0x90`. In named mode the helper emits key `h` and a two-entry map. Its two fields are `q` and `l`, in that order. Positional mode emits a two-element array without those keys.
- The first value reads tracker `+0x90`. The writer's bitwise OR with `0xc2` yields the MessagePack false and true bytes `c2` and `c3` for the canonical input bytes 0 and 1.
- The second value reads tag tracker `+0x91`. Tag 1 uses the 32-byte value at tracker `+0x92`, takes the shared lowercase hexadecimal encoder and emits a MessagePack string. The selected other arm emits nil byte `c0`. The two sources remain distinct in [the earlier hash-signature record path](../RE-017-hash-signature-record-115/README.md), which reads the policy byte separately and stages a digest using the presence tag and two 16-byte stores.

## Selected named reader

- Tracker reader `0x33b2a30` uses dispatch table `0x765648`. Entry 5 calls child reader `0x322e740`. That branch's duplicate field diagnostic references `h`.
- Within the child, the single-byte key decoder maps `q` to 0 and `l` to 1. Reader table `0x6f285c` sends those indices to `0x322f12a` and `0x322f244` respectively. The latter branches on nil and otherwise delegates to the decoder with the `AbciDigest` context literal.
- On the selected successful parent copy, the first two result values reach tracker `+0x90` and `+0x91`. The 32 distinct digest bytes from the child result at stack `+0x17b` reach tracker `+0x92..+0xb1` in order. Two subsequent 184-byte copies preserve the tracker layout.

Run this from the repository root.

```sh
python3 -B research/work-items/RE-009-node115-checkpoint-hardfork-hash/verify.py
```

The static verifier checks bytes against the authenticated original image inside six FDE boundaries. The copy check numbers every byte in a synthetic decoder result to detect incorrect offsets or byte order. The [offline run](offline-log.txt) records the command and results. To inspect any attached span, run LLVM objdump 23.1.4 with `-d --x86-asm-syntax=intel --start-address=START --stop-address=END artifacts/node/115/hl-node` using a range beginning at an instruction address from `windows.txt`.

The type names and field roles derive from the selected reader/writer join. This covers canonical emitted shapes and the ordinary named read with a present digest. The broader child decoder, alternative representations, policy semantics, checkpoint provenance, replay-root equality and production execution remain outside the result. No captured code was executed.
