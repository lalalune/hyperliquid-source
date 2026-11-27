# action-dispatch: survey shared admission calls across the 92 node #115 handlers

The 92 handler entries selected by the node #115 action router all contain the same three leading direct calls and both common check calls. The evidence records their instruction sites, target FDEs, and literal result markers so later handler work can distinguish a shared call shape from a shared full implementation.

- Component ID: `action-dispatch` (RE-010).
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: `4b9b672f669b8c487aa364989db9750465fbb91a`; no reference source used.
- Claim status: observations are direct call instructions, FDE extents, and immediate-store bytes. The shared helpers' meanings are not inferred anew here.
- Scope included: all 92 router-selected handler entries, from each entry through its second call to `0x2c206b0`, plus `0x120` and `0x0f` immediate stores anywhere in each recorded FDE. Excluded: helper bodies, proof that every pinned call executes on every path, full handler semantics, wire decoding, and a component gate.

## Reproduce

The capture used GNU objdump `2.47.20260726` to inspect the digest-bound ELF; the checked packet and its verifier need no disassembler or network access.

```sh
python3 tools/action_dispatch_shared_admission_115.py
python3 -m unittest tests.test_action_dispatch_shared_admission_115
shasum -a 256 -c research/work-items/action-dispatch-shared-admission-115/MANIFEST.sha256
```

The verifier checks the target digest, the 92 router indices and tags, each indexed FDE end, every pinned call encoding and target, and every recorded immediate byte sequence. `handlers.tsv` stores all addresses as ELF virtual addresses. Calls marked `direct` are `E8 rel32`; calls marked `got` are `FF 15 disp32` and the target column names the resolved GOT slot address.

## Evidence

Every handler entry has, as its first three call instructions, direct calls to `0x2a8ab70`, `0x4717440`, and `0x3ed25b0`. Each entry also contains direct calls to `0x2c202b0` and `0x2c206b0`; calls between the first helper chain and the second check vary by handler and are retained in `handlers.tsv` rather than treated as a uniform body.

Across each whole FDE, 88 of 92 handlers contain an immediate 16-bit store of `0x120`, and all 92 contain an immediate byte store of `0x0f`. Four handlers (`0x2c0ede0` / tag `0x89`, `0x2c1fd40` / `0x8a`, `0x2c06530` / `0x98`, `0x2c0a610` / `0xa9`) have no matching `movw $0x120` instruction in the indexed FDE; this is a byte-pattern result, not proof that they lack an equivalent error path. A literal elsewhere in an FDE is not proof that it is reachable from the common call sequence or has identical meaning.

The separate `action-dispatch-prior-key-wrapper-115` packet models ten exact 1087-byte wrapper clones. This packet maps them into the router's table: tags `0x87`, `0x8c`, `0x8e`, `0x9b`, `0x9f`, `0xa1`, `0xb3`, `0xbd`, `0xd6`, and `0xda`. It inventories the other call shapes without generalizing that ten-clone model to the remaining handlers.

No captured binary was executed. The observations do not establish complete source-level function boundaries: FDEs are unwind extents, and split hot/cold code can exist. No component progress gate is requested.

## Results and limitations

Machine-checked counts: 92/92 router entries have the pinned leading call sequence; 92/92 contain both check calls; 88/92 have a pinned literal `0x120` word store; 92/92 have a pinned literal `0x0f` byte store. Negative controls cover digest, table size/index, call displacement, and marker-byte corruption.

Next question: for handler families outside the ten exact clones, determine which intermediate checks execute before the shared pair and whether their result layouts match the wrapper model.
