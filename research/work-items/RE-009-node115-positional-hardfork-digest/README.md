# RE-009 · Node #115 positional checkpoint tracker digest

This maps the positional MessagePack value of `HashSignatureTracker.h` in Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.

The enclosing reader at `0x1c062b0` names `HashSignatureTracker` in its field diagnostic table. Its named-map case for `h` calls `0x198e9b0` at `0x1c065a2`. The duplicate-field branch from `0x1c0658f` reaches the single-byte `h` diagnostic at `0x1c0825a`. Its positional reader reaches the same child at `0x1c080b1` through the field-count branch at `0x1c07c86`.

For the selected compact positional array, `0x198ea21` reaches the array visitor and `0x198eb30` saves the array size. The visitor decodes the first element as a boolean and then calls the optional-`AbciDigest` reader at `0x198f021` for the second element. The boolean and digest-presence flag are separate values.

| Selected second element | Child's successful output |
| --- | --- |
| Explicit MessagePack nil (`0xc0`) | Boolean at `+1`, presence 0 at `+2` |
| A successfully decoded `AbciDigest` | Boolean at `+1`, presence 1 at `+2`, 32 digest bytes at `+3..+0x22` |
| Second element missing from a one-element array | Error path at `0x198f22e` |
| Optional decoder reports an error | Error payload propagates to the child's tag-1 result |

The optional reader at `0x22a6250` writes a zero word for nil. For a decoded digest it writes bytes `00 01` with two adjacent 16-byte copies after them. The tuple visitor separates the boolean and presence at `0x198f0de` and `0x198f0e3`. The parent reads both bytes from separate destinations at `0x1c080e7` and `0x1c080ec` and copies the 32-byte area independently. Consumers should use the presence flag when deciding whether the payload has a digest. An absent second element and an explicit nil follow different paths.

The [optional reader work item](../RE-017-node115-abci-optional-digest-readers/README.md) establishes the two low-level tag encodings without attributing them to a field. This work binds one encoding to the positional tracker caller and records its tuple-level behavior. PR #7291 covers the distinct named checkpoint visitor and its present-digest path. The evidence here covers the selected decoder branch. A captured checkpoint, a per-height reference root, and a replay comparison remain outstanding.

## Reproduce

From the repository root with the pinned ELF available locally:

```sh
python3 -B research/work-items/RE-009-node115-positional-hardfork-digest/verify.py
```

The [disassembly windows](windows.txt) include the LLVM commands. The verifier reads the ELF offline, checks the digest and indexed unwind ranges, compares the captured instruction bytes, and recomputes the selected relative destinations and literal references. [Offline log](offline-log.txt).
