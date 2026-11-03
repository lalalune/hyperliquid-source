# RE-001-node115-lu-resolver: the node #115 lu resolver end to end

- Component ID: RE-001-node115-lu-resolver
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (node-115-only)
- Claim status: observation
- Scope included and excluded: resolver FDE `0x4d35b60..0x4d35de4` only (644 bytes, 134 strict mnemonic-line instructions); leaf-op, merge/redistribute, flag, and completion internals are cited, not re-claimed. Static analysis only; the node binary was never executed.

## Reproduce

Exact commands, working directory `~/workspace/hl-wt-calls199-115`:

```sh
objdump -d -M intel --start-address=0x4d35b60 --stop-address=0x4d35de4 \
  artifacts/node/115/hl-node
python3 tools/node115_lu_resolver.py
python3 -m unittest tests.test_node115_lu_resolver -v
```

`.text` file offset = VA − 0x1000. Instruction counts are strict
mnemonic-line counts (address + byte field + tab + mnemonic);
objdump byte-continuation lines are excluded. No execution, no side
effects.

## Evidence

Original addresses and coordinate system: virtual addresses as shown
by objdump; file offsets are VA − 0x1000 for `.text`.

Validated boundaries: resolver starts at `0x4d35b60` (push rbx,
frame setup) and ends at the second `ret` at `0x4d35de3`; the next
bytes are `int3` padding (`0x4d35de4..0x4d35def`) and a new function
at `0x4d35df0`. First `ret` at `0x4d35d68` is the levels-`== 0`
early return. Raw disassembly is in `resolver.objdump.txt`; raw
bytes are in `resolver.hex` (644 bytes, SHA-256
`49457f6b0159d558b0f70375d1bdd6862c47d0d665c54c3ed2e763d65013fed7`).

Callers/callees: the resolver calls only the leaf op `0x4d24790`,
at `0x4d35c75` (rightmost path, bytes `e8 16 eb fe ff`) and
`0x4d35d5b` (levels-`== 0` path, bytes `e8 30 ea fe ff`). Its only
direct caller is the completion helper `0x4da86a0` at `0x4da86c9`
(bytes `e8 92 d4 f8 ff`); a full `.text` E8 scan finds no other
direct caller, and `readelf -r` shows no relocation addend
`0x4d35b60` (0 GOT sites).

Source mapping evidence: node layout (parent `+0xb0`, keys
`+0xb8 + 4*i`, child index `+0xe4`, count `+0xe6`, children
`+0xe8 + 8*i`) matches the node.rs layout established by
#195/#196/#198; no new source-file claim is made here.

ABI/layout observations: resolver signature `f(out: *mut [u8; 48],
loc: *const Loc, flag: *mut u8)`; loc `{node @+0, levels @+0x8,
index @+0x10}`; out48 `{key @+0, value @+0x8, flag @+0x10, node
@+0x18, levels @+0x20, edge @+0x28}`. The swap masks the stored
flag to bit 0 (`and r9b, 0x1` at `0x4d35cf1`). The climb loop
compares 16-bit counts (`cmp r8w, [rax+0xe6]` at `0x4d35cc2`).

Analysis is complete for the claimed FDE; no range was timed out.

## Implementation and comparison

Not yet implemented/measured: no independent Rust path is built
in this packet; the verifier checks byte, count, census, and
records agreement against the target binary only.

## Results and limitations

Machine-readable metrics: 644 bytes, 134 instructions (106 body +
28 tail), 4 nops, 2 rets, 2 calls, 1 direct caller, 0 GOT sites.
Verifier exit 0; unit tests pass (see test output); MANIFEST
7/7. What remains unknown: the downstream use, if any, of the
resolver's node/edge outputs (ignored by its only caller). The
gate covers the full claimed FDE and its census. Finish with the
concrete next question in README.md: census and decode the
completion helper's direct callers beyond the `0x4fb52e0`
gate-release worked example.
