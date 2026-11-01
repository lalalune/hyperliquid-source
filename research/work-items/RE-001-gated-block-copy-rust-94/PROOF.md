# Complete leaf relation and memory domain

Target #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, linked ELF VA `[0x4ff8b30,0x4ff8b9c)`. The 108 bytes decode as 25 instructions, including an unreachable five-byte NOP between the two return blocks. Four subsequent `int3` bytes are outside the body. The full FDE inventory has exactly one overlapping FDE for this body. Both GNU and LLVM decode every body/caller byte with identical boundaries. No source name or field meaning is established.

## Selection from an immutable entry image

Let `M` be stable ordinary byte memory at entry, `d=RDI`, `s=RSI`, `p=RDX`, `b=signed32(ECX)` and `f=R8B`. Upper R8 and RCX bits do not participate. Define a selection offset `a` using only the required entry bytes:

1. If `f=0`, `a=0x158`; neither the index nor the gate byte is read.
2. Otherwise read `u=LE32(M[p+0x14..p+0x18])`. Define `t=signed32((u-1) mod 2^32)`. If `t>b`, `a=0x158`; the gate is not read.
3. Otherwise read `g=M[s+0x1a0]`. If `g=0`, `a=0x158`; else `a=0x188`.

The `sub` is 32-bit wrapping. The subsequent `cmp` overwrites its flags before `jg`, so the comparison is the signed ordering of the **wrapped** result against the bound. In particular, an index bit pattern `0x80000000` decrements to `0x7fffffff`; index zero decrements to -1. The bound includes all i32 values. There is no valid-index or Boolean-byte assumption: every nonzero flag/gate passes its respective test.

The final relation is, for every address `x`,

```
M'(x) = M(s+a+x-d)  if d <= x < d+48
        M(x)        otherwise
RAX = d
```

All three 16-byte source loads on the selected path occur before its first store. The destination stores cover consecutive, disjoint chunks `[d,d+16)`, `[d+16,d+32)`, `[d+32,d+48)`. Consequently the pointwise formula uses the entry image even for arbitrary source/destination overlap. Selection is also finished before any store, so destination overlap with the index, gate, either source block, or any combination does not change the selection. The gate byte is itself byte 24 of the preferred block and must remain in the copied payload unchanged. No source byte is reversed or interpreted numerically.

## Safe projection and refusals

The Rust API accepts one mutable byte slice and usize offsets `destination`, `source`, `index_source`, plus `bound:i32` and `flag:u8`. It returns the destination offset on success. Interpret the slice as `[B,B+len)` and offsets as addresses `B+offset`. For target correspondence, all accessed ranges and address additions must be nonwrapping and representable in the 64-bit target address space; the slice represents stable readable memory and writable destination memory. The safe API is not the original machine-pointer ABI. Returning offset `d` represents raw `RAX=B+d`; it is not a reconstructed source-language return type.

Only actually used ranges are required: index `[p+20,p+24)` iff flag is nonzero; gate at `s+416` iff the first two gates pass; the chosen 48-byte source block; and the 48-byte destination. Offsets are checked with overflow-aware arithmetic. There is no blanket requirement for the whole source struct or the unselected block to exist. Thus an unusable index offset is accepted with flag zero, and a fallback-only image can end exactly at `s+392` when the gate is skipped. A gate-selected fallback requires the gate byte but still does not require all preferred bytes. No source/destination alignment restriction is introduced.

After validation, Rust snapshots the selected 48 bytes before writing. Every refusal leaves the image unchanged. This refusal policy is additional safe behavior, not an emulation of native faults: the target may fault after partial stores, and a faulting invocation has no claimed correspondence. Concurrent mutation, volatile/MMIO effects, page permissions/fault timing, invalid raw pointers, wraparound address aliases, calling convention, flags, vector registers and all unobserved registers are excluded. The snapshot proof covers admitted overlapping ordinary memory, rather than assuming disjoint inputs.

## Independent oracle

`oracle.py` computes the wrapped decrement with arbitrary-precision modular arithmetic and an explicit signed interval mapping, then constructs the final image pointwise from immutable input bytes. It does not reproduce vector operations, store loops, registers or instruction stepping. Inputs and expected full-image differences were frozen and hashed before `src/node94-gated-block-copy/` existed. Sparse differences are lossless: every omitted byte must equal the input, and the native client compares the entire before/after image to produce them. Status and returned destination offset are also compared without masks.

Fixtures cover both block choices, flag/gate values beyond Boolean 0/1, signed extremes and exact bounds, every byte value in payloads, exact/short buffers, inaccessible skipped operands, overflow-sized offsets, source/destination overlap at every displacement -47..47, index/gate/destination aliases, and deterministic random combinations. An intentionally streaming copy is a useful negative control: for positive displacement its stores overwrite unread source bytes, unlike the target's all-loads-before-stores rule.

## Closure and limits

The leaf has no calls, no RIP-relative data operands and no branch outside the body. Its constants and field displacements are all immediate bytes in the bound body. A full `.text` E8/rel32 scan finds eight direct sites in seven FDEs. The full caller bodies and unwind records are bound; every site is an instruction boundary in both decoders. This establishes incoming edges, not complete caller semantics. For example, `0x5023e87..0x5023e9f` prepares a stack destination, loads source from object+0x38 and index owner from object+0x48, and reloads the bound/flag before the call. `0x5027f8c..0x5027fae` has the same pointer fields and passes flag 1. Larger caller control flow, other calls and any source-level object identity remain unclaimed.

All 80,300 RELA entries are scanned; no addend equals the leaf address. The direct byte-pattern and relocation scans are not a complete census of indirect or computed references. No wider copy family, original Rust/C++ type, whole-node binary equality or progress gate is claimed. Only newly authored Rust executes; no captured executable or instruction emulator is used.
