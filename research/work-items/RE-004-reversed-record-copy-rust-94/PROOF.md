# Ordered byte-copy correspondence

The claim is the final ordinary-memory bytes and destination-pointer projection
on normal return from node #94 `[0x3818d40, 0x3818dc4)`. It covers every initial
byte value and every overlap of two admitted 52-byte ranges. It is conditional on
stable ordinary memory, valid nonwrapping addresses, supported SSE2 execution and
normal instruction/return behavior. It does not model faults, races, MMIO,
self-modifying code, overwritten return state or intermediate observations.

## Complete static boundary and call binding

`verify_static.py` checks all 91,774,280 target bytes against SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` before parsing.
The selected FDE has exactly the 132-byte range above, body hash
`b71e7d985a8e36e530abbe68d074df86d2ad0d0700525d85bc2902baedc474df`.
The preceding FDE ends at `0x3818d3e` and the following begins at `0x3818dd0`;
the separating two and twelve bytes are INT3 padding. The leaf has no LSDA,
branch, helper call or external constant load. Its 31 instructions have identical
byte coverage and boundaries in retained GNU and LLVM exports. Neither export
needed the verifier's supported standalone LOCK-prefix grouping.

The first instruction copies full RDI to RAX. Subsequent instructions only
modify ECX, XMM0, XMM1, XMM2 and destination memory before RET. Thus normal-return
RAX is the original destination pointer; writing ECX does not affect it.

The `.got` slot at VA `0x5775570` (file offset `0x5773570`) contains eight zero
file bytes. Its RELA record at file offset `0x1c7618` has symbol zero, kind 8
(`R_X86_64_RELATIVE`) and addend `0x3818d40`. With the normal relocation applied,
the runtime slot is the image load bias plus the leaf address. It is not a literal
pointer in the captured file. Four aligned FF15 RIP-relative calls resolve to
this slot:

| Complete caller FDE | Bytes / instructions | Call sites |
| --- | ---: | --- |
| `[0x326b090, 0x326cfb3)` | 7,971 / 1,455 | `0x326b4b1`, `0x326b9b5`, `0x326c50d` |
| `[0x3284c70, 0x3284d85)` | 277 / 66 | `0x3284c87` |

Both complete caller bodies, their CIE/FDE records and both decoder exports are
bound in `static.json`. Caller1 body SHA-256 is
`f4bb1602abd69472ac9080331d5d9600593a3e8ae9ea7aaa6709497c2b0d7662`;
caller2 is `acbb6844cc39474c2835d9fe0b4b94531142ed971db1676afd6c3d5e790b1287`.
The whole `.text` byte scan finds no E8-relative call candidate to the leaf,
exactly these four FF15 candidates to the slot, and no FF25 candidate to it.
Instruction alignment is separately checked within the full caller decodes.
This is a bounded encoding/reference census, not an exhaustive indirect-call
census. The caller LSDAs are recorded but their exception paths, helper semantics,
other data and application purpose are outside the claim.

All 80,300 RELA records are parsed; the five encountered kinds (1, 6, 7, 8, 18)
have eight-byte destinations for this check. No relocation overlaps protected
leaf/padding/caller code. The selected GOT relocation is the only parsed record
whose addend equals the entry address. The meaning of other references, source
types, vtables and library provenance is not inferred from that observation.

## SIMD reversal for all byte values

Number register bytes from low to high as `b0,...,b15`. PXOR clears XMM1.
PUNPCKLBW and PUNPCKHBW interleave the low and high eight bytes with zero bytes,
giving word vectors `[b0,...,b7]` and `[b8,...,b15]`, respectively. Every word lies
in `[0,255]`.

For either eight-word vector `w`, PSHUFD immediate `0x4e` selects doublewords
`[2,3,0,1]`, hence words `[w4,w5,w6,w7,w0,w1,w2,w3]`. PSHUFLW `0x1b` reverses
the low four words, and PSHUFHW `0x1b` reverses the high four. The result is
`[w7,w6,w5,w4,w3,w2,w1,w0]`. PACKUSWB takes the reversed high-half words from
XMM0 followed by the reversed low-half words from XMM2, producing
`[b15,b14,...,b0]`. Signed-word to unsigned-byte saturation changes no value,
because all words remain in `[0,255]`. XMM1 stays zero for the second identical
sequence. This establishes a full 16-byte reversal for either load, independent
of byte values. Instruction definitions are in Intel's
[Software Developer's Manual, Volume 2](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html),
under PUNPCKLBW/HBW, PSHUFD, PSHUFLW/HW and PACKUSWB.

## Ordered memory transformation, including aliasing

Let `s` and `d` be source and destination offsets in one memory array `M`. The
complete body has four load/store stages:

| Stage | Read interval | Write interval | Mapping of write offset `j` |
| --- | --- | --- | --- |
| 0 | `[s+48,s+52)` | `[d+16,d+20)` | read `s+48+j` |
| 1 | `[s+32,s+48)` | `[d,d+16)` | read `s+32+j` |
| 2 | `[s+16,s+32)` | `[d+20,d+36)` | read `s+31-j` |
| 3 | `[s,s+16)` | `[d+36,d+52)` | read `s+15-j` |

Each complete load enters registers before its corresponding store. Its bytes
therefore come from memory after all earlier stages and before this stage's
write. This remains true when its read/write intervals overlap. The four write
intervals partition exactly `[d,d+52)`; no other data memory is written.

For an arbitrary final position `p`, define `origin(p,k)` through the first `k`
stages. Find the largest stage `i < k` whose write interval contains `p`. If none
exists, the answer is `p`. Otherwise map `p` to its source position using the
table, then return `origin(mapped_position,i)`. Every recursive step strictly
decreases the stage number; at most four steps occur. Induction on `k` shows
that after `k` stages the byte at `p` equals the initial byte at `origin(p,k)`.
The exclusion of stage `i` from the recursive call is essential: a block cannot
read its own partial store.

This recurrence is a value-independent characterization of all alias layouts,
including disjoint ranges and every signed displacement `d-s`. Native tests
cover all 103 overlapping displacements `-51..51`, but the proof does not depend
on enumerating them. For in-place input bytes `0..51`, the final bytes are
`32..47`, `48..51`, descending `31..20`, descending `51..48`, descending `47..32`.
In particular, a snapshot of all 52 source bytes before any write is incorrect.

## Safe Rust refinement and bounds

`copy_record` first computes `s+52` and `d+52` using `checked_add`, then compares
both endpoints to the slice length. If any check fails, it returns `None` before
allocating a block or writing memory. For valid endpoints, every smaller constant
offset and block endpoint in the table is representable and at most the checked
endpoint. Therefore every subsequent addition and slice operation is valid,
including zero offsets, exact-fit ranges and the largest admitted slice offsets.
No unchecked pointer arithmetic, integer wrap, unsafe operation or arbitrary
maximum arena size is introduced.

`copy_block` snapshots one source block into a fresh fixed-size array, reverses
that array when required, then writes the destination slice. Applying it four
times in table order realizes the recurrence above. The Rust `&mut [u8]` API
allows the two offset ranges to overlap without creating aliased mutable Rust
references. The only loops are finite fixed-size copies/reversals; the function
terminates for every admitted arena. Its output is independent of byte values.

For original pointers `RDI = base+d`, `RSI = base+s` whose 52-byte ranges match
the admitted ordinary arena and whose execution returns normally, Rust has
the same final arena bytes and returns `Some(d)`, the offset projection of RAX.
It does not return the original numeric pointer. Refusal is a new safe behavior;
invalid original addresses may fault and have no corresponding `None` result.
The original leaf has no length parameter. Host tests use 64-bit `usize`; other
Rust targets admit their own representable slice/offset domain.

## Independent oracle and limits of execution evidence

`oracle.py` evaluates initial bytes at the recursively composed preimages. It
does not run memory writes, Rust copies, SIMD semantics, captured instructions
or an instruction emulator. Its interval relation is derived from the static
proof; it is independent of the Rust implementation, not an independent witness
of the captured program's execution. The input/expected streams and canonical
provenance maps were frozen while the Rust source directory did not exist.
`frozen.json` binds that oracle, the static record and target. The freeze guard
and hashes are a local chronology record, not an external timestamp attestation.

The input-only client constructs real arenas and emits all 256 backing bytes,
including bytes outside its admitted slice. Thus expected refusal, preservation,
overlap and return projections are checked independently. Finite tests support
the implementation correspondence; the argument above establishes the full byte
and alias domain. Native execution is only the newly authored Rust on the pinned
host. It establishes neither original x86 execution nor original compiler/code
generation identity, whole-caller semantics or whole-node equivalence.
