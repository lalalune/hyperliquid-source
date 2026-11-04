# RE-001: a stride-56 ring-span projection in node #115

- Component: function map; a direct callee of a quantity-source-associated body. The source association does not identify the leaf's type.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no external source revision or prior implementation is used.
- Bounded question: given the input words and valid memory, what four words does the leaf store?

**Answer.** Let `x`, `base`, `index`, and `count` be the unsigned 64-bit words at input offsets 0, 8, 16, and 24, and let all arithmetic wrap modulo 2^64. If `count` is zero, `first`, `end`, and `wrap` are zero. Otherwise set `first = index - (x if index >= x else 0)` and `remaining = x - first`. If unsigned `count > remaining`, set `end = x` and `wrap = count - remaining`; otherwise set `end = count + first` and `wrap = 0`. The function writes `base + 56*first`, `base + 56*end`, `base`, and `base + 56*wrap`, in that order, to the output and returns the output pointer. It has no callees. This is a raw register and memory relation for the entire u64 domain, including wraparound; interpreting it as a valid ring requires additional invariants.

## Evidence and instruction walk

All addresses are original ELF virtual addresses; file offsets are in `records.json`. The measured FDE is `0x4561f70..0x4561fd6`, **102 bytes**; its body SHA-256 is `8eee1c8e0290bb58ad98d136ddf7838edc84ba0a8ee6f9ea5d0f34d2f8a5466e`. The FDE at file offset/VA `0xed2d50` points to the `zR` CIE at `0xca6ed8`, with no LSDA. The following **10 bytes** up to the next indexed start `0x4561fe0` are `cc` padding. The FDE and the complete straight-line and branch decoding together support this entry/extent; unwind coverage alone does not prove function boundaries.

`records.json` contains the complete ordered walk of **34 instructions**, with every original instruction byte, address and decoded operation. The strict decoder admits only those exact encodings and checks all branch targets land on instruction starts. In the walk:

- `0x4561f70..0x4561f7c` retains the output pointer, reads `count`, and branches to the zero case when it is zero. That case clears all three indices.
- `0x4561f7c..0x4561f95` loads `x` and `index`; unsigned `cmp`/`cmovae` selects either `x` or zero for subtraction. It then computes `remaining = x-first` with ordinary wrapping subtraction.
- `0x4561f95..0x4561fad` subtracts `remaining` from `count`. `ja` means both no borrow and nonzero result, i.e. unsigned `count > remaining`; this preserves `x` as `end` and the difference as `wrap`. The other branch sets `end = count+first` and clears `wrap`. Equality belongs to the latter branch.
- `0x4561fad..0x4561fd6` loads `base`, multiplies each index by 56 using the low 64-bit result, adds `base`, writes the four output words, and returns. There are no direct or indirect calls or tail transfers in this body.

The full `.text` byte-by-byte `e8`/`e9` signed-rel32 scan yields **1 candidate**, the direct call at `0x3c15671`. The short conditional branch at `0x3c1560f` targets `0x3c15665`; the locally decoded setup there advances RSI by `0xa0` and points RDI at a stack slot before that call. The caller's indexed FDE is `0x3c154d0..0x3c15802`; a separate RIP-relative LEA at `0x3c15756` references a relocated Location for `l1/src/qtys/impl_ntl.rs:682:1`. This is evidence of a shared caller body, not proof that the leaf belongs to that source file. The scan includes false positives from instruction interiors in general; this one candidate is supported by its local instruction bytes. Indirect, dynamic, and non-`.text` callers are not enumerated.

## Novelty check

Before analysis, this search for both forms returned no matches (exit status 1), including the adjacent PR title lists:

```sh
rg -i '4561f70|72753008' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

There are no callee addresses to check. These searches cover the available local lists, not unlisted or later work.

## Reproduce and controls

From the repository root, with the authenticated artifact materialized, Python 3.10 or newer and no network or captured executable invocation:

```sh
python3 tools/node115_ring_spans.py --out research/work-items/RE-001-node115-ring-spans/
python3 -m unittest tests.test_node115_ring_spans -v
python3 research/work-items/RE-001-node115-ring-spans/verify.py
make verify
make catalogue-check
```

The producer checks the entire binary size and digest before reading evidence or writing output. It independently decodes the fixed supported instruction encodings, FDE/CIE and relative transfers, scans `.text`, and emits the semantic JSON and manifest. The authored README and verifier are copied from this packet when generating to another directory. No objdump is used by the producer, verifier, or tests. Test controls reject wrong digest, changed body byte, shifted FDE, altered branch and caller targets, and packet/manifest corruption. The model is independently written from the instruction relation; vectors test zero, exact boundary, split, wrapping and unsigned extremes. They are static deductions, not captured-node execution.

## Limits and next step

Assume the input words are readable, output stores are valid, and input/output do not alias in a way that changes future loads; normal return and no memory faults are assumed. No original Rust name, ABI type, production input invariant, allocation validity, ownership, application-level quantity meaning, full caller behavior or runtime equivalence is claimed. No source build or binary comparison was attempted; helper, relocation, vtable/data and whole-ELF closure remain open, with no normalization masks or component gate claimed. All code and analysis here are independently authored under the repository's MIT license. Next, establish the caller's input invariants and use of the four returned words before assigning this projection a concrete collection type.
