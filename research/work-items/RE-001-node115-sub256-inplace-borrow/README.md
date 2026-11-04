# RE-001: node #115 in-place unsigned wide subtraction with borrow

Component: foundation. Task: RE-001 function bind. Target: Linux x86-64 node
#115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base/source revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
New producer, model, tests and documentation are independently authored under
the repository MIT license; no inferred source or dependency implementation was
copied. Imported evidence, pins and progress gates are unchanged.

**Question:** What does the previously unbound function at `0x43be060` compute,
which operand does it mutate, and how does it report unsigned underflow?

**Answer:** For disjoint valid buffers, RDI is an output pointer, RSI points to
a mutable unsigned 256-bit left operand, and RDX points to an unsigned 256-bit
right operand, represented as little-endian 64-bit limbs. The function writes
`D = (left - right) mod 2^256` into the left buffer, copies D into output
bytes `[0,32)`, and writes `left < right` as a byte at output offset `32`.
It performs these writes even on underflow: this is wrapping subtraction with
a separate borrow flag. RAX is left holding the original most significant
right limb; that is a machine observation, not an asserted Rust return type.

## Scope, extents and measured counts

All addresses are original ELF virtual addresses, with half-open extents.
The selected function is `[0x43be060,0x43be091)`, file offset `0x43bd060`.
Its body SHA-256 is
`ddc8e1d31bf3e406e23cd98cc4d8f38975b0d0d0a54b4db2dedbbe9dfa7fdb91`.
The actual FDE is at VA/file offset `0xea5568`, CIE at VA/file offset
`0xca6ed8`. The CIE uses `zR`, PC-relative signed-word encoding, code alignment
`1` and data alignment `-8`; the FDE has no LSDA. Its encoded range ends just
after RET, agreeing with the complete instruction walk. The next FDE starts
at `0x43be0a0`; the intervening `[0x43be091,0x43be0a0)` is all `cc`/INT3 and
is excluded from the body. This combines unwind metadata, decoded straight-line
control flow and padding; executable-section membership alone is not a boundary.

The denominator below is this leaf, its explicitly labeled caller context,
and the specified scan interval. It is not a whole-node function denominator.
Every count in this packet's README is in the following JSON-derived table;
the targeted test and verifier require exact agreement with `records.json`.

<!-- counts-from-records -->
| Metric | Count |
| --- | ---: |
| callees | 0 |
| caller_context_bytes | 1332 |
| caller_context_instructions | 251 |
| caller_owners | 1 |
| direct_call_sites | 2 |
| direct_tail_sites | 0 |
| function_bytes | 49 |
| indirect_transfers | 0 |
| instructions | 14 |
| padding_bytes | 15 |
| scan_bytes | 83719936 |
| vectors | 36 |
<!-- end-counts -->

## Instruction walk and proof

The raw body, raw FDE/CIE, typed operands and every instruction's address, size
and original bytes are in `records.json`. No byte or operand is normalized.
The producer decodes the complete leaf with a restricted Python x86 decoder;
it rejects unsupported/truncated instructions instead of skipping them.

| VA | Bytes | Decoded operation |
| --- | --- | --- |
| `0x43be060` | `48 8b 02` | `mov rax, qword [rdx]` |
| `0x43be063` | `48 29 06` | `sub qword [rsi], rax` |
| `0x43be066` | `48 8b 42 08` | `mov rax, qword [rdx+8]` |
| `0x43be06a` | `48 19 46 08` | `sbb qword [rsi+8], rax` |
| `0x43be06e` | `48 8b 42 10` | `mov rax, qword [rdx+16]` |
| `0x43be072` | `48 19 46 10` | `sbb qword [rsi+16], rax` |
| `0x43be076` | `48 8b 42 18` | `mov rax, qword [rdx+24]` |
| `0x43be07a` | `48 19 46 18` | `sbb qword [rsi+24], rax` |
| `0x43be07e` | `0f 10 06` | `movups xmm0, [rsi]` |
| `0x43be081` | `0f 11 07` | `movups [rdi], xmm0` |
| `0x43be084` | `0f 10 46 10` | `movups xmm0, [rsi+16]` |
| `0x43be088` | `0f 11 47 10` | `movups [rdi+16], xmm0` |
| `0x43be08c` | `0f 92 47 20` | `setb byte [rdi+32]` |
| `0x43be090` | `c3` | `ret` |

Let `M=2^64`, with original limbs `a_i,b_i` in `[0,M)`, and let `c_0=0`.
The first SUB and subsequent SBBs implement
`d_i=(a_i-b_i-c_i) mod M` and
`c_(i+1)=[a_i < b_i+c_i]`. MOV preserves the incoming carry between limbs.
For each step,
`a_i-b_i-c_i = d_i-M*c_(i+1)`; multiplying by `M^i` and summing telescopes to
`A-B = D-2^256*c_4`. Since D is in `[0,2^256)` and carry is Boolean,
`c_4=[A<B]`. This proves the wrapping result and borrow over the entire stated
input domain, including when `b_i` is all ones and the incoming borrow is set.

The SIMD moves copy the already mutated left buffer in ascending half order.
They do not change flags, so SETB writes the final SBB carry. XMM0 ends with
the high half of D. No arithmetic result is placed in RAX after the final
right-limb load. RSI/RDI/RDX are not changed. Apart from the documented memory,
RAX, XMM0 and arithmetic flags, the body only has the normal RET stack effect.
The buffer theorem assumes readable right storage, readable/writable left
storage, writable output including its borrow byte, a valid return stack,
disjoint ranges, and no concurrent mutation. It does not claim the same
integer relation for partially overlapping buffers or faulting accesses.

Callee identity/extent closure is vacuous for the selected leaf: the complete
walk contains no call, tail transfer, indirect dispatch or global data load.
Its dependencies are memory validity and ordinary x86 instruction semantics,
not an opaque arithmetic helper.

## Direct caller census and source association

`scan_rel32` examines every byte position in `.text`
`[0x1419300,0x63f0a00)` for `e8`/`e9` and computes
`site+5+signed_little_endian_rel32`. It does not begin by assuming instruction
boundaries. All matches are subsequently confirmed by decoding the entire
containing FDE from its entry; every local branch target in that caller also
lands at a decoded instruction boundary. The scanner handles the last complete
relative instruction without reading beyond `.text`. Byte-interior matches
would not silently acquire caller status.

| Call site | Caller FDE | Left stack buffer | Right stack buffer | Output |
| --- | --- | --- | --- | --- |
| `0x4353cf6` | `[0x4353990,0x4353ec4)` | `rsp+0xe0` | `rsp+0xb0` | `rsp+0x30` |
| `0x4353db7` | `[0x4353990,0x4353ec4)` | `rsp+0xb0` | `rsp+0x160` | `rsp+0x30` |

The shared output LEA is at `0x4353cdb`. The branch at `0x4353ce0` reaches the
second setup without changing RDI. These stack regions are disjoint. Each call
is followed by `cmp byte [rsp+0x50],0` and JNE to `0x4353d74`, consuming exactly
the flag at output `+0x20`. This is immediate use evidence, not a reconstruction
of the caller's broader success/failure contract or its other helpers.

The caller's FDE is at `0xe9e4f8`, with the same CIE as the leaf. Its full raw
body and SHA-256 are retained as context. At `0x4353eb7`, a decoded RIP-relative
LEA selects Location `0x64768d8`. The actual `R_X86_64_RELATIVE` record at file
offset `0xa2a08` supplies path VA `0x432b6f`; the Location's length and line/column
resolve exactly to `l1/src/spot_meta.rs:119:33`. The capture contains a relative
source path here. The raw Location and relocation bytes are retained and checked.
This supplies a direct first-party caller association. It does **not** establish
that the leaf itself was authored first-party; it could be a dependency
instantiation. Symbol-proximity labels from native disassemblers are not names.

The caller is decoded to establish boundaries and the observations above. Its
other callees, indirect targets, arithmetic policy and original types remain
unbound. None is included in the selected leaf's callee closure or claimed as
another behavior bind. The census excludes indirect callers, address-taken
references, other executable sections and dynamically reachable paths.

## Novelty check before investment

At the base revision, before adding this packet, the following exact searches
returned exit status `1`, empty stdout and empty stderr:

```sh
rg -i 43be060 research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 71032928 research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

No previously bound callee behavior is adopted. The selected start is inside
the assigned band and outside the excluded or claimed addresses. These checks
are historical selection evidence: rerunning them now will find this packet.
The local title-list snapshots had the following SHA-256 values:

| Snapshot | SHA-256 |
| --- | --- |
| `../open_prs.txt` | `83b29058afc8074477713a58deced1e3b9f4e4ee61e8c9c62fdd871ab0b785b8` |
| `../merged_prs.txt` | `80cd2adad0142c40c0b26e47d29cbbcc4e1b37b8f0611aba9cddd87651ab5cbd` |
| `../closed_unmerged_prs.txt` | `c2688622e486965bc44d14e12efe1ad80ed79745b43990d376ee8f9a35dd6a15` |

## Reproduce and negative controls

Platform used: Linux x86-64; Python 3.13.5. The producer, verifier and tests use
Python 3.10+ standard library only, plus the repository's unchanged
`elf_index.py` and `fde_extents.py`, whose hashes are in the closed manifest.
GNU objdump 2.44 was used only for initial manual scouting; no generator,
verifier or test invokes it. There was no connected REA provider or available
Ghidra in this environment. Analysis is complete for the selected leaf and
bounded caller decoding, with no decompiler or timeout-derived result.

The active RE-001 blocker was the lack of a machine-checkable contract for this
leaf. Existing ELF/FDE parsers supply geometry but do not decode this function's
borrow chain or validate its caller boundaries. The added tool is the bounded
certificate for that question; no shared analysis infrastructure is changed.

From the repository root, after materializing the authenticated capture:

```sh
python3 tools/node115_sub256_inplace_borrow.py --out research/work-items/RE-001-node115-sub256-inplace-borrow/
python3 -m unittest tests.test_node115_sub256_inplace_borrow -v
python3 research/work-items/RE-001-node115-sub256-inplace-borrow/verify.py
make verify
make catalogue-check
```

`records.json` is regenerated byte-identically from the authenticated capture;
README, verifier and manifest are reviewed supporting files. The manifest also
pins producer, tests and unchanged parser dependencies. The verifier admits
only its explicit filenames, rejects missing/duplicate/unlisted entries and
checks README counts. The producer checks the entire target digest before
parsing or creating output. A read-only mapping avoids redundant whole-image
copies; corruption tests use a private copy-on-write mapping and restore bytes.

The integer model uses unbounded Python arithmetic. The separate extracted
limb recurrence agrees with instruction-derived boundary vectors and seeded
wide samples. The vectors include equality, unsigned extremes and borrow
propagation across limb boundaries. This supports the algebraic proof; it is
not differential execution of the target. Actual operand counterfacts change
SBB to SUB, SETB to SETAE, and a right-limb offset, demonstrate changed results,
and are then rejected by the semantic checker below the digest gate. Other
controls reject every selected-body byte flip, truncation, unsupported decode,
shifted FDE start/length, CIE changes, a retargeted actual caller CALL, changed
Location/relocation/path, changed padding and an injected extra scan hit.

Local targeted tests, packet verification, `make verify` and
`make catalogue-check` passed. `make doctor` reported static analysis ready;
exact rebuilding is unavailable. Repository-wide `make test` was not run.
No inventory or literal-analysis output was changed or reinterpreted; the
Location is read directly from the authenticated ELF. No catalogue regeneration
or progress/gate edit is requested.

## Results, non-claims and next step

Before: no retained bind for the selected start in the searched research and
PR-title snapshots. After: the complete leaf's arithmetic, mutation, output
layout and carry flag are byte-bound, and its direct call sites have validated
boundaries plus first-party source context. The strong result is this local
memory/arithmetic theorem, not recovery of an enclosing asset operation.

No original function name, Rust type/ABI, first-party leaf authorship, complete
caller semantics, allocation/unwind closure of the caller, source-built Rust
implementation, compiled byte comparison, ABI integration, timing guarantee,
whole-ELF equivalence, protocol behavior or component gate is claimed.
Rust/Cargo/compiler comparison fields are not yet implemented/measured.
There are no normalization masks, reconstructed machine-code substitutions,
captured execution, network requests, installations, live chain actions or
hosted CI results in this work. No failed validation remains at submission.

Next question: identify the provenance and units of the wide stack operands
at these call sites, and close their producer helpers before assigning asset
or protocol meaning to the subtraction.
