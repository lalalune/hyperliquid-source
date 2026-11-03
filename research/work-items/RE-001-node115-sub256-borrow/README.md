# RE-001: node #115 unsigned subtraction with final borrow

Task/component: RE-001 function binding; foundation arithmetic used by a
quantity-associated caller. Source/reference base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. New Python and
prose are independently authored under the repository MIT license. Existing
ELF/FDE parsers are reused unchanged; no inferred source implementation is copied.

**Bounded question:** what does the complete leaf at `0x2ccdd80` compute
and write, and does its final byte mean unsigned borrow or signed overflow?

**Answer:** for valid, stable, pairwise-disjoint buffers, interpret the
4 little-endian 64-bit limbs at RSI and RDX as unsigned
integers A and B. The function overwrites RSI with `(A-B) mod 2**256`,
copies that result to RDI, and writes `int(A < B)` at RDI+32.
It wraps on underflow and reports the borrow; it neither saturates nor panics.
The 14-instruction body has 0 callees and
0 indirect transfers. The arithmetic theorem covers the
entire function under the stated memory premises, without opaque helpers.

## Target, extent and bytes

Target: `artifacts/node/115/hl-node`, 105896032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Every record belongs to this digest; public
generation rejects any mismatch before parsing or creating output.
Addresses are original linked ELF VAs, with half-open ranges. The window is
`0x2ccdd80..0x2ccddb1`, 49 bytes, at file offset `0x2cccd80`.
Body SHA-256: `ddc8e1d31bf3e406e23cd98cc4d8f38975b0d0d0a54b4db2dedbbe9dfa7fdb91`. Actual FDE VA/file offset:
`0xd8b2b8` / `0xd8b2b8`; CIE VA/file offset:
`0xca6ed8` / `0xca6ed8`. The CIE uses
`zR`/PC-relative signed displacement encoding; the FDE has no LSDA.
Its raw records and unwind-header link are retained and checked.
The trailing `0x2ccddb1..0x2ccddc0` interval is
15 INT3 bytes outside the body. A complete straight-line
decode from the indexed entry ends at RET exactly at the FDE end. This is
stronger evidence of this local extent than an unwind-start interval alone.

| Measurement | Count |
| --- | ---: |
| bound_functions | 1 |
| body_bytes | 49 |
| decoded_instructions | 14 |
| callees | 0 |
| indirect_transfers | 0 |
| direct_call_sites | 3 |
| direct_tail_sites | 0 |
| caller_fdes | 1 |
| padding_bytes | 15 |
| vectors | 289 |
| text_bytes_scanned | 83719936 |

These are packet denominators, not node coverage or acceptance gates.
The vector count is the Cartesian boundary set recorded in `records.json`.

## Instruction walk and rule proof

| VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2ccdd80` | `488b02` | mov rax, 64-bit [rdx+0] |
| `0x2ccdd83` | `482906` | sub 64-bit [rsi+0], rax |
| `0x2ccdd86` | `488b4208` | mov rax, 64-bit [rdx+8] |
| `0x2ccdd8a` | `48194608` | sbb 64-bit [rsi+8], rax |
| `0x2ccdd8e` | `488b4210` | mov rax, 64-bit [rdx+16] |
| `0x2ccdd92` | `48194610` | sbb 64-bit [rsi+16], rax |
| `0x2ccdd96` | `488b4218` | mov rax, 64-bit [rdx+24] |
| `0x2ccdd9a` | `48194618` | sbb 64-bit [rsi+24], rax |
| `0x2ccdd9e` | `0f1006` | movups xmm0, 128-bit [rsi+0] |
| `0x2ccdda1` | `0f1107` | movups 128-bit [rdi+0], xmm0 |
| `0x2ccdda4` | `0f104610` | movups xmm0, 128-bit [rsi+16] |
| `0x2ccdda8` | `0f114710` | movups 128-bit [rdi+16], xmm0 |
| `0x2ccddac` | `0f924720` | setb 8-bit [rdi+32] |
| `0x2ccddb0` | `c3` | ret  |

Let `W=2**64`. For each ascending limb, the memory SUB/SBB writes
`d_i=(a_i-b_i-c_i) mod W`, with incoming borrow zero for SUB and the preceding
carry flag for SBB. The outgoing carry is `c_(i+1)=int(a_i < b_i+c_i)`.
MOV between arithmetic instructions preserves flags. Summing
`a_i-b_i-c_i=d_i-W*c_(i+1)` after multiplication by the limb place values
cancels all internal borrows. Therefore `A-B=D-W**4*c_final`.
Since D is in the unsigned range, `c_final` is exactly `int(A < B)`.
This also covers the maximal subtrahend limb with an incoming borrow;
`b_i+c_i` is a mathematical integer and must not be prematurely wrapped.

The unaligned vector moves copy the completed left buffer in ascending blocks
at offsets 0, 16. They preserve flags,
so SETB stores the final arithmetic carry at output+32.
No signed-overflow test, saturation branch, data table, relocation or callee
is involved in the leaf. Incoming carry is irrelevant because SUB initializes it.
RAX retains the last loaded right limb; the integer result is in memory.
Writable left memory is essential even when only the output is wanted.

The buffer premises are readable right and readable/writable left ranges of
32 bytes, a writable output range of
33 bytes, valid return stack, and ordinary stable
memory. Buffers must not overlap executable code or the return-address slot.
Partial overlaps are outside the theorem: sequential source loads,
in-place writes and vector copies can change later reads. Other bytes are not
explicitly written by the leaf. This is a machine-level buffer contract, not
an assertion about Rust alias rules, type layout or the caller's public API.

`model()` uses independent whole-integer subtraction/modulo. The recorded vectors
come from the decoded limb equations, including each limb boundary, long borrow
propagation, equality, zero, high-bit and unsigned-maximum neighbors. The algebra
above proves the full domain; the fixtures check the independent formulation.
Tests additionally replace actual SBB with SUB and SETB with SETAE: the equations
change on distinguishing inputs before the semantic certificate rejects them.

## Callers and first-party context

The producer scans every eligible byte position in the complete `.text` range
`0x1419300..0x63f0a00`
for E8/E9 signed rel32 targets. The raw candidates are `0x2c70e23`, `0x2c70e87`, `0x2c70eca`; all are CALLs
inside FDE `0x2c70160..0x2c70fd9`. There are
0 E9 candidates. Raw bytes, source file offsets, owner
FDE/CIE and focused instruction contexts are retained. Every context decodes
the stack-buffer LEAs, direct CALL, output-borrow comparison and nonzero branch.
Those stack ranges are disjoint, and the compared byte is exactly the leaf's
output borrow byte. The taken edge is recorded without assigning final caller
success/error meaning.

The same caller FDE contains a decoded RIP-relative LEA at `0x2c70f64`
to Location `0x6487478`. Its symbol-zero RELATIVE relocation, path bytes,
length and line/column bind `l1/src/qtys/impl_wei.rs:6:1`.
This supplies a first-party quantity association for the direct caller. It does
not recover the leaf's original name, crate, Rust integer type or financial units.

The census is deliberately qualified: a raw E8/E9 scan is not a global
instruction-boundary proof. The focused sequences were also inspected in native
static disassembly, but the reproducible certificate only decodes these bounded
contexts, not the complete caller CFG. Indirect/address-taken references, runtime
reachability and callers outside `.text` remain unmeasured. Callee identities
and extents are an empty set because the complete leaf has no call or jump.

## Novelty preflight

Before creating this packet, at the source base above, these exact commands
each returned empty stdout, empty stderr and exit status 1 (no matches):

```sh
rg -i 2ccdd80 research/
rg -i 46980480 research/
rg -i 2ccdd80 ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 46980480 ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The entry lies inside the assigned address band and is absent from the supplied
claimed-address list. There are no callee behavior bindings requiring another
novelty check. The commands naturally match this packet after it is added.
The PR-list snapshots were local review inputs; no online PR check is claimed.

## Reproduce and controls

Run from the repository root with the authenticated capture materialized:

```sh
python3 tools/node115_sub256_borrow.py --out research/work-items/RE-001-node115-sub256-borrow/
python3 -m unittest tests.test_node115_sub256_borrow -v
python3 research/work-items/RE-001-node115-sub256-borrow/verify.py
make verify
make catalogue-check
```

Python 3.10+ standard library only; validated locally on Linux x86-64 with
Python 3.13.5. Initial exploration used GNU objdump 2.44 in a bounded static
export under ignored `work/`; it is not a generator, verifier or test dependency.
No connected REA provider was available. ELF bytes are read through one mmap;
mutant controls use private copy-on-write pages. No captured code is executed.
No network, installs, Rust build, hosted CI or container run is involved.
`records.json` and this README regenerate byte-identically; the manifest also
pins producer, verifier, tests and the unchanged ELF/FDE parser dependencies.
The verifier uses an exact manifest whitelist and compares regenerated evidence.

Controls include wrong/truncated input, actual instruction-byte mutations below
the digest gate, shifted FDE bounds, changed frame bytes, wrong CALL target,
changed argument/borrow operands, source metadata/relocation corruption, scan
end boundaries and manifest tampering. README counts are checked against JSON;
the complete README is also compared with its deterministic renderer. Static
instruction equations are not target execution or differential runtime testing.

## Status, non-claims and next step

Before: no function bind at the novelty-checked entry. After: its full bytes,
extent, carry semantics, in-place effects and output contract are bound to the
target, with a reproducible direct-call candidate census and source association.
Observation: decoded operations and bytes. Inference: the unsigned arithmetic
rule follows under the explicit buffer premises. Unresolved: original symbol,
source ownership, API, units, caller reachability and partial-alias behavior.

No Rust reconstruction, compiled-byte equivalence, full caller behavior,
whole-ELF equivalence, protocol correctness, source-built node or component gate
is claimed. There are no normalization masks, helper closure gaps or data-table
dependencies in the leaf; whole-program call/data/relocation integration remains
open. Existing evidence, source pins, progress and catalogue files are unchanged.
Next: trace the caller's operand construction and borrow branch to establish
which quantity operation uses this subtraction and what rejection it causes.
