# RE-001: node #115 two-field storage contract

- Task: RE-001 function mapping, supporting RE-002 dependency provenance.
- Component allocation: foundation; dependency field arithmetic, not recovered
  first-party node code.
- Target: Linux x86-64 node **#115**, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes.
- Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Bounded question: do the two storage callers, including their inlined
  arithmetic and out-of-line helpers, implement the same numeric output
  contract? What is their actual 80-byte-input/64-byte-output layout?
- Intended files: this evidence packet and the generated README/banner count.
- Status: static symbolic result under the explicit model below; original
  function names, original source/build identity and caller invariants unknown.
- Source: independently authored analysis of the authenticated instructions.
  No inferred reference source or imported C implementation is included.

Public context consulted: MIT-licensed `rust-bitcoin/rust-secp256k1` commit
`6648126c69ce8056d053cbaa22246d12c76f3fc1`, specifically
[`field_5x52_impl.h`](https://github.com/rust-bitcoin/rust-secp256k1/blob/6648126c69ce8056d053cbaa22246d12c76f3fc1/secp256k1-sys/depend/secp256k1/src/field_5x52_impl.h)
and [`group_impl.h`](https://github.com/rust-bitcoin/rust-secp256k1/blob/6648126c69ce8056d053cbaa22246d12c76f3fc1/secp256k1-sys/depend/secp256k1/src/group_impl.h).
These are interpretation context, not recovered target source identities.

## Result and gap addressed

Two complete callers implement the same two-field storage transform, despite
different register allocation, stack size, vector copies and normalization
order. This resolves their previously unproved inlined arithmetic and packing
semantics. [PR #2038](https://github.com/lalalune/hyperliquid-source/pull/2038)
motivated the question but is **not a dependency**: this packet admits the
target, extracts all four bodies and proves its claims independently of that
unmerged packet. The live PR search found no other secp storage contribution.

| Role | ELF VA interval (end exclusive) | File offset | Bytes | Instructions |
| --- | --- | --- | ---: | ---: |
| Caller A | `0x6325530..0x6325731` | `0x6324530` | 513 | 137 |
| Caller B | `0x6337d80..0x6337f8b` | `0x6336d80` | 523 | 133 |
| A's helper | `0x631d630..0x631d733` | `0x631c630` | 259 | 74 |
| B's helper | `0x632c130..0x632c233` | `0x632b130` | 259 | 74 |

The denominator is **two callers (1,036 bytes) plus their two distinct helper
extents (518 bytes)**, 418 decoded instructions in total. All have unique
matching FDE extents, complete linear decoding, executable section/PT_LOAD
membership, and an INT3 gap to the next FDE. A caller's final instruction is
its canary-failure call; its normal return immediately precedes that block.
FDEs alone are not being used as function-boundary proof.

These are semantic analyses of authenticated bytes, **not source-built byte
comparisons**. No raw-equal/normalized-only reconstruction bytes, completion
gate or byte-registry credit is requested. All 92 component gates remain false.

## Observed layout and call closure

Under the normal System V AMD64 call setup, RSI designates ten consecutive
little-endian qwords and RDI designates eight output qwords. Only input offsets
`0..79` are read. Output writes cover exactly `0..63`. Input is not written.
The two five-limb fields start at offsets `0` and `40`; their four-qword packed
outputs start at offsets `0` and `32`. No extra infinity/validity field is read
by either body. That does not prove any original enclosing structure's type.

A normalizes the first field inline and calls `0x631d630` on a stack copy of
the second at `0x632565e`. B calls `0x632c130` on a stack copy of the first at
`0x6337dbd`, then normalizes the second inline. The analysis expands each
helper's decoded transfer functions; it does not substitute a trusted summary.

The `.text` E8/E9 pattern census spans 83,719,936 bytes. All four entry
references have complete enclosing-FDE instruction-boundary confirmation:

| Site | Destination | Enclosing FDE start / length |
| --- | --- | --- |
| `0x632565e` | A's helper | `0x6325530` / 513 |
| `0x632b866` | A | `0x632b7b0` / 416 |
| `0x6337dbd` | B's helper | `0x6337d80` / 523 |
| `0x6339f41` | B | `0x6339e90` / 352 |

No E9 pattern targets these entries. This is not an indirect, short-jump,
alternate-entry or complete semantic xref census. The two outer callers are
leads, not analyzed input-magnitude contracts.

Both storage callers also have a conditional failure edge to `0x63f0d70`.
Its PLT jump resolves through GOT `0x64ee308`, whose `.rela.plt` entry is
`R_X86_64_JUMP_SLOT` for `__stack_chk_fail`. This is an external unresolved
runtime dependency on the failure path. Under stable TLS and disjoint valid
memory, the saved/reloaded canary equality is proved, making that edge
unreachable. No libc implementation or dynamic-loader behavior is proved.
No relocation applies inside any of the four analyzed code extents.

## Numeric contract

Let `B=2^52`, `L=2^48`, `C=2^32+977`, and `p=2^256-C`. Each field's five
input qwords are unsigned limbs `a[0..4]`. Define `N(a)=sum(a[i]*B^i)`.

The specification in [analyze.py](analyze.py) first folds `a[4]>>48` times
`C` into the low limb and propagates four 52-bit carries. Every intermediate
addition and multiplication wraps modulo `2^64`, exactly as in the decoded
instructions. If the resulting limbs are `t`, its final reduction selector is

```text
s = (t[4] >> 48) |
    ((t[4] == L-1) & ((t[1]&t[2]&t[3]) == B-1) & (t[0] >= B-C))
```

A second carry pass adds `(-s)&C` to the low limb, masking the first four
output limbs to 52 bits and the last to 48 bits. Call this result `F(a)`.
The final output qwords for either field are exactly

```text
q[0] = F[0]       | (F[1] << 52)
q[1] = F[1] >> 12 | (F[2] << 40)
q[2] = F[2] >> 24 | (F[3] << 28)
q[3] = F[3] >> 36 | (F[4] << 16)
```

Shifts and ORs here are 64-bit operations. Thus each output is four native
little-endian qwords, equivalently a little-endian 32-byte integer, with the
first field before the second. It is not a claim about an external wire format.

Twenty solver queries return **UNSAT**, including output disagreement for
each complete caller for **all ten unsigned u64 inputs**, preservation of the
six callee-saved GPRs, the two canary edges, packing's radix identity, and the
normalization properties below. Stack balance and untouched helper return
addresses are also checked. SAT/UNKNOWN/timeouts fail a positive proof.

For the bounded domain

```text
a[0..3] <= 64*(2^52-1)
a[4]    <= 64*(2^48-1)
```

the independent arithmetic query proves
`N(F(a)) = N(a) - ((a[4]>>48)+s)*p` and `0 <= N(F(a)) < p`.
Packing preserves this integer. Consequently each caller produces the two
unique canonical residues on this domain. This is a conditional contract:
**neither outer caller's satisfaction of these bounds is proved**.

For arbitrary u64 limbs the selector remains Boolean and the result stays
below `p`, but input congruence can fail through first-pass wrap. The retained
off-domain input `[2^64-1,0,0,0,2^48]` produces `C-1`; its mathematical residue
is `2^64+C-1`. No unsupported all-u64 modular-reduction claim is made.

## Independent checks and controls

[observed/analysis.json](observed/analysis.json) retains all admitted bytes,
instruction records, raw CIE/FDE bytes, mappings, xrefs, memory-access regions,
callee/PLT closure, solver outcomes and negative controls. Independent GNU
disassembly exports cover all four bodies and the failure PLT entry.
`disassemble.py` checks that all 418 instruction addresses, bytes and mnemonics
agree between GNU and Capstone; it does not compare operand semantics.

The integer oracle uses Python's arbitrary-precision `% p`, independently of
the bitvector normalization specification. Its **264 paired inputs / 528
caller checks** cover every one of the 256 single-bit positions, zero, `p-1`,
`p`, `p+1`, `2p-1`, `2p`, `2^256-1` and `2^256`. The full rows are retained in
[observed/analysis.boundaries.tsv](observed/analysis.boundaries.tsv).
These evaluate derived symbolic expressions, not captured instructions.

For each caller an actual encoded packing shift is changed from 52 to 53,
then decoded again. Each counterfactual returns **SAT** for output disagreement
and has an explicit input/output replay. These controls bypass digest admission
deliberately, are marked unqualified and add no target credit. Separately, a
full-image byte mutation fails target admission. Removing the magnitude bounds
has the concrete congruence counterexample above. No original input is changed.

## Reproduction and limits

From the repository root, using Python 3.13.12, `pyelftools==0.32`,
`capstone==5.0.7`, `z3-solver==4.15.4.0` and GNU objdump 2.42:

```sh
python3 research/work-items/RE-001-node115-secp-storage/analyze.py \
  --output work/new-secp-storage/analysis.json
python3 -O research/work-items/RE-001-node115-secp-storage/analyze.py \
  --output work/new-secp-storage-optimized/analysis.json
cmp work/new-secp-storage/analysis.json work/new-secp-storage-optimized/analysis.json
cmp work/new-secp-storage/analysis.boundaries.tsv work/new-secp-storage-optimized/analysis.boundaries.tsv
python3 research/work-items/RE-001-node115-secp-storage/disassemble.py \
  --output work/new-secp-storage-disassembly
make doctor
make verify catalogue-check
mkdir -p work/secp-storage-validation/tmp
TMPDIR="$PWD/work/secp-storage-validation/tmp" make test
make reproduce
```

The script performs static symbolic transfer-function construction. It has no
emulator, target process, generated executable, network access or subprocess.
It never runs a captured instruction. Each solver query has a 60-second limit;
there is no weaker fallback. [MODEL.md](MODEL.md) states the model and trust
boundary. [VALIDATION.json](VALIDATION.json) records actual repository checks.

No independent Rust implementation, full C/crate build identity, original
function name or ABI type, timing/security property, exception/unwind behavior,
curve membership or whole-node equivalence is established. Abstract disjoint
memory excludes overlap and alias behavior. No gates or comparison registry
entries change; only the generated work-item count increases.

Next: inspect the two outer caller FDEs to establish how each field is produced
and whether its magnitude stays in the admitted domain before this transform.
