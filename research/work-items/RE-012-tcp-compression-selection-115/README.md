# RE-012: node #115 TCP compression selection and framing handoff

Component: transport. Target: Linux x86-64 node #115, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `05bc2de303c05525b71e7e257426e741bc66a390`. Addresses are ELF VAs,
without rebasing or byte masks. New research is MIT; no inferred reference
source, public codec implementation or captured-code execution was used.

## Question and contribution

When does the selected TCP sender choose the compressed payload, which
compression entry does it call, and how does that choice reach the wire prefix?

The base's `RE-012-node115-tcp-prefix` packet explicitly leaves the producer of
R15B and the selected payload unresolved, identifying slot `0x64e7798` as a
helper lead. `RE-012-lz4-decode-115` also leaves the writer selection open.
This packet resolves that **caller-side adapter**, including the actual two
codec bindings, its allocation and error boundaries, and its marker handoff.
It does not reconstruct a compressor. Shared sender bytes were already
exported by the prefix, deadline and write-progress packets; exporting them
again earns no additional coverage. An inspected inventory of 121 open PRs
on 2026-11-04 contained no competing compression-selection task; no open
non-PR issues were returned. No issue was created or claimed.

## Observed eligibility and retained state

At `0x2b7a2ca`, the initial selected arm reads a context pointer from object
`+0x10`, input pointer from `+0x18`, and input length **n** from `+0x20`.
The first slot of the signed-relative dispatch table at `0x604cbc` names this
arm. The predicate at `0x2b7a2de..0x2b7a2fe` is:

```
n >= 1025 AND (((context_dword_at_0x90 - 4000) mod 65536) < 65534)
```

`SETAE` uses the unsigned qword length comparison. The field is initially read
as a DWORD, but `CMP SI, -2` and `SETB` examine only its low 16 bits. Thus the
second conjunct is exactly **low16(field) not in {3998, 3999}**, regardless
of the high 16 bits. The original field's type/name and the origins of these
two excluded values are **unknown**; they are not asserted to be ports,
message tags or negotiated versions.

The computed boolean is saved to object `+0x308`. The selected restored arm
at `0x2b7a480` reloads it, and `CMP DL,1` at `0x2b7a4a9` accepts exactly one.
This is a statement about those two arms, not arbitrary future-state validity.
The complete state machine and all table entries remain outside this packet.
The bypass at `0x2b7a4bc` sets R15D to zero and reaches the payload join with
the original pointer and count. It does not invoke either codec.

## Allocation, prefix and the two real codec entries

On the enabled path, `0x2b7a366` multiplies n by 110, with an overflow branch.
Let **q = floor(110*n/100)** when that checked multiply succeeds. The caller
requests **q+24** bytes, writes the low 32 bits of n to the first four bytes
in **little-endian** order, and presents a sink beginning at allocation+4,
with capacity **q+20** and initial position zero.

The reciprocal sequence at `0x2b7a377..0x2b7a38b` does calculate the stated
quotient for every successful checked product, not just the small fixtures:
for x=110*n, z=floor(x/4), M=`0x28f5c28f5c28f5c3`, its output is
floor(z*M/2^66). Since 25*M=2^66+11 and z<2^62, the extra fraction is less
than 11/400, which is less than 1/25. It cannot carry any of the 25 residue
classes across an integer. Therefore the result is floor(z/25)=floor(x/100).
The largest multiply-admissible n is 167,697,673,397,359,560; this algebraic
bound is not a claim that such a slice can be allocated.

| Input length, assuming eligibility | Scratch request | Call site / RELATIVE slot | Complete callee FDE |
| --- | ---: | --- | --- |
| n < 65,535 | 8,192 bytes | `0x2b7a433` / `0x64e77a0` | `0x477e950..0x477f036` |
| n >= 65,535 | 16,384 bytes | `0x2b7a562` / `0x64e77a8` | `0x477f040..0x477f746` |

Both calls receive the original pointer/count, zero in EDX, the sink descriptor,
the scratch descriptor and one in R9D. Both entry prologues check remaining
sink capacity against their same q+20 requirement. Their insufficient-capacity
arms return RAX=1. The table entry widths and full match-finding/encoding
algorithms are deliberately not inferred merely from scratch allocation sizes.

Relocated source Locations at `0x644ac38`, `0x644ac50`, and `0x644ac68`
name the captured build path ending in `z_vendor/lz4_flex/src/block/compress.rs`,
at 629:15, 680:18 and 682:29. They support the LZ4 compression attribution,
not an exact crate revision, unmodified public dependency or recovered source.
The adjacent sender Location at `0x644b020` names `net_utils/src/tcp/write.rs:34:17`.

## Result, failure and wire handoff

After scratch release, the caller compares the retained helper RAX with one
at `0x2b7a583`. Equality enters `0x2b7a8b3`: it supplies the literal
`called Result::unwrap() on an Err value` (with the captured backticks retained
in `records.json`), plus the compress.rs:680:18 Location, to the call through
`0x64df6a0`. This is an **unwrap failure path**, not a raw-payload fallback.
The panic helper's implementation and unwind effects remain unclosed.

On the non-one return path, let k be the retained RDX. The code checks k+4
for overflow, then chooses **L=min(k+4,q+24)**. If L is below allocation size,
it calls a resize helper; allocation failures have separate paths. Describing
this as an unconditional k+4 length would omit the caller's clamp. Whether a
valid codec success can exceed the allocation is not established here.

After the timing/statistics calls normally return, `0x2b7a68a` sets R15B=1,
and `0x2b7a69c` moves the selected compressed length into R13 and its buffer
pointer into R12. There is **no caller-level comparison of compressed length
against original length that chooses the raw payload** along this success
path. This observation is conditional on normal helper returns and the
retained buffer not being invalidated; it does not close arbitrary helper
aliasing, failure or allocation behavior.

Both paths meet at `0x2b7a6a9`. The already-studied framing handoff rejects a
selected count above u32, writes the selected count big-endian at bytes 0..3,
and writes R15B at byte 4. Thus the enabled-success payload has an **inner
little-endian original-length prefix** while its outer five-byte frame uses a
**big-endian selected-payload length and marker one**. The disabled path uses
the original payload and marker zero. Actual bytes produced by either codec,
socket writes, interoperability and receiver equivalence are not tested here.

## Correcting the helper lead

Slot `0x64e7798` resolves uniquely to `0x47855c0..0x4785a0a`, not either
codec above. At its selected call, RSI is original n and RDX is L. Its first
three updates are `LOCK ADD [*arg0+0x10], RSI`,
`LOCK ADD [*(arg0+8)+0x10], RDX`, and
`LOCK INC [*(arg0+16)+0x10]`. It also receives elapsed-time data in XMM0.
These concrete counter updates support the **statistics/telemetry** label.
Its later lookup/logging behavior, concurrent ownership and entire side-effect
set are not reconstructed. It cannot be treated as a pure compression oracle.

## Evidence and reproduction

The four complete FDE exports total **9,417 bytes / 1,958 instructions**:
sender 4,755/914, small codec 1,766/401, large codec 1,798/408, statistics
1,098/235. These are export sizes, not understood/reconstructed byte counts.
`records.json` binds all four hashes, exact FDE/CIE records, LSDA addresses,
154 calls, 260 direct branches, 34 selected instruction obligations, actual
relocation writers and the selected source Locations. Indirect branches,
type/action tables, LSDA execution and unexamined callees remain boundaries.

`collect.py` reauthenticates the capture, rejects overlapping FDEs and checks
the complete instruction partitions against GNU objdump and LLVM objdump.
LLVM prints ten LOCK prefixes as separate rows; only those literal prefixes
are joined with their contiguous instruction for partition comparison. No
bytes are masked or normalized. Raw native output is retained. GNU readelf
independently confirms the four ranges. `tools.json` records actual versions.

From repository root, with Python, Capstone 5.0.7, GNU binutils and LLVM:

```sh
python3 -B research/work-items/RE-012-tcp-compression-selection-115/collect.py --out work/tcp-selection-fresh
diff -u research/work-items/RE-012-tcp-compression-selection-115/records.json work/tcp-selection-fresh/records.json
python3 -B research/work-items/RE-012-tcp-compression-selection-115/verify.py --out work/tcp-selection-check.json
make doctor verify test catalogue-check reproduce
```

The focused verifier regenerates the retained record; rejects one actual-byte
mutation per obligation **without relying on the full-file hash guard**;
rejects two wrong/truncated capture controls; checks all 65,536 low words,
four high words and six boundary lengths (1,572,864 integer relations); and
spot-checks the independently explained quotient proof at 21,000 inputs.
These counts describe static qualification and arithmetic, **not behavioral
differential tests, captured execution, emulation or an independent peer review**.
No new Rust implementation or compiled-code comparison is claimed.

Actual repository check outcomes are recorded in `validation.json`.
All 92 component gates and byte-comparison totals remain unchanged.
The generated README/SVG inventory advances from a stale 559 to 561: the
base already tracks 560 packet READMEs, and this PR adds exactly one. This
is a regenerated inventory correction, not two new tasks or completion credit.
Next bounded work: establish the writer context field's producer/type or
recover the two compressor loops with independently authored Rust and
target-bound fixtures; neither is silently included in this adapter result.
