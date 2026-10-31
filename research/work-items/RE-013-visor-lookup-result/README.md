# RE-013: which numerical values can the visor's skip-name lookup return?

- Component: `visor`; source base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Target: captured `artifacts/visor/captured/hl-visor`, 8,305,392 bytes,
  SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Claim: a static **normal-return low32 upper bound of `{0,1}`** for the
  lookup at `0x5d3220..0x5d3361`, with explicit control/dataflow conditions.
  The observed return cases are 0, 1 and 1; their runtime feasibility and
  termination are not proved. Whole-RAX high bits and Rust types are excluded.
- Scope: one 321-byte unwind extent; its complete retained linear decode and
  local direct-edge graph under opaque normal-return calls. The 352-byte
  probe callee is boundary/hash and selected-call metadata only.
- No captured executable, emulator, chain or networking action is run.
  No progress or completion gate is requested.

[PR #988](https://github.com/lalalune/hyperliquid-source/pull/988), frozen head
`0e24c1be56d8bfcfaa58951f4e263a7fee024b6a`, binds a call with the exact
13-byte `skip-download` name and follows its EAX result into a stored byte.
That packet deliberately leaves the lookup's return domain unqualified.
This closes that specific numerical question. It does not repeat #988's
constructor/extraction work or [#45](https://github.com/lalalune/hyperliquid-source/pull/45)'s
held lifecycle effects. No unlicensed inferred reference source was used.

## Reproduce

Use a checkout with the authenticated pinned inputs, GNU objdump 2.44 and
Python 3.12.14; the author's platform was Linux/x86-64. From repository root:

```sh
mkdir -p work/visor-lookup
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/visor_lookup_result.py \
  --output work/visor-lookup/record.json
cmp research/work-items/RE-013-visor-lookup-result/record.json \
    work/visor-lookup/record.json
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  research/work-items/RE-013-visor-lookup-result/check_packet.py
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests \
  -p test_visor_lookup_result.py -v
```

The public producer reads `--binary` once into immutable Python bytes,
requires its complete size/digest, and uses that same snapshot for ELF,
FDE/CIE, relocation, symbol, caller and instruction extraction. The private
`_derive` seam permits real-byte corruption controls below the outer hash;
it is not a CLI re-pin option. Records are derived before exclusive output
creation, so failed inputs preserve prior evidence and create no new output.

The native decoder receives only the admitted 321-byte raw slice in a
0700 temporary directory, in a 0400 file named `lookup.bin`. Its command is:

```sh
objdump -D -b binary -m i386:x86-64 -M intel --insn-width=16 \
  --adjust-vma=0x5d3220 lookup.bin
```

It never receives or reopens the original ELF pathname. Before/after scratch
bytes are checked, and **every** native instruction's address/byte span is
compared with the admitted snapshot. This covers a restored wrong view too:
a control changes a scratch opcode, runs actual GNU, restores the file before
the post-check, and still requires row-byte rejection. `lookup.objdump.txt`
is the complete original native output; its relative filename is stable
across temporary directories. The record binds its tool/options, bytes and
hash. The checker freshly regenerates the record and native export.
No native ELF metadata parser, guessed load base or normalization mask is used.

## Evidence and normal-return proof

Coordinates are linked ELF VAs; `record.json` also supplies file offsets,
raw bytes and hashes. The exact lookup FDE is at `0x24f9b0`, CIE `0x22a3a0`,
and ends at `0x5d3361`; the decoded body has **94 instructions / 321 bytes**.
All eleven encoded branch destinations are independently recomputed from
operands and land on decoded instruction starts. The three calls are opaque
normal-return edges. The only local RET is `0x5d335c`.

All normal RET paths pass through the shared epilogue
`0x5d334e..0x5d335d`. It adjusts RSP and restores RBX/R12/R13/R14/R15/RBP;
it does not write EAX. Its only outside predecessors are:

| Case | Incoming site | Why low32 is canonical |
| --- | --- | --- |
| False initializer | `0x5d334c` | `xor eax,eax` sets the entire low32 to 0. |
| Cached-name comparison | `0x5d335f` | `test eax,eax` at `0x5d3256` and the zero branch at `0x5d3258` select `0x5d335d`, which writes `al=1`. Because EAX was zero, the result is EAX=1, not merely AL=1. |
| Probed-name comparison | `0x5d3303` | At `0x5d32fd`, ECX captures the returned EAX before `al=1`. The following `test ecx,ecx` and zero branch require the captured value to be zero, so the retained upper24 of EAX are zero and current EAX=1. |

The checker also verifies predecessors of the zero-test/capture chains and
every interior epilogue instruction. A branch into a predicate after its test,
or into the epilogue after its initializer, cannot silently bypass the proof.
All normal-graph edges are recorded. This is an intraprocedural cutset proof
under the stated normal-call model, not a proof of exception/nonreturn paths,
all supervisor control flow, memory validity or feasible input outcomes.

The distinction between EAX and RAX matters. The true arms use partial AL
writes; their preceding **32-bit** zero predicates close the remaining low24.
They do not establish the high32 of RAX. The false XOR does zero RAX, but that
stronger fact does not qualify every return case.

## Comparison, probe and caller obligations

The direct slot call at `0x5d3250` uses `0x7e4c78`. The later load at
`0x5d329f` obtains the same slot in R13 before `call r13` at `0x5d32fa`.
The actual relocation is GLOB_DAT type 6, symbol index 9, addend 0; its dynamic
symbol is undefined `bcmp`. The producer reads and binds those ELF records.
It does not prove the runtime-selected DSO, interposition or bcmp implementation.
The return proof needs only the observed EAX-zero predicates, not an assumption
that a particular comparison result means equal byte strings.

Entry saves the current name pointer in R14 and length in RBX. The cached
comparison takes its candidate pointer from `[rax+8]` after the candidate
length `[rax+16]` matches RBX; the probed comparison similarly guards its
candidate length before supplying candidate/current pointers and RBX in RDX.
Relating those registers to incoming arguments across calls assumes ordinary
callee-saved register preservation. Private table layouts and helper ABIs
are not reconstructed by those machine-level observations.

The call at `0x5d3273` targets `0x626760..0x6268c0` (352 bytes, FDE
`0x25336c`). Its two selected calls target `0x628d00`; the second supplies
one byte `0xff`. Those boundary/byte/call facts are retained, without naming
or implementing the hashing algorithm. Its returned probe value can be
arbitrary for the normal-return cutset proof: it influences probing, but
cannot bypass one of the three recorded return cases. Hash consistency,
probe termination, table validity, membership completeness and key ownership
remain separate obligations. The metadata-only dependency is not added to
the 321-byte native-CFG denominator.

The selected revisited #988 sites supply `skip-download` with length 13,
call `0x5d3220`, copy EAX to EBP at `0x5b910a`, and store BPL to output
`[rbx+0x18]` at `0x5b923d`, with RBX saved from incoming RDI. Consequently
that output byte is bounded to 0/1 **if intervening normal helper calls preserve
callee-saved RBP/RBX**, the same explicit condition as #988. This is not a
recovered Rust bool layout, complete private ABI or flag/download policy.

## Implementation, controls and limits

Rust source, manifests/lock, compiler/linker provenance, two-build results,
raw/normalized binary comparisons and equivalence fixtures are **not yet
implemented/measured** here. There is no byte-matching denominator or accepted
gate. The new independently authored Python is an offline evidence collector;
passing its controls is not source reconstruction.

Ten focused tests use the actual pinned target and include:

- whole-input rejection before the native provider;
- both noncanonical AL immediate counterfactuals;
- EAX-to-AL / ECX-to-CL test-width changes, wrong capture, missing full zeroing
  and epilogue writes that invalidate the low32 reasoning;
- actual encoded branches redirected onto valid instruction boundaries that
  bypass a zero test or enter the epilogue interior;
- changed comparison binding/arguments, probe targets and FDE extent;
- the actual GNU restored-wrong-scratch-view control described above;
- real CLI output preservation and rejected-input publication boundaries;
- freshly regenerated packet/native output versus false retained evidence.

The scope is 94 decoded instructions, eleven local branches, three opaque
calls and one RET within one unwind extent. These are normal-graph counts,
not original Rust-function, full-call-graph or matched-window counts. No
accepted syntax, defaults, trailing/multiple arguments, parser policy,
private container type, lifecycle/download effect or component completion
is claimed. Original captures, imports, pins and progress gates are unchanged.

Next question: establish actual table/hash invariants and the intended
comparison contract before interpreting the canonical number as key-membership
behavior, then bind its lifecycle consumer before assigning a public flag effect.
