# RE-012: post-copy helper writes to the tracked context word

- Component/task: transport / RE-012, with RE-001 byte and relocation bindings.
- Sole target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Status: conditional static preservation on selected call-free paths.
- Owned files: `helpers.py`, `helpers-spec.json`, `helpers/`, this report,
  `helpers-validation.json`, packet links and manifest. No shared tooling,
  imported material, Rust implementation or acceptance gate is changed.

## Result and acceptance boundary

The two constructor helpers `0x2cd0910` and `0x2cd06c0` have selected
uncontended, flag-zero paths that return without calling another function.
On those paths their three explicit writes into the current allocation `P`
are eight-byte writes at **`+0x18`, `+0x3038`, and `+0x3030`**. None overlaps
the tracked two bytes **`P+[0xc8,0xca)`**. The descriptor scalars that resolve
the indexed writes are checked against the captured ELF, not assumed from a
library layout.

This narrows one premise of [FACTORY-JOIN](FACTORY-JOIN.md). It does not remove
the separate premises that scheduler/bucket/head-link storage and the helper
stack do not alias the field, that the descriptor stays intact, and that no
other thread modifies the field. Publication into a list does not prove
subsequent poll ordering or resource lifetime. Other helper paths contain
calls and remain outside this preservation result.

## Inputs, descriptors and field coordinates

`P` denotes the allocation returned before the constructor's final copy;
`S` is the constructor's retained first argument. Linked ELF virtual addresses
are used throughout, before load bias. Original bytes, file offsets, full FDE
bounds, LSDA pointers, native exports and decoded transfers are retained in
[helpers/records.json](helpers/records.json). FDE extents are selected decode
bounds, not a whole-node function inventory or coverage denominator.

| Binding | Executor A | Executor B |
| --- | --- | --- |
| Constructor | `0x2cd1070` | `0x2cd1970` |
| Helper call | `0x2cd11e7 -> 0x2cd0910` | `0x2cd1ae7 -> 0x2cd06c0` |
| Helper registers at call | `RDI=S, RSI=P, RDX=P` | same |
| Descriptor installed at `P+0x10` | `0x6449600` | `0x6449790` |
| Descriptor `+0x38` scalar | `0x3030` | `0x3030` |
| Descriptor `+0x40` scalar | `0x20` | `0x20` |
| Descriptor `+0x48` scalar | `0x28` | `0x28` |
| Descriptor callback `+0x30` | `0x2b2f4b0` | `0x2b2e4c0` |
| Descriptor callback `+0x10` | `0x2b2cc20` | `0x2b2ce00` |

The constructors pass the same `P` in RSI and RDX after the `0x3080`-byte
copy. Helper prologues retain `RSI` in R15, `RDX` in R14, and `RDI` in R12.
The descriptor is installed via constructor stack `+0x90` and copied from
stack `+0x80`, giving `P+0x10`; the preceding factory packet supplies the
separate `P+0xc8` field coordinate. Its collector was rerun without changing
its retained outputs.

Both descriptor regions are retained as raw 80-byte records with seven
unique `R_X86_64_RELATIVE` slots each. Pointer slots are zero in the retained
file bytes and obtain their targets from the relocations. `+0x38` and `+0x48`
are literal, unrelocated scalars; `+0x40` is recorded but is not used to
resolve the selected link writes. The two descriptors have distinct callback
targets; they are not interchangeable typed layouts.

## Selected paths and explicit writes

Let `I = QWORD[P + QWORD[descriptor+0x48]] = QWORD[P+0x28]`.
The selected bucket address is `B = QWORD[S] + 24*(QWORD[S+0x20] & I)`.
Names such as bucket, head and links describe the observed indexing and
pointer writes; original Rust names/types and scheduler ownership are inferred,
not recovered facts.

The selected path requires the initial byte `cmpxchg` at B to succeed,
`BYTE[S+0x30] == 0`, the reloaded ID to equal I, `H=QWORD[B+8] != P`, and
the final byte `cmpxchg` at B to succeed. The head-null and tail-nonnull
branches are varied independently in the static path check.

| Destination/effect | Helper A site | Helper B site |
| --- | --- | --- |
| `QWORD[P+0x18] = QWORD[S+0x28]` | `0x2cd0934` | `0x2cd06e4` |
| byte compare/exchange at B | `0x2cd095b` | `0x2cd070b` |
| `QWORD[P+0x3038] = H` | `0x2cd0a1c` | `0x2cd07cc` |
| `QWORD[P+0x3030] = 0` | `0x2cd0a29` | `0x2cd07d9` |
| if H != 0: `QWORD[H + QWORD[QWORD[H+0x10]+0x38]] = P` | `0x2cd0a3e` | `0x2cd07ee` |
| `QWORD[B+8] = P` | `0x2cd0a42` | `0x2cd07f2` |
| if `QWORD[B+0x10] == 0`: set it to P | `0x2cd0a4d` | `0x2cd07fd` |
| atomic increment at S+0x10 | `0x2cd0a51` | `0x2cd0801` |
| atomic increment at S+0x18 | `0x2cd0a55` | `0x2cd0805` |
| byte compare/exchange at B | `0x2cd0a5e` | `0x2cd080e` |
| return R14 (retained P) in RAX | `0x2cd0a80` | `0x2cd0830` |

The predecessor's descriptor is loaded separately. Its link offset is **not**
assumed to be `0x3030`; its effective write address must be outside the tracked
field. Merely checking `H != P` is insufficient to prove this. The same
non-alias requirement applies to the scheduler and bucket writes. Even the
head-null case still needs those external storage and concurrency premises.

Each complete 581-byte helper FDE has 22 explicit memory destinations,
classified by opcode and width. Nine are helper-stack stores; thirteen are
other stores/atomic operations, including excluded branch/unwind sites.
The collector checks this inventory rather than relying on decoder access
flags. Push/pop/call/ret stack effects are distinct from that explicit count;
called-function effects are not included. The selected paths contain no calls.

There are four checked syntactic paths per helper (eight total), with 71--75
instructions per path. These are encoded-CFG traversals under manually chosen
branch decisions, **not execution or CPU emulation**. They are not eight
observed runs, nor proof that every head/tail combination satisfies actual
queue invariants. The register-to-region annotations are manually reviewed;
this is not an automated alias analysis or a complete scheduler proof.

## Excluded branches and remaining unknowns

- Initial lock contention calls through `0x64e01f8 -> 0x5bb59d0`.
  Unlock slow paths call `0x64e0f38 -> 0x5bb5650`. Their transitive effects
  are unclosed. Taking either contention edge is rejected by the selected
  call-free-path checker; it is not an assertion that contention cannot occur.
- If `BYTE[S+0x30] != 0`, the helpers call descriptor `+0x30` with P,
  then perform `lock xadd QWORD[P], -0x40`. Depending on the old counter,
  descriptor `+0x10` can also be called. For a nonzero shifted old counter,
  the join at `0x2cd0a7d` / `0x2cd082d` clears R14 and returns zero in RAX.
  A zero shifted counter instead calls `0x1680e60`; its nonreturn/error
  contract is not proved here. Return/lifetime behavior is therefore not
  generalized from the selected queue path.
- The four resolved callback bodies are exported in full. Callback `+0x30`
  changes header bits/counters and may pass `P+0x20` to `0x2b31810` or P
  to additional helpers. Callback `+0x10` calls `0x2aacc40` (A) or
  `0x2aaca40` (B) and tail-dispatches through `0x64df4a0`, with RSI=`0x3080`
  and EDX=7. Those transitive callees are not analyzed here; no lifetime or
  successful destruction/cancellation claim follows from the callback names.
- ID mismatch, already-head assertions, landing pads, unwind cleanup and
  externally resumed states are excluded. LSDA addresses are recorded;
  a complete exception-edge analysis is not claimed.
- Accept cleanup, adapter callbacks, the two pollers and their scheduling
  remain separate premises of the larger port-provenance relation. Both
  previously selected executors still lead to large A `0x2accee0`; this
  packet does not establish the source of large B `0x2ad0db0`.

## Reproduction, controls and status

From the repository root, with Python 3.12, Capstone 5.0.7, GNU objdump and
llvm-objdump on PATH, use fresh output directories:

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/helpers.py --out work/context-helpers-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/helpers.py --out work/context-helpers-optimized
```

The collector authenticates the complete capture before analysis. Eight full
FDE intervals total **3,090 bytes / 710 Capstone rows**: the two primary
helpers (1,162 bytes / 310 rows), two constructors and four callbacks.
These are evidence-export sizes; no reconstructed source comparison or
function-coverage credit is claimed. Exact versions/options and native
commands are in [helpers/versions.json](helpers/versions.json) and
[helpers/commands.json](helpers/commands.json).

GNU and LLVM exports retain every byte and match Capstone boundaries, with
explicit accounting for LLVM standalone LOCK-prefix splits. No normalization
masks are used. The normal and optimized collectors produce identical output
files. Agreement checks byte partitions/boundaries, not full semantic agreement
between disassemblers.

All **104 controls** reject their intended invalid input or excluded scope:
22 instruction-span byte changes, six descriptor scalar-byte changes,
50 changed/duplicate parsed relocations, eight truncated FDE bounds, two
damaged store inventories, ten excluded branch choices, four overlapping
interval counterfactuals and two wrong captures. The first byte controls can
fail at the full-body hash before individual pins; they do not independently
isolate each validator. The ten branch controls are scope guards, and the four
interval controls are arithmetic over annotations, not binary mutations.
Adjacent writes ending at `+0xc8` or starting at `+0xca` are accepted.

Fresh repository checks, focused tests, retained-output comparisons and known
failures are recorded in [helpers-validation.json](helpers-validation.json).
The existing incomplete full-suite result remains in [validation.json](validation.json);
catalogue checking still reports stale generated README content. No whole-suite
or hosted CI success is claimed. No new independent-agent review was performed.

The next bounded question is what the selected pollers `0x2b1d9a0` and
`0x2b26920` and their immediate pre-call helpers can write before entering
`0x2accee0`. Contended/nonzero-flag helper branches remain additional work.
No captured code, socket, key or chain action was run. No commit/push was made;
all 92 acceptance gates remain false. New analysis/code is independently
authored MIT work; retained target bytes keep their original terms.
