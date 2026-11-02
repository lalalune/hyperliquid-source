# RE-009: node94 block-reader inclusive-range guard and dispatch coordinates

- Component: storage; bounded static RE-009 research.
- Target: node #94 Linux x86-64, `artifacts/node/94/hl-node`, 91,774,280 bytes,
  SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `e5c9b6436876b2a4a39daef813171f9879317699`;
  reference gitlink `999556f6e0a474b8312db96ec3149e1c44e97c23` was consulted
  only as a lead. No inferred Rust is copied or implemented.
- Question: on the selected initial dispatch arm, which two-u64 intervals
  pass the count guard, what count is stored, and where does rejection go?
- Status: exact instruction, dispatch-entry and source-Location observations;
  inclusive-interval interpretation inferred from the arithmetic. No complete
  async future, backend read, application error type or accepted API input
  population is established. All component gates remain false.

## Reproduce

From the repository root with the pinned artifact materialized:

```sh
python3.11 -B research/work-items/RE-009-block-reader-inclusive-range-94/reproduce.py
```

Observed: Python 3.11.15, Darwin arm64, Apple LLVM 21.0.0. The producer uses
the reviewed repository `elf_index.py` and `fde_extents.py` static parsers;
their hashes and exact LLVM commands are in `records.json`. It invokes the
existing Apple command-line-tools `llvm-objdump` and `llvm-dwarfdump` paths
recorded in the script. Only static local reads and packet writes occur;
no captured program, network request, DB operation or chain action runs.

The complete 1,721-byte owner is linearly decoded from its authenticated FDE
entry. Every decoded row must match the original bytes, cover the next
contiguous address and contain no unknown instruction. All selected probes
and dispatch destinations must be decoded boundaries. The **381 decoded
instruction/prefix rows** include LLVM's separately printed `lock` prefixes;
the count is not a whole-program function or equivalence denominator.
There are no normalization masks, timeout or reduced native analysis profile.
The two LLVM text exports normalize only trailing newline formatting to one
final newline; no instruction text, operand or evidence byte is changed.

Expected and observed result:

```json
{"arithmetic_probes": 121, "dispatch_entries": 12, "instruction_pins": 15, "owner_bytes": 1721, "owner_instructions": 381, "rejected_mutations": 18}
```

The script's `owner_instructions` metric counts those decoded rows. Exact
regeneration and generated-file hashes are recorded in `validation.json`.

## Original evidence and scope

All coordinates are ELF virtual addresses; ends are exclusive. The owner
range is **`0x27abee0..0x27ac599`**, FDE VA `0x10f8420`. Its raw FDE/CIE,
code hash and unwind-index record are retained in `records.json`. Independent
LLVM `--eh-frame` output agrees with that range in `owner-fde.llvm.txt`.
`owner.llvm.txt` contains the complete original byte/instruction export,
including unclaimed backend/poll/cleanup branches.

A `lea` at `0x27ac42b` references Location `0x56c3098`. Its original pointer
word is zero; its unique `R_X86_64_RELATIVE` relocation resolves to the
51-byte captured path `/home/ubuntu/hl/code_Mainnet/db/src/block_reader.rs`.
The following fields encode line 45, column 114. The relocation bytes,
Location bytes and path are independently verified by this producer.
This source context does not identify every type, operation or source line
inside the owner. The earlier `RE-009-storage-state-roots` packet had listed
the Location ownership but did not analyze this range guard.

### Selected dispatch entries

The entry loads a byte at future `+0xf0` and uses it to index signed-dword
relative table `0x3eec1c`. There is **no preceding bounds check** in this
entry sequence. The four selected table indices resolve to:

| Selected index | Target |
| --- | --- |
| 0 | `0x27abf0b` — range setup interpreted below |
| 1 | `0x27ac41e` — diagnostic/helper path |
| 2 | `0x27ac411` — diagnostic/helper path |
| 3 | `0x27abf9b` — nested dispatch |

Two nested tables at `0x3eec2c` and `0x3eec3c` also have four selected
entries recorded and checked against the owner boundaries. Their indexed
bytes are at future `+0xc9` and `+0xb0`, respectively. All 12 original
relative entries are retained. This qualifies **indices 0..3 only**; it does
not prove a complete valid state domain or table length, nor make arbitrary
other state bytes valid inputs. Future construction, scheduling, resumption
and source-language enum identities remain outside this packet.

### Exact initial range guard

On the selected outer index-0 arm, let `L` be the u64 loaded from future
`+0xd0` and `H` the u64 loaded from `+0xd8`. The relevant instructions are:

```text
0x27abf37  mov rax,r14             ; H
0x27abf3a  sub rax,rbp             ; H-L modulo 2^64
0x27abf3d  setae cl                ; unsigned subtraction had no borrow
0x27abf40  cmp rax,-1              ; delta != 2^64-1
0x27abf44  setne sil
0x27abf48  and sil,cl
0x27abf4b  cmp sil,1
0x27abf4f  jne 0x27abfd0
0x27abf5b  inc rax
0x27abf5e  mov [rbx+0xe0],rax
```

Thus this **guard**, considered over two raw u64 words, passes exactly when:

```text
H >= L unsigned AND (H-L mod 2^64) != 2^64-1
```

On passage, it stores the nonzero representable inclusive count `H-L+1`
at future `+0xe0`, then continues with allocation/preparation work. A wider
integer formulation of the same local relation is `1 <= H-L+1 <= u64::MAX`.
Examples of this guard's arithmetic, not executed native requests:

| L | H | Guard/count |
| --- | --- | --- |
| 0 | 0 | Pass, 1 |
| 5 | 4 | Reject (borrow) |
| 0 | `u64::MAX` | Reject (inclusive count would be `2^64`) |
| 0 | `u64::MAX-1` | Pass, `u64::MAX` |
| 1 | `u64::MAX` | Pass, `u64::MAX` |
| `u64::MAX` | `u64::MAX` | Pass, 1 |

The guard contains no small batch-size cap. This observation does not prove
large requests are constructible, survive caller checks or can be served;
it is not an externally reachable defect claim. The later backend, resource
limits and source API are not recovered here.

### Rejection joins a tagged output and numeric state store

The failure branch reaches `0x27abfd0`, sets BPL to `0x08` and jumps directly
to `0x27ac3e8`, which writes BPL to byte `[rdi]`. The common sequence also
writes three scratch/output qwords, then sets AL to 1 and writes that byte
to future `+0xf0` at `0x27ac3f9` before returning. No helper call lies on
this direct guard-failure-to-return path.

This proves output byte `0x08` and numeric state 1 for that local rejection
path. It does not recover a named `Result`, error variant, semantic content
of the three other output words or a complete calling convention. In
particular their scratch values are not claimed as initialized application
payloads for tag `0x08`. Later paths also use the common output join, so the
join itself is not uniquely an invalid-interval detector.

## Controls and validation

The producer checks full target size/SHA-256 before parsing, actual CIE/FDE
and unwind-index identity, independent LLVM range output, complete owner
bytes/boundaries, 15 exact instruction spans, 12 selected dispatch targets
and the Location's unique relocation/path.

There are **18 targeted byte mutations**: one in each of the 15 instruction
spans and one in each of the three selected dispatch tables. They use a
patched read view and deliberately bypass **both whole-input and body hash
gates**, reaching the same instruction/table validator; all are rejected.
These are evidence-corruption controls, not native behavioral mutations.

The arithmetic check uses 11 explicit u64 values: 0, 1, 2, 4, 5, 6, the two
values around `2^63`, and the last three u64 values. All 121 ordered pairs
compare the modulo-subtraction/borrow form with an independent unbounded
integer inclusive-count relation. The raw chosen population and each result
are retained. This finite check supports the algebra above; it is not a
test of backend reads, actual native execution or every application input.

## Result and remaining gaps

Before this packet, main associated a block-reader Location with this owner
without an interpreted range guard. Afterward it has a target-bound account
of the selected initial arm's exact u64 admission relation, stored count,
failure output/state and 12 qualified dispatch coordinates. The complete
owner export permits follow-up without claiming recovery of its whole body.

No Rust code, Cargo build, captured execution, source/binary equivalence,
complete CFG/helper closure, valid future-state domain or progress-gate
change is claimed. All 0/1/2/3 and `0x08` names remain numeric. Component
checks and repository-wide verification are reported separately by
integration rather than invented here.

Next question: determine how the nested call at `0x27ac215` yields the
output words and how the later comparison with saved `+0xe0` governs count
mismatch, without assuming a vector/`Poll` source type from the tags alone.
