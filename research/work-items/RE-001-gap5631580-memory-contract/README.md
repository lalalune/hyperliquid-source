# RE-001: conditional memory contract of candidate 0x5631580

- Component/task: RE-001, node #94 function-map follow-up.
- Target: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Included: linked-VA candidate `[0x5631580,0x56319fd)`, 1,149 bytes;
  file offset 90,375,552; slice SHA-256
  `2ad5e86209996d34c689f686461158e32c45f792f0cb3f37fd7c8f15e8d48560`.
- Claim: observed instructions plus a **conditional static memory contract**.
  This is not an original Rust function/type/ABI/algorithm identification.
- Excluded: the second candidate, caller ownership, runtime dispatch, source
  implementation, concrete execution, termination, safety and equivalence.

## Before and resulting evidence

The maintained base has no contract for this unwindless region. PR #373 leaves
its code boundaries as a next question; our separate PR #981 records two
boundary candidates and explicitly leaves semantics unresolved. That boundary
packet is context, not an implementation dependency or source of instruction
bytes here. This analyzer independently authenticates the maintained base ELF,
extracts its first candidate and obtains a fresh native decode.

The new result identifies where a caller would need to supply memory and where
results are written. All 285 native instruction rows are lifted into six finite
symbolic phases. Complete local CFG recovery gives nine basic blocks, six
direct branches, one RET, and no other control-transfer instruction. All 285
rows are statically reachable; loops are retained as edges, never executed.

| Phase | Linked VAs, half-open | Rows | Observed role |
| --- | --- | ---: | --- |
| Prologue | `5631580..56315de` | 35 | Save GPRs, load state, construct frame |
| Outer guards | `56315de..5631669` | 33 | Compute stop and four early exits |
| Seed | `5631669..56316c0` | 16 | Save input cursors, seed four table cells |
| Inner body | `56316c0..563199b` | 164 | Emit, refill, test sole inner backedge |
| Tail restore | `563199b..56319ae` | 4 | Restore three input registers, outer edge |
| Normal return | `56319ae..56319fd` | 33 | Twelve state writes and GPR restoration |

## Physical state and result locations

Let `Q` be **the physical entry RDI value**, without assigning an original
source type. The following names describe use in the instruction transfer;
they do not infer a source calling convention or original field names.

| Entry-Q offset | Width | Loaded physical register | Observed use |
| --- | ---: | --- | --- |
| `00,08,10,18` | 64 each | `r8,r9,r10,r11` | Four input addresses |
| `20,28,30,38` | 64 each | `rsi,rbx,rcx,rdi` | Four byte-output addresses |
| `40,48,50,58` | 64 each | `rbp,rdx,r12,r13` | Four shifting bit words |
| `60` | 64 | `r14` | Base of 16-bit table reads |
| `68,70` | 64 each | Stack copies | Two outer-bound input words |

The four `je/jb` exits all target `0x56319ae`, before the seed can reuse
`r9/r10/r11` as table cells. The inner body has one backedge to its first
instruction and no early exits; its fallthrough restores those three input
registers before the sole outer backedge. Hence every normal RET reaches
the same twelve explicit qword stores at `Q+00..Q+58`, writing the current
four input addresses, four output addresses and four bit words. There is
no explicit state-relative write at `Q+60`, `Q+68` or `Q+70`. Under the
disjoint-memory conditions below, those three words remain unchanged.

All fifteen GPRs other than RSP are pushed before state loads and restored in
reverse order after the state writes. In particular, normal return restores
entry RAX; it does not return a newly computed status in RAX. RFLAGS
preservation is **not** claimed. The frame reaches `entry_RSP-176`, protects
the saved values/configuration above working-frame offset 24, and RET leaves
RSP at `entry_RSP+8`, loading its target from the original return-address slot.
The normal-return phase generalizes mutable working-frame offsets `0,8,16,24`
to arbitrary exit-cutpoint values. In particular, its first dead POP reads
offset 24, which can hold the initial dummy R15 or a previous loop stop.
It must not be labeled unconditionally as entry R15. The next three POPs
overwrite RAX and recover Q from protected offset 48. Protected offsets
`32..168` retain their exact prologue values, so state-writeback and GPR
postconditions do not depend on mutable scratch contents.

## One inner iteration, with explicit widths

For lane `i`, let `I_i`, `O_i`, and `B_i` be its current 64-bit input address,
output address and bit word, and let `T` be R14. Define this little-endian
table read, with 64-bit modular address arithmetic:

```
C(B) = zero_extend_64(load16(T + 2 * (B >>u 53)))
```

The seed establishes `C(B_i)` in `r15,r9,r10,r11` respectively. For each
`j=0..4`, the unrolled lane transfer is:

```
cell = C(B_i)
store8(O_i + j, bits_15_to_8(cell))
B_i = (B_i << (cell & 63)) mod 2^64
```

The machine performs the shift before its adjacent byte store, but MOV to RAX
preserves the original cell and the store uses AH. In this proof domain those
operations have the same transfer above. Each of the first four positions
reloads `C` after the shift; the fifth is followed by refill. Thus there are
**twenty byte stores per executed inner iteration: five per lane**, not twenty
per invocation. This statement does not estimate how often the loop executes.

Every table index is an unsigned 64-bit word shifted right by 53: an 11-bit
value in `0..2047`. Its two-byte read therefore uses relative offsets
`0..4095` from T, modulo address width. This is an envelope, not a claim that
all table entries are read or that 4 KiB is actually allocated/readable.
Shift counts use the cell's low six bits; emitted bytes use its upper eight.

After the fifth output position, each lane performs this refill:

```
z = BSF_64(B_i)                   # defined only when B_i != 0
I_i' = I_i - (z >>u 3)           # modulo 2^64
O_i' = O_i + 5                   # modulo 2^64
B_i' = (load64(I_i') | 1) << (z & 7)   # modulo 2^64
next_cell = C(B_i')
```

On the defined nonzero domain, 64-bit BSF gives `z` in `0..63`: the input
address therefore retreats by **0..7 bytes** and the refill shift is **0..7
bits** per lane per iteration. The refill reads eight bytes at the retreated
address; no input-range allocation or validity is inferred from that bound.

For lanes 1..3, input addresses live in working-frame offsets `0,8,16`
while their physical registers hold cells. The transfer checks their spills
and tail restoration, not just visible register names. The seed establishes
the cell invariant; all four refills re-establish it on the sole inner
backedge. Every loop store is classified: twenty output bytes and three
qword input spills. Outer/seed stores affect only scratch/stop offsets
`0,8,16,24`; protected frame offsets `32..168` are unchanged across a cycle.

The outer stop calculation is retained as exact width-explicit multiply-high,
shift, subtract, unsigned-select and add expressions in `REPORT.json`.
No division identity, validated bound, global byte count or termination
claim is needed here. The first exit tests `stop == O_3`; the other three
test `I_1 <u I_0`, `I_2 <u I_1`, `I_3 <u I_2`. The inner backedge tests
`stop >u O_3'` after the five-byte advances.

## Proof domain and symbolic transfer semantics

The contract applies to normal-return paths with available x86-64
instructions and valid memory at every recorded access. The state block,
176-byte frame plus return slot, table reads, input reads, and output writes
are disjoint; output lanes are disjoint for the stream interpretation. No
concurrent/asynchronous memory modification, faults or signals are modeled.
Without the separation condition, an output pointer could overwrite state,
table data or saved registers, so unconditional preservation is not claimed.

Every BSF operand must be nonzero on every executed inner iteration. The
original code does not supply a checked zero case before BSF; its undefined
destination on zero is outside this contract. Neither the condition nor
validity of caller-supplied pointers is proved. Modular arithmetic does not
prove nonwrapping ranges, bounds safety, allocations or input validity.

`REPORT.json` contains a hash-consed expression DAG and each row's register
reads/writes, memory reads/writes and comparisons. All arithmetic nodes have
width 64; `offset` means addition of its signed displacement modulo `2^64`.
`multiply_low`/`multiply_high_unsigned` select the low/high halves of an
unsigned 128-bit product. Logical shifts use an explicitly masked six-bit
count. Loads specify 8/16/64 bits and little-endian order. `extract` uses its
recorded low bit and width; 32-bit register writes zero-extend to 64 bits.
`trailing_zero_count_nonzero` is BSF's defined nonzero transfer only.
`if_unsigned_above(a,b,x,y)` selects x when `a >u b`, otherwise y.

The analyzer lifts finite straight-line phases and verifies their joining
invariants. It never chooses concrete initial values, evaluates branch
conditions, runs a loop, dereferences symbolic pointers, or executes captured
machine code. Native decode is GNU objdump on the raw slice. Its address,
width and bytes are checked against the authenticated ELF mapping, and each
branch destination is independently recomputed from encoded displacement.

## Reproduce and controls

Python **3.12.14**, GNU objdump **2.44**, Linux x86-64; standard library only.
From the repository root, with an owned scratch directory in TMPDIR:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/node94_gap5631580_memory_contract.py \
  --output-dir work/gap5631580-memory-contract
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests \
  -p test_node94_gap5631580_memory_contract.py -v
make --jobs=1 'PYTHON=python3 -B' doctor verify test catalogue-check reproduce
```

The focused suite authenticates the original ELF, then alters only private
1,149-byte slices and obtains fresh native decodes. It rejects a wrong fifth
store offset, AH-to-AL change, real VEX shift-count register change, wrong
refill bit mask, addition instead of input retreat, wrong state-writeback
offset, swapped saved-register pops, and an instruction-aligned but incorrect
backedge. It also rejects stale native-output bytes, verifies all 285 rows and
memory postconditions, and checks two actual CLI runs for identical outputs.
An existing output directory is refused and all its bytes are preserved.

The twelve focused tests pass; `FOCUSED-VALIDATION.json` records that run.
The exit-cutpoint regression also checks that the first dead POP is not
misrepresented as the initial dummy after the seed overwrites its slot.
Final committed-tree aggregate results are reported separately in the PR;
focused success does not imply aggregate or hosted success. `OUTPUT-MANIFEST.json`
binds the three generated outputs; `MANIFEST.json` binds packet/source/tests.
Pre/post full SHA-256 checks admit the same mmap and catch persistent input
changes. Native tools never reopen the original ELF pathname. These checks
are not an atomic snapshot guarantee against transient in-place writes.

## Remaining work

No independently authored Rust implementation or compiler comparison exists
for this candidate. Original function identity, input protocol/algorithm,
caller preconditions, ABI/source types, runtime feature dispatch and actual
loop termination remain unresolved. This packet requests **no progress gate**,
function denominator or equivalence credit. A useful next question is to
recover one instruction-aligned caller and establish which of the explicit
memory/BSF preconditions it actually guarantees.
