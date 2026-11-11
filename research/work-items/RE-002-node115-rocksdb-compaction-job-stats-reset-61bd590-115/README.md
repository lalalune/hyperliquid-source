# RE-002 / node #115 — `rocksdb::CompactionJobStats::Reset`

Reconstruction of one vendor body of the pinned node #115 artifact:

| | |
|---|---|
| symbol | `_ZN7rocksdb18CompactionJobStats5ResetEv` |
| demangled | `rocksdb::CompactionJobStats::Reset()` |
| address | `0x61bd590..0x61bd60f` (127 bytes, 24 instructions, 1 `.eh_frame` FDE) |
| member | `6cca28ae25285154-compaction_job_stats_impl.o` (`liblibrocksdb_sys-b032f986857674dc.rlib`) |
| crate / version | `librocksdb-sys` / `0.11.0+8.1.1` |
| body sha256 | `cfcbe3988ac0d3eeaf68f8d2bb01aa116ee041e03bbd57ab23818ea23a03c009` (raw-equal to the rebuilt source body, 0 relocations) |
| memory effect | 2 loads, **18 stores**, no call, no branch, no stack frame |
| callers | **8 direct calls in 8 FDEs**, all 8 discard the register the body leaves, 0 read it |

## Recovered semantics

```c
// rdi = this
void CompactionJobStats::Reset() {
    // The 0x4a..0x4f bytes survive because the store at +0x48 is two bytes wide.
    *(uint64_t*)(this + 0x40) = 0;          // 8-byte field
    *(uint16_t*)(this + 0x48) = 0;          // 2-byte only - +0x4a..+0x4f survive
    *(uint64_t*)(this + 0xc8) = 0;          // string 1 size; +0xc0/+0xd0 kept
    memset16(this + 0x00, 0, 0x40);         // 0x00,0x10,0x20,0x30
    memset16(this + 0x50, 0, 0x70);         // 0x50,0x60,0x70,0x80,0x90,0xa0,0xb0
    *(char*)this->s1.data = '\0';           // inlined std::string::clear()
    *(uint64_t*)(this + 0xe8) = 0;          // string 2 size; +0xe0/+0xf0 kept
    *(char*)this->s2.data = '\0';           // inlined std::string::clear()
    memset16(this + 0x100, 0, 0x10);        // 0x100
}
```

The write set, in program order — one row per store, so each row lines up with an instruction:

| # | target | width | instruction |
|---|---|---|---|
| 1 | `this + 0x40` | 8 | `movq $0x0,0x40(%rdi)` |
| 2 | `this + 0x48` | 2 | `mov %ax,0x48(%rdi)` |
| 3 | `this + 0xc8` | 8 | `movq $0x0,0xc8(%rdi)` — string 1 size |
| 4–7 | `this + 0x00,0x10,0x20,0x30` | 16 | `movups %xmm0,…(%rdi)` |
| 8–14 | `this + 0x50,0x60,0x70,0x80,0x90,0xa0,0xb0` | 16 | `movups %xmm0,…(%rdi)` |
| 15 | `*(uint8_t*)this->s1.data` | 1 | `movb $0x0,(%rax)` — loaded from `this + 0xc0` |
| 16 | `this + 0xe8` | 8 | `movq $0x0,0xe8(%rdi)` — string 2 size |
| 17 | `*(uint8_t*)this->s2.data` | 1 | `movb $0x0,(%rax)` — loaded from `this + 0xe0` |
| 18 | `this + 0x100` | 16 | `movups %xmm0,0x100(%rdi)` |

18 rows, **220 bytes** touched, and the two rows 15 and 17 are the only ones whose address is not
a fixed offset: the body loads a `std::string` data pointer **out of the object** (`mov 0xc0(%rdi),%rax`)
and writes one NUL through it. That is an inlined `std::string::clear()` — the size word is zeroed,
the pointer and the capacity word are **preserved**, and the buffer keeps its allocation.

Five things the packet pins that a reading of the source alone does not give:

1. **`+0x4a..+0x4f` survives a `Reset`** — the store at `+0x48` is two bytes wide, while every
   neighbouring field is written with an 8- or 16-byte store, which a prose reconstruction misses;
2. **the string capacities at `+0xd0`/`+0xf0` are never written** — the 16-byte strides step over
   each string's metadata block, so a reset string keeps its buffer and its capacity;
3. **the write set is not a fixed address list** — it is a fixed offset list plus two pointer
   dereferences, which is why the packet models and emulates both halves;
4. **the routine is idempotent** — all eighteen stores write zero, so a second `Reset` is a no-op
   (tested explicitly);
5. **a self-referential (SSO) string changes nothing** — the object's pointer names an address
   *inside* the object, the NUL lands there, and the count stays at 18: there is no
   size-dependent branch anywhere in the body.

## Caller census (recomputed from `.text` and `.eh_frame`)

| site | caller FDE | `rdi` formed by | what it names |
|---|---|---|---|
| `0x5deb6c8` | `0x5deb5a0..0x5deb8ea` | `lea rdi,[rbp - 0x180]` | a stack object |
| `0x5debacf` | `0x5deb9c0..0x5debc68` | `lea rdi,[rbp - 0x180]` | a stack object |
| `0x5df2e26` | `0x5df2380..0x5df3659` | `mov rdi,rbx` | an object already in `rbx` |
| `0x5df3ebb` | `0x5df3dd0..0x5df64b6` | `lea rdi,[rbp - 0x6e0]` | a stack object |
| `0x5dfd1e0` | `0x5dfd120..0x5dfd41b` | `lea rdi,[rsp + 0x68]` | a stack object |
| `0x5dfd544` | `0x5dfd4a0..0x5dfd77b` | `lea rdi,[rsp + 0x68]` | a stack object (a different frame) |
| `0x5dfe710` | `0x5dfe640..0x5dfe8c1` | `lea rdi,[rdi + 0x60]` | **a member of the caller's own receiver** |
| `0x5e4380f` | `0x5e41fa0..0x5e44899` | `lea rdi,[rbp - 0x8b0]` | a stack object |

`consumers = {discarded: 8}`, `sites reading rax = 0`, `argument forms = {lea: 7, register-copy: 1}`.

`Reset` returns nothing: the register it leaves in `rax` is the second `std::string` data pointer it
loaded at `0x61bd5f2`, and the census confirms that **no caller reads it** — each drops it within a
few instructions or at the next intervening `call`. The census is derived from the artifact, not
from the excerpt: a raw byte scan of `.text` finds the `e8 rel32` call encodings that target the
entry (each confirmed by decoding exactly five bytes), `.eh_frame` attributes each one to its FDE,
and a taint walk follows `rax` forward inside that FDE with the **caller-saved set killed at every
intervening call** (Capstone does not report `rax` among a `call`'s written registers, so the ABI
kill is applied explicitly; a conditional branch is *not* a clobber).

## Evidence

```
python3 research/work-items/RE-002-node115-rocksdb-compaction-job-stats-reset-61bd590-115/export_excerpts.py
python3 tools/rocksdb_compaction_job_stats_reset_61bd590_115.py
python3 research/work-items/RE-002-node115-rocksdb-compaction-job-stats-reset-61bd590-115/census.py
python3 research/work-items/RE-002-node115-rocksdb-compaction-job-stats-reset-61bd590-115/semantics.py
python3 research/work-items/RE-002-node115-rocksdb-compaction-job-stats-reset-61bd590-115/verify.py
python3 -m unittest discover -s tests -p 'test_rocksdb_compaction_job_stats_reset_61bd590_115.py'
```

| file | what it holds |
|---|---|
| `main.txt` | the raw window listing: encoded bytes + instruction text, branch annotations stripped |
| `frames.txt` | the routine's FDE and the eight FDEs that call it |
| `relocations.txt` | the empty relocation set and the body digest |
| `semantics.tsv` | 24 claim anchors, one per instruction |
| `callers.tsv`, `caller_use.tsv` | the census tables above |
| `cases.tsv` | the 300-row ledger (model vs decoded-bytes answer, 0 disagreements) |
| `writes.tsv` | the routine's executed write set (18 rows / 220 bytes) |
| `records.json` | the bound context, register roles, census contract and unknowns |

Two independent artefacts are kept apart on purpose: `model_writes()` is the closed-form write list
a reader would author from the disassembly, and `decoded()` executes the routine's **own bytes** in
a small interpreter that raises on any instruction or operand form it does not implement. The claim
is that the emulator's **store log** equals the model row for row (program order) *and* that the
resulting memory image matches — a disagreement is a finding, not a transcription bug.

## Validation

`verify.py` re-derives the whole packet from the artifact and the committed excerpts: manifest
digests, the 127-byte window digest and its int3 fencing on both sides, the byte-for-byte agreement
between the excerpt and the artifact (parsed as a byte stream, because objdump splits instructions
longer than seven bytes onto continuation lines), the 24 anchors (each one a real instruction,
re-decoded with Capstone), the census (8 calls / 8 FDEs / the map above, recomputed from `.text`
and `.eh_frame`), the model-vs-decoded ledger, a 150-case sweep, idempotence, three
doctored-excerpt checks that prove the emulator executes the committed bytes rather than echoing
the model, and the static memory effect (2 loads / 18 stores in 24 instructions, 127 bytes).

The differential has two halves, and both must have teeth: the emulator's store log must equal the
model's 18 rows in program order, **and** the resulting memory image must match. The image comparison
covers the two regions where the staged bytes are - the object (`0x100000..0x100200`) and the string
arena (`0x200000..0x200200`) - not a nominal window; a revision that compared the low 64 bytes of the
address space proved nothing, because nothing writes there. Three negative tests corrupt one byte at
`+0x100`, at `+0x1f0` and in the arena and require the comparison to report exactly that address.

As in the sibling packets, a doctored excerpt must change the answer: widening the two-byte store
to `mov %eax,0x4c(%rdi)` or moving the last `movups` to `0x120(%rdi)` must divert the write set,
and an instruction the interpreter does not model (`add %eax,%eax` in place of the `ret`) must
raise rather than be silently guessed.

## Limits

- The offset↔field mapping is **not** recovered: the binary fixes the offsets, not the names. The
  two `std::string` members are inferred from the load-then-one-byte-zero shape plus the 16-byte
  gap that follows each, which is what libstdc++'s SSO layout produces.
- The eight caller FDEs are identified by address range only — the image is stripped, so no claim
  is made about which method each one is. The member-object call at `0x5dfe710` is the only one
  whose `rdi` is derived from the caller's own receiver.
- The census follows the linear fall-through inside each FDE; a value that only dies on a branch
  path would still be reported as read. No site here is path-dependent.
- The three identical source copies the vendor census records are not enumerated; the
  reconstruction is bound to the body sha256.
- No claim is made about *why* a caller resets the object, or about the lifetimes of the two
  `std::string` buffers whose first byte this routine writes.
