# RE-002 / node #115 — `rocksdb::CompactionPicker::AreFilesInCompaction`

Reconstruction of one vendor body of the pinned node #115 artifact:

| | |
|---|---|
| symbol | `_ZN7rocksdb16CompactionPicker20AreFilesInCompactionERKSt6vectorIPNS_12FileMetaDataESaIS3_EE` |
| demangled | `rocksdb::CompactionPicker::AreFilesInCompaction(std::vector<rocksdb::FileMetaData*> const&)` |
| address | `0x5d9a390..0x5d9a3cf` (63 bytes, 22 instructions, 1 `.eh_frame` FDE) |
| member | `e7c8f0e01ce23ae2-compaction_picker.o` (`liblibrocksdb_sys-b032f986857674dc.rlib`) |
| crate / version | `librocksdb-sys` / `0.11.0+8.1.1` |
| body sha256 | `6de8326a03541c2778148ae408b2f22c254ffdb5d4e5c204fc145911752d90b3` (raw-equal to the rebuilt source body, 0 relocations) |
| memory effect | 4 loads, **0 stores**, no call, no indirect branch |
| callers | **9 direct calls in 5 FDEs**, all 9 read the result, 0 discard it |

## Recovered semantics

```c
// rsi = &files  (vector header: begin at +0x0, end at +0x8, cap at +0x10)
// returns the first non-zero byte at +0xb4 of any element, or 0
n = (end - begin) >> 3;                 // sar $0x3, signed - see the precondition
if (end == begin) return 0;             // answered from the header, no element touched
for (i = 0;; ++i) {                     // rotated do-while
    FileMetaData* f = files[i];
    uint8_t flag = *(uint8_t*)((char*)f + 0xb4);
    if (flag != 0) return flag;         // the byte itself, not a normalised true
    if ((uint64_t)i >= (uint64_t)n) return flag;   // jae, unsigned - the exit share
}
```

Five things the packet pins that a source reading alone does not give:

1. **the empty vector never dereferences an element** — `cmp %rcx,%rax; je 0x5d9a3cb` goes
   straight to the shared exit with `edx = 0`;
2. **the return value is the flag byte itself**, zero-extended by `movzbl`, so a build that
   wrote `2` or `0xFF` at `+0xb4` would return that value;
3. **there is a single `ret`** — the empty path and the not-found path both funnel through
   `mov %edx,%eax` at `0x5d9a3c8`;
4. **the loop is a rotated do-while**: the increment and the unsigned bound test live at the
   back edge after a 2-byte `xchg %ax,%ax` alignment nop, so the body loads an element before
   it has tested that any exists;
5. **the count is a signed shift compared unsigned** — impossible for a valid `std::vector`
   (`end >= begin`), and the model asserts that precondition instead of inventing behaviour
   for it.

## Caller census (recomputed from `.text` and `.eh_frame`)

| site | caller FDE | first use | what the caller does |
|---|---|---|---|
| `0x5d9a539` | `0x5d9a400..0x5d9a5b8` | arithmetic | `xor eax,1` — asks for the negation |
| `0x5d9dae8` | `0x5d9da80..0x5d9db2f` | **returned** | the predicate becomes the caller's own return value |
| `0x5d9de9d` | `0x5d9dd80..0x5d9e6b2` | arithmetic | `test al,al` |
| `0x5d9e0b0` | `0x5d9dd80..0x5d9e6b2` | stored | `mov byte ptr [rbp - 0x195],al` |
| `0x5d9e18a` | `0x5d9dd80..0x5d9e6b2` | arithmetic | `test al,al` |
| `0x5d9e4e7` | `0x5d9dd80..0x5d9e6b2` | arithmetic | `test al,al` |
| `0x5da3af9` | `0x5da3060..0x5da48ec` | arithmetic | copied to `ecx`, then `test cl,cl` |
| `0x5da3d7c` | `0x5da3060..0x5da48ec` | arithmetic | `test al,al` |
| `0x5df2b48` | `0x5df2380..0x5df3659` | arithmetic | `test al,al` |

`consumers = {arithmetic: 7, returned: 1, stored: 1}`, `discarded = 0`.

The census is derived from the artifact, not from the excerpt: a Capstone linear sweep of
`.text` finds the 9 direct calls, `.eh_frame` attributes each one to its FDE, and a taint walk
then follows `rax`/`eax`/`al` forward inside that FDE until it is first consumed. The taint is
dropped when a register is overwritten and at every intervening `call`; a **conditional branch
is not treated as a clobber** (only `call` is), and the ABI kill is applied explicitly because
Capstone does not report `rax` among a `call`'s written registers. The site at `0x5d9dae8` is
exactly why that matters: it carries the byte in the callee-saved `ebx` across an intervening
`call _ZdlPvm` and moves it back to `eax` at the epilogue, so the routine's result *is* that
caller's return value.

## Evidence

```
python3 research/work-items/RE-002-node115-rocksdb-are-files-in-compaction-5d9a390-115/export_excerpts.py
python3 tools/rocksdb_are_files_in_compaction_5d9a390_115.py
python3 research/work-items/RE-002-node115-rocksdb-are-files-in-compaction-5d9a390-115/census.py
python3 research/work-items/RE-002-node115-rocksdb-are-files-in-compaction-5d9a390-115/semantics.py
python3 research/work-items/RE-002-node115-rocksdb-are-files-in-compaction-5d9a390-115/verify.py
python3 -m unittest discover -s tests -p 'test_rocksdb_are_files_in_compaction_5d9a390_115.py'
```

| file | what it holds |
|---|---|
| `main.txt` | the raw window listing: encoded bytes + instruction text, branch annotations stripped |
| `frames.txt` | the routine's FDE and the five FDEs that call it |
| `relocations.txt` | the empty relocation set and the body digest |
| `semantics.tsv` | 22 claim anchors, one per instruction |
| `callers.tsv`, `caller_use.tsv` | the census tables above |
| `cases.tsv` | the 300-row ledger (model vs decoded-bytes answer, 0 disagreements) |
| `accesses.tsv` | the routine's executed memory effect (6 loads / 0 stores) |
| `records.json` | the bound context, register roles, census contract and unknowns |

Two independent artefacts are kept apart on purpose: `model()` is the closed-form
reconstruction a reader would author, and `decoded()` executes the routine's **own bytes** in a
small interpreter that raises on any instruction or operand form it does not implement. A
disagreement between them is a finding, not a transcription bug.

## Validation

`verify.py` re-derives the whole packet from the artifact and the committed excerpts:
manifest digests, the 63-byte window digest and its int3 fencing, the byte-for-byte agreement
between the excerpt and the artifact, the 22 anchors (each one a real instruction, re-decoded
with Capstone), the census (9 calls / 5 FDEs / the consumer map above, recomputed from `.text`
and `.eh_frame`), the model-vs-decoded ledger and sweep, and the static memory effect
(4 loads / 0 stores in 22 instructions, 63 bytes).

## Limits

- The name of the field at `+0xb4` (`FileMetaData::being_compacted`) comes from the public
  rocksdb 8.1.1 source; the binary fixes the offset, not the name.
- The five caller FDEs are identified by address range only — the image is stripped, so no
  claim is made about which method each one is.
- The census follows the linear fall-through inside each FDE; a value that only dies on a
  branch path would still be reported as read. No site here is path-dependent.
- The three identical source copies the vendor census records are not enumerated; the
  reconstruction is bound to the body sha256.
- No claim is made about the routine's behaviour on an invalid vector (`end < begin`), which the
  model rejects rather than models.
