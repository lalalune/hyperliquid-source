# RE-002-node115-rocksdb-get-bg-job-limits-5dd5f00-115

Bounded reconstruction of one vendor routine in the pinned node #115 artifact.

| | |
|---|---|
| artifact | `artifacts/node/115/hl-node` |
| SHA-256 | `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` |
| symbol | `_ZN7rocksdb6DBImpl14GetBGJobLimitsEiiib` |
| signature | `(int max_background_flushes, int max_background_compactions, int max_background_jobs, bool multi_db) -> std::pair<int,int>` |
| member | `4d429ab1cb2d8f8b-db_impl_compaction_flush.o` |
| rlib / crate | `liblibrocksdb_sys-b032f986857674dc.rlib` / `librocksdb-sys` |
| version in the bundle | `0.11.0+8.1.1` (rocksdb 8.1.1) |
| window | `0x5dd5f00..0x5dd5f5b` (91 bytes, 29 instructions, one `.eh_frame` FDE) |
| body | `fdf3ef61c6dc45309e0e7b76154028fa69dfa01fcdcdfb1a12dfdfceb046bc53` (raw-equal, 0 relocations, 3 identical source objects) |

`GetBGJobLimits` decides how many background flush and compaction threads a
rocksdb instance may run, given the three size options and whether the
deployment hosts several databases. `-1` is rocksdb's `kDefault`: "derive this
one". The routine is a **leaf that touches no memory at all** - it reads four
register arguments, computes, and returns.

```
edi = max_background_flushes (int)      esi = max_background_compactions (int)
edx = max_background_jobs (int)         ecx = multi_db (bool; low byte only)
```

## The recovered policy

```c
if (flushes == -1 && compactions == -1) {      /* both kDefault: derive */
    f = jobs > 7 ? jobs / 4 : 1;               /* signed shift $2 */
    c = jobs - f;
    if ((int)c <= 0) c = 1;                    /* signed compare */
} else {
    f = flushes > 0 ? flushes : 1;             /* kDefault and 0 both clamp */
    c = compactions > 0 ? compactions : 1;
}
if (!multi_db) c = 1;                          /* single-db: one compaction */
return (pair){ f, c };
```

Every rule is anchored to the instruction that carries it (`semantics.tsv`, one
row per instruction):

| rule | instruction | address |
|---|---|---|
| the derivation needs **both** counts to be `kDefault` | `cmp $-0x1,%esi` | `0x5dd5f3d` |
| `kDefault` flushes clamps to 1 like a non-positive value | `mov $0x1,%eax` | `0x5dd5f38` |
| the split is `jobs / 4`, signed, and only above 7 jobs | `sar $0x2,%esi` / `cmp $0x7,%edx` | `0x5dd5f44` / `0x5dd5f47` |
| the remainder is clamped with a **signed** compare | `cmovle %esi,%edx` | `0x5dd5f56` |
| a single-db deployment is forced to one compaction, derived path included | `cmove %ecx,%edx`, rejoined by `jmp` at `0x5dd5f59` | `0x5dd5f26` |

Two consequences worth naming, both kept as ledger rows:

- **the clamp is signed, so it clamps `INT_MIN` as well**: at `jobs = INT_MIN`
  the subtraction `jobs - 1` wraps to `INT_MAX`, which is positive and survives
  the clamp, so the routine returns `(1, 2147483647)`;
- **`multi_db = false` overrides the derivation**: even with both counts
  `kDefault` the compaction count becomes 1.

## The return is a packed pair

`std::pair<int,int>` is two INTEGER-class dwords, so the psABI returns both in
the single INTEGER eightbyte `rax`: `rax[31:0]` is the first field (flushes) and
`rax[63:32]` the second (compactions), formed by

```
0x5dd5f29  shl $0x20,%rdx      ; move the compaction count into the high dword
0x5dd5f2d  or  %rdx,%rax       ; rax = compactions:flushes
```

and this is what the callers do with it - **all four** call sites read `rax`,
and every one splits the pair themselves:

| site | caller FDE | first use | where the pair is split |
|---|---|---|---|
| `0x5d7265a` | `0x5d71fe0..0x5d72e50` | `mov rbp, rax` | `sar $0x20` at `0x5d7268d` (via `rbp` -> `r14`) |
| `0x5d7267c` | `0x5d71fe0..0x5d72e50` | `mov r13, rax` | `sar $0x20` at `0x5d72689` |
| `0x5dfceed` | `0x5dfcea0..0x5dfcfb6` | `sar rax, 0x20` | `sar $0x20` at `0x5dfcef9`, in place |
| `0x5e5cff5` | `0x5e5cf70..0x5e5df0f` | `mov r14, rax` | `shr $0x20` at `0x5e5d00c` (via `r14` -> `rcx`) |

Three callers split the pair with a **signed** shift and one with an
**unsigned** shift; both are correct here only because both fields are small
positive ints. No call site discards the value. `census.py` proves the split per
site rather than inferring it from the nearby text: it follows the packed value
through register copies inside the caller's FDE and drops the taint when the
register is overwritten *and* at every intervening call, which clobbers the
caller-saved set - the two adjacent sites in `0x5d71fe0..0x5d72e50` are exactly
that trap.

## Caller census

Four direct calls, no tail jumps, in **three** caller FDEs; consumers
`{register-copy: 3, arithmetic: 1}`; sites reading the return `4`; discarded
`0`. The census is recomputed from `.text` and `.eh_frame` by `census.py`, which
reads the first use of `rax` through Capstone's `regs_access()` so a read
*through* a memory base cannot be missed.

All four call sites pass `multi_db = true` (`mov $0x1,%ecx`), so the single-db
forcing rule is **recovered by decoding, not exercised** by any caller in this
artifact - the packet states that rather than implying reachability.

## Evidence and how to reproduce it

```
python3 tools/rocksdb_get_bg_job_limits_5dd5f00_115.py            # rebuild cases.tsv (300 rows)
python3 research/work-items/RE-002-node115-rocksdb-get-bg-job-limits-5dd5f00-115/census.py
python3 research/work-items/RE-002-node115-rocksdb-get-bg-job-limits-5dd5f00-115/semantics.py --write
python3 research/work-items/RE-002-node115-rocksdb-get-bg-job-limits-5dd5f00-115/verify.py
python3 -m unittest discover -s tests -p 'test_rocksdb_get_bg_job_limits_5dd5f00_115.py'
```

`main.txt` is the raw `objdump -d` listing of the window (regenerate with
`export_excerpts.py`), `frames.txt` the four `.eh_frame` entries involved,
`relocations.txt` the empty relocation record and the body digest.

`verify.py` re-derives everything independently: the excerpt bytes are compared
against the artifact, each of the 29 claim anchors is re-decoded, the census is
recomputed, and the model is re-checked against the decoded instruction stream
over a 3400-case grid plus the 300-row ledger.

## Results and limitations

Proven here:

- the recovered policy, exhaustively: a closed-form model and an emulator that
  executes the routine's own 91 bytes agree on **all 3400 grid cases** (every
  rule edge and the `INT_MIN`/`INT_MAX` neighbourhoods) and on the 300-row
  stratified ledger, with the boundary rows kept verbatim;
- the packed-pair return and its field layout, from the two instructions that
  form it and the four call sites that unpack it;
- that the routine reads and writes no memory (0 loads, 0 stores, 26 non-nop
  instructions), checked rather than asserted: `accesses()` raises if a memory
  operand appears;
- the window is a complete function body: 7 int3 bytes below the entry, 5 above
  the end, no relocations, and raw-equal to its rebuilt source body.

Not established here:

- which `DBOptions` field feeds each argument is an inference from the callers'
  load offsets plus the public rocksdb 8.1.1 source; the binary fixes the
  register roles, not the field names;
- the `multi_db = false` branch has no caller in this artifact;
- the three identical source copies the vendor census records
  (`identical_source_count` 3) are not enumerated individually;
- nothing here claims anything about the callers beyond their FDE ranges.

Next question: whether the two adjacent call sites inside
`0x5d71fe0..0x5d72e50` compute the two configurations that
`MaybeScheduleFlushOrCompaction` compares (`cmp %ebp,%eax; jg ...` at
`0x5d72696`), or two unrelated option sets - that needs the enclosing function.
