# RE-007: decode the PDI asset-name lookup body behind slot 0x64e69b8 (0x421a8b0)

- Component ID: RE-007 (per-index state and registry records, `l1/src/asset/pdi.rs`)
- Target release and full SHA-256: Linux x86-64 node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no source tree was copied
- Claim status: observations (below), inferences (separate section), unresolved items (separate section)
- Scope included: the one complete FDE extent listed next, its six external slots, and the
  call-site census for its slot. Scope excluded: every caller body, the value builder
  `0x3bcb6c0`, and any Rust reconstruction

Independently authored static research; the target was never executed. The body bytes were
run in a small software evaluator whose only externals are recording stubs; that is a model
of the bytes, not execution of the captured binary.

- Complete FDE `[0x421a8b0,0x421a9cc)`: 284 bytes / 78 instructions, no LSDA, body SHA-256
  `6f1a63aad6cfbcc1635d94d4cb57cd28153f4714301d3b23da4711bf1e8cc967`.

Export denominator: **284 bytes / 78 instructions**. This is an evidence extent, not
recovered or compiled-comparison coverage. No progress gate is requested.

## Question and relation to the merged caller packet

The merged packet `RE-007-node115-asset-registration-caller-name-rules` maps the
pre-registration rule check `0x447d760`. Its rule 9 calls the body behind slot
`0x64e69b8` with `(out, suffix pointer, suffix length, front record)` and lists that body
as **Unresolved**, with the body itself as the packet's next question. The RE-001 packet
`RE-001-node115-loc-edge-421a9a4` records only a Location edge into it
(`l1/src/asset/pdi.rs` 32:14) and states the body's meaning remains unresolved. This
packet answers that question for the body alone: what does the lookup compute, and what
exactly does it return or trap on for every input shape?

The slot `0x64e69b8` holds an `R_X86_64_RELATIVE` relocation to `0x421a8b0`. A census of
direct `call [rip+disp32]` sites naming the slot finds **65 call sites inside 49 FDE
extents**, including the rule check (site `0x447da3f`) and the PDI range caller of the
merged RE-004 pdi-range packet (site `0x291385d`); there are no direct `E8` callers.
The full census is in `call-sites.tsv`.

Arguments observed at entry: RDI output pointer, RSI suffix pointer, RDX suffix length,
RCX front record pointer. The front record carries a name-table pointer at `+8`, a record
count at `+0x10`, and a page value at `+0x50`; records are `0x20` bytes with a name
pointer at `+8` and a name length at `+0x10`.

## Observations

1. The count at `[front+0x10]` gates everything. With zero records the function goes
   straight to the miss path: the page product below is never computed, so even a page
   whose product would overflow is ignored (`count-zero-page-overflow-ignored`).
2. With at least one record, `prod = [front+0x50] * 10000` is computed once, before the
   scan. A product above `2^64-1` traps through the multiply-overflow panic shim
   (`[0x64df870]`). The largest page whose product fits is `1844674407370955`, giving
   `prod = 2^64 - 1616`.
3. The scan walks records in order at a `0x20` stride. For each record, the qword at
   `record+0x10` must equal the suffix length before `bcmp` (`[0x64df9f8]`, the
   `bcmp@GLIBC_2.2.5` slot) compares that many bytes from the record's name pointer
   against the suffix. The comparison covers exactly the length-field count of bytes:
   a zero length compares equal against any record, and a length past a shorter stored
   name reads whatever follows it in memory.
4. Before the record at position `p` is examined, `prod + p` is checked for add
   overflow (`jb` to the add-overflow panic shim `[0x64df520]` when the running index
   passes `prod`). At the maximal page the first unreachable position is 1616: a table
   of 1617 records traps before record 1616 is examined even when that record matches,
   position 1615 still returns the index `2^64 - 1`, and a 1616-record table with no
   match traps instead of returning the miss result.
5. A hit stores the word `0x1a2` at `[out]` and the global index `prod + position` at
   `[out+8]` and returns. The first matching record wins. Bytes `out+2..out+8` are
   never written.
6. A miss builds an owned copy of the suffix and stores the word `0x68` at `[out]`:
   - length with the top bit set (negative as `i64`): trap through the
     allocation-error shim (`[0x64df498]`) with arguments `(0, len)`; nothing is stored;
   - length 0: cap `0` at `[out+8]`, pointer `1` at `[out+0x10]`, length `0` at
     `[out+0x18]`; nothing is allocated;
   - any other length: allocate `len` bytes (`[0x64df480]`), copy the suffix into the
     allocation (`memcpy` via `[0x64df508]`), then store cap `len`, the allocation
     pointer, and `len`. An allocation failure traps with arguments `(1, len)`.
7. Both panic shims are entered with RDI = the shared Location object `0x6483fb0`, whose
   embedded string is `l1/src/asset/pdi.rs` at line 32, column 14 — the same Location
   the RE-001 loc-edge packet recorded for this body. The multiply guard's payload
   string is `attempt to multiply with overflow`; the loop guard's is
   `attempt to add with overflow`.

## Validation

`tools/pdi_name_lookup115.py` verifies the target digest and the body digest, decodes
the full extent with a fail-closed decoder for exactly the encodings present (78
instructions, landing exactly on the FDE end), and runs the bytes in the evaluator
against an independently written rule list:

- 31 named cases — hits, misses, decoys (same length different bytes, same bytes
  different length field), duplicate names, empty suffix, empty table, maximal page,
  both overflow guards at their exact boundaries, allocation failure, and the
  `2^63`-length traps: **31/31 match**, including the full `0x20` output bytes, the
  stub call trace, and the heap contents of every miss copy.
- A seeded sweep of **3000** generated tables and suffixes (seed 20261109): **3000/3000
  match**.
- Nine targeted single-point mutations (multiplier, both tags, record stride, length
  offset, count branch, bcmp branch, empty-miss sentinel, page-field offset): **all
  killed**. Two structure controls (wrong body digest, non-FDE start): **both refused**.
  A seeded sample of 60 random single-bit flips: 35 killed, 2 survived, 23 undecodable
  — the survivors are reported as-is in `controls.tsv`.

## Inferences

- The result is a Rust `Result`-shaped value in this binary's layout: tag `0x1a2` with
  one qword payload on success, tag `0x68` with a `{cap, ptr, len}` string triple on
  failure — the missing name itself, owned by the caller. The registration caller can
  therefore report exactly which name was not found.
- The global index `page * 10000 + position` is the same `+0x50` field times-10000
  formula the merged RE-004 pdi-range packet established independently for the body at
  `0x22b3160`, so the page field is a per-dex page number shared across the PDI asset
  table.

## Limitations

- The six external slots are modelled as stubs identified by relocation and call
  shape; the real `bcmp`, `memcpy`, allocator and panic shims were not executed.
- How callers consume the returned index and the error string is outside this body;
  for the registration caller it stays with the RE-007 caller packet's open R8/R9
  question.

## Next question

When the registration caller's optional insert runs, its value is built by
`0x3bcb6c0` from the entry's stored id. What does `0x3bcb6c0` construct, and which of
its five unknown callees decide the stored value's shape?

## Reproduce

```sh
python3 tools/pdi_name_lookup115.py --check
python3 tools/pdi_name_lookup115.py --out research/work-items/RE-007-node115-asset-name-lookup-evaluation
sha256sum -c research/work-items/RE-007-node115-asset-name-lookup-evaluation/MANIFEST.sha256
python3 -m unittest discover -s tests -p test_pdi_name_lookup115.py -v
```

This directory retains the byte-evaluator study. The separate
[static study](../RE-007-node115-asset-name-lookup/README.md) stays in its own
packet; both examine the same bounded body and do not supply additive coverage.
