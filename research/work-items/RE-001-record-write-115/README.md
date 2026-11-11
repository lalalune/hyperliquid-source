# RE-001: pin node #115 record-write entry 0x5f0f930 with its three once-helper sites and the 0x5f0e890 insert dispatch

Task: RE-001. Target: node #115 binary `work/hl-node-115.bin`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(the digest in `provenance/artifacts.json`).

## Bounded question

What does the full record-write entry 0x5f0f930 do end to end on
node #115: how is the internal key built, how are the two product
lookups resolved, what does the virtual dispatch at owner slot
0x40 do with its three once-helper sites, when does the grow path
run, when does ProtectionInfo validation run and fail, and how does
the arm-2 path reach the 0x5f0e890 insert from #3330? This packet
pins, end to end:

- the entry window 0x5f0f930..0x5f10134 (516 bytes code, landing
  pads 0x5f100ea..0x5f10134): the out Status* (rdi), the owner
  (rsi/r12), the tag qword (rdx), the key slice record (rcx), the
  options slice record (r8), the direct pointer or null (r9).
- the key build 0x5eab0c0: varint(len(key)+8) + key + [second
  slice] + trailer ((tag<<8)|0x16, 8 LE bytes); inline buffer iff
  len(key)+len(second)+13 <= 0xc8 (200), else operator new. The
  -0x150 slice is the built key minus its 8-byte trailer (varint
  prefix + user key); it is the slice the bucket projection, the
  product-2 check, the arm-1 fold's fourth hash and the resolve's
  second slice all read. It is an out-parameter of the product-1
  slot-0x30 call, overwritten with {data, total-8} before any
  read.
- the product-1 lookup on owner+0xa50: slot 0x98 vs GOT
  0x64ed778 (0x5f04d80, #3286's forwarder); canonical calls slot
  0x90 instead. Then slot 0x30, slot 0x10 (must be true, else
  NotFound), slot 0x18 returns the found key bytes. The found-key
  length is parsed (first byte < 0x80, else varint32 0x61bd4f0);
  the trailer is the qword at payload + klen - 8 and its low byte
  must be 1 (kTypeValue), else NotFound.
- the product-2 lookup on owner+0x10: slot 0x98 vs GOT
  0x64ed010 (0x5d2ca80); canonical calls slot 0x10 on the
  product+0x20 subobject. Opposite return senses: the canonical
  slot 0x10 proceeds on return 0, the non-canonical slot 0x98
  proceeds on nonzero return.
- the value length 0x5f06f40 at trailer + 8, the bucket
  projection 0x5f099b0 (#2115, merged) on the -0x150 slice, and
  the bucket write-lock 0x60d5ab0.
- the dispatch `call *0x40(%r12)` with (value ptr, &-0x17c
  reported-length inout, options record by value, &-0x140 out
  string, orig r9), returning 0, 1 or 2:
  - Arm 0: once helper 0x5f07490 at 0x5f0fc4d; out Status{0}.
  - Arm 1 (0x5f0fce4): if reported_len < vlen, grow: re-encode
    varint(reported_len) at the value-varint position; when
    varint_len(vlen) > varint_len(reported_len) the value bytes
    shift with memcpy. Stats slot 0xb0 code 0x27 on owner+0x50
    if non-null. If r9 non-null: fold = *(r9) ^
    H(tag, 0x77a00858ddd37f21) ^ H(trailer>>8,
    0x77a00858ddd37f21) ^ H(options, 0xd28aad72f49bd50b) ^
    H(-0x150 slice, 0xd28aad72f49bd50b); resolve 0x5f09e90
    with value_ptr=&fold (direct path), first_slice=orig-rcx,
    second_slice=-0x150, byte_in=1, qword_in=trailer>>8,
    out_slot=value_ptr+reported_len, stored truncated to
    owner+0x6c width; then validate 0x5f09b10 over the found
    record [0, value_end) with capacity *(*(owner+0x10)+0x28)
    and protection=fold; out is the validate status (Corruption
    code 2 + one of 7 messages on failure). If r9 null: resolve
    runs its own four-way fold and out={0} with no validate.
  - Arm 2 (0x5f0ff5e): fold2 = *(r9) ^ H(options,
    0xd28aad72f49bd50b) ^ H(dispatch out-string,
    0xd28aad72f49bd50b); insert 0x5f0e890 (#3330) at 0x5f0ff12
    with out=&-0x150 (reused slot), owner, keypart=tag, type=1,
    part1=orig-rcx slice, part2=dispatch out-string slice,
    arg7=&fold2 (or NULL when r9 null, in which case insert
    runs its own hash path and validate is skipped), flag=0,
    context=NULL, counters=NULL. Insert status move-assigned
    -0x150 -> temp -0x170 -> out via 0x5f05310 twice; the two
    delete[] checks after each move find null (the move
    already zeroed the source) and are no-ops. Stats slot 0xb0
    code 0x25; once; out is the insert status (OK, TryAgain 13
    "key+seq exists", or Corruption).
  - Any other dispatch code returns NotFound (code 1).
- the three once-helper sites, one per dispatch arm
  (0x5f0fc4d, 0x5f0fce4, 0x5f0ff5e) — all live. This answers the
  state file's open question from #3322/#3330 about the
  reachability of the three once-helper sites in 0x5f0f930.
  The census counts all 7 sites of 0x5f07490: the other four
  are 0x5f0ef46 (in 0x5f0e890), 0x5f10920 (in the 0x5f103f0
  tail), 0x5fbced8 and 0x5fbd180 (the unreachable tree-walk
  sites from #3322).
- the single caller: 0x5f0f930 has exactly one caller,
  0x5fc6433, inside FDE 0x5fc6070..0x5fc6e8b — the same
  function also calls the sibling 0x5f0f3d0 at 0x5fc625c.
- the helpers pinned whole-function: the varint encoder
  0x61bd410 and decoder 0x61bd4f0, the record move-assign
  0x5f05310, the once helper 0x5f07490 with its predicate
  0x5f07300, and the rwlock write-lock 0x60d5ab0 / unlock
  0x60d5c30 (rc in {0, 0x10, 0x6e} accepted, else fprintf
  "pthread %s: %s\n" then _M_dispose + abort).
- the epilogue (dispatch arms only): bucket unlock 0x60d5c30,
  out-string _M_dispose, product-1 release (slot 0x8 on rbx),
  key-buffer delete[] iff heap-allocated. Early-NotFound
  paths skip the lock/unlock and the dispose (the string is
  empty SSO there).

## Claim status

- Observation: every address, byte range, call site, GOT
  slot, relocation record, census count and literal in
  `records.json` was read from the binary and re-checked by
  `verify.py` against a fresh objdump run and the raw
  binary; the 14 excerpts are verbatim objdump output.
- Inference: the field names (owner, product, tag, options,
  direct) and the C++-level reading of the slots (the
  dispatch callee behind owner slot 0x40, the exact meaning
  of dispatch codes 0/1/2) are inferred from the arms and
  the surrounding packets; the exact C++ spelling is not
  claimed.
- Unresolved: the body of the 64-bit hash callee 0x61c3530
  (cited by contract only, as in the merged packets); the
  concrete callee of the owner's virtual slot 0x40 and the
  exact C++ meaning of codes 0/1/2; whether the dispatch
  writes a smaller length to -0x17c (inferred from the
  arm-1 comparison, not proven from this window alone); a
  found-key varint failure returns 0 in the binary (the
  window would then read at payload+len-8 with a null
  pointer) while the model raises ValueError; what the
  single caller 0x5fc6433 is and what it passes as the
  key/tag/options/direct arguments.

## Evidence

- `main.txt`: the whole entry 0x5f0f930..0x5f10134,
  verbatim. Mnemonics such as `endbr64` are genuine
  instructions present in the target binary, not
  placeholders.
- `key_build.txt`: the whole key builder
  0x5eab0c0..0x5eab192, verbatim.
- `key_len.txt`: the whole length reader
  0x5f06f40..0x5f06f99, verbatim.
- `varint_encode.txt`: the whole varint encoder
  0x61bd410..0x61bd4e9, verbatim.
- `varint_decode.txt`: the whole varint decoder
  0x61bd4f0..0x61bd53b, verbatim.
- `record_insert.txt`: the whole insert
  0x5f0e890..0x5f0f37e, re-shipped byte-identical from
  #3330 (SHA-256 `36ec095b…`).
- `record_move.txt`: the whole record move-assign
  0x5f05310..0x5f05379, re-shipped byte-identical from
  #3330 (SHA-256 `0860da25…`).
- `once_helper.txt`, `once_predicate.txt`: the once helper
  0x5f07490 and its predicate 0x5f07300, re-shipped
  byte-identical from #3330 (SHA-256 `0173f065…`,
  `bf883076…`).
- `value_resolve.txt`: the whole resolver
  0x5f09e90..0x5f09faf, re-shipped byte-identical from
  #3330 (SHA-256 `11242b89…`).
- `protection_validate.txt`: the whole validator
  0x5f09b10..0x5f09e84, re-shipped byte-identical from
  #3330 (SHA-256 `d6da3d8b…`).
- `hash_bucket.txt`: the whole bucket projection
  0x5f099b0..0x5f09a42, re-shipped byte-identical from
  upstream main (SHA-256 `1d176feb…`).
- `rwlock_wrlock.txt`, `rwlock_unlock.txt`: the whole
  write-lock 0x60d5ab0..0x60d5b45 and unlock
  0x60d5c30..0x60d5cc5, verbatim.
- `records.json`: semantic records only; instruction-level
  detail lives in the raw excerpts above.
- `frames.txt`: the 14 FDE ranges from a fresh readelf run.
- `callers.tsv`: 530 caller rows (plus header) from the
  census run over all 16 pinned routines.
- `relocations.txt`: the 2 RELATIVE records for the GOT
  slots this packet reads.
- `census.py`, `export_excerpts.py`: the scripts that
  produced `callers.tsv`/`relocations.txt` and the
  excerpts; `verify.py` re-runs every check from the
  binary and prints ALL CHECKS PASSED.

## Relationship to earlier work

- #3330 (RE-001 record insert) pins the insert 0x5f0e890
  this routine dispatches to in arm 2, and the once
  helper, move-assign, resolve and validate excerpts
  re-shipped here.
- #3322 (RE-001 lazy one-time resolver) pins the once
  helper 0x5f07490 and records the three once-helper
  sites in 0x5f0f930 as an open question; this packet
  answers it (all three are live, one per dispatch arm).
- #3286 pins the canonical forwarder 0x5f04d80 behind GOT
  slot 0x64ed778.
- The merged packets RE-001-value-resolve-store-115 and
  RE-001-protection-info-validate-115 pin the two callees
  this window calls at 0x5f0fe15/0x5f10096 and 0x5f0fe35;
  their excerpts are re-shipped byte-identical here.
- RE-001-hash-bucket-projection-115 (#2115, merged) pins
  the bucket projection this window calls at 0x5f0fbdf.
- #3037 pins the stats-emit caller 0x5d7dfc0, the routine
  ruled out as this cycle's candidate because it was
  already covered.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java,
so `make verify` / `make catalogue-check` cannot run here;
the packet is verified instead by `verify.py` (fresh
objdump + raw-binary byte checks) and by the model tests
in `tests/test_record_write_115.py` (118 checks, run
directly; no pytest on this VM). The 64-bit hash callee
0x61c3530 is cited by contract only and injected as
`hash64` in the model and tests.

## How to verify

    python3 research/work-items/RE-001-record-write-115/verify.py
    python3 tests/test_record_write_115.py
