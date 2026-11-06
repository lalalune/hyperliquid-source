# RE-001: pin node #115 record insert 0x5f0e890 with its key build, ProtectionInfo validate, bloom insert, +0xc18/+0xc20 min-install and type-0xf shared_ptr install

Task: RE-001. Target: node #115 binary `work/hl-node-115.bin`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(the digest in `provenance/artifacts.json`).

## Bounded question

What does the full record insert 0x5f0e890 do end to end on
node #115: how is the key built and the value resolved, when
does ProtectionInfo validation run and fail, how do the two
commit branches dispatch through the product slots, what does
the bloom insert set, who writes owner+0xc18 and owner+0xc20
(the open unknown from #3322), and what does the type-0xf
tail install? This packet pins, end to end:

- the entry window 0x5f0e890..0x5f0f37e (0xaee bytes): the
  owner (rsi/r13), the two-part key (r8/rbp and r9/r12 as
  {ptr, len} slices), the key-part qword (rdx/rbx), the type
  byte (rcx/r15b), the direct-value/protection pointer
  (stack arg7), the flag byte (stack arg8), the opaque
  context pointer (stack arg9) and the counters struct
  (stack arg10).
- the key build: varint(L1+8) + part1 + an 8-byte trailer
  (keypart << 8 | type) + varint(L2) + part2 + width zero
  bytes, where width is *(owner+0x6c); the total is
  varint_len(L1+8) + L1 + 8 + varint_len(L2) + L2 + width.
  The product is owner+0xa58 when type is 0xf, else
  owner+0xa50; the buffer comes from the inner object's
  slot 0x10 when the product's vtable slot 0 is the
  forwarder 0x5f04dc0, else from slot 0 itself.
- the value resolve (0x5f09e90, merged ground, re-shipped
  byte-identical): a directly supplied qword when arg7 is
  non-null, else a four-way xor-fold of the 64-bit hash
  callee over the two key slices, the type byte and the
  key-part, stored truncated to the width at the tail.
- the ProtectionInfo validate (0x5f09b10, merged ground,
  re-shipped byte-identical): run only when arg7 is
  non-null, over the record minus the width-byte tail; two
  varint length parses with capacity bounds, then the
  four-way fold equality; on failure the out status takes
  the Corruption status (code 2) with one of the seven
  pinned messages and the record is not inserted.
- the commit dispatch: flag != 0 runs the product slots
  0x30/0x28/0x38 (or slot 0x40 when the context pointer is
  null) against the GOT canonicals 0x5f05780/0x5f04d20/
  0x5f04d30; flag == 0 runs the +0xc78 filter gate, the map
  find-or-insert 0x5f0e660 and the product slots
  0x20/0x18/0x8, or the direct slot-0x10/slot-0x8 arm when
  the gate is absent or false. Only slots 0x30, 0x40 and
  0x20 gate on their boolean result; a false result builds
  Status TryAgain (code 13) "key+seq exists".
- the counters, path-specific: the flag!=0 path updates
  the caller's counters struct (count +1, total += key
  total, typed +1 when type != 0) at 0x5f0eb0a and never
  touches the owner fields; the flag==0 path updates the
  owner fields +0xa70 (+1), +0xa68 (+= total) and
  +0xa78 (+1 for types 0, 7 and 20, the set bits of
  0x100081) at 0x5f0ee09 and never touches the caller's
  counters struct.
- the bloom insert, one block per path with the same shape
  (0x5f0eb26..0x5f0ec09 on the flag!=0 path,
  0x5f0ee46..0x5f0ef1c on the flag==0 path): the
  +0xc58/+0xc60 filter's slot 0xa0 gates and slot 0x98
  supplies the hashed pair; the golden-ratio mixed hash
  sets two bits per probe for *(filter+0x4) probes,
  rolling right by 12 each probe. When *(owner+0x30) != 0
  a second insert runs on the same pair hashed directly
  (0x5f0f206 on the flag!=0 path, 0x5f0f0a7 on the
  flag==0 path).
- the +0xc18/+0xc20 min-install, which closes the open
  unknown from #3322: block A installs the key-part when
  (old - 1) >= key-part unsigned; block B, gated on +0xc20
  being the sentinel 0x00ffffffffffffff or the key-part
  being below +0xc20, installs it when +0xc18 equals
  +0xc20, is the sentinel, or is above the key-part. When
  +0xc18 is still 0 afterwards — exactly when the
  key-part is 0 — the first-install path stores it and,
  when +0xc20 is still the sentinel, copies it there too.
- the type-0xf tail: one 0x48-byte control holding a
  0x38-byte cache object, then one 0x20-byte control per
  table entry (N = 1 << *(owner+0xd18)); the big control's
  use count ends at N; the +0xce8 mutex is held only when
  the flag is non-zero; +0xa60 ends at 0. Any other type
  runs the once helper 0x5f07490 and the lazy resolver
  0x5f074e0 (#3304/#3322) on the owner instead.
- the helpers pinned whole-function: the map find-or-insert
  0x5f0e660 (hash seed 0x18d, bucket = hash % bucket count,
  0x28-byte nodes), the 32-bit hash 0x61c34a0, the varint
  encoder 0x61bd410, the record move-assign 0x5f05310 and
  the Status builder 0x61cf670.

## Claim status

- Observation: every address, byte range, call site, GOT
  slot, relocation record, census count and literal in
  `records.json` was read from the binary and re-checked by
  `verify.py` against a fresh objdump run and the raw
  binary; the 13 excerpts are verbatim objdump output.
- Inference: the field names (owner, product, filter,
  counters, key-part) and the C++-level reading of the
  slots (SkipListRep products, shared_ptr controls, the
  bloom filter) are inferred from the shapes and the
  surrounding packets; the exact C++ spelling is not
  claimed. The min-install net effect is stated for the
  single-threaded case; the CAS loops are the concurrent
  form.
- Unresolved: the body of the 64-bit hash callee
  0x61c3530 and of the varint decoder 0x61bd4f0 (cited by
  contract only, as in the merged packets); the virtual
  slot implementations behind the product dispatch; the
  node types in the +0xc70 chain; what the +0xc78
  filter's slots compute; the reachability of the three
  once-helper call sites in 0x5f0f930.

## Evidence

- `main.txt`: the whole insert 0x5f0e890..0x5f0f37e,
  verbatim. The function contains jumps into its own
  landing-pad area at 0x5f0f372..0x5f0f379 (endbr64 at
  0x5f0f372, then `mov %rax,%rbx; jmp 0x5f0e860`), which
  is inside the FDE range; the sibling routine 0x5f0f930
  also jumps back into this range (shared cold blocks).
  Mnemonics such as `endbr64` are genuine instructions
  present in the target binary, not placeholders.
- `hash_resolve.txt`: the whole resolver
  0x5f09e90..0x5f09faf, re-shipped byte-identical from
  the merged packet RE-001-value-resolve-store-115.
- `key_validate.txt`: the whole validator
  0x5f09b10..0x5f09e84, re-shipped byte-identical from
  the merged packet RE-001-protection-info-validate-115.
- `map_find_or_insert.txt`: the whole map routine
  0x5f0e660..0x5f0e85f, verbatim.
- `hash32.txt`: the whole 32-bit hash
  0x61c34a0..0x61c3525, verbatim.
- `varint_encode.txt`: the whole varint encoder
  0x61bd410..0x61bd4e9, verbatim.
- `record_move.txt`: the whole record move-assign
  0x5f05310..0x5f05379, verbatim.
- `once_helper.txt`, `once_pred.txt`, `resolver.txt`,
  `canonical.txt`: re-shipped byte-identical from
  #3304/#3322.
- `release.txt`: the whole release helper
  0x5d350c0..0x5d35145, verbatim.
- `status_builder.txt`: the whole Status builder
  0x61cf670..0x61cf767, verbatim.
- `records.json`: semantic records only; instruction-level
  detail lives in the raw excerpts above.
- `frames.txt`: the 13 FDE ranges from a fresh readelf run.
- `callers.tsv`: 2390 caller rows (plus header) from the
  census run over all 15 pinned routines.
- `relocations.txt`: the 8 RELATIVE records for the GOT
  slots this packet reads.
- `census.py`, `export_excerpts.py`: the scripts that
  produced `callers.tsv`/`relocations.txt` and the
  excerpts; `verify.py` re-runs every check from the
  binary and prints ALL CHECKS PASSED.

## Relationship to earlier work

- #3304 (RE-001 owner-tail phases) pins the owner-tail
  init that leaves +0xc18 at 0 and +0xc20 at the
  sentinel, and the once helper 0x5f07490.
- #3322 (RE-001 lazy one-time resolver) pins the tail
  resolver 0x5f074e0 and the canonical 0x5d4b100, and
  records the writer of owner+0xc18 as an open unknown;
  this packet closes that unknown.
- The merged packets RE-001-value-resolve-store-115 and
  RE-001-protection-info-validate-115 pin the two callees
  this window calls at 0x5f0ea4f and 0x5f0ea79; their
  excerpts are re-shipped byte-identical here.
- #3286 pins the SkipListRep products this window selects
  from owner+0xa50/+0xa58.
- #3251 pins the Status builder 0x61cf670; #3263 pins the
  release helper 0x5d350c0.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java,
so `make verify` / `make catalogue-check` cannot run here;
the packet is verified instead by `verify.py` (fresh
objdump + raw-binary byte checks) and by the model tests
in `tests/test_record_insert_115.py` (150 checks, run
directly; no pytest on this VM). The 64-bit hash callee
0x61c3530 is cited by contract only and injected as
`hash64` in the model and tests.

## How to verify

    python3 research/work-items/RE-001-record-insert-115/verify.py
    python3 tests/test_record_insert_115.py
