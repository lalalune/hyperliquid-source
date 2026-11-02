# RE-004: What the same-callee trio's shared callees compute (node #94)

- Component ID: RE-004 (core-to-EVM value construction; trio constructors)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Claim status: observation for the byte-level facts listed under Evidence;
  inference for the "constructor" and "template instance" role names;
  unresolved items listed at the end.
- Scope included and excluded: included - the three 501-byte FDEs that the
  #166 same-callee trio calls, their 30-byte tag thunks, the two shared
  helpers they call, and all 12 direct `call rel32` sites reaching them
  (6 caller functions, 2 sites each), with each site's output buffer,
  header store, and install copy. Excluded - the helpers' internals, the
  gate comparisons themselves (#165), the non-rejoin path partition (#166),
  the decoded-buffer producers, the tag/empty-string roles, and node #115.
- Relation to prior packets: this packet answers #166's Next question (a)
  directly - what the trio's shared callees compute and whether their output
  depends on anything other than the buffer they are given. It does not
  re-claim #165's 47 gates or #166's 13-gate partition: the newly claimed
  bytes are the 3 constructor bodies (3 x 501) plus the 3 thunk bodies
  (3 x 30) = 1593 bytes, none of which appears in #157-#166's claimed FDE
  sets. The 12 call sites and install copies are anchors into the gate
  functions, listed for the census, not counted as newly claimed bytes.
  This is not template population: the three constructors are one contract
  in a single packet, not one packet per clone.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3
(standard library only), GNU objdump 2.42 for the optional human cross-check.
The binary is only read; nothing is executed.

```
python3 tools/artifacts.py verify
python3 tools/trio_constructor_callers.py --out research/work-items/RE-004-trio-constructor-callers-94
python3 -m unittest tests.test_trio_constructor_callers -v
sha256sum -c research/work-items/RE-004-trio-constructor-callers-94/MANIFEST.sha256
# optional cross-check of one constructor and one thunk
objdump -d -M intel --start-address=0x4e6c8b0 --stop-address=0x4e6caa5 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4e73650 --stop-address=0x4e7366e artifacts/node/94/hl-node
# optional cross-check of the tag-slot relocations
readelf -r -W artifacts/node/94/hl-node | grep -E "574b9c0|574ce30|574b950"
```

The tool refuses to run if the input SHA-256 differs. It prints the summary
`{"call_sites": 12, "constructors": 3, "helper_sites": 9,
"pairwise_differing_bytes": {"AB": 32, "AC": 22, "BC": 32}}`
and writes `evidence.json`, `constructors.tsv`,
`constructor-differences.tsv`, `call-sites.tsv` and `helper-sites.tsv`
(MANIFEST hashes beside them).

## Evidence

Coordinates are ELF virtual addresses. `.text` VA = file offset + 0x1000.
Function extents come from `.eh_frame` FDE records (via the repo's shared
`tools/fde_extents.py` parser), not from the start-only unwind index.
Segment lines below give start..end with length == end - start, plus digest,
so a checker can recover the exact bytes.

1. Three constructors, one template. FDEs `0x4e6c8b0..0x4e6caa5`,
   `0x4e81dc0..0x4e81fb5`, `0x4e6b5f0..0x4e6b7e5`, each 501 bytes
   (`constructors.tsv`, `evidence.json: constructors`):
   A sha256 `fcd65620ff13915c6b71153b4b74df2ac434eff210271ce5051f42705c482474`,
   B sha256 `340c807076867e092ba7d494e29943b34e97e48483c4daa10133b3e27e993a69`,
   C sha256 `c8192eedf6a5d389f8b72b197efd51bec71bad72d378b6754651607ee0722d74`.
   Pairwise differing bytes: A-B 32 (agreement 469/501), A-C 22 (479/501),
   B-C 32 (469/501), all recorded byte-by-byte in
   `constructor-differences.tsv`.
2. Every differing byte is an address field. The 32/22/32 differing bytes
   fall inside exactly 10 instructions per pair (body offsets 29, 99, 295,
   326, 368, 383, 447, 465, 487, 496). Resolving each instruction's disp32
   in all three instances gives 9 shared targets plus 1 per-instance slot:
   PLT-indirect malloc `0x576dfd8` (offsets 29, 326), helper `0x4e7d270`
   (99), helper `0x4e7c6b0` (295), empty-string pointer `0x1e629b` (383),
   PLT `0x576e020` (447), PLT `0x576dfb8` (465), PLT `0x576e010` (487),
   `_Unwind_Resume` PLT `0x5660110` (496), and the tag-slot lea (368) whose
   target differs per instance: A `0x574b9c0`, B `0x574ce30`, C `0x574b950`.
   No logic byte differs: the three bodies are the same code with different
   embedded addresses.
3. Fixed output contract. Each constructor takes a single argument, the
   output pointer in rdi (saved at `[rsp+0x20]` on entry; no caller data
   pointer is read), and writes exactly 6 qwords, 0x30 bytes:
   `[out+0x0]` = tag-slot pointer, `[out+0x8]` = `0x1e629b`,
   `[out+0x10]` = 1, `[out+0x18]` = 0, `[out+0x20]` = heap-block pointer,
   `[out+0x28]` = 0. The stores are at body offsets 368..418 (lea + mov
   pairs, verified as template patterns by the tool).
4. Heap block. On the success path the constructor allocates 0x28 bytes
   (PLT malloc `0x576dfd8`, `mov edi,0x28`) and writes 5 qwords:
   `[heap+0x0]` = 1, `[heap+0x8]` = 1, `[heap+0x10]` = masked-byte buffer,
   `[heap+0x18]` = 8, `[heap+0x20]` = capacity. Capacity starts at 1
   (`[rsp+0x8]` = 1 after the first 1-byte malloc) and grows through the
   helper at `0x4e7c6b0`, called with the capacity/buffer pair at
   `[rsp+0x8]` whenever the write index reaches capacity.
5. Masked-copy loop. The body calls helper `0x4e7d270` once (body offset 99)
   with the local struct at `[rsp+0x28]`, then loops copying bytes from
   that struct's fields, ANDing each byte with the mask byte at `[rsp+0x40]`
   (`and r15b,bpl` at body offset 0x94) and storing it to the growing
   buffer (`mov [r14+r12],r15b` at body offset 0x9e). A secondary path
   ANDs with the byte at `[rsp+0x50]` (saved to `[rsp+0x6]`). What helper
   `0x4e7d270` puts in the struct, and where the masked bytes ultimately
   come from, is helper-internal and unresolved (see Limitations).
6. Tag slot and thunk. Each constructor's first output field points at a
   `.data.rel.ro` slot whose file bytes are zero and whose `R_X86_64_RELATIVE`
   relocation resolves it to a 30-byte thunk: A slot `0x574b9c0` ->
   thunk `0x4e73650..0x4e7366e`, B slot `0x574ce30` ->
   thunk `0x4e84aa0..0x4e84abe`, C slot `0x574b950` ->
   thunk `0x4e6c880..0x4e6c89e`. Each thunk, called as (out, rdx, rcx),
   writes `[out+0x0]` = its own slot address, `[out+0x8]` = rdx,
   `[out+0x10]` = rcx, `[out+0x18]` = 0, and returns out. The three thunks
   are byte-identical modulo their own slot lea (digests in
   `constructors.tsv`). The tag is therefore self-referential: the value's
   first field names the slot that names its initializer.
7. Empty-string field. The second output field, `0x1e629b`, points at a
   NUL byte in `.rodata` that immediately follows the terminator of the
   path string `.../chrono-0.4.38/src/naive/date/mod.rs` (which ends at
   `0x1e629a`; the next string, an h2 path, begins at `0x1e629c`). So the
   field is a pointer to an empty string sitting between two crate path
   strings. Its role (default name, sentinel, or string-table artifact)
   is unresolved.
8. Caller census: 12 sites, 6 functions, exactly 2 per function
   (`call-sites.tsv`). Every site is a direct `call rel32` to its
   constructor, verified byte-by-byte by the tool:

   | caller FDE | role | callee | call | out buffer | header store | install copy |
   |---|---|---|---|---|---|---|
   | 0x4e6fd50..0x4e6fee2 | trio | A | 0x4e6fdb7 | [rsp+0x38] | [rsp+0x30]=1 | [obj+0x0..0x40] from [rsp+0x30..0x70] (non-match) |
   | 0x4e6fd50..0x4e6fee2 | trio | A | 0x4e6fe3c | [rsp+0x0] (mov rdi,rsp) | [r14]=1 | [r14+0x0..0x38] from [rsp+0x0..0x30] (match) |
   | 0x4e6fef0..0x4e713bd | orchestrator | A | 0x4e70804 | [rsp+0x28] | [rsp+0x20]=1 | join-block install (not traced here) |
   | 0x4e6fef0..0x4e713bd | orchestrator | A | 0x4e70e58 | [rsp+0xe0] | none (direct movups reads) | direct movups reads from [rsp+0xe0..] |
   | 0x4e852a0..0x4e85663 | double-gate | B | 0x4e85320 | [rsp+0x58] | [rsp+0x50]=1 | [r14+0x0..0x40] from [rsp+0x50..0x90] (non-match) |
   | 0x4e852a0..0x4e85663 | double-gate | B | 0x4e85454 | [rsp+0x20] | [r14]=1 | [r14+0x0..0x38] from [rsp+0x20..0x50] (match) |
   | 0x4e856f0..0x4e85b12 | trio | B | 0x4e85769 | [rsp+0x78] | [rsp+0x70]=1 | [r14+0x0..0x40] from [rsp+0x70..0xb0] (non-match) |
   | 0x4e856f0..0x4e85b12 | trio | B | 0x4e858cd | [rsp+0x20] | [r14]=1 | [r14+0x0..0x38] from [rsp+0x20..0x50] (match) |
   | 0x4e862b0..0x4e8673a | gate-like | B | 0x4e86384 | [rsp+0x98] | [rsp+0x90]=1 | [r14+0x0..0x40] from [rsp+0x90..0xd0] |
   | 0x4e862b0..0x4e8673a | gate-like | B | 0x4e8644c | [rsp+0x20] | [r14]=1 | [r14+0x0..0x38] from [rsp+0x20..0x50] |
   | 0x4e6bcb0..0x4e6c840 | trio | C | 0x4e6bf8b | [rsp+0x38] | [rsp+0x30]=1 | [rbp+0x0..0x40] from [rsp+0x30..0x70] (non-match) |
   | 0x4e6bcb0..0x4e6c840 | trio | C | 0x4e6c028 | [rsp+0x30] | [rbp]=1 | [rbp+0x0..0x38] from [rsp+0x30..0x60] (match) |

   No other direct call reaches any of the three constructors: the census
   was taken by scanning every `E8` byte in `.text` for the three targets.
   (The 0x4e862b0 pair is gate-like, not sentinel-gated: its branch is a
   register-value comparison, so it sits outside #165's census; it is
   included here because it calls the same constructor.)
9. Install shape asymmetry. In every gate-pattern caller, the non-match
   install copies 0x40 bytes (header + 6 constructor fields + 8 tail
   bytes) while the match install copies 0x38 bytes (header + 6 fields).
   The 8 tail bytes are read from stack slots the constructor never wrote:
   the constructor writes `[buf+0x0..0x30]` and the header is 8 bytes, so
   `[buf+0x38..0x40]` of the install source is outside both writes. What
   produced those 8 bytes is unresolved (see Next question).
10. Helper sharing. Helper `0x4e7d270` has 4 direct call sites (in the
    three constructors plus FDE `0x4e76900..0x4e76af5`); helper `0x4e7c6b0`
    has 5 (the same 4 functions plus FDE `0x4e88d10..0x4e88e8e`)
    (`helper-sites.tsv`). The helpers are therefore not constructor-private;
    their internals are out of this packet's scope.

## Inferences (not observations)

- The three constructors are instances of one code template: identical
  logic, differing only in embedded addresses and one per-instance data
  pointer. The per-instance difference is the tag slot, not the algorithm.
- Answer to #166(a): the constructor's output does NOT depend on any
  caller data pointer, because it takes none: the only caller-supplied
  input is the output buffer address. The gate's only effect on the value
  is which buffer the constructor writes to (scratch buffer on the
  non-match side, the decoded buffer in place on the match side in the
  trio). The output content comes from the helpers' state (mask bytes,
  shared pointers) plus the fixed fields, not from the caller's decoded
  value. This is bounded by the helper caveat: helper `0x4e7d270` reads a
  caller-built local struct only in the sense that the constructor builds
  it internally before the call; no caller buffer address reaches it.
- The match/non-match install asymmetry (0x38 vs 0x40) is systematic
  across all four gate-pattern callers, not a one-site accident.

## Limitations

- Helper internals are not analyzed: what `0x4e7d270` writes into the
  `[rsp+0x28]` struct, what `0x4e7c6b0` does to grow the buffer, and what
  the masked bytes represent are all unresolved.
- The tag slot's role (type tag, vtable-ish tag, or callback registry) and
  the empty-string field's role are not determined from code alone.
- The 0x4e6fef0 orchestrator's join-block install ranges are not traced;
  only its two call buffers and header stores are recorded.
- The 0x4e862b0 second site's install continues past `[r14+0x0..0x38]`
  with further reads from `[rsp+0x70..]`; those further fields are not
  traced here.
- Failure paths are noted but not modeled: a failed first malloc goes to
  a cleanup + `_Unwind_Resume` path; a failed heap malloc goes to a
  PLT `0x576e020` call followed by `ud2`.

## Next question

- Who produces the 8 tail bytes that the non-match installs copy from
  `[buf+0x38..0x40]` (stack slots the constructor never wrote)? A concrete
  writer with byte anchors would close the last gap in the installed
  value's provenance. Until one is found, the installed object's final
  qword must be reported as unproduced-by-the-constructor, not assumed.
