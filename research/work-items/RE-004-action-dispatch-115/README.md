# RE-004: reconstruct the seven-arm action dispatcher at 0x50d3530 and the callees it composes

- Component ID: RE-004 (quantities and asset ids; `l1/asset/pdi.rs`, `l1/spot_meta.rs`, `base/l1_map/entry.rs`
  and `l1/exchange/impl_outcome_deploy.rs` are the reference leads for the five body group 0x4dd59a0, 0x50d3530,
  0x55c1580, 0x55d1ff0, 0x5acc8c0)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base `a8616af9432b8d8517b2af677880e117b7c28ef3`; no reference tree
  was copied and the older release (#94) was not used
- Claim status: observations (Evidence), inferences (listed separately), unresolved items (listed separately)
- Scope included: the complete FDE 0x50d3530..0x50d3f39 (2,569 bytes, 496 instructions, jump table 0x91a328),
  the asset-id vector builder 0x5acc8c0 (312 bytes), the dex search twins 0x446af70 / 0x446b070 (254 bytes each) and the
  dex indexer 0x446b3f0 (113 bytes), all run as real bytes. Scope excluded: the bodies of the other callees
  (0x4dd59a0, 0x55c1580, 0x55d1ff0, 0x5397b50, 0x55bd550, 0x4308890, 0x421a8b0, 0x449d7f0, 0x448d090, 0x54c9c70,
  0x50f1840, 0x43cd290, 0x44e0810), which are served by a scripted host that records every argument.

One sentence: the dispatcher is a seven-arm `match` on a niche-encoded action enum whose arms resolve a coin or dex name
against a vector of 0x510-byte dex records, map the resulting index to a 32-bit asset id (identity below 10,000, plus
100,000 up to index 99,899,999, `0xffffffff` beyond), and forward one of two fixed events, so a Rust port can now be
written arm by arm with every error code, free, and record write fixed by 15,629 byte-checked cases.

## Reproduce

```
sha256sum artifacts/node/115/hl-node
python3 tools/re004_action_dispatch_115.py --out research/work-items/RE-004-action-dispatch-115
python3 -m unittest tests.test_re004_action_dispatch_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

Standard library plus the shared `tools/elf_index.py` and `tools/fde_extents.py` parsers. The binary is only read, never
executed; the generator fails if its SHA-256 differs. One regeneration takes about 40 s with a peak of about 320 MB resident. All output
files except this README and `MANIFEST.sha256` are byte-reproduced by the command above.

## Evidence

Coordinates are virtual addresses of the PIE image (file offset equals address in the first LOAD segment for read-only
data; `.text` by section header). Observations:

1. FDE of the root: start 0x50d3530, end 0x50d3f39 (2,569 bytes); six pushes, `sub $0x218,%rsp`; `rdi` result slot,
   `rsi` action pointer, `rdx` context pointer (`mov %rdx,%r14`). Result slot: u16 code at +0, first payload word at +8;
   code 0x1a2 is success, every other value is an error and the whole 0x70 bytes are copied from the callee result.
2. Prologue (0x50d354e..0x50d357a): `tag = [rsi]`; `index = tag - 2^63 - 13` when `tag > 2^63 + 12` (unsigned `cmova`),
   otherwise 5; `movslq (table,index,4)` with table 0x91a328 and `jmp *%rax`. `arms.tsv` decodes the table: entries 0..6
   are 0x50d357c, 0x50d3780, 0x50d36c9, 0x50d3759, 0x50d366c, 0x50d37c5, 0x50d3820 (all inside the FDE); entries 7..15
   point to 0x50d3f70.. beyond the FDE end, so they belong to a neighbouring table.
3. Arm 0 (tag 2^63+13, String at +8 as capacity, pointer, length): `cmp $0x65,%r13; jae` rejects names of 101 bytes or more
   with code 0x158 (frees the String when capacity is non-zero). Otherwise a 0x29-byte searcher block is built on the
   stack (pointer, length, 0, length, `0x3a0000003a`, 1; the needle is ':') and passed to 0x43cd290; the dex name is the
   prefix before the match (or the empty name 1/0 when absent). Slot 0x64e6a68 (0x446af70) finds the dex; slot
   0x64e69b8 (0x421a8b0) turns (name, dex) into an index; then `cmp $0x270f` (9,999): index kept; `cmp $0x5f45a5f`
   (99,899,999): `add $0x186a0` (100,000); else `0xffffffff`. An event block `{0x35, id:u32, 1:u8}` goes to 0x5397b50
   with the context, whose result slot is the dispatcher result; then the String is freed.
4. Arm 1 (tag 2^63+14): `{0x2d, 21 bytes copied from action+8}` to 0x5397b50; no free.
5. Arm 2 (tag 2^63+15): String at +8 checked by slot 0x64e4e58 (0x4308890); on error the result is copied and the
   String freed; on success 0x4dd59a0 is called with `ctx+0x338`, the String by value and `action+0x20`, result 0x1a2,
   nothing freed (ownership moves).
6. Arm 3 (tag 2^63+16): same 100-byte limit, then slot 0x64e6c18 (0x446b070) searches the dex; `cmp %r13,0x378(%rsi)`
   against 2^63 yields 0x156; flag byte at action+0x20: zero writes `0` to record+0x468, non-zero writes `2` and calls
   0x5acc8c0 over `{record, 0, [record+0x10]}`, then 0x54c9c70(ctx, id) for each returned id, frees the vector
   (`cap*8`) and the String.
7. Arm 4 (tag 2^63+17): 0x55bd550 resolves the String to (record, value); record+0x378 == 2^63 gives 0x156,
   record+0x408 != 2^63+1 gives 0x1a1; slot 0x64e6c20 (0x449d7f0) is probed with (record+0x378, value) and its byte at
   +8 is compared with 2: with the flag set the follow-up runs when the byte is 2, with the flag clear when it is not;
   the follow-up computes `value/10000` as `(value*0x346dc5d63886594b)>>64>>11`, indexes the dex vector at
   `ctx+0x1330` through slot 0x64e6ad8 (0x446b3f0) and calls slot 0x64e6c28 (0x448d090) with (handle, value, 1 or 2).
8. Arm 5 (dataful variant: any tag word at or below 2^63+12 and tag 2^63+18): `memcpy` of 0xb0 bytes, 20 zero bytes, then
   0x55d1ff0(ctx, zero20, block); success gives 0x1a2, an error copies the 0x70 result; both end with the drop 0x50f1840.
9. Arm 6 (tag 2^63+19): `cmp 0xb8(%r14),%rax; jae` gives code 0xfa with the index in the payload word; otherwise
   `action[8..0x60)` is passed to 0x55c1580 whose result slot is the dispatcher result.
10. 0x5acc8c0 builds `Vec<u64>` of `10000*[record+0x50] + start + i`; `mulq` overflow and the carry of the final add call the
    panic slots 0x64df870 / 0x64df520, sizes above 2^63-8 or counts with bit 61 set call 0x64df498 with (0, size), a null
    allocation calls it with (8, size). 0x446af70 / 0x446b070 (byte-identical but for panic locations) return the first
    record for an empty name (unwrap failure 0x2b-byte message if none) or search records of stride 0x510 skipping those
    with `[+0x378] == 2^63`, comparing the length at `[[+0x4a0]+0x10]` and then the bytes; 0x156 when none matches.
    0x446b3f0 returns `base + 0x510*i` or the same unwrap failure.

`sites.tsv` lists the instructions whose immediate, displacement, magic constant or shift were matched by byte pattern.
`slots.tsv` lists each callee slot, its relocation addend and the FDE size. Excerpt of the root:

```
 50d3555:  add    $0xfffffffffffffff3,%rcx      # tag - 13 (after + 2^63)
 50d355d:  cmp    %rdx,%rax                     # rdx = 2^63 + 12
 50d3565:  cmova  %rcx,%rax                     # index, else 5
 50d3588:  cmp    $0x65,%r13                    # arm 0: 101-byte limit
 50d3659:  cmp    $0x270f,%rax                  # 9999
 50d3d7d:  cmp    $0x5f45a5f,%rax               # 99,899,999
 50d3e5b:  add    $0x186a0,%eax                 # +100000
 50d3d1f:  movabs $0x346dc5d63886594b,%rcx      # value / 10000
 50d3820:  mov    0x8(%rsi),%rax                # arm 6: index against 0xb8(%r14)
```

## Implementation and comparison

`tools/re004_action_dispatch_115.py` holds (a) an x86-64 interpreter over the ELF bytes with the shared parsers, (b)
`dispatch()` and `vec_model()`, `find_dex()`, `dex_at()`, `asset_id()`, `slot_index()`: the pure model, and (c) the case
generator, comparison and damage battery. For each case a scripted host (`World`) serves the callees: it records the
call name and arguments (including the bytes of every block the callee would read) and returns a scripted 0x70-byte
result, error results being random bytes so a wrong copy length shows. The model and the interpreter must agree on
status, the 0x80 result bytes, the 0x500 record bytes plus the 0x2800 dex vector bytes, and the full call log (also
for panics and frees). No Rust is written yet; the model is a Python specification, not a port.

Cases: 29 edge cases (thresholds 9,998..0x5f45a61, `value/10000` multiples near 2^64, arm-6 bounds) + 1,500 per arm
stub mode + 1,200 per arm (0, 3, 4) composed mode with the dex search, `memcmp`, dex indexing and the vector builder as
real bytes + 1,500 standalone vector builder cases. Damage battery: 124 mutants (condition flips, immediates,
displacements, `cmov`, shift counts, the division magic number) over the five real bodies; each is run against a
battery of 344 + 90 cases and the vector cases and must be noticed.

## Results and limitations

`measure.json`: 15,629 cases, 0 mismatches; 124 negative controls, 117 detected, 7 equivalent (all inside cleanup
blocks entered only through the unwind tables: 0x50d3e9a..0x50d3f18 and 0x5acc9dc; no modelled callee unwinds, so the
mutated instruction cannot run; they are listed with that reason in `equivalent-mutants.tsv`). Instruction coverage
`coverage.tsv`: 668 of 756 instructions of the five bodies executed; the other 88 are the cleanup blocks, padding and
the instructions after diverging panic calls (0 outside those). 39 binary-free unit tests replay 2,850 recorded
digests with the model alone and include wrong-constant and damaged-digest controls.

Inferences (not proven by the bytes): the dex records are HIP-3 perpetual dex records and the ':' split reads
`dex:COIN`; the id rule matches the documented 100,000 + 10,000*dex + asset layout; slot 0x64e6ad8 is
`universe.get(i).unwrap()`; 0x43cd290 is a char-searcher `next_match`; 0x44e0810 is drop glue of a plain error code.

Unresolved: the semantics of events 0x2d and 0x35 and of the 44,573-byte 0x5397b50; bodies of the other callees and of
0x4dd59a0 (map insert), 0x55c1580, 0x55d1ff0 (not interpreted here); the jump table beyond entry 6; `memcmp` and `memcpy`
slots have no local addend (imported, modelled as host calls); no unwinding path is exercised. No progress gate is
requested.

Next question: execute 0x421a8b0 and 0x4308890 as real bytes under the same composed mode to fix the asset index source
and the name validity rule.
