# RE-006: slot insertion growth and unwind routes on node 94

The insertion primitive increments its occupied counter before validating the requested slot, and its growth and invalid-slot unwind paths use different source-buffer cleanup guards; a reconstruction can therefore preserve the observed write order and conditional cleanup instead of treating slot admission as an atomic check.

- Component ID: RE-006, order-book state transitions.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. Reference labels are leads, not source evidence; no reference code was copied.
- Claim status: the instruction and exception-table facts below are observations; source-level names, field meanings and the conditional consequences of unwinding are inferences, explicitly identified below.
- Scope included and excluded: three slot-insert FDEs, the shared capacity-growth FDE, three incoming call instructions and the two selected landing routes per insert. Generic allocation and deallocation bodies, the enclosing book mutation, compiler/runtime behavior after a process abort, matching, rollback and external effects are excluded.

## Reproduce

Work at the repository root with the pinned target present. The collector requires Python 3 and the repository's `tools/elf_index.py` and `tools/fde_extents.py`; it hashes the target before parsing it. It reads ELF bytes only; it does not execute the captured binary, invoke binutils, or access a network. Recorded environment: Linux x86-64, Python 3.12.3; GNU objdump 2.42 was used only for human inspection and is not an input to generated files or tests.

```sh
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 -m unittest tests.test_book_slot_growth94
python3 tools/book_slot_growth94.py --out <tmp-dir>/first
python3 tools/book_slot_growth94.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
```

The generated evidence files in this directory are exactly the files emitted under either output directory. `MANIFEST.sha256` also covers this README. The generator binds each selected FDE both to the unwind index and to its complete body bytes, decodes the selected LSDA call-site tables and RIP-relative edges, verifies the relocations and copy import, and rejects a non-file-backed mapping. `bodies.tsv`, `cfi.tsv`, `cie.tsv`, `contexts.tsv`, `lsda.tsv`, `witnesses.tsv`, and `functions.tsv` retain raw bytes or hashes for independent inspection. `cases.tsv` contains synthetic projections of the documented branch rules; these are not captured-node executions.

## Evidence

All addresses are linked ELF virtual addresses; file offsets are independently resolved through section headers in `functions.tsv`. Intervals are half-open unwind-described ranges, not a claim about all original source-function boundaries. No address rebasing is applied.

| Role | FDE interval | Body bytes | LSDA |
| --- | --- | ---: | --- |
| Slot insertion A | `0x28e0e40..0x28e0f73` | 307 | `0xa35600` |
| Slot insertion B | `0x28e0f80..0x28e10b3` | 307 | `0xa3561c` |
| Slot insertion C | `0x45a4dd0..0x45a4f03` | 307 | `0xb5578c` |
| Growth wrapper | `0x32d5940..0x32d59a4` | 100 | none |

The three callers in `contexts.tsv` load the key from the candidate slab's `+0x20`, pass the slab, key and source-value pointers, and call A, B and C respectively. This is the only caller context read here. The target's relocated Location records at `0x56c73e8` and `0x572afd0` both point to the suffix `l1/src/slab/slab.rs`, line 79, column 21; the failure arm references those records. These observations support the slab description, but do not prove original Rust names or a complete book call graph.

The three complete insert bodies have distinct raw hashes. Masking exactly nine four-byte RIP-relative displacements in each leaves the same 307-byte sequence; no branch displacement, immediate, opcode, or data byte is masked. `relocations.tsv` further shows that both distinct growth slots resolve through `R_X86_64_RELATIVE` to the same growth wrapper. The slot used by both copy arms is bound to the dynamic symbol `memcpy` in `imports.tsv`. The raw hashes and unmasked bytes remain in the packet, so this is a bounded copy comparison, not whole-ELF equivalence.

### Entry, append and reuse

The byte operands are collected in `layout.tsv`, and all selected conditional destinations are decoded from the ELF bytes in `branches.tsv`. In the table, “source” is the 248-byte value passed to the routine. Names such as occupied count and free head describe the observed use, not independently recovered types. Key and length comparisons use unsigned 64-bit values.

| Condition in order | Observed result |
| --- | --- |
| Entry, before comparing the key | Read `slab+0x18`, add one and retain `u64::MAX` on wrap; store it back. |
| `key == slab+0x10` and key differs from `slab+0x00` | Copy `0xf8` bytes to `*(slab+0x08) + key * 0xf8`; increment key and store it at both `slab+0x10` and `slab+0x20`. |
| `key == slab+0x10 == slab+0x00` | Call the common growth wrapper before the copy and two stores. |
| `key < slab+0x10`, entry's first dword equals 2 | Read the entry qword at `+0x08`, write it to `slab+0x20`, and tail-call `memcpy` for `0xf8` bytes into that entry. |
| `key > slab+0x10`, or key is below length and the first dword is not 2 | Enter the Location-bearing failure call; the occupied-count store has already occurred. |

For the capacity comparison on entry, `+0x00` is read as the allocation bound by the instruction and is named capacity here. The equality case is append, so the `key >= length` failure branch only applies after equality has already been excluded. `contexts.tsv` establishes the `+0x20` argument in these callers; it does not prove that every possible caller supplies the same key.

The growth wrapper doubles its input capacity using 64-bit wraparound and selects 4 if that doubled value is below 5. It passes the selected value, an alignment of 8, and element size `0xf8` to the direct allocation-delegate edge. If the returned stack tag is not 1, it stores the returned pointer at `+0x08`, then the selected capacity at `+0x00`. Tag 1 calls the error edge instead. The delegate itself is outside this packet. In particular, arithmetic wrap on corrupted or implausibly large capacities is an observation of this wrapper, not a claim that such an allocation or subsequent copy is valid.

### Exceptional cleanup

The call-site tables have four rows per slot routine. `exception-routes.tsv` binds the last byte of each six-byte call to its table row and landing pad. For insertion A:

| Covered call | Table interval | Landing pad |
| --- | --- | --- |
| Growth call at `0x28e0e8d` | `0x28e0e7f..0x28e0e93` | `0x28e0f2f` |
| Invalid-slot failure call at `0x28e0f27` | `0x28e0f14..0x28e0f2d` | `0x28e0f4f` |

If unwinding reaches the growth landing pad, it uses source fields saved before the call: source qword `+0x00`, qword `+0x50`, and pointer `+0x58`. It skips the cleanup call when the first qword equals 2 or the `+0x50` qword is zero. Otherwise it calls the relocated cleanup edge with pointer `+0x58`, size `(source[+0x50] << 3) mod 2^64`, and zero in the third argument. If unwinding reaches the invalid-slot landing pad, the pad reloads `+0x50` and `+0x58` from source and tests only the former for zero before making the same cleanup call. Both then reach the resume edge. The cleanup target is outside the packet; its deallocation role and the interpretation of `+0x50` as an allocation capacity are inferences supported by the argument shape and the use-based interpretation in `research/work-items/RE-006-order-relation-transitions-94/README.md`.

The failure arm constructs a two-word descriptor with a pointer to the saved input key and a function pointer loaded through a relocated slot; the formatter role is an inference. It also references the length-prefixed text `expected vacant entry `, retained in `diagnostics.tsv`; that text does not by itself establish an externally returned error. The exception table shows where an exception lookup would transfer control; it does not establish that the allocation-error handler actually unwinds, or that every runtime configuration avoids aborting. Neither landing pad restores `slab+0x18` in its decoded instructions. This is a local write-order observation, not a claim that the enclosing transaction lacks rollback.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. There is no source build, fixture replay against the captured process, byte-equivalence result, or measured relocation/vtable/data closure. The comparison is between the three complete static insert bodies with the stated displacement masks, and the individual raw body hashes are retained separately. The allocation delegate, error handler, cleanup target, indirect helpers and their behavior remain edge gaps.

The 13 synthetic projections cover empty growth, minimum-capacity boundaries, growth from a larger full buffer, append with spare capacity, vacant reuse, invalid and occupied keys, two cleanup gates and counter saturation. The projections assume the selected caller passes the current free head as key; `vacant_next` represents the next key stored in a reused entry. A projected unwind case assumes the indicated call unwinds. These cases test consequences of the documented instruction reading without executing or emulating the target. The separately asserted unit-test expectations and negative controls cover damaged identity, body opcode, masked operand, FDE start, LSDA header/row, direct-call opcode/displacement, relocation addend, source-path corruption, non-file-backed addresses and out-of-range synthetic integers. Synthetic input states can violate real allocator or book invariants; they are not claimed reachable in the target.

## Results and limitations

The generated denominator is four selected indexed FDEs: three insert bodies and one growth wrapper. There are 19 selected branch rows, 26 call/edge rows, 12 LSDA rows and six explicit call-to-landing associations. The local unittest suite has 14 tests and no skips. These counts are for this bounded packet, not a function census or progress percentage.

The source-level tag meanings, buffer ownership on all routes, exact allocator failure policy and higher-level transaction recovery remain unresolved. No network, keys, captured-node execution, source-equivalence claim, or component progress gate is involved. Next question: independently establish the caller's recovery or abort behavior after a failed slot allocation without reusing the already covered insertion bodies.
