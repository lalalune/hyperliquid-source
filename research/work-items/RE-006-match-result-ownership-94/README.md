# RE-006: insertion match-result ownership and cleanup on node 94

A reconstruction can now distinguish the two insertion paths' temporary match-result ownership: one appends 0x238-byte records and the other appends 0x228-byte records, and the wider path transfers its record vector and final map to the returned result while retaining separate cleanup obligations on abandoned and unwinding paths.

- Component ID: `orderbook`, task `RE-006`.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: independent repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; unlicensed reference `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference was used as a search lead; no reference code was copied.
- Claim status: byte ranges, FDEs, encoded branch and call targets, relocation entries, exception-table rows, and operand values are static observations. The terms vector, map, fill and release are interpretations of these operations and previous book evidence. Runtime reachability, rollback and actual exception delivery remain unresolved.
- Scope included and excluded: the two previously unselected growth FDEs and two cleanup FDEs below, plus bounded caller instructions and call-site tables from already researched insertion bodies. The enclosing insertion bodies are contextual evidence, not newly selected functions. Map-iterator internals, allocation/error implementations, full fill semantics, concurrent access, other releases and target execution are excluded.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3 and the authenticated artifact. The generator first checks the entire input SHA-256, imports `tools/elf_index.py` and `tools/fde_extents.py`, rejects NOBITS mappings, and uses only the Python standard library and the repository parsers. It invokes no external program and does not execute the node. GNU objdump 2.42 was used for human inspection of instruction boundaries, not to generate or parse evidence.

```sh
python3 tools/artifacts.py verify
python3 tools/book_match_result_ownership94.py --out work/match-result-a
PYTHONHASHSEED=4242 TZ=Pacific/Honolulu python3 tools/book_match_result_ownership94.py --out work/match-result-b
diff -r work/match-result-a work/match-result-b
diff -r -x README.md -x MANIFEST.sha256 work/match-result-a research/work-items/RE-006-match-result-ownership-94
python3 -m unittest tests.test_book_match_result_ownership94
python3 tools/catalogue.py --check
(cd research/work-items/RE-006-match-result-ownership-94 && sha256sum -c MANIFEST.sha256)
```

The single generated file `evidence.json` records raw selected bodies and windows, hashes, instruction bytes, decoded relative transfers, relocation records, FDEs, complete selected call-site tables, derived operands and the explicit comparison masks. Its contents do not depend on the output directory, timezone or hash seed. `MANIFEST.sha256` also covers this README.

## Evidence

Addresses are linked ELF virtual addresses, before any load bias; all ends are exclusive. File offsets and source bytes are in `evidence.json`. An FDE describes an unwind range; it does not establish an original source-level function boundary. All 4 selected entries also occur in the unwind index. Their 1,614 bytes are retained without normalization.

| Newly selected role | FDE extent | Bytes |
| --- | --- | ---: |
| Wider record-vector growth | `0x32d5e80..0x32d5ee4` | 100 |
| Narrower record-vector growth | `0x454f1f0..0x454f254` | 100 |
| Wider result cleanup | `0x277b220..0x277b4e3` | 707 |
| Narrower result cleanup | `0x433f6a0..0x433f963` | 707 |

The earlier `RE-006-spot-order-insert-94`, `RE-006-perp-order-insert-94` and `RE-006-price-level-lifecycle-94` packets identify insertion and matching contexts. This packet inspects only the listed windows inside their previously described neighboring variants. Its connection to the newly selected entries is established by these machine transfers:

| Bounded context | Site and transfer | Observation |
| --- | --- | --- |
| Wider insertion | `0x26ed2e5` through slot `0x5774870` | Relative relocation names growth `0x32d5e80`. |
| Narrower insertion | `0x430f206` through slot `0x5774838` | Relative relocation names growth `0x454f1f0`. |
| Wider insertion | `0x26ef880`, `0x26ef90f`, `0x26efe7c`, `0x26efea3` | Direct calls to `0x277b220` with a stack-object address. |
| Narrower insertion | `0x4310cc2`, `0x4310df2`, `0x431109e`, `0x43110e9` | Direct calls to `0x433f6a0` with a stack-object address. |

Runtime GOT patching is not examined. The dynamic relocation for slot `0x576dfe0` identifies `memcpy`; the release-shaped slot `0x576e010` is bound by a relative relocation. Its allocator semantics are not independently established here.

### Initialize, append and grow

At `0x26ec954..0x26ec9d3`, the wider insertion initializes the optional-tree gate to 1 with its root zero, initializes three vector-shaped headers, and writes 8 into each empty vector's pointer position. For the header at object `+0x38`, capacity at `+0x38` and length at `+0x48` are zero and pointer at `+0x40` is 8. This is a machine representation, not a claim that address 8 is dereferenced.

At `0x26ed2cb..0x26ed312`, the wider body compares length with capacity, calls the growth slot only on equality, copies `0x238` bytes to `pointer + length * 0x238`, and then increments length. At `0x430f1ec..0x430f293`, the narrower body similarly checks equality and uses stride `0x228`: it copies `0x1f0` bytes, writes the remaining fields, and then increments length. The checks here are equality checks; they do not reject a corrupt `length > capacity` before proceeding. The prior perp packet identifies these records as matching results; that product label is an inference for the bounded variants here.

The narrower record is assembled completely before its length is incremented. The checked stores partition its bytes as follows; these are machine offsets and widths, not recovered Rust field names:

| Destination in the `0x228`-byte record | Source observed at the append site |
| --- | --- |
| `+0x000..+0x1ef` | A `0x1f0`-byte `memcpy` from a stack block. |
| `+0x1f0`, `+0x1f8`, `+0x200` | Three separate qword stores. |
| `+0x208`, `+0x218` | Two separate 16-byte stores from stack blocks. |

The wider site instead copies the entire `0x238` bytes in one call. No field-by-field correspondence between the two formats follows from these stores.

Both growth FDEs compute a wrapping 64-bit double of the old capacity. They choose 4 when that double is below 5 unsigned and otherwise choose the double. They pass alignment 8 and their respective element widths to different helper entries. When the helper's low dword result is 1, control goes to the error slot before either pointer or capacity is stored. Otherwise pointer `+0x08` and then capacity `+0x00` are stored. The example overflow at old capacity `2^63` produces 4 at the machine arithmetic step; no valid allocation or reachable book state is claimed for it.

### Temporary structure and normal return

The following offsets are relative to the object passed to either cleanup FDE. The two implementations use the same offsets, but the record-vector stride differs as above.

| Offset | Observed use |
| --- | --- |
| `+0x00`, `+0x08`, `+0x10`, `+0x18` | A nonzero qword at `+0x00` enables a second tree-shaped traversal using the other three words. |
| `+0x20`, `+0x28` | Nonzero first word causes a release-shaped call on the second word with byte count `first * 0x20`. |
| `+0x38`, `+0x40` | Nonzero first word causes a release-shaped call on the second with byte count `first * 0x238` or `first * 0x228`, respectively. |
| `+0x50`, `+0x58` | Nonzero first word causes a release-shaped call on the second with byte count `first * 0x28`. |
| `+0x78`, `+0x80`, `+0x88` | Three words set up the first iterator-shaped traversal. |
| `+0x90`, `+0x98`, `+0xa0` | Three words set up the final traversal; each returned entry is indexed at stride `0x18`, and its nonzero count triggers a release-shaped call with count times 8. |

The full cleanup calls the first iterator at least once, conditionally calls the second iterator when `+0x00` is nonzero, processes the three vector-shaped headers in offset order, then walks the final tree and conditionally releases each inner buffer. A null root initializes an empty iterator but does not skip its first call. Iteration order, aliased or malformed pointers, and the external iterator and release internals are outside the evidence.

On the wider normal-result route, `0x26ed985..0x26eda3f` copies the temporary object into the stack object later passed to full cleanup on alternate exits. The recorded `0x90`-byte copy source is initialized by both bounded source windows to the earlier object's `+0x20`; identifying it across intervening calls assumes those calls do not overwrite the saved stack pointer through an alias.

At `0x26ef670..0x26ef70f`, the caller copies the three qwords at temporary `+0x38/+0x40/+0x48` to result `+0x00/+0x08/+0x10`, and the three qwords at temporary `+0x90/+0x98/+0xa0` to result `+0x18/+0x20/+0x28`. It then calls the first tree cleanup and, if enabled, the optional tree cleanup, and releases the buffers at `+0x20` and `+0x50`. This selected continuation does not call the full cleanup or release the `+0x38` vector or `+0x90` tree. Under the stated ownership and no-alias assumptions, those two headers have been transferred to the result rather than destroyed. This is a local ownership inference, not a proof of all result consumers or unwind behavior after publication.

### Failure and cleanup branches

| Trigger or condition | Byte-backed observation |
| --- | --- |
| Growth helper returns low dword 1 | Calls its error slot before publishing the replacement pointer or capacity. Whether that call aborts or unwinds is unknown. |
| Wider growth call unwinds | Its LSDA interval selects `0x26efdc6`; both conditional jumps and the intervening fall-through converge on the path calling full cleanup on the original stack object at `0x26efea3`. |
| Narrower growth call unwinds | Its LSDA interval selects `0x4311027`, whose direct jump enters the path that calls full cleanup on the stack object at `0x43110e9`. |
| First cleanup iterator unwinds | Each cleanup FDE selects a landing pad that checks the optional-tree gate before the remaining vector and final-tree cleanup. |
| Second cleanup iterator unwinds | Its distinct landing pad bypasses that optional-tree check and joins the remaining cleanup. |

After the full cleanup and further conditional release-shaped calls, both selected enclosing unwind continuations call `0x5660110`. Its checked PLT jump reaches a `R_X86_64_JUMP_SLOT` relocation for the dynamic symbol `_Unwind_Resume`; this identifies the static continuation, not runtime exception delivery. The cleanup FDEs each have five LSDA call-site rows. The two context tables have 69 and 61 rows; all are retained, including actions. The tool checks the six cited call-to-landing mappings. The type/action table and the actual behavior of nested failure calls are not interpreted, and this is not a rollback claim.

### Comparison and interpretation

The 100-byte growth bodies differ in seven byte positions. Masking only one element-size immediate and two PC-relative operands yields one hash. The 707-byte cleanup bodies differ in 56 byte positions. Masking exactly the 15 listed PC-relative operands and two element-size immediates yields one hash. The raw bodies, all mask offsets, resolved direct calls and relocation-backed slots remain in `evidence.json`; different helper destinations are not treated as equivalent. No relocation, helper closure or whole-ELF comparison is implied by the masked hashes.

The observations support a vector-shaped header and transfer of ownership because the caller copies the header into the result and its selected normal continuation omits the corresponding release. They do not prove the original Rust types, the semantic role of every record byte, memory safety for malformed objects, or behavior of the untouched consumers. In particular, the `+0x38` result vector's record meanings rely on prior insertion and matching packets, not on a new runtime observation here.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No Cargo lock, compiler flags, two-build result, source-to-target comparison, behavioral execution, relocation closure or whole-node identity is claimed. The two masked comparisons above compare target code with target code only. The Python projection used in tests is a synthetic consequence of the selected instructions under terminating-iterator and non-aliasing assumptions; it is not execution or emulation of the captured program.

## Results and limitations

The generator records 4 FDEs, 26 bounded windows, 46 selected conditional branches, 50 selected transfers, 7 relocations, 2 slot loads, 1 PLT jump, and 140 LSDA call-site rows across the 4 tables. These are selected evidence counts, not a whole-book coverage denominator. The focused suite has 18 passing tests and no skips; it corrupts each selected body, window, branch predicate and displacement, transfer displacement and relocation, as well as both dynamic symbol names, the PLT displacement, LSDA headers and whole-file digest. It also checks unbacked addresses and synthetic growth and cleanup boundaries. Two independent regenerations matched byte for byte with different hash seeds and timezones using a Python-only executable path.

No component progress gate is requested. Next question: trace the returned vector and tree through their first real consumer, including how each 0x238-byte record differs from the 0x228-byte form and which fields are owned at every exit.
