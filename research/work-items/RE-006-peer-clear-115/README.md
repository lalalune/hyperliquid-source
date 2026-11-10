# RE-006: reconstruct reciprocal order-link clearing and record lookup

This packet makes it possible to reconstruct how node #115 clears an order's
optional reciprocal link during an established order-removal path, including
both lookup representations, missing records, and the state left by a
second-lookup failure.

- Component ID: orderbook, task RE-006.
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: `a8616af9432b8d8517b2af677880e117b7c28ef3`; no
  unlicensed reference source was copied.
- Claim status: byte observations and conditional-model results below;
  field names are inferences; dependency behavior and complete removal are
  unresolved.
- Scope included: two link-clearing bodies and two standalone lookup bodies,
  with explicit boundaries at their lookup, comparison, and panic callees.
  Prior caller bodies are used only for checked call-site context.
- Scope excluded: full cancel/match processing, callee internals, allocation,
  unwinding, concurrent execution, and production node behavior.

## Reproduce

From the repository root, with the pinned artifact in place and Python 3.10 or
newer:

```sh
python3 tools/book_peer_clear_115.py --out research/work-items/RE-006-peer-clear-115
python3 -m unittest tests.test_book_peer_clear_115
(cd research/work-items/RE-006-peer-clear-115 && sha256sum -c MANIFEST.sha256)
```

For the deterministic replay, substitute two empty directories for the
placeholders and compare the results:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/book_peer_clear_115.py --out <first-dir>
PYTHONHASHSEED=90210 TZ=Pacific/Honolulu python3 tools/book_peer_clear_115.py --out <second-dir>
diff -r <first-dir> <second-dir>
```

The interpreter reads the ELF as data; it does not execute the captured node.
It checks the entire input digest before constructing the ELF view, uses only
the Python standard library and the repository's `elf_index` and
`fde_extents` parsers, excludes SHT_NOBITS sections from file mapping, and
calls no external commands. A synthetic world is built and compared one case
at a time. `cases.tsv` retains one quarter of cases with a rotating selection
that samples every fault-schedule residue, including predicted and
observed hook transcripts, panic arguments, touched words, return registers,
and hashes of the complete compared heaps. `witnesses.tsv` indexes sampled
cases for the principal boundary and failure classes. Every case is rerun by
the default command, with its seed and aggregate counts recorded. Generated files other
than this README and the manifest come solely from that command.

Analysis used Python 3.12.3 on Linux x86-64. GNU objdump 2.42 was used only to
inspect bounded human-readable disassembly during investigation; none of its
output is parsed or emitted by the tool. The prior MIT-licensed
`tools/book_peer_links_115.py` contributed the generated book layouts and
lookup-model scaffolding; the peer-clearing behavior, boundary cases, and
this comparison are specific to the four bodies here.

## Evidence

Coordinates are ELF virtual addresses. File offsets, FDE ranges, raw
instruction bytes, decoded instructions, branch reachability, and body hashes
come directly from the authenticated ELF and are in `functions.tsv` and
`instructions.tsv`. An FDE range supplies an unwind extent, not a complete
function census. All four entries are also independently supported by checked
direct call sites. These body windows decode to their respective FDE ends.
The tool checks that every decoded conditional and direct-jump target is an
instruction boundary within the same extent, and that the direct calls name
the three stated lookup hooks; `cfg.tsv` records the counts. This check does
not resolve indirect calls or establish absence of overlapping code.

| Role | FDE start | FDE end | Bytes | Decoded instructions |
| --- | --- | --- | ---: | ---: |
| Clear | `0x58e6960` | `0x58e6f0b` | 1,451 | 333 |
| Clear twin | `0x58e6f10` | `0x58e74bb` | 1,451 | 333 |
| Lookup | `0x58ebea0` | `0x58ec187` | 743 | 181 |
| Lookup twin | `0x58ec190` | `0x58ec477` | 743 | 181 |

The earlier order-removal FDEs beginning at `0x58e1400` and
`0x58e2a80` call the respective clear twins at `0x58e1469` and
`0x58e2aea`. Before these calls the checked instruction bytes place a
20-byte copied key in `rsi`, the book pointer in `rdi`, and the saved
order ID in `rdx`. The same FDEs subsequently call the previously studied
parent-detach bodies at `0x58e1491` and `0x58e2b13`. For each
clear call, the tool decodes 28 straight-line instructions from the caller's
FDE start to the call, checks the saved argument registers and the complete
20-byte copy, and checks the direct call displacement. Reaching the clear
call assumes the preceding helper returns normally. The corresponding twin
caller sites and the lookup callers are also recorded in
`caller-sites.tsv`; the callers themselves are not emulated.

### Observed lookup behavior

For each lookup the tested ABI is `rdi` = book, `rsi` = pointer to 20 key
bytes, `rdx` = unsigned 64-bit order ID.

1. The order-ID probe at `0x4ef4010` is called first. If it returns
   `rax == 1`, `rdx` is checked against the book's index length at
   `+0x10`; an out-of-range index reaches the panic slot `0x64df620`
   with location `0x649e918`. Otherwise a 24-byte index entry at book
   `+0x08` supplies a slot index at entry `+0x10`.
2. The slot index is checked against book `+0x90`; slots at book `+0x88`
   have stride `0x110`. Slot dword tag 2, an out-of-range slot, or a
   mismatch of the 20 bytes at slot `+0xf8` produces a miss. A valid
   match selects slot `+0x20`. These misses do not continue into the
   alternative user store.
3. If the ID probe does not return 1, the user store begins at book
   `+0xe8`. Its first qword equal to `0x8000000000000000` selects a
   B-tree; otherwise it selects a sorted ring with capacity, pointer, head,
   and length at `+0xe8`, `+0xf0`, `+0xf8`, and `+0x100`. Ring rows
   have stride `0x70`, and the user value begins at row `+0x18`.
   A reported search miss or a reported index at or above length gives a
   miss before indexing. A hit uses head plus the logical index with one
   conditional subtraction of capacity.
4. A user value has an order store at `+0x20`. The same sentinel selects
   its B-tree; otherwise the ring capacity, pointer, head, and length are
   at `+0x20`, `+0x28`, `+0x30`, and `+0x38`. Order-ring rows
   have stride `0xe0` and a value at row `+0x08`. B-tree keys are
   compared as unsigned 64-bit values. On either user-store path, a value
   whose first dword is 2 selects its body eight bytes later.
5. The standalone lookup bodies return low byte `dl = 0` for a slab hit,
   `1` for a user-store hit, and `2` for a miss. On a hit, `rax`
   contains the selected body pointer. The rest of `rdx` and the pointer
   on a miss are not qualified by this packet.

The B-tree layouts exercised here use 20-byte user keys at node `+0x3d0`,
user values of stride `0x58` starting at `+0x08`, length at `+0x4ae`,
and children at `+0x4b0`. Order nodes use 64-bit keys at `+0x08`,
values of stride `0xd8` starting at `+0x60`, length at `+0x9aa`, and
children at `+0x9b0`. Node height and child pointers are inputs to the
walk. Both flat and tree routes are exercised under the stated fixture limits.

### Observed clearing behavior

The clear bodies inline that lookup. If the first record is absent, they
return without a write. If present, they read the first body's dword at
`+0x20` and qword at `+0x28`, then write an eight-byte zero at
`body + 0x20` regardless of the saved dword. Only a saved dword equal to
1 triggers a second lookup using the saved qword as its ID and the same
20-byte key. If that lookup succeeds, the second body's qword at `+0x20`
is also zeroed; its saved ID word remains in place. The second body need not
point back to the first. A missing second record leaves the first zero in
place. A bounds panic during the second probe likewise occurs after that
first write. A self-reference is looked up again and causes the same word
to be written twice.

The terms *user*, *order ID*, *peer*, and *reciprocal link* are inferred from
the surrounding layout and prior orderbook evidence. The bytes establish the
field widths, operations, branches, and checked call-site order; they do not
independently establish wire semantics or an economic interpretation.

## Implementation and comparison

`tools/book_peer_clear_115.py` contains an executable Python specification
and an embedded, bounded x86-64 interpreter. The model predicts ordered
lookup/comparison calls, panic arguments, the complete used synthetic heap
after a clear, and the lookup result tag and hit pointer. The interpreter
decodes and steps the original bytes, without invoking the binary. Each case
starts with a freshly generated world; comparison happens before the next
world is built. The comparison masks the upper 56 bits of the lookup tag,
ignores the lookup pointer on a miss, and ignores `rax` from clear bodies.
It applies no masks to the compared synthetic heap or to ordered hook
transcripts; stack bytes and stub internals are outside the comparison. The
sample preserves raw predicted and observed fields and transcripts, plus
heap hashes. No Rust implementation or compiled-byte comparison is claimed:
not yet implemented/measured.

The ID probe, sorted user and order ring searches, 20-byte comparator, and
panic slot are hooks. Their assumed observable contracts are explicit in the
tool. Fixtures include both B-tree and ring stores, nonzero ring heads, vacant
slab entries, mismatched keys, absent records, a first or second invalid probe
index, tags with nonzero high bits, self-links, and peer records that are
missing. Deliberately inconsistent ring-search responses test positions equal
to length, length plus one, and the maximum u64, plus odd and even result
bytes. Probe responses also include non-1 values whose low 32 bits equal 1,
testing the full-width comparison. IDs include 0, 1, 2, both sides of the
signed midpoint, and the largest two u64 values. All keys and records are
synthetic.

The default comparison runs 10,000 cases, 2,500 per entry. The evidence
records 85 negative controls: 50 conditional-branch byte mutations, six
deliberately incorrect specifications, and 29 digest, body-byte, caller-setup,
relocation, CFG, and address boundary checks. All 85 must be detected; a mutation that causes an
interpreter exception is not counted as detected until a separate case shows
an observable disagreement. `controls.tsv` retains every constructed control,
its witness, attempts, and such exceptions.

## Results and limitations

The default run produced 10,000 matches, zero mismatches, 85 detected of 85
negative controls, and zero equivalent or unexplained controls. The 2,500
saved case rows are a reproducible sample of those comparisons.
`results.json` gives per-body instruction and conditional-arm coverage and
boundary-input counts; `outcomes.tsv` classifies the compared states.
Across the four bodies the compared worlds reached all 1,028 decoded
instructions and both outcomes of all 126 conditional branches. Coverage
includes deliberately malformed helper responses and is coverage of this
interpreter/hook environment, not evidence of native runtime coverage.

B-tree nodes with more than 11 keys or height greater than two, malformed
pointers, unusual allocator behavior, unwind cleanup, and lookup-hook
internals are not covered. The 20-byte comparison is modelled as
lexicographic byte comparison; the ID and ring search routines are stubs.
The `0x64dfb50` relocation names the imported symbol `memcmp`; the panic
slot `0x64df620` is a relative relocation with addend `0x1680cbf`.
These entries are parsed from ELF bytes in `relocations.tsv`; symbol-version
resolution and the actual implementations remain outside this comparison.
The model compares against interpreted target bytes, not a running node, and
does not prove full cancellation, matching, concurrency, helper closure,
source-build identity, or whole-ELF equivalence. Direct target addresses and
the two named GOT slots are checked or modelled as described; the actual
callee implementations, relocation and vtable closure, and whole-ELF
comparison remain unmeasured. No component gate changes.

Next question: reconstruct the ID-probe and sorted-ring search contracts from
their own #115 bytes, then bind them to a fully validated removal caller.
