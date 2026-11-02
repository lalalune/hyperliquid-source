# RE-001: span cursor selection and record materialization, node94

- Task: RE-001. Research allocation: foundation; source ownership is unresolved.
- Target: node94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `966865f1637a29ce75b019e1bf11d5529cc6f519`.
- Status: bounded static observations and conditional interpretation. No gate requested.

## Question and prior gap

The existing [span-count packet](../foundation-span-count-94/README.md) models
43bytes at `0x53c7490`: call the lazy helper, compute a span count minus one,
store32bits, then jump. It explicitly excludes the tail target. That leaves
whether the stored value is a count or a cursor, how empty spans behave, and
what the tail does with the object unresolved.

This packet links that existing parent to the validity method, the412byte tail,
and a393byte sibling that uses the same tail after an index search. The71byte
output-buffer helper is included because both copy branches can call it.
Addresses are ELF virtual addresses; evidence.json records file offsets and
canonical unwind extents. Raw disassembly remains in disassembly.txt.

## Observations

`0x53c3c70..0x53c3c8d` loads `u32[obj+0x80]`, reads the span at offsets68/70,
subtracts and arithmetic-shifts right by2 in64bits, and returns `setb`.
The comparison is unsigned. For a valid post-helper span with1 <= N <=2**32 elements, the parent selects
the last position; it does not publish an independent count. For larger N,
the32bit subtraction truncates and this last-position interpretation does not hold.
For an empty span its stored `0xffffffff` fails this validity check. A high
32bit sign bit alone does not make an index invalid. These are instruction
interpretations, not executions of the captured binary.

The optimized path at `0x53c4edf` compares the object's virtual slot10 against
this validity method. When equal, it inlines the bounds comparison. Its
alternate path calls the actual slot and trusts its boolean result; that
callback's effects remain open.

On the guarded selected-record path:

1. Load the32bit entry at `spanStart + cursor*4`.
2. Multiply it by `u32[source+0x7c]` in32bits, then add `ptr[source+0x10]`.
   The multiply truncation must not be replaced by unbounded integer math.
3. If `byte[source+0x20]` is zero, copy `u32[source+0x70]` bytes to the output
   buffer. Otherwise copy `u32[source+0x74]` bytes and append the little-endian
   64bit literal1. The imported memcpy identity was resolved in the preceding
   static import analysis; this packet does not claim a fresh import census.
4. Store the output span and a second selected-record view using the source's
   length fields. Field names and a concrete key/value type remain inference.

The invalid-index path sets the lengths at object+90/a8 to zero. It installs a
constant pointer at+88 and returns. The pointer's content/type is not recovered.
The output-buffer helper changes allocation/storage metadata and has two
imported calls whose contracts remain open; successful allocation is a premise.

The sibling `0x53c74c0` calls the same lazy helper, then halves the span and
compares a selected entry through an indirect comparator. A negative result
advances the lower boundary; otherwise the upper boundary narrows. It stores
the resulting position to+80 and jumps to the same materializer. Under a valid
ordered span and pure comparator this resembles lower_bound. Ordering and
callback purity have not been proved, so this is a conditional interpretation.

## Reproduce and controls

From the repository root, with the authenticated node94 LFS artifact present:

```
python3 -B research/work-items/RE-001-span-cursor-materialization-94/verify.py --controls
```

`--artifact PATH` selects an existing copy; the full target SHA is still
required. The checker uses the unchanged upstream unwind parser, validates
five declared ranges, hashes, executable mappings, selected instruction bytes
and retained disassembly coverage. Corruption controls exercise the same
checker with altered target identity, range/offset/FDE/body claims, instruction
claims and disassembly. These controls validate the retained facts. They do
not execute the target or prove its full semantics. No new Python dependency
is required by the checker.

Disassembly was exported with Capstone distribution5.0.9 (the Python wrapper
reports5.0.7), x86-64 mode, no skip-data. The native DLL SHA is in evidence.json.
No source type name was taken from nearest-symbol labels or can1357 source.
The analytical edge table concerns the exact32/64bit instructions. It is not
an independently observed behavioral oracle.

## Validation and limits

Repository-wide command outcomes and final source head belong in VALIDATION.md;
only actual completed runs may be reported there. This packet does not alter
component/progress/catalogue inputs or count these bytes as reconstructed code.
No Rust implementation, target execution, build identity or completion gate
is claimed. Raw disassembly retains the captured artifact's rights; new analysis
and checker code were authored independently without copying can1357 source.

The lazy callee's initial span, source-size constraints and complete helper
closure remain open. Nonaliasing storage, legal record indices, the actual
vtable, comparator and allocator contracts are explicit premises. Next, recover
the constructor/reset paths and the source record's bounds; then test a real
independent implementation under an authorized differential protocol. Do not
turn these observations into a whole-function equivalence claim.
