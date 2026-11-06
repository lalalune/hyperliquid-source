# RE-012: node115 borrowed-message I/O-error construction and concrete boxed lifetime

Component: foundation; task RE-012. Sole target Linux x86-64 node #115,
105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`; original ELF VAs,
no rebasing, normalized bytes, captured execution or instruction emulation.
New project-authored static research and scripts are MIT.

## New bounded question

What objects does `0x5c700a0..0x5c701a9` allocate for a borrowed error message,
which actual trait destructor does it install, and how are all owned layers
released on normal drop and the selected allocation-failure unwind routes?

The preceding file-open work resolves slot `0x64e0750` only as an opaque
invalid-options error maker. Generic I/O-error destructor contexts show an
arbitrary trait object and cannot identify the producer, payload type or
specific drop target. This outcome closes that **concrete borrowed-message
producer and its complete selected lifetime family**. Shared generic-drop
and open-caller windows receive no extra byte-equality credit.

The earlier path-wrapper error result concerns an 80-byte erased object with
another table. This producer creates a tagged 24-byte custom I/O-error payload
containing a separate boxed 24-byte owned-message object. Their allocation
shapes and tables are independently bound here. Live open titles inspected
on 2026-11-04 showed no competing boxed-message constructor result. No issue
was opened, drafted or claimed.

## Constructor inputs and the three owned layers

Entry EDI is retained as a kind word, RSI is the borrowed message pointer,
and RDX its byte length. Only the kind's **low byte** is stored. The actual
caller covered below supplies 20; arbitrary invalid source-language enum
values are not asserted safe.

For a nonempty message, the constructor performs these allocations in order:

| Allocation | Contents established by actual stores |
| --- | --- |
| Message-length bytes | Copy exactly that many borrowed bytes through memcpy; no NUL terminator is appended |
| 24-byte message object | Three qwords: allocation count=length, cloned byte pointer, length |
| 24-byte error payload | +0 message-object pointer; +8 table pointer `0x64c4178`; +0x10 kind byte |

The last seven bytes of the outer allocation are not initialized by this
constructor. They are not normalized or treated as meaningful error bytes.
The returned word is the outer allocation address **plus one**. With the
valid 8-byte alignment required by this allocation contract, its low two bits
are 1. This is a concrete observed representation, not a claim that arbitrary
host Rust I/O errors have a stable public ABI.

For message length zero, the first allocation and copy are skipped; its byte
pointer is the literal **1**, allocation count and length are zero. Both
24-byte allocations still occur. The selected destructor skips freeing that
nonallocated byte pointer because it checks the allocation count.
`layout.json` records every field and source/destination relationship.

## Real trait header and selected destructor

The constructor's LEA at `0x5c7010e` and pointer store at `0x5c70115` install
**0x64c4178**. Its first slot has a unique R_X86_64_RELATIVE writer to the
complete FDE **0x5c75250..0x5c75265**. Plain header qwords at table+8 and
+0x10 are **24 and 8**, respectively, with no relocation writer for either
fixed field. The captured first-slot zeros are interpreted through the
relocation, not as the runtime destructor address.

The selected 21-byte destructor reads the message allocation count at
payload+0. If zero it returns; otherwise it tail-calls deallocation with the
message byte pointer at +8, that allocation count and EDX=0. This matches the
owned triple created above, including its empty-message branch. Other trait
methods beyond this header are not identified merely from adjacent table
entries; their display/downcast/error semantics remain outside the lifetime
claim.

## Tagged and bare-box normal destruction

The complete tagged-error destructor `0x5c74b90..0x5c74c5e` first checks the
error word's low two bits. Encodings 0, 2 and 3 return without this heap work.
For encoding 1, it recovers outer allocation address `error_word-1`, loads
the message-object pointer from there and the table from `error_word+7`.
For this producer those values are the objects and table above.

Its normal cleanup order is therefore:

1. Dispatch the selected first slot to `0x5c75250`, freeing the cloned
   message bytes when their count is nonzero.
2. Read size/alignment 24/8 from the table and release the message object.
3. Release the 24-byte outer error payload.

The deallocation binding is `0x64df4a0` -> `0x635de30`. The observed layout
calculation supplies its optimized alignment encoding zero for the selected
24/8 pair; this does not redefine a general public allocator ABI. Actual
allocator effects and exceptional behavior remain boundaries.

The bare-box helper `0x5c74c60..0x5c74cf1` accepts an object pointer and table
separately. It invokes the same selected first slot and releases only that
message object by its table layout. This is exactly the ownership operation
needed before an outer error payload has been successfully allocated.

## Allocation failure and actual call-site metadata

Constructor body shape alone would not prove which cleanup follows a thrown
allocation-failure helper. This packet decodes the actual LSDA header and
**complete call-site tables** for the constructor, tagged drop and bare-box
drop. All nonzero landing offsets resolve to instructions inside their own
FDEs. The records include covered call addresses and retain the raw table
bytes.

For a failed allocation that returns null, the selected failure-helper calls
have these actual call-site entries:

| Failed allocation | Failure-helper call | LSDA landing | Observed cleanup |
| --- | --- | --- | --- |
| 24-byte message object | `0x5c70149` | `0x5c7018b` | Release cloned message bytes when nonempty, then resume unwinding |
| 24-byte outer error payload | `0x5c7015b` | `0x5c70171` | Pass message object and table 0x64c4178 to bare-box helper; release bytes and message object, then resume unwinding |

The initial message-byte allocation has no earlier owned layer to release.
The two 24-byte failure routes reach `ud2` if their designated failure helper
returns normally; no general normal-return result is invented for allocation
failure. A failure from the initial allocation's designated failure helper
also retains its own native nonreturn/unwind boundary.

The tagged-drop call-site table routes an exception from the inner destructor
to cleanup that releases the message-object allocation and outer payload
before resuming. Bare-box drop similarly retains release of its allocation
on its selected inner-destructor unwind route. Further cleanup failure and
personality behavior are not simulated. **Action/type tables are not fully
interpreted**: call-site offsets and cleanup landings do not establish every
catch/abort rule of the native unwinder.

## Concrete open-options caller

`0x5c97060..0x5c97226` has two invalid-option diagnostics. It supplies borrowed
literal pointer/length pairs at `0x949b01` (58 bytes) and `0x949b3b` (61 bytes),
then kind 20 to slot `0x64e0750` -> this constructor. The two retained strings
identify missing access selection and creation/truncation without write or
append access. The returned tagged word is stored at output+8 with result
tag 1. Those validation branches reach this constructor before an open64
call; no actual file operation was performed to verify them.

The caller's normal file-open policy is separate established work. Its
presence here binds actual consumers and literal lengths; it is not offered
again as new open-flags or write-loop discovery.

## Evidence and qualification

Five complete FDEs total **1091 bytes / 335 instructions**: constructor,
tagged drop, bare-box drop, selected message destructor and actual caller
context. They contain 25 calls and 49 branch records. Export sizes are not
reconstructed byte totals. `records.json` binds exact body hashes, actual
FDE/CIE bytes and LSDA addresses, three complete call-site tables, table
header and relocation writers, and the dynamic symbols memcpy, errno-location
and open64. Constructor allocation/failure/deallocation slots are resolved
individually, without executing them.

GNU and LLVM objdump agree with Capstone on every instruction byte; GNU
readelf independently confirms all extents. A separate LLVM LOCK prefix row,
if present, is joined only to its contiguous instruction. No bytes are masked.
`tools.json` retains actual versions; collector commands preserve options.

```sh
python3 -B research/work-items/RE-012-boxed-io-error-115/collect.py --out work/fresh-boxed-error-export
diff -u research/work-items/RE-012-boxed-io-error-115/records.json work/fresh-boxed-error-export/records.json
python3 -B research/work-items/RE-012-boxed-io-error-115/verify.py --out work/fresh-boxed-error-check.json
```

The focused verifier freshly reproduced the record and rejected **24 actual
instruction corruptions, six header/literal/LSDA corruptions, six
RELATIVE-addend mutations, three imported-writer mutations, three actual
call-site-table truncations and two wrong/truncated capture controls**.
It additionally rejects redirecting the real first-slot relocation into the
supposedly fixed size word. These narrow checks do not rely on the whole-file
identity guard for their operand/data/relocation failures.

An initial collector extension failed because a per-FDE instruction-boundary
map had not been populated before LSDA landing checks. That bookkeeping was
corrected; the target findings did not change. `validation.json` records the
observed failure and subsequent successful export/verifier results.
`qualification.json` records actual control outcomes. Parent publication
owns repository/catalogue verification.

## Boundaries

No captured process, instruction interpreter, allocator, filesystem operation
or network was run. No Rust implementation, mock allocator, complete standard
error ABI, peer runtime, hosted CI or container result is claimed. Valid
pointer/alignment contracts, allocator/import effects, remaining trait
methods, action/type tables and the full unwind runtime remain boundaries.
This is the selected constructor/table/ownership closure; all 92 component
gates and registered byte-comparison totals stay unchanged.
