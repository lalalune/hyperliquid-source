# RE-021: BLAKE2b registry construction through runtime lookup and result handling

This packet connects the existing address-09 BLAKE2b record to a runtime call path: mode-2 construction inserts its tagged value into a 20-byte-key hash table, shared or owned lookup retrieves it, and tag-0 dispatch calls the reviewed wrapper before gas accounting and checkpoint success or rollback handling. This establishes the registry and dispatch layouts needed for a reconstruction; it does not establish which fork or table a live node selects.

- Component ID: `evm`; RE-021 extends the unresolved lookup question in `RE-021-blake2b-compress-94` (not a new official TASKS row).
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `d3af75257a396c85d20857f421c370ddb8cb40e5` / can1357 `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference implementation was copied; inferred source labels are not evidence.
- Claim status: observation for bytes, FDE extents, relocations and branch destinations; inference for semantic names, container roles and constructor-derived membership; unresolved for actual runtime seeds, caller-supplied registry contents and whole-component behavior.
- Scope included and excluded: selector, six constructor variants, record materialization, map/set clone and insertion, two lookup forms, two enum dispatchers, caller result handling and the checkpoint rollback branch map. The existing wrapper and compression bodies are endpoints from prior work, not newly claimed functions. Other cryptographic bodies, allocator internals, database callbacks, hash-seed initialization, complete exception dispatch, #115 and visor are excluded.

## Reproduce

Run from the repository root with Python 3.12 or later and the authenticated artifact present:

```sh
python3 tools/blake2b_runtime.py --out research/work-items/RE-021-blake2b-runtime-94
python3 -m unittest tests.test_blake2b_runtime
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For independent output directories, substitute two empty directories for the placeholders:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/blake2b_runtime.py --out <tmp-dir>/first
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/blake2b_runtime.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
```

The generator writes only the generated evidence files; README and MANIFEST are not generator outputs. MANIFEST covers every other file in this evidence folder. Tools and tests are separate new repository files. No captured code runs, including under emulation. The generator and tests import only the standard library and the repository's shared ELF/FDE readers; they do not launch external programs. The input digest is checked before ELF interpretation. SHT_NOBITS addresses cannot be read as file bytes.

Analysis used Python 3.12.3. GNU objdump 2.42 was used only for human instruction reading, not as an input to generated counts, addresses or tables. The byte-shape walker accepts the opcode families in these authenticated bodies and validates local branch and table destinations against its instruction boundaries. It is not a general-purpose x86 decoder. Its output is independent of binutils versions. All files are ASCII, deterministically ordered, and contain no wall-clock or host-path data.

## Evidence

Every code address below is an ELF VA. `functions.tsv` provides explicit file offsets, actual FDE start/end, CIE/FDE coordinates, LSDA pointer and whole-interval SHA-256. `function-bytes.json`, `unwind-records.json` and `instructions.tsv` retain the original bytes. No next-unwind-start estimate is used as a body size. FDE intervals and instruction closure do not establish whole-module coverage.

### Construction and the new record boundary

The earlier packet identifies callback slot `0x574f0b0` and key `0x574f0c0`. The mode-2 constructor at `0x4e99650` shows that the **full copied record starts eight bytes earlier**, at `0x574f0a8`: a 24-byte tagged value followed by a 20-byte address and padding. Its tag is zero. The three loads at `0x4e997a0`, `0x4e99791`, `0x4e99782` copy consecutive 16-byte pieces; `constructor-copies.tsv` reassembles all 48 bytes and checks equality against the source record. The callback slot's symbol-free `R_X86_64_RELATIVE` addend is the prior wrapper `0x4e9d2a0`.

`0x4e9d240` indexes the relative-offset table at `0x7c50b8`. `registry-selector.tsv` checks each entry's cache-address load and constructor tail jump. The six mapped entries are:

| Mode | Constructor | Parent | Changes to the parent registry | Derived size | Address 09 |
| --- | --- | --- | --- | ---: | --- |
| 0 | `0x4e99110` | none | addresses 01..04 | 4 | absent |
| 1 | `0x4e98c70` | mode 0 | add 05..08 | 8 | absent |
| 2 | `0x4e99650` | mode 1 | replace 06..08; add 09 | 9 | wrapper `0x4e9d2a0` |
| 3 | `0x4e99f30` | mode 2 | replace 05 | 9 | preserved |
| 4 | `0x4e99af0` | mode 3 | add 0a | 10 | preserved |
| 5 | `0x4e9a310` | mode 4 | add 0b..11 | 17 | preserved |

The mode numbers and destinations are observations; historical fork names are intentionally not assigned. `registry-lineage.json` derives this membership from decoded parent calls, source-record references and the observed clone/replace semantics. It is not a memory dump. `static-records.json` retains all 21 source records and their relocated callbacks. No other callback body is reclaimed by this table.

Mode 2 clones the parent's map (`0x4e94fc0`) and companion address set (`0x4e94e80`), preserving their separate hash seeds. The four source records are materialized through `0x4e9db00`; addresses go through `0x4e9bec0`, and records through `0x4e9c0b0` into `0x4e9bc40`. The final registry allocation is 80 bytes. Publication at `0x4e9998a` uses `lock cmpxchg`; a losing publisher destroys its private allocation and returns the winning pointer. Existing-cache, reserve, allocation-failure, replacement-drop and unwind tails are retained in the control ledger. `0x276e2d0` and `0x4e76bc0` pack a mode-2 or mode-5 cache pointer with a zero first word into a borrowed-registry value.

### The address lookup is a hash probe

The source-array layout differs from the hash bucket layout; the move loop at `0x4e9c0ee..0x4e9c12a` makes the reorder explicit:

| Representation | Key | Tagged value | Callback |
| --- | --- | --- | --- |
| Static/source record, 48 bytes | +24, length 20 | +0, length 24 | +8 |
| Map bucket, 48 bytes | +0, length 20 | +24, length 24 | +32 |
| Returned value pointer | key is 24 bytes before it | +0 | +8 |

The map header has controls at +0, bucket mask at +8, growth budget at +16, element count at +24 and hash seed at +32. Buckets precede the controls: bucket `i` begins at `controls - 48*(i+1)`. The getter at `0x4e8cfd0` returns `controls - 48*i - 24` for a matching bucket, or null on a miss.

For a 20-byte key, define `w0`, `w4`, `w8`, `w12` as little-endian u64 loads starting at those byte offsets and `fold(a,b) = low64(a*b) XOR high64(a*b)`. The arithmetic at `0x4e8a250`, in the owned getter and in the inserter agrees on:

```text
h = fold(fold(w8 XOR secret1, w12 XOR secret0)
       XOR fold(w0 XOR map_seed, w4 XOR secret0)
       XOR 20, secret0)
```

The process-word pointer comes through relocation slot `0x576e3e0` to `0x5788348`, which is mutable/NOBITS state, not file-backed seed bytes. Bucket positions therefore cannot be fixed statically. The high seven bits (`h >> 57`) form the control fingerprint; the initial group position is `h & mask`.

Both lookup forms compare a 16-byte group, iterate matching fingerprint bits with `tzcnt` and bit clearing, and compare all 20 key bytes before accepting a candidate. A control byte equal to `0xff` terminates an unsuccessful group. Deleted controls do not terminate the search. Group advances are triangular: +16, +32, +48, masked by the bucket mask. Matches are checked **before** the group's empty-control test. These details distinguish a valid hash-table reconstruction from a linear scan or a fingerprint-only lookup.

`0x4e9bc40` uses the same hash and key comparison for insertion. An existing key returns its old 24-byte value and replaces that value. A new key updates the control byte and its mirrored tail byte, adjusts the header counters and writes a 48-byte key/value bucket. Reservation and destruction helpers remain explicit call boundaries, not silently stubbed behavior.

### Runtime entry, dispatch and failure handling

`0x4e6fef0` receives the output object in rdi, context in rsi and call input in rdx. The gas word is call-input +88, address is +96 and bytes object is +40. The depth guard compares context +168 against 1024; the greater-than branch returns status byte `0x11`. After account-loading boundaries, it saves checkpoint lengths, increments depth and appends an empty journal frame.

At `0x4e7007e`, a zero context word at +224 selects the borrowed registry pointer at +232. A nonzero word doubles as the owned table's control pointer, and `0x4e70096` calls `0x4e8cfd0`. The borrowed form performs equivalent lookup inline at `0x4e706a1..0x4e70785`, using `0x4e8a250` for hashing. An empty map, exhausted candidates followed by an empty control, or a null owned getter result goes to ordinary account-code handling at `0x4e7078a`. Input transfer-variant and scheme gates can also bypass precompile lookup; no claim is made that every call reaches it.

For a borrowed hit, `0x4e70909` computes the value pointer and `0x4e70927` calls through slot `0x5774e30`, relocated to `0x4ea2df0`. For a standard owned value, slot `0x5774e38` resolves to `0x4ea2d70`. Context-specific owned variants have additional trait call boundaries in the caller. The shared and mutable dispatch tables are retained separately:

| Value tag | Shared dispatch | Mutable dispatch |
| ---: | --- | --- |
| 0 | `0x4ea2e0a`: call value+8 with input and gas | `0x4ea2d8b`: same ABI |
| 1 | `0x4ea2e9b`: additionally pass environment | `0x4ea2dd0`: same ABI |
| 2 | `0x4ea2e1b`: aligned object plus vtable+24 | `0x4ea2d9b`: same trait slot |
| 3 | `0x4ea2e40`: allocate and return fatal error | `0x4ea2dbd`: object plus vtable+32 |

Consequently the constructed address-09 **tag-0 value** reaches `0x4e9d2a0` through the function field at value+8. The wrapper's input length, rounds, final flag and compression semantics remain the responsibility of the existing [BLAKE2b packet](../RE-021-blake2b-compress-94/README.md). This packet does not repeat its execution claims or include its body in the new coverage count.

Caller result handling at `0x4e7096d..0x4e70b57` has distinct outcomes:

| Condition in returned words | Caller action |
| --- | --- |
| word0 nonzero, cost at word4 <= supplied gas | subtract cost; status `0x02`; decrement depth |
| word0 nonzero, cost > supplied gas | destroy returned buffer; status `0x53`; rollback checkpoint |
| word0 zero, low bit of word1 set | return outer error tag 4; bypass local checkpoint action |
| word0 zero, low bit of word1 clear, word2 = signed-u64 minimum bit pattern | status `0x53`; rollback checkpoint |
| other ordinary error word2 | status `0x60`; rollback checkpoint |

The error paths copy the original gas word into the result's remaining-word position; this observation is **not** a claim about gas available to an upper-level caller after failure. Fatal errors bypass this function's local rollback branch; ownership of final fatal-error cleanup remains outside this packet. No external enum names are assumed for the numeric status bytes.

The checkpoint helper `0x4e6f690` decrements depth, reverses journal entries through `0x4e79b00`, restores saved log/journal lengths and releases discarded buffers. `journal-effects.tsv` maps its 11 journal-tag entries, including flag updates, four-limb balance reversals, nonce-shaped word updates, storage/transient-storage reversal and code-payload cleanup. Fields are reported as offsets where names remain inferred. The account/storage lookup, transient mutation and allocator calls remain external helper boundaries. `jump-tables.tsv` and `table-edges.tsv` preserve both journal dispatch sites and the nested code-drop table; panic tails for missing rows or inconsistent counters are present in the control ledger.

### Evidence inventory and ownership

`summary.json` reports 24 selected FDE intervals, 20,907 code bytes, 4,467 byte-decoded instructions, 779 control records (calls, branches and terminals, not 779 independent branches), 45 table entries, 10 bound indirect-jump sites and 46 annotated semantic windows. All counts come from ELF bytes. `layout-operands.tsv` decodes concrete field offsets, widths, gas/status constants and strides from fixed byte predicates. `relocations.tsv` retains the original 24-byte RELA entries, including table callbacks and call slots.

The selected FDE starts were checked against existing work-item evidence and the provided open/merged PR inventory. None was found outside this new packet. Prior callback endpoints appear only as dependencies. The public GitHub check did not provide a fresh main/PR snapshot; the run's supplied PR inventory and the stated checkout revision are the overlap-check baseline. No publication was attempted.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo.lock, compiler/linker flags, rebuilt-code comparison, native behavioral comparison and whole-ELF identity: **not yet implemented/measured**. There are no normalization masks and no transplanted executable bytes used as an implementation.

The Python helpers model the recovered hash/probe arithmetic and caller result decisions; they do not run machine code. `lookup-cases.json` contains seven synthetic cases using the real address-09 key with explicit arbitrary seeds: zero count, direct hit, same-fingerprint wrong prefix, wrong last byte, a deleted-control second-group hit, a triangular third-group hit, and a match before empty-control termination. `result-cases.json` contains ten gas/error boundary cases. These are instruction-derived expectations, not captured runtime fixtures.

The focused suite has 24 passing tests and zero skips. Controls include corrupt target digest and instruction byte, invalid/NOBITS/cross-section/ambiguous reads, missing/duplicate FDE, changed byte predicate, wrong relocation type, corrupt jump table, unsupported/truncated instruction shape, branch into an instruction, every individual bit of the 20-byte key, group wrap, malformed controls, seed dependence, independent 32-bit-limb multiplication, and success/error/fatal precedence. Generated files are compared byte-for-byte with a fresh collection. Two CLI regenerations under different hash seeds/timezones are also compared with `diff -r`; see the final submission report for actual validation results.

## Results and limitations

The former static Address+callback-only connection now has a constructor-to-bucket-to-getter-to-enum-call trace and a caller success/error/checkpoint map. A reconstruction can preserve the distinct source-record and bucket layouts, seed-dependent lookup, replacement semantics, borrowed/owned dispatch differences and fatal-error precedence without guessing from source labels.

This is a partial component result. The **evm gates remain 0/4**, and no progress/catalogue files are changed. The complete COMPONENTS first task (reth/revm private fork boundaries and all state-transition inputs) is not satisfied. Large-packet ambition is not a completion or grade claim.

The selected corpus still has 44 distinct resolved external control targets and 39 dynamic call sites. Some dynamic sites are explained conditionally (notably the tag-0 BLAKE callback); this is not transitive helper, allocator, database, vtable or exception closure. FDE LSDA pointers and original records are retained, but exception call-site tables were not decoded. The byte-shape walker is scoped to the authenticated corpus; decoded byte count is not a whole-node matched-window denominator. The model checks are not evidence of native output equivalence.

Next question: bind a specific HyperEVM adapter's fork selector and registry installation to this runtime context, including private overrides, then independently reconstruct the table ABI and validate it under a separately authorized differential protocol.
