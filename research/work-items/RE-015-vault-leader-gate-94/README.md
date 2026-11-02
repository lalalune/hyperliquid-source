# RE-015: trace the name-gated 20-byte record query in node #94

The selected #94 path constructs a 48-byte-stride result from records whose 20-byte field matches the query and whose flag byte is zero, then applies a separate seven-name configuration gate; this permits reconstruction of the filter and result layout without making the configured name part of the filter.

- Component ID: `constants`, task `RE-015`, with the connected state-query consumer needed to show what the configuration branch controls.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred, unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is a lead, not target source and not copied as an implementation.
- Claim status: observations are authenticated bytes, relative transfers, relocation entries, selected FDE/LSDA records, and local stores. Record names, source types, and the relationship to the existing configuration interpretation are inferences. Runtime reachability, external helper behavior, and endpoint identity remain unresolved.
- Scope included and excluded: one wrapper, its locked query, the selected collector and two cleanup bodies, including local normal and failure paths. The existing static-config loader, 76-name inventory, iterator body, allocation and growth internals, other callers, node #115 and visor are excluded. This is not full component recovery and requests no progress gate.

## Reproduce

From the repository root on Linux x86-64, Python 3.12.3 was used. The collector checks the entire capture SHA-256 first, imports the repository `elf_index` and `fde_extents` readers, rejects NOBITS as file data, and interprets only fixed instruction encodings within the five selected FDEs. The instruction reader adapts the independently authored MIT reader in RE-015 agent-timing, PR #1603. It checks that every admitted instruction fits in its FDE and every in-range direct branch targets an admitted start; this is not a general-purpose disassembler. The tool and tests use no external program. No captured program is executed and no network or chain action occurs.

```sh
python3 tools/config_vault_leader94.py --out research/work-items/RE-015-vault-leader-gate-94
python3 -m unittest tests.test_config_vault_leader94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-vault-leader-gate-94 && sha256sum -c MANIFEST.sha256)
```

Two independent regenerations can be compared with the committed generated evidence. These directories must start empty:

```sh
mkdir -p work/re015-vault-a work/re015-vault-b
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_vault_leader94.py --out work/re015-vault-a
PYTHONHASHSEED=983 TZ=Pacific/Honolulu python3 tools/config_vault_leader94.py --out work/re015-vault-b
diff -r work/re015-vault-a work/re015-vault-b
for f in work/re015-vault-a/*; do cmp "$f" "research/work-items/RE-015-vault-leader-gate-94/${f##*/}"; done
```

GNU objdump 2.42 was used only for human inspection; its output is neither an input to the collector nor a generated evidence file. For example:

```sh
objdump -d -M intel --start-address=0x2586fd0 --stop-address=0x2587110 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x2569d00 --stop-address=0x256a2b7 artifacts/node/94/hl-node
```

`functions.json` retains whole selected FDE bytes, hashes and unwind coordinates. `instructions.tsv`, `transfers.tsv`, `contracts.tsv`, `layout.tsv`, `anchors.tsv`, `relocations.tsv`, `descriptors.tsv`, `exceptions.tsv`, `exception-headers.json`, `cfg.json`, `name-cases.tsv`, `floating-cases.tsv`, `selector-cases.tsv`, `lock-cases.tsv` and `summary.json` are generated from the authenticated ELF and explicitly synthetic test inputs. The manifest covers this README and every generated file. There are no timestamps, random values or machine-specific paths in generated records.

## Evidence

All addresses below are linked ELF virtual addresses before a load bias; FDE ends are exclusive. The generated records also give file offsets, computed from each file-backed ELF section. An FDE is an unwind-described range, not by itself proof of a source-function boundary or a complete function census.

| Selected FDE | Byte count | Local role established by the selected instructions |
| --- | ---: | --- |
| `0x2586fd0..0x2587110` | 320 | Copies a 20-byte input, calls the locked query, then applies the configuration guard and returns the saved three-word result. |
| `0x27d7cb0..0x27d7fe0` | 816 | Acquires and releases a word at owner `+0x568`, prepares the iterator, calls the collector, and preserves two binary64 values and the result. |
| `0x2569d00..0x256a2b7` | 1,463 | Filters records, copies a variable-length field and a 20-byte key into a growable array, and handles local allocation and iterator failures. |
| `0x277b7f0..0x277b86c` | 124 | Cleanup of one saved array representation on an exceptional path. |
| `0x2782520..0x278259c` | 124 | Cleanup of the other saved array representation on an exceptional path. |

### Configuration identity and name guard

The retained full entries are `c0 0e /static_config 00` at `0x1ef5f5` and `c0 05 /cham 00` at `0x1fc0ec`. They are format-template anchors, not complete rendered paths. Their already-owned callers are not reanalyzed. Prior `constants` and `constants-aws-name-parse-94` evidence binds the configuration byte and distinguishes the file/parse fallback from a successfully parsed `NvTestnet`; that earlier evidence identifies both resulting bytes as 32. This packet independently reads the selected `NvTestnet` descriptor at `0x5668488` and its RELATIVE relocation to the nine bytes at `0x2180ff`, but does not independently reprove the loader's default.

Here `0x258703f` loads slot `0x576e928`, whose `R_X86_64_RELATIVE` addend is `0x577b288`. The code checks the word at that cell's `+0x50` and, after any slow initialization boundary returns, reads the byte at `+0x48`. The selected gate is preceded by an SSE comparison of the sum of two binary64 values with the binary64 `3.0` at `0x20aab8`. A less-than, equal or unordered result bypasses the name read. On the greater, ordered branch, the code checks `name <= 31`, then tests bit `name` of `0x803c6000`. The seven set positions and their separately read, length-delimited descriptors are:

| Configuration byte | Descriptor text |
| ---: | --- |
| 13 | `HeavyTestnet` |
| 14 | `HeavyMainnet` |
| 18 | `SoloTestnet` |
| 19 | `SoloMainnet` |
| 20 | `LockerTestnet` |
| 21 | `LockerMainnet` |
| 31 | `SoloSandbox` |

Byte 32 (`NvTestnet`) fails the unsigned upper-bound check, including when the floating sum is above 3. The floating model assumes masked floating-point exceptions; the values are not asserted to be wall-clock durations or to use any particular unit. The gate reaches a separate state-word read at `0x577ab98`. If that word is nonzero, the wrapper calls the Once boundary with cell `0x577ab80`; its RELATIVE addend is the previously studied build-mode initializer. If the word is zero, that call is bypassed. The previous build-mode packet owns the initializer body.

The query call occurs before this guard. All local normal branches after the name check reach the same saved-result copy at `0x258706c`; the local CFG has no path from the configuration load back to the query call. This observation assumes the external calls return and makes no claim about their arbitrary effects or concurrent state. The full 256-byte predicate and floating controls are synthetic deductions from the locked instruction bytes, not target executions.

### Query, selected record and output

The wrapper copies 16 plus four input bytes before calling the locked body at `0x2587010`. The locked body passes an iterator to the collector at `0x27d7e25`. The existing `vaults-equity-views-94` packet describes the external iterator as walking a tree with 20-byte keys and values at stride `0xb0`; this packet treats that iterator as a boundary and does not claim its body. The local first-record code and the later inlined scan independently perform the following tests, with offsets relative to the candidate value:

| Condition | Local next step |
| --- | --- |
| 16 bytes at `+0x98` and four at `+0xa8` differ from the input | Continue the scan. |
| All 20 bytes match, but byte `+0xac` is nonzero | Continue the scan. |
| All 20 bytes match and byte `+0xac` is zero | Read a pointer at `+0x28` and length at `+0x30`, then build a result row, subject to the allocation and sentinel branches below. |
| Initial iterator boundary returns no item | Return three words `(0, 8, 0)` without taking the first-row allocation path. |

The two comparisons are checked at `0x2569d48..0x2569d7f` and `0x256a0b1..0x256a0f5`. `layout.tsv` binds the offsets and first/later agreement to individual bytes. The earlier vault packet labels `+0x98` as a leader address, `+0xac` as closed, and the key as a vault address. Their binary-consistent layout supports a leader-filtered vault-list interpretation here, but does not by itself prove an HTTP method, route, source signature or every record's validity.

A first retained row requests `0xc0` bytes for four `0x30`-byte rows. The copied variable-length field supplies row words `+0x00` and `+0x10` (both the observed length) and `+0x08` (the copied allocation pointer); the 20-byte tree key is stored at `+0x18..+0x2b`. The final four bytes of the stride are not established as initialized. A zero field length uses pointer value 1 without the field allocation. Later matching rows append at stride `0x30` and increment length; when length equals capacity, a separate growth boundary receives element size `0x30`. Its allocation policy is not recovered.

For a nonzero field length, the observed code calls allocation and copy boundaries before testing the `0x8000000000000000` length sentinel. Equality then goes back to scanning in both the first and later paths. We do not assume that an allocation and copy of that size can succeed on a valid runtime input. `selector-cases.tsv` models only the key/flag filter, before allocation, sentinel and other failures; it is not a model of the full returned vector.

### Lock, errors and exceptional paths

The locked body first reads owner word `+0x568`. If bit `0x08` is set, or the unsigned word is at least `2^64 - 16`, the code takes the slow boundary. Otherwise it attempts an atomic compare-exchange of the old word to old word plus 16; a failed exchange also takes the slow boundary. After the collector returns, an atomic exchange-add subtracts 16. If the **old** word returned by that operation satisfies `(old & 0xfffffffffffffff2) == 0x12`, execution calls another boundary before continuing. These are instruction-level branches; the implementation and side effects of the called helpers remain unknown.

| Local condition or call | Observed branch or landing |
| --- | --- |
| First or later nonzero-length field allocation returns null | The respective error boundary is reached; local bytes lead toward `ud2` if the relevant error boundaries return. |
| First row-array allocation returns null | The error boundary at `0x256a264` is reached; its LSDA landing can free the pending field allocation before unwind continues. |
| Later array growth call unwinds | The selected LSDA range lands at `0x256a26c`, which can release the pending field and calls an existing vector-cleanup boundary. |
| Iterator state guard or parent pointer fails | Separate local error calls are selected at `0x256a234` and `0x256a225`; their external semantics are not inferred. |
| Collector call unwinds inside the lock | The selected LSDA range lands at `0x27d7f5e`, which subtracts 16, conditionally calls the release boundary and resumes unwinding. |
| Optional flag-controlled helper unwinds | Its LSDA landing at `0x27d7f49` calls cleanup `0x277b7f0`; a later call range lands at `0x27d7f8f` and calls `0x2782520`. |
| Either wrapper Once call unwinds | Its landing reaches the previously owned vector-cleanup boundary and resumes unwinding. |

Each new cleanup iterates the vector length at 48-byte stride; a row with a nonzero first word passes its pointer and that word to the same deallocation slot. It subsequently tests vector capacity, rather than vector length, before passing `capacity * 48` and the backing pointer to that slot. The arithmetic uses machine-width operations; actual valid capacities and allocator semantics are not established. The two cleanup bodies are raw-equal in 118 of 124 bytes. Masking only the four-byte RIP displacements at body offsets `0x20` and `0x6e` leaves 116 of 116 other bytes equal; the code verifies both pairs of resolved targets. These are two target-code copies, not a source-build comparison.

`exceptions.tsv` records 20 call-site ranges from three selected LSDAs; the two cleanup FDEs have no LSDA. A landing and raw action value are observations, not proof that an exception occurs or a decoding of action/type-table semantics. `cfg.json` records 22 reachability propositions over normal local edges, with conditional edges both allowed and external calls assumed to return. A structural witness does not prove a feasible real input, and exceptional edges are represented separately.

### Inferences and prior ownership

The selected field offsets and 20-byte key agree with the earlier vault layout, so “leader”, “closed”, and “vault address” are useful provisional names. The exact endpoint and any relationship to a particular request remain unproven. The earlier small-vault query packet, PR #1759, covers a different wrapper and a different 120-byte-stride record filter; it does not own any of the five selected starts here. The existing iterator and shared allocator/growth routines are explicitly boundaries. The existing configuration and build-mode packets supply the prior default and initializer interpretations; this packet adds a distinct consumer path and does not replace the original 76-name inventory.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo manifest and lock, compiler/linker flags, two-build comparison, target execution, behavior fixtures, helper and vtable closure, relocation-qualified source comparison, and whole-ELF identity are **not yet implemented or measured**. No source-level matching bytes are claimed. The two-target-body comparison above states its precise masks and does not count as a reconstructed implementation.

## Results and limitations

For the selected ranges only: 5 FDE extents, 2,847 bytes, 670 admitted instruction rows, 173 exact instruction contracts, 84 direct branches, 45 calls or indirect transfers, 30 extracted layout facts, 20 relocation records, 8 selected descriptors, 20 LSDA entries and 22 bounded normal-CFG propositions. The two independent output directories matched byte for byte under different hash seeds and time zones; generation and the focused 24-test suite also passed with a Python-only PATH and zero skips. Controls include digest, instruction, valid-but-wrong branch, RELA, FDE, LSDA, descriptor, template, NOBITS and address-range corruption; all 256 name bytes, all 20 key positions, nonzero flag values, floating boundaries and selected lock boundaries are exercised as static models. Artifact/signature verification, catalogue consistency and static inventory reproduction passed.

The input corpus and open-PR file inventory do not expose every external PR body; the submitting account must also confirm address ownership against any unavailable bodies. The actual configured byte, runtime timing values, selection inputs, Once behavior, allocator behavior, complete exception actions, source build and target behavior remain unmeasured. No component gate is advanced: `constants` remains 0/4, and this packet does not complete the component's full first task. Next, bind the already-indexed request boundary to a separately unowned serializer or caller and validate the returned row layout with an independently authorized fixture.
