# RE-011: Trace the node 115 balance-read adapter and its conditional state updates

On the selected node #115 balance-read path, the parsed block field reaches the handler but its argument register is replaced before the address-only account-read tuple is built, while a separate conditional path updates in-memory measurement records.

- Component ID: `evm-rpc`, with the `evm` account-read and fork boundaries; task `RE-011`.
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: hyperliquid-source `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; separately pinned public `hyper-evm-sync` `d0945c699d9d4774417f4355b10744e7cd420df8`. The unlicensed inferred reference supplied a search lead only and is not a generator input or implementation source.
- Claim status: the byte, relocation, branch and file observations below are static observations. Role names and the implications for a source reconstruction are inferences; runtime reachability and wire behavior remain unresolved.
- Scope included and excluded: one registration-linked balance callback, selected object and positional parameter branches, the address array and error wrappers, account-read result tags, and the conditional measurement-map update. Shared router lookup, the account backend, complete scalar value parsing, final response serialization, persistent EVM writes, the complete fork diff and target execution are excluded.

## Reproduce

From the repository root on Linux x86-64, Python 3.12.3 and GNU objdump 2.42 were used. The collector requires Python 3.11 or newer, the standard library, and the repository's `tools/elf_index.py` and `tools/fde_extents.py`. It first checks the whole node SHA-256, then reads file-backed ELF sections, the unwind header, CIE/FDE records, selected exception call-site tables, selected RELA and dynamic-symbol records, and raw instruction bytes. It checks the SHA-256 of the public sync manifest and lockfile before reading their dependency declarations. No captured program is executed and the collector and tests invoke no external program.

```sh
python3 tools/artifacts.py verify
python3 tools/re011_balance_read115.py --out research/work-items/RE-011-balance-read-115
python3 -m unittest tests.test_re011_balance_read115
python3 tools/catalogue.py --check
(cd research/work-items/RE-011-balance-read-115 && sha256sum -c MANIFEST.sha256)
```

The collector writes the generated evidence files, not this README or the manifest. For an independent byte-for-byte check, substitute a writable directory for `<tmp-dir>`:

```sh
python_exe=$(command -v python3)
PATH= PYTHONHASHSEED=1 TZ=UTC "$python_exe" tools/re011_balance_read115.py --out <tmp-dir>/a
PATH= PYTHONHASHSEED=937 TZ=Pacific/Honolulu "$python_exe" tools/re011_balance_read115.py --out <tmp-dir>/b
diff -r <tmp-dir>/a <tmp-dir>/b
```

Compare those generated files with the same names in this packet. `MANIFEST.sha256` covers every packet file other than the manifest. For human instruction-boundary inspection only, the following commands disassemble the authenticated input; their output is not parsed or included in a generated file:

```sh
objdump -d -w -M intel --start-address=0x2d009f0 --stop-address=0x2d00f79 artifacts/node/115/hl-node
objdump -d -w -M intel --start-address=0x2694df0 --stop-address=0x26954d6 artifacts/node/115/hl-node
objdump -d -w -M intel --start-address=0x2a3e430 --stop-address=0x2a3eb51 artifacts/node/115/hl-node
objdump -d -w -M intel --start-address=0x4771f70 --stop-address=0x47721e9 artifacts/node/115/hl-node
```

## Evidence

All addresses are linked ELF virtual addresses before relocation; file offsets are zero based, and FDE ends are exclusive. `functions.tsv` records each selected unwind-described extent, body hash, index entry and CIE/FDE bytes. These extents are not a complete function census or independent proof of original source boundaries. `windows.tsv` and `transfers.tsv` retain the selected bytes and decoded transfers; `relocations.tsv`, `references.tsv` and `comparison-symbol.json` record the selected data and call links. `lsda-headers.tsv` and `lsda-call-sites.tsv` preserve the selected exception table headers, raw call-site records, protected ranges and landing offsets; type and action tables are not decoded. No relocation operands are masked and no compiled-code comparison is claimed.

### Registration, input and handoff

| Stage | Selected evidence | Observation |
| --- | --- | --- |
| Registration boundary | `0x2a060b9`, `0x2a060cd` | A selected call site supplies the 14-byte `eth_getBalance` literal to `0x2cff4e0`. The surrounding router is covered by existing work and is not a selected FDE here. |
| Descriptor | `0x2cff4e0..0x2cff5bd` | The routine increments a reference count, allocates a descriptor and passes tag 0 plus table `0x64506c8` to an insertion slot. A nonpositive increment branches to a trap and a null allocation takes the failure call. The table's RELATIVE slots at offsets `0x18`, `0x20` and `0x28` have addends `0x2dd5c60`, `0x2d009f0` and `0x2d009f0`; its two scalar header words are both 8. |
| Wrapper and callback | `0x2dd5c60..0x2dd5cf3`, `0x2d009f0..0x2d00f79` | The wrapper copies selected arguments, directly calls the callback and decrements its held count. The callback tests a sentinel, empty input and an initial `{`, then chooses object-shaped or positional processing. Exactly `[]` takes a special empty positional representation; surrounding spaces do not take that exact branch. |
| Positional address | `0x2d0f8f0..0x2d0fc5d`, `0x1d6b370..0x1d6b52b` | The selected cursor helper treats an empty cursor or leading `]` as no further address parameter. Leading `[` or `,` takes a nested parser path after a slice-boundary check; other leading bytes take a separate formatter. The nested helper scans a four-byte whitespace set and directly calls the same address-value parser as the named visitor. The code has a selected slice-boundary helper for an immediately following byte in `0x80..0xbf`. On the selected no-more-parameter branch, assuming allocation succeeds, it calls an error builder with signed 32-bit immediate `-32602`, title bytes `Invalid params`, and constructed bytes `No more params`. Allocation failure reaches a separate boundary. The builder `0x25cd880` is separately owned by `RE-011-evm-fee-history-115`; its internals and final wire encoding are outside this packet. |
| Named fields | `0x1d734b0..0x1d735c5`, `0x1f5cc20..0x1f5d635` | The visitor compares immediate bytes for `address`, `blockId` and `block_id`. The two block spellings share a duplicate check; a second address also takes a duplicate-field path. If normal field-value parsing and unknown-field skipping succeed, an absent address reaches the missing-field formatter and an absent block takes internal tag 2. The wrapper has a separate trailing-non-whitespace error path. |
| Address value | `0x298d2f0..0x298d9a7` | A quoted-value arm calls the previously owned fixed-width decoder through slot `0x64e1e48`, passing width 20. A 33-entry relative table selects, among other arms, `[` to the separate array visitor. This establishes selected control flow, not every accepted address representation. |
| Array and errors | `0x2694df0..0x26954d6`, `0x1dc1b20..0x1dc1b86`, `0x2697370..0x269740e` | Twenty element-presence guards select length arguments 0 through 19 on the indicated missing-element arms. Twenty selected payload stores write offsets 1 through 20. A subsequent probe with tag 0/present 1 selects length argument 21; tag 0/present 0 reaches the payload stores. The probe's nonzero-tag path performs selected cleanup and then reaches those stores if cleanup returns normally. The error wrapper references a data word 20 and a formatting representation containing the byte strings `exactly ` and ` bytes`; the following data word is 40, but its use and the complete final text are not established. |

`parameter-cases.tsv`, `positional-cases.tsv`, `positional-error.json`, `field-names.tsv`, `field-flows.tsv`, `address-dispatch.tsv`, `array-elements.tsv`, `array-stores.tsv`, `element-wrapper-vectors.tsv` and `array-vectors.tsv` make these selected checks reproducible. The positional cases start at the helper's internal cursor, after any callback normalization; the invalid-byte cases describe conditional machine branches, not necessarily reachable valid strings. The field and array vectors are synthetic branch models: they assume the indicated nested parser results and, where applicable, normal cleanup. They are not JSON requests executed against the node. In particular, the extra-probe observation does not establish that an arbitrary malformed RPC request succeeds.

For the selected successful positional handoff, `0x2d00c03` forms the address pointer in `rdx`, `0x2d00c0b` forms the block-related pointer in `rcx`, and `0x2d00c16` calls `0x2a2b890`. At the callee entry the instructions save the output pointer, load the context from `rsi`, and load a context-derived pointer; `0x2a2b8b0` then overwrites `rcx` with the address of the 11-byte `eth_balance` diagnostic. The tuple passed onward contains context, the `rdx` address pointer and that diagnostic. The named success path joins the same call. This is a register/data-flow observation on these selected paths; it does not prove that ambient context cannot have been affected elsewhere, nor that every selector reaches the same snapshot.

### Account-read tags and guard

`0x2a2b890..0x2a2c1fd` carries the address tuple to `0x2a3e430..0x2a3eb51`; optional thread-local bookkeeping has a separate route to the same callee. In the latter, the guard word is at context offset `0x6a8`; the state pointer is loaded at context offset `0xb00`, with inner offset `0x1c98`. Two selected arms copy 16 plus 4 address bytes and call the separately owned account-read boundary `0x3d48970`. The backend's complete error taxonomy and live state are not assumed.

| Selected returned tag | Local normal-return path |
| --- | --- |
| 1 | Copy the first 32 payload bytes to the local result. |
| 0 | Select 32 zero bytes. |
| 2 | A subtag below 2 bypasses the selected cleanup, subtag 2 calls through a pointer, and higher subtags conditionally deallocate when the auxiliary word is nonzero; after normal cleanup the selected path uses 32 zero bytes. |

These labels describe values at the caller boundary and do not establish when the backend produces them. The model rejects a zero indirect-cleanup word; a nonzero word still needs to identify a valid object for the indirect call to return normally. On the selected callback return branch, tag 3 selects two 16-byte payload copies and sets a local word to 1. The callback stores its tag and payload in a stack object and passes its address in `rdx` to `0x22d02d0` at `0x2d00d04`, then copies selected returned fields to its output. `response_handoff` and `response_output_copy` in `windows.tsv` capture that handoff. The response-builder internals and exact wire encoding remain outside this packet.

The selected guard fast arm adds `0x10` with `lock cmpxchg` only when bit `0x8` is clear and the old unsigned word is less than `2^64 - 16`; a failed exchange takes the slow boundary. Normal and unwind release arms use `lock xadd` with `-0x10`. On release, `(old & 0xfffffffffffffff2) == 0x12` takes the selected wake helper. `guard-vectors.tsv` explores hypothetical words and exchange outcomes; it does not assert that every vector is reachable or model races and the slow helpers.

### Conditional measurement-map state

After the account read, `0x2a3e996` tests a local boolean together with the context dword at `+0x128` against `1,000,000,000`. When both selected conditions hold, `0x2a3e9dd` calls RELATIVE slot `0x64e7058`, whose addend is `0x4771f70`, with the object at context `+0x28` and a computed scalar. The source of that scalar and the full meaning of the surrounding context are not established.

The update range `0x4771f70..0x47721e9` attempts a byte `0 -> 1` lock exchange and has a slow-acquire continuation. It calls `0x476f260..0x476f478`: the selected lookup hashes an input record through another helper, probes 16 control bytes at a time, compares candidate key metadata and calls a dynamic symbol named `bcmp`. Its return distinguishes an existing entry from a missing-entry/insertion result; a zero word at map offset `+0x10` on the selected missing branch calls a growth boundary first. Actual dynamic binding, the hash helper and growth internals remain unresolved.

On the selected missing-entry path, the update writes control bytes and a 24-byte key into a 48-byte-stride record, clears the adjacent aggregate fields and increments a map word. On the selected common continuation it increments the word at entry-end offset `-0x18` with saturation at `2^64 - 1`, computes a floating-point sum path stored at `-0x10`, and applies `MAXSD` with the input scalar to the value at `-0x8`. The sum's non-finite branches and the exact semantic names of these fields are not fully recovered. The normal and unwind paths attempt to release the byte lock; failure reaches a slow release boundary. These are in-memory synchronization and measurement-map writes, not evidence of a persistent EVM state transition.

The selected exception table gives the lookup call's protected interval as `0x4771f97..0x4771fa1` and its landing address as `0x47721c1`. At that landing, a byte-lock release is attempted before a call to the unwind-resume boundary; a failed release takes the selected slow helper. This ties that cleanup arm to the protected call-site record, subject to the runtime's unwind and action-table behavior. It does not establish a complete exception taxonomy or execution of the arm.

`selected-layout.json` and `metric-count-vectors.tsv` derive the selected displacements, opcodes and count boundaries from the authenticated image. `comparison-symbol.json` records the ELF relocation and symbol-table bytes/coordinates used to identify `bcmp`; the symbol name does not prove which dynamic implementation will bind at runtime.

### Fork and dependency context

`fork-tokens.tsv` records exact token occurrences in file-backed `.rodata`, not unique dependencies or a complete Cargo graph. `public-forks.json` parses the separately pinned public sync project's manifest and lockfile, with both input hashes. These public declarations are not versions inferred for the node binary.

| Node #115 path token | Occurrences | Separate public sync context |
| --- | ---: | --- |
| `z_forks/reth-chainspec` | 1 | Node source revision not established. |
| `z_forks/reth-ethereum-forks` | 1 | Public sync lockfile records reth tag `v1.1.5`. |
| `z_forks/reth-rpc-eth-types` | 2 | Node source revision not established. |
| `z_forks/reth-rpc-server-types` | 1 | Node source revision not established. |
| `z_forks/revm-precompile` | 12 | Public sync lockfile records registry `revm-precompile` `16.2.0`. |
| `z_vendor/revm` | 26 | Public sync manifest pins `revm` `19.2.0`. |

### Inferences and unresolved points

The literal and registration call support associating this descriptor with `eth_getBalance`; the diagnostic and width support calling the following path a balance/account read. These names do not prove original Rust types. The selected callee does not carry the incoming block pointer into its constructed read tuple, but parsers, context aliasing, the separately owned router, the backend and other routes remain outside the proof. The 32-byte tag-1 value has not been independently identified as a specific account-field layout or serialized result. No private fork patches, exact node crate revisions, runtime state, complete exception handling or persistent state writes are established.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. There is no new Cargo graph, compiler or linker configuration, two-build comparison, executed differential fixture, raw or normalized candidate comparison, normalization mask, helper closure or whole-ELF equivalence claim. The Python files regenerate selected evidence and exercise conditional models; they are not node implementations. The target binary is never executed.

## Results and limitations

The generator records 15 selected FDE ranges, 13 selected exception headers and 95 call-site records, 105 byte windows, 179 selected transfers, 21 RELATIVE slots, one separately decoded dynamic-symbol slot and 12 selected RIP references. Its bounded synthetic tables contain 5,613 field-name cases, 341 field sequences, 18 parameter-shape cases, 19 positional-cursor cases, 43 array-result cases, 38 guard cases, 58 account-tag cases, eight element-wrapper cases and six counter cases; the selected address jump table has 33 entries. The focused suite passed 44 tests with no skips, including changed digest, every selected window and transfer, malformed FDE and exception relationships, invalid mappings and NOBITS, altered relocations and symbol names, positional-immediate corruption, array-branch and store corruption, invalid payloads, and numeric boundaries. These counts describe this packet, not overall node coverage or target execution.

No component gate is advanced. The account backend and response builder remain boundaries, and the conditional map write is not a persistent EVM transition. Next question: independently establish which snapshot supplies the context for each block selector, then trace a non-overlapping backend or response continuation with its real error and serialization closure.
