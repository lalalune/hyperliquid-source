# RE-021: type-1 access-list construction and environment copy

Node #94's type-1 transaction path constructs ordered address and storage-key rows, and its compatible environment-copy helper deep-copies those rows, making their layout, cursor behavior and failure ordering reconstructible for the precompile-preparation path.

- Component ID: `evm`; RE-021 continues the unresolved runtime-wiring question in `RE-021-blake2b-compress-94` and is not an official TASKS row.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred reference tree `999556f6e0a474b8312db96ec3149e1c44e97c23`. No unlicensed reference implementation is copied.
- Claim status: **observed** for authenticated bytes, selected FDE and LSDA records, fixed instruction windows, relocation entries and decoded branch destinations; **inferred** for field names, RLP and type-1 labels, symbolic copy lanes and composition with earlier work; **unresolved** for the actual caller handoff, runtime handler selection, external helper behavior and native equivalence.
- Scope included and excluded: the type-1 signed and unsigned decoders, nested row/key parser, two vector growth paths, selected cleanup and row-copy helpers, and selected error/exception edges. The previously studied typed dispatcher, transaction-to-environment converter, access preparation, registry lookup, 0x09 wrapper and compression function are external dependencies rather than newly selected FDEs. Other transaction types, allocator internals, database callbacks, node #115 and visor are excluded.

## Reproduce

From the repository root, with the authenticated artifact present, Python 3.12.3 on Linux x86-64 was used:

```sh
python3 tools/re21_type1_access94.py --out research/work-items/RE-021-type1-access-list-94
python3 -m unittest tests.test_re21_type1_access94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-type1-access-list-94 && sha256sum -c MANIFEST.sha256)
```

For a reproducibility check, replace each placeholder with a different empty directory:

```sh
PYTHON_BIN=$(command -v python3)
PATH= PYTHONHASHSEED=1 TZ=UTC "$PYTHON_BIN" tools/re21_type1_access94.py --out <tmp-dir-a>
PATH= PYTHONHASHSEED=937 TZ=Pacific/Honolulu "$PYTHON_BIN" tools/re21_type1_access94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
PATH= "$PYTHON_BIN" -m unittest tests.test_re21_type1_access94
```

The extractor first authenticates the complete input and then imports the repository's shared ELF and FDE readers. Its restricted instruction-length decoder is adapted from the repository's MIT-licensed `tools/evm_kvs_inventory.py`; it rejects unsupported encodings and is not a general disassembler. Python's standard library and those shared readers are its only dependencies. It excludes SHT_NOBITS from file-backed mappings and launches no other program. GNU objdump 2.42 was used for human inspection only; no tool or test parses its output. No target instruction or captured byte was executed or emulated. JSON and TSV files in this directory are generator output; this README and `MANIFEST.sha256` are packaging files.

## Evidence

All addresses are linked ELF virtual addresses before load bias; `functions.tsv`, `instructions.tsv` and `windows.tsv` also give file offsets. `bodies.json` and `unwind.json` preserve full selected code bytes and corresponding FDE/CIE/index records. Each selected start is checked against both the unwind header and an actual FDE. The FDE end is an unwind extent, not proof of every source-level function boundary. `control-flow.tsv` is a linear decode ledger, not a reachability proof; external and register-indirect targets remain boundaries. `decisions.tsv` annotates selected conditional edges, `error-stores.tsv` decodes selected raw error immediates, and `exception-sites.tsv` retains call-site records; exception action chains and type tables are not decoded.

| Selected FDE start | Bounded role inferred from the bytes |
| --- | --- |
| `0x4e54230` | Parse the enclosing signed list, call the unsigned and signature boundaries, compare declared and consumed lengths, and publish the signed result. |
| `0x134f840` | Decode ordered unsigned fields, including a recipient, a byte-string payload and an access list. |
| `0x1350c40`, `0x1350970` | Decode selected unsigned-word and byte-string fields. |
| `0x1350e50` | Decode the outer access list, each address row and its key vector. |
| `0x1353a90`, `0x1353af0` | Grow the outer row vector and check its allocation size. |
| `0x135b590`, `0x135b5f0` | Grow the inner key vector and check its allocation size. |
| `0x1353a40`, `0x1350bc0`, `0x4e53b90` | Release initialized row payloads on selected error, unwind and signed-wrapper cleanup paths. |
| `0x4e54fe0`, `0x4e52960` | Replace existing rows and append deep-copied rows in a destination vector. |

### Input and row layout

The pending type-2 transaction packet #1733 retains the separate typed-dispatch and converter bodies. Its dispatch table's type-1 case reaches the signed decoder above; this packet studies different FDEs and does not re-export those prior bodies. The signed decoder calls the unsigned decoder through a symbol-free relative relocation, then calls the prior signature-decoding boundary. On the successful path, the selected copy sizes are `0xa0` unsigned bytes and `0xe0` signed-result bytes. The earlier field order, widths and helper shapes motivate the names chain word, nonce, fee, gas, recipient, value, payload and access list; they are not recovered symbols.

The unsigned result stores a three-word access-list vector at `+0x68`, with count at `+0x78`, and a tagged recipient at `+0x80`. A present recipient has a one-byte tag followed by 20 address bytes, subject to the previously studied recipient-helper contract. The list decoder returns its vector only after its rows have been constructed. `layout.json` obtains the selected offsets and strides from instruction operands; `windows.tsv` retains the fixed byte predicates supporting those extractions.

| Row offset | Size | Inferred role |
| ---: | ---: | --- |
| `+0x00` | 8 | Key-vector allocation capacity |
| `+0x08` | 8 | Key-vector pointer |
| `+0x10` | 8 | Key-vector element count |
| `+0x18` | 20 | Address bytes |

Rows advance by 48 bytes and key elements by 32 bytes. The selected row and key paths require address length 20 and key length 32 before their copies. `lanes.tsv` symbolically projects all 20 address and 32 key byte lanes through the pinned loads, intermediate stack copies and stores: on those success edges the bytes retain their order. The model assumes the selected branches, valid pointers and no mutation by intervening helpers; it is not an execution receipt. The loop increments the row/key counts as it appends, preserving the selected input order. The row's final padding is not characterized.

The list parser initializes an empty outer vector with zero capacity and count and pointer sentinel 8; its inner key vector uses zero capacity and count and pointer sentinel 1. The latter value is also used by the selected empty-key clone arms. These are representation observations, not pointers to dereference.

### Length checks and cleanup order

After a valid outer list header and payload-bound check, `0x1350fac` advances the caller's cursor to the end of that outer list **before** parsing its first nested row. Thus a later selected row error is reached after that cursor update; this is not an assertion that every caller retains the cursor after handling an error. Empty outer input, noncanonical length forms, a non-list row, wrong address/key widths and mismatched declared row lengths have distinct observed raw words. The examples below are static projections of specific branches, not captured target results:

| Selected input or predicate | Raw result and effect |
| --- | --- |
| No byte available for the outer list | Error word 2; no outer-list header was consumed. |
| Outer prefix `81 00` | Error word 3 after consuming the prefix on the selected single-byte check. |
| Long-form length begins with zero | Error word 1 on the selected length check. |
| Long-form payload length below the short-form boundary | Error word 4. |
| Outer list `c0` | Normal empty-vector return. |
| Non-list row, or address/key with the wrong selected width | Error word 6 for the selected non-list arm, or 5 for the selected width arms; allocated partial data is released on their cleanup paths. |
| Declared row length differs from bytes consumed | Error word 8 after selected key-vector cleanup. |
| Signed envelope declared length differs from consumed length | Error word 8 followed by selected signed-payload and row cleanup. |

These are bounded examples: earlier header/truncation tests can win, so the table does not assign one error to every malformed encoding. The full selected conditional transfer ledger remains in `control-flow.tsv`.

When an outer vector or inner key vector is full, the corresponding helper chooses 4 for a doubled capacity below 5, otherwise the doubled capacity. The row allocation helper compares the proposed count with the bound decoded in `growth.json` before multiplying by 48. The key helper checks both the high bits of the count and the sign bit of the shifted 32-byte allocation size. These statements assume valid vector invariants and do not establish the behavior of the allocator or every overflow state.

`exception-sites.tsv` binds the key-growth and row-growth call intervals to separate landing pads in the list parser. The selected landing code releases the current key allocation when present, then invokes `0x1350bc0`, which visits initialized rows in 48-byte steps, releases their key allocations and finally releases the outer allocation. On the regular error path, `0x1353a40` visits the initialized rows and the caller separately releases the outer allocation. The signed wrapper similarly cleans the initialized row payloads after its length-mismatch arm. These are static landing/cleanup edges, not evidence that an exception occurred in the target.

### Deep copy and conditional precompile connection

For the selected row-copy helper `0x4e54fe0`, a source shorter than the existing destination first stores the shorter destination count and releases trailing rows. For overlapping rows it allocates and copies each nonempty source key vector, releases the old destination key allocation, then stores the new vector and 20 address bytes. An empty key vector bypasses allocation and uses pointer sentinel 1 with zero length. If source rows remain, a tail transfer enters `0x4e52960`, which appends deep-copied rows and has its own corresponding empty-key arm. Allocation-size overflow and a zero allocation return enter separate recorded failure boundaries. The append helper's LSDA entry for its failure call names a landing that stores the count of completed rows before calling the unwind boundary. These observations establish ordering for the selected paths, not transactional rollback, arbitrary alias safety or the internals of allocation and deallocation.

The earlier pending converter evidence retains the type-1 case that passes its source row pointer/count to this copy helper and supplies the destination vector in the transaction-environment subobject. The earlier preparation packet #1563 records a 48-byte row list with a 20-byte address and 32-byte keys in the environment consumed before precompile lookup. These shapes agree with the new parser and copier. Conditional on the decoded type-1 object being supplied unchanged to that converter, the helper and allocation boundaries returning normally, the resulting environment being the one used by #1563, and its previously documented provider, account and registry guards holding, a recipient of nineteen zero bytes followed by `09` is compatible with the existing address-09 lookup and wrapper. The access-list row address is a separate field from the transaction recipient; including address 09 in an access list alone does not establish that it is the call target. The caller connecting the decoded object to the converter and an actual runtime invocation are not proved here. The existing object and wrapper remain owned by [the compression packet](../RE-021-blake2b-compress-94/README.md); registry construction and lookup remain under pending PR #1373.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo.lock, compiler/linker settings, independent rebuilds, target execution, target-vs-Rust comparisons, normalization masks, complete helper/relocation closure and whole-ELF comparison: **not yet implemented or measured**. No machine-code bytes are transplanted as an implementation.

The focused Python tests are static controls. They alter the input digest, every fixed instruction window, unwind index and FDE metadata, relocation type, branch boundaries, exception headers and symbolic copy operands. They also exercise every bit in the selected address/key lane projections, independent integer checks at both allocation bounds, and a separately encoded and decoded synthetic type-1 RLP object containing a 213-byte input, duplicate keys and a 20-byte address 09. That object has deliberately unchecked signature fields and is not evidence of a valid transaction or target acceptance. Truncated, noncanonical, wrong-width and wrong-shape controls test the independent fixture model; they do not emulate target instructions.

## Results and limitations

`summary.json` reports 14 selected FDE extents, 8,535 selected bytes, 2,086 linearly decoded instructions, 409 control-flow records including 220 conditional transfers, 112 exact windows, 24 annotated decisions, nine selected error stores, 52 projected byte lanes, 20 relocation records and 23 call-site rows in four exception tables. These counts are derived from authenticated ELF bytes and this explicitly selected corpus; they are not whole-node function coverage or compared Rust bytes. The focused suite passed 24 tests with zero skips. The submission report records the final independent regenerations and repository checks.

No full-scope milestone is requested: the `evm` component remains 0/4, and the complete first component task of identifying private reth/revm fork boundaries and all state-transition inputs is not finished. Actual transaction-to-converter handoff, dynamic callback replacement, the live runtime seed, external allocator/database behavior, complete exception actions, target behavior, #115 and visor remain unresolved. The supplied PR inventory is a snapshot; public main and PR heads require a fresh submission-time ownership check.

Next question: find an unowned caller or data handoff connecting a recovered signed transaction to the existing converter, and independently validate the resulting recipient and access-list preparation under a separately authorized target-grounded protocol.
