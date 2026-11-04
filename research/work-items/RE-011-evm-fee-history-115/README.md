# RE-011: node 115 fee-history-shaped RPC adapter

The selected node #115 adapter combines a five-block request cap, a state-backed
height lookup, a bounded history scan, weighted reward selection, and a
JSON-RPC result/error serializer; these observations constrain an independent
Rust implementation of that path, while the external method-name binding and
several helper semantics remain unresolved.

- Component ID: `evm-rpc` (RE-011; associated `evm` dependency observations).
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository snapshot
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. The separately recorded public
  `upstream/hyper-evm-sync` pin is `d0945c699d9d4774417f4355b10744e7cd420df8`;
  its presence in `provenance/sources.json` does not establish that those
  contents were linked into the node.
- Claim status: static byte observations and explicitly labeled local models;
  function names and the fee-history association are inferences, not recovered
  symbol names.
- Scope included and excluded: the registration routine given a caller-supplied
  key, its callback and future, selected state-read and storage-task paths,
  reward selection, and result/error serialization. The common method-table
  builder belongs to a separate active packet and is excluded. This record does
  not independently establish which external method key selects this routine.

## Reproduce

Run from the repository root with the authenticated `artifacts/node/115/hl-node`
installed. These are static reads only. The collector uses Python standard
library modules and the repository's `tools/elf_index.py` and
`tools/fde_extents.py`; it verifies the complete input SHA-256 before parsing or
writing. It never runs the input binary or another program. Development used
CPython 3.12.3 on Linux x86-64; the optional human disassembly below used GNU
objdump 2.42. The two output directories in this example are relative, ignored
workspace locations.

```sh
python3 tools/evm_fee_history115.py --out work/evm-fee-a
python3 tools/evm_fee_history115.py --out work/evm-fee-b
diff -r work/evm-fee-a work/evm-fee-b
for f in work/evm-fee-a/*; do cmp "$f" "research/work-items/RE-011-evm-fee-history-115/${f##*/}"; done
python3 -m unittest tests.test_evm_fee_history115
(cd research/work-items/RE-011-evm-fee-history-115 && sha256sum -c MANIFEST.sha256)
```

For visual review only, `objdump -d -M intel --start-address=0x2a20078
--stop-address=0x2a200b4 artifacts/node/115/hl-node` displays the percentile
loop. Objdump is not a collector or test dependency and its text does not feed
any generated record. All checked artifact hashes are in `MANIFEST.sha256`.

## Evidence

All addresses are linked ELF virtual addresses (VA), not process addresses;
file offsets are zero-based. The selected FDE starts, exclusive FDE ends, raw
FDE/CIE records, unwind index entries, file offsets and body hashes are in
`functions.json`. Each selected function is checked against both the decoded
FDE and the `.eh_frame_hdr` entry. An FDE is not claimed to prove a complete
source function or all control-flow edges. For example, the history future
starts at VA `0x2a1fd20` (file offset `0x2a1ed20`) and its decoded FDE ends
exclusively at `0x2a21c6d`. Data in file-backed sections is translated by the
shared ELF parser; `SHT_NOBITS` never supplies file bytes.

The complete set of *selected* observations is in `summary.json`: 28 FDEs,
133 fixed instruction windows, 25 direct calls, 10 RIP-relative indirect
calls with relative relocations, three imported-symbol calls, 82 conditional
branches, 44 entries from ten jump tables, six selected
RELATIVE descriptor relocations, 23 referenced literals, one unbound candidate
method literal, and five
Location-shaped records. These are reviewable selections, not a denominator for
whole-node coverage. Raw bytes, x86 relative displacements, instruction VAs,
relocation records, and table entry targets are retained in the neighboring JSON
and TSV files; none comes from parsing disassembler output.

| Stage | Selected evidence | Established local handoff |
| --- | --- | --- |
| Registration | `0x2d024e0`, descriptor `0x6450758` | The routine forwards a supplied key and a descriptor. Descriptor slots `0x6450778` and `0x6450780` each relocate to callback `0x2d032b0`. The supplied key's value is not established here. |
| Callback | `0x2d032b0`, table `0x6450a48` | Constructs a `0x90`-byte future; slot `0x6450a60` relocates to poll function `0x2d0bee0`. |
| Input and future | `0x2d0bee0`, `0x2d10a60` | The selected input branches and error diagnostics name `block_count: U64`, `newest_block: BlockNumberOrTag`, and optional `reward_percentiles: Option < Vec < f64 > >`. The constructed `0x2f8`-byte future uses table `0x6445590`, whose slot `0x64455a8` relocates to `0x2a1fd20`. |
| Height | `0x2a1fd20` -> `0x2a21c70` -> `0x2a3eb60` | Selector 5 uses the attached value; other selectors call the height resolver. The resolver uses the diagnostic label `eth_blockNumber`. On selected normal paths its state helper reads a qword through `[context+0xb00]`, then offset `0x39d8`, under a local lock protocol and returns it. |
| Storage task | `0x2a1fd20` -> `0x2a06530` -> `0x2a0acc0` -> `0x2b3daa0` | A typed lookup precedes the inclusive range future. Its task object stores table `0x64494c0`; selected RELA entries bind its run slot to `0x2b230d0` and poll slot `+0x18` to `0x2b16880`. |
| Task and range | `0x2b230d0` -> `0x2698000` -> `0x26990d0`, `0x231fef0`, `0x26985d0`, `0x231bc30` | The task copies captured inputs, calls the range iterator, transfers its result, and the reader polls the task. The range iterator builds two keys, obtains and walks an iterator, decodes candidate values, and projects selected value records. |
| Success/error | `0x2d0bee0` -> `0x22d7a70` -> `0x260b360` -> `0x22e0850` or `0x260cb30` | The envelope chooses either the history-field serializer or the error serializer. The latter emits the `error`, `code`, `message`, and conditionally `data` labels on its selected continuation. |

The selected descriptor edges are relocations, not presumed dynamic dispatch.
The task constructor puts `0x64494c0` in the allocated object's table field;
`0x2e4aa1a` calls the `+0x18` slot after reading that field. The task runner's
direct call to `0x2698000` and its result transfer are distinct observations.
The ten selected iterator and readiness calls in `indirect-calls.tsv` include
instruction bytes, slot bytes, RELA records, and first-level addends. The
iterator wrappers themselves make additional virtual calls; concrete instances,
underlying database implementation, scheduling and concurrent behavior are not
resolved by those first-level targets.

`external-symbols.tsv` decodes three separate `R_X86_64_GLOB_DAT` entries and
their undefined ELF dynamic symbols directly: the selected concatenation call
references `memcpy`, prefix equality references `bcmp`, and the key-bound
comparison references `memcmp`. These are link-time names, not proof of the
implementation supplied by a running process. The shared `bcmp` import slot
also appears in the separate permit-routing packet; the range-scan call site
and its owning FDE are different, and this packet excludes that router's code.

### Input, state, and error decisions

The following table describes selected local branches; it is not a complete
parse grammar or exhaustive CFG. Internal tags are not automatically wire codes.

| Condition and branch VA | Local result or continuation |
| --- | --- |
| Missing required array input, `0x2d0c191` to `0x2d0c201` | Constructs the bytes `No more params`, passes the message `Invalid params` and signed code `-32602` to `0x25cd880`. That constructor records class 5 and the supplied code. |
| Error response, `0x260b489`, `0x260cb30` | The error arm selects a table entry from class; entry 5 leads to immediate `-32602`. `error-code-map.tsv` includes all eight selected table entries. The data field is skipped on the local first-word-equals-2 branch at `0x260ccef`. This is serializer evidence, conditional on the error object reaching it and successful writes; no network response was captured. |
| Count zero, `0x2a1fe6b` | Takes the empty-result construction before the optional percentile checks or state lookup. |
| Percentile vector present, `0x2a20053` through `0x2a200b2` | Length greater than 100 takes internal tag `0x17`. For each *adjacent pair*, `UCOMISD` rejects when the preceding value is ordered above 100.0 or above the next value. The final element is not separately compared in this loop. A length below two performs no pair comparison. |
| Positive count and selector, `0x2a1fe8b` through `0x2a1fed0` | Caps the count at 5. Selector 5 uses its attached qword directly. Selector 4 clears the stored selector word and changes the capped count to `max(count - 1, 0)`, then calls the resolver; every selector other than 5 reaches the resolver. Numeric selector names are unresolved. |
| Resolved height, `0x2a1fefd`, `0x2a200c8`, `0x2a201aa` | Height `2^64 - 1` takes local tag 9 on increment overflow. Otherwise let `end_exclusive = height + 1`, `n = min(adjusted_count, end_exclusive)`, `oldest = end_exclusive - n`. The subsequent unsigned range-order test takes tag 9 when `oldest > height`. |
| Typed lookup, `0x2a06551` through `0x2a066bc` | Empty/null table, failed lookup, or selected identity check failure produces first output word `0x8000000000000000` and byte `0x25` at output offset `0x10`; the history future copies this result. Key words are recorded in `constants.json`; the registered type itself is unknown. |
| Inclusive reader, `0x2a0ad1c` through `0x2a0ad42` | Computes `end - start + 1` only if unsigned subtraction and increment are valid; otherwise selects tag 9. A task poll result of 2 produces local pending tag `0x29` and state 3. A successful returned vector with the expected length takes tag `0x28`; the mismatch cleanup selects tag 9. A separate completed-error path selects `0x27`. |
| Storage iterator, `0x2698024`, `0x26980f0`, `0x2698233` to `0x2698348` | Reversed bounds take the empty path. A null iterator follows the selected failure call and `UD2`. Invalid iterator, null key/value, short key, changed prefix, or reaching the selected other bound exits the scan. A wrong nonempty suffix length or a decode failure is skipped through the advance path; see the actual branch targets in `branches.tsv`. |
| Result fields, `0x22e08ce` to `0x22e0aab` | `baseFeePerGas`, `baseFeePerBlobGas`, and `blobGasUsedRatio` are each omitted when their tested qword at input offsets `0x10`, `0x40`, and `0x58` is zero. `reward` is omitted when the word at `0x60` is the signed-minimum sentinel (`NEG; JO`). `gasUsedRatio` and `oldestBlock` are attempted on the normal continuation, subject to preceding serializer errors. |

For unordered `UCOMISD`, both the local `JA` rejection and the subsequent
`JBE` condition have the x86 flag behavior recorded in the synthetic test. This
is an instruction-level observation only: it does not establish that a JSON
parser accepts a non-finite number. `synthetic-cases.json` records modeled
boundary cases, including an isolated last element, a descending pair, and the
zero-count ordering; these are not target executions.

### Store keys, task state, and reward selection

The range-key builder `0x26990d0` copies a dynamic prefix, allocates eight
bytes, byte-swaps the input qword, and passes the prefix and qword as two
segments to `0x231fef0`. That helper adds segment lengths with an overflow
branch and copies the segments in order into the output buffer. The scanner
checks the candidate prefix,
requires an eight-byte suffix for the selected decoded path, and byte-swaps
the loaded suffix back to a qword. The prefix bytes and their semantic table
name are not recovered. Its retained entries have stride `0x3e8`; the
projection at `0x231bc30` advances by that stride and copies the following
`0x3e0` bytes. The history assembler consumes `0x3e0`-stride rows. The value
decoder's selected failure result is tag 2 with payload 4 and reaches the skip
path, but the underlying codec and all variants remain unknown.

The task gateway initializes its local result to 2 and calls the stored table's
`+0x18` entry. For the selected table, the join poller calls a readiness helper;
when it returns zero the initialized result stays 2. When nonzero, the poller
checks and transfers the task output. The outer and inner futures each have
separate four-entry top-level and nested jump tables; pending continuations
store state 3, completion stores state 1, and selected unwind cleanup stores
state 2. `state-tables.tsv` preserves the actual table entries instead of
assuming state labels for all paths. No scheduling order or memory consistency
claim follows from this static mapping.

For a present reward option, the selected history code consumes a helper-built
vector and, for at least two rows, invokes a sorting helper. Its comparison and
the construction of those rows are not reconstructed. *After that helper*,
the code selects from 32-byte rows with an eight-byte weight at offset `0x10`
and a 16-byte payload at offsets `0x00` and `0x08`. If there are no rows, it
appends one zero payload per requested percentile. Otherwise it starts at the
first row and keeps a forward-only cursor and accumulated weight. For each
percentile it computes the binary64 expression `percentile * total / 100.0`,
converts it to a saturating unsigned 64-bit threshold, advances while the
accumulator is below that threshold and the cursor is not at the last row,
and appends the selected 16-byte payload. `total` is separately loaded from
another helper-built 40-byte-stride vector; equality with the sum of selected
weights is not assumed. An overflowing weight addition follows the selected
failure call and `UD2`. The instruction constants for the conversion and the
frozen loop bytes are in `constants.json` and `windows.json`.

The synthetic reward model covers empty rows, exact thresholds, a zero initial
weight, a single row, cursor direction, and a corrupted/overflowing weight.
It models only the post-helper selection just described; it does not establish
the actual sort order, row construction, transaction semantics, or a complete
fee calculation. The blob-ratio path separately contains a binary64 divisor
of 786432.0; the complete base-fee and reward construction formulas remain open.

### Dependency and fork observations

`fork-paths.tsv` reports the first file-backed occurrence and raw `.rodata`
prefix count for 29 selected prefixes: eight `z_forks` entries, ten Alloy,
seven revm, two jsonrpsee, and the selected RocksDB and serde_json vendor
entries. These are string occurrences, not a dependency graph or an exhaustive
crate inventory. In particular, `z_forks/reth-rpc-eth-types/src/fee_history.rs`
is present; the selected adapter's parameter and output names make a
fee-history association plausible. The literal `eth_feeHistory` also occurs
in read-only data at `0x6023fc`, but this packet does not trace an edge from
that occurrence to the selected registration routine. The selected
Location-shaped records also
refer to `evm_rpc/src/evm_rpc.rs`, `evm_rpc/src/evm_store.rs`, and
`evm_rpc/src/reth_rpc_helpers_copied.rs`. Path strings do not prove upstream
versions, private modifications, linked crate boundaries, source line contents,
or a relationship to the public sync pin.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo dependencies,
compiler/linker flags, two-build reproducibility, and binary comparisons: **not
yet measured**. No bytes are transplanted into executable code: the fixed
windows are read-only evidence expectations. The Python models exercise only
selected branch and arithmetic semantics; they are not an implementation of
the target or an equivalence test. No helper closure, relocation normalization,
or whole-ELF comparison is claimed.

## Results and limitations

The collector generated 17 evidence files and the focused unittest suite passed
33 tests with zero skips. Controls include a changed input digest, selected
instruction and branch corruption, wrong indirect-call displacement and RELA
addend/type, a corrupted imported-symbol name, duplicate RELA slot, a jump outside its FDE, NOBITS and ambiguous
section mappings, invalid key suffixes, selector/count boundaries, and a
reward-weight overflow. Tests use synthetic cases and static bytes only. The
manifest covers this README and every generated evidence file; the collector
regenerates only the 17 evidence files.

The lookup's concrete type, selector names, exact method-key binding, all
unselected helper bodies, storage prefix, value codec, iterator virtual targets,
reward sorting and complete fee math remain unresolved. A byte observation or
successful test is not target execution, wire capture, Rust equivalence, an
exhaustive function map, or proof of the complete fork matrix. No `evm` or
`evm-rpc` component gate is requested; both remain 0/4. Next question: recover
the ordering comparator and the construction of the two reward input vectors,
and bind the final iterator vtable statically without overlapping the separate
method-router packet.
