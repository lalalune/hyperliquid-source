# RE-017: serialize the node 115 state-root reduction tree

This packet establishes the selected encoding of a state-root reduction tree and follows its 32-byte result into a nonfull history node, including the selected serialization and allocation failure boundaries.

- Component ID: `abci`; RE-017, connected to the RE-009 state-root question.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: main `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; navigation-only reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference source is not copied or treated as evidence.
- Claim status: observations are bounded #115 bytes, relocation, FDE/LSDA and selected control-flow records; the preimage model and cross-packet pointer joins are conditional inferences. Actual execution, a complete hash algorithm and all reachable inputs remain unresolved.
- Scope included and excluded: the nonempty or empty vector-result route, its row/index/leaf/nested writers, selected buffer and error branches, and the enclosing digest-result handoff, and selected nonfull history-node insertion. The process entry, other block actions, all state mutations, all reducer/serializer alternatives, runtime dispatch and complete begin/action/end-block component scope are excluded.

## Reproduce

From the repository root, with the authenticated #115 artifact and the shared repository parsers present:

```sh
python3 tools/abci_root_tree115.py --out research/work-items/RE-017-abci-root-tree-115
python3 -m unittest tests.test_abci_root_tree115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
mkdir -p work/re017-root-tree-tmp
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_root_tree115.py --out work/re017-root-tree-tmp/one
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_root_tree115.py --out work/re017-root-tree-tmp/two
diff -r work/re017-root-tree-tmp/one work/re017-root-tree-tmp/two
diff -r -x README.md -x MANIFEST.sha256 work/re017-root-tree-tmp/one research/work-items/RE-017-abci-root-tree-115
(cd research/work-items/RE-017-abci-root-tree-115 && sha256sum -c MANIFEST.sha256)
```

Use fresh output directories. The historical input is optional and is separately authenticated; it does not change the generated #115 records:

```sh
python3 tools/abci_root_tree115.py --historical references/can1357-hl/bin/hl-node-mainnet-new --out work/re017-root-tree-tmp/historical
diff -r work/re017-root-tree-tmp/one work/re017-root-tree-tmp/historical
```

Python 3.12.3 on Linux x86-64 was used. The tool imports the repository's `tools/elf_index.py` and `tools/fde_extents.py`, verifies the full input digest before output, reads file-backed ELF bytes directly, and rejects `SHT_NOBITS` mappings. It makes no subprocess calls and never executes a captured binary. GNU objdump 2.42 was used only for manual inspection; its text is not an input to the generator or tests. For example, a human can inspect the selected array writer with:

```sh
objdump -d --start-address=0x41444a0 --stop-address=0x414471e artifacts/node/115/hl-node
```

Output hashes are in `MANIFEST.sha256`; the generated files contain no disassembler text. Reproduction has no network or chain side effects.

## Evidence

Coordinates below are linked ELF virtual addresses before rebasing; the generated files also give file offsets, exact bytes and full selected unwind-range hashes. Every selected FDE is checked against the unwind header and is disjoint from the other decoded FDEs. An FDE range is unwind metadata, not a source-level function boundary or a complete control-flow census. The selected transfer sites are fixed byte patterns, not a general x86 disassembly pass.

### Prior boundaries and the new route

The already proposed loader packet `RE-017-abci-loader-handoff-115` (PR #2047) pins the #115 `state.rs:123:37` Location at `0x64767a8` and the surrounding loader handoff. The proposed `RE-017-abci-expanded-result-115` (PR #2243) relates a loader-fed owner to a selected block result under its stated pointer, dispatch and alias assumptions. The proposed `RE-017-abci-block-root-115` (PR #2107) supplies the separate begin/item/end route, its capture slots, the reducer `0x141a250`, the outer digest function `0x41c5140`, and the leaf-only formatting observation. Their functions, previously established calls and GOT entries are **context**, not newly owned functions in this packet. The old history wrapper and insertion FDEs are contextual boundaries; the two callees below are selected as new ranges.

The existing capture setup initializes 59 slots. On the prior normal status path the reducer traverses 24-byte children, skips the sentinel and the selected child-result tag 2, and retains the original slot position in each emitted row; this conclusion assumes the slot array and its length have not been changed by an intervening alias. The previously unexamined **vector-result** branch at the digest boundary then calls the new array writer. The checked contextual windows show the digest input and the later end-selector call that passes the resulting 32-byte buffer to the existing history boundary. They do not establish that the earlier loader and a particular runtime block used the same allocation.

| Selected #115 unwind range | Observation |
| --- | --- |
| `0x41444a0..0x414471e` | Reads the vector pointer and length, requests an array header on the selected normal path, traverses rows at stride `0x30`, and requires each row result to equal `0x8000000000000004`. It returns the first different result and conditionally releases a temporary buffer. |
| `0x41c7780..0x41c7b27` | In the direct selected mode, requests a two-element array, passes row `+0` to the unsigned writer, and selects a leaf at row `+9` or a nested vector at row `+0x10` using the byte at `+8`. A successful row reaches the pair finish function. |
| `0x41d2670..0x41d27ac`, `0x3d517e0..0x3d51a52` | The index wrapper calls the unsigned writer and forwards non-2 helper results. The writer selects the byte, 16-, 32- and 64-bit cases; the three wider bodies are included in `functions.json`. |
| `0x41acea0..0x41ad05e`, `0x41d3f60..0x41d4149` | The selected sentinel fast paths return `0x8000000000000004`. The alternate paths emit headers and copy buffered bytes; their capacity, overflow, helper-failure and cleanup branches are in `transfers.tsv` and `lsda.tsv`. |
| `0x41b9330..0x41b94ff`, `0x41771f0..0x417753c` | The separately selected buffered pair and nested-array routines use `0x92`, process rows in `0x30` steps and call their own index, string, recursion and finish helpers. A 32-bit count overflow reaches a separate failure call. |
| `0x3d50540..0x3d50663`, `0x3d51450..0x3d517d5`, `0x41c6610..0x41c6824` | These distinct buffered-route helpers establish the selected array markers, unsigned markers and byte order, and the `0xd9` length-prefixed leaf string. |
| `0x41acd70..0x41ace9a`, `0x41d4150..0x41d4294` | These finish helpers return the same selected success sentinel in their direct case and include buffer-copy, growth, cleanup and unwind boundaries. |
| `0x51f32f0..0x51f3414` | From the existing history-insert boundary, this adapter dispatches a non-null cursor to `0x4c5f1b0`; its null-cursor branch allocates and initializes a new node. Both successful branches increment the history count. |
| `0x4c5f1b0..0x4c5fda6` | A node with fewer than 11 entries takes an append or overlapping shift path, stores a qword key and the 32-byte input value, increments its 16-bit count, and returns a selected result triple. A full-node path requests another node and has a separate allocation-failure edge. |

The former array-header helper `0x3d50270`, marker packer `0x3d52310`, leaf string writer `0x41c6110`, and hex formatter binding are established context from earlier packets. Their relevant target bytes are checked as contextual windows; their FDEs and slots are not counted as newly selected functions. The previously bound formatter, reducer and digest slots at `0x64e4d08`, `0x64df500` and `0x64e7820` are rechecked as context against their respective relocation targets `0x2eabb50`, `0x141a250` and `0x41c5140`. The checked data alphabet is `0123456789abcdef`. Context windows also preserve the first-byte and repeated high/low-nibble lookups in the formatter, and the direct string length store and payload-copy boundary; these remain prior-owned functions.

### Selected normal byte model

For a vector whose count fits 32 bits, whose writer mode takes the recorded direct route, and whose helpers return normally, the outer header and each 48-byte row have the following byte shapes. The root capture count 59 bounds its own selected row indexes to `0..58` if its input length is preserved. Other nested inputs are not assumed to have that bound.

| Quantity | Bytes on the selected normal-capacity path |
| --- | --- |
| Array length `0..15` | One byte `0x90 | length`. |
| Array length `16..65535` | `dc`, then the length in two big-endian bytes. |
| Array length `65536..0xffffffff` | `dd`, then the length in four big-endian bytes. |
| Each row | Array marker `92`, an unsigned index, then its selected child value. |
| Unsigned index `0..127` | One byte containing the index. |
| Unsigned index `128..255` | `cc`, followed by one byte. |
| Unsigned index `256..65535` | `cd`, followed by two big-endian bytes. |
| Unsigned index `65536..0xffffffff` | `ce`, followed by four big-endian bytes. |
| Larger unsigned index through `0xffffffffffffffff` | `cf`, followed by eight big-endian bytes. |
| Leaf | `d9 42`, ASCII `0x`, then 64 lowercase hexadecimal characters for the 32 bytes beginning at row `+9`. |
| Nested child | Recursively serialize the vector triple beginning at row `+0x10`. |

The `tree_preimage` function is a synthetic model of this subset, not recovered Rust or a captured runtime output. For example, an empty vector models as `90`. A one-row vector with index zero and a zero-filled leaf begins `91 92 00 d9 42 30 78`, followed by 64 ASCII zero characters. The focused tests also check sparse indexes and a nested row. The model deliberately rejects counts outside its 32-bit scope; the target has a separate deferred-buffer path for a wider count, so this model restriction is not a claim that the target rejects such a count.

For the normal canonical row tags, both selected writer families use the same leaf/nested distinction. Their machine tests differ on noncanonical bytes: the direct pair writer branches to nested on any nonzero byte at `+8`, whereas the buffered pair writer tests for exactly 1. For example, a synthetic tag 2 takes different branches. No claim is made that such a row is reachable from the reducer. A reconstruction must not silently treat the two machine tests as identical for malformed input.

### Failure and result delivery

| Condition | Observed selected consequence |
| --- | --- |
| Array-header helper returns a word other than 2 | The array writer constructs an output triple beginning with `0x8000000000000000` and forwards the two helper-result words. It does not enter the regular row loop on that branch. |
| Index, nested child or string result differs from `0x8000000000000004` | The pair writer forwards the selected result triple; the array writer forwards the first non-success row and performs its conditional temporary-buffer cleanup. |
| A two-byte unsigned encoding reaches a full buffer after writing `cc` | At `0x3d51925` the marker is stored and at `0x3d51934` the length is advanced before the growth call. Its failure edge reaches the non-2 return at `0x3d5194c`. A partial prefix can therefore exist in the local buffer before propagation; the record does not assume rollback. |
| Enclosing vector serializer returns a result other than `0x8000000000000004` | In the prior digest boundary, the selected error continuation stores 32 zero bytes to its output. It does not take the recorded digest-update/finalize path. On the enclosing selector's normal return, the output-buffer address is passed to the existing history boundary without an intervening conditional transfer. |
| Exception during a selected call | `lsda.tsv` records the bounded call-site encodings and landing addresses; `unwind-witnesses.tsv` maps the selected calls to them. Action numbers are retained without claiming the full unwind action semantics. A missing LSDA entry is not evidence that an error cannot occur. |

The `cc` example requires an index from 128 through 255. It cannot be the index of an outer row from the captured 59-slot root if that length is preserved; a nested index in this range or a different input would be needed, and either occurrence remains unproven.

The last handoff assumes normal ABI-preserving returns and no intervening writes through aliases. The zero-filled output is a static branch observation, not a claim that an actual node took the branch or persisted that value.

### Selected history mutation

The already-owned end selector passes the 32-byte output pointer and its height word through `0x5a03fa0` to `0x4dd45c0`. Context windows preserve argument movement, the selected tree-mode search, and the call at `0x4dd49ba`; the new adapter and node-writer ranges are listed separately. The parent retains the input key and output-buffer pointer across that call under normal ABI and no-alias assumptions. The history tree representation, search validity and caller reachability are not fully proved.

Let `n` be the 16-bit node count at node `+0x1c2`, and `i` the selected cursor index. For the non-null path, assume `0 <= i <= n`; the first two cases additionally require `n < 11`. The table preserves the selected write order:

| Condition | Selected writes and boundary |
| --- | --- |
| `i == n` | Write the height/key qword at node `+0x168 + 8*i`, then copy the 32-byte input into node `+32*i`, and store `n+1` at node `+0x1c2`. |
| `i < n` | Call through the `memmove` symbol slot for `8*(n-i)` key bytes, write the key, then call through the same slot for `32*(n-i)` value bytes before writing the 32-byte value and count. The result assumes the dynamically bound symbol follows its named semantics. |
| `n >= 11` | Take the distinct split path; it requests `0x1c8` bytes. On a null allocation, control reaches the allocation-failure slot. The remainder of split, cleanup and any error-handler behavior are unresolved. |
| Null cursor | Request `0x1c8` bytes, initialize the new node and store its pointer in the history object, place the key and 32-byte value in its first slot, and advance the local node count. A null allocation calls the same failure slot before these adapter stores. This machine branch is recorded for completeness: the earlier history representation guard can change the representation when the count is small, so a valid runtime route to this particular branch has not been established. |

After the selected nonfull helper returns, the adapter increments the qword at history-object `+0x18` with a wrapping x86 increment and returns its location tuple. The count increment has no local saturation branch; overflow reachability is unknown. The byte-valued history insertion result, the selector's later decisions and retention behavior are separate prior boundaries. Under all stated path, pointer, normal-return and alias assumptions, even the earlier zero-filled serialization-error output can be the 32-byte value supplied to these stores; no runtime occurrence or persistence is claimed. `constants.json` records the node offsets and checks the `R_X86_64_GLOB_DAT` `memmove` symbol binding directly from the ELF; this commonly used GOT slot is a dependency, not new slot ownership.

### Release-specific anchor

The earlier #94 lead is bound to SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`: its record at `0x56dfbf8` names `state.rs:107:37`, its reference is at `0x3273856`, and its separate result comparison at `0x3273871` compares with 2. Those historical observations are in the earlier evidence at commit `d3bc12bdf4cb324ee659a2c79fdcf4e2f8eba1b0`. Independently, #115 uses Location `0x64767a8`, reference `0x3c1352f`, line 123 column 37, and a comparison with 1 at `0x3c1353b`. The optional check authenticates and validates the #94 bytes separately; it does not put #94 addresses, layouts or behavior into #115 results. No behavioral equivalence between releases is asserted.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo graph, compiler/linker options, two-build comparison, normalization masks, helper closure and whole-ELF comparison: not yet measured. The Python model is an analysis control and its synthetic examples are not differential tests against the captured node.

## Results and limitations

`summary.json` records 18 selected FDEs, 69 selected windows, 24 contextual windows, 169 selected transfers, 40 LSDA call-site rows and 67 call witnesses, 47 of which are covered by a recorded LSDA row. These are explicitly chosen records, not coverage denominators. The focused suite passed 30 tests with zero skips, including input hash and missing-file rejection before output; corruption of every selected FDE body and transfer displacement; encoded FDE/index and LSDA damage; NOBITS, ambiguous and out-of-range mappings; bad Location and relocations; array and unsigned-width boundaries; canonical and noncanonical tag controls; ordered, sparse and nested synthetic preimages; the 59-slot index bound; history-node stores and allocation-failure branches; a corrupted dynamic symbol and relocation; and the selected failure handoff. Two regenerations under distinct hash seeds and time zones matched byte-for-byte with binutils absent from `PATH`; the separately authenticated optional #94 check produced the same #115 output. Artifact digest/signature verification and the catalogue check passed.

The upstream loader-to-owner join and the final output handoff depend on prior pending packets, normal calls and no conflicting alias writes. The result-byte model covers selected normal paths only; it does not establish all alternate writer flags, all malformed representations, full history search/splitting/retention and helper effects, all reducer children, dynamically selected digest implementations, the complete digest value, a real block transition or binary equivalence. No component gate is advanced. The complete repository test suite, captured binaries, hosted CI and container were not run.

Next question: bind the selected digest update/finalization implementation to a licensed source revision and prove its portable and dispatched paths over the serialized tree, then establish the complete history search, split and retention invariants and trace other block-result consumers without re-owning the existing functions.
