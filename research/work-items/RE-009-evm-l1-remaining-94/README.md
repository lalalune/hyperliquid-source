# RE-009: EVM-to-L1 remaining ledger in state serialization and app-hash input

Node #94 binds `user_to_evm_to_l1_wei_remaining` to Exchange offset `+0x3a50`, and to `+0x1f30` in a separately compiled state context, and serializes each as address/unsigned-value pairs, allowing a reconstruction to represent this previously unnamed state-hash input and distinguish its bare hash input from its named state-serialization form.

- Component ID: RE-009, storage/state roots (`l1/abci/state.rs` and Exchange state).
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` was a lead, not implementation authority.
- Claim status: observation for the name, field offset, code windows, calls, memory operands and selected control flow; inference for the map's business meaning and serialization labels; unresolved for tree comparator, complete reader and cross-release compatibility.
- Scope included and excluded: the named writer, tree-to-pair collection, MessagePack-shaped and JSON-shaped writers, selected propagation and allocation guards, and the linkage to the previously mapped hash input. The general Exchange serializer, the hash closure body, shared formatting and integer helper bodies, state mutations, all readers, an actual database fixture, other releases and whole-component coverage are excluded.

## Reproduce

From the repository root with Python 3 and the standard library. `tools/elf_index.py` supplies section parsing and `tools/fde_extents.py` supplies CIE/FDE parsing. The input is read once into immutable bytes and its SHA-256 is checked before parsing. Only file-backed sections are eligible for reads; SHT_NOBITS is refused. No program parses binutils output, invokes external tools or executes the target.

```sh
python3 tools/evm_l1_remaining94.py --out research/work-items/RE-009-evm-l1-remaining-94
python3 -m unittest tests.test_evm_l1_remaining94
(cd research/work-items/RE-009-evm-l1-remaining-94 && sha256sum -c MANIFEST.sha256)
```

`records.json`, `windows.tsv`, `examples.tsv` and `count-headers.tsv` are generated. The latter two contain **synthetic model inputs and outputs**, not captured node execution or a live fixture. Selected instruction windows are exact byte patterns; all addresses, section offsets, immediates, table bytes, branch displacements, FDE records and call targets in the generated output are read from the admitted ELF. No instruction operand is normalized. The study used CPython 3.12.3 and GNU objdump 2.42, the latter only for human inspection. A second run with no binutils on PATH also passed. Separate regenerations under different hash seeds and time zones were byte identical.

## Evidence

All addresses are linked ELF virtual addresses; FDE ends are exclusive. The FDE extents below are unwind-described intervals, supported by the selected entry and control-flow windows; they are not a complete census of functions or a claim that every exit and indirect call is closed.

### Binding and ownership

| Observation | Evidence |
| --- | --- |
| Named field | The wrapper at `0x27b4450` refers to the 31 bytes at `0x3ef66c`. Its named branch passes those bytes to the string writer, then tail-jumps to `0x25ebac0`. A zero mode byte bypasses the name. A name-write result other than 2 takes the failure branch. |
| Exchange offset | The site `0x275b67a` forms `state+0x3a50` and passes it to the named wrapper. The separately formatted JSON path at `0x275c07b` supplies the same offset, name and length to `0x295aeb0`. These short contexts are included to bind the new callees; their larger existing callers are not analyzed as new functions. |
| Hash input | The earlier `RE-009-app-hash-builder-94` packet assigns row 31 to state offset `+0x3a50`. The call window at `0x281ac15` initializes writer bytes `00 04 00 01 00` and calls `0x25ebac0` directly. Thus this call feeds the **map value without the outer field name** into the existing row-hash path. The previous packet, not this one, establishes the hash operation and the job's capture. |
| Second state context | At `0x3753e0a`, a different caller passes its base `+0x1f30` to `0x3798960`, which reads the same 31 bytes at `0x598aec` and tail-jumps to `0x360b8f0`. The JSON context at `0x37533bb` passes base `+0x1f30` and the same name to `0x3c87920`. Only selected corresponding paths are checked; they are not whole-body identity claims. |

The older `bridge-evm-block-step-94` packet listed the field name but left its offset unbound. `vaults-subaccount-spot-transfer-94` identified `+0x3a50` as a per-address u64 map updated on a USDC transfer path, but did not establish its state-field name or wire representation. Together with the new offset/name binding, those observations make the field's transfer-related role plausible; they do not establish its complete invariant or unit independently. The two offsets apply to their own caller contexts; this packet does not determine why their surrounding layouts differ or permit substituting one displacement for the other. The existing `bridge-state-json-94` call-chain evidence connects both JSON caller bodies to state-file routing; this packet does not reanalyze that routing.

### Writer path and layouts

| Stage | FDE extent | Selected behavior |
| --- | --- | --- |
| Named wrapper | `0x27b4450..0x27b44ac` | Optional name write, then tail-call the value writer. |
| Map wrapper | `0x25ebac0..0x25ebb89` | Null/non-null tree root initializes an iterator; collect pointers, write the array, free a nonempty temporary allocation. |
| Tree pointer collection | `0x2566dd0..0x25670c0` | Allocate `16 * count` bytes after a shift/limit guard. Each result row has two pointers: one to node `+0x60 + 20*i`, one to node `+0x08 + 8*i`; node count is read at `+0x13e`. The empty case uses a non-null sentinel and zero count. |
| Array | `0x1e15cb0..0x1e15f3b` | Calls the array-header helper with the count, then advances through 16-byte pointer pairs and invokes the pair writer. A count with nonzero high 32 bits enters a separate buffered path. |
| Pair | `0x1dd3870..0x1dd3a14` | In the non-buffered path, asks for a two-element sequence, writes the first pointer as an address, then writes the second pointer's u64. Both child failures join an error-copy/cleanup path. |
| Buffered pair | `0x1e025a0..0x1e026e8` | The alternate local writer path has an explicit `0x92` byte store and separate key/value calls. |
| Corresponding copy | `0x3798960..0x37989bc`, `0x360b8f0..0x360b9b9`, `0x3bcb9f0..0x3bcbcde`, `0x3203ee0..0x320416b`, `0x31ca400..0x31ca5a4` | A second named wrapper reaches its own collector, array and pair functions; checked windows show the same pointer-pair stride and corresponding key/value failure joins. Helper targets and unselected instructions may differ. |

The collector follows the container's traversal; the comparator and whether its order is lexicographic over all 20 bytes have not been established here. The model accepts rows in caller-supplied order and never sorts them.

For the first writer path, the address helper's call site supplies input length 20, capacity 42 and mode zero through RELATIVE slot `0x5773120`. The already documented `RE-005-prefixed-hex-rust-94` evidence identifies that slot's target as the lowercase prefixed-hex primitive. Hence the conditional modeled address is `0x` followed by 40 lowercase digits; this packet records the call-site bytes and slot, rather than claiming a new analysis of the shared formatter.

The unsigned writer selects positive fixint through 127, `cc` for 128..255, `cd` with two big-endian bytes through 65535, `ce` with four through `2^32-1`, and `cf` with eight thereafter. The checked code windows include the comparisons, marker stores and byte reversals. On this selected path a normal row has the MessagePack-shaped form `[address_text, unsigned_value]`; the outer value is an array of those pairs. For example, the synthetic zero-address/value-128 model starts `91 92 d9 2a`, followed by the 42 ASCII address bytes and `cc 80`. This example is not a native execution.

### JSON path and failure branches

`0x295aeb0..0x295af47` passes the supplied field to a shared field writer and then calls `0x25df960..0x25dfa26`. The latter uses the same pointer collector and calls `0x2919ea0..0x291a582`: its checked stores open and close an outer array and each nested pair, pass 20 address bytes to `0x27e2690`, the quoted-hex writer previously analyzed in `bridge-state-json-94`, and pass the value qword to `0x27869f0..0x2786b32`. The latter's checked 200-byte digit table and arithmetic support an unsigned decimal interpretation. Whitespace and complete JSON framing depend on surrounding writer state and are not modeled. In the second context, `0x3c87920..0x3c879b7` calls `0x3612a80..0x3612b46`, which reaches the second collector and `0x3c767b0..0x3c76e32`; selected windows show an outer array and 16-byte pointer-pair traversal. This does not establish whole-body equality with the first JSON implementation.

| Condition at checked site | Static branch/result |
| --- | --- |
| Named-mode byte is zero | Branch at `0x27b445f` reaches `0x27b4481`, bypassing the field-name write. |
| Name write does not return 2 | Branch at `0x27b447f` reaches `0x27b4491`, which stores the error result. |
| Tree root is zero | Branch at `0x25ebad5` reaches `0x25ebb0c`, initializing an empty traversal. |
| Array or pair header write fails | The conditional branches at `0x1e15d25` and `0x1dd3902` reach error result construction at `0x1e15dde` and `0x1dd39be`. |
| Array count exceeds 32 bits | The branch at `0x1e15d06` reaches `0x1e15e02`, which requests a separate 128-byte buffer; allocation failure is not modeled. |
| Collector allocation returns null | The branch at `0x2566e2f` reaches `0x2567093`; the packet records the edge without interpreting its full destination. |
| Pair key or value child fails | `0x1dd3943` and `0x1dd395c` both reach `0x1dd396d`; corresponding branches in the second copy join at `0x31ca4fd`. |
| Collector's scaled length overflows or exceeds the checked allocation limit | `0x2566dd8` tests the shifted count and `0x7ffffffffffffff8`; its failure calls an allocation-failure edge. |
| JSON field writer returns tag 1 | `0x295aec4` reaches `0x295af10` and the second copy branches from `0x3c87934` to `0x3c87980`. After a value write, zero returns through `0x295af05` and a nonzero result returns directly. The full semantics of tag 1 are not established here. |

These are selected edges conditional on the checked instructions and callee returns. They do not establish every allocation error, panic, indirect call or malformed-state behavior.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Compiled comparison, masks, complete helper/data closure, differential execution and real state fixtures are not yet measured. Eleven focused unittest methods pass with zero skips, including altered ELF digest, instruction windows, branch opcodes and displacements, field bytes, duplicate and wrong-type RELATIVE relocation, out-of-range and NOBITS addresses, modeled count boundaries, and unsigned-value boundaries. Mutation controls exercise the static checks or the local model, not the node's runtime behavior.

## Results and limitations

The generator records 18 FDE-described intervals, 18 selected direct call or tail-call edges, 16 conditional branches, 83 instruction windows and the two fixed alphabets. It models 10 synthetic amount cases and 7 synthetic array-count headers. These are scoped denominators, not function coverage or component completion. No RE-009 progress gate is requested. Snapshot-version compatibility, reader duplicate handling, byte-for-byte hashing of a real state, comparator order, successful allocation guarantees, all format modes, and the complete hash closure remain open.

Next question: trace the non-overlapping field reader and its duplicate-key/invalid-address paths to determine whether it reconstructs this array without changing traversal order.
