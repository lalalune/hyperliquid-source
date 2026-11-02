# RE-009: request-budget state-root value encoding in node 94

This packet connects the request-budget table to app-hash job 16 and recovers the ordered, default-eliding encoding of its nine value fields, and identifies a matching reader with explicit duplicate-field and unknown-field paths.

- Component ID: RE-009 (storage and state roots; request-budget table)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference code is copied.
- Claim status: observation for the pinned bytes, selected edges, field literals, offsets and branch destinations; inference for the connection to the request-budget semantics and the small-sort ordering; unresolved items are listed below.
- Scope included and excluded: the low-lane job 16 capture, selected collection, small sort, pair/value writers enum field and compatible reader dispatch. Generic address formatting, date formatting, large-sort internals, reader defaults, other hash jobs and complete app-hash recomputation are boundaries.

## Reproduce

Run from the repository root with Python 3 and the standard library. The generator imports the repository's `tools/elf_index.py` and `tools/fde_extents.py`, verifies the complete input digest, and reads ELF bytes without executing the node or invoking binutils. It parses RELA and dynamic symbols with `struct`; all instruction conclusions use fixed byte windows and checked direct relative calls, rather than parsed disassembler output. SHT_NOBITS sections are excluded from file-backed address resolution. Output is independent of time and hash iteration order.

```sh
python3 tools/request_budget_root94.py --out research/work-items/RE-009-request-budget-root-94
python3 -m unittest tests.test_request_budget_root94
(cd research/work-items/RE-009-request-budget-root-94 && sha256sum -c MANIFEST.sha256)
```

The research environment used Python 3.12.3 on Linux x86-64; GNU objdump 2.42 was used only to inspect human-readable instructions. The files `functions.tsv`, `windows.tsv`, `calls.tsv`, `branches.tsv`, `fields.tsv`, `enum.tsv`, `presence.tsv`, `classifier.tsv`, `reader-dispatch.tsv` and `summary.json` are generated. The manifest includes their hashes and this README. Two separately generated directories were compared byte for byte. The generator writes only to its `--out` directory and does not access a network, keys or runtime state.

## Evidence

Addresses below are unrelocated ELF virtual addresses; offsets identify the indicated in-memory object. The selected function ranges are derived from `.eh_frame` FDEs and checked against the unwind index. They are unwind extents, not claims of complete CFG boundaries. `windows.tsv` preserves selected machine-code bytes; its contents are not disassembly.

### Capture and collection

The existing app-hash builder packet identifies 41 low-lane jobs and leaves their serializers open. Here `0x2756640` captures builder argument `+0x740`, and `0x2756d04` places that box beside vtable `0x56bdc38`. Its `+0x18` RELATIVE relocation resolves to thunk `0x1f6b260`, which calls closure `0x2819ad0`. At `0x2819b20` that closure calls `0x20296f0` with configuration `0x01000400` and byte `+0xc = 0`.

`0x20296f0` collects table entries through `0x256dd10`, sorts the resulting vector through `0x1fe87b0`, then emits it through `0x1e4a430`. Entries in that vector are two pointers at a 16-byte stride. The latter writer emits an array and calls `0x1dd8490` for each entry; that writer emits a two-element pair, delegates its key, and reaches the value writer `0x275ce60`. Errors from the array header, pair, field names and field values follow the recorded branches, instead of silently advancing to the next item.

In the sort arm for fewer than 21 entries, `0x1fe883a` supplies length 20 and the relocation at `0x576e488` names `memcmp`. The inspected insertion arm orders those 20-byte keys in ascending byte order. The code takes a different path at 21 entries; this packet does not establish its ordering. The key's complete wire representation is a helper boundary, so this is a statement about the key comparison, not a claim about every encoded key.

### Value fields and defaults

For the named serializer mode used by the captured closure, the fields are emitted in the following order. `fields.tsv` records each literal VA and the writer call sites. The value offsets are relative to the value itself; the prior request-budget study locates that value at bucket `+0x18`.

| Field | Value offset | Emitted when | Selected operation |
| --- | --- | --- | --- |
| `ln` | `+0x00` | word is nonzero | unsigned integer writer |
| `R` | `+0x08` | word is nonzero | unsigned integer writer |
| `C` | `+0x10` | word is nonzero | signed integer writer |
| `P` | `+0x18` | word is nonzero | signed integer writer |
| `t` | `+0x30` | three date/time words differ from the helper-produced epoch | date/time helper |
| `no` | `+0x20` | word is nonzero | unsigned integer writer |
| `f` | `+0x3d` | boolean is true | boolean byte |
| `r` | `+0x28` | word is nonzero | unsigned integer writer |
| `a` | `+0x3c` | enum tag is nonzero | enum string helper |

The header count is computed before the values are emitted. For well-formed boolean and enum values, `presence.tsv` enumerates all 512 combinations of these nine predicates, the corresponding count and named-map header. The byte at `+0x3d` is added directly to the count, so the model explicitly assumes a valid boolean byte. The date comparison calls the same indirect slot `0x576e890` with day 719163 twice; a zero result takes the failure branch at `0x275d35f`. The earlier `fees-request-budget-94` packet independently identifies this as the epoch default for a newly created row. This packet does not execute or reimplement that date helper.

As bounded static examples, an all-default named value has bytes `80`, and a value with `R = 1`, `r = 2`, epoch time and all other fields at defaults has bytes `82a15201a17202`. These are models of the admitted byte paths, not captured node outputs. The complete integer and date encodings remain helper boundaries.

### Enum and failure paths

The ninth field is handled by `0x27b18c0`, which emits the name `a` and tail-jumps to `0x28e7990`. `enum.tsv` resolves the five signed relative offsets at `0x3f5a20`; tags 0 through 4 select the one-byte strings `e`, `i`, `d`, `u`, `p`, respectively. The enclosing value writer omits the field for tag 0. The table lookup has no demonstrated bounds check in this selected body; malformed in-memory tags and decoding are unresolved.

The value writer branches to error handling for header, name and child failures. Representative edges include `0x275cfb5` for `ln`, `0x275d11d` for `t`, and `0x275d23d` for `a`. `branches.tsv` retains 40 selected conditional branches with their condition codes and exact targets. The timestamp conversion and key formatter can themselves fail; their complete internal errors are not decoded here.

### Reader field dispatch

`0x1956bf0` calls classifier `0x26bf820` at `0x1957ed7`. Its byte and word comparisons classify exactly the same nine names, in the same tag order as the writer. Its dispatch table at `0x35ccb8` has ten entries: tags 0 through 8 call the per-field readers listed in `reader-dispatch.tsv`, and tag 9 calls the unknown-value skip helper `0x19682d0`. Each known-field arm checks its own presence marker; a second occurrence branches to an error path naming that field and using the `duplicate field` template at `0x1e0fd5`. Two incoming edges from `0x2635305` and `0x18e0796` call this reader; the full parent paths are not reconstructed here. Matching names, order and compatible field readers support the reader association as an inference; no direct call from the hash closure to the reader is claimed.

`classifier.tsv` records all 256 single-byte classifications from the classifier's relative jump table. The tests additionally cover every two-byte string: `ln` and `no` map to their tags and all other two-byte inputs take the unknown tag. Other lengths take the unknown tag in this classifier. This is a static model of the selected classifier, not an execution of the target reader.

### Inferences

The association with request-budget records follows the independently established capture at state `+0x740` and the existing `fees-request-budget-94` work: it identifies a 20-byte-keyed table there, with total charged weight at value `+0x08`, reserved weight at `+0x28` and a date/time at `+0x30`. Those same offsets are the writer's `R`, `r` and `t`. Thus the strongest supported semantic join is `R` to charged weight and `r` to reserved weight. Other abbreviated field meanings are not assigned from their names. The bytes of an entire job digest are not known until the helper and ordering gaps are resolved.

## Implementation and comparison

Rust implementation: not yet implemented. Binary comparison, normalized masks, helper/data closure and two-build result: not yet measured. The examples and 512 presence cases are static models, not target execution. No node, visor, chain data, private key or networking was used.

## Results and limitations

The extractor checks 10 selected FDE extents, 22 byte windows, 25 direct-call edges, 50 conditional branches, 9 fields, 5 enum table entries, 256 single-byte classifier cases, 10 reader dispatch entries and 512 bounded predicate combinations. Eleven unit tests pass, including corrupted digest, call displacement, enum table, out-of-range address, NOBITS mapping, and short-sort domain controls. The test of the insertion arm covers 120 permutations of five distinct 20-byte keys, plus empty, duplicate and out-of-domain inputs. These counts describe selected evidence and models, not function coverage of the node. No milestone gate is requested.

Next question: recover reader defaults and invalid-enum behavior, and validate the large-sort path and datetime helper before attempting a full job-16 digest.
