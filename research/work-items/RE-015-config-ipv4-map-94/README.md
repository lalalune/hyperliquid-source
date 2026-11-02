# RE-015: configuration IPv4 map readers and updates in node 94

The `internal_ips` configuration value has object/map-shaped readers that pair byte-string keys with four-byte IPv4 values and replace an existing value on an equal key, so reconstructing it as the inferred reference's set of address strings would lose observed behavior.

- Component ID: `constants`; task `RE-015`, `global_constants/*`.
- Target release and full SHA-256: Linux x86-64 node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository
  `e5c9b6436876b2a4a39daef813171f9879317699`; inferred, unlicensed reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23`. Its declarations are clues,
  not recovered source or authority.
- Claim status: byte, address, control-transfer and ELF records are observations;
  field association, value meaning and source-level names are inferences. Inputs
  in the case tables are synthetic static models, not captured executions.
- Scope included and excluded: eight selected FDE ranges covering a binary map
  reader, two binary value readers, a JSON value reader, insertion, split,
  cleanup and iterator. Previously investigated field visitors and their JSON
  object reader, the IPv4 primitive and key reader are handoff boundaries only.
  There is no claim of complete initialization, a running configuration,
  all input cases, or coverage of node #115 or visor.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3 and the standard
library. The extractor imports the repository's `tools/elf_index.py` and
`tools/fde_extents.py`; it authenticates the entire node #94 artifact first,
uses only unique allocated file-backed section mappings, excludes SHT_NOBITS,
and neither invokes external programs nor executes the artifact.

```sh
python3 tools/config_ipv4_map94.py --out research/work-items/RE-015-config-ipv4-map-94
python3 -m unittest tests.test_config_ipv4_map94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
```

The 19 generated evidence files are the JSON and TSV files in this folder.
Their individual hashes and this README's hash are in `MANIFEST.sha256`.
To compare independent outputs, replace the placeholders with two distinct,
empty writable directories:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_ipv4_map94.py --out <tmp-dir-one>
PYTHONHASHSEED=983 TZ=Pacific/Honolulu python3 tools/config_ipv4_map94.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

The comparison was also run with a PATH containing Python alone; outputs were
identical. The focused tests use no external programs. GNU objdump 2.42 was used
for human inspection; its text is not input to the extractor or tests. No node
or visor executable was run; no network, actual configuration, key or chain
action was used.

## Evidence

All addresses below are linked node #94 ELF virtual addresses (VAs), with no
rebase; `functions.tsv`, `instructions.tsv`, `contracts.tsv` and
`prior-handoffs.tsv` also provide section-mapped file offsets. An FDE supplies a
half-open unwind range, not a proof of a complete source-level function or a
whole-node function census. The eight selected ranges are hashed in
`functions.tsv`. The instruction decoder is deliberately restricted to the
encodings encountered in these authenticated ranges: the instruction and branch
lists are linear decoding of those bytes, not a claim that every row is
reachable. It rejects unknown encodings and local branch targets inside an
instruction. Signed relative table entries and relocation records are read
directly from ELF bytes.

Prior, separately scoped field-classifier research associates `internal_ips`
with discriminator `0x27`. The literal is at VA and file offset `0x21bc13`;
the prior classifier leaf at `0x13c791e` writes that discriminator. The binary
visitor table slot at `0x20fae4` selects arm `0x13ad1e4`, whose call at
`0x13ad213` hands off to the selected map reader `0x13bf580`. The prior JSON
visitor hands off at `0x14a3bf9` to object reader `0x14ba3f0`; at the latter's
selected handoffs, an object key and a value are supplied to `0x14cb140`.
These prior bodies are not selected or newly claimed here. Their field
association is a dependency of the `internal_ips` inference, not an independent
reanalysis of the whole visitor. The previously reported relation to the
configuration directory is likewise a boundary; it does not establish a runtime
file or a link from `NvTestnet` to this map.

A newly selected pool reference is at VA `0x13bfa0a`, file offset `0x13bea0a`:
it addresses the 12 bytes `IPv4 address` at VA/file offset `0x21b07f`; the
length argument is set at `0x13bf9fd` and the selected text reader is called at
`0x13bfa17`. The JSON object-reader boundary has a parallel diagnostic
handoff at `0x14ba584`. The string is an expected-value diagnostic argument,
not a claim about a literal configured address. `prior-handoffs.tsv` retains
just the byte windows needed to connect the earlier work to the new ranges.

| Selected role | FDE start and exclusive end | What is observed or bounded |
| --- | --- | --- |
| Binary map reader | `0x13bf580..0x13bff97` | Reads count/depth and key/value results, selects a value reader, inserts pairs, and drops the accumulated map on checked errors. |
| Binary text value reader | `0x13b7e20..0x13b8601` | Bounds the decoded text length and passes a slice to the existing IPv4 parser. |
| Binary other-mode value reader | `0x13b6c50..0x13b7621` | Dispatches on a cached state and has a bounded, four-octet success path. |
| JSON value reader | `0x14bdbe0..0x14bdd1b` | Requires a quoted string, bounds its length, calls the same parser and writes four result bytes on success. |
| Map insertion | `0x14cb140..0x14cb3f6` | Compares key bytes and lengths, replaces an equal key's four-byte value, or inserts a new key/value pair. |
| Leaf and parent insertion/split | `0x1398430..0x139911c` | Shifts entries, splits full nodes, walks parent links and can publish a new root; some propagation and error details remain unresolved. |
| Map cleanup | `0x14da680..0x14da744` | Calls the selected iterator and conditionally invokes a deallocation slot for key storage. |
| Cleanup iterator | `0x14ce920..0x14ceccd` | Tracks remaining entries and walks/deallocates tree storage. |

The selected binary map reader's format byte at context offset `0x24` selects
`0x13b7e20` when nonzero and `0x13b6c50` when zero. A successful value result
is checked for tag `9` and contributes four bytes; calls at `0x13bf9ab` and,
on the JSON side, `0x14ba5db`, reach the same insertion routine. The JSON
reader's successful result uses tag `0` and places four bytes at result offset
1. These numeric tags describe local result representations and are not the
field discriminator.

| Decision or condition | Recorded transition |
| --- | --- |
| JSON value has no opening quote or input is exhausted | `0x14bdc02` / `0x14bdc5f` lead to distinct error-building boundaries. |
| Decoded text length exceeds 15 | Binary `0x13b809e` or JSON `0x14bdca3` rejects before the IPv4 parser call. |
| Existing IPv4 parser fails or leaves input | The success flag and remaining length are both checked at `0x13b80bd..0x13b80cb` and `0x14bdcb9..0x14bdcc3`; the parser at `0x1573af0` is a boundary. |
| Fresh binary marker in `0x80..0x8f` | With cached state 1, the reader consumes the marker and enters the map count/depth path using its low four bits. |
| Fresh marker `0xde` or `0xdf` | Indirect table indices `0x1e` and `0x1f` select two- or four-byte big-endian counts. A short count consumes the available header bytes before its error boundary. |
| Map depth at offset `0x22` | An initial zero branches to an external failure boundary; one is decremented to zero and returns tag 8; values above one decrement and continue. The later restore checks `0xffff` before incrementing. |
| Other-mode state `0xc4`, mode argument zero | Table entry at base `0x210cc4` reaches `0x13b6d09`. After its length byte is read, insufficient declared payload takes an error; lengths 0 through 3 reach an error constructor for a missing octet. With at least four available bytes, the first four are returned and the outer cursor is advanced by the declared payload length. |
| Equal key | `0x14cb1fb -> 0x14cb227`: optional incoming-key cleanup, old 32-bit value loaded at `0x14cb261`, replacement stored at `0x14cb268`, result flag 1. This route bypasses the total-count increment at `0x14cb387`. |
| Empty tree / new key | The insertion path requests `0x140` bytes at `0x14cb32b`; a null result follows `0x14cb339`. On the successful root path, key triples occupy 24-byte strides, values use four-byte strides from node offset `0x110`, and node and total counts increase. |
| Full node | At count 11, `0x1398430` chooses the split pivot and requests another `0x140`-byte node; a null allocation follows `0x13985c0`. Pivot and local-index cases are in `split-index-cases.tsv`. |
| Split with parent | `0x13987cc` checks the parent's count against 11: a nonfull parent enters `0x1398cf2`, while a full parent requests `0x1a0` bytes at `0x1398850`. The `0x1398bee` branch can return to the parent loop. |
| Split without parent | `0x139878b` enters the root-growth path, which requests `0x1a0` bytes at `0x1398c35`; null allocation and overflow of the height-like word have separate failure branches. The old root is linked at new-root offset `0x140`, the new root and incremented height-like word are published at `0x1398c7e` and `0x1398c81`, and the new sibling receives a parent link and index. |
| Key or value error | The selected map reader reaches cleanup at `0x13bfb1e` or `0x13bfbf6`. Its LSDA also covers the two selected value calls at `0x13bfa17` and `0x13bfa26` with landing `0x13bff64`; exception action/type interpretation remains a boundary. |

The binary count/depth checks and cursor/status branches are recorded in
`contracts.tsv`, `branches.tsv` and `instructions.tsv`. On ordinary valid
keys, the equality decision compares the common prefix through the dynamically
relocated `memcmp` slot `0x576e488`, then uses the length difference if the
prefix compares equal; the exact source type and the valid key domain are not
established. A duplicate value is replaced in this insertion routine; this
alone does not establish every enclosing visitor's duplicate-field policy.

The state-table report contains 225 consecutive four-byte entries for each of
three selected state bases, plus the neighboring 18-entry and 32-entry tables
for each, for 825 words total. The first count ends at the next recorded table;
it is not evidence that all other state-byte values are possible or impossible.
Each recorded signed displacement resolves to a decoded start within its
selected FDE. The 76 AWS-name discriminators are outside this packet.

`cfg.tsv` records 26 normal-flow reachability propositions under an
all-conditions-feasible, calls-return model; indirect jumps and exception
transfers stop that analysis. The case tables are separately labeled models of
specific fixed-byte witnesses, with parser success/remaining supplied as inputs;
`map-header-cases.tsv` assumes cached state 1, and `raw-c4-cases.tsv` counts
payload consumption after the length byte, not total stream consumption. The
depth restore model describes the later guard for the supplied current value;
it makes no assumption that external readers preserve depth. Neither the table
rows nor the CFG assert that every modeled case is dynamically reachable.

| Evidence files | Contents |
| --- | --- |
| `summary.json`, `functions.tsv` | Input identity, bounded counts and FDE range hashes. |
| `instructions.tsv`, `branches.tsv`, `transfers.tsv`, `rip-references.tsv`, `contracts.tsv` | Linear byte decoding, relative targets and explicitly checked instruction witnesses. |
| `prior-handoffs.tsv`, `dispatch-tables.tsv`, `relocations.tsv` | Context windows, table entries and relocation records. |
| `lsda-headers.tsv`, `lsda-sites.tsv`, `cfg.tsv` | Selected exception call-site tables and bounded normal-flow propositions. |
| `map-header-cases.tsv`, `map-depth-cases.tsv`, `text-gate-cases.tsv`, `raw-c4-cases.tsv`, `split-index-cases.tsv`, `key-order-cases.tsv` | Conditional finite cases, not target execution results. |

## Implementation and comparison

Rust implementation: not yet implemented. Compiler/linker builds, byte matching,
normalization masks, full helper and data closure, whole-ELF comparison and
runtime target comparison: not yet measured. The inferred reference declares
`internal_ips` as `BTreeSet<IpAddress>` with `IpAddress` aliased to a string.
The observed object key/value handoff and four-byte replacement are incompatible
with treating this selected value as only a set of address strings, conditional
on the prior field association and the external reader/parser contracts. The
exact Rust map type, key validation and consumers remain unresolved; no
unlicensed source was copied into an implementation.

## Results and limitations

For the selected eight FDE ranges only, the extractor reports 12,567 bytes,
2,990 linear instruction records, 457 direct branch/jump records, 150 call or
indirect-transfer records, 136 RIP-relative references, 183 fixed byte
contracts, 16 prior-context anchors, nine bounded tables, 17 relocation slots,
six LSDA headers and 44 LSDA call-site records. These denominators do not
measure component or node coverage. It also records 35 header cases, 10 depth
cases, 16 text-gate cases, 16 other-mode payload cases, 12 split cases and 10
key-order cases, all modeled.

The focused suite passed 45 tests with no skips, including corrupted artifact
identity, FDE body, context and literal bytes, table destinations, LSDA and
relocation records, absent or ambiguous file mappings, malformed instruction
forms, and boundary cases. Two different hash seeds and timezones produced
byte-identical evidence; the producer and tests also passed with Python as the
only program on PATH. `tools/artifacts.py verify`, `tools/catalogue.py --check`
and `tools/reproduce.py` passed. No whole-component progress gate is requested.

Next question: what is the independently established key domain and which
unowned consumers read the stored four-byte values, including the complete
parent-split and outer configuration error paths?
