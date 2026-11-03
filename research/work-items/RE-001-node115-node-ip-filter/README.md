# RE-001: node115 node-IP filter result substitution and report gating

Component: `consensus`, bounded static research under RE-001. Question: how
does the node-IP collector turn the query's raw result into retention, what
does it record separately, and when does the caller report those records?

Target Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. New code/docs are independently
authored under root MIT. No unlicensed inferred code was copied.

## Retained evidence and scope

| Role | Complete FDE (exclusive end) | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Filter owner | `0x5b2b150..0x5b2b45b` | 779 | 169 |
| Collector | `0x5b7bc60..0x5b7c3de` | 1,918 | 366 |
| Query-result predicate | `0x4fbf270..0x4fbfa0b` | 1,947 | 405 |
| Tracing wrapper | `0x4f2c470..0x4f2cda5` | 2,357 | 459 |
| Rebuild adapter | `0x4dbfa80..0x4dbfba6` | 294 | 75 |

The **7,295 bytes / 1,474 instructions** are independently exported in full by
GNU and LLVM, including non-claimed tracing and unwind context. They are an
evidence denominator, not a whole-function semantic completion or rebuilt-byte
match. Addresses are ELF VAs. `records.json` binds hashes, file offsets,
FDE/CIE identities, source Locations, relocations, calls and qualified incoming
references. The filter is named by RELATIVE slot `0x64e7408`.

Locations `node/src/consensus/node_ips.rs:58:52`, `77:13` and `79:30`, and
the literal `firewall_filtered_check_is_blocked`, tie the selected chain of
calls to this source path. That literal is context; it does not establish the
meaning of every raw status returned by the query.

## Observed result relation

The filter's raw DL byte is compared with **3**; the equality result is saved
and passed by reference into the collector. The collector reads 24-byte
entries containing a 20-byte key and trailing u32. Flat iteration advances
with circular indexing; tree iteration obtains the same fields from a helper.
Both feed the tracing wrapper, which either tail-calls the predicate directly
or calls it and preserves EAX across tracing cleanup.

At both predicate query sites (`0x4fbf446` and `0x4fbf63e`), slot `0x64eb298`
binds target `0x4d56a00`. The arguments include context+0x6c8 and the entry's
u32. This query remains opaque. Its raw low return byte q is handled as follows:

| q | Append the original 20-byte key + u32 to side vector? | Predicate low byte | Collector retains entry? |
| --- | --- | --- | --- |
| 0 | no | 0 | yes |
| 2, raw mode != 3 | yes | 0 | yes |
| 2, raw mode == 3 | yes | 1 | no |
| all other byte values | no | q | no |

The special result **2 is not returned directly**: it records the original
entry and substitutes the saved mode-equality byte. Consequently recording an
entry does not itself prove it was removed. The collector's first loop retries
on nonzero; its later flat and tree loops append on zero. The two query-site
copies agree on the same record/substitute rule. The predicate preserves that
result through its timing/lock cleanup and returns it in EAX.

After collection the owner calls the rebuild adapter and stores its 32-byte
result into the input state's leading header **before** the report gate.
Reporting requires all three conditions: incoming R8B nonzero, raw DL equal
3, and nonempty side vector. A zero report flag suppresses reporting, not
filtering or rebuilding. On normal return the owner copies the resulting
104-byte state to output and releases the side vector (24-byte element stride).

The rebuild adapter has separate sorting handoffs for input lengths 2..20
and >=21, then an opaque canonicalization helper. Its resulting length <=64
selects the compact representation; >64 selects a tree-building handoff and
the min-i64 representation sentinel. No sorting/deduplication semantics or
final map contents are inferred from those helper names alone.

## Boundaries and prior work

The raw q=0/1/2 values are not assigned public allow/block/unknown meanings.
The all-byte relation is a local projection, not proof that arbitrary query
outputs or modes are reachable. The query's IP-policy behavior, timing,
lock/tracing protocol, allocation failures, tree iterator validity,
canonicalization and external callers remain unclosed. Full exports make
these boundaries reviewable; they do not claim full helper reconstruction.

Prior #702 concerns node94 validator/configuration checks; #1378 recovers
packed IPv4 translation; #1504 studies value encoding. #569 and its Rust
projection #1939 cover the firewall update cycle, explicitly leaving the
computed-IP builders opaque. #562 covers a separate mismatch logger. None
establishes this node115 query-result substitution/retention relation.
`scope-check.json` records the all-state audit and main-history search.

## Reproduce and validation

Python 3.14.7, Capstone 5.0.7, GNU binutils 2.47.20260726 and LLVM 18.1.4 on
macOS arm64. Run from the repository root with GNU and LLVM on PATH:

```sh
python3 research/work-items/RE-001-node115-node-ip-filter/export_disassembly.py
python3 research/work-items/RE-001-node115-node-ip-filter/verify.py --controls
python3 research/work-items/RE-001-node115-node-ip-filter/relations.py
python3 -m unittest discover -s tests -p test_node115_node_ip_filter.py -v
make doctor verify test catalogue-check reproduce
```

`--write` regenerates JSON. The original capture is authenticated before
exports are produced through a private static copy. No original or mutated
capture is executed or emulated. **81 deep corruption controls** bypass the
whole-image/body/export guards and exercise the finer obligations.
`relations.py` uses native operands for 65,536 query/mode pairs (both query
sites) and 131,072 report combinations. Four real operand/branch mutations
change the corresponding projection. These are static relational checks,
not a runtime differential test or a reconstructed IP-policy implementation.

`validation.json` records actual full repository checks, baseline provenance,
and environment skips. No public ABI, recovered Rust, hosted CI, container
success, original-byte equivalence or progress-gate completion is claimed.
Next close query `0x4d56a00` before assigning policy meaning to its raw results.
