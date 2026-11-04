# RE-001: node #115 rate-limiter source-Location coordinates

- Component: transport; allocation is inferred from the embedded `net_utils` path.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Repository source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Status: static coordinate observations, not a recovered algorithm or function identity.
- Question: which selected native references and unwind extents are associated with
  the captured `net_utils/src/rate_limiter.rs:131:20` source Location?

## Observed result

The source-path bytes occupy ELF VA/file offset `0x439f4a` (29 bytes).
The 24-byte source Location at VA `0x64b6f68` / file `0x64b4f68`
contains a zero stored pointer, length 29, line 131 and column 20.
A unique `.rela.dyn` record at file `0xed378` has destination
`0x64b6f68`, information word 8 (`R_X86_64_RELATIVE`, symbol zero),
and addend `0x439f4a`. Thus the loaded path pointer comes from relocation,
not from interpreting the zero stored word as a valid source pointer.

| Unwind extent, linked ELF VA, half-open | LEA VA | LEA file offset |
| --- | --- | --- |
| `[0x59db700,0x59db98d)` | `0x59db91d` | `0x59da91d` |
| `[0x59db990,0x59dbc1d)` | `0x59dbbad` | `0x59dabad` |

Both selected regions are 653 bytes. Both instruction-aligned RIP-relative
LEAs load this Location into RSI. Each immediately precedes a direct relative
call to `0x57d32a0`; that callee's identity and contract are unresolved.
`proof.json` retains raw Location/relocation bytes, original coordinates,
readelf FDE rows, complete selected-region hashes and both 12-byte LEA/call
windows. The adjacent native text files retain the two bounded disassemblies.
The tool decodes both complete ranges, but only the selected LEA/call pairs
are instruction-checked. This is not exhaustive instruction or cross-reference closure.

The measured denominator is one selected Location, two selected references,
and two containing unwind extents. FDE membership corroborates an unwind
range; it does not prove semantic function boundaries or source ownership.
The source-path label does not prove these regions implement a particular
rate-limit policy, peer protocol, clock, counter or thread-safety contract.

## Reproduce

From the repository root, with the pinned artifact materialized:

```sh
python3 tools/node115_rate_limit_coordinates.py --out work/rate-limit-reproduction
python3 -m unittest tests.test_node115_rate_limit_coordinates -v
(cd research/work-items/RE-001-node115-rate-limit-coordinates && sha256sum -c SHA256SUMS)
```

No target is executed. The new standard-library-only helper authenticates the
whole capture, parses ELF PT_LOAD/section/RELA structures, invokes static GNU
`readelf --debug-dump=frames`, then two bounded `objdump -d -Mintel` decodes.
It accepts an explicit `--target` path but only the pinned size/digest.
Outputs contain no timestamps or installation paths. `VERSIONS.json` records
the observed Python, binutils and platform; raw readelf formatting is not a
cross-version equality requirement. No installer, network or model call is used.
Prerequisite manifests, instructions and hooks were inspected during discovery;
no repeated setup or captured-executable invocation is needed to reproduce.

## Checks and controls

`SCOPED-TESTS.txt` records the actual implementation-machine scoped run.
Tests authenticate the real capture, verify the committed structured proof,
exercise both selected native references and compare two independent static
provider invocations. Lower-level controls deliberately bypass only whole-image
identity to reach source-field/path, relocation multiplicity/type/address,
ELF/range, LEA/call byte, instruction-boundary/decode and FDE corruption checks.
Passing these controls establishes evidence checking, not target equivalence.
Whole-image authentication remains mandatory on the normal command path.
Required independent repository/global validation is separate from this log;
its result must be read from the trusted validation receipt, not inferred here.

## Implementation and comparison

The helper and tests are independently authored for this bounded coordinate
question. No inferred source or reference implementation was copied, and no
Rust implementation, compiled comparison or target runtime was measured.
Captured native bytes and excerpts retain their original upstream rights;
the root MIT license does not relicense them. No source pins, existing
executable files, component catalogue or progress gates are changed.

The pinned integrated text search found no selected coordinates; that bounded
search is not an exhaustive novelty proof. The inspected RPC limiter work
(#2114), raw-transaction forwarding (#2161), and JsonRpcResult packet (#2127)
address different named lanes; #2127's three declared extents are disjoint.
This packet does not reproduce or claim their semantic/test results.

## Limits and next question

No subsystem completion, caller/callee closure, algorithm, source reconstruction,
rate-limit behavior, timing or runtime safety is claimed. No gate advances.
Next: after review of these coordinates, establish the shared callee's actual
static contract and caller context before attaching a rate-limit interpretation.
