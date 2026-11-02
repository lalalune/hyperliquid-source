# RE-015: binary name-key envelope and its unit-payload path

Node #94's binary name-key envelope distinguishes a direct key from a one-entry map whose key is followed by a separately checked unit byte, so a reconstruction must preserve both the extra read and the different cursor/error outcomes.

- Component ID: `constants`, task `RE-015` (`global_constants/*`).
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as a lead rather than copied or treated as authority.
- Claim status: byte-backed local observations, an explicitly conditional transfer model, and inferred names for input types and function roles. No target execution, independent Rust implementation, or full-component gate is claimed.
- Scope included and excluded: four selected FDE extents, their normal direct branches, the selected 76-entry same-target dispatch run, output and cursor stores, and the envelope's LSDA call-site records. Existing name recognition, scalar dispatch, the common reader and cleanup function are call boundaries. Configuration publication, the outer map reader, complete error/allocator behavior, #115 and visor are outside this selection.

## Reproduce

From the repository root, with the authenticated artifact present, Python 3.12.3 was used. The producer authenticates the full ELF before reading it, uses `tools/elf_index.py` and `tools/fde_extents.py`, and excludes `SHT_NOBITS` when resolving file bytes. The selected x86 encoding walker is adapted from the independently authored HlChain-reader research; it accepts a reviewed subset and rejects unsupported or truncated instructions. The producer and tests use only Python and those shared readers. No captured executable, external disassembler, process, network, chain, or key is used by them.

```sh
python3 tools/aws_key_unit94.py --out research/work-items/RE-015-aws-key-unit-94
python3 -m unittest tests.test_aws_key_unit94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-015-aws-key-unit-94 && sha256sum -c MANIFEST.sha256)
```

For two independent generations, replace the placeholders with different empty, writable relative directory names. Compare generated files with their namesakes here; the README and manifest are authored metadata and are not generator outputs.

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/aws_key_unit94.py --out <tmp-dir-one>
PYTHONHASHSEED=983 TZ=Pacific/Honolulu python3 tools/aws_key_unit94.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

GNU objdump 2.42 was used only for human inspection. Evidence files contain ELF bytes and directly decoded operands, not its text. `instructions.tsv` partitions each selected FDE; its numeric addresses are decimal linked virtual addresses and its file offsets come from section mapping. Its immediate fields are unsigned encodings; direct branch targets use signed displacements. A `-` in a TSV cell denotes an absent or unmodeled value, as appropriate to that column. The constrained walker verifies selected direct branch destinations against decoded instruction starts. It is not a general x86 decoder or proof of whole-program coverage. `exception-sites.tsv` retains raw LSDA record bytes, ranges and landing addresses; action/type semantics are not decoded.

## Evidence

The existing inventory establishes the default name byte and the 76-name descriptors. Earlier name and scalar work associates the common reader called here with `AwsName`; this packet does not repeat that table or select those reader functions. The outer caller and prior configuration-field work remain separate boundaries. On that basis the term “name key” below is an inference; the byte operations and transfers are observations.

| Selected FDE start | Exclusive end | Observed local role |
| --- | --- | --- |
| `0x13aa150` | `0x13aa2e2` | Normalize a fresh or cached marker; select a direct key, one-entry map key, local count error, or truncated-header handoff. |
| `0x13f4250` | `0x13f42fb` | Delegate key recognition, dispatch the successful key byte, check a unit payload, and copy or construct a result. |
| `0x13f4300` | `0x13f435f` | Delegate directly and copy the returned result, without the additional local unit check. |
| `0x1409860` | `0x14098cc` | Read one fresh byte, accept `0xc0` as tag 9, or construct a local non-unit/EOF result. |

These are unwind-described extents, not independently proven source-function boundaries. The selected functions have no start address in the retained research work items or the available prior PR packets inspected for this run. Their external call targets are not claimed as newly selected functions.

### Marker and cursor decisions

At `0x13aa156`, cursor bytes at `+0x20/+0x21` hold a marker class and payload; class 1 causes a fresh read using pointer `+0x10` and remaining length `+0x18`. A successful fresh read advances the pointer by one and reduces the length by one. With no byte available on that path, the envelope writes tag 0 and an error descriptor; the other result bytes are not inferred.

| Class or complete prefix | Decision before the delegated reader |
| --- | --- |
| Fixed map `0x80`–`0x8f` | The low four bits are the count. Count 1 takes the map-key route; every other count writes tag 4 and the count. |
| `0xde` plus two bytes | Read a big-endian 16-bit count; count 1 takes the map-key route, otherwise write tag 4 and the count. |
| `0xdf` plus four bytes | Read a big-endian 32-bit count; the same count decision applies. |
| Incomplete two- or four-byte count | Advance over the remaining bytes, set remaining length to zero, and invoke the direct-key boundary. Its eventual result is outside this local model. |
| Other normalized marker classes | Invoke the direct-key boundary; the envelope does not locally decide the key-reader result. |

The one-entry path resets the cached marker byte to 1 before calling `0x13f4250`. In the fresh-marker case the marker has already been consumed; for an already cached marker, no second marker byte is consumed. `marker-cases.tsv` and `prefix-cases.tsv` record modeled fresh/cached cases and consumption **up to the call boundary**, not observed node outputs or effects inside the previous reader.

### Successful key and failure handoffs

`0x13f4250` and `0x13f4300` both call the previously identified common key reader with a flag byte of 1. If that reader returns a tag other than 9, both wrappers copy its local result. On tag 9, the map wrapper uses the returned byte as an index into the relative table at `0x217a50`. For the 76 contiguous entries checked from that base, the signed offsets all resolve to `0x13f428e`, which calls `0x1409860`; the next 4-byte value differs. This is a same-target run, not a new table of 76 name strings or independent proof that the following word is an admissible entry.

The unit reader advances the cursor by one when a byte is available. `0xc0` returns tag 9. Every other byte follows the local tag-2 path, with marker and payload fields; EOF returns tag 0 without advancing the cursor. It reads directly from the cursor rather than consulting its cached marker byte. If the unit result has tag 9, `0x13f429f` writes the original key byte to output `+1` and tag 9 to output `+0`; otherwise the wrapper copies the unit result. `wrapper-cases.tsv` is conditional on an assumed result from the external key reader and restricts the index to the checked table run. It does not prove acceptance of any concrete name input or predict an external error payload.

For the previously documented `NvTestnet` discriminant 32, this local path preserves byte 32 if the external reader returns tag 9 with that byte and the subsequent unit read returns tag 9. This conditional case does not establish that a particular spelling, or the global default, reaches this reader.

The LSDA at `0x91e434` has a call-site range `0x13aa223`–`0x13aa282` covering both key-wrapper calls; its landing address is `0x13aa2c1`. That landing path calls an external cleanup boundary and then the unwind-resume boundary. A separate record covers the cleanup call with another landing address. Only the selected call-site ranges and raw action values are asserted; personality behavior and action/type tables remain unresolved.

`cfg-edges.tsv` and `cfg-paths.tsv` retain the normal-flow graph and 15 structural queries. They connect the envelope entry to both wrapper calls, the empty-input and count-error stores, and connect the map wrapper through its checked table run to unit success and error-copy sites. They also show that, in this normal-flow graph, the map-wrapper call cannot reach the direct-wrapper call and the successful key write cannot reach the unit-error copy. Branch conditions are over-approximated, calls are assumed to return, the indirect edge is limited to the checked run, and exceptional transfers are excluded. A listed path is not proof that a concrete input makes its conditions feasible.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo manifest/lock, matching compiler and linker flags, target fixture replay, raw and normalized binary comparisons, and whole-ELF equivalence: not yet implemented or measured. No normalization masks or reference source code are used. The body hashes and byte contracts bind this selected analysis; they do not establish the semantics of external helpers or the full published configuration.

## Results and limitations

The generated selection contains 4 FDEs and 776 bytes, 242 decoded instructions, 40 direct intra-FDE branches/jumps, 10 call or indirect-transfer sites, 17 byte contracts, 261 normal-flow edges, 15 graph queries, and 4 LSDA call-site records. The table result is a 76-entry same-target run. The 256 fresh-marker, 257 unit/EOF, 69 prefix, and 21 wrapper cases are conditional static model rows, not captured executions. These are denominators for this selection only.

The focused unittest suite passed 32 tests with zero skips, including wrong-digest, altered opcode and operand, invalid or valid-but-redirected branch targets, changed table entry, malformed LSDA encoding, changed relocation, invalid address and non-file-backed section controls. Two regenerations with distinct hash seeds and time zones matched byte for byte; a Python-only PATH check and artifact/catalogue checks are reported in the draft. `python3 tools/verify_imports.py` did not complete: its fresh-index status check caused Git LFS to attempt a write in a read-only administrative directory. The pinned reference HEAD and its ordinary status were readable. No captured program or public networking was used. The pre-existing dirty workspace files were not part of this work.

The previous key reader and its accepted input forms remain external: in particular this packet does not independently prove that any given serialized spelling or number reaches tag 9. The semantic origin of the selected key result, full parser-to-configuration publication, helper/data closure and all four constants milestones remain open. Next question: after coordinating the existing name-reader ownership, connect a concrete accepted binary key input through the outer map's insertion and publication path without re-claiming those bodies.
