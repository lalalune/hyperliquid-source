# consensus-rpc-inventory-94: exact-file Location and literal inventory

Task: RE-001, bounded consensus component evidence for exactly
`node/src/consensus/rpc.rs`. The question is which relocated panic Locations,
instruction-boundary LEAs, explicit literal lengths and direct call edges can
be tied to this path in node #94. This is observation-level static research;
source function names, types and behavior remain unresolved.

Target: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The compiler path prefix embedded in that target is preserved as hexadecimal
bytes in every Location's `path_bytes`; it is not analyst runtime state.
Addresses are ELF link-time virtual addresses, with explicit file offsets.
All range ends are exclusive. No ASLR or provider rebase is applied.

Base source revision: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
The available [reference file](../../../references/can1357-hl/node/consensus/rpc.rs)
is unlicensed inferred material used only for search hints. None of its code
or narrative is copied. Diagnostic text here was independently observed in
and extracted from the authenticated binary. Reference labels are not source
recovery. Ellipsis paraphrases and short generic fragments are excluded from
the finite probe set instead of being counted as artificial absent probes.

The independent MIT decoder and test scaffolding were adapted from local branch
`consensus-server-inventory-94`, commit
`0cc6da86bd085a87b0d8205cceaa67ca3f5502f6` (its
`tools/consensus_server_inventory.py` and corresponding tests/verifier).
This packet adds its own tool and tests; it does not depend on that branch
being checked out. Producer and prior-packet content hashes are in the JSON.
The only shared imports are existing MIT `tools/elf_index.py` and
`tools/fde_extents.py`. No existing files, imports, submodules, progress gates
or catalogues are changed.

## Reproduce

Run from the repository root with Python 3.10+ and the retained target,
reference and prior packets present. Validation used CPython 3.13.5 on Linux
x86-64. Only the standard library is needed by this packet; neither GNU nor
LLVM objdump, REA, Ghidra, Rust, pip, nor network access is required. REA was
not exposed in this session; no provider setup or installation was attempted.

```sh
python3 tools/consensus_rpc_inventory.py --out research/work-items/consensus-rpc-inventory-94/
python3 -m unittest tests.test_consensus_rpc_inventory -v
python3 research/work-items/consensus-rpc-inventory-94/verify.py
python3 -O research/work-items/consensus-rpc-inventory-94/verify.py
make verify test catalogue-check
make reproduce
```

The tool authenticates the entire target before parsing. It memory-maps that
file and decodes only the scoped FDE bodies. It writes deterministic JSON with
no timestamps or local environment data. The verifier checks an exact packet
whitelist, manifest hashes, byte-identical regeneration, pinned target facts,
and generated tables in both reports. It never updates the manifest or reports.
For an intentional report refresh, use `evidence_tables()` on the regenerated
`inventory.json` and recompute the manifest only after reviewing all changes.

## Evidence method and denominator

1. Inspect every `R_X86_64_RELATIVE` relocation in `.rela.dyn`. A Location has
   aligned storage in `.data.rel.ro`, a zero pre-relocation pointer, a u64
   path length, u32 line and u32 column. Its relocation must point into
   `.rodata` and its complete length-delimited path must equal the scoped
   path. Record every such slot, including repeated source coordinates.
   A matching path with malformed fields aborts instead of reducing the count.
2. Search executable sections for the precise `48/4c 8d` RIP-relative form.
   Every candidate addressing a Location slot must lie wholly in a decoded
   actual FDE extent. Preserve the raw FDE, CIE and unwind table entry.
   Validate the whole ELF FDE/index consistency, then decode sequentially from
   each scoped entry through its exact end. Never resynchronize past unknown
   bytes. Check all internal direct branch destinations against instruction
   boundaries. These are unwind extents, not a complete CFG or source boundary.
3. Decode each claimed LEA, E8/E9 transfer, register move and immediate store
   from its bytes. The general boundary decoder supports only enumerated legacy
   encodings; VEX/EVEX and unsupported prefix/group combinations fail closed.
   `other` in the transcript means a length-decoded instruction whose operand
   semantics are not claimed. No objdump text is consumed or regenerated.
4. Search the entire authenticated file for each finite literal probe. Bind only
   an exact literal-start LEA in a scoped FDE plus an explicit matching length:
   either a qword pointer store and adjacent qword immediate length store, or
   a short contiguous non-clobbering register setup ending in a call. The
   accepted pointer/length register pairs are RDI/ESI, RDX/ECX, R8/R9D and
   RCX/R8D. Those register facts do not recover an ABI or argument meaning.
   Header-prefixed LEAs are retained separately and remain unbound. Generic
   runtime and foundation strings are excluded from the probe denominator.
5. Count an attributed direct edge only when its E8/E9 rel32 target equals a
   scoped FDE entry. Preserve all other direct transfers with dispositions;
   indirect calls and jumps stay unresolved. Reference helper-call leads are
   checked as external byte edges without importing their names or semantics.
6. Constant candidates are limited to the reference's timeout and block-count
   configuration roles. Neither role is uniquely established by a decoded
   immediate in these shared ranges. Ordinary immediate numbers, lengths and
   timer arithmetic do not become RPC configuration constants by co-location.

## Derived census

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | ---: |
| constants_bound | 0 |
| constants_unresolved | 2 |
| decoded_instructions | 4024 |
| diagnostics_absent | 0 |
| diagnostics_bound | 14 |
| diagnostics_probed | 22 |
| diagnostics_unresolved | 8 |
| indirect_calls_unresolved | 238 |
| indirect_jumps_unresolved | 21 |
| internal_rel32_calls | 0 |
| internal_rel32_jumps | 208 |
| location_leas | 14 |
| locations | 9 |
| pointer_length_anchors | 14 |
| scoped_fde_bytes | 21907 |
| scoped_fdes | 4 |
| scoped_rel32_calls | 1 |
| scoped_rel32_jumps | 0 |
| unique_line_column | 9 |
| unresolved_external_rel32_calls | 119 |
| unresolved_external_rel32_jumps | 0 |
<!-- END GENERATED METRICS -->

<!-- BEGIN GENERATED LOCATIONS -->
| Location VA | Line:column | LEA sites | Owning FDE starts |
| --- | --- | --- | --- |
| 0x571d090 | 248:108 | 0x4385850, 0x438585d | 0x43848f0 |
| 0x572eef0 | 90:61 | 0x47b4021, 0x47b4030 | 0x47b3f50 |
| 0x572ef08 | 103:66 | 0x47b448a | 0x47b3f50 |
| 0x572ef20 | 106:56 | 0x47b43fb | 0x47b3f50 |
| 0x572ef38 | 115:66 | 0x47b06de, 0x47b06ed | 0x47b05f0 |
| 0x572ef50 | 119:17 | 0x47b0950 | 0x47b05f0 |
| 0x5738698 | 203:31 | 0x4b34365 | 0x4b33eb0 |
| 0x57386b0 | 184:109 | 0x4b34c6c, 0x4b34c7e | 0x4b33eb0 |
| 0x57386c8 | 119:30 | 0x4b34c52, 0x4b34c5f | 0x4b33eb0 |
<!-- END GENERATED LOCATIONS -->

<!-- BEGIN GENERATED FDES -->
| Start VA | End exclusive | Bytes | FDE record VA |
| --- | --- | --- | --- |
| 0x43848f0 | 0x4386a36 | 8518 | 0x1237634 |
| 0x47b05f0 | 0x47b0b43 | 1363 | 0x12914b8 |
| 0x47b3f50 | 0x47b494c | 2556 | 0x1291728 |
| 0x4b33eb0 | 0x4b363ae | 9470 | 0x12c6138 |
<!-- END GENERATED FDES -->

These are complete for the stated relocated Location layout and exact path
on the pinned artifact. They are not an all-functions, all-literals,
matched-window, source-line coverage or engineering-completion denominator.
The tool rejects missing Location LEAs and candidates inside other instructions.

## Packet files

- [inventory.json](inventory.json): artifact pin, relocations, raw Location and
  FDE records, LEA context, literal proofs and negatives, constant limitations,
  direct transfers, reference checks, prior-work relationships and non-claims.
- [instructions.json](instructions.json): complete scoped instruction-byte
  transcript with FDE-relative offsets and decoded categories.
- [RESULT.md](RESULT.md): derived results, interpretation limits and verdict.
- [verify.py](verify.py): fail-closed whitelist, manifest, regeneration and
  report checks. `MANIFEST.sha256` hashes every packet file except itself.
- [tool](../../../tools/consensus_rpc_inventory.py) and
  [tests](../../../tests/test_consensus_rpc_inventory.py): producer and
  target-grounded corruption controls.

## Prior work and implementation status

[RE-008](../RE-008-consensus-wire-state/README.md) already checks the shared
seed starts as leads for types/signed/state. Its
[consensus-wire.json](../RE-008-consensus-wire-state/consensus-wire.json)
marks these entries as lacking its own scoped Locations. That is consistent
with this exact RPC-path census. No wire tags, signature, quorum or state
transition claims are repeated or changed here.

[RE-009](../RE-009-storage-state-roots/README.md) is prior hashing/storage work.
The retained [hashers.json](../RE-009-storage-state-roots/hashers.json), whose
hash is recorded in `prior_work`, contains neither the exact RPC path nor a
scoped FDE among its first-party direct hasher callers. The supplied description
of an RPC co-location does not match this local packet. No hasher claim is
inferred from that discrepancy, and no prior evidence is modified.

Rust implementation, Cargo/build provenance, differential execution, normalized
comparison, helper/data/vtable closure and whole-ELF comparison are **not yet
implemented or measured** by this packet. Normalization masks are empty.
No progress gate is requested. See RESULT.md for validation results and the
next bounded question.
