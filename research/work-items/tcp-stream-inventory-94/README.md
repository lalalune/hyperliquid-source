# tcp-stream-inventory-94: exact-file Location and operand evidence

Task: RE-001 / RE-012, component `transport`. Which node #94 instruction
ranges actually reference `net_utils/src/tcp/tcp_stream.rs`, and which literal
and direct-call observations survive an exact-file attribution rule?

Target: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base checkout: `d30ce21e87a5e9777e6949b523c6e8e2461e4169`.
The reference provenance commit is
`999556f6e0a474b8312db96ec3149e1c44e97c23`, as recorded in
[provenance/sources.json](../../../provenance/sources.json), not inferred from
a nested `git rev-parse` in this flattened checkout. The exact lead file is
[references/can1357-hl/net_utils/tcp/tcp_stream.rs](../../../references/can1357-hl/net_utils/tcp/tcp_stream.rs),
SHA-256 `36b7bd99220cc9b66cbd15deb11e63f1355beefddb13886bc97542e47157b51b`.
Its unlicensed text supplies search hints only. No source, comments or absent
literal text are copied into this packet.

Status: **strong bounded static evidence**, with no reconstruction or milestone
claim. The useful result is an exact Location-to-instruction map, length-bearing
anchors in small ranges with only this file's first-party Locations, and decoded
entry calls into those ranges. Large shared ranges are retained to make the
census complete; their literals do not earn an exact-file binding by proximity.
See [RESULT.md](RESULT.md) for qualifications and prior-work overlap.

## Scope and method

The binary confirms the compiler path
`/home/ubuntu/hl/code_Mainnet/net_utils/src/tcp/tcp_stream.rs` exactly. This is
target provenance, not analyst runtime state; the raw path bytes, length,
section, VA and file offset are retained for every record. Distinct relocated
Location slots remain distinct even when line/column coordinates coincide.

The new collector closes a concrete gap: existing inventories target other
files, while the frame-reader packet records selected read/EOF observations
without this exact-file Location census or a sequentially decoded attribution
map. The change composes their existing MIT ELF/FDE and instruction readers;
no existing tool, test, packet, catalogue or progress gate is changed.

All addresses are ELF link-time VAs, with separate file offsets. Intervals have
exclusive ends. The collector authenticates the entire input first, checks
actual `.eh_frame` FDE/CIE records against the unwind index, scans executable
sections for exact RIP-relative LEA candidates, then decodes each owning FDE
sequentially from its entry. Unknown encodings, truncation, or direct internal
branches into operands fail closed. No resynchronization or external
disassembler is used. An FDE is an unwind range, not exclusive source ownership
or proof of reachability; indirect branches remain unresolved.

Each accepted Location LEA is immediately followed by a decoded RIP-indirect
call. The Location relocation, LEA displacement/register, call displacement,
call-slot relocation and executable callee entry are retained. No panic helper
name or behavior is assigned. Foreign first-party Locations are retained only
to explain the limits of attribution, never as claims on adjacent files.

Literal admission requires an aligned scoped RIP LEA, decoded length-bearing
setup, and either only exact-file first-party Locations in its FDE or an
exact-file Location in the same local setup. A shared FDE alone is insufficient.
This conservative rule rejects valid byte setups whose source attribution is
not specific enough. The finite diagnostic denominator is every unique quoted
literal in the exact reference file plus target-derived probes listed in JSON.
An absent reference probe is represented by line, byte length and SHA-256 only.

## Reproduce

From the repository root, with Python 3.10+ and its standard library:

```sh
python3 tools/tcp_stream_inventory.py --out research/work-items/tcp-stream-inventory-94/
python3 -m unittest tests.test_tcp_stream_inventory -v
python3 research/work-items/tcp-stream-inventory-94/verify.py
make verify
```

The recorded local interpreter is Python 3.13.5 on Linux x86-64. The collector,
tests and verifier require no objdump, REA, Ghidra, installations or network.
The target is read through a read-only mapping. Mutation tests use private
copy-on-write pages; they never modify or execute the artifact. Producer source
hashes are in [inventory.json](inventory.json). Packet hashes and exact file
membership are enforced by [MANIFEST.sha256](MANIFEST.sha256) and
[verify.py](verify.py), including the verifier itself. Re-running the collector
must reproduce JSON byte for byte. Both reports' generated blocks are checked
against regenerated JSON, not manually maintained count claims.

## Census

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | --- |
| adjacent_location_calls | 34 |
| byte_proven_but_unattributed_setups | 12 |
| call_edges | 3 |
| constants_bound | 0 |
| constants_unresolved | 10 |
| counted_fragment_anchors | 0 |
| decoded_instructions | 12213 |
| diagnostics_absent | 12 |
| diagnostics_bound | 3 |
| diagnostics_probed | 18 |
| diagnostics_unresolved | 3 |
| location_leas | 34 |
| locations | 15 |
| only_exact_file_first_party_fdes | 6 |
| pointer_length_anchors | 8 |
| scoped_fde_bytes | 67679 |
| scoped_fdes | 12 |
| shared_first_party_fdes | 6 |
| tail_edges | 0 |
| unique_line_column | 4 |
<!-- END GENERATED METRICS -->

<!-- BEGIN GENERATED LOCATIONS -->
| Slot VA | Line:column | LEA sites | FDE owners |
| --- | --- | --- | --- |
| 0x5697298 | 45:80 | 0x203510b, 0x2035118, 0x204878a, 0x2048799 | 0x2034eb0, 0x20485e0 |
| 0x56972b0 | 50:73 | 0x2048770, 0x204877d | 0x20485e0 |
| 0x56972c8 | 60:82 | 0x203673e, 0x203674d | 0x2036460 |
| 0x56972e0 | 33:60 | 0x204899f, 0x20489ac | 0x20487f0 |
| 0x56a09c8 | 45:80 | 0x2264488, 0x226449a | 0x22615b0 |
| 0x56a09e0 | 50:73 | 0x226438c, 0x226439e | 0x22615b0 |
| 0x571ec08 | 45:80 | 0x4387edb, 0x4387ee8, 0x439ef7a, 0x439ef89 | 0x4387c80, 0x439edd0 |
| 0x571ec20 | 50:73 | 0x439ef60, 0x439ef6d | 0x439edd0 |
| 0x571ec38 | 60:82 | 0x4387bee, 0x4387bfd | 0x4387910 |
| 0x571ec50 | 33:60 | 0x439f1a7, 0x439f1b4 | 0x439efe0 |
| 0x572fbf0 | 45:80 | 0x4744c69, 0x4744c9f | 0x4744160 |
| 0x572fc08 | 50:73 | 0x4744bfd, 0x4744c33 | 0x4744160 |
| 0x573e160 | 45:80 | 0x4b7333f, 0x4b73354 | 0x4b72900 |
| 0x573e178 | 50:73 | 0x4b732c6, 0x4b73301 | 0x4b72900 |
| 0x573e190 | 33:60 | 0x4b3a1c9, 0x4b3a1db | 0x4b399a0 |
<!-- END GENERATED LOCATIONS -->

<!-- BEGIN GENERATED FDES -->
| Start | End exclusive | Bytes | First-party Location paths |
| --- | --- | --- | --- |
| 0x2034eb0 | 0x203516e | 702 | net_utils/src/tcp/tcp_stream.rs |
| 0x2036460 | 0x20367c3 | 867 | net_utils/src/tcp/tcp_stream.rs, net_utils/src/tcp/write.rs |
| 0x20485e0 | 0x20487e7 | 519 | net_utils/src/tcp/tcp_stream.rs |
| 0x20487f0 | 0x2048f05 | 1813 | net_utils/src/tcp/tcp_stream.rs |
| 0x22615b0 | 0x22689f0 | 29760 | base/src/duration.rs, base/src/fu.rs, base/src/lu.rs, net_utils/src/tcp/read.rs, net_utils/src/tcp/tcp_stream.rs, node/src/evm_kvs.rs, node/src/gossip_config.rs, node/src/gossip_rpc_client.rs |
| 0x4387910 | 0x4387c73 | 867 | net_utils/src/tcp/tcp_stream.rs, net_utils/src/tcp/write.rs |
| 0x4387c80 | 0x4387f3e | 702 | net_utils/src/tcp/tcp_stream.rs |
| 0x439edd0 | 0x439efd7 | 519 | net_utils/src/tcp/tcp_stream.rs |
| 0x439efe0 | 0x439f7cb | 2027 | net_utils/src/tcp/tcp_stream.rs |
| 0x4744160 | 0x474822f | 16591 | base/src/duration.rs, base/src/fu.rs, base/src/lu.rs, net_utils/src/tcp/read.rs, net_utils/src/tcp/tcp_stream.rs, node/src/evm_kvs.rs, node/src/gossip_config.rs |
| 0x4b399a0 | 0x4b3b924 | 8068 | base/src/duration.rs, base/src/lu.rs, net_utils/src/async_sleep_retry.rs, net_utils/src/tcp/reconnecting_tcp_client.rs, net_utils/src/tcp/tcp_stream.rs, node/src/consensus/network.rs |
| 0x4b72900 | 0x4b73d7c | 5244 | base/src/duration.rs, base/src/lu.rs, net_utils/src/tcp/read.rs, net_utils/src/tcp/tcp_stream.rs |
<!-- END GENERATED FDES -->

[instructions.json](instructions.json) contains every decoded instruction in
these scoped FDEs, with offsets, raw bytes and decoded kinds. These are a
restricted decoder's transcripts, not full assembly semantics. The code hashes,
FDE/CIE/index record bytes, transfers, rejected literal candidates and
cross-references are in [inventory.json](inventory.json).

## Implementation and comparison

No Rust implementation, build scope, Cargo.lock, source equivalence, behavioral
comparison or whole-ELF comparison is offered. No normalization masks are used.
Helper behavior, non-scoped calls, general relocations, vtables/data, indirect
control flow and FDE-less code remain separate gaps. No acceptance gate changes.

The targeted controls test authentication before parsing; Location fields,
relocations and path identity; missing/nonallocated sections; FDE extent and
index mismatches; instruction truncation and embedded opcode lookalikes;
shifted/retargeted LEAs; pointer/length clobbers; relative-call retargeting;
counted-text delimiters; shared-range false attribution; prior-evidence
corruption; report drift; and manifest omission/traversal/symlink attacks.
Tests run collection and verification with process/network entry points blocked.
