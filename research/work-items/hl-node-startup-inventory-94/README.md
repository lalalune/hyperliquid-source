# RE-012: node #94 startup/CLI inventory

This packet asks which relocated `node/src/hl_node.rs` panic Locations and
CLI/startup string anchors can be attributed to actual unwind ranges in node
#94. It reports **53 Locations, 57 Location LEA sites, 15 owning FDEs, and
10 bound / 6 unresolved CLI candidates**. These are static observations, not a
recovered CLI implementation or a complete startup map.

- Task/component: RE-012 APIs/gossip/startup; `node-runtime` allocation.
- Target: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference gitlink: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  Its inferred, unlicensed source is a lead, not official source or an
  implementation dependency. No reference Rust is copied into `src/`.
- Owned files: `tools/hl_node_startup_inventory.py`,
  `tests/test_hl_node_startup_inventory.py`, and this packet only.
- No progress, catalogue or gate changes requested. No target execution.

The checkout's reference submodule directory is empty. The three reference
files were inspected read-only in the already available sibling reference
cache, whose HEAD matches the gitlink. Their SHA-256 identities are:

| Reference path under can1357/hl | SHA-256 |
| --- | --- |
| `node/hl_node.rs` | `70d1cd2fbadac9360287216359c8f7cecfa9dd5c3f702a7177e6ef9c57c26b4d` |
| `node/gossip_config.rs` | `6308d01ba0d3b939fc374ddd7ee44215ce43889311ee1d2777123864ac5aabf8` |
| `node/gossip_rpc.rs` | `2a10096ba1288887e72567452809fab6de28ae61b0ac0add7dbf5ec930a2aee8` |

`research/catalogue/seed-candidates.json` was inspected for those paths. Its
15 `hl_node.rs` seeds coincide with the observed FDE starts, but neither seed
comments nor executable-section membership is used to derive this census.
The l1-evm/action-delayer packets mentioned in the task are absent from this
checkout; the available `tools/info_request_path.py` supplies the methodological
precedent. No existing packet/tool was changed.

## Reproduce

From the repository root, with the pinned artifact available:

```sh
python3 tools/hl_node_startup_inventory.py --out research/work-items/hl-node-startup-inventory-94/
python3 -m unittest tests.test_hl_node_startup_inventory -v
python3 research/work-items/hl-node-startup-inventory-94/verify.py
python3 -O -B research/work-items/hl-node-startup-inventory-94/verify.py
```

The generator uses Python's standard library and the existing MIT
`elf_index.py` and `fde_extents.py` parsers. It has no reference-tree or native
disassembler dependency. Tests require installed `objdump` and `readelf`; their
absence fails the independent checks rather than silently skipping them.
Observed tools: Python 3.13.5, GNU binutils 2.44 on Linux x86-64.
No REA connection was exposed; `make doctor` reported no local Ghidra/Java.
No installation, registration, decompilation, target execution or network
operation was performed.

`--out` writes only the JSON and raw excerpts. It does not refresh the
manifest or documentation, so regeneration cannot silently bless edited
claims. `verify.py` checks an exact manifest whitelist including **RESULT.md**,
rejects missing/duplicate/foreign paths, hashes all listed files, verifies the
binary identity, then demands byte-identical JSON and excerpts. The manifest
also binds the generator, tests and two parser dependencies. `MANIFEST.sha256`
excludes itself to avoid a circular hash; `verify.py` itself is included.

## Evidence and method

All addresses are linked ELF virtual addresses, without a guessed load base.
Explicit file offsets are resolved through PT_LOAD; `.text` offsets are VA
minus `0x1000` for this artifact. FDE ends are exclusive.

1. Authenticate the entire artifact before parsing or writing output. There
   is no CLI digest override. The private structural-analysis function exists
   only to exercise corruption controls beneath authentication.
2. Decode actual CIE augmentation and FDE `pc_range` fields using
   `eh_frame_records`; cross-check every `.eh_frame_hdr` entry against its
   FDE. Reject unsupported encodings, duplicate/unindexed records, overlapping
   ranges and extents outside `.text`. The 121,299 decoded FDEs are a global
   unwind population, not a verified function-coverage denominator.
3. Scan `R_X86_64_RELATIVE` relocations into `.data.rel.ro` for the exact
   48-byte first-party path `/home/ubuntu/hl/code_Mainnet/node/src/hl_node.rs`.
   Require the 24-byte Location layout: relocated pointer, u64 length, u32
   nonzero line and u32 nonzero column. Report every qualifying record,
   including records without LEAs if encountered. Here all 53 have references.
4. Scan `.text` for seven-byte REX.W RIP-relative LEA candidates. Attribute
   only whole instructions within decoded FDE extents. Retain raw instructions,
   relocated Location bytes, relocation entries, CIE/FDE records and range
   hashes. A byte scan alone does not prove instruction starts: the test suite
   cross-checks every reported LEA, call and numeric instruction using linear
   `objdump -d --wide` from each owning FDE start to its decoded end. It also
   checks all 15 ranges against `readelf -wF`. No full CFG/reachability claim.
5. Search `.rodata` for the explicit 16-candidate CLI list. Keep all occurrence
   addresses, even unbound ones. Binding requires exactly one qualifying
   occurrence with a direct scoped LEA and at least one contiguous
   `lea literal,%rsi; mov $length,%edx` pair with the exact candidate length.
   Other scoped LEAs to that occurrence are retained too. No global uniqueness
   assumption, nearest-string association, `undelegate` substring shortcut,
   guessed call closure or reference-source semantics.
6. Diagnostics use exact direct anchors, or a scoped LEA to the whole buffer
   bounded by the preceding/following NUL. The latter records the literal's
   offset and all raw buffer bytes; it does not decode the format language.
   Merely sharing a `.rodata` neighborhood is insufficient.

`startup-inventory.json` gives all records and explicit denominators;
`byte-excerpts.txt` is a deterministic raw-byte rendering with no masks.
`RESULT.md` separates observations, inferences and gaps. Native disassembly
is a second-method test, not the authority for semantic names.

## Implementation, comparison and limitations

No Rust implementation, Cargo manifest/lock, build comparison, behavior
comparison or binary-equivalence result exists for this packet. Before and
after this change those results remain unmeasured. No instruction operands,
relocations or differences are normalized. Raw generator-to-packet comparisons
are exact; this is reproducibility of static evidence, not reconstruction.
Helper closure, indirect calls, vtable/data relationships and whole-ELF
identity of reconstructed code remain unmeasured.

The scope is the exact `hl_node.rs` Location census plus directly co-located
candidate strings. Gossip configuration loading remains unresolved. Optional
non-TCP utility attribution is skipped. `net_utils/src/tcp/**`, TCP frame
reading/compression/chunking, InfoRequest JSON handling, EVM RPC implementation,
DEX registry, rmp_signable, action-delayer and l1-evm packets are excluded.
An FDE may include inlined/shared code from other components; its presence in
this census does not claim exclusive ownership or redo those components.

The suite tests digest rejection and preservation of existing output on error;
Location length/line/LEA corruption; CIE/FDE bounds; CLI bytes and pointer-length
corruption; substring negatives; diagnostic buffer boundaries; call opcode and
destination corruption; packed immediate corruption; manifest allowlist and
RESULT corruption; optimized-Python verification; and two hash-seed directory
regenerations. See RESULT for actual validation outcomes and environmental
failures. No hosted CI or container validation is claimed.

Next bounded question: trace a validated startup call/relocation path to the
`override_gossip_config.json` consumer, retaining its own Locations and exact
string length before assigning a gossip-loader name or any service port.
