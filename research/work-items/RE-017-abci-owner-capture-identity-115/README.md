# RE-017: distinguish the two node-115 ABCI task owner captures

- Component ID: `abci`; bounded subquestion of #3923's state-root handoff.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`; no external source code or reference binary is used.
- Question: the existing compact-root packet leaves open whether the root/apply owner captured at task `+0x78` and the result-write owner captured at `+0xa8` may alias. What are their origins at the node-115 task constructor?
- Claim status: instruction bytes, FDE extents, the relative relocation, and task-field stores are observations. The separate-allocation identity conclusion is conditional on a valid live first owner, successful second allocation, and the node allocator's non-overlap contract.
- Scope: one parent FDE, the task constructor FDE, and the selected allocator fast path. It does not establish scheduler execution, dynamic pointer values, every allocator refill path, later indirect alias mutation, or a complete ABCI component gate.

## Reproduce

Run from the repository root with the pinned node artifact, Python 3.14.3 and Capstone 5.0.7:

```sh
git submodule update --init --recursive
python3 tools/abci_owner_capture_identity115.py --out research/work-items/RE-017-abci-owner-capture-identity-115
python3 -m unittest tests.test_abci_owner_capture_identity115 -v
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_owner_capture_identity115.py --out work/owner-capture-repro/one
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_owner_capture_identity115.py --out work/owner-capture-repro/two
diff -r work/owner-capture-repro/one work/owner-capture-repro/two
diff -r --exclude=README.md --exclude=analysis.log --exclude=MANIFEST.sha256 research/work-items/RE-017-abci-owner-capture-identity-115 work/owner-capture-repro/one
(cd research/work-items/RE-017-abci-owner-capture-identity-115 && sha256sum -c MANIFEST.sha256)
```

The generator authenticates the full #115 file size and SHA-256, validates each selected FDE against `.eh_frame` and `.eh_frame_hdr`, decodes the three selected extents, checks instruction-aligned anchors and reads the allocator and constructor relative relocations. `evidence.json` and `anchors.tsv` contain the machine-readable result and exact VA/file-offset/byte anchors. The generator makes no subprocess calls and executes no captured program. GNU objdump 2.47 is optional for human inspection only. There is no network, signing, key, chain or runtime effect.

The focused tests include a valid-target check, a wrong-digest rejection, three instruction-byte mutation controls with the digest repinned to force semantic validation, and a changed-context-projection control.

## Evidence

Addresses are link-time ELF virtual addresses before rebasing; `anchors.tsv` records file offsets and exact bytes. The selected FDEs are `0x2cb6500..0x2cbbbdf` (parent), `0x5a6cbc0..0x5a6cfa7` (task constructor), and `0x6355830..0x63558f2` (small allocator). FDEs are unwind extents, not proof of source function boundaries or complete control flow.

### Existing root/apply owner (`P1`)

The prior [compact-root packet](../RE-017-abci-compact-root-115/README.md) traces an incoming pointer at parent input `+0xdd8` through four checked stack-copy stages to parent object `+0x840`; its `parent_projection.tsv` is revalidated byte-for-byte by this tool and hashed into `evidence.json`. At `0x2cb8863`, the parent loads `[rbx+0x840]` into `rsi`; at `0x2cb886a` it increments the pointed-to qword on the selected positive branch, then retains `rsi` through the constructor call.

### Separate result-write owner (`P2`)

At `0x2cb865d` the parent sets `edi=0x6f0` and calls indirectly through slot `0x64df480`. Its `R_X86_64_RELATIVE` relocation resolves to `0x6355830`. On the selected small-allocation path the allocator rounds the request to an eight-byte size class, reads a pointer from the class cursor, advances that cursor, and returns the selected pointer. Cursor exhaustion branches to the larger refill routine at `0x6353a70`, which is outside this packet's full semantic analysis.

The parent preserves that return in `r15`, copies `0x6f0` bytes from its stack staging area through slot `0x64df508` (the `R_X86_64_GLOB_DAT` entry for `memcpy`), and stores the returned pointer in parent field `+0xae8` at `0x2cb868d`. At `0x2cb8887`, it reloads `[rbx+0xae8]` into `rdx`.

### Constructor and result

At `0x2cb8915`, the parent calls through slot `0x64e7458`, whose relative relocation names constructor `0x5a6cbc0`; `rsi` still holds `P1` and `rdx` holds `P2`. The constructor saves those inputs separately and copies a `0xb8`-byte task record. Its selected stores place `rsi` at task `+0x78` and `rdx` at task `+0xa8`, matching the two owner loads already mapped in the compact-root callback.

The two task captures therefore have separate origins: `P1` is an existing retained pointer copied through the parent projection; `P2` comes from a second allocation performed while constructing that parent. Under a valid live-owner path and the allocator's non-overlap contract, they are distinct allocations and cannot be equal. This resolves the alias question for the two owner objects on that path. Consequently the result-write owner's direct `+0x6b0` update should not be joined to the root/apply owner's `+0xb00` field as though both offsets belonged to one owner allocation.

The conclusion is not a runtime pointer observation. The allocator's selected fast path is pinned, but refill semantics, scheduler execution, the full lifetime proof for every exceptional path, pointer contents shared between the two objects, and any later writes through other aliases remain outside scope. No state-root digest or persistence claim is made, and no component gate is advanced.

## Results and limitations

The new evidence closes the static origin distinction asked by the prior packet's next-step note. The remaining dependency is the allocator's slow-refill/lifetime path and any cross-object references; these are not required to state that the constructor receives the two independently sourced owner arguments on the selected normal path. Reproduce the evidence and test controls above. Keep the broader RE-017/RE-009 gates false.

The pinned submodules were materialized with `git submodule update --init --recursive`; their gitlink commits remain unchanged. `make verify` passed: #115 and visor hashes/signatures, 32 imported files, 4,618 evidence-packet manifests and 33,616 entries. `make catalogue-check` passed. The generator was also run under two hash seeds/time zones; both outputs matched each other and the durable packet files. The full `make test` result is recorded after the command completes.
