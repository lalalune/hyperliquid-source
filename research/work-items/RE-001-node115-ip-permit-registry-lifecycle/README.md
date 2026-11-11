# RE-001: node #115 IP permit registry creation, reuse and pruning

- Component: network permit registry; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses, exclusive interval ends.
- Evidence: five complete FDEs, 3,805 bytes; boundaries and digests are in `records.json`.
- Scope: keyed semaphore lifecycle before acquisition. Cadence internals, generic map algorithms and concurrent runtime behavior remain unresolved. All component gates stay false.

## Finding

The provider `0x47849c0` locks the owner, calls an opaque cadence helper, and conditionally prunes its map **before** looking up the requested 17-byte key. Both prune and get-or-create receive the current configured limit at owner `+0x28`. The map starts at owner `+8`.

The entry routine `0x476fb90` handles occupied raw tag 2 before reading the limit. It returns the existing semaphore slot unchanged. For a missing entry it reads the limit, rejects any value with a nonzero `limit >> 61`, allocates a 56-byte Arc-backed object, initializes strong and weak counts to one, clears queue fields and writes `2 * limit` to packed state `+0x30`. Thus the observed configuration is applied on creation; an occupied key does not get resized on this path.

The prune dispatcher `0x476c260` supports flat and tree maps. Both use the same criterion: **remove when `(packed_state >> 1) == current_limit`**. The flat path `0x476aea0` compacts unequal rows and drops the removed Arc references. The tree iterator `0x4765b30` decrements map count and invokes its removal helper on equality. The low closed-state bit is discarded by the shift. No test of age or stored original capacity appears in this criterion.

These observations explain a configuration-sensitive distinction without assuming configuration changes occur at runtime: an entry created with limit 3 and state 6 is retained by a prune using limit 4; an entry with state 4 is removed by a prune using limit 2. The policy compares current availability with the current limit. The relations retain these cases, closed-bit variants and the valid creation boundary. They stop before acquisition.

After retrieval the provider clones the Arc and performs the already documented packed permit operation: reject closed bit 1, require state at least 2, and atomically subtract 2. That operation is credited context. The lock, timing samples, cleanup, tree-to-flat conversion and generic collection helpers are visible in complete exports but are not claimed as newly recovered algorithms.

| Native interval | Observation |
| --- | --- |
| `0x4784a94..0x4784ac2` | Cadence result controls prune before key lookup |
| `0x4784ac2..0x4784af3` | 17-byte key; configured limit passed to entry helper |
| `0x476fba2..0x476fbc9` | Occupied return precedes reading limit |
| `0x476fbc9..0x476fc11` | Missing-entry limit bound and packed initialization |
| `0x476aefb..0x476af16`, `0x476af78..0x476afa0` | Flat removal/retention predicate |
| `0x4765b9e..0x4765bb6`, `0x4765c83..0x4765cb4` | Same tree predicate and removal |

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-ip-permit-registry-lifecycle/export_disassembly.py
python3 research/work-items/RE-001-node115-ip-permit-registry-lifecycle/verify.py --controls
python3 research/work-items/RE-001-node115-ip-permit-registry-lifecycle/relations.py
python3 -m unittest discover -s tests -p 'test_node115_ip_permit_registry_lifecycle.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-ip-permit-registry-lifecycle/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The available-history audit is in `scope-audit.json` and `pr-census.json.bz2`. [PR #974](https://github.com/lalalune/hyperliquid-source/pull/974) covered packed semaphore acquisition and left keyed count/expiry policy open. New [PR #2883](https://github.com/lalalune/hyperliquid-source/pull/2883) implements that packed capacity/CAS primitive and likewise leaves provider and lifecycle behavior open; it is credited context, outside this claim. [PR #2824](https://github.com/lalalune/hyperliquid-source/pull/2824) left this provider opaque. [PR #2417](https://github.com/lalalune/hyperliquid-source/pull/2417) concerned conditional refund. This packet answers creation, reuse and prune-selection policy; it does not claim the older acquisition primitive or a time-based expiry policy as new.

The audit includes open and closed PR metadata and available patches. Missing patches and a capped historical file list are recorded limitations; unpublished work and future submissions are not covered.

New analysis and verification are independently authored under the repository MIT license. Generic verification/export helpers adapt existing MIT packets. No unlicensed inferred source was copied. Captured binary and imported-reference rights are unchanged. There is no runtime equivalence, full component completion or hosted-CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
