# RE-001: node #115 RPC batch cost includes count and per-payload framing

- Component: RPC batch cost; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; interval ends are exclusive.
- Evidence: 5 complete FDEs, 1,061 bytes; boundaries/digests in `records.json`.
- Scope: the bounded policy below with unresolved helpers retained. All component gates remain false.

## Finding

The cost wrapper `0x5861e30` starts a u64 counter at zero and passes it through `0x5b569b0`. After a successful header call, that body counts the payload vector length and then each payload's length prefix plus its raw length. On the successful, non-overflowing path the result is:

`H + V(number_of_payloads) + sum(V(length_i) + length_i)`

Here **H is the counter contribution of the header helper**, and `V(x)` is 1 for x < 251, 3 for x < 65536, 5 for x < 2^32, and 9 otherwise. The primitive `0x5822850` that establishes these widths is prior work and is included as supporting context.

The payload loop reads the pointer array at input `+0x180`, its count at `+0x188`, and each pointed record's qword `+0x20`. It does not read payload content. Equal header contribution and equal payload lengths therefore give equal projected costs regardless of payload bytes under these premises. A zero-length payload still contributes its one-byte length prefix; an empty vector still contributes its count prefix. Crossing 250 to 251 adds both one payload byte and two extra prefix bytes.

Header context is bounded too. `0x5829040` passes eight qwords from input `+0x130..+0x168` to `0x59680a0`; that routine counts each using V and adds one fixed byte. It then calls **opaque** `0x5966e40` on the remaining header representation. Consequently H includes `sum(V(eight_words)) + 1` plus an unresolved contribution. This packet does not claim a complete serialized header size, codec field names, RPC units, or a whole wire format.

Every count helper's raw success tag 8 is checked before proceeding. Payload length is added with a carry/overflow branch before storing the new counter. Ordinary non-success results propagate out of the inner body. The outer wrapper dispatches their cleanup through an eight-entry table, then returns the accumulated counter; raw tag 8 returns directly. A panic/abort path does not return a partial successful value. The inherited varint helper can update its marker count before a later overflow panic, so exact panic-state counters are not modeled.

| Native interval | Observation |
| --- | --- |
| `0x5861e34..0x5861e6f` | Zero counter and inner counting call |
| `0x5b569c4..0x5b56a08` | Header must succeed before vector count and iteration |
| `0x5b56a20..0x5b56a59` | Length prefix followed by checked raw length addition |
| `0x5829052..0x58290af` | Fixed header prefix followed by opaque header remainder |
| `0x59680a0..0x59681cb` | Eight u64 counts and one-byte tail |

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-rpc-batch-cost-framing/export_disassembly.py
python3 research/work-items/RE-001-node115-rpc-batch-cost-framing/verify.py --controls
python3 research/work-items/RE-001-node115-rpc-batch-cost-framing/relations.py
python3 -m unittest discover -s tests -p 'test_node115_rpc_batch_cost_framing.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-rpc-batch-cost-framing/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The all-state audit is in `scope-audit.json` and `pr-census.json.bz2`. [PR #2620](https://github.com/lalalune/hyperliquid-source/pull/2620) established the batch caller while leaving its cost helper opaque. [PR #2257](https://github.com/lalalune/hyperliquid-source/pull/2257) established the exact varint count primitive. This packet credits that primitive and adds the batch-specific composition, metadata offsets and error/overflow boundaries. Header remainder semantics stay unresolved.

The audit covers open and closed PR metadata and available patches. Missing patches and a capped historical file list are recorded limitations; unpublished work, alternative terminology and future submissions are not ruled out.

New analysis and verification are independently authored under the repository MIT license. Generic parsing/export/checking helpers adapt existing MIT packets. No unlicensed inferred source was copied. Binary and reference rights remain unchanged. There is no runtime equivalence, full component completion or hosted-CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
