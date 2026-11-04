# RE-001: node #115 consensus address-count admission before worker creation

- Component: consensus server admission; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; interval ends are exclusive.
- Measured evidence: complete FDE `0x29f7280..0x29f7780`, 1,280 bytes.
- Scope: the count threshold, exact loopback exception and count-store ordering below. Component gates remain false.

## Finding

The consensus admission wrapper obtains a mutable count through entry helpers while holding its visible registry lock. It rejects a count **at least 2**, except when the projected address is the exact IPv4 loopback value. The immediate address word is `0x0100007f`, corresponding to bytes `127.0.0.1`; the exception also requires the address variant's low bit to be zero. Neither the full 127/8 range nor IPv6 loopback is exempted by this comparison.

On rejection, the wrapper releases the lock, requests cleanup of its captures and returns. It does not write the count or invoke the worker-creation helper. On admission, it computes **min(U64_MAX, count+1)**, stores the result through the returned count pointer, releases the lock, and only then calls worker helper `0x2b13a30`. The saturation is visible as INC followed by a zero-sensitive CMOV, not an unchecked wrap to zero. In particular, the exempt address can retain U64_MAX at this local boundary.

| Count | Projected exact IPv4 loopback? | Local result |
| --- | --- | --- |
| 0 or 1 | Either | Increment, unlock, worker handoff |
| 2 or more | No | Unlock and cleanup; no increment or handoff |
| 2 or more | Yes | Saturating increment, unlock, worker handoff |

The registry entry input is a raw address descriptor plus a separate u16 context. The stack descriptor has a variant byte at `+0`, projected address beginning at `+1` (up to 16 bytes), padding at `+0x11`, and a u16 at `+0x12`. The latter comes from input `+0x90`. Inactive IPv4 tail bytes are not all initialized by this function. The opaque lookup decides which bytes participate in equality; this packet does not invent a contiguous byte-key comparison or call the u16 a port. It consequently does not claim a global per-IP limit independent of that context.

The admitted capture retains the projected address and context for the later worker. Actual worker execution, eventual decrement/removal, complete ownership/drop behavior, lock implementation and race guarantees remain unresolved. A successful local count store is not proof of an established or eventually delivered connection.

| Native interval | Observation |
| --- | --- |
| `0x29f7346..0x29f73c4` | Address fields and variant projection |
| `0x29f73d0..0x29f7434` | Lock, key descriptor, entry helper and count pointer |
| `0x29f7434..0x29f7468` | Exact address and unsigned count-two gate |
| `0x29f74f3..0x29f7513` | Saturating count store before unlock |
| `0x29f7652..0x29f7676` | Capture completion and worker creation call |

Relations enumerate all 256 supplied variant bytes, neighboring addresses, threshold and saturation boundaries. The variant-byte tests describe the machine predicate only; normal source-level variants are not broadened. Three actual operand changes distinguish an off-by-one threshold, incorrect loopback literal and wrapping increment. The full native export retains cleanup and slow-lock paths as context.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-consensus-address-count-admission/export_disassembly.py
python3 research/work-items/RE-001-node115-consensus-address-count-admission/verify.py --controls
python3 research/work-items/RE-001-node115-consensus-address-count-admission/relations.py
python3 -m unittest discover -s tests -p 'test_node115_consensus_address_count_admission.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-consensus-address-count-admission/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The all-state audit is in `scope-audit.json` and `pr-census.json.bz2`. [PR #2628](https://github.com/lalalune/hyperliquid-source/pull/2628) covers a later listener's peer-address authorization and request-class budgets. [PR #502](https://github.com/lalalune/hyperliquid-source/pull/502) and [PR #1954](https://github.com/lalalune/hyperliquid-source/pull/1954) concern configurable global gossip peer counts, while [PR #974](https://github.com/lalalune/hyperliquid-source/pull/974) covers a packed permit primitive. [PR #582](https://github.com/lalalune/hyperliquid-source/pull/582) and [PR #604](https://github.com/lalalune/hyperliquid-source/pull/604) cover socket accept/IPv6 behavior. Those claims do not establish this count-two exception and store-before-worker contract.

The audit inspected open and closed PR metadata and available patches, including prior releases. GitHub omits many patches and caps a large historical PR's file list; these limitations are recorded. This is a bounded finding at the stated snapshot, not a guarantee about unpublished work or future submissions.

New analysis and verification are independently authored under the repository MIT license. Generic export/parsing/checking helpers adapt existing MIT research packets, especially registry-row-labels and quote-midpoint-product-guard. No unlicensed inferred source was copied. Binary and imported-reference rights remain unchanged. There is no source-to-target equivalence, full component completion or hosted-CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
