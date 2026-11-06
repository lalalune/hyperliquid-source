# RE-001: node #115 outbound IPv4 validation occurs after connection success

- Component: outbound connector; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; interval ends are exclusive.
- Measured evidence: one complete FDE, `0x5ab3b90..0x5ab4386`, 2,038 bytes. Body digest, calls, data and imports are in `records.json`.
- Scope: the address-validation ordering below. Component gates remain false.

## Finding

The outbound connector saves the original 32-byte address at owner offsets `+0x20..+0x3f` before its connect state machine. It checks that saved representation **only after the underlying connection produces a successful stream**. A pending result (raw `3`) or an ordinary connection error (raw `2`) bypasses this address check. Thus this is not an early input filter that prevents every attempt for a non-IPv4 address.

On success, `cmp byte [owner+0x20], 0` selects two paths:

| Saved raw variant | Native result |
| --- | --- |
| `0` | Read u32 at `+0x22` and u16 at `+0x26`; pass them and the stream to the existing constructor at `0x4784d00` through relocation slot `0x64e7540`. |
| Nonzero | Build the exact nine-byte error `ip not v4`; call cleanup helper `0x4ee5320`; call imported `close` when the stream descriptor is not `-1`; call cleanup helper `0x5a518e0`; publish raw error `2`. |

The diagnostic and the four-byte/two-byte arguments support identifying raw variant 0 as the IPv4/port representation at this boundary. They do not recover the full producer enum, all possible variants, DNS or address-resolution behavior. The error's nine-byte length is explicit at `0x5ab415a`; adjacent printable bytes are not part of that message.

The completed paths set owner byte `+0xe8` to `1`. The pending publication writes output qword `3` and sets that owner byte to `3`. Cleanup helpers are call boundaries with unresolved effects. The `close` import and descriptor guard are authenticated; successful close, release timing, concurrency and cancellation guarantees are not claimed.

| Native interval | Observation |
| --- | --- |
| `0x5ab3bc5..0x5ab3bf4` | Save original address before underlying connection work |
| `0x5ab3fdb..0x5ab403b` | Pending/error and socket-error query context |
| `0x5ab411a..0x5ab4136` | Connection error converts and returns before variant check |
| `0x5ab4136..0x5ab4192` | Successful stream, variant check, bounded error, cleanup and guarded close |
| `0x5ab4192..0x5ab41f5` | IPv4/port arguments to existing statistics constructor |
| `0x5ab41f5..0x5ab4253` | Completed versus pending publication |

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-outbound-connect-ipv4-validation/export_disassembly.py
python3 research/work-items/RE-001-node115-outbound-connect-ipv4-validation/verify.py --controls
python3 research/work-items/RE-001-node115-outbound-connect-ipv4-validation/relations.py
python3 -m unittest discover -s tests -p 'test_node115_outbound_connect_ipv4_validation.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-outbound-connect-ipv4-validation/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The all-state audit is in `scope-audit.json` and `pr-census.json.bz2`. [PR #1606](https://github.com/lalalune/hyperliquid-source/pull/1606) inventoried the diagnostic. [PR #582](https://github.com/lalalune/hyperliquid-source/pull/582) and [PR #604](https://github.com/lalalune/hyperliquid-source/pull/604) covered similar rejection on incoming accepts. [PR #1672](https://github.com/lalalune/hyperliquid-source/pull/1672) covered an initial IPv4 connect boundary, and [PR #1697](https://github.com/lalalune/hyperliquid-source/pull/1697) covered the statistics constructor under a fresh-IPv4 premise. This packet resolves the outbound post-connect validation and cleanup ordering; those earlier claims and the generic connect state machine are context.

The audit inspected open and closed PR metadata and available patches, including prior releases. GitHub omits many patches and caps a large historical PR's file list; these limitations are recorded. This is a bounded finding at the stated snapshot, not a guarantee about unpublished work or future submissions.

New analysis and verification are independently authored under the repository MIT license. Generic export/parsing/checking helpers adapt existing MIT research packets, especially registry-row-labels and quote-midpoint-product-guard. No unlicensed inferred source was copied. Binary and imported-reference rights remain unchanged. There is no source-to-target equivalence, full component completion or hosted-CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
