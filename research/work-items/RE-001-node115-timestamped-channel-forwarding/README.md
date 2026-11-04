# RE-001: node #115 timestamped channel forwarding and suspension order

- Component: node channel scheduling; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; interval ends are exclusive.
- Measured evidence: three complete FDEs, 1,613 bytes: worker `0x2e071c0`, zero-delay adapter `0x2d4f790`, and sender context `0x2ced920`.
- Scope: receive, timestamp-delay, forwarding and local termination order below. Component gates remain false.

## Finding

This node channel worker holds one received record while it waits for that record's timestamp, then forwards it before requesting another record. It does not scan later messages while that wait is pending. The source Locations bind `node/src/channel.rs` and `net_utils/src/channel.rs`; original public type names and the caller's message purpose remain unresolved.

The receiver is an opaque poll boundary. A nonzero pending byte returns AL=1 and stores outer state **3**. On readiness, a zero record tag requests receiver/sender cleanup and terminates with outer state **1** and AL=0. A nonzero record tag retains the payload, samples the current time, and computes its wait before forwarding.

The record timestamp and sampled time are three dwords. Comparison treats the first as signed and the remaining two as unsigned, in lexicographic order. An earlier record timestamp sets duration to zero without calling the difference helper. Equal or later timestamps call the already documented difference primitive `0x162a290` with record time first and current time second. That primitive's internals are credited context rather than a new claim.

For supplied difference `(seconds: i64, nanos: i32)`, the local code adjusts a negative seconds value with positive nanos to `(seconds+1, nanos-1000000000)`, converts both to binary64 and computes `seconds + nanos/1000000000`. It clamps this value below by zero; the retained comparison also maps an infinity/unordered result to zero. Finite integer helper outputs cannot overflow binary64 in this conversion, so that last check is not evidence of a reachable nonfinite duration. Timestamp producer validity and the date helper's complete domain remain outside this packet.

The wait adapter has a useful exact shortcut: **either sign of zero skips the nested wait**. A nonzero delay polls its nested wait. A pending wait returns AL=1 and stores worker state **4**. The outer jump table resumes state4 directly at that wait, without receiving another record, resampling the clock, or recomputing the duration.

Once waiting is ready, the worker calls the sender and continues only for raw result **5**. The retained sender context binds that value to its ordinary reservation/enqueue path; its closed-bit path returns raw **0**. Any worker-observed sender result other than 5 takes cleanup and terminal state1. This establishes a local call and continuation contract, not scheduler fairness, physical delivery, or receiver consumption.

| Boundary | Worker result |
| --- | --- |
| Receive pending | State3, AL=1; no clock sample or forwarding |
| Receive ready with record tag0 | Cleanup, state1, AL=0 |
| Received timestamp earlier than now | Zero delay; difference helper skipped |
| Computed zero delay | Nested wait skipped |
| Wait pending | State4, AL=1; held record retained |
| Wait ready, sender raw5 | Loop to receive next record |
| Wait ready, sender other tag | Cleanup, state1, AL=0 |

The actual jump table, zero-delay branch, mixed comparisons, helper bindings and result bytes are retained. Corruption controls and relations distinguish signed timestamp ordering, exact raw5 continuation and the zero-delay shortcut. Relations supply receiver/wait outcomes and date differences explicitly; they do not fabricate a receiver or timer implementation. Destructor effects, exceptional exits, invalid state tags, races, and operational timing remain unresolved.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-timestamped-channel-forwarding/export_disassembly.py
python3 research/work-items/RE-001-node115-timestamped-channel-forwarding/verify.py --controls
python3 research/work-items/RE-001-node115-timestamped-channel-forwarding/relations.py
python3 -m unittest discover -s tests -p 'test_node115_timestamped_channel_forwarding.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-timestamped-channel-forwarding/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The all-state audit is in `scope-audit.json` and `pr-census.json.bz2`. [PR #2857](https://github.com/lalalune/hyperliquid-source/pull/2857) owns the date-difference primitive. [PR #30](https://github.com/lalalune/hyperliquid-source/pull/30) and [PR #2060](https://github.com/lalalune/hyperliquid-source/pull/2060) wait before conditional process exit; [PR #2117](https://github.com/lalalune/hyperliquid-source/pull/2117) sets a greeting-send timeout. [PR #2568](https://github.com/lalalune/hyperliquid-source/pull/2568) handles RPC store updates, and [PR #2342](https://github.com/lalalune/hyperliquid-source/pull/2342) serializes a delayed action result. None of those claims establishes this per-record timestamp-gated channel forwarding contract.

The audit inspected open and closed PR metadata and available patches, including prior releases. GitHub omits many patches and caps a large historical PR's file list; these limitations are recorded. This is a bounded finding at the stated snapshot, not a guarantee about unpublished work or future submissions.

New analysis and verification are independently authored under the repository MIT license. Generic export/parsing/checking helpers adapt existing MIT research packets, especially registry-row-labels and quote-midpoint-product-guard. No unlicensed inferred source was copied. Binary and imported-reference rights remain unchanged. There is no source-to-target equivalence, full component completion or hosted-CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
