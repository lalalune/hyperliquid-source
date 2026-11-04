# RE-001: node #115 outcome account settlement projection

- Component: outcome settlement account projection; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Complete projection `0x38da9e0..0x38daf71`, plus five enclosing caller/collection FDEs. Exclusive ELF VA ends in `records.json`; all full-scope gates remain false.

## Finding

The settlement routine's already-known coarse conversion supplies `c` and `1000-c` to an account projection. The separate fine weights used elsewhere in the caller are not these inputs. The context pointer chain is retained through `0x3bf2be0 → 0x3c6dac0 → 0x3d9c7d0 → 0x3ebf870 → 0x3914680 → 0x38da9e0`. The sequential folder passes each112-byte source row and its20-byte address at row+0x58 to the projection. Parallel scheduling and collection ordering outside that folder remain opaque.

The projection first excludes either of two special20-byte addresses. Each is `0x32`, eleven zero bytes, and the corresponding token identifier encoded as big-endian u64. Exact byte equality skips that account before any balance lookup. Changing any address byte removes that equality, subject to equality with the other excluded address.

For the first token, a missing map entry supplies total=held=0. A found entry supplies its total and held qwords. The local available value is `max(total-held,0)`; an underflow reaches a diagnostic callback before continuing with zero if that callback returns. The available value must equal total or the projection returns raw error19. Under valid balance invariants this requires held=0. It is not precisely the predicate `held==0` for malformed inputs: total0/held1 would compare zero with zero after the diagnostic. The packet preserves this distinction without claiming that malformed state occurs.

A positive first total appends a logical `(first token,total)` row. The projection then computes `total*c` with unsigned64 checked multiplication; a nonzero high product word returns raw error14. Only after that succeeds does it look up and apply the same available-equals-total gate to the second token, append its positive total, and check `second_total*(1000-c)`. Thus the first product overflow wins over an error in the second token's balance. Failed projections discard their temporary rows rather than returning a partial success vector.

After both products succeed, their sum is checked. Overflow calls the quantity diagnostic; **if it returns**, continuation saturates the sum to `U64_MAX`. There is no division after these integer multiplications. A positive sum appends a third row using the destination identifier from the caller's previously matched pair-lookup qword. Token denomination and the later application of these rows are not inferred here.

For ordinary unlocked balances `A` and `B`, the arithmetic before overflow handling is:

`payout = A*c + B*(1000-c)`

Rows appear in first-token, second-token, destination order, omitting zero quantities. Even equal identifiers are not coalesced by this projection. If no row remains, the result is the skip niche `0x8000000000000001`; the folder does not append it. A nonempty success also returns the two original totals. An error uses the separate `0x8000000000000000` niche plus its raw error byte. Uninitialized inactive payload bytes are outside the claim.

| Input condition | Local projection result |
| --- | --- |
| Address equals either constructed token address | skip, no lookup |
| First token held balance makes available differ from total | error19 before second lookup |
| First checked product overflows | error14 before second lookup |
| Second balance/product fails | error19/14 after first checks |
| Both totals zero | skip |
| Positive total but its weight is zero | original token row retained; zero payout row omitted |
| Products each fit but their sum overflows | diagnostic, then saturating payout if callback returns |

## Validation and limits

The six complete bodies bind the coarse-weight context and the projection's full control flow. Relations use explicit lookup results, compare u64 low/high product handling with independent unbounded integer arithmetic, cover weight endpoints and nearby overflow limits, and distinguish early errors and exact20-byte exclusions. Four changed native instruction operands distinguish the address prefix, held-balance gate, product-overflow branch and sum saturation value.

This is a pure row projection. It does not mutate balances, prove redemption succeeds, reconstruct generic map lookup/balancing or Rayon scheduling, or establish diagnostic callbacks always return. The mathematical relation uses valid native descriptors and successful allocation. Noncanonical subtraction and sum-overflow continuation are conditional on the recorded diagnostic call returning. No captured code is executed or emulated.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Four changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-outcome-account-settlement-projection/export_disassembly.py
python3 research/work-items/RE-001-node115-outcome-account-settlement-projection/verify.py --controls
python3 research/work-items/RE-001-node115-outcome-account-settlement-projection/relations.py
python3 -m unittest discover -s tests -p 'test_node115_outcome_account_settlement_projection.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-outcome-account-settlement-projection/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

[PR #2885](https://github.com/lalalune/hyperliquid-source/pull/2885) owns the dual coarse/fine fraction conversion and entry prerequisites; it expressly leaves downstream account projection opaque. [#1859](https://github.com/lalalune/hyperliquid-source/pull/1859) and [#997](https://github.com/lalalune/hyperliquid-source/pull/997) cover outer settlement collection/admission while excluding this body. [#460](https://github.com/lalalune/hyperliquid-source/pull/460), [#454](https://github.com/lalalune/hyperliquid-source/pull/454) and [#419](https://github.com/lalalune/hyperliquid-source/pull/419) cover different outcome operations and generated pricing.

[#1155](https://github.com/lalalune/hyperliquid-source/pull/1155) supplies general total/held balance context. [#1163](https://github.com/lalalune/hyperliquid-source/pull/1163) recovers a different spot payout using proportional floating shares, dust and ordering. Those are credited predecessors, not claims repeated here. The new boundary is the account projection's reserved-address exclusions, coarse integer weights, error precedence and logical row output.

GPT-6.1 Terra searched all-state PR metadata and available file evidence. Inaccessible historical content and missing patches limit an absolute uniqueness guarantee. New analysis and relations are independently authored under MIT; evidence/export scaffolding reuses existing MIT packets. No unlicensed inferred source, full source equivalence, imported-rights changes or hosted CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
