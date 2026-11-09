# Node 115 post-transfer scalar redistribution

Task **RE-001**, component **vaults**, partial evidence for issue **#3925**.
The issue remains open. No acceptance or component gate changes.

The prior [value-transfer packet](../RE-001-node115-vault-value-transfer/README.md)
binds the admitted value-transfer path to `0x44ad9e0` but leaves this helper's
rescaling behavior unresolved. This packet follows that handoff through the
actual numeric calculation, the temporary keyed values, and the final write to
the original in-memory map payload. It supplies an independently authored,
dependency-free Rust **scalar kernel**, not a vault implementation.

## Input identity and method

| Item | Identity |
| --- | --- |
| Target | `artifacts/node/115/hl-node`, 105,896,032 bytes |
| SHA-256 | `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` |
| Publication base | `0781ce04826eeefd89fe336cb8ea073be0c1de30` |
| Coordinates | ELF virtual addresses; enclosing `.eh_frame` FDE boundaries |
| Static tools | Python 3.14.7, Capstone 5.0.7; original pinned ELF parser reused |
| Rust tools | rustc 1.95.0, cargo 1.95.0 (independent checks; initial author checks used 1.93.1) |
| Reference arithmetic | Python standard-library integers and `fractions.Fraction`; no host float arithmetic |

The retained eight windows contain **6,456 bytes / 1,502 instructions**.
The verifier authenticates the complete target, window digests, instruction
boundaries and retained rows, then checks **183 semantic facts**. All **28
in-memory corruption controls** are rejected by the semantic checks with global
digest/window comparisons deliberately bypassed. No target code was executed,
emulated, linked into the Rust crate, or copied as an implementation.

## Numeric contract

Name the signed `RCX` input `prior`, signed `RDX` input `delta`, original scalar
`w`, and whether its 20-byte key is the caller's selected key `selected`. These
names describe arithmetic roles; they do not establish business units or share
ownership. Under the floating-point premises below, the selected calculation is:

```text
t = saturating_i64_add(prior, delta)
d = binary64(max(t, 0)) / 1_000_000.0
p = binary64(prior) / 1_000_000.0
n = w * p
if selected: n = n + binary64(delta) / 1_000_000.0
if n < 1e-7 or n is nonfinite or d < 1e-15: result = +0.0
else:
    q = n / d
    result = +0.0 if q is nonfinite else q
```

Every conversion and arithmetic operation rounds separately. Algebraically
cancelling the million-scale divisions, adding converted quantities before
integer saturation, or fusing the multiplication and addition changes results.
The strict numerator comparison retains a value exactly equal to the stored
binary64 representation of `1e-7`.

The native denominator guard also rejects `+infinity` and unordered values;
those cannot arise from the clamped `i64` input. After admission the numerator
and denominator are positive and finite. The native final `ucomisd q,+inf; jne`
keeps a finite quotient and converts `+inf`/unordered to positive zero. The Rust
finite-result check is equivalent on this admitted domain; no claim is made for
injecting arbitrary values directly into an interior instruction.

## Actual caller, staging, and writeback

1. At `0x44aee1e–0x44aee4c`, the earlier value-transfer caller copies the selected
   20-byte key, forwards owner `RBP`, delta `R13`, and prior quantity `R12`, and
   calls `0x44ad9e0`. The helper preserves the arguments. Its signed overflow
   branch at `0x44ae2a5` chooses the `i64` endpoint and, on normal return from
   the diagnostic callback, rejoins the positive clamp. A positive-delta prelude
   calls `0x44a9430`; its normal return is a premise, not a reconstructed check.
2. `0x44add10–0x44add41` computes `d` and `p`. The original map is at `owner+0x50`.
   Its flat iterator uses 72-byte rows. The capture at iterator offset `0x48`
   points to `p`; `0x44ade1e` calls `0x3bcc440`, which calls `0x3dda220`.
3. In that transform, the flat row's scalar is at `row+0x18`. The first and
   remaining item paths at `0x3dda373` and `0x3dda49a` multiply it by the captured
   `p`, retain the 20-byte key, and emit 32-byte temporary rows with `n` at
   `row+0x18`. The enclosing collection constructors and tree iteration remain
   prerequisites; this crate does not reconstruct map allocation or sorting.
4. The selected-key lookup is `0x44ade30 → 0x3cd3dd0`. The entry accessor
   `0x44ade3a → 0x3f170d0` returns the temporary scalar pointer; its vacant paths
   supply a positive-zero default to insertion helpers. At `0x44ade42–0x44ade53`
   the helper converts and divides `delta`, adds it to that scalar, and stores
   it. For an absent selected key the Rust caller supplies `prior_weight=0.0`;
   insertion and key matching are outside the source API.
5. The following loop reads each temporary 20-byte key and numerator. Tree
   values are selected at `0x44adf62`; flat values at `0x44adfd0`. The guards
   and division run at `0x44adff4–0x44ae045`. All four referenced literals are
   pinned by both RIP targets and raw binary64 bytes:

   | Address | Bits | Meaning |
   | --- | --- | --- |
   | `0x4599a0` | `412e848000000000` | `1_000_000.0` |
   | `0x459920` | `3e7ad7f29abcaf48` | rounded `1e-7` |
   | `0x459ba0` | `3cd203af9ee75616` | rounded `1e-15` |
   | `0x459010` | `7ff0000000000000` | positive infinity |

6. `0x44ae056 → 0x3cd3550` receives the same copied key and original map
   `owner+0x50`. `0x44ae097 → 0x3f19c20` returns its payload pointer. Its occupied
   flat path computes a wrapped physical index, a 72-byte row, and offset
   `0x18`; its occupied tree path uses a 48-byte payload stride. The caller's
   `movsd [rax],xmm0` at `0x44ae0a2` replaces only the first eight bytes of the
   returned payload, then advances to the next temporary item. This is an
   **in-memory scalar write**, not evidence of storage durability.

These call/dataflow observations support the numeric API's context. They do not
prove search correctness, all tree layouts, constructor behavior, or preservation
of surrounding fields by every delegated helper. Valid collections, appropriate
entry results, and normal helper returns are explicit premises.

## Source and independent numerical validation

The source at `src/node115-vault-redistribution/lib.rs` contains one `no_std`,
unsafe-forbidden function. It operates on typed scalar inputs; it neither stubs
out map helpers nor pretends to supply admission, a ledger, or a node workspace.

`rational-reference.py` reconstructs finite binary64 values as exact rationals,
rounds each operation to nearest/ties-to-even using integer division, and handles
subnormal rounding, signed zero, overflow, NaN and infinity classification. It
does not reuse the Rust implementation or host floating-point arithmetic.
Self-checks include midpoint ties, normal/subnormal round trips, underflow and
the finite-to-infinity rounding boundary. NaN payload identity is not asserted;
all such inputs are rejected by the native numeric guard.

The retained fixture has **18,432 cases**: 24 prior quantities × 16 deltas × 24
raw scalar bit patterns × 2 selected-key flags. It includes both signed integer
saturation endpoints, values around `2^53`, numerator threshold neighbors,
subnormals, signed zero, maximum finite values, infinities and NaNs. Rust debug
and release tests compare all output bits to this independently generated table.
Three test functions also explicitly exercise the selected addition and guard
behavior. All passed, as did formatting and Clippy.

The same denominator is used for five changed reference calculations; each
produces mismatches:

| Changed calculation | Differing cases / 18,432 |
| --- | ---: |
| Wrapping integer total | 940 |
| Add converted quantities before scaling | 916 |
| Omit selected addition | 2,747 |
| Reject equality at numerator floor | 12 |
| Cancel scaling and round the collapsed expression | 1,236 |

This validates the independently authored scalar arithmetic against a precise
numeric specification grounded in the pinned static instructions. It is **not**
a native runtime differential test or proof of complete vault equivalence.

## Reproduction

From the repository root, with the pinned LFS target materialized and the
recorded Python/Capstone dependency available:

```sh
python3 research/work-items/RE-001-node115-vault-redistribution/verify.py
python3 research/work-items/RE-001-node115-vault-redistribution/rational-reference.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-vault-redistribution/Cargo.toml
cargo +1.95.0 test --offline --release --locked --manifest-path src/node115-vault-redistribution/Cargo.toml
cargo +1.95.0 clippy --offline --locked --manifest-path src/node115-vault-redistribution/Cargo.toml --all-targets -- -D warnings
cargo +1.95.0 fmt --manifest-path src/node115-vault-redistribution/Cargo.toml -- --check
shasum -a 256 -c research/work-items/RE-001-node115-vault-redistribution/MANIFEST.sha256
make doctor verify catalogue-check reproduce
```

The static verifier reports 183 facts and rejects 28 controls. The reference
command reproduces the fixture and comparison summary byte-for-byte; `--write`
regenerates those two authored files. Repository-check outcomes are recorded in
the PR. Full unfiltered `make test` is excluded because its discovery includes
captured-instruction emulation; this work has no authorization for that action.

## Limits and attribution

IEEE binary64 round-to-nearest/ties-to-even, gradual underflow, and separately
rounded operations are premises. This packet does not establish the target's
MXCSR initialization, exception masks, or alternate floating environments.
The Rust output models no native exception flags, callbacks or allocator effects.
The positive-delta prelude, full collection implementation, unwinding, complete
wire action, business-unit names, admission, authorization, ownership, aggregate
conservation and persistence remain unproved. No component gate is completed.

Prior work: PR #3945 and its value-transfer packet establish the upstream
handoff; PR #2220 covers entry guards; PR #4035 covers a separate diagnostic
edge. Open PR #4350 models a distinct standalone finite-ratio leaf at
`0x14ca350`: it clamps a small negative numerator and reports a separate
success flag while retaining selected raw output bits. This path instead
applies a positive `1e-7` numerator floor and returns positive zero on
rejection, in addition to the saturated total, separately rounded scaling,
selected-key addition and keyed writeback described above. Both use a
`1e-15` divisor threshold, but substituting the leaf changes the contract.
Current-main
source/evidence, all open PR titles/bodies and targeted
all-state searches for the helper addresses and vault rescaling were checked.
No competing implementation was found. This is not an assertion that every
historical patch was manually inspected; metadata search can miss unindexed code.

Implementation and interpretation: OpenAI `gpt-6-astra`, `codex-desktop`.
GitHub/browser reads, independent review, and publication: OpenAI
`gpt-6.1-terra`, `codex-desktop`. Authored Rust, oracle and prose are independent;
no unlicensed inferred reference source was copied.
