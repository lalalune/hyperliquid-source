# RE-001: node #115 lu.rs f64-to-scaled-integer conversion — two 4-entry dispatch tables, 10^9 scaling, and a 4-member skeleton family

- Component: `base/src/lu.rs` numeric conversion, with a caller-side state machine as context.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (upstream main, node-115-only migration).
- Question: what does the `base/src/lu.rs` conversion function at `0x15d5cb0` do — which tags select which input, how is the f64 scaled, and what does it write back?
- Observation: the function dispatches on two tag bytes through two private 4-entry i32 tables, converts an f64 by exponent cases with a multiply by 1,000,000,000 (10^9) and a carry guard, copies a 112-byte result to `[rbx+0x18..0x88]`, and writes tags 1/2/3 to `[rbx+0x88]` and `[rbx+0x90]` on the conversion paths (`[rbx+0x90]` only on the exact-zero path).
- No Rust reimplementation, no Duration-type proof, no caller-identity, no full-component gate claim. The abbreviation `lu` is not expanded: no source for it is in the tree.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| conversion (characterized instance) | `0x15d5cb0..0x15d606b` | 955 | 235 |
| caller-side state machine (context) | `0x15d6e00..0x15d6ee1` | 225 | 60 |
| once-guard function (context) | `0x15d6ef0..0x15d6fc4` | 212 | 60 |

The measured denominator for the characterized function is **one complete FDE, 955 bytes / 235 native instructions**. Each complete native export starts at its actual FDE entry and covers the complete body. Native readelf confirmations, raw FDE/CIE records, file offsets, body hashes, source Location records and relocation addends are retained. All bodies are hash-pinned without normalization. This is not a raw-equal or normalized cross-function equivalence claim beyond the skeleton-family check described below.

## Dispatch: two private 4-entry tables, no bounds check

The entry reads the tag byte at `[rdi+0x90]` and jumps through the i32 table at `0x4699e8`:

| Index (tag +0x90) | Offset | Target | Arm |
| ---: | ---: | --- | --- |
| 0 | 18268918 | `0x15d5cde` | f64 input at `[rbx+0x0]`, published to `[rbx+0x8]` |
| 1 | 18269644 | `0x15d5fb4` | panic arm, cites `base/src/lu.rs:63:46` |
| 2 | 18269631 | `0x15d5fa7` | panic arm, cites `base/src/lu.rs:63:46` |
| 3 | 18268949 | `0x15d5cfd` | nested dispatch on tag +0x88 |

The nested dispatch reads `[rbx+0x88]` and jumps through the i32 table at `0x4699f8`:

| Index (tag +0x88) | Offset | Target | Arm |
| ---: | ---: | ---: | --- |
| 0 | 18268967 | `0x15d5d1f` | f64 input at `[rbx+0x10]` |
| 1 | 18269656 | `0x15d5fd0` | panic arm, cites `base/src/lu.rs:74:57` |
| 2 | 18269641 | `0x15d5fc1` | panic arm, cites `base/src/lu.rs:74:57` |
| 3 | 18269503 | `0x15d5f37` | main conversion path |

Each table is exactly 16 bytes: the next table (or the next data) starts immediately after. Each table is used by exactly one `lea` site in the whole binary (`0x15d5cce` and `0x15d5d0f` respectively), so the tables are private to this function, not shared. There is no bounds check before either table jump: the tag bytes are trusted as 0–3 enum discriminants, and tags 1 and 2 are the invalid states that panic. Offsets are i32 values relative to the table base (`movsxd` + `add` + `jmp`), not absolute addresses.

## Conversion: exponent cases, 10^9 scale, carry guard

Both live arms feed one f64 into the same conversion:

- Zero check: `ucomisd` against 0.0. An exact 0.0 input skips conversion, stores tag `[rbx+0x90] = 1`, and returns 0. A nonzero or unordered (NaN) input proceeds.
- Exponent extract: the f64 bits are shifted right by 0x34 (52) and masked with 0x7ff, yielding the biased exponent. Four thresholds partition the range: `0x3e0` (992), `0x3ff` (1023, the bias), `0x433` (1075), `0x43f` (1087). The bands select different shift/mask sequences for the mantissa.
- Scale: the mantissa path multiplies by `0x3b9aca00` = 1,000,000,000. A carry guard compares the scaled value against 1,000,000,000 and carries (with `cmove` to 0) when the scaled value reaches exactly 10^9.
- Out-of-range exponents (at or above `0x43f`, and the unordered path) funnel into a panic call citing `/rustc/.../library/core/src/time.rs:962:23`. That citation, together with the 10^9 scale, is consistent with a seconds-to-nanoseconds (Duration-family) interpretation, but that interpretation is **inference, not observation**: the packet does not prove the output type is a Duration.

After scaling, the function calls a helper citing `base/src/lu.rs:75:5`, then copies a 112-byte (0x70) value from the helper's stack output `[rsp+0x20..0x90]` to `[rbx+0x18..0x88]`. An identical 112-byte copy is also staged at `[rsp+0x90..0x100]`; no read of that staging area appears on the observed paths, so its role is unresolved. A compare helper (GOT slot `0x64e0858` → `0x5cf2d30`, 703-byte FDE) is then called with `([rbx+0x18], second argument)`; its boolean result is the function's return value. The compare helper itself is not decoded.

## Tag writes and the drop path

On the conversion paths (nonzero input), both tag bytes `[rbx+0x88]` and `[rbx+0x90]` receive the same value:

- `1`: the compare reports equality, after the drop path below.
- `3`: conversion completed and the compare reports difference.
- `2`: unwind/landing-pad paths only (both tags set to 2 before `_Unwind_Resume`).

The exact-zero path is the exception: it writes only `[rbx+0x90] = 1` and returns 0 without touching `[rbx+0x88]`.

When the compare reports equality, the function takes a drop path first: it decrements the refcount at `[rbx+0x20]` (calling drop helper `0x5ce8da0` or `0x5ce86d0` when the count reaches zero, selected by the tag byte at `[rbx+0x18]`), then calls `0x15df190` on `[rbx+0x28]`, and only then stores tag 1. When the compare reports difference, the drop path is skipped and tag 3 is stored directly.

## Caller-side state machine (context, not the main claim)

The caller at `0x15d6e00` (225 bytes, 60 instructions) drives the same struct:

- State byte `[rbx+0xa0]`: `0` → publish the f64 at `[rbx+0x0]` to `[rbx+0x8]`, zero `[rbx+0x98]`, then call the conversion; `3` → call the conversion directly; any other state → panic path citing `base/src/lu.rs:220:26`, then mark state `2` and unwind.
- After the conversion returns false, if both tag bytes `[rbx+0x90]` and `[rbx+0x98]` equal 3, the caller drops two refcounted fields (`[rbx+0x28]`, `[rbx+0x30]`) and retries from the publish step.
- After the conversion returns true, the caller stores state `[rbx+0xa0] = 3` and returns true.

The adjacent guard function at `0x15d6ef0` (212 bytes, 60 instructions) gates a shared 1,733-byte worker behind the global DWORD at `0x64f03d8` and a `lock cmpxchg` (expected `0xcc`, new `0x84`) slow path, citing `base/src/lu.rs:148:9` and `base/src/lu.rs:215:36`. Its once helper (GOT `0x64df9f0` → `0x5c87d50`, 540 bytes) runs a DWORD state machine masking with `0x3` and `0x4`.

Reachability caveat (observed, not smoothed over): the conversion instance at `0x15d5cb0` has exactly two direct `E8` callers in the binary (`0x15d6e4c` inside the caller above, and `0x15d5bc7` inside a 430-byte function at `0x15d5b00`), and both of those caller functions themselves have no direct `E8` callers, no `E9` jumps to them, and no qword/`lea` references. So this instance's direct reachability is unproven. The skeleton family below is what grounds the function as live code: its siblings are directly called from large functions.

## Skeleton family: 4 members, same 235-instruction sequence

Four 955-byte FDEs share the identical 235-instruction mnemonic sequence (verified by linear disassembly from each FDE start; only address-dependent bytes differ). Each carries the same five `lu.rs` site pattern (75:5 ×1, 63:46 ×2, 74:57 ×2) at corresponding positions:

| Instance | FDE | Direct E8 calls | Callers include |
| --- | --- | ---: | --- |
| `0x15d5cb0` (characterized) | `0x105b070` | 2 | the two unreferenced callers above |
| `0x15ebbe0` | `0x105f0c8` | 3 | — |
| `0x2a90a50` | `0x116fce4` | 10 | 2,727-byte, 820-byte, 23,802-byte, 12,984-byte, 11,142-byte, 22,372-byte (×2), 3,586-byte, 5,161-byte, 4,479-byte functions |
| `0x2c7f360` | `0x118e470` | 7 | 2,722-byte, 22,239-byte (×2), 3,659-byte, 34,299-byte (×2), 10,657-byte functions |

The other 41 same-size (955-byte) FDEs in the binary have 23 other instruction skeletons and are **not** claimed as this function. Same size alone is not identity.

## What this does not claim

- The Rust type name of the struct, the enum variant names, and the expansion of `lu` are not asserted.
- The Duration interpretation of the 10^9 scale is inference from the scale constant plus the `core/src/time.rs:962:23` panic citation, not a proven type identity.
- The compare helper (`0x5cf2d30`), the post-scale helper (`0x5cf2150`), and the shared 1,733-byte worker are mapped as call targets only; their internals are not decoded.
- The staged `[rsp+0x90..0x100]` copy's role is unresolved.
- The 41 other 955-byte FDEs are not characterized.
- No gate is requested by this packet; the next question is whether the compare helper at `0x5cf2d30` distinguishes "equal" by value or by identity, which decides what tag 1 vs 3 means for callers.
