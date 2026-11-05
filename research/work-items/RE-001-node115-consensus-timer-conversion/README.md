# RE-001 / RE-008: node115 consensus timer f64 conversion decision table

- Component: consensus, observed `node/src/consensus/timer.rs` path.
- Target: node #115 Linux x86-64, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`; no inferred source copied or treated as an oracle.
- Question: how exactly does the one FDE attributed to `timer.rs:17:30` turn an f64 number of seconds into the seconds/nanoseconds pair it assembles — which inputs are rejected, where are the regime boundaries, and how does fractional rounding carry?
- Status: complete static export of one FDE plus its only two call sites. The 0x70-byte payload constructor's body and the panic payload's formatting remain unmeasured. No implementation or gate claim.

## Scope and binding

`0x4eca5d0..0x4eca82c` is the complete measured FDE, **604 bytes / 150 instructions**. `records.json` preserves raw bytes, body hash, file mapping, FDE/CIE, calls/branches, slot resolutions and the caller record. `native.asm` retains the full GNU disassembly of the FDE; `caller_excerpt.asm` retains the caller window around both call sites. There is no byte normalization. An FDE describes an unwind range, not a guarantee that all semantics or cold parts are closed.

At `0x4eca743`, LEA binds the Location `0x649dcf8`. Its actual `R_X86_64_RELATIVE` relocation and 24 raw bytes resolve `node/src/consensus/timer.rs:17:30`. This is bounded source attribution, not an original symbol name. That Location is also passed as the fourth argument to the payload constructor below, so the attribution is the function's own, not a neighbour's diagnostic.

The incoming convention is output pointer RDI (preserved in RBX), f64 input in XMM0. The output record is `0x20` bytes: seconds u64 at `+0`, nanoseconds u32 at `+8`, a heap pointer at `+0x10`, and a zero byte at `+0x18`. No source-level name for the record or its fields is recovered.

## Ordered decisions

The input's biased exponent `E` (bits 62..52) selects one regime. All comparisons below are on the raw encoding; the sign bit is consulted only by decision 1.

1. **Negative input panics.** `ucomisd` compares `0.0` against the input; if `0.0 > x` the function enters the non-returning arm at `0x4eca7dd` with flag byte **0**. This fires for every strictly negative value, including negative subnormals; `-0.0` compares equal and continues to decision 2.
2. **`E < 0x3e0` (x < 2^-31 s, including ±0 and subnormals):** seconds = 0, nanoseconds = 0. Values below ~0.466 ns therefore produce exactly zero, consistent with round-to-nearest at nanosecond granularity.
3. **`0x3e0 <= E < 0x3ff` (2^-31 <= x < 1):** seconds start at 0. The significand is shifted into a 128-bit lane, multiplied by **1,000,000,000** (`0x3b9aca00`), and the nanosecond result is rounded **to nearest, ties to even**: the carry into the integer nanoseconds is set from the discarded fraction's half bit, the sticky bits below it, and the result's low bit. If the rounded nanoseconds equal exactly 1,000,000,000, seconds become 1 and nanoseconds become 0.
4. **`0x3ff <= E < 0x433` (1 <= x < 2^52):** seconds are the integer part extracted by shifting the significand; the fractional part goes through the same ×1e9 ties-to-even rounding as decision 3. If the rounded nanoseconds equal exactly 1,000,000,000, nanoseconds become 0 and **seconds increase by one** (`add r14, rax` at `0x4eca72c`).
5. **`0x433 <= E < 0x43f` (2^52 <= x < 2^64):** the value is already an integer count of seconds; seconds are the significand shifted left by `E - 0x433` (the byte added at `0x4eca73d`, `cl += 0xcd`, wraps to exactly that count over this range), nanoseconds = 0.
6. **`E >= 0x43f` (x >= 2^64, +inf, NaN):** the function sets flag byte **1** (`mov r15b, 1` at `0x4eca7da`) and enters the same non-returning arm at `0x4eca7dd`. NaN reaches this arm because the unordered `ucomisd` result at decision 1 does not take the `ja` branch and its exponent is `0x7ff`.

The non-returning arm stores the flag byte at `rsp+0xf` and builds a two-word payload at `rsp+0x10`: a pointer to that flag byte, and the word resolved from slot `0x64e13a8` (`0x1689370`). It then calls the core panic runtime through slot `0x64df6b8`, whose RELATIVE relocation resolves to `0x1680e80`, with `rsi` pointing at the payload; the `rdi` argument (a static computed as `0x1fdb857`) is not identified here. The arm continues through a 96-byte cleanup helper at `0x4e50c80` and the `_Unwind_Resume` PLT entry, and the FDE's final call (slot `0x64df4c0` → `0x1680cab`) is the unreachable continuation. The flag byte is the only distinction the arm itself records between the negative and too-large cases; the payload's formatting and message text are **not** measured here.

## Output assembly and dependencies

On a successful conversion the function first calls an indirect constructor through slot `0x64e13a0`, whose RELATIVE relocation resolves to the FDE `0x5cf2150..0x5cf22e9` (409 bytes, **body unmeasured**). Arguments are `(out = rsp+0x10, seconds, nanoseconds, Location timer.rs:17:30)`; it writes a `0x70`-byte value on the stack. The function then requests `0x70` bytes through slot `0x64df480` (RELATIVE → `0x6355830`, the allocation entry; body unmeasured). A null result diverts to the allocation-failure call at `0x4eca7d2` (slot `0x64df490` → `0x141e251`, arguments align 8 / size `0x70`) followed by `ud2`. On success the `0x70` stack bytes are copied verbatim into the allocation, whose pointer is stored at output `+0x10` after seconds and nanoseconds are stored at `+0` and `+8`; the byte at `+0x18` is written as 0 last. What the `0x70`-byte payload represents is not established by this FDE and is not claimed.

## Callers

The FDE has **no direct `rel32` callers**. Its address is stored exactly once, in slot `0x64e87d8`, whose RELATIVE relocation resolves to `0x4eca5d0`. A whole-text scan finds exactly two call sites through that slot, at `0x2e1c74c` and `0x2e1c762`, both inside the FDE `0x2e1b6b0..0x2e1da0e` (9,054 bytes), which binds the Location `node/src/consensus/state.rs:123:106` at `0x2e1d1cf`. The two calls are adjacent and identically shaped:

- `lea rdi, [rsp + 0x368]`; `movsd xmm0, [0x459a20]` — bits `0x3fd3333333333333`, the nearest f64 to **0.3** — call.
- `lea rdi, [rsp + 0x388]`; `movsd xmm0, [0x459410]` — bits `0x3fb9999999999999`, value **0.09999999999999999** (one ulp below the nearest f64 to 0.1) — call.

The two `0x20`-byte results therefore land in neighbouring stack slots of one consensus-state function, built from the constants 0.3 s and ~0.1 s. Which state-machine roles those two durations play is a caller-side question and is **not** decided here; the proven facts are the call sites, the exact input bits, and the output placement. A panic in either call (decision 1 or 6) would originate from `timer.rs:17:30`, but neither constant can reach those arms: both are positive and far below 2^64.

## Reproduction and controls

Run from the repository root with Python **3.12.3**, Capstone **5.0.7**, GNU objdump **2.42**:

```sh
python3 tools/node115_consensus_timer_conversion.py --write
python3 tools/node115_consensus_timer_conversion.py
python3 -m unittest discover -s tests -p test_node115_consensus_timer_conversion.py -v
```

The first command regenerates the static packet, the second checks exact replay. The objdump exports are produced from the repository root with the target as the relative path `artifacts/node/115/hl-node`, so no checkout-specific absolute path enters the artifacts. The node is read only; no captured executable, emulator, socket, chain or signing operation runs. All **13 tests** pass. Ten decoded-instruction corruption controls cover the negative-input branch, both fractional-regime boundaries, the one-billion multiplier, the exact-billion carry test, both whole-second regime boundaries, the boxed pointer's output offset, the overflow flag value, and the constructor's Location argument. Wrong-artifact and truncated-decode controls also reject. These are structural checks of the authentic target evidence, not execution of the target or a differential source implementation.

## Results and limitations

One bounded question is answered completely at the static-evidence level: the full decision table of the `timer.rs:17:30` conversion FDE, its rounding and carry behaviour, its two rejection cases, its output layout, and its only two call sites with their exact f64 inputs. Not measured: the payload constructor at `0x5cf2150`, the allocation entry at `0x6355830`, the allocation-failure and panic runtime bodies, the payload's semantic identity, and any source-level names. No progress gate is requested. Next question: what does the `0x5cf2150` constructor build from the (seconds, nanoseconds, Location) triple, and which field of the caller's state record consumes the two `0x20`-byte results?
