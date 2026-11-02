# Visor child-argument values — pre-code packet

Target: Visor SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.

This packet prepares one real, dependency-free Rust component for the already established conditional child-argument value relation. The 503-byte validator, 67-byte actual adapter and 860-byte collector are **credited existing evidence** from [#1029](https://github.com/lalalune/hyperliquid-source/pull/1029) and [#1040](https://github.com/lalalune/hyperliquid-source/pull/1040), with selected caller provenance from [#988](https://github.com/lalalune/hyperliquid-source/pull/988). No new native-byte credit, component completion or captured execution is claimed.

The chosen safe interface distinguishes a null-empty stop from a nonnull empty argument, keeps canonical UTF-8 bytes unchanged and ordered, and preserves embedded NUL. Invalid UTF-8 is a **new safe API refusal**; the native adapter's error helper remains opaque.

- [CONTRACT.md](CONTRACT.md): proposed source/API, input mapping, oracle and pre-code gate.
- [BRIDGE.md](BRIDGE.md): exact caller corridor, complete dependency/frame domain and proof composition.
- [VALIDATION-PLAN.md](VALIDATION-PLAN.md): real build admission, input-only comparison and required controls.
- `bind.py`: authenticate and rebind credited native bytes, full FDE/CIE records, used relocations and independent GNU/LLVM partitions.
- `corpus.py`: derive canonical UTF-8 from all Unicode scalar values and emit separate synthetic inputs/expectations.

Production Rust does not exist at this phase. The parent must review the frozen contract, independent corpus and source absence before code is written. Later results will use separate freezes; this pre-code record will not be restamped as if it tested later source.

From the source root, with the pinned capture and credited packets available, run the pre-code checker with a fresh output directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-013-visor-child-args-rust/verify_precode.py --out /tmp/child-args-precode-UNIQUE
```

It checks native admission controls and regenerates all five native-evidence files and seven corpus files without changing the committed copies. It requires the planned production source directory to be absent; later implementation validation uses a separate source/build freeze. The corpus contains108,604 collection cases and197 integer-domain cases. These are finite mathematical expectations, not captured-program outputs.
