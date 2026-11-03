# node115 packed millisecond conversion

Independent MIT Rust projection of five target115 conversion segments. It
accepts three rawu32 words, retaining both raw signed milliseconds and the
native positive-or-zero clamp. Raw invalid dates/times are boundary states,
not an original chrono/API validity claim. The low four packed bits are ignored.

See [the evidence packet](../../research/work-items/RE-014-packed-millis-115/README.md)
for the target digest, pre-Rust freeze, exact arithmetic derivation, native
negative controls, input-only builds and limits. No dependency version,
original source identity/ABI, surrounding helper or full node is recovered.
There is intentionally no fabricated Cargo workspace or dependency graph.
