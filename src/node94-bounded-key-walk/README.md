# node94 bounded key-walk stored values

Independent, dependency-free `no_std` Rust for node #94's complete leaf
at `[0x1b26100,0x1b2616a)`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`raw_triple(nodes, start, index, key) -> Result<[u64;3], Refusal>` returns
the exact three qwords selected for storage: first-node/key, later-node/
previous-gate, or exhausted/last-node/last-index. The index wraps at
64 bits. The initial key comparison is unsigned64; subsequent gate
comparisons are unsigned16.

`Node` supplies stable values indexed by unique nonzero opaque IDs.
IDs may retain original pointer bits, but this code dereferences none.
Missing snapshots are refused only when reached. Cycles that stop at
a gate are supported, including self/closing edges; only proved
nonterminating cycles are refused after at most N edge checks.
Invalid maps, missing information and nontermination refusals are new
safe-API behavior, not original returns. No memory is changed.

Original pointer validity, output-memory/aliasing effects, returned
out-pointer ABI, concurrency and the fields' meaning are outside this
projection. See the [proof and evidence](../../research/work-items/RE-004-node94-bounded-key-walk-rust/README.md).
No component gate is changed.

From the repository root with installed rustc 1.94.1, Python, Capstone
5.0.7 and GNU objdump:

```sh
python3 -B -O research/work-items/RE-004-node94-bounded-key-walk-rust/validate.py
```

The validator builds this library and its input-only driver with
standalone rustc. It creates no Cargo workspace or dependency lock,
and runs only the newly built Rust programs.
