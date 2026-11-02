# Node115 conditional nonce ring invariant

RE-001, l1 nonce-container foundation. This independently authored dependency-free
Rust component reconstructs the conditional strict adjacent-u64 relation already
bound in `research/work-items/RE-001-node115-nonce-ordering`. It does not recount
those native bodies as new mapping, recover any provider/error ABI, or establish
nonce admission, replay policy, allocation or caller reachability. No completion
gate or target machine-code identity is claimed.

Target #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Native five-body evidence is reused with explicit credit. It requires valid raw
capacity/head/count and initialized nonwrapping storage, with capacity <=
isize::MAX / 8. The Rust C interface is a logical test boundary only; invalid
metadata is outside this contract and is not claimed rejected by the original.
The source is independently authored from the original unsigned comparison and
ring equations; no unlicensed inferred source was copied. New source/docs MIT.

Actual offline locked release Cargo library build passed using official Rust
1.94.1/LLVM21.1.8 and the Linux x86-64 target on Windows. The own compiled scalar
is 47 bytes / 17 instructions. Identical repeated object builds were observed.
Only this freshly compiled own code enters the byte-accurate evaluator; original
captured code is read statically, never run. No native Rust test executable runs.

The compiled-code evidence: all physical arrays of length 0..4 over five unsigned edge
values, every valid head and count: 14,161 calls, zero mismatch. The independent
oracle obtains both span obligations and actual unsigned JB operands from the
existing digest/FDE/body/data-bound native checker. All five native routes have
the same two observed predicates; their provider/normal-output behavior is open.

The additional layout evidence: 47,872 additional calls across every valid head/count
for capacities 1..32 with ascending, duplicate, descending and deterministic
random logical data. Zero mismatch. Counts are separate evaluation runs, not a
claim of unique cases across runs. Three real source corruptions were compiled
and rejected on native-derived counterexamples: accepting equals, skipping the
wrap boundary, and omitting the first comparison. Own RAM validity rejects reads
outside initialized synthetic memory. There were no new evaluator ISA extensions.

Build the standalone dependency-free library with Rust 1.94.1:

```
cargo build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-nonce-ring/Cargo.toml
python tools/nonce_ring_rust.py --rustc /path/to/direct/rustc --out-dir work/nonce-ring-comparison
HYPERLIQUID_NONCE_RING_RUSTC=/path/to/direct/rustc python -m unittest discover -s tests -p test_nonce_ring_rust.py -v
```

The component test needs the explicit compiler variable and Capstone5.0.6;
otherwise it honestly skips. Check the corresponding evidence packet for exact
compiled-code records, source controls and actual repository-check limitations.
No complete original function, Rust ABI or component gate is claimed.

The raw-storage contract includes unaligned addresses: read_unaligned preserves
the captured x86-64 load behavior. Another5,784 measured comparisons cover all
eight byte alignments for capacities0..8, every valid head/count and three
logical patterns. The own code remains47 bytes/17 instructions. A false result
is the logical invariant-failure decision, not an original error return.
