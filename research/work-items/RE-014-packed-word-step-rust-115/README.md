# RE-014 packed-word preparation and CAS retry for node115

The current native evidence establishes the IP-permit capacity prefix and
the packed-word retry loop. This packet implements those operations in a
standalone Rust library. The tested base is
`05bc2de303c05525b71e7e257426e741bc66a390`.

The Linux x86-64 node115 target digest is
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The complete 409-byte step FDE starts at 0x4770f40 and ends at 0x47710d9.
The complete 1,402-byte constructor FDE starts at 0x47710e0 and ends at
0x477165a. The original MIT native certificate and static model are reused
unchanged. The checker verifies both actual FDEs and CIEs, 356 Capstone
instruction rows and the certificate's address, operand and call bindings.
The full native bodies supply context for the selected prefixes.

Capacity below 2^61 passes the guard and gives the encoded word 2*n.
The constructor store and the acquisition load and CAS all use owner+48.
In the step, a set low bit takes the flag gate. A word below two takes the
empty gate. Otherwise the locked CAS proposes w-2. On failure, the returned
memory word in RAX goes back through both gates. Success establishes one
decrement of the packed word.

The Rust library exposes a capacity projection and a safe operation on a
borrowed AtomicU64. The Rust implementation chooses SeqCst. The source
ordering of the captured program and broader concurrency, lifecycle,
provider, allocation, refund and cleanup semantics remain open. The new
outcome enum labels local routes. Its tags belong to the synthetic probe ABI.
The source comparison covers finite same-word writes immediately before CAS
attempts and the resulting local route and word. These histories do not
establish native caller reachability or represent a real thread test.

The shared evaluator stops at the freshly compiled own instruction
`lock cmpxchg` at 0x10001e, with initial word four. The retained blocker
records the exact object instruction stream. The local evaluator supports
only the locked 64-bit memory form at the designated synthetic word. It
records the compare accumulator, current word, proposal and success at each
attempt. See the [Intel instruction reference, pages 3-208–3-209](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf)
and the [Rust AtomicU64 API](https://doc.rust-lang.org/stable/core/sync/atomic/type.AtomicU64.html#method.compare_exchange).
The Rust compiler used for the recorded object is pinned separately to 1.94.1.

The run compares 1,047 capacity inputs and 10,470 step histories. It observes
6,784 failed CAS attempts and zero mismatches. The corpus includes both
terminal gates after interference, repeated retry, high-bit words and the
capacity boundary. Six compiled mutations and four operand changes are
rejected. Both own objects built twice agree byte for byte. Only own ELF REL
instructions enter the evaluator. The authenticated capture stays inert.

The report retains compiler, input, source and body hashes, raw transcript
hash, controls and full native exports. Reproduction writes the transcript
to the requested fresh output directory. No target-byte match or acceptance
gate is claimed.

## Reproduction

```sh
python tools/packed_word_step115_rust.py --rustc /path/to/rustc --out work/permit-fresh
cargo build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-packed-word-step/Cargo.toml
HYPERLIQUID_PACKED_WORD_RUSTC=/path/to/rustc python -m unittest discover -s tests -p test_packed_word_step115_rust.py -v
```
