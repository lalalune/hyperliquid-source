# How node #115's sysinfo accounting updates process and task CPU percentages

The existing [sysinfo reference map](../RE-002-node115-rust-sysinfo-process-references/README.md) registers a 328-byte Linux process accounting function at 0x5cb6f30. It reports the address of a floating-point operand. This packet checks the value stored there, the call that supplies time and ceiling arguments, the result store, and the recursive child path. It compares the published function with an independent accounting model across three generations of synthetic processes.

| Node #115 site | Observed effect |
| --- | --- |
| 0x5cd0eed to 0x5cd0eff | The caller loads two 32-bit scalar arguments into XMM0 and XMM1 and calls 0x5cb6f30. |
| 0x5cb6f45 to 0x5cb6f59 | Both old counters are zero on the early return. The stored percentage and children are untouched. |
| 0x5cb6f66 to 0x5cb6f8e | Each counter decrease contributes zero; the sum of both unsigned deltas saturates at the maximum u64. |
| 0x5cb6f92 to 0x5cb6fc7 | Convert the unsigned sum to binary32, divide by the supplied time and multiply by the binary32 100 at 0x45a1d8. |
| 0x5cb6fcc to 0x5cb6fe4 | Apply the caller-supplied ceiling and store the binary32 result at process + 0x15c. |
| 0x5cb7023 to 0x5cb7039 | Pass a child process and the same two scalar arguments to the same function. |

A newly observed process with both old counters at zero can therefore retain its previous displayed value and skip child updates. A sampled parent whose child has no baseline still updates its own value. For ordinary positive intervals, the public source computes the two saturating deltas, divides by the interval and caps the percentage. Its Linux refresh code supplies the number of logical CPUs times 100 as the ceiling. The target caller evidence here identifies the two argument loads, without deriving their upstream process-wide values.

## Reproduction

The [control program](control.rs) invokes the unmodified function text from the checksum-pinned sysinfo 0.29.11 archive. Its three-generation process tree provides counters and stored percentages without reading host process data. An independent Python model rounds u64 to binary32, rounds the division and multiplication separately, and applies the first-sample rule down the tree.

The first 512 controls use every three-generation arrangement of eight named counter cases, including a missing baseline, decreasing user and system counters, saturating sums and binary32 rounding boundaries. A further 512 deterministic trees vary u64 counters, time intervals and CPU ceilings. All 3,072 resulting percentage bit patterns agree. [Recorded digests](result.json) cover the full vector stream and output stream.

With Python 3 and Rust 1.95.0 installed, materialize the repository's authenticated Linux node #115 and run from this directory.

```sh
curl -fLo sysinfo.crate https://static.crates.io/crates/sysinfo/sysinfo-0.29.11.crate
python3 -B verify.py sysinfo.crate
```

Target SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The public source fixture runs on the host. The captured node is read statically. The control supplies a small ordered child map and does not test the native hash table layout, Linux sampling intervals, procfs reads or higher-level telemetry consumers. No target coverage changes. The packet's original code uses the repository license. Public sysinfo source remains separately distributed under its upstream terms.
