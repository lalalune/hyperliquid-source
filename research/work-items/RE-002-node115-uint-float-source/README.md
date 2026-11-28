# RE-002: reproduce node #115 unsigned u128-to-binary64 at two opt levels

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Baseline 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860, rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The existing RE-004 conversion packet relies on an exact match against the published object. Two clean, offline source builds now reproduce the same 132 bytes at ELF VA 0x63f00d0. At both opt-level 2 and 3, the full source section equals the target body and contains no relocation. Thus this function does not discriminate between the two levels. That differs from the unsigned remainder result in the neighboring source-build packet and cannot establish the original optimization setting. This adds provenance for the conversion without repeating its numerical proof.

Provision the cache as described in RE-002-node115-umodti3-source-build. Use Python 3.12+, Rust/Cargo 1.95.0, and GNU binutils. The tool directory must contain ar, nm-new (or a link to GNU nm), objdump and objcopy. Run from the root:

```sh
python3 -B research/work-items/RE-002-node115-uint-float-source/verify.py /path/to/cache /path/to/binutils
```

The log reports both raw body digests and relocation counts. The capture is read as bytes. No gate or byte-window registry changes.
