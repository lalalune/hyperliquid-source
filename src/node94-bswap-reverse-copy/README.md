# node94 ordered byte-swap/reverse copy

Dependency-free `no_std` Rust state projection of the complete node94 leaf
`[0x5632d90,0x5632dbb)`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`copy_reverse(memory, source, destination)` performs four ordered qword
reads, byte swaps and writes in one mutable buffer. Each 8-byte input is
captured completely before its write. Later qwords observe earlier writes,
so arbitrary byte-offset overlap and self-copy are preserved. The result is
the final raw RAX value, not an inferred source-language type.

The source qword offsets are 24, 16, 8 and 0; destination offsets are 0, 8, 16
and 24. Disjoint regions therefore produce a reversed 32-byte sequence. That
shortcut is wrong for some overlapping regions. For self-copy of bytes 0..31,
the final buffer contains bytes 31..16 followed by 16..31.

Both logical u64 offsets must name complete 32-byte regions in the supplied
slice. `Bounds` is a new safe API refusal before any mutation; it does not
reproduce original native faults or partial effects of invalid memory. The
projection assumes valid nonwrapping native regions and ordinary memory
permitting unaligned qword accesses. Native pointers, concurrent changes,
MMIO and faults are excluded. See [PROOF.md](PROOF.md).

```sh
python3 -B -O research/work-items/RE-004-node94-bswap-reverse-copy-rust/validate.py \
  --output work/node94-bswap-reverse-copy/recheck
```

The [evidence packet](../../research/work-items/RE-004-node94-bswap-reverse-copy-rust/README.md)
contains the pre-Rust backward-provenance oracle, native validation, exact raw
streams, full-body/caller/FDE closure and limits. Builds use installed rustc
1.94.1 directly; no root workspace or external crate is introduced.
