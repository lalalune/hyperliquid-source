# Identify the Base64 engine passed by a node #115 caller

The registered encoder at 0x1607710 has four byte-compatible reference symbols from three releases. Its machine code accepts the encoding table as an argument. One caller at 0x26e2b19 selects the padded standard alphabet. The other inspected caller at 0x43035e4 forwards its engine. The evidence for the first caller does not determine the second caller's alphabet.

## Binding the data to the call

Both six-byte indirect calls resolve through a single GOT entry, 0x64e1938, whose ELF relative relocation points at 0x1607710. At 0x26e2b09 a RIP-relative LEA loads the first argument with 0x5f405b. The next three instructions initialize other arguments. The encoder indexes its table at first argument + 3, for example at 0x1607768. In the calling function the padding loop writes the equals character at 0x26e2b4a.

Build the three controls from the published base64 0.20.0 crate with the pinned rustc and Linux target, using [control.rs](control.rs). The verifier reads the complete engine object from each named ELF section.

| Independent compiler input | Size | Bytes differing from the selected target object |
| --- | ---: | ---: |
| STANDARD alphabet, PAD | 323 | 0 |
| URL_SAFE alphabet, PAD | 323 | 6 |
| STANDARD alphabet, NO_PAD | 323 | 2 |

The 323-byte object contains the configuration bytes, the 64-byte forward table and the 256-byte reverse table. The positive control occurs twice in read-only data, at 0x5f405b and 0x7bd3aa. Only the first address is the operand of the inspected caller. Source reconstructions based on an unconstrained byte search could pick either.

## Source attribution

All nine source-location LEAs in the [earlier operand map](../RE-002-node115-rust-base64-encode-bindings/README.md) dereference to the version-bearing path ending in z_vendor/base64-0.20.0/src/engine/fast_portable/mod.rs. The line and column values map into the authenticated 0.20.0 source. Neither of the two other candidate archives contains that module path. [The recorded result](result.json) contains each coordinate, its source line hash, the two caller sites, both identical data locations and the negative-control differences. This narrows the source attribution for the mapped function. An identical historical lockfile or an unmodified entire crate remains unverified.

## Replay

Use Python 3.12+ and rustup with 1.95.0 and its x86_64-unknown-linux-gnu standard library installed. Materialize the pinned node #115. From this directory run the following.

```sh
for v in 0.20.0 0.21.7 0.22.1; do
  curl -fLo "base64-$v.crate" "https://static.crates.io/crates/base64/base64-$v.crate"
done
python3 -B verify.py base64-0.20.0.crate base64-0.21.7.crate base64-0.22.1.crate
```

Target SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier authenticates each public package against the candidate archive checksums before compiling the 0.20.0 source in a temporary directory. No target or control executable is run. The new verification code uses the repository license; the public crate sources retain their licenses and are downloaded separately. This packet reuses the registered function and adds no byte coverage.
