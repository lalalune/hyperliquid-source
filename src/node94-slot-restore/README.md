# node94 slot restore

Independent, dependency-free, safe `no_std` reconstruction of node #94 linked
ELF VA `[0x3290130,0x3290192)`, target SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`restore(image, base, output, owner, state)` uses abstract u64 address values
over a mutable image; these values are never dereferenced as host pointers.
The owner field at +216 supplies a hop address, whose +568 field supplies an
eight-byte link. A zero selector qword at `state` chooses displacement 16;
otherwise displacement 0. The selected link is at state+displacement+40, the
16-byte slot at +48, and the kind byte at +64.

Kind 0..4 retains all 16 entry slot bytes, kind 16..21 retains the first eight,
and every other kind clears all 16. The link is overwritten with its entry
snapshot, then output receives byte 5 last. The final tag can replace a byte
in the link or restored/cleared slot. Every admitted image alias is preserved.
The result is the original output address value, corresponding to raw RAX.

Only actually accessed ranges must exist. Owner/hop bases below the image are
accepted when their positive-offset fields fit. Invalid ranges or wrapping
address calculations return `Unavailable` before any write. The image itself
must not wrap. This checked image API excludes native faults, volatile/MMIO or
concurrent memory, raw pointer ABI and unobserved machine state. Field meanings
and original source types remain unknown.

This is a real standalone component, not a node workspace or binary match.
It has no dependencies, unsafe code, build scripts or external services.
The stdin-only client emits status, RAX and lossless full-image differences;
it has no expected-output file interface.

From the repository root, with Rust 1.94.1 installed:

```sh
cargo check --offline --locked --manifest-path src/node94-slot-restore/Cargo.toml
python3 -O research/work-items/RE-001-slot-restore-rust-94/verify.py --out work/slot-restore-replay
```

The [evidence packet](../../research/work-items/RE-001-slot-restore-rust-94/README.md)
contains the full static proof, independent pre-Rust fixtures, input-only native
builds, effective compiled mutations, exact raw streams and limitations.
New code is MIT; target disassembly retains original artifact rights.
