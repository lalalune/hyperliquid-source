# node94 fused multiply/fold leaf

Independent `no_std` Rust reconstruction of the complete 786-byte leaf
`[0x565d440,0x565d752)`, node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`Prepared` contains eight independent incoming register words. `evaluate`
combines them with four A words, three later-B words, four M words and the
supplied value of original `[entry RSP+8]`. It returns four output words and
all 13 modified general-purpose registers. It preserves 384-bit accumulator
wrap, the low/high fold's discarded carry, and the final five-word subtraction.
Neither matching prepared registers nor a modular-inverse property is required.

`apply_image` models stable byte reads and the final four qword stores. Only
B+8..B+31 is read from the B region; B+0 is unused. All data aliases are admitted
because every input read precedes every store. Original stack/control storage
is explicitly disjoint from the represented data image; its output-address
slot is supplied as a value, never dereferenced by Rust. Missing spans produce
the new API's atomic `None` refusal. See the [complete proof](../../research/work-items/RE-004-node94-fused-multiply-fold-rust/PROOF.md).

The library has no allocation, external dependency or unsafe code. Build with
the pinned installed compiler, independently of any root Cargo workspace:

```sh
mkdir -p work/node94-fused-multiply-fold/manual
/opt/homebrew/opt/rustup/bin/rustc +1.94.1 --edition=2021 -Dwarnings \
  --crate-name node94_fused_multiply_fold --crate-type rlib \
  -C opt-level=3 -C overflow-checks=yes -C panic=abort \
  src/node94-fused-multiply-fold/lib.rs \
  -o work/node94-fused-multiply-fold/manual/libnode94_fused_multiply_fold.rlib
python3 -O research/work-items/RE-004-node94-fused-multiply-fold-rust/validate.py \
  --output work/node94-fused-multiply-fold/recheck
python3 -O research/work-items/RE-004-node94-fused-multiply-fold-rust/verify_recorded.py
```

Qualification matches 10,896 cases per build at opt0/opt3 and repeats both:
10,677 admitted projections and 219 finite-image refusals each. Twenty-one
compiled controls alter successful admitted values; one separately changes
only new-API refusal images. The input-only native client receives no expected
outputs or oracle. Only newly authored Rust is executed.

The two dispatch wrappers, original ABI, flags, stack/CET effects, fault/MMIO
or concurrent observations, input meanings, compiled-byte identity and whole
node reconstruction remain excluded. No component progress gate is advanced.
