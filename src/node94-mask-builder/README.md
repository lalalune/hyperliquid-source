# node94 mask builder

Independent `no_std`, safe Rust for complete node94
`[0x5521d10,0x5521d37)`, target SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`apply(input, entry_rcx, load_bias, &mut slot)` replaces an eight-byte
image of global `0x5788110` and returns the full RAX, RCX and store-address
bits. It accepts every u64 input. Only full-width `u64::MAX` produces an
all-ones mask and preserves incoming RCX. Other inputs produce
`(1 << (input & 63)) - 1` and zero-extend the input's low32 into RCX.
The numeric store address includes the supplied load bias modulo 2^64.

For example, with incoming RCX `0x123456789abcdef0`:

| Input | RAX / stored qword | RCX |
|---|---|---|
| `0` | `0` | `0` |
| `64` | `0` | `64` |
| `255` | `0x7fffffffffffffff` | `255` |
| `0x1ffffffff` | `0x7fffffffffffffff` | `0xffffffff` |
| `0xffffffffffffffff` | `0xffffffffffffffff` | `0x123456789abcdef0` |

The slot is a supplied byte image, not a global variable created by this
crate. Returned address bits are never dereferenced. The function's original
name, quantity meaning and the global's runtime role remain unknown. Original
ABI, flags, faults and physical access traces are not reproduced. The
[evidence proof](../../research/work-items/RE-004-node94-mask-builder-rust/PROOF.md)
states the complete relation and original-memory premises.

Build standalone; there is no root Cargo workspace or dependency graph:

```sh
rustc +1.94.1 --edition=2021 --crate-name node94_mask_builder \
  --crate-type rlib src/node94-mask-builder/lib.rs \
  -C overflow-checks=yes -o work/libnode94_mask_builder.rlib
python3 -O research/work-items/RE-004-node94-mask-builder-rust/validate.py \
  --output work/node94-mask-builder/review
```

The input-only driver reads four hexadecimal u64 columns: input, entry RCX,
load bias and initial slot qword. It prints RAX, RCX, destination bits and
final slot qword. Expected results are kept outside that executable. New
source/docs are MIT; no inferred unlicensed reference implementation was
read or copied, and captured code is never executed by the validator.
