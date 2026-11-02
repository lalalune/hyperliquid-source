# node94 five-word coefficient combination

Independent `no_std` Rust value and byte-image reconstruction of the complete
306-byte helper `[0x565e960,0x565ea92)`, node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`combine` admits every pair of five-word values and raw signed-i64 coefficient
bit patterns. For each term, it conditionally negates the whole 320-bit input,
multiplies its low 256 bits by the coefficient magnitude, and subtracts the
transformed fifth word AND magnitude at bit256. It then adds the two terms
modulo2^320. It preserves this unusual fifth-word rule rather than assuming a
general 320-bit multiplication. The result includes five output words and all
13 modified GP registers, including the final raw MUL halves in RAX/RDX.

`apply_image` reads two adjacent 40-byte inputs and writes a 40-byte result.
It snapshots all 80 input bytes before writing, so arbitrary unaligned data
aliases are admitted. Offsets describe one nonwrapping finite image, never
native pointers. Missing spans produce the new API's `None` refusal without
changing the image. See the [full proof and premises](../../research/work-items/RE-004-node94-five-word-combine-rust/PROOF.md).

Build this component with the pinned installed rustc 1.94.1:

```sh
mkdir -p work/node94-five-word-combine/manual
/opt/homebrew/opt/rustup/bin/rustc +1.94.1 --edition=2021 -Dwarnings \
  --crate-name node94_five_word_combine --crate-type rlib \
  -C opt-level=3 -C overflow-checks=yes -C panic=abort \
  src/node94-five-word-combine/lib.rs \
  -o work/node94-five-word-combine/manual/libnode94_five_word_combine.rlib
python3 -O research/work-items/RE-004-node94-five-word-combine-rust/validate.py \
  --output work/node94-five-word-combine/recheck
python3 -O research/work-items/RE-004-node94-five-word-combine-rust/verify_recorded.py
```

There is no Cargo workspace or external library dependency. The separate
input-only client uses `std`; the library forbids unsafe code and allocates
nothing. Qualification covers 13,570 descriptors per build, at opt0/opt3 with
repeated builds: 13,505 admitted projections and 65 explicit API refusals each.
Eighteen compiled controls change admitted target projections; one separately
tests refusal atomicity. No captured code or instruction emulator was run.

This is a bounded value/image projection under stable ordinary-memory,
successful-access premises. Native ABI, flags, stack/CET, exceptions, MMIO,
concurrent observations, original quantity meanings and whole-node behavior
remain outside its claim. Original input/output effective address formation
must be nonwrapping for this finite-image adapter.
