# node94 calendar constructor

Independent safe `no_std` Rust for complete node94
`[0x151f6f0,0x151f86a)`, bound to target SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`construct(input, entry_rax)` accepts every u64 pair. It interprets only
input's low32 as a signed day count and returns full RAX plus RCX. RAX is
nonzero exactly for day counts `-95746129..=95745399`; outside that interval
it is the original function's zero result, not a new API refusal. RCX always
contains the supplied incoming RAX, matching the target's PUSH/POP sequence.

A nonzero result packs a signed 19-bit year at bit 13, a one-based ordinal at
bit 4 and four year-flag bits. For example, input day -365 returns RAX `0x14`,
day 0 returns `0x16e4`, and day 1 returns `0x201e`. Input high32 is ignored.
The year range is `-262143..=262142`. No native pointers or process state are
read by this API. Other scratch registers, flags, original ABI, physical
stack, faults and access traces are excluded.

The [full proof](../../research/work-items/RE-004-node94-calendar-constructor-rust/PROOF.md)
closes every original input, every table index and all four panic arms.
Those arms are unreachable under the bound readonly tables. This does not
reconstruct the enclosing millisecond conversion or the nearby packed-date
addition. The source derives the calendar flags arithmetically; it does not
transplant captured code or a reference table initializer.

Standalone build and qualification, with no root Cargo workspace:

```sh
rustc +1.94.1 --edition=2021 --crate-name node94_calendar_constructor \
  --crate-type rlib src/node94-calendar-constructor/lib.rs \
  -C overflow-checks=yes -o work/libnode94_calendar_constructor.rlib
python3 -O research/work-items/RE-004-node94-calendar-constructor-rust/validate.py \
  --output work/node94-calendar-constructor/review
```

The input-only client reads two hexadecimal u64 columns, input bits and
incoming RAX, and prints returned RAX/RCX. It receives no expected outputs.
New source and documentation are MIT; no unlicensed inferred source was
read or copied. Native validation executes only newly built Rust.
