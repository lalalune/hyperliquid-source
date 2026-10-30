# RE-001: Bucket guard timing, fixed window roller, and latency sampling, node #94

- Component `foundation`; one bounded RE-001 boundary/xref question, no
  prerequisites; no component gates change.
- Node #94 SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes; no #115/visor claim.
- Independent main base `6fb86319763b30860f92b9da746cbe4f9b637573`.
- Reference `999556f6e0a474b8312db96ec3149e1c44e97c23`;
  unlicensed `base/bucket_guard.rs` is a lead, not copied implementation or trusted
  semantics. All tool/test code here was authored from target bytes.
- Question: how is the fixed window roller laid out, how are bucket durations calculated,
  and how does the guarded latency sampling path operate?

The observed debug extent at `0x13e09a0` reveals the concrete field layout of
`FixedWindowRoller`: fields `pattern`, `compression`, and `count` at relative offsets
`+0x1c`, `+0x20`, and `+0x18`. The bucket duration calculation extent at `0x13c8e10`
applies integer scaling factors of 1,000 (milliseconds), 1,000,000 (nanoseconds), and
86,400 (day boundary) with an unwrap panic location binding to `base/src/bucket_guard.rs:66:84`.
The guarded latency sampling extent at `0x2227c80` gates execution on byte `+0x20 == 1`,
records sample durations to location `base/src/bucket_guard.rs:118:21`, and releases
its lock via atomic `lock cmpxchg`. These establish structural invariants without
claiming a complete rate-limiter, scheduler, or full runtime equivalence.

## Reproduce

Linux, Python 3.10+, authenticated project inputs/unchanged references, GNU
binutils. Recorded on Windows/binutils 2.47 and cross-checked against project invariants.

```sh
make doctor verify test catalogue-check reproduce
python3 tools/bucket_guard_static.py --output work/bucket-guard-init-94
diff -ru research/work-items/RE-001-bucket-guard-94/observed work/bucket-guard-init-94
python3 -m unittest discover -s tests -p test_bucket_guard_static.py -v
```

Full input identity is checked first. Exact FDE extents come from `readelf -wf`;
RELA bindings are parsed and raw `readelf -rW` rows retained. `objdump -d` uses
default AT&T syntax and linked ELF VAs. Only its local input pathname is
replaced; no instruction/body normalization is performed. Different binutils
rendering is possible; exact bytes/body hashes are retained. No captured node,
emulator or supervisor was executed; no model, chain or networked-node calls.

## Exact scope and attribution

| Inferred role | ELF VA, half-open | File offset | Bytes |
| --- | --- | --- | ---: |
| Bucket duration calculation | `0x13c8e10..0x13c8f53` | `0x13c7e10` | 323 |
| Fixed window roller debug | `0x13e09a0..0x13e0a42` | `0x13df9a0` | 162 |
| Guarded latency sampler | `0x2227c80..0x2228121` | `0x2226c80` | 1,185 |

Three exact unwind regions, 1,670 bytes; not three reconstructed Rust functions
or a matching denominator. Two source-location RELA records at `0x5666b68` and
`0x569e0a0` point to `/home/ubuntu/hl/code_Mainnet/base/src/bucket_guard.rs` at
VA/file offset `0x1e2490` (lines 66:84 and 118:21). Slot `0x5666f58` resolves to
`0x13d2f20`, and slot `0x56676d0` resolves to `0x13e71d0`.

## FixedWindowRoller field layout

The Debug implementation at `0x13e09a0..0x13e0a42` loads the struct name and
field names:

| Struct / field name | Virtual address | Length | Relative struct offset |
| --- | --- | ---: | --- |
| `FixedWindowRoller` | `0x217634` | 17 | `+0x00` (type name) |
| `pattern` | `0x217645` | 7 | `+0x1c` (`rcx`) |
| `compression` | `0x21764c` | 11 | `+0x20` (`r10`) |
| `count` | `0x217657` | 5 | `+0x18` (`r14`) |

The struct debug helper forwards these references to the standard debug struct
formatter call at `0x576eb80`. This establishes the memory layout of the roller
component in `bucket_guard`.

## Integer scaling in duration calculation

The duration calculation extent at `0x13c8e10..0x13c8f53` computes duration
boundaries using exact integer multiplication:

1. `imul $0x3e8, %r15d, %ecx`: scales by 1,000 for milliseconds conversion.
2. `imul $0xf4240, %r14d, %ecx`: scales by 1,000,000 for nanoseconds conversion.
3. `imul $0x15180, %r12, %rdx`: scales by 86,400 for 24-hour day boundaries.

Failure on the unwrap branch at `0x13c8f08` loads the static panic string
`called Result::unwrap() on an Err value` at `0x216f9d` and line location
`0x5666b68` (`bucket_guard.rs:66:84`), invoking the panic runtime at `0x576e048`.

## Guarded latency sampling and atomic unlock

The extent at `0x2227c80..0x2228121` gates sampling through byte check:

```
movzbl 0x20(%rdi), %r14d
cmp    $0x1, %r14b
jne    2228079
```

When enabled (`1`), execution timestamps are collected before and after the
operation. The elapsed latency (`xmm0`) is recorded at `0x2228068` with
location parameter `0x569e0a0` (`bucket_guard.rs:118:21`). The guard releases
its spinlock using an atomic compare-exchange:

```
xor    %ecx, %ecx
mov    $0x1, %al
lock cmpxchg %cl, (%r15)
jne    22280c4
```

with the fallback slow-path unlock dispatched at `0x22280c4`.
