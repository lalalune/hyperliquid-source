# RE-001: node #115 fee-schedule validator: post-gate path and `true` return

- Component: `fees`. This is the third follow-up to `RE-001-node115-fee-schedule-gate` (#2153), after `-sources` (#2162) and `-finite` (#2169).
- Target #115: 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Question: after the ordering and range chain, what must hold for the validator `0x36a1c20` to return true?
- Claim status: byte-derived observations plus conditional normal-path relations. The floor helper and the map iterator are opaque. No Rust reconstruction, oracle or progress gate.

## Result

With these packets, the validator's normal-path result is accounted for end to
end, except for two opaque helpers. **AL=1** (the `bool`) is reached only if
all of the following hold. Every failure returns EAX=0 (#2153):

1. **Finiteness gate** `0x3d3b6c0` (#2169).
2. **Ordering, pair and range chain** (#2153), over the slices bound in #2162.
3. **Map sum** (`0x36a2a8b`): `0x3c6d100(&[rsp+0x270], &input+0x48)` starts an
   iterator, and `0x4504fe0` yields `(rax, rdx)` until `rax=0`. The sum starts
   at **−0.0** (`0x459458`) and adds `*rdx`. It fails if `sum ja 1.0`, so the
   sum must be at most 1.0.
4. **Discount range** (`0x36a2d59`): `[rsp+0x10]` fails if it is above 1.0 or
   below 0.0. `[rsp+0x10]` holds +0.0 (`0x36a2a31`) or the last stake pair's
   second component (`0x36a2a41`). A native CFG shows no other store on the way.
   **Redundant on the normal path:** #2153 already requires those components to
   be strictly increasing from +0.0 with the last at most 0.5.
5. **Two floor-helper calls**: `0x36a58d0`, a 1,136-byte opaque helper, is
   called with a record at `[rsp+0x140]`, and the validator fails on AL=0.

   | Record field | Perp call `0x36a2e1c` | Spot call `0x36a2eba` |
   | --- | --- | --- |
   | `+0x00` | `&[rsp+0xa0]` (slice 2 vector) | `&[rsp+0xd0]` (slice 4 vector) |
   | `+0x08` | `&[rsp+0x18]` (slice 5 vector) | `&[rsp+0x30]` (slice 6 vector) |
   | `+0x10` | `r12 = &[rsp+0x88]` (slice 1 vector) | `&[rsp+0xb8]` (slice 3 vector) |
   | `+0x18` | `input+0x70` | `input+0x80` |
   | `+0x20` | `input+0x68` | `input+0x78` |
   | `+0x28` | `input+0x88` | `input+0x88` |
   | `+0x30` | `[rsp+0x10]` (last stake second) | same |
   | `+0x38`, `+0x40` | `input+0x90` (twice) | same |

   The native CFG shows that `r12` is not written between `0x36a2576` and
   `0x36a2dae`.
6. **Cross range** over every element of slice 1, then slice 3 (an inline
   two-range chain). A value fails if `0.0 > x` or `x > 0.001` (`0x459af0`).
   A value with `x > 0` must also satisfy `x ≥ 0.0001` (`0x459b50`). So each
   value is **0, or lies in [0.0001, 0.001]**.
7. **Add range** over every element of slices 2, 5 and 4, using the chain
   iterator `0x36e1b90`, then slice 6 inline. A value fails if `|x| > 0.001`
   (`andpd` with the mask `0x7fffffffffffffff×2` at `0x450180`), and a positive
   value must be at least 0.0001. So each value lies in **[−0.001, 0] ∪ [0.0001, 0.001]**.
8. **Success**: `mov bpl,1` and `mov bl,1` (`0x36a30cb`), then the shared
   epilogue `mov eax,ebx`. Only **AL** is defined as 1.

`0x36e1b90` (complete FDE, 111 bytes) is fully decoded. Its tag `[rdi]` has
three states:
- **1:** yields range A `[+8,+0x10)`, then range B `[+0x18,+0x20)`, then sets the tag to 0;
- **0:** yields range C `[+0x28,+0x30)`, then sets the tag to 2;
- **2:** finished.

Each element is returned as a pointer in RAX.

## Relation to retired #94 evidence

#128's rows line up with these checks:
- `extra_sum` corresponds to the map sum;
- `discount_high/low` were "never reached", which matches the redundancy shown here;
- `perp_floors`/`spot_floors` correspond to the two `0x36a58d0` calls (#94 used `0x3c05c30`);
- `cross_negative`/`cross_cap` correspond to the cross range;
- `add_cap` corresponds to the add range.

#128 did not list the **positive minimum of 0.0001**, which applies to both
the cross and add ranges. These are leads, not names for #115.

## Reproduce and validation

Python 3.13.18, Linux x86_64, GNU binutils 2.42. From repository root:

```sh
python3 -B tools/fee_schedule_post_static.py --output work/fee-schedule-post115
python3 -B -m unittest discover -s tests -p test_fee_schedule_post_static.py -v
make doctor verify test catalogue-check
(cd research/work-items/RE-001-node115-fee-schedule-post && sha256sum -c MANIFEST.sha256)
```

Five focused tests cover:
- regeneration;
- the decoded cross and add predicates at their boundaries, and the floor-call records;
- **nine synthetic schedules** run through the joined model: finiteness from
  #2169, ordering from #2153 and #2162, and this post-gate path, with the floor
  helper supplied as an oracle;
- four counterfactuals:
  - the shared 1e-4 literal;
  - `ja→jae` on the add maximum;
  - `ja→jbe` on the sum;
  - a moved perp record argument;
- 11 corruption controls below the identity gate, each rejected.

No captured code was executed. Imports, pins and gates are unchanged.

## Limits and next question

Not claimed:
- the internals of `0x36a58d0`, `0x3c6d100`, `0x4504fe0` and `0x37c7260`;
- source names;
- other callers of `0x36a1c20`;
- panic, unwind and allocator-failure behaviour.

Next question: the floor helper `0x36a58d0`, the last predicate in this
validator. #94 recorded fused multiply-add floors with scales 1.0, 0.2, 6.0
and 0.1.
