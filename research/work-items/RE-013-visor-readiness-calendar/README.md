# RE-013: admitted Visor +60 calendar rollover and fallback

This closes the calendar-domain gap left by
[readiness-clock](../RE-013-visor-readiness-clock/README.md):
given an explicitly canonical source date and ordinary time, the selected
deadline adds60 seconds across midnight/year boundaries and clamps overflow
at the greatest ordinary admitted triple. The timestamp producer and current
clock's calendar construction remain premises. No full readiness-policy,
elapsed-time, source-type or reconstructed-Rust claim is made.

Target: captured Visor, 8,305,392 bytes, SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
Component/task: visor / RE-013. Authoring base:
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Node #94/#115 are not targets.
All addresses are ELF VAs; records retain PT_LOAD-translated file offsets.

| Retained complete FDE extent | Bytes | GNU/LLVM rows | Role |
|---|---:|---:|---|
| `0x445830..0x445992` | 354 | 87 | time normalization, whole-day carry |
| `0x444040..0x44426c` | 556 | 145 | packed-date day adjustment |
| `0x330360..0x330581` | 545 | 140 | fixed binary64 60 conversion |
| `0x5b41b0..0x5b470d` | 1,373 | 276 | source copy, calls, guards, fallback/compare |
| Total | 2,828 | 648 | native context, not new recovery credit |

These bytes were already exported by the earlier packet. The contribution is
the conditional semantic closure and bounded arithmetic certificates, with
**zero newly recovered byte credit**. The analogous
[node #94 packet](../RE-001-chrono-shift-helpers-94/README.md) excludes Visor
and leaves the second table's meaning open; no node instruction or inferred
reference implementation is used here. No unmerged packet is a dependency.

## Result and assumptions

[PROOF.md](PROOF.md) supplies the address-bound argument and all premises.

- Canonical dates use years -262143 through 262142, ordinal 1 through the
  Gregorian year's length, and the independently derived 400-year flag table.
  The raw 401-byte leap-prefix and 400-byte flag tables match the formulas.
- For seconds s in [0,86399] and nanos n in [0,999999999], fixed +60 gives
  second `(s+60)%86400`, unchanged n, and day delta `[s>=86340]`.
  Both caller carry guards admit the only two possible carries.
- Every ordinary date path is either the within-year fast path or one of 400
  year-end cases. The latter yields next-year ordinal 1 without needing the
  helper's borrow-correction branch. Only rollover past year 262142 returns zero.
- The fallback `(2147473118,86399,999999999)` is the last ordinary admitted
  triple. Under the same ordinary domain for the current value, strict
  comparison against it selects deferral, including equality.
- Separately, source n in [1e9,2e9) becomes n-1e9 with the same day carry.
  This raw normalization is not a civil leap-second contract. A current value
  at the fallback date/second with n=1e9 is strictly greater: the ordinary
  deferral theorem does **not** cover that extended current domain.

Premises include readable stable input, canonical timestamp values, valid
nonaliasing storage, unchanged code/tables/relocations and ordinary instruction
and call preservation. The producer of either timestamp is not proved here.
Earlier opaque calls, clock changes, all generic helper inputs, cold error
callees, incoming computed references and later diagnostic-call outcomes stay
outside the proof. FDE extents are unwind evidence, not complete ownership.

## Reproduce and validate

The packet-local scripts only read the authenticated ELF, invoke native
readelf/objdump/LLVM decoders on a read-only temporary copy, and check scalar
integer formulas. There is no captured execution or instruction interpreter.
Set the three tool paths to installed GNU binutils and LLVM. On the retained
macOS run they were `/opt/homebrew/opt/binutils/bin/{objdump,readelf}` and
`/Library/Developer/CommandLineTools/usr/bin/llvm-objdump`.

```sh
packet=research/work-items/RE-013-visor-readiness-calendar
python3 "$packet/collect.py" --binary artifacts/visor/captured/hl-visor \
  --output work/visor-calendar-native-new
python3 "$packet/arithmetic.py" --binary artifacts/visor/captured/hl-visor \
  --output work/visor-calendar-native-new/arithmetic.json
python3 "$packet/verify.py" --binary artifacts/visor/captured/hl-visor \
  --output work/visor-calendar-verify-new.json
python3 -O "$packet/verify.py" --binary artifacts/visor/captured/hl-visor \
  --output work/visor-calendar-verify-optimized-new.json
```

Each command also accepts `--objdump`, `--readelf`, `--llvm`, except
arithmetic.py, which needs no native tools. Output directories/files must be
new. Raw native output and version fields are tool-version-sensitive; exact
retained regeneration uses the recorded providers.

Normal and `-O` verification regenerate the 14 retained outputs and reject 46
controls: 3 image-identity, 39 named instruction/data/RELA/FDE/CIE binding controls
run below whole-image authentication, and 4 row/FDE-record controls.
These categories remain distinct. A changed-program semantic test is not
claimed merely because an exact binding check rejects a change.

The finite certificates exhaust the signed-year /400 domain, positive seconds
/86400 domain, relevant cycle /146097 and /365 domains, every output-year
gate value, all 400 year-end cases and canonical ordinal path classes.
The native-to-formula correspondence still needs the manual proof; finite
arithmetic is not a substitute for it. Exact commands, source/artifact hashes
and results are in [VALIDATION.json](VALIDATION.json), with concise receipts in
[validation/](validation/). GNU and LLVM agree on all 648 byte partitions.

No Rust build, two-build comparison, hosted CI or complete component gate is
claimed. Repository baseline checks belong to the integration review. Full
test discovery is excluded because it includes captured-instruction evaluators.
No imported evidence, progress gate, catalogue or shared tool was changed.

## Provenance and next question

ELF mapping/RELA and decoder-partition mechanics adapt the project's MIT
readiness-clock survey and LLVM crosscheck; this packet's bindings and
arithmetic are independently authored. The official
[Chrono v0.4.42 date source](https://github.com/chronotope/chrono/blob/v0.4.42/src/naive/date/mod.rs)
was consulted as a comparison lead. It does not authenticate the captured
source symbol/version and is not independent corroboration of binary behavior.
No inferred unlicensed source was read or copied into these scripts.

Next question: bind the original timestamp's construction and mutation sites
before composing this admitted arithmetic with a complete readiness policy.

The [independent integration review](ROOT_REVIEW.json) binds the corrected
proof and final sources; the author receipts above preserve their original
pre-integration hashes. [ROOT_VERIFY.json](ROOT_VERIFY.json) records the final
coordinator reproduction.
