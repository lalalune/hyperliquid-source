# RE-004: complete raw-byte selector and returned data extent

This packet reconstructs the complete node #94 leaf
`[0x14b4e20,0x14b4e48)` in independently authored safe Rust. It closes every
raw byte input, all four written general registers, numeric load-bias wrapping
and the full 796-byte union of mechanically returned intervals. The earlier
`foundation-error-name-94` packet established a static relation, left Rust
unimplemented and explicitly stopped its data claim after 62 bytes.

Target: 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Task/component: bounded RE-004 reconstruction, foundation. Original source
identity, calling convention recovery and whole-component acceptance gates
remain unclaimed. The label “error-label selector” is descriptive, not a
recovered symbol or type.

The current source and live overlap inspection found no implementation claim
in 204 open PRs, 100 recent merged PRs or zero open issues. `scope.json` binds
the inventories and records the rejected alternative `0x5430d60`: its
post-memcmp `SETE CL; MOV EAX,ECX` does not close upper ECX bits through the
standard import ABI. This packet has no external call or unresolved helper.
Neighbor FDEs are boundary context, not additional implementations or a family
census.
## Observed relation and safe API

For the successfully read byte `t`, the captured leaf computes full RDX
`3*(t xor 1)+14` and full RCX `t`. RAX selects linked `0x21bf92` for zero
and `0x21bfa3` otherwise; RSI always retains the latter address. Both numeric
addresses include the supplied load bias modulo `2^64`.

All 256 tags are admitted by `select(u8,u64)`. The Rust input is the result
of the original byte read through RDI; original pointer accessibility, faults,
stack/flags, timing and CPU ABI are not modeled. Every numeric bias is handled,
without claiming every bias is a realizable executable mapping. No numeric
address is dereferenced by the Rust code.

`captured_bytes` is a separately documented safe host adapter over a supplied
796-byte window, not a memory read done by the captured function. The exact
captured data yields the complete mechanical returned span. At tag 254 the
length is 779, reaching `0x21c2ae`; tag 255 gives 776. Only 0/1 select exactly
the initial two literal intervals. Later spans include raw subsequent data;
no logical enum range, library/version, UTF-8 or meaningful-name claim follows.

See [PROOF.md](PROOF.md) for the full-domain argument, code/data closure,
normal-return premises and adapter limits. The new
[library](../../../src/node94-error-label-selector/lib.rs) is `no_std`, forbids
unsafe code and has no dependencies. Its source contains no copied inferred
implementation or transplanted captured instructions. The original artifact
bytes in evidence and fixtures retain their original rights; new code/docs
are MIT. The reference pin `999556f6e0a474b8312db96ec3149e1c44e97c23` remains
unchanged and its unlicensed implementation was not read or copied.

## Static evidence

`verify_static.py`, `static.json`, GNU/LLVM exports and `captured-window.hex`
bind the full 40-byte/ten-instruction body, complete FDE/CIE, neighbor FDEs,
four preceding/eight following padding bytes, both RIP targets and all 796
returned-data bytes. The data is file-backed in read-only `.rodata`/PT_LOAD.
All 256 spans fit, and tag 254 proves the upper extent tight.

All 80,300 RELA records are checked for code/data writers and uniqueness of
the entry slot `0x566de38`: one exact RELATIVE writer, raw file qword zero.
No E8/E9 encoding candidate targets the entry anywhere in `.text`. This is
not a complete indirect-call census and does not establish callers' tag domain.
There are no helpers or imports in this leaf. Thirty-six structural corruption
controls reject body/operands, FDE/CIE/boundaries, old-window overflow data,
maximum last byte, slot contents, duplicate/partial relocation writers and
introduced entry references, independently of the target-digest gate.

## Frozen expectations and actual native results

`oracle.py`, `frozen.json`, `inputs.bin.gz` and `expected.bin.gz` were generated
before the Rust source directory existed. They bind the static record, oracle
and all captured data. The oracle uses the independent parity formula
`3*t+17` for even bytes and `3*t+11` for odd bytes, unbounded integer quotient
remainders for addresses, and explicit byte-interval enumeration. It imports
no Rust and executes no captured instructions.

All 6,885 frozen cases include all 256 tags over common bias corners, additional
bit boundaries and deterministic random biases. There are 1,792 address-wrap
cases and 257 cases with numeric zero in RAX or RSI. The input-only native
client receives just bias, tag and the raw data window; it reads neither
expected outputs nor captured instruction bytes.

Actual qualification passed:

- Four builds, opt0/opt3 and a repeat of each: 27,540 output records agree in
  all four registers and every selected byte. Three unit tests pass/profile.
- Four repeated artifact pairs, rlib/client per profile, are raw byte-equal
  with no normalization.
- Twenty-five actual compiled wrong implementations run in both profiles:
  all 50 runs differ. Forty-two runs change registers; 24 change selected
  bytes, with overlapping categories. Controls cover XOR/parity, multiplier,
  additive constant, tag width/sign/boolean collapse, zero selection, both
  address additions and bias widths, full returned register widths, unconditional
  RSI and byte-view start/length/end. No refusal-only mutant is needed here.
- Changed output and missing-record comparator controls, plus three malformed
  input lengths/profile, are detected. All 25 mutant spellings first passed
  actual compiler metadata checks with warnings denied.

No qualifier or preflight failure occurred. Native commands and their exact
348 stdout/stderr streams are retained in `native-commands.json` and the
lossless `native-streams.json.gz` archive. The 6,901,376-byte archive has SHA-256
`986f3ceb6b776d6408b9cc8abc6ddc697f305744a23d2c028e0a0a59851873fb`.
It contains a label-to-hash map and base64 payloads; every stream's hash and
length is checked. Incremental content-addressed gzip checkpoints precede
each command assertion; one final consolidated archive uses gzip level 1,
mtime 0. The preflight archive retains all mutated sources and its 50 streams.
`native-audit.json`/`archive-audit.json` bind sources, frozen streams, command
logs, checkpoints, preflight-to-executed mutations and repeated artifacts.

## Exact build and repository validation

The actual compiler is rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, host/target
`aarch64-apple-darwin`, LLVM 21.1.8. Its file SHA-256 is
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The pinned recipe uses edition 2021, one codegen unit, overflow checks on,
warnings denied, opt-level 0 or 3 and `/usr/bin/cc`. The latter is Apple clang
17.0.0, file SHA-256
`34129c71a01a74f7f3b2443521519b2e5447553fa187f5fcafaaf8c42cc192e2`.
Full source/tool versions, hashes and actual command flags are retained.
This qualifies new ARM64 host code as a value component; it is not an original
Linux x86-64 compiled-byte match or node build.

From the repository root, with Python 3.14.3, Capstone 5.0.7, GNU binutils
2.47.20260726 and Apple LLVM objdump 17 available:

```sh
python3 -O research/work-items/RE-004-error-label-selector-rust-94/verify_static.py
python3 -O research/work-items/RE-004-error-label-selector-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/error-label-selector-replay
python3 tools/foundation_error_name.py \
  --check research/work-items/foundation-error-name-94/evidence.json
python3 -m unittest tests.test_foundation_error_name \
  tests.test_fde_extents_cie_aug_encoding tests.test_gnu_binutils_tools -v
make doctor
make verify
make catalogue-check
make reproduce
```

The legacy checker, 16 focused tests, all four make commands and rustfmt passed;
`checks.json` and its exact 18-stream archive record these results. The separate
parent baseline at source `56c0ec672bd8fdcfaa80f2db700a61e6240b3663` attempted
971 files / 15,462 reported tests / 69 skips. Its original `make test` exited 2
solely for three disk-full files; all 20 affected tests passed isolated retry.
No successful full-sweep rerun, full suite on this head, skipped Linux
qualification or hosted-CI success is claimed.

No captured executable, instruction emulator, live node, chain, credentials
or unlicensed inferred source was used. No imported pin, catalogue or gate was
changed. A future ABI/caller reconstruction would need its own closed evidence;
this packet establishes only the documented leaf and byte-view relation.
Authorship: OpenAI, Codex client; exact model identifier unavailable.
