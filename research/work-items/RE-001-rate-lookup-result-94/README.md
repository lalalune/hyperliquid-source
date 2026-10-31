# RE-001: rate-maintenance-associated callee return word, node #94

- Component: `transport`; a bounded call-boundary question, not a later-task
  implementation or prerequisite-completion claim.
- Target: Node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Independent source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
  Pinned reference: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  No reference implementation was consulted or copied for this question.
- Claim status: observed instruction/data coordinates; inferred local arithmetic;
  helper, object, policy and concurrency contracts unresolved. No gate requested.

## Question and prior evidence

The earlier [maintenance packet](../RE-001-rate-maintenance-94/README.md)
retains the guarded caller at `0x4714c10` and the call to `0x4956d50`, but
leaves the latter's result contract open. This packet asks what word its two
visible normal-return sites compute, and whether the selected caller compares
that result before passing it onward. It adds the callee's exact unwind extent
and revisits only the caller's result-use slice.

The rate-maintenance association comes from that earlier packet's embedded
`net_utils/src/rate_limiter.rs` source-location record. It does not recover
this callee's Rust symbol, source file, method, type or business meaning.
`lookup` is a local filename label only. No table-entry or admission enum is
inferred from a reference filename or an immediate value.

## Reproduce

Debian 13.6, Linux x86-64, Python 3.12.14, GNU binutils 2.44. Existing project
artifacts and all seven pinned submodules must be present; no install, recovery
download or binary execution is part of these commands. Run from repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/rate_lookup_result_static.py --output work/rate-lookup-result-94
diff -ru research/work-items/RE-001-rate-lookup-result-94/observed work/rate-lookup-result-94
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p test_rate_lookup_result_static.py -v
sha256sum -c research/work-items/RE-001-rate-lookup-result-94/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The collector authenticates the complete input against both the checked-in
artifact identity and this question's explicit Node94 pin. Native tools receive
only a separate, owned mode-0600 non-executable snapshot in a mode-0700 temporary
directory. Full snapshot SHA-256 and identity checks run before and after native
collection. The source identity and full digest must also remain unchanged;
incidental source hard-link count/ctime changes are allowed. Only the owned
snapshot is cleaned up. It checks selected instruction bytes and five RELA records.
The project's `.eh_frame`
reader and GNU `readelf -wf` independently agree on the two selected extents.
GNU `objdump -d --insn-width=16` uses default AT&T syntax and linked ELF VAs;
displayed bytes must match the selected file bytes contiguously. No instruction
operand or value is normalized. The private snapshot pathname alone becomes
`<authenticated-node94>` in raw disassembly. Binutils rendering can vary;
`observed/records.json` also binds actual body hashes and options are fixed above.
Native exports use `LC_ALL=C` and explicit UTF-8/LF text writes. The output
directory must not already exist: use a fresh path for every author repeat.
An existing empty directory, file or symlink is rejected. Input/native validation
finishes before output creation. A later publication I/O failure can leave only
the newly created partial directory; earlier evidence is preserved.

### Native input consistency control

The initial collector at `f1dad89734bb94f3a87d6d5bb1a697b8f202e4b2`
authenticated a byte vector but let native tools reopen the caller's pathname.
A private-copy reproduction replaced that pathname after authentication and
changed just the lookup FDE's CIE-reference field at file offset `0x12aaa44`:
`18ce2e00` became `2c955c00`, selecting the existing valid `zR` CIE at
`0xce1518` instead of `0xfbdc2c`. Real GNU `readelf` then exported the changed
CIE binding while `records.json` still described the original bytes, and the
initial collector returned success. The other four exports stayed identical.
`input-binding-before.json` retains those exact hashes, coordinates and lines.

The corrected regression performs the same swap on an owned copy and uses real
GNU tools. All native readers stay on the admitted snapshot; the final source
identity/digest check rejects the replaced source before publishing any output.
The regression fails on the initial collector with `ValueError not raised` and
passes on the correction. Small independent filesystem controls reject mutation
of the owned snapshot and allow source hard-link metadata changes while still
rejecting changed bytes with restored size/mtime. No canonical input is edited.

No captured executable, emulator, node service, chain action, network protocol,
filesystem operation implemented by the target, or reference implementation runs.
The only processes invoked by the collector are GNU static metadata/disassembly
tools. The output directory is ordinary local research evidence.

## Exact scope and coordinates

| Region | ELF VA, half-open | File offset | Bytes |
| --- | --- | --- | ---: |
| Callee unwind extent, displayed in full | `0x4956d50..0x4956eeb` | `0x4955d50` | 411 |
| Existing caller unwind extent, metadata/hash only here | `0x4714c10..0x4714ffb` | `0x4713c10` | 1,003 |
| Caller result-use slice, displayed here | `0x4714f17..0x4714f66` | `0x4713f17` | 79 |

There are 490 displayed bytes in the accepted exports: 411 newly displayed
callee bytes plus 79 revisited caller bytes. The parent caller extent is not
counted again. Neither two unwind records nor 490 bytes is a reconstructed
function count, complete component denominator or equivalence measurement.
Unwind extents alone do not prove complete function boundaries.

The initial caller display stopped at `0x4714f67`, inside the epilogue
instruction starting at `0x4714f66`. The incomplete raw display and its original
hash are retained in `rejected/`, with an explicit correction record. It is
excluded from accepted display bytes and every interpretation below. The final
79-byte slice ends before that epilogue. The listing-byte validator checks
contiguous bytes; it is not a general instruction-boundary proof.

## Observed return arithmetic

At `0x4956d5a`, `xor eax,eax` sets RAX to zero; `cmp (%rdi),%rax` computes
flags for 64-bit `0 - [rdi]`; `jno 0x4956d78` takes the helper-bearing path
when this subtraction does not overflow. For 64-bit signed subtraction, zero
minus a word overflows only for the bit pattern `0x8000000000000000`. This is
an architectural arithmetic inference, not a Rust discriminant or a claim that
arbitrary input words are valid objects.

For that bit pattern, the fall-through sequence at `0x4956d61` and
`0x4956d69` computes, then returns at `0x4956d77` without a call:

```text
RAX = ([rdi + 0x08] + 608 * [rdi + 0x18]) modulo 2**64
```

For the other word patterns, the shown path copies selected input words to its
stack and makes calls through the selected relocation slots below. Immediately
before direct call `0x4959020`, it sets RDI to `rsp+0x58`, RSI to `rsp+0x20`,
and RDX to `rsp+0x2b8`. If these opaque calls return normally and execution
reaches `0x4956e7a`, its second visible normal return at `0x4956e92` computes:

```text
RAX = ([rsp + 0x58] + 608 * [rsp + 0x68]) modulo 2**64
```

Both sequences use the same immediate stride, with different operand locations.
They constrain a future address/word-return contract; they do not prove that the
result is a valid pointer, that a 608-byte object exists, which source fields
were used, or what the helper wrote. Temporary cleanup and unwind tails remain
opaque despite their raw bytes being retained. No allocation or lifetime
guarantee follows from the no-call fragment on an arbitrary invalid object.

## Observed caller use

The caller builds two stack arguments and directly calls `0x4956d50` at
`0x4714f38`. Between its return and the next call, the selected instructions:

1. set RDX to numeric data address `0x572e848` without reading its contents;
2. set ESI to one;
3. copy the unchanged returned RAX word to RDI at `0x4714f49`;
4. load XMM0 from the caller's `rsp+0x10`;
5. call through slot `0x576efb0`, whose RELATIVE addend is `0x14027b0`.

There is no comparison or conditional branch on the returned word between
these two calls. In particular, the observed callee result is forwarded as a
callback argument, not used here as a directly tested admission boolean.
Neither the callback's type nor the value at `0x572e848` is established.

After that indirect call, the selected continuation overwrites AL with one
before the byte `lock cmpxchg`. On the displayed fall-through after the branch
at `0x4714f61`, `mov %r14d,%eax` overwrites the full architectural return word.
The alternate branch to `0x4714fb3` is outside this new slice; the packet makes
no function-wide statement about callback-result handling on that branch.
The origin or meaning of the saved R14D is not recovered here.

## Selected relocation obligations

Raw rows from `readelf -rW` accompany directly parsed ELF64-LE RELA records:

| Slot VA | Info | Addend / observed native import |
| --- | --- | --- |
| `0x576e010` | `0x8` | `0x54c8cb0` |
| `0x576e040` | `0x8` | `0x1344760` |
| `0x576efb0` | `0x8` | `0x14027b0` |
| `0x576efc8` | `0x8` | `0x1403c30` |
| `0x576dfe0` | `0x600000006` | zero addend; `memcpy@GLIBC_2.14` |

The first four are numeric RELATIVE targets, with no invented Rust names.
The last row records an import identity, not its runtime resolution. The
full callee export also shows direct calls to `0x5660110` with GNU's
`_Unwind_Resume@plt` display label; exception/helper closure is not claimed.
Nearest-symbol offsets on other objdump labels do not identify callee symbols.

## Validation, implementation and limits

Ten focused tests authenticate the real Node94 bytes, verify 16 instruction
sites, reject a single-byte mutation at each site and five actual relocation
addend retargets below the whole-input hash gate, and check numeric targets.
The arithmetic tests examine actual encoded stride/operand bytes and selected
boundary examples. They are local architectural models, not execution or
semantic differential tests. The listing tests reject missing, shifted and
byte-altered selected output. The real CLI is also run against an existing
empty output directory and one containing prior binary/text bytes: both fail
without changing entries or bytes. `focused-tests.txt` retains the author run.
The three native-input/filesystem controls above are included in that count.

Independent Rust path, Cargo.lock/build flags, two-build comparison, raw or
normalized equivalence, masks, runtime fixtures and performance: **not yet
implemented/measured**. No #115/visor claim, target execution, full admission/
TTL policy, complete object/table ABI, helper/exception closure, concurrency
claim, source-pin change, catalogue change or progress gate. The remaining
concrete question is the actual postcondition of `0x4959020` on the stack words
later consumed at `rsp+0x58` and `rsp+0x68`, followed by the callback's independent
contract. This packet does not implement either by guessing a type or policy.
