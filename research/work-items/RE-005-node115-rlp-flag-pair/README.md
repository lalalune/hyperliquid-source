# RE-005: Node115 flag and two RLP scalar fields

Target Linux x86-64 node115 is SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(105896032 bytes). Base source is
`05bc2de303c05525b71e7e257426e741bc66a390`.
Coordinates below are linked ELF virtual addresses before load bias.
This packet advances the approved RE-005 serialization task and retains
RE-001 boundary/call evidence. It is a bounded reconstruction gap, not a
reported application vulnerability. No captured code ran and no gate changes.

## Question and result

The base's active source has no implementation or address-bound packet for
this flag/two-word reader. Recover its complete logical value/error/cursor
relation and the complete shared 256-bit reader, rather than guessing the
record's application name from a diagnostic. The independently authored,
dependency-free Rust component is `src/node115-rlp-flag-pair`.

| Body | Extent | Bytes | Role |
| --- | --- | ---: | --- |
| Flag/two-word root | 0x298f160..0x298f422 | 706 | New bounded question |
| Unsigned 256-bit reader | 0x2a00700..0x2a009a9 | 681 | Complete scalar composition |
| Caller A | 0x2986c90..0x2987130 | 1184 | Context only |
| Caller B | 0x2987130..0x29875dc | 1196 | Context only |
| Caller C | 0x29875e0..0x29879f6 | 1046 | Context only |
| Caller D | 0x2987a00..0x2987e8e | 1166 | Context only |

The two selected bodies are 1387 bytes and 365 instructions. Four complete
containing callers add 4592 bytes of context; they are not extra implementation
coverage. Every retained instruction row has independent GNU/Capstone
address/byte agreement. No bytes or operands are normalized.

## Observations and logical reconstruction

- The root's first value is false for the empty string prefix 0x80 and true
  for direct byte 0x01. Direct zero is rejected (code1), direct bytes2..127
  are rejected (code9), and a canonical one-byte value at least128 is rejected
  with code9. Other string lengths are rejected with code0 after their
  payload is consumed. The native error9 diagnostic at0x602150 is
  `invalid bool value, must be 0 or 1` (34 bytes).
- The root calls0x2a00700 at0x298f1c1 and0x298f1e7 in order, forwarding the
  first reached failure and its cursor. Success retains two four-limb words
  and a final flag. The output layout motivates a logical flag/word/word
  API, not an asserted original Rust type or native ABI.
- The scalar accepts empty as zero and1..32 big-endian bytes with no leading
  zero. It returns four little-endian limbs in least-significant-first order.
  A leading zero is code1, a longer value code0; both checks occur after
  consuming a complete canonical string payload. A source byte sequence is
  not copied into an implementation instruction window.
- A consumed RLP prefix stays consumed on every failure. A short declared
  payload stays unread; a noncanonical single-byte wrapper (code3) consumes
  only its prefix. Long headers consume available length bytes before
  rejecting leading-zero length (code1), length below56 (code4), or missing
  payload (code2). Missing length bytes leave the length bytes unread.
- A list is rejected with code7 when its declared payload is available,
  otherwise code2, without consuming the list payload. Long-list length
  canonicality checks run before that rejection. Numeric error codes are
  observations; no source enum names or inactive padding fields are invented.

The four instruction-boundary-qualified calls to the root are0x2986efd,
0x298737d,0x29877f5 and0x2987c3d. Their complete containing FDEs are retained
for replay. This is a census of E8/E9 candidate forms qualified against full
FDE disassembly in the initial probe, not a proof of every indirect/dataflow
caller or a complete transaction schema.

## Helpers, observations and limits

The shared indirect slot0x64df508 has an actual R_X86_64_GLOB_DAT relocation
to `memcpy`. The other two actual R_X86_64_RELATIVE slots are
0x64df520->0x1681da0 and0x64df848->0x1681e40. Those panic/error helpers are not
reconstructed. The scalar's checked loop reaches neither with valid disjoint
input/state/output, length at most32 and ordinary memory-copy behavior.
This restricted logical domain is an assumption, not recovered runtime closure.
The verifier binds the slots, instruction bodies and literal; it does not
claim libc, panic, allocation, aliasing, faults or whole-program equivalence.

The input parsing is inferred to be RLP from observed prefix classes, length
rules and big-endian integers. Application field names, signature validation,
cryptographic meaning, enclosing list/schema and call-site lifetime remain
unknown. No native execution, captured-instruction emulator, live chain,
network, signature creation or private data was used.

## Frozen expectations and controls

`frozen-predictions.json` was preserved before the Rust implementation;
its original SHA-256 is
`e0f3bdbb8f2a29504a210734861804cff7b9f1abdaa81ae978161e9adad87073`.
The20 manual predictions derive from the complete instruction paths, not
captured outputs. `predictions.tsv` is the same value/error/cursor table
consumed by a Rust integration test. Internal tests add a nonuniform
32-byte limb-order vector, long-list/string differences and truncated headers.
Four compiled wrong implementations (cursor, flag, leading zero, limb order)
are required to fail the behavior tests; operator receipts retain their
original nonzero exits. These controls do not establish target-execution
differential or Rust-to-original machine-code identity.

Physical evidence tests reject omitted/duplicated/zero-size or changed
Capstone rows, changed mnemonics, truncated/duplicated GNU output, wrong
artifact identity and changed recorded call/relocation declarations.

## Reproduce

Use the repository's authenticated Node115 artifact and installed GNU
binutils/Capstone. No tool is downloaded by these commands. Collection used
GNU2.47 and Capstone binding5.0.7 from the retained5.0.9 distribution.
Preserve providers' exact versions when replaying decoded text.

```sh
python -B tools/node115_rlp_flag_pair.py
python -B tools/node115_rlp_flag_pair.py --collect --objdump /absolute/path/to/objdump --packet work/rlp-replay
python -B -m unittest discover -s tests -p test_node115_rlp_flag_pair.py -v
python -B -O -m unittest discover -s tests -p test_node115_rlp_flag_pair.py -v
cargo test --offline --locked --manifest-path src/node115-rlp-flag-pair/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-rlp-flag-pair/Cargo.toml
```

Collection refuses an existing output directory. Original GNU stdout uses a
relative artifact argument, so it contains no operator's absolute path.
Raw .objdump files retain their exact bytes under the existing -text rule;
JSON, TSV, Python, Rust and Markdown use LF.

Initial base doctor and artifact hash/signature verification passed.
Initial base catalogue-check failed because generated README.md was stale.
These are initial checks, not final-head/full-suite results. Exact final
mandatory results, any failures and comparison scope belong in the PR.
No accepted component gate, measured Rust byte window or integrated node is
claimed. Next work is the enclosing transaction/schema and caller-owned
validation/ownership context.

## Necessary validation blocker correction

The active RE-005 work was blocked by the unmodified mandatory suite at
test_assembled_record_readers_static.py: its relocation mutation test creates
a fresh105896032-byte bytes object for every loop entry. The selected slot is
entry52494. Both the candidate and a separate exact-base control exceeded the
unchanged180-second no-progress bound at that test.

The one-line correction passes its unchanged local bytearray directly to
struct.unpack_from. Every one of60723relocation tuples matches an immutable
snapshot before mutation; the local array is changed only at the found slot,
then the loop breaks. All27assertion calls and11test methods are unchanged.
The corrected file ran all11tests in62.618seconds. No timeout, assertion,
fixture or test-selection rule is relaxed.

validation-blocker.json preserves the original base stdout, corrected stdout,
their raw SHA-256 values, source hashes and complete equivalence record.
This is the smallest infrastructure change needed to resume this active
reverse-engineering task under AGENTS.md, rather than standalone tooling work.
The imported target, original packet contents and original negative results
are preserved. This focused result is not a complete-suite pass.
