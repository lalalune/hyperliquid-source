# RE-001: complete constructed hex-iterator state and result relation

Foundation question: what does the complete 953-byte node94 iterator do to its
cursor, byte count, halt flag and result bytes for every immutable valid UTF-8
string, including invalid scalars, odd nibbles and repeated calls?

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The original measured base is `3324e50333042b391312515e542279ca21f63dc8`.
Current integration starts at `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`;
the [resume addendum](resume/README.md) separates new observations from the
unchanged historical builds and frozen proof. Primary complete
FDE: ELF VA `0x4eb64f0..0x4eb68a9`, 953 bytes / 242 GNU rows, hash
`2149bd77d5168ff0d084c27ed603847edf1b735b70ce0dc6572016f36510215d`.
The separate supporting scalar decoder is `0x4eb6360..0x4eb63ec`, 140 bytes /
47 rows, hash `5886107cd1d6c98febbed6cfd33b4bdf940a84320ce65ba12be53097cce9b70e`.
The already established 876-byte outer address caller remains context only.

Accepted #339 supplies outer/ASCII framing and selected anchors, without
complete Unicode/helper/state closure. Merged #1334 supplies an outer
ASCII 20-byte address acceptance/payload API and explicitly leaves those gaps
open. This packet implements the distinct complete stateful iterator and its
normal scalar-helper relation. It does not add an outer address API or count
nibble cases as separate contributions. Existing source/evidence stays intact.

## Native relation and independent authority

`native/` contains fresh full-digest static GNU exports, actual executable
mapping and selected FDE/CIE records, the real direct helper edge, exceptional
GOT/RELATIVE bindings and all three 24-byte source Locations. An independent
stdlib ELF reader reauthenticates their uniqueness and absence of body RELA.
The embedded enumerate.rs/rustc-hex-2.1.0 path labels are observations, not
permission to copy implementation. No inferred or upstream Rust source is read
or copied into this component.

`oracle/hex-iterator-proof.md` proves all normal paths and the complete
valid-UTF-8 scalar equations of the 140-byte no-call helper. The constructor
invariant proves all three exceptional native branches unreachable; their
behavior is not replaced with stubs. The proof covers exact result write masks,
raw result identity and cursor/count/halt effects. In particular an invalid
Unicode scalar is decoded in full while the outer cursor/count advance only
one byte; the halt guard then prevents later use of that interior cursor.
Natural end does not set halt, while odd/invalid input does. Prefix handling
belongs to the outer caller and is absent from this leaf.

An independent author froze 39,850 unique high-level Unicode cases and 185,490
full observations before new Rust existed. Expected observations use explicit
ASCII sets and Python Unicode scalars; a separate serializer produces raw
UTF-8. The actual client receives only raw text bytes, arbitrary initial 16
output bytes and call counts. All 16 result bytes and every state observation
are compared, including output staleness and repeated halted calls. The corpus
supports the structural full-domain proof; it is not an exhaustive string
population or a claim of executed target calls.

Source commit `01723660c6b76e5e3cb69a2d49ff89454b40a080` was preserved on
the fork before this task's first compiler experiment. `build-c1/` retains the
new actual measurements at that clean commit:

- O0 and O3 each match all 185,490 full observations across 39,850 cases,
  including every result byte, cursor/count/halt and output identity.
- Three independent external Rust test methods pass in each profile.
  Complete own rlibs rebuilt with identical source/provider/flags and the same
  output basename are raw-equal within each profile. No target byte comparison
  is inferred from those own-library rebuilds.
- Five actual compiled mutants change Unicode cursor width, whitespace,
  prefix removal, result clearing and odd-input halt. They cause respectively
  57,060 / 1,341 / 76 / 152,657 / 6,690 mismatched observations over the same
  185,490-observation denominator. Raw streams and full mismatch-ID digests are
  retained; they are not target execution counts.
- Three Python methods pass: exact independent Unicode-oracle regeneration,
  complete comparator content/count controls, and actual compressed-input
  corruption rejection.

The raw command ledger binds the actual compiler, cc/ld, source/corpus, full
target/two spans and all 103 provider payloads before and after, with unchanged
HEAD/tree/status and seven pins. No prior formatter/address results are reused
as current passes.

`native/HEX-ACTUAL-ARTIFACT-REVIEW.json` independently verifies all 32 command
records and 64 raw streams, both actual libraries/clients, every source/provider
identity, raw rebuild equality and all mutant counts/full mismatch-ID digests.
The mutants affect 9,729 / 256 / 12 / 39,329 / 1,359 unique cases over 39,850;
these case counts are distinct from the observation counts above. The peer
then reruns both actual clients with raw frozen inputs only: each exits zero
with all 185,490 observations byte-equal to the frozen expectations. The four
cleared repository static checks and current-base replay are recorded in the
resume addendum, with their exact source identities and scopes.

```sh
python3 -B tools/hex_pair_iterator_rust.py \
  --rustc /tmp/hl-resume-20261101/toolchain/prefix/bin/rustc \
  --output /tmp/fresh-hex-pair-build --controls
python3 -B -m unittest tests.test_hex_pair_iterator_rust -v
```

`provider/PROVIDER-AUDIT.json` records the official compiler/std archives,
installed manifests and 103 payloads. All payloads and manifest bytes are checked
before and after the runner, along with full target/body, frozen data, all own
executed source files, actual cc/ld, HEAD/tree/status and seven pinned imports.
The manifests contain the original prefix
`/tmp/hl-resume-20261101/toolchain/prefix`; recreating this recorded provider
requires that same owned prefix and hash-pinned archive recipes. Installing
identical payloads elsewhere needs its own build record. Rust 1.94.1 is a
research provider, not a unique original compiler identification.

Full current `make test` and CI remain NOT_RUN: newly merged captured
instruction-evaluator families have not been authorized. The draft and every
publication commit use `[skip ci]`. No captured node/visor/object or CPU,
register or PC instruction evaluator is executed. There is no new Rust/target
machine-code match, original nominal ABI, invalid UTF-8/forged-state behavior,
panic/unwind/physical-fault guarantee or whole-node equivalence. No component
gate or byte-window registry changes. New independently authored code/docs are
MIT; original captured evidence retains its separate ownership. Next bind an
actual higher-level consumer to this now specified stateful operation.
