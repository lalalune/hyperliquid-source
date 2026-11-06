# RE-001: the global default name `"nullptr"` (node #115)

Task ID: RE-001. Bounded question: what is node #115's global
default name, how is it constructed at startup, and what does every
consumer site do with it?

## Answer in one paragraph

The global is the `std::string` at `0x6508980` in `.bss`, and its
value is the literal `"nullptr"` (7 bytes, SSO). It is constructed
by the static initializer `0x61d2970` — `.init_array` entry #142
(0-based slot 141 of 168, slot address `0x63f3b30`) — which writes
`"null"` at `+0x10`, points `_M_p` at its own local buffer
(`0x6508990`), writes `"lptr"` at `+0x13` (overlapping the last
`'l'`, so the buffer reads `"nullptr"`), sets length 7 at `+0x08`,
writes the NUL at `+0x17`, and registers `~basic_string` with
`__cxa_atexit` (func from GOT `0x64ed5d8`,
`_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev@GLIBCXX_3.4.21`,
arg `0x6508980`, dso `__dso_handle` at `0x64efa20`). All eleven
consumer sites apply the same length-then-memcmp test — length must
be 7 before any byte is compared — and treat a match as "no name
was given": the create host releases the holder, the release host
clears the holder, find_entry clears the name string and the map,
find_norm assigns the fallback name, the matcher assigns the global
itself, the resolver host assigns it when the delegate is null, the
matcher wrapper returns true on a kind-2/kind-3 match, and the twin
consumers refuse to assign a record whose name is the default.

## Artifact binding

- Binary: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (verified against `provenance/artifacts.json` and the local file
  by `verify.py`).
- Base: upstream `main` at `05bc2de30`.

## Evidence format

- `records.json` holds semantic records only: the global object,
  the initializer (stores, `.init_array` slot, `__cxa_atexit`
  record), the ten consumer-site records (the matcher wrapper
  contributes two sites), the helpers, the literals, the
  relocations, and the census counts. There is no per-instruction
  mnemonic list anywhere in this packet.
- `excerpts/` holds one whole-function verbatim objdump excerpt per
  routine (17 windows). Instruction-level detail lives only there.
  Regenerate with `export_excerpts.py`; the objdump command is
  recorded in that script. The mnemonics in the excerpts (`endbr64`
  included) are genuine instructions present in the target binary,
  not placeholders.
- `verify.py` (plus `census.py`, `export_excerpts.py`,
  `gen_records.py`) is committed in the packet, so the checker
  behind "ALL CHECKS PASSED" is visible in the diff.
- `frames.txt` lists the 17 FDE ranges; `callers.tsv` is the
  reproducible caller census (939 rows) over the whole binary;
  `relocations.txt` lists the 11 relocations this packet relies on.

## Routines

| routine | address | role |
|---|---|---|
| initializer | `0x61d2970` | constructs `"nullptr"`, registers the dtor |
| create_host | `0x6077820` | create-by-name host; name gate at `0x6077907` |
| resolver_host | `0x607e710` | resolver host; null delegate assigns the default |
| twin_a | `0x6086b70` | twin consumer A (kind-0x15/0x16 tail) |
| twin_b | `0x60a7420` | twin consumer B (holder offset `0x90`, not `0x630`) |
| matcher_wrapper | `0x60bf5f0` | matcher wrapper; kind-2/3 default checks |
| release_host | `0x6137290` | release-by-name host; name gate at `0x61372c8` |
| string_equal | `0x5e4bcf0` | string equality (length, then memcmp) |
| map_find_name | `0x5d66e30` | unordered_map find (linear ≤ 20, hash above) |
| kind_validator | `0x60bf980` | kind dispatch; jump table `0x978718`, 25 entries |
| once_init_create | `0x6075bc0` | pthread_once init for the create host |
| once_init_release | `0x6138a10` | pthread_once init for the release host |
| canonical_name | `0x6130140` | returns `"rocksdb.BuiltinBloomFilter"` (`0x44481b`) |
| find_entry | `0x609e510` | registry Find entry (re-shipped from #3485) |
| find_norm | `0x609a410` | normalized Find (re-shipped from #3485) |
| matcher | `0x60bb9a0` | kind matcher (re-shipped from #3485) |
| status_builder | `0x61cf670` | Status builder (re-shipped from #3440) |

The find_entry, find_norm and matcher excerpts were already
exported byte-identical by #3485 and the status_builder excerpt by
#3440; they are regenerated here from the same binary so this
packet is self-contained. They are consumers in their own right
(each contains one of the eleven sites), not just helpers.

## Consumer sites (all eleven)

| site | routine | test | match outcome |
|---|---|---|---|
| `0x6077907` | create_host | len 7, then memcmp | release holder, Status 0 |
| `0x607e8e0` | resolver_host | delegate null | assign default, Status 0 |
| `0x6086c84` | twin_a | record len, then memcmp | return 1, nothing assigned |
| `0x60a7534` | twin_b | record len, then memcmp | return 1, nothing assigned |
| `0x60bf710` | matcher_wrapper | `string_equal(candidate, default)` | return True (kind 2) |
| `0x60bf730` | matcher_wrapper | len, then memcmp | return True (kind 3) |
| `0x61372c8` | release_host | len 7, then memcmp | clear holder, Status 0 |
| `0x609e567` | find_entry | len 7, then memcmp | clear name + map, Status 0 |
| `0x609a45e` | find_norm | len 7, then memcmp | assign fallback name |
| `0x60bbc99` | matcher | flag-gated | assign default |
| `0x61d2974` | initializer | — (construction) | — |

Related gates the packet also pins: the create host builds a fresh
`StatisticsImpl` for an empty name and for the 15-byte name
`"BasicStatistics"`; the release host installs a fresh control
block for the 26-byte canonical name `"rocksdb.BuiltinBloomFilter"`;
the resolver host clears the output name when the descriptor's
`+0x04` byte is set.

## The twins

`0x6086b70` and `0x60a7420` are two instantiations of one function
template: their instruction streams are identical except the
holder-map field offset in their respective owners (`0x630` in A,
`0x90` in B) — `verify.py` checks the normalized streams differ
only in those two loads. Both sit at vtable slot index 12 (offset
`0x60`) —
twin A at slot `0x64d3210` (vtable `0x64d31b0`), twin B at slots
`0x64d3690` (vtable `0x64d3630`) and `0x64d3710` (vtable
`0x64d36b0`) — which is the virtual call the kind validator makes
at `0x60bfa2a` (`call *0x60(%r14)`). Neither has a direct call site
in the census; both are reached by indirect dispatch.

## Model

`tools/default_name_115.py` models the initializer (stores +
`__cxa_atexit` record), the length-then-memcmp test, `string_equal`
(`0x5e4bcf0`), `map_find_name` (`0x5d66e30`, linear and hash paths
with seed `0xc70f6907`), and every consumer's default-name
decision. `tests/test_default_name_115.py` runs 92 checks,
including boundary and corruption controls (wrong length, wrong
bytes, empty names, missing records, live vs null flag-gated base
entries).

## Boundaries (explicitly not claimed)

- The Find pipeline the consumers call into — `find_entry`'s
  normal path, `find_norm`'s `'='` search, the matcher beyond its
  default-name site, the resolver `0x60971c0`, the fallback
  `0x609e2d0`, the translator `0x6076b20` — is mapped in #3485,
  #3488 and #3440; here those callees' outcomes are harness
  inputs, and only the default-name decision at each site is
  modeled.
- The kind validator `0x60bf980` is fully excerpted, but its
  internal 25-way dispatch is a boundary: the twins consume only
  its boolean, and the model takes that boolean as a harness input.
  Its jump table at `0x978718` is verified to re-decode to 25
  in-range targets.
- The pthread_once init routines `0x6075bc0` / `0x6138a10` are
  excerpted; their registry/singleton internals are a boundary.
- The `StatisticsImpl` constructor `0x6071a00` and the control
  blocks the create/release hosts install are not reconstructed
  here; the packet pins only which name triggers their
  construction and which name clears the holder instead.

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so `make
verify` / `make test` / `make catalogue-check` cannot run here;
the packet's own `verify.py` (digest, manifest, excerpt
regeneration, byte-for-byte raw checks, seeded random gate spots,
FDEs, relocations, literals, census reproduction, model constants,
model tests) is the verification that was run, and it prints ALL
CHECKS PASSED.
