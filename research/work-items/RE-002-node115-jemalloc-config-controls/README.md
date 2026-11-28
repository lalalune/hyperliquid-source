# Node 115 jemalloc build configuration

The shipped allocator exposes 12 compiled configuration values via its named
control table. Five Boolean getters previously shared the same set of possible
source names in the [native library census](../RE-002-node115-native-libs-wave2-census/).
Resolving the table identifies each of the five handlers even though their
normalized machine code is identical.

| Control under config | Handler VA | Compiled value |
| --- | --- | --- |
| cache_oblivious | 0x63784f0 | true |
| debug | 0x6378570 | false |
| fill | 0x6378470 | true |
| lazy_lock | 0x63786f0 | false |
| malloc_conf | 0x636ea30 | empty string |
| opt_safety_checks | 0x63785f0 | false |
| prof | 0x63783f0 | true |
| prof_libgcc | 0x6378670 | true |
| prof_libunwind | 0x63780a0 | false |
| stats | 0x6377dc0 | true |
| utrace | 0x6378370 | false |
| xmalloc | 0x6378770 | false |

## Evidence

In the named dispatcher the RIP-relative load at 0x63a890c points to the
super-root at 0x64da4c0. The lookup call at 0x63a891c goes to 0x636e340.
The dispatcher loads the selected record's callback at offset 32 and calls
it indirectly. The 13 root names and all 12 ordered config leaf names agree
with the packaged jemalloc src/ctl.c. Each 40-byte named record carries its
name, child count, child pointer and handler at offsets 8, 16, 24 and 32.
ELF R_X86_64_RELATIVE addends resolve the pointers. The config parent at
0x64da5c8 identifies the leaf array at 0x64ded20. Each callback starts at a
target unwind frame boundary. The machine code sets the same immediate in the
temporary and successful one-byte output store of each Boolean getter. The
string getter writes a pointer to a NUL at 0x4376fd on its eight-byte output path.

For the five previously ambiguous getters, the verifier also rechecks the
census target and source body hashes and the original relocation-qualified
comparison. The other seven entries have a named dispatch binding and getter
value here. The evidence describes build capabilities. Determining whether
profiling was active in any particular process would also require runtime
state. The empty compiled string leaves environment and application overrides
open. These observations constrain build settings without recovering their
original configure command or uniquely identifying a source revision.

## Replay

From the repository root with the LFS inputs materialized, download the
published crate pinned in the wave-2 Cargo.lock. The verifier checks both
the archive and captured executable digests and only reads their contents.

```sh
packet=research/work-items/RE-002-node115-jemalloc-config-controls
cache=$(mktemp -d)
version=0.6.1+5.3.0-1-ge13ca993e8ccb9ba9847cc330696e02839f328f7
curl -fLsS "https://static.crates.io/crates/tikv-jemalloc-sys/tikv-jemalloc-sys-${version}.crate" -o "$cache/source.crate"
python3 -B "$packet/verify.py" "$cache/source.crate" > "$cache/results.json"
diff -u "$packet/results.json" "$cache/results.json"
python3 -B "$packet/check_controls.py" "$cache/source.crate"
```

The first mutation swaps the fill and stats callback relocations in memory.
Their values and the old five-way code comparison still pass, while exactly
those two name-to-handler bindings change. A second mutation makes the two
Boolean stores disagree, which the verifier rejects. Neither control writes
to the captured ELF.
