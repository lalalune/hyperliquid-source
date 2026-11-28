# RE-002 · Linux time zone discovery in node #115

The registered iana-time-zone lookup checks the text of the /etc/localtime symlink, falls back to /etc/timezone, and reaches the OpenWrt /etc/config/system reader on failure. The link comparison accepts four prefixes, including two NixOS layouts. Among four public source releases examined, 0.1.51 lacks the two NixOS prefixes and OpenWrt fallback. Releases 0.1.60, 0.1.63 and 0.1.65 all produce the later behavior.

## Target evidence

Component foundation; Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Baseline `2da45cb0a761cff6b478e40421699857d87a94df`. The earlier ThinLTO census identifies both complete functions. The existing Chrono zone linkage packet concerns different function bodies. The verifier authenticates the census and rechecks every byte of these two functions against its source-body hashes and relocation records.

| Observed target operand | Derivation |
| --- | --- |
| /etc/localtime | At 0x2e9ba1e and 0x2e9ba2d, two overlapping immediate values construct a 14-byte pathname on the stack. |
| /usr/share/zoneinfo/ | SIMD compares 16 bytes and a four-byte tail, then selects 20 as the removal length. |
| ../usr/share/zoneinfo/ | Two 16-byte comparisons overlap at input offset 6. The success path selects 22 bytes. |
| /etc/zoneinfo/ | Two eight-byte immediates overlap at offset 6. The success path selects 14 bytes. |
| ../etc/zoneinfo/ | One 16-byte SIMD comparison selects 16 bytes on success. |
| /etc/timezone | The failure path at 0x2e9bbef resolves a RIP-relative pointer and a 13-byte length. |
| /etc/config/system | The direct call at 0x2e9bc33 resolves to the registered 0x2e9af00 OpenWrt function. Its opening path assembles a 16-byte load and two immediate trailing bytes. |

The target confirms the paths, tested prefix bytes, success lengths and fallback call edge. These are static observations. No captured functions were executed.

## Public-source comparison

The host fixture compiles the published Linux source module for each release with rustc 1.95.0. It redirects only the source's filesystem calls to three files under a temporary root (two calls in the 0.1.51 control). It supplies the enclosing crate's error variants and invokes the original lookup function. Each case has an independent directory. Symlinks point to names with no corresponding file, allowing the tests to distinguish textual prefix removal from resolving the link target. No system timezone setting is modified.

[results.json](results.json) records 48 outcomes across four releases and 12 fixtures. The three later sources agree in all cases. They accept all four links ahead of a conflicting /etc/timezone. When a link is unrecognized, a file with leading spaces and trailing whitespace retains its leading spaces. An empty timezone file succeeds before OpenWrt. When the file is absent or invalid UTF-8, an OpenWrt system section can supply a zonename in preference to its POSIX timezone, or the POSIX value alone. An unrelated section supplies neither.

The 0.1.51 control differs on six cases, including each NixOS link and OpenWrt-only input. The Linux module is byte-identical between 0.1.63 and 0.1.65; 0.1.60 differs only in constructing the final missing-value error. The lookup behavior therefore leaves the precise crate version unresolved. A host outcome applies to the public source used by the fixture, and does not establish which files existed on a historical production system.

## Replay

From the repository root with the pinned target and rustup toolchain 1.95.0 available, fetch the published crates once. The script checks their compressed SHA-256 identities before reading the module. The host compiler builds temporary fixture executables from public Rust source under the upstream MIT OR Apache-2.0 licensing. The captured ELF is only read.

```sh
cache=$(mktemp -d)
for v in 0.1.51 0.1.60 0.1.63 0.1.65; do
  curl -fsSL "https://static.crates.io/crates/iana-time-zone/iana-time-zone-$v.crate" -o "$cache/$v.crate" || exit 1
done
packet=research/work-items/RE-002-node115-linux-timezone-discovery
python3 -B "$packet/verify.py" "$cache" > "$cache/replay.json"
diff -u "$packet/results.json" "$cache/replay.json"
```
