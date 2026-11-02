# Visor move-request argument encoding

This packet closes the operand-producing relation between the updater's opaque downstream request and the already studied shell helper. For the captured Visor and the explicit storage, allocator, valid-UTF-8 and normal-return premises in [PROOF.md](PROOF.md), the non-tag-2 preflight path builds `mv` followed by the encoded **original** nonblank source/destination slices, separated by one ASCII space. Empty/all-whitespace slices are omitted; surrounding whitespace on a nonblank slice is preserved. An embedded NUL propagates a tagged construction error before any call to the shell helper. Successful construction passes option byte **1**.

This is one conditional six-body semantic closure, with **no new recovered-byte credit**. It does not establish successful movement, pathname/option interpretation, escaping safety, arbitrary malformed-UTF-8 behavior, filesystem durability, allocator correctness or a complete error-result discriminant. The preflight result is opaque. Option 1 is not an unconditional quiet-wrapper guarantee: a quoted operand can itself contain the helper's earlier raw `2>&1` substring. The existing formatter owns the selected quiet-stream result.

| Evidence or result | Scope |
| --- | --- |
| Target | `artifacts/visor/captured/hl-visor`, SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31` |
| Complete native bodies | `3a15d0`, `323b60`, `3e1920`, `3a98d0`, `6516e0`, `371b60`: **4,067 bytes / 1,007 rows**, six actual FDE extents with raw referenced CIEs |
| Additional context | Two publication call sites and one existing quiet-option selection: **137 bytes**, selected windows only |
| Semantic result | Exact 25-scalar blank predicate; complete byte-mask/chunk grammar and NUL/tag path; fixed three-record producer; bounded join and cleanup relation |
| Sufficient size domain | Combined source lengths `<=2^61-2`; constructed length `<=2^63-4`, valid nonwrapping object addresses separately required |
| Static checks | **169 negative controls**, two identical GNU/LLVM regenerations, separate optimized-Python run; controls do not execute target behavior |
| Mathematical checks | 1,792 byte/mask cases, 1,112,064 canonical scalar equations/classifications, 18 handwritten encoding examples, 11,110 bounded grammar words |

Read [PROOF.md](PROOF.md) for the address-bound argument and all opaque dependencies; [VALIDATION.md](VALIDATION.md) explains what the checks can and cannot establish. Complete readable GNU bodies, compressed LLVM bodies, the full transfer inventory and compact metadata are in [observed/](observed/). `pins.json` is an operand/data binding contract, not a semantic oracle.

The accepted [lifecycle unresolved edges](../RE-013-visor-lifecycle/unresolved-edges.md) and [shell-command packet](../RE-013-visor-shell-command/README.md) ([PR 1266](https://github.com/lalalune/hyperliquid-source/pull/1266)) supply the existing boundary. [PR 1345](https://github.com/lalalune/hyperliquid-source/pull/1345) owns the [formatter's quiet-stream proof](../RE-013-visor-format-requests/PROOF.md); [PR 1375](https://github.com/lalalune/hyperliquid-source/pull/1375) owns prepared-path production, and [PR 1402](https://github.com/lalalune/hyperliquid-source/pull/1402) owns initialized-prefix provenance. No files or conclusions from those unmerged path/prefix or metadata-publication contributions are required. The new result is the missing original-input → filter/encoder → collected-records → exact joined request relation, not another formatter/path claim.

From the repository root, with the authenticated artifact materialized and the two native tools available:

```sh
python3 -B research/work-items/RE-013-visor-move-argument-encoding/verify.py --out /tmp/visor-move-check.json
python3 -O -B research/work-items/RE-013-visor-move-argument-encoding/verify.py --regenerations 0 --out /tmp/visor-move-check-optimized.json
python3 -B research/work-items/RE-013-visor-move-argument-encoding/collect.py --out /tmp/visor-move-native
```

Outputs must not already exist. Default tool paths are GNU `/opt/homebrew/opt/binutils/bin/objdump` and Apple `/usr/bin/objdump`; the collector accepts explicit `--gnu`/`--llvm` paths and records versions. It reads/copies/disassembles bytes only. The repository's MIT ELF/FDE parsers are reused and hash-recorded; no unlicensed implementation source is incorporated. Packet-local `.gitattributes` retains gzip exports as ordinary Git bytes rather than LFS pointers.
