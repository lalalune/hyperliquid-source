# RE-013: initialized prefix consumed by the Visor prepared-path builder

Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; component `visor`.
Target: captured Visor, 8,305,392 bytes, SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.

Prior [draft #1375](https://github.com/lalalune/hyperliquid-source/pull/1375)
leaves G in `P = G || /tmp/ || X` unqualified. This packet traces the selected
initialization descriptor and factory, the source of H, both H/suffix requests,
the ordinary-return selector and its publication to the exact G field. See
[PROOF.md](PROOF.md) for addressed observations, premises and unknowns.

Under those premises the selector returns H/cham when its first metadata
predicate accepts; otherwise H/hl when its second predicate accepts or its
preparation result is zero. The factory independently rechecks the selected
tuple before publishing its fields. H is derived by an adapter around HOME
lookup and an account lookup fallback, with conversion/error branches; H is
not universally identical to raw HOME. Actual H/G values, filesystem effects,
concurrency, error/unwind paths and source equivalence remain unproved.

The question is distinct from #1375's preferred/fallback temporary payload
selection, #1361's calendar rollover and the node94 constants inventory. Indexed
address searches found no prefix-function packet; two 4ac6a0 search hits were
only hexadecimal substrings in log SHA-256 values, not address claims. This
search is not exhaustive proof of historical uniqueness; live ownership was
also checked before selection and must be rechecked before publication.

## Reproduce, without captured execution

Author's platform: Linux x86-64, GNU objdump/readelf 2.42, LLVM objdump 18.1.3.
These scripts are static parsers and native disassembly collectors. They do
not interpret/evaluate captured instructions, query the host environment on
behalf of the target, run the target, access keys, network or chain services.

From repository root, set P to this packet's directory, then:

```sh
B=artifacts/visor/captured/hl-visor
python3 -B "$P/survey.py" --binary "$B" --output work/visor-prefix-new
diff -r "$P/observed" work/visor-prefix-new
python3 -B "$P/verify.py" --binary "$B" --receipt work/visor-prefix-integrity.json
python3 -B -O "$P/verify.py" --binary "$B" --receipt work/visor-prefix-integrity-opt.json
python3 -B "$P/check_argument.py" --binary "$B" --receipt work/visor-prefix-argument.json
python3 -B -O "$P/check_argument.py" --binary "$B" --receipt work/visor-prefix-argument-opt.json
python3 -B "$P/crosscheck_llvm.py" --binary "$B" --output work/visor-prefix-llvm-new
diff -r "$P/independent" work/visor-prefix-llvm-new
make doctor
make verify
make catalogue-check
make reproduce
```

Output/receipt locations must not already exist. Exact results and limitations
are in VALIDATION.json. Integrity checks regenerate all native records twice,
compare the entire inventory and reject corrupt identities/records and existing
output overwrites. Manual proof controls run normally and under `python -O`.
Full root `make test` is NOT RUN: unrestricted discovery includes captured
instruction evaluators outside this session's static-only authorization.
Hosted CI, a container/full build, Rust reconstruction and target equivalence
are NOT CLAIMED. Draft/commit/title use `[skip ci]` for this boundary.

Twenty retained FDEs total 7,011 bytes. GNU/LLVM raw partitions agree on 18;
two differ only by seven explicitly addressed standalone LOCK display rows.
Both raw outputs and the exact display joining rule are retained. No byte or
operand mask. Reused formatter/path context is not new recovery credit.

## Authorship and rights

New packet code and prose are independently authored under this repository's
MIT terms. survey.py, verify.py and crosscheck_llvm.py adapt this same author's
MIT draft1375 packet at frozen head
`0e740791da481f38d368525e75e92886842024f3`, with prefix-specific ranges,
bindings, data and a disclosed LOCK display qualification. No unlicensed
can1357 source was copied or used as semantic authority. Original capture
rights remain with its upstream provenance; native snippets are evidence and
do not become a new implementation license. Imports, pins, source manifests,
generated progress/catalogues and all component gates remain unchanged.
