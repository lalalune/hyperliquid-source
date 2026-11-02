# Offline evidence storage

The repository-wide `*.gz` rule originally stored these small evidence files
as Git LFS pointers. A checkout or Git archive without LFS hydration therefore
contained text beginning `version`, causing manifest failures and
`gzip.BadGzipFile`, even though the uploaded LFS payloads were valid.

This packet overrides that rule locally and stores its gzip evidence as
ordinary Git blobs. The compressed bytes, decompressed bytes, target bindings,
frozen expectations and checker logic are unchanged. Large captured binaries
retain the repository's original LFS policy and still need to be materialized
before native regeneration.

The coordinator verified every staged packet file against MANIFEST.sha256,
decompressed every retained gzip blob, exported the staged Git tree with
`git archive`, and repeated those checks using only archive bytes. No network,
LFS hydration, captured execution or instruction evaluator is needed for this
packet-storage check. Native regeneration remains subject to the tool versions
and target prerequisites documented in README.

From an exported packet directory:

```sh
shasum -a 256 -c MANIFEST.sha256
```

This is a delivery correction to the existing contribution, not a new native
finding or a claim that the entire repository can run offline.
