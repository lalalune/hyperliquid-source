# Frozen value-corpus protocol, version 1

Files are UTF-8 ASCII TSV with LF endings and no header. `cases.tsv.gz` contains
inputs; `expected.tsv.gz` contains outputs. Gzip uses mtime=0. Both raw and gzip
SHA-256 are recorded. No case contains private/user runtime data.

Every input line has five tab-separated fields:

`case_id<TAB>dex_byte<TAB>samples<TAB>fallbacks<TAB>records<LF>`

Every expected/driver-output line has three fields:

`case_id<TAB>samples<TAB>fallbacks<LF>`

Case IDs are `C` followed by six decimal digits in corpus order. The dex byte is
exactly two lowercase hexadecimal digits. Every key, tag and payload is exactly
16 lowercase hexadecimal digits representing a u64. No floats or signed parse
is used.

* Empty maps and an empty record slice use `-`.
* Samples use `key:value,value;key:value,...` with keys in strictly increasing
  unsigned order. An existing empty vector is encoded `key:` and must remain
  distinguishable from an absent key.
* Fallbacks use `key:value;key:value` in strictly increasing unsigned key order.
* Records use `key,tag,payload;key,tag,payload` in supplied order. Repeated keys
  and tags are permitted. The record slice is not sorted or deduplicated.

The canonical encoder never emits a trailing separator or whitespace. Expected
and observed output line counts, IDs, entry presence, vector element order and
every bit of every word must match. The fixture driver will parse only input
frames; expected output is read solely by the external comparator.

The protocol belongs to the evidence harness, not the native program or public
library. A malformed fixture is a harness error, not a reconstructed target
refusal. Allocation/resource limits remain those in `CONTRACT.md`.
