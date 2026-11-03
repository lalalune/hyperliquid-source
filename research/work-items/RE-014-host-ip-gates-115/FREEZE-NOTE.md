# Chronology and limits

Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
The first freeze commit `ba1d5653` records 5,397 raw boundary-word rows
before any `src/node115-host-ip-gates` source existed. Historical project-MIT
host-IP gate policy already existed in Git history (`5491d673`); this is
fresh target-115 validation of that policy, not a blind recovery of it.

The second freeze adds the complete 978-byte IPv4 leaf at 0x167ccb0 and
actual CALL/RET composition from the 0x1562bf5 caller length check. No Rust
component exists at this freeze. Expected rows come only from interpreting
pinned original instruction bytes with synthetic memory and known-bit GPRs.
No instruction bytes are transplanted into a candidate executable.

The initial second-freeze attempt completed native comparisons and six
corruptions but failed selecting a smoke fixture absent from its corpus
(KeyError); its lossless external log and output streams remain in ignored
work. The corrected producer explicitly includes that fixture and writes a
separate v2 output directory. Neither failure nor partial output is a PASS.
The initial first-freeze streams remain separately preserved.

The pure parser has no calls. The composed interpreter permits only the
actual call at 0x1562c17 to 0x167ccb0. All command/process/service, override
reader, diagnostic, allocation, collection, and whole-caller return behavior
remain outside the interpreted scope. Command strings are data, never run.
