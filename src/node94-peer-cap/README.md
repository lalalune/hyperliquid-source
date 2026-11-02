# node94-peer-cap

The baseline has static evidence for the flagged gossip peer-cap path, but no independent Rust implementation. This adds the option-to-limit rule, supplied-peer IPv4 projection, exempt-peer counting and intermediate result code. None defaults to 8; Some(v) clamps to [8,100] and requests a clipping diagnostic only if changed. Bit-0-tagged keys map to 127.0.0.1. Allowed IPv4 entries are excluded from the count; at exact capacity only an allowed incoming key gets code 3.

Build directly with rustc 1.94.1, edition 2021; safe `no_std`, no external
dependencies or invented Cargo workspace. Evidence, commands and exact build
flags: `research/work-items/RE-012-peer-cap-rust-94/`.

Code 3 is an intermediate cap result: the native owner has a further unresolved step and this API does not establish final peer admission. Original option/NodeIp layout, B-tree iteration/equality/helper bodies, tracker loading, locks, logs, mutation order, ownership/unwind and concurrent effects remain unclosed. The supplied vector/slice API is new; synthetic vectors are not a proof of original map reachability.
