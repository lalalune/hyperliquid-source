# node115-listener-prefix

Composes the existing frame/LZ4/u32 readers with the limits selected by native consensus listener0x2af8be0: outer payload and declared decoded size each<=11,000,000, then a fresh typed budget11,000,000 with initial charge0. The recovered20-byte identity and u32 prefix costs24 typed units; its body is retained for a future independently reconstructed handler.

See [evidence and caller bindings](../../research/work-items/RE-012-node115-listener-limit-binding/README.md). `ListenerPrefixReader` is an offline one-frame API; inherited terminal/EOF behavior does not claim target connection lifecycle. A returned `Prefix` is neither a fully decoded message nor authentication. `decode_prefix` alone consumes already decoded bytes and does not enforce framing limits. Other callers and all body-specific charges remain outside scope.
