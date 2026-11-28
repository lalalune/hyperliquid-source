# RE-010 — Node #115 ENV79 occupied map entries

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This connects the ENV79 container wrapper from #7433 to an ordered map consumer.

At `0x14b0614` the consumer calls the ENV79 wrapper, saves result byte +1, and requires result byte +0 to be 9 before decoding the corresponding value at `0x14b0639`. The latter also has a success check for tag 9. The selected ordinary occupied-entry path uses three result words at offsets +8, +0x10 and +0x18 as the replacement value.

Beginning with the root pointer at stack +0x78 and depth at +0x80, each node uses a 16-bit count at +0x112, one-byte ordered keys starting at +0x114 and child pointers at +0x120. The caller compares the zero-extended ENV79 identifier with the zero-extended node key and advances while it is greater. Matching key index `i` selects the 24-byte value at node +8 + 24*i. The occupied path at `0x14b0700` replaces all three words there, leaving the matched key unchanged. This proves how the ENV79 byte becomes a container key and how the accompanying result is stored.

The enclosing configuration field name, full value-decoder behavior, vacant inserts and ownership cleanup beyond this selected path remain outside scope. Run `PYTHONPATH=tools python3 research/work-items/RE-010-node115-env79-map-occupied/verify.py` from the repository root for the static byte and edge checks.
