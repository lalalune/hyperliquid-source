# RE-008 · EMA result helper tree-slot and output layout

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. PR #6785 records that the preceding helper calls `0x4d30990`; this packet follows the called function itself and answers which selected state slot and result fields it writes.

The actual FDE at `0xf1646c` covers `[0x4d30990,0x4d30c7a)` (746 bytes). The function preserves the output pointer, walks a descriptor-selected tree through the `+0x278` child links, and calls `0x4d2ec40` with a stack descriptor. On the selected nonempty path it replaces the chosen node's slot at `base + index*8 + 0x218` with the returned pointer, saves and restores the node's 48-byte entry, and then follows the parent path to its end.

At the return path, the function writes the returned tuple into output offsets `+0x00..+0x37`, clears output `+0x40`, and writes another qword at `+0x48`. The empty path calls the same `0x4d2ec40` helper with a shorter stack descriptor and returns through the same output-copy path. These are static field and control-flow observations; the tuple's semantic types, ownership, and the called helper's full behavior remain unresolved.

Run `python3 research/work-items/RE-008-node115-ema-result-helper/verify.py`. It checks the target digest, full FDE body digest, 13 instruction witnesses, three edges and 13 byte-mutation controls. The captured binary is never executed.
