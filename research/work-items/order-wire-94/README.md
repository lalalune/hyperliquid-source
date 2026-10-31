# RE/OrderWire: Order Wire Serialization & Field Parsing (node #94)

- Component ID: `RE/OrderWire` (`l1/src/order_wire.rs`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91774280 bytes)
- Source commit / reference commit: repository baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference lead `references/can1357-hl/l1/order_wire.rs`
- Claim status: verified observation (static disassembly, panic records, struct stride, and instruction opcodes)
- Scope included: 2 FDEs (batch compact order decode, wire field parsing), struct stride 56 bytes (0x38), reciprocal base-10 division, 3 panic records in `order_wire.rs`
- Scope excluded: binary execution (static disassembly only), live order submission

## Problem and Result

Hyperliquid node #94 deserializes compact wire orders and parses textual decimal fields into typed representations:
1. **FDE 1 (`0x3330570..0x3330900`, 912 B)**: `decode_compact_orders`
   - Batch compact decoding loop for orders.
   - Decodes wire integers via reciprocal division by 10 (`0xcccccccd` and `0x199999999999999a`) to extract mantissa and power-of-10 scale exponents (`0x80000`, `0x70000`).
   - Guard at `0x333057e` (`js 33308b9`) branches to error handling / panic at `0x33308c7` referencing `0x56e9a80` (`/home/ubuntu/hl/code_Mainnet/l1/src/order_wire.rs:326:35`).
2. **FDE 2 (`0x3340e90..0x3341af0`, 3,168 B)**: `OrderWire::to_internal`
   - Parses `WireDecimal::parse(&self.p)` and `WireDecimal::parse(&self.s)`.
   - Iterates across order wire elements using an exact stride of **56 bytes (0x38)** (`3341602: imul rcx, r13, 0x38`).
   - Assigns decoded fields into the internal structure:
     - `+0x00`: 16-byte packed flags / asset / header (`movdqu`)
     - `+0x10`: `limit_px` (8 bytes)
     - `+0x18`: `sz` (8 bytes)
     - `+0x20`: 4-byte auxiliary field
     - `+0x24`: 1-byte flag (`reduce_only`)
     - `+0x25`: 16-byte order type / payload (`movdqu`)
     - `+0x35`: 1-byte cloid tag
     - `+0x36`: 1-byte secondary tag
   - Mapped panic records:
     - `0x56e9a98`: `order_wire.rs:123:86` (referenced at `0x3341a98`)
     - `0x56e9ab0`: `order_wire.rs:133:53` (referenced at `0x3341a6e`)

Total size across the 2 FDEs is 4,080 bytes.

## Reproduce

Working directory: repository root. Pure static disassembly; zero binary execution.

```sh
# Generate evidence packet and run test suite
python tools/order_wire_static.py
pytest tests/test_order_wire_static.py

# Verify SHA-256 manifest integrity
(cd research/work-items/order-wire-94 && sha256sum -c MANIFEST.sha256)
```

## Evidence

### 1. FDE Extents and Ground Truth

| Routine | ELF VA Range | File Offset | Size | SHA-256 |
| :--- | :--- | :--- | ---: | :--- |
| `decode_compact_orders` | `0x3330570..0x3330900` | `0x332f570..0x332f900` | 912 B | `f6b4a1c10d7c42c1a8fefc076610f510d1d26cc13eadb8d85f4a4e3ae2919ad8` |
| `OrderWire::to_internal` | `0x3340e90..0x3341af0` | `0x333fe90..0x3340af0` | 3,168 B | `98b28dcb3dc33a259df31a804abcb2b1374598f219ad7b57094f9dbcc9efbec4` |

### 2. Struct Stride Verification (56 Bytes)

In FDE 2 (`0x3340e90`):
```asm
3341602: imul   rcx, r13, 0x38             # index * 56 bytes stride
334160f: movdqu XMMWORD PTR [rax+rcx*1], xmm2
3341614: mov    QWORD PTR [rax+rcx*1+0x10], rsi  # limit_px
3341619: mov    QWORD PTR [rax+rcx*1+0x18], r8   # sz
334161e: mov    DWORD PTR [rax+rcx*1+0x20], r9d
334162a: mov    BYTE PTR [rax+rcx*1+0x24], dl    # reduce_only
3341637: movdqu XMMWORD PTR [rax+rcx*1+0x25], xmm0
334163d: mov    BYTE PTR [rax+rcx*1+0x35], r10b
3341642: mov    BYTE PTR [rax+rcx*1+0x36], r12b
3341647: inc    r13                              # next element
```

### 3. Mapped Panic Records

| Panic Record VA | File | Line:Column | Referenced By |
| :--- | :--- | :--- | :--- |
| `0x56e9a80` | `l1/src/order_wire.rs` | 326:35 | FDE 1 (`0x33308c7`) |
| `0x56e9a98` | `l1/src/order_wire.rs` | 123:86 | FDE 2 (`0x3341a98`) |
| `0x56e9ab0` | `l1/src/order_wire.rs` | 133:53 | FDE 2 (`0x3341a6e`) |

## Results and Limitations

- All 2 FDE extents (4,080 B total), 56-byte struct stride, 11 control instruction opcodes, and 3 panic records verified with 100% agreement against node #94.
- No captured binary execution performed.
