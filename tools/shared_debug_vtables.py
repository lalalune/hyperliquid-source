#!/usr/bin/env python3
"""Pin the 31 sibling vtables that share the io-error Debug method stub.

Work item: RE-005, node #115.  The preceding packet (RE-005,
``tools/error_vtable.py``, PR packet for vtable 0x64005f0) pinned one
vtable: header at 0x64005f0 in .data.rel.ro, drop 0x15be1a0, size 8,
align 8, and a single method slot (+0x18) naming the PLT stub
0x5ca5610, whose GOT cell resolves to the Debug format function
0x5ca7ea0 of the 8-byte tagged std io error value.  That packet closed
with an explicit boundary: 32 vtables in .data.rel.ro name the same
stub at +0x18 (this one plus 31 siblings), and one .got cell
(0x64e0170) names it too.

This tool settles what those 31 siblings are vtables *of*.  The answer
it re-derives and pins:

* Every sibling is a vtable for the same value: the 8-byte tagged std
  io error.  All 32 headers read size 8 / align 8, and all 30 distinct
  drop bodies are the same tag-dispatch template (load the word,
  tag & 3; tags 0/2/3 do nothing; tag 1 drops the boxed inner error
  through the inner value's own vtable and frees the 24-byte box and
  the inner allocation through the shared dealloc slot 0x64df4a0).
* 18 siblings (counting 0x64005f0) are standalone Debug-only vtables
  (extent 0x20: header plus the one stub slot).
* 13 are extended vtables of extent 0x58 carrying eight method slots
  with one recurring shape: +0x18 the Debug stub, +0x20 the value's
  Display format function 0x5ca84b0 (pinned by its "(os error " and
  "strerror_r failure" string references), +0x28 a pointer to the
  one-method Display vtable at base-0x20 (same drop, size 8, align 8),
  +0x30 the forwarder 0x5ca8760 (tag 1 forwards to the boxed error's
  +0x30 slot, other tags return 0), +0x48 the forwarder 0x5ca8730
  (same shape, forwards to +0x48), and local bodies at +0x38, +0x40
  and +0x50.
* One sibling is an outlier: tokio's 0x64c6458 (extent 0x40), whose
  four extra slots are local bodies in the tokio address range; its
  Self is still the 8-byte io error by drop, size, align and the Debug
  slot, but the trait those slots serve is not identified here.
* The 32 vtables are referenced 94 times in .text, always by
  rip-relative lea, never by any other form: 57 panic-pair sites (the
  value is formatted into a panic payload, message and Location
  extracted and pinned per site), 6 field accessors (a 12-byte body
  returning the field at +0x38 of a parent trait object paired with
  one of these vtables), 10 enum accessors (a niche-discriminated
  body returning one arm's field paired with one of these vtables),
  14 pair-store sites and 3 clone sites (bodies writing or returning
  a fresh (value, vtable) pair), and 4 other sites (one passes the
  vtable in r8 to an indirect call; three hold it in r13 inside one
  body).

Boundaries kept explicit: the parent traits of the accessor, store
and clone bodies are recorded structurally (parent vtable base, entry
offset, Self size and drop) but never named; the extended vtables'
local slots (+0x38, +0x40, +0x50) are recorded as targets, not
identified; the two forwarders' trait-slot names are not asserted --
only their forwarding targets (+0x30 / +0x48 of the boxed error's
vtable) are pinned; tokio's sibling trait is not identified.

Run against the reconstructed #115 artifact only.  ``analyze`` works
on bytes; ``generate`` writes the packet under
research/work-items/RE-005-node115-shared-debug-vtables/.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import subprocess
import sys
from bisect import bisect_right
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105_896_032
TARGET = Path("artifacts/node/115/hl-node")
PACKET = Path("research/work-items/RE-005-node115-shared-debug-vtables")

METHOD_STUB = 0x5CA5610
METHOD_STUB_BYTES = bytes.fromhex("ff2562c28300")
METHOD_GOT_SLOT = 0x64E1878
METHOD_BODY = 0x5CA7EA0
METHOD_BODY_SHA256 = (
    "09eb233d4d2fc55ca993391546ad05afb0b80958ac342d16cb0ef4840a20fdf7")
STUB_GOT_CELL = 0x64E0170
DISPLAY_BODY = 0x5CA84B0
DISPLAY_OS_ERROR_STR = 0x43D45F
DISPLAY_STRERROR_STR = 0x949F1E
FWD_SOURCE = 0x5CA8760
FWD_SOURCE_CALL = (0x24, bytes.fromhex("ff5030"))
FWD_PROVIDE = 0x5CA8730
FWD_PROVIDE_CALL = (0x24, bytes.fromhex("ff5048"))
DEALLOC_SLOT = 0x64DF4A0
PANIC_SLOT = 0x64DF6A0
PANIC_THUNK = 0x1680C30
H13_VTABLE = 0x64005F0
H13_DROP_SHA256 = (
    "b885e0eb89f25e75b60b385a076b04e5e2469790d0fa6d97bf25c6c611b6b52a")
RELOC_TOTALS = {"relative": 59_534, "glob_dat": 263,
                "jump_slot": 278, "total": 61_001}
TOKIO_VTABLE = 0x64C6458
TAG_MASK = re.compile(rb"\x83[\xe0-\xe7]\x03")
MOV_18 = re.compile(rb"\xbe\x18\x00\x00\x00|\x41\xbe\x18\x00\x00\x00")

EXPECTED_VTABLES = {
    0x63f8f58: (0x14c4d00, 88),
    0x63fc2b8: (0x150c590, 32),
    0x63fd838: (0x1538380, 32),
    0x63fe880: (0x1569f30, 32),
    0x63ffe40: (0x15ab660, 32),
    0x64005f0: (0x15be1a0, 32),
    0x64015d0: (0x15dd590, 32),
    0x64032c8: (0x1609960, 32),
    0x640d678: (0x17263b0, 88),
    0x640e4e0: (0x1740fe0, 88),
    0x6411298: (0x1774cf0, 32),
    0x642d688: (0x2308f50, 32),
    0x64445c0: (0x29eca70, 88),
    0x64474a8: (0x2ab0780, 32),
    0x644e600: (0x2c96c90, 88),
    0x6451a20: (0x2df7230, 32),
    0x6455a88: (0x2e69050, 88),
    0x6456c40: (0x2e6cc20, 32),
    0x645b248: (0x2e854e0, 32),
    0x645b320: (0x2e854e0, 88),
    0x64842f0: (0x4232440, 88),
    0x6494e90: (0x4746700, 88),
    0x6496828: (0x4775060, 88),
    0x649db98: (0x4e509c0, 32),
    0x649e030: (0x4e509c0, 88),
    0x64b8398: (0x5a4b8f0, 32),
    0x64c3270: (0x5c74b90, 32),
    0x64c5170: (0x5cd6a70, 32),
    0x64c5520: (0x5cdd280, 32),
    0x64c6458: (0x5cee460, 64),
    0x64c7348: (0x5d00d80, 88),
    0x64c74f0: (0x5d01190, 88),
}
EXPECTED_SITES = {
    0x63f8f58: [(0x14c57d3, 0x14c57a0, 'enum_accessor'), (0x14c5824, 0x14c5800, 'enum_accessor'), (0x14ca773, 0x14ca740, 'enum_accessor'), (0x14cb1e4, 0x14cb1c0, 'enum_accessor'), (0x14cb644, 0x14cb640, 'field_accessor'), (0x15aea60, 0x15aea00, 'clone'), (0x15e1315, 0x15e12a0, 'store'), (0x15e1354, 0x15e12a0, 'store')],
    0x63fc2b8: [(0x150ba55, 0x150b310, 'panic')],
    0x63fd838: [(0x1534f91, 0x1534ed0, 'panic')],
    0x63fe880: [(0x1565d72, 0x1565460, 'panic')],
    0x63ffe40: [(0x15a5a57, 0x15a3b90, 'panic')],
    0x64005f0: [(0x15d5c42, 0x15d5b00, 'panic')],
    0x64015d0: [(0x15d668d, 0x15d63c0, 'panic'), (0x15d7213, 0x15d6fd0, 'panic'), (0x15d7250, 0x15d6fd0, 'panic')],
    0x64032c8: [(0x1608a7f, 0x16087a0, 'other')],
    0x640d678: [(0x17271c3, 0x1727190, 'enum_accessor')],
    0x640e4e0: [(0x17417c3, 0x1741790, 'enum_accessor'), (0x1741da9, 0x1741d30, 'store'), (0x1741e07, 0x1741d30, 'store'), (0x1746442, 0x17457f0, 'other'), (0x1747299, 0x17457f0, 'other'), (0x174794f, 0x17457f0, 'other'), (0x1751024, 0x1750fb0, 'clone')],
    0x6411298: [(0x1774072, 0x1773fd0, 'panic')],
    0x642d688: [(0x2adc399, 0x2ad7140, 'panic'), (0x2aeeab1, 0x2aeaef0, 'panic'), (0x2caea98, 0x2cad9b0, 'panic'), (0x2cb9fed, 0x2cb6500, 'panic')],
    0x64445c0: [(0x2a01804, 0x2a01800, 'field_accessor')],
    0x64474a8: [(0x2ae17ea, 0x2ae1690, 'panic')],
    0x644e600: [(0x2b11be0, 0x2b11b80, 'clone'), (0x2cac633, 0x2cac600, 'enum_accessor'), (0x2cc9a53, 0x2cc9a20, 'enum_accessor'), (0x2cca949, 0x2cca8d0, 'store'), (0x2cca9a7, 0x2cca8d0, 'store'), (0x2ccab69, 0x2ccaaf0, 'store'), (0x2ccabc7, 0x2ccaaf0, 'store')],
    0x6451a20: [(0x2d27369, 0x2d25620, 'panic')],
    0x6455a88: [(0x2e73cf9, 0x2e73c80, 'store'), (0x2e73d57, 0x2e73c80, 'store')],
    0x6456c40: [(0x2e6dd87, 0x2e6dd10, 'panic')],
    0x645b248: [(0x2e86a87, 0x2e86a10, 'panic')],
    0x645b320: [(0x2e7dcf5, 0x2e7db50, 'store'), (0x2e7e063, 0x2e7db50, 'store'), (0x2e861c5, 0x2e86150, 'store'), (0x2e86223, 0x2e86150, 'store')],
    0x64842f0: [(0x4302f84, 0x4302f80, 'field_accessor')],
    0x6494e90: [(0x4747124, 0x4747120, 'field_accessor')],
    0x6496828: [(0x4775a14, 0x4775a10, 'field_accessor')],
    0x649db98: [(0x4e39216, 0x4e391b0, 'panic')],
    0x649e030: [(0x4ecdca4, 0x4ecdca0, 'field_accessor')],
    0x64b8398: [(0x5a08601, 0x5a07ec0, 'panic'), (0x5a08e61, 0x5a08720, 'panic'), (0x5a6e131, 0x5a6dd30, 'panic')],
    0x64c3270: [(0x156727f, 0x1565f40, 'panic'), (0x15672ff, 0x1565f40, 'panic'), (0x1567347, 0x1565f40, 'panic'), (0x156737d, 0x1565f40, 'panic'), (0x1567430, 0x1565f40, 'panic'), (0x1567499, 0x1565f40, 'panic'), (0x156756a, 0x1565f40, 'panic'), (0x15675c5, 0x1565f40, 'panic'), (0x22d93d8, 0x22d9070, 'panic'), (0x22d942a, 0x22d9070, 'panic'), (0x2adbe1e, 0x2ad7140, 'panic'), (0x2adc28e, 0x2ad7140, 'panic'), (0x2cc742f, 0x2cc1120, 'panic'), (0x2cc777c, 0x2cc1120, 'panic'), (0x5a38c0b, 0x5a35f50, 'panic'), (0x5a38c7f, 0x5a35f50, 'panic'), (0x5a38d26, 0x5a35f50, 'panic'), (0x5a38d7b, 0x5a35f50, 'panic'), (0x5a38e39, 0x5a35f50, 'panic'), (0x5a38e7b, 0x5a35f50, 'panic'), (0x5c84322, 0x5c842e0, 'panic'), (0x5c8435c, 0x5c842e0, 'panic'), (0x5c986f2, 0x5c98260, 'panic'), (0x5c9871c, 0x5c98260, 'panic'), (0x5c98746, 0x5c98260, 'panic'), (0x5ca0287, 0x5c9fdb0, 'panic'), (0x5ca02bb, 0x5c9fdb0, 'panic')],
    0x64c5170: [(0x5cd5fb5, 0x5cd5ea0, 'panic')],
    0x64c5520: [(0x5cfcf24, 0x5cfcec0, 'panic')],
    0x64c6458: [(0x156f04c, 0x156ef90, 'panic'), (0x172d07c, 0x172cfc0, 'panic'), (0x2a00aec, 0x2a00a30, 'panic'), (0x2e74219, 0x2e74160, 'panic'), (0x478118f, 0x4781080, 'panic'), (0x59647c9, 0x5964710, 'panic'), (0x5ce0a32, 0x5ce09a0, 'panic')],
    0x64c7348: [(0x5d00f64, 0x5d00f40, 'enum_accessor')],
    0x64c74f0: [(0x5d01844, 0x5d01820, 'enum_accessor')],
}
EXPECTED_PANICS = {
    0x150ba55: ('failed to spawn thread', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/thread/functions.rs', 131),
    0x1534f91: ('failed to spawn thread', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/thread/functions.rs', 131),
    0x1565d72: ('ren restart file error', 'base/src/ren.rs', 234),
    0x15a5a57: ('called `Result::unwrap()` on an `Err` value', 'base/src/log/handle.rs', 136),
    0x15d5c42: ('failed to spawn thread', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/thread/functions.rs', 131),
    0x15d668d: ('failed to spawn thread', 'base/src/lu.rs', 159),
    0x15d7213: ('tokio_run', 'base/src/lu.rs', 58),
    0x15d7250: ('tokio_run', 'base/src/lu.rs', 55),
    0x1774072: ('called `Result::unwrap()` on an `Err` value', 'global_constants/src/aws_name.rs', 295),
    0x2adc399: ('failed to spawn thread', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/thread/functions.rs', 131),
    0x2aeeab1: ('failed to spawn thread', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/thread/functions.rs', 131),
    0x2caea98: ('failed to spawn thread', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/thread/functions.rs', 131),
    0x2cb9fed: ('failed to spawn thread', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/thread/functions.rs', 131),
    0x2ae17ea: ('called `Result::unwrap()` on an `Err` value', 'node/src/utils.rs', 66),
    0x2d27369: ('failed to spawn thread', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/thread/functions.rs', 131),
    0x2e6dd87: ('&mut [u8].write() cannot error', '/home/ubuntu/hl/code_Mainnet/z_vendor/hyper/src/proto/h1/encode.rs', 324),
    0x2e86a87: ('&mut [u8].write() cannot error', 'z_forks/hyper-fork/src/proto/h1/encode.rs', 324),
    0x4e39216: ('failed to spawn thread', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/thread/functions.rs', 131),
    0x5a08601: ('failed to spawn thread', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/thread/functions.rs', 131),
    0x5a08e61: ('failed to spawn thread', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/thread/functions.rs', 131),
    0x5a6e131: ('failed to spawn thread', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/thread/functions.rs', 131),
    0x156727f: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 103),
    0x15672ff: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 103),
    0x1567347: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 103),
    0x156737d: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 103),
    0x1567430: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 101),
    0x1567499: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 101),
    0x156756a: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 101),
    0x15675c5: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 101),
    0x22d93d8: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 103),
    0x22d942a: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 101),
    0x2adbe1e: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 103),
    0x2adc28e: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 101),
    0x2cc742f: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 103),
    0x2cc777c: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 101),
    0x5a38c0b: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 103),
    0x5a38c7f: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 103),
    0x5a38d26: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 103),
    0x5a38d7b: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 101),
    0x5a38e39: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 101),
    0x5a38e7b: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 101),
    0x5c84322: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 103),
    0x5c8435c: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/pal/unix/time.rs', 101),
    0x5c986f2: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/process/mod.rs', 65),
    0x5c9871c: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/process/mod.rs', 61),
    0x5c98746: ('called `Result::unwrap()` on an `Err` value', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/process/mod.rs', 57),
    0x5ca0287: ('failed to generate random data', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/random/linux.rs', 157),
    0x5ca02bb: ('failed to open /dev/random', '/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/random/linux.rs', 136),
    0x5cd5fb5: ('called `Result::unwrap()` on an `Err` value', '/home/ubuntu/hl/code_Mainnet/z_vendor/threadpool/src/lib.rs', 777),
    0x5cfcf24: ('failed to create UnixStream', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/signal/unix.rs', 71),
    0x156f04c: ('failed to wake I/O driver', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/io/driver.rs', 272),
    0x172d07c: ('failed to wake I/O driver', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/io/driver.rs', 272),
    0x2a00aec: ('failed to wake I/O driver', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/io/driver.rs', 272),
    0x2e74219: ('failed to wake I/O driver', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/io/driver.rs', 272),
    0x478118f: ('failed to wake I/O driver', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/io/driver.rs', 272),
    0x59647c9: ('failed to wake I/O driver', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/io/driver.rs', 272),
    0x5ce0a32: ('failed to wake I/O driver', '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/io/driver.rs', 272),
}
EXPECTED_FIELD_OFFSETS = {
    0x14cb644: 56,
    0x2a01804: 56,
    0x4302f84: 56,
    0x4747124: 56,
    0x4775a14: 56,
    0x4ecdca4: 56,
}

FAMILIES = {0x20: "standalone", 0x58: "extended", 0x40: "tokio"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def hx(value: int) -> str:
    return f"0x{value:x}"


def read(data: bytes, va: int, size: int) -> bytes:
    for sec in sections(data):
        start = sec["address"]
        if start <= va and va + size <= start + sec["size"]:
            off = sec["offset"] + va - start
            return data[off:off + size]
    raise ValueError(f"unmapped read at {hx(va)}")


def relocations(data: bytes) -> dict:
    secs = {s["name"]: s for s in sections(data)}
    mapping: dict[int, dict] = {}
    counts = {"relative": 0, "glob_dat": 0, "jump_slot": 0, "total": 0}
    for name in (".rela.dyn", ".rela.plt"):
        rela = secs[name]
        blob = data[rela["offset"]:rela["offset"] + rela["size"]]
        for off in range(0, len(blob), 24):
            addr, info, addend = struct.unpack_from("<QQq", blob, off)
            rtype = info & 0xFFFFFFFF
            counts["total"] += 1
            if rtype == 8:
                counts["relative"] += 1
            elif rtype == 6:
                counts["glob_dat"] += 1
            elif rtype == 7:
                counts["jump_slot"] += 1
            else:
                continue
            mapping[addr] = {"type": rtype, "addend": addend}
    return {"map": mapping, "counts": counts}


def body_map(data: bytes) -> dict[int, dict]:
    _, rows, _ = fde_extents(data)
    return {f["start"]: {"start": f["start"], "end": f["end"],
                         "bytes": f["end"] - f["start"]}
            for f in rows if f["end"] > f["start"]}


def cell(rel: dict, data: bytes, va: int) -> tuple[str, int]:
    entry = rel["map"].get(va)
    if entry and entry["type"] == 8:
        return "RELATIVE", entry["addend"]
    return "raw", struct.unpack("<Q", read(data, va, 8))[0]


def is_header(rel: dict, data: bytes, fdes: dict, va: int) -> bool:
    k0, v0 = cell(rel, data, va)
    k1, v1 = cell(rel, data, va + 8)
    k2, v2 = cell(rel, data, va + 0x10)
    return (k0 == "RELATIVE" and v0 in fdes and k1 == "raw"
            and k2 == "raw" and 0 < v1 <= 0x100000
            and v2 in (1, 2, 4, 8, 16, 32, 64, 128))


def header_bases(rel: dict, data: bytes, fdes: dict) -> list[int]:
    sec = next(s for s in sections(data) if s["name"] == ".data.rel.ro")
    return [va for va in range(sec["address"],
                               sec["address"] + sec["size"], 8)
            if is_header(rel, data, fdes, va)]


def extent_of(rel: dict, data: bytes, fdes: dict, bases: list[int],
              bases_set: set[int], base: int) -> int:
    i = bases.index(base)
    nxt = bases[i + 1] if i + 1 < len(bases) else None
    ext = 0x18
    while True:
        if nxt is not None and base + ext >= nxt:
            break
        kind, val = cell(rel, data, base + ext)
        ok = val in fdes or val in bases_set
        if not ok:
            break
        ext += 8
        if ext > 0x400:
            break
    while ext > 0x18:
        kind, val = cell(rel, data, base + ext - 8)
        if kind == "raw" and val == 0:
            ext -= 8
        else:
            break
    return ext


def slots_of(rel: dict, data: bytes, base: int, extent: int) -> list[dict]:
    out = []
    for off in range(0x18, extent, 8):
        kind, val = cell(rel, data, base + off)
        out.append({"offset": hx(off), "kind": kind, "target": hx(val)})
    return out


def drop_template(data: bytes, fdes: dict, drop: int) -> dict:
    size = fdes[drop]["bytes"]
    blob = read(data, drop, size)
    dealloc = 0
    for m in re.finditer(rb"\xff\x15(....)", blob, re.S):
        tgt = drop + m.start() + 6 + struct.unpack("<i", m.group(1))[0]
        if tgt == DEALLOC_SLOT:
            dealloc += 1
    return {
        "tag_mask": bool(TAG_MASK.search(blob)),
        "dealloc_refs": dealloc,
        "mov_0x18": bool(MOV_18.search(blob)),
        "word_load": b"\x48\x8b\x07" in blob[:16],
    }


def extract_string(data: bytes, va: int, ln: int) -> str:
    return read(data, va, ln).decode("utf-8", "replace")


def panic_args(data: bytes, rel: dict, text: dict, site: int,
               panic_call: int) -> dict:
    """Extract the panic message and Location a panic-pair site loads.

    The window runs from 0x80 before the vtable lea to the panic
    call: the last lea rdi names the message, the last mov esi its
    length, and the last lea r8 the Location record {file pointer
    (a RELATIVE relocation), file length at +8, line at +0x10}.
    """
    tb = text["address"]
    raw = data[text["offset"]:text["offset"] + text["size"]]
    win = raw[site - 0x80 - tb:panic_call - tb]
    wbase = site - 0x80
    out: dict = {"message": None, "location": None}
    msg = None
    for m in re.finditer(rb"\x48\x8d\x3d....", win):
        d = struct.unpack_from("<i", win, m.start() + 3)[0]
        msg = wbase + m.start() + 7 + d
    length = None
    for m in re.finditer(rb"\xbe(....)", win):
        length = struct.unpack("<I", m.group(1))[0]
    if msg is not None and length is not None and length < 300:
        try:
            out["message"] = extract_string(data, msg, length)
        except ValueError:
            pass
    loc = None
    for m in re.finditer(rb"\x4c\x8d\x05....", win):
        d = struct.unpack_from("<i", win, m.start() + 3)[0]
        loc = wbase + m.start() + 7 + d
    if loc is not None:
        entry = rel["map"].get(loc)
        if entry and entry["type"] == 8:
            try:
                flen, line = struct.unpack(
                    "<QI", read(data, loc + 8, 12))
                fstr = extract_string(data, entry["addend"], flen)
                if flen <= 300 and fstr.endswith(".rs"):
                    out["location"] = {"file": fstr, "line": line}
            except ValueError:
                pass
    return out


def classify(data: bytes, text: dict, fdes: dict, rel: dict,
             named: dict, body_starts: list[int], site: int,
             base: int) -> dict:
    tb = text["address"]
    raw = data[text["offset"]:text["offset"] + text["size"]]
    i = bisect_right(body_starts, site) - 1
    body = body_starts[i] if i >= 0 and site < fdes[
        body_starts[i]]["end"] else None
    blob = raw[site - tb:site - tb + 0x30]
    rex = blob[0]
    modrm = blob[2]
    regmap = {0x05: "rax", 0x0D: "rcx", 0x15: "rdx", 0x1D: "rbx",
              0x2D: "rbp", 0x35: "rsi", 0x3D: "rdi"}
    lea_reg = regmap.get(modrm)
    if lea_reg and rex in (0x4C, 0x4D):
        lea_reg = "r" + str(8 + int(lea_reg[1:])) if lea_reg[1:].isdigit() \
            else {"rax": "r8", "rcx": "r9", "rdx": "r10", "rbx": "r11",
                  "rbp": "r13", "rsi": "r14", "rdi": "r15"}[lea_reg]
    entry: dict = {"site": hx(site),
                   "body": hx(body) if body else None}
    # panic-pair: a call through the panic-import slot follows closely
    panic_call = None
    for m in re.finditer(rb"\xff\x15(....)", blob, re.S):
        tgt = site + m.start() + 6 + struct.unpack("<i", m.group(1))[0]
        if tgt == PANIC_SLOT:
            panic_call = m.start()
            break
    if panic_call is not None:
        args = panic_args(data, rel, text, site, site + panic_call)
        entry["kind"] = "panic"
        entry["message"] = args["message"]
        loc = args["location"]
        entry["location"] = ({"file": loc["file"], "line": loc["line"]}
                             if loc else None)
        return entry
    if lea_reg == "rdx" and b"\xc3" in blob[:0x15]:
        bstart = raw[body - tb:body - tb + 0x60] if body else b""
        fm = re.match(
            rb"\x48\x8d\x47(.)\x48\x8d\x15....\xc3", bstart)
        if fm:
            entry["kind"] = "field_accessor"
            entry["field_offset"] = fm.group(1)[0]
        else:
            entry["kind"] = "enum_accessor"
        entry.update(parent_record(rel, data, fdes, named, body))
        return entry
    if lea_reg == "rax" and any(p in blob[:0x14] for p in
                                (b"\x89\x43", b"\x89\x46",
                                 b"\x89\x83", b"\x89\x86")):
        entry["kind"] = "store"
        return entry
    if lea_reg == "rax" and b"\xc3" in blob[:0x24]:
        entry["kind"] = "clone"
        entry.update(parent_record(rel, data, fdes, named, body))
        return entry
    entry["kind"] = "other"
    entry["lea_reg"] = lea_reg
    return entry


def parent_record(rel: dict, data: bytes, fdes: dict, named: dict,
                  body: int | None) -> dict:
    if body is None or body not in named:
        return {}
    c = named[body][0]
    for back in range(0, 0x101, 8):
        if is_header(rel, data, fdes, c - back):
            _, pdrop = cell(rel, data, c - back)
            _, psize = cell(rel, data, c - back + 8)
            return {"parent": {"cell": hx(c), "vtable": hx(c - back),
                               "entry_off": hx(back),
                               "self_size": psize,
                               "self_drop": hx(pdrop)}}
    return {"parent": {"cell": hx(c), "vtable": None,
                       "entry_off": None}}


def analyze(data: bytes) -> dict:
    require(len(data) == SIZE, "artifact size mismatch")
    require(hashlib.sha256(data).hexdigest() == SHA256,
            "artifact hash mismatch")
    rel = relocations(data)
    require(rel["counts"] == RELOC_TOTALS,
            f"relocation counts drifted: {rel['counts']}")
    fdes = body_map(data)
    bases = header_bases(rel, data, fdes)

    # The shared method: stub bytes, GOT resolution, body hash (the
    # same pins the H13 packet set).
    require(read(data, METHOD_STUB, 6) == METHOD_STUB_BYTES,
            "method stub bytes drifted")
    stub_sha = hashlib.sha256(METHOD_STUB_BYTES).hexdigest()
    jump = struct.unpack("<i", read(data, METHOD_STUB + 2, 4))[0]
    require(METHOD_STUB + 6 + jump == METHOD_GOT_SLOT,
            "stub does not jump through its recorded GOT slot")
    got = rel["map"].get(METHOD_GOT_SLOT)
    require(got and got["type"] == 8 and got["addend"] == METHOD_BODY,
            "method GOT slot does not resolve to the method body")
    require(METHOD_BODY in fdes, "method body has no FDE extent")
    mlen = fdes[METHOD_BODY]["bytes"]
    msha = hashlib.sha256(read(data, METHOD_BODY, mlen)).hexdigest()
    require(msha == METHOD_BODY_SHA256, "method body hash drifted")
    require(cell(rel, data, STUB_GOT_CELL) == ("RELATIVE", METHOD_STUB),
            ".got stub cell drifted")
    thunk = fdes[PANIC_THUNK]
    require(thunk["bytes"] == 82, "panic thunk extent drifted")

    # Display body pins: the sibling one-method vtables' method and the
    # extended vtables' +0x20 slot.
    require(DISPLAY_BODY in fdes, "display body has no FDE extent")
    dlen = fdes[DISPLAY_BODY]["bytes"]
    dsha = hashlib.sha256(read(data, DISPLAY_BODY, dlen)).hexdigest()
    require(read(data, DISPLAY_OS_ERROR_STR, 10) == b"(os error ",
            "display body lost its (os error string pin")
    require(read(data, DISPLAY_STRERROR_STR, 18)
            == b"strerror_r failure",
            "display body lost its strerror_r string pin")
    for fwd, (off, code) in ((FWD_SOURCE, FWD_SOURCE_CALL),
                             (FWD_PROVIDE, FWD_PROVIDE_CALL)):
        require(fwd in fdes and fdes[fwd]["bytes"] == 41,
                f"forwarder {hx(fwd)} extent drifted")
        require(read(data, fwd + off, 3) == code,
                f"forwarder {hx(fwd)} lost its inner-vtable call pin")

    # Census: every cell naming the stub must be a vtable +0x18 slot
    # (32) or the one .got cell.
    naming = sorted(va for va, e in rel["map"].items()
                    if e["type"] == 8 and e["addend"] == METHOD_STUB)
    vtable_cells = [va for va in naming if va != STUB_GOT_CELL]
    require(len(vtable_cells) == 32,
            f"expected 32 vtable slots naming the stub, "
            f"found {len(vtable_cells)}")
    census = sorted(va - 0x18 for va in vtable_cells)
    require(census == sorted(EXPECTED_VTABLES),
            "vtable census drifted from the recorded set")

    # Reference census over all 32 bases.
    text = next(s for s in sections(data) if s["name"] == ".text")
    tb, tsize = text["address"], text["size"]
    raw = data[text["offset"]:text["offset"] + tsize]
    targets = set(census)
    pat = re.compile(rb"(?:\x48|\x4c)\x8d[\x05\x0d\x15\x1d\x2d\x35\x3d]"
                     rb"(....)", re.S)
    rip_sites: dict[int, list[int]] = {b: [] for b in census}
    for m in pat.finditer(raw):
        tgt = tb + m.start() + 7 + struct.unpack("<i", m.group(1))[0]
        if tgt in targets:
            rip_sites[tgt].append(tb + m.start())
    movabs: dict[int, list[int]] = {b: [] for b in census}
    abs_pat = re.compile(rb"\x48\xb8(........)\x00\x00", re.S)
    for m in abs_pat.finditer(raw):
        val = struct.unpack("<Q", m.group(1))[0]
        if val in targets:
            movabs[val].append(tb + m.start())
    addends = [va for va, e in rel["map"].items()
               if e["addend"] in targets]
    qpat = re.compile(b"|".join(re.escape(struct.pack("<Q", b))
                                for b in census))
    reloc_cells = set(rel["map"])
    rip_spans = [(s - 3, s + 4) for lst in rip_sites.values()
                 for s in lst]
    raw_hits: dict[int, list[int]] = {b: [] for b in census}
    for sec in sections(data):
        if sec["name"] not in (".data.rel.ro", ".rodata", ".data",
                               ".got", ".got.plt"):
            continue
        sblob = data[sec["offset"]:sec["offset"] + sec["size"]]
        for m in qpat.finditer(sblob):
            va = sec["address"] + m.start()
            if va in reloc_cells:
                continue
            if any(lo <= va <= hi for lo, hi in rip_spans):
                continue
            raw_hits[struct.unpack("<Q", m.group(0))[0]].append(va)
    for b in census:
        require(not movabs[b] and not raw_hits[b],
                f"vtable {hx(b)} gained a non-lea reference")
    require(not addends, "a relocation addend names a sibling vtable")

    body_starts = sorted(fdes)
    named: dict[int, list[int]] = {}
    for va, e in rel["map"].items():
        if e["type"] == 8 and e["addend"] in fdes:
            named.setdefault(e["addend"], []).append(va)

    vtables = []
    drop_records: dict[int, dict] = {}
    kind_totals: dict[str, int] = {}
    for base in census:
        exp_drop, exp_ext = EXPECTED_VTABLES[base]
        _, drop = cell(rel, data, base)
        _, size = cell(rel, data, base + 8)
        _, align = cell(rel, data, base + 0x10)
        require(drop == exp_drop and size == 8 and align == 8,
                f"vtable {hx(base)} header drifted")
        extent = extent_of(rel, data, fdes, bases, set(bases), base)
        require(extent == exp_ext,
                f"vtable {hx(base)} extent drifted: {hx(extent)}")
        family = FAMILIES[extent]
        slots = slots_of(rel, data, base, extent)
        require(slots[0]["target"] == hx(METHOD_STUB),
                f"vtable {hx(base)} lost the shared stub slot")
        sibling = None
        if family == "extended":
            require(slots[1]["target"] == hx(DISPLAY_BODY),
                    f"extended vtable {hx(base)} +0x20 is not Display")
            require(slots[3]["target"] == hx(FWD_SOURCE),
                    f"extended vtable {hx(base)} +0x30 is not the "
                    "source forwarder")
            require(slots[6]["target"] == hx(FWD_PROVIDE),
                    f"extended vtable {hx(base)} +0x48 is not the "
                    "provide forwarder")
            sib = base - 0x20
            require(is_header(rel, data, fdes, sib),
                    f"extended vtable {hx(base)} lost its sibling")
            _, sdrop = cell(rel, data, sib)
            _, ssize = cell(rel, data, sib + 8)
            _, salign = cell(rel, data, sib + 0x10)
            _, smethod = cell(rel, data, sib + 0x18)
            require(sdrop == drop and ssize == 8 and salign == 8
                    and smethod == DISPLAY_BODY,
                    f"sibling of {hx(base)} drifted")
            require(slots[2]["target"] == hx(sib),
                    f"extended vtable {hx(base)} +0x28 does not name "
                    "its sibling")
            sibling = {"base": hx(sib), "drop": hx(sdrop),
                       "size": ssize, "align": salign,
                       "method": hx(smethod)}
        sites = [classify(data, text, fdes, rel, named, body_starts,
                          s, base) for s in rip_sites[base]]
        want = [(hx(s), hx(b) if b else None, k)
                for s, b, k in EXPECTED_SITES[base]]
        got = [(s["site"], s["body"], s["kind"]) for s in sites]
        require(got == want,
                f"sites of {hx(base)} drifted: {got} != {want}")
        for s in sites:
            kind_totals[s["kind"]] = kind_totals.get(s["kind"], 0) + 1
            if s["kind"] == "panic":
                wmsg, wfile, wline = EXPECTED_PANICS[int(s["site"], 16)]
                require(s["message"] == wmsg
                        and s["location"] == {"file": wfile,
                                              "line": wline},
                        f"panic args at {s['site']} drifted")
            if s["kind"] == "field_accessor":
                require(s["field_offset"]
                        == EXPECTED_FIELD_OFFSETS[int(s["site"], 16)],
                        f"field offset at {s['site']} drifted")
        if drop not in drop_records:
            dlen2 = fdes[drop]["bytes"]
            drop_records[drop] = {
                "start": hx(drop), "bytes": dlen2,
                "sha256": hashlib.sha256(
                    read(data, drop, dlen2)).hexdigest(),
                "template": drop_template(data, fdes, drop)}
            t = drop_records[drop]["template"]
            require(t["tag_mask"] and t["mov_0x18"] and t["word_load"]
                    and t["dealloc_refs"] >= 2,
                    f"drop {hx(drop)} lost the io-error template")
        vtables.append({
            "base": hx(base), "is_h13_vtable": base == H13_VTABLE,
            "drop": hx(drop), "size": size, "align": align,
            "extent": hx(extent), "family": family, "slots": slots,
            "sibling_display_vtable": sibling,
            "references": {"rip": sites, "movabs": [],
                           "relocation_addend": [], "raw_qword": []}})

    require(len(drop_records) == 30,
            f"expected 30 distinct drops, found {len(drop_records)}")
    h13_drop = drop_records[EXPECTED_VTABLES[H13_VTABLE][0]]
    require(h13_drop["sha256"] == H13_DROP_SHA256,
            "H13 vtable drop hash no longer matches its packet")

    return {
        "artifact": {"path": str(TARGET), "size": len(data),
                     "sha256": SHA256},
        "relocation_counts": rel["counts"],
        "method": {"stub": hx(METHOD_STUB), "stub_bytes": 6,
                   "stub_sha256": stub_sha,
                   "got_slot": hx(METHOD_GOT_SLOT),
                   "body": hx(METHOD_BODY), "body_bytes": mlen,
                   "body_sha256": msha,
                   "got_cell_naming_stub": hx(STUB_GOT_CELL),
                   "panic_thunk": hx(PANIC_THUNK),
                   "panic_slot": hx(PANIC_SLOT),
                   "dealloc_slot": hx(DEALLOC_SLOT)},
        "display": {"body": hx(DISPLAY_BODY), "body_bytes": dlen,
                    "body_sha256": dsha,
                    "os_error_string_at": hx(DISPLAY_OS_ERROR_STR),
                    "strerror_string_at": hx(DISPLAY_STRERROR_STR)},
        "forwarders": {
            "plus_0x30": {"body": hx(FWD_SOURCE), "bytes": 41,
                          "inner_call_offset": hx(FWD_SOURCE_CALL[0]),
                          "inner_slot": "0x30"},
            "plus_0x48": {"body": hx(FWD_PROVIDE), "bytes": 41,
                          "inner_call_offset": hx(FWD_PROVIDE_CALL[0]),
                          "inner_slot": "0x48"}},
        "census": {"vtables": len(census), "distinct_drops": 30,
                   "families": {
                       "standalone": sum(1 for v in vtables
                                         if v["family"] == "standalone"),
                       "extended": sum(1 for v in vtables
                                       if v["family"] == "extended"),
                       "tokio": sum(1 for v in vtables
                                    if v["family"] == "tokio")},
                   "reference_sites": sum(len(v["references"]["rip"])
                                          for v in vtables),
                   "site_kinds": kind_totals},
        "drops": [drop_records[d] for d in sorted(drop_records)],
        "vtables": vtables,
        "answers": [
            "All 31 siblings of the H13 vtable are vtables for the "
            "same value: the 8-byte tagged std io error.  Every "
            "header reads size 8 / align 8 and every one of the 30 "
            "distinct drop bodies is the same tag-dispatch template "
            "(tag & 3; only tag 1 acts, dropping the boxed inner "
            "error through its own vtable and freeing the 24-byte "
            "box via 0x64df4a0).",
            "18 of the 32 are standalone Debug-only vtables (extent "
            "0x20); 13 are extended vtables (extent 0x58) whose slots "
            "are the Debug stub, the Display body 0x5ca84b0, a "
            "pointer to the one-method Display vtable at base-0x20, "
            "the +0x30 and +0x48 forwarders 0x5ca8760 / 0x5ca8730, "
            "and three local bodies; 1 (tokio 0x64c6458, extent "
            "0x40) carries four local slots instead.",
            "The 94 references are all rip-relative lea: 57 "
            "panic-pair sites (messages and Locations pinned per "
            "site, from 'failed to spawn thread' expects to tokio's "
            "'failed to wake I/O driver' and libstd's own internal "
            "unwraps on 0x64c3270), 6 field accessors and 10 enum "
            "accessors returning (value, vtable) pairs out of parent "
            "trait objects, 14 pair-store and 3 clone sites, and 4 "
            "other sites.",
        ],
        "limitations": [
            "Parent traits of the accessor, store and clone bodies "
            "are recorded structurally (parent vtable, entry offset, "
            "Self size and drop) but not named; the byte evidence "
            "does not carry trait names.",
            "The extended vtables' local slots (+0x38, +0x40, "
            "+0x50) and tokio vtable 0x64c6458's four local slots are "
            "recorded as targets; the traits they serve are not "
            "identified.",
            "The forwarders at +0x30 and +0x48 are pinned by their "
            "forwarding targets inside the boxed error's vtable; "
            "their trait-slot names are not asserted.",
            "Panic messages and Locations are read from the static "
            "string and Location records the bodies load; no value "
            "was executed.",
        ],
    }


def frames(records: dict) -> str:
    lines = [
        "shared io-error Debug vtables - node #115 (RE-005)",
        "",
        "stub 0x5ca5610 -> GOT 0x64e1878 -> Debug body 0x5ca7ea0 "
        "(H13 pins); .got cell 0x64e0170 also names the stub",
        "32 vtables name the stub at +0x18; all size 8 / align 8; "
        "30 distinct drops, all the io-error tag template",
        "families: 18 standalone (0x20), 13 extended (0x58), "
        "1 tokio (0x40, 0x64c6458)",
        "extended slots: +0x20 Display 0x5ca84b0, +0x28 sibling "
        "Display vtable at base-0x20, +0x30 fwd 0x5ca8760, "
        "+0x48 fwd 0x5ca8730",
        "94 rip-relative references: 57 panic, 6 field accessors, "
        "10 enum accessors, 14 stores, 3 clones, 4 other",
        "",
    ]
    for v in records["vtables"]:
        kinds = {}
        for s in v["references"]["rip"]:
            kinds[s["kind"]] = kinds.get(s["kind"], 0) + 1
        lines.append(
            f"{v['base']} [{v['family']}] drop {v['drop']} "
            f"refs {kinds}")
    return "\n".join(lines) + "\n"


def objdump(data: bytes, start: int, size: int) -> bytes:
    proc = subprocess.run(
        ["objdump", "-d", f"--start-address={start}",
         f"--stop-address={start + size}", str(TARGET)],
        check=True, capture_output=True)
    return proc.stdout


def export_bodies(data: bytes, records: dict) -> dict[str, tuple[int, int]]:
    out: dict[str, tuple[int, int]] = {}
    for d in records["drops"]:
        start = int(d["start"], 16)
        out[f"drop_{start:x}"] = (start, d["bytes"])
    out["method_stub"] = (METHOD_STUB, 6)
    out["method_body"] = (METHOD_BODY, records["method"]["body_bytes"])
    out["display_body"] = (DISPLAY_BODY,
                           records["display"]["body_bytes"])
    out["forwarder_0x30"] = (FWD_SOURCE, 41)
    out["forwarder_0x48"] = (FWD_PROVIDE, 41)
    return out


def generate() -> dict:
    data = TARGET.read_bytes()
    records = analyze(data)
    packet = PACKET
    packet.mkdir(parents=True, exist_ok=True)
    (packet / "records.json").write_text(
        json.dumps(records, indent=2, sort_keys=True) + "\n")
    (packet / "frames.txt").write_text(frames(records))
    for role, (start, size) in sorted(
            export_bodies(data, records).items()):
        (packet / f"{role}.objdump.txt").write_bytes(
            objdump(data, start, size))
    digests = []
    for path in sorted(packet.iterdir()):
        if path.name == "MANIFEST.sha256":
            continue
        digests.append(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
            f"{path.name}")
    (packet / "MANIFEST.sha256").write_text("\n".join(digests) + "\n")
    return records


def main() -> int:
    if sys.argv[1:] == ["generate"]:
        generate()
        print(f"wrote {PACKET}")
        return 0
    if sys.argv[1:] == ["check"]:
        records = analyze(TARGET.read_bytes())
        retained = json.loads((PACKET / "records.json").read_text())
        require(records == retained, "records drifted")
        print("shared-debug-vtable records match the materialized "
              "artifact")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
