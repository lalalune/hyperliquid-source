#!/usr/bin/env python3
"""RE-005: digest-bound node115 builder-caller wrapper identities.

Answers the question PR #2950 left open. That packet pinned the
driver builder 0x5cf9600 (vendored tokio runtime Builder::build):
its only callers are two bodies reached through the GOT slot
0x64e1760, and both overwrite the builder config's u16 at +0xe5
with 0x0101. It did not identify the two caller bodies. This
packet does, from panic Locations, panic message strings, and
call-graph position.

Wrapper a (0x15d6fd0..0x15d8447, 5239 bytes) is a runtime-runner
function of the base crate, source file base/src/lu.rs. Its two
builder calls are guarded by an entry flag in edi:

- edi != 0 (source arm ending at lu.rs:55:40): the body first
  reads a process-global once state dword at 0x64f01d8; when it
  is nonzero it calls call_once_force (GOT slot 0x64df9f0 ->
  0x5c87d50) with the once at 0x64f01d8 and a closure environment
  holding the address of a global cell at 0x64f01c0, then falls
  into the build: cfg_ctor (0x5cf93f0) with kind argument 1, the
  0x0101 overwrite at cfg +0xe5, the builder through the slot,
  a cfg drop (0x5cf1af0). A builder error result (tag dword 2)
  panics through the message thunk (slot 0x64df6a0 -> 0x1680c30)
  with the message "tokio_run" and Location lu.rs:55:40.
- edi == 0 (source arm ending at lu.rs:58:76): the same build
  with cfg_ctor kind argument 0 and no once consultation; the
  error panic carries Location lu.rs:58:76.

After either build the body copies the 0x70-byte runtime object
to rsp+0x70, memcpy's (slot 0x64df508 -> memcpy@GLIBC) its
second argument's 0x3d0 bytes into the frame, and enters the
vendored runtime context (TLS state byte at fs:-0x1130+0x48;
the inlined scheduler bodies carry current_thread/mod.rs and
multi_thread/mod.rs Locations). Its own nested-runtime panic
site carries Location lu.rs:60:13 with the 387-byte "Cannot
start a runtime from within a runtime..." message. The body's
only caller is a 67-byte adapter (0x155fa10) that expands a
0x30-byte input into the 0x3d0-byte argument (zero byte at
+0x3c8) and passes edi = 0 -- so as linked, only the kind-0 arm
is exercised. The adapter has no direct callers; it is called
once, through its function-pointer GOT slot 0x64e1190, by a
498-byte list-walking dispatcher (0x15b8fd0) that is itself
recorded in a static .data.rel.ro table (cell 0x6400548).

Wrapper b (0x2ae1690..0x2ae27b2, 4386 bytes) is the node binary's
principal entry function. The ELF entry _start (0x1419300)
passes main = 0x2cef8f0 to __libc_start_main (slot 0x64df458);
that 39-byte compiler main shim registers the user main
0x2cd8370 with std's lang_start (slot 0x64e6c30 -> 0x5c99970);
the user main zero-builds a 0x2c40-byte struct (explicit zero
byte at struct +0x21a) and calls wrapper b with its address --
wrapper b's only caller. Wrapper b builds exactly one runtime:
cfg_ctor kind 1, the 0x0101 overwrite, the builder through the
slot, and on a tag-2 error it panics through the same thunk
with the standard 43-byte unwrap message and Location
node/src/utils.rs:66:70; its nested-runtime panic site carries
Location node/src/utils.rs:66:79. It then memcpy's the
0x2c40-byte argument into its frame and enters the runtime
context exactly as wrapper a does.

The two bodies are therefore the same idiom in two different
crates -- build a runtime through the shared vendored builder
and block on it in place -- but they are not the same function
and neither calls the other: different argument shapes (0x3d0
vs 0x2c40 bytes), different failure behaviour (an expect with
the message "tokio_run" in base/src/lu.rs vs a plain unwrap in
node/src/utils.rs), and opposite ends of the call graph (a
callback reached through a registration table vs the callee of
the process main).
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = (ROOT / 'research/work-items/'
          'RE-005-node115-builder-wrapper-identities')
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
OWNERS = {
 'wrapper_a': (0x15d6fd0, 0x15d8447,
            '0a33a4e33944ad1377a8544831780bcc081401ce3f7d5e86c33606c88ff44d8c'),
 'wrapper_b': (0x2ae1690, 0x2ae27b2,
            '6ca0595c13836bca0cb0173bd591a09d6da6791532e23a5a71c63715380727d9'),
 'adapter_a': (0x155fa10, 0x155fa53,
            '61b4de43a06f936410b37a7d3c49857857e0fd892024a617d7a522ac59692155'),
 'adapter_b': (0x2cd8370, 0x2cd83af,
            'ed23bc89640a43b1a5f373d5cb18929d79ce5b47923e58ba0565f592ba2b60d6'),
 'main_shim': (0x2cef8f0, 0x2cef917,
            'c0621248d6ec3fd7ae1ee2df6b09bdd79541219362b313e5567717eb8f59a5c9'),
 'entry_start': (0x1419300, 0x1419326,
            'cf432d50b96a11a67b03f671fe51599dd44a6b9c5a009eefba514c487d9e23bd'),
 'dispatcher_a': (0x15b8fd0, 0x15b91c2,
            '20cd3ac9bdc80df92482568c93f647e74cf4402f9b8b9c8f917d8f7ba32dd0d9'),
 'cfg_ctor': (0x5cf93f0, 0x5cf959f,
            '9736d15280792f960bb0b52a53ff015185c0ac78b5f3a7f4daaf0387ead23680'),
 'builder': (0x5cf9600, 0x5cfa8b1,
            '12813161d76cb5aa11039d12cbbf45d6f170b2aa53da586df8e03b579e02d13b'),
 'panic_msg_thunk': (0x1680c30, 0x1680c82,
            '2d00fd36dc6102ab0738e08907482bb818bca6e76e32a5b941eabf431f20767a'),
 'panic_entry': (0x1680e80, 0x1680eac,
            '28fc3434a04bb9e49d5a0164306a5c31abf6bce26425d99d27031ac1c9beb2e3'),
 'lang_start': (0x5c99970, 0x5c9a045,
            '85c321c5ef4dd64cd999ac133e97a170ffa7d088eab3fe7fcb64f31768181111'),
 'call_once_force': (0x5c87d50, 0x5c87f6c,
            '677090dab02d8f4089593e314f7dfd16a4acf10c0866e469734fab4b365853bb')}
BUILDER = 0x5cf9600
CFG_CTOR = 0x5cf93f0
CFG_DROP = 0x5cf1af0
BUILDER_SLOT = 0x64e1760
# GOT slots: value is ('relative', target) or ('glob_dat', symbol).
SLOTS = {0x64e1760: ('relative', 0x5cf9600),
         0x64df9f0: ('relative', 0x5c87d50),
         0x64df6a0: ('relative', 0x1680c30),
         0x64df6b8: ('relative', 0x1680e80),
         0x64e1190: ('relative', 0x155fa10),
         0x64e6c30: ('relative', 0x5c99970),
         0x64df508: ('glob_dat', 'memcpy'),
         0x64df458: ('glob_dat', '__libc_start_main'),
         0x64df480: ('relative', 0x6355830)}
# Location structs referenced from each wrapper body:
# struct va -> (file, line, column).
LOCATIONS_A = {
 0x6401240: ('/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/thread/local.rs', 479, 25),
 0x64014f8: ('base/src/lu.rs', 58, 76),
 0x6401510: ('base/src/lu.rs', 55, 40),
 0x6401528: ('base/src/lu.rs', 60, 13),
 0x6401908: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/mod.rs', 91, 9),
 0x6401920: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/mod.rs', 92, 39),
 0x6401950: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 218, 33),
 0x6401968: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 235, 26),
 0x6401980: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 491, 50),
 0x6401998: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 491, 30),
 0x64019b0: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 485, 20),
 0x64019c8: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 900, 36),
 0x64019e0: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 903, 53),
 0x64019f8: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 908, 23),
 0x6401a10: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 903, 33)}
LOCATIONS_B = {
 0x6443cf0: ('/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/thread/local.rs', 479, 25),
 0x6447bf0: ('node/src/utils.rs', 66, 70),
 0x6447c08: ('node/src/utils.rs', 66, 79),
 0x644a4a8: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/mod.rs', 91, 9),
 0x644a4c0: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/mod.rs', 92, 39),
 0x644a4d8: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 218, 33),
 0x644a4f0: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 235, 26),
 0x644a550: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 900, 36),
 0x644a568: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 903, 53),
 0x644a580: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 908, 23),
 0x644a598: ('/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/current_thread/mod.rs', 903, 33)}
STRINGS = {
 0x469c40: (b'tokio_run', 'wrapper a builder-error expect message'),
 0x605542: (b'called `Result::unwrap()` on an `Err` value',
            'wrapper b builder-error unwrap message'),
 0x469d92: (b'Cannot start a runtime from within a runtime. '
            b'This happens because a function (like `block_on`) '
            b'attempted to block the current thread while the '
            b'thread is being used to drive asynchronous tasks.',
            'wrapper a nested-runtime panic message'),
 0x60692e: (b'Cannot start a runtime from within a runtime. '
            b'This happens because a function (like `block_on`) '
            b'attempted to block the current thread while the '
            b'thread is being used to drive asynchronous tasks.',
            'wrapper b nested-runtime panic message'),
 0x6069ef: (b'failed to park thread',
            'wrapper b park panic message')}
PINS = {
 'wrapper_a': [
  (0x15d6fe4, '85ff', 'entry flag test on edi'),
  (0x15d6fe6, '0f84ad000000', 'edi == 0 branches to the kind-0 build'),
  (0x15d6fec, '8b05e691f104', 'kind-1 arm loads the once state dword at 0x64f01d8'),
  (0x15d6ff4, '0f85b6010000', 'nonzero once state branches to the call_once path'),
  (0x15d7002, 'be01000000', 'kind-1 cfg_ctor argument is 1'),
  (0x15d7007, 'e8e4237204', 'kind-1 cfg_ctor call'),
  (0x15d700c, '66c78424f50500000101', 'kind-1 u16 0x0101 store at cfg +0xe5'),
  (0x15d7026, 'ff1534a7f004', 'kind-1 builder call through slot 0x64e1760'),
  (0x15d7034, 'e8b7aa7104', 'kind-1 cfg drop call'),
  (0x15d7039, '83bc244001000002', 'kind-1 result tag dword compare with 2'),
  (0x15d7041, '0f84f2010000', 'kind-1 tag 2 branches to the lu.rs:55:40 expect'),
  (0x15d70a1, '31f6', 'kind-0 cfg_ctor argument is 0'),
  (0x15d70a3, 'e848237204', 'kind-0 cfg_ctor call'),
  (0x15d70a8, '66c78424f50500000101', 'kind-0 u16 0x0101 store at cfg +0xe5'),
  (0x15d70c2, 'ff1598a6f004', 'kind-0 builder call through slot 0x64e1760'),
  (0x15d70c8, '83bc244001000002', 'kind-0 result tag dword compare with 2'),
  (0x15d70d0, '0f8426010000', 'kind-0 tag 2 branches to the lu.rs:58:76 expect'),
  (0x15d7138, 'bad0030000', 'argument copy length is 0x3d0'),
  (0x15d7140, 'ff15c283f004', 'argument copy through the memcpy slot 0x64df508'),
  (0x15d71b0, '488d050990f104', 'once path loads the global cell 0x64f01c0'),
  (0x15d71cf, '488d3d0290f104', 'once path passes the once at 0x64f01d8'),
  (0x15d71ec, 'be01000000', 'call_once_force flag argument is 1'),
  (0x15d71f1, 'ff15f987f004', 'call_once_force through slot 0x64df9f0'),
  (0x15d71f7, 'e9fefdffff', 'once path falls into the kind-1 build'),
  (0x15d720c, '488d3d2d2ae9fe', 'kind-0 expect message is at 0x469c40'),
  (0x15d7213, '488d0db6a3e204', 'kind-0 error vtable is at 0x64015d0'),
  (0x15d721a, '4c8d05d7a2e204', 'kind-0 expect Location is lu.rs:58:76'),
  (0x15d7229, 'be09000000', 'kind-0 expect message length is 9'),
  (0x15d722e, 'ff156c84f004', 'kind-0 expect through the thunk slot 0x64df6a0'),
  (0x15d7249, '488d3df029e9fe', 'kind-1 expect message is at 0x469c40'),
  (0x15d7250, '488d0d79a3e204', 'kind-1 error vtable is at 0x64015d0'),
  (0x15d7257, '4c8d05b2a2e204', 'kind-1 expect Location is lu.rs:55:40'),
  (0x15d7266, 'be09000000', 'kind-1 expect message length is 9'),
  (0x15d726b, 'ff152f84f004', 'kind-1 expect through the thunk slot 0x64df6a0'),
  (0x15d8031, '488d3d5a1de9fe', 'scheduler-side nested-runtime message at 0x469d92'),
  (0x15d8038, '488d15c998e204', 'scheduler-side Location is multi_thread 91:9'),
  (0x15d803f, 'be83010000', 'nested-runtime message length is 0x183'),
  (0x15d8044, 'ff156e76f004', 'scheduler-side panic through slot 0x64df6b8'),
  (0x15d804c, '488d3d3f1de9fe', 'own nested-runtime message at 0x469d92'),
  (0x15d8053, '488d15ce94e204', 'own nested-runtime Location is lu.rs:60:13'),
  (0x15d805a, 'be83010000', 'own nested-runtime message length is 0x183'),
  (0x15d805f, 'ff155376f004', 'own nested-runtime panic through slot 0x64df6b8')],
 'wrapper_b': [
  (0x2ae16cc, 'be01000000', 'cfg_ctor argument is 1'),
  (0x2ae16d1, 'e81a7d2103', 'cfg_ctor call'),
  (0x2ae16d6, '66c78424150200000101', 'u16 0x0101 store at cfg +0xe5'),
  (0x2ae16f2, 'ff156800a003', 'builder call through slot 0x64e1760'),
  (0x2ae16f8, '83bc24a85a000002', 'result tag dword compare with 2'),
  (0x2ae1700, '0f84cd000000', 'tag 2 branches to the utils.rs:66:70 unwrap'),
  (0x2ae175e, 'ba402c0000', 'argument copy length is 0x2c40'),
  (0x2ae1768, 'ff159add9f03', 'argument copy through the memcpy slot 0x64df508'),
  (0x2ae17e3, '488d3d583db2fd', 'unwrap message is at 0x605542'),
  (0x2ae17ea, '488d0db75c9603', 'error vtable is at 0x64474a8'),
  (0x2ae17f1, '4c8d05f8639603', 'unwrap Location is utils.rs:66:70'),
  (0x2ae1800, 'be2b000000', 'unwrap message length is 0x2b'),
  (0x2ae1805, 'ff1595de9f03', 'unwrap through the thunk slot 0x64df6a0'),
  (0x2ae21b6, '488d3d7147b2fd', 'scheduler-side nested-runtime message at 0x60692e'),
  (0x2ae21bd, '488d15e4829603', 'scheduler-side Location is multi_thread 91:9'),
  (0x2ae21c4, 'be83010000', 'nested-runtime message length is 0x183'),
  (0x2ae21c9, 'ff15e9d49f03', 'scheduler-side panic through slot 0x64df6b8'),
  (0x2ae21d4, '488d3d5347b2fd', 'own nested-runtime message at 0x60692e'),
  (0x2ae21db, '488d15265a9603', 'own nested-runtime Location is utils.rs:66:79'),
  (0x2ae21e2, 'be83010000', 'own nested-runtime message length is 0x183'),
  (0x2ae21e7, 'ff15cbd49f03', 'own nested-runtime panic through slot 0x64df6b8')],
 'adapter_a': [
  (0x155fa17, '488b4710', 'adapter copies its input head from rdi +0x10'),
  (0x155fa39, 'c68424c803000000', 'adapter zeroes the byte at argument +0x3c8'),
  (0x155fa44, '31ff', 'adapter passes edi = 0'),
  (0x155fa46, 'e885750700', 'adapter calls wrapper a')],
 'adapter_b': [
  (0x2cd8395, 'c684242202000000', 'user main zeroes the byte at struct +0x21a'),
  (0x2cd839d, '488d7c2408', 'user main passes the struct at rsp+8'),
  (0x2cd83a2, 'e8e992e0ff', 'user main calls wrapper b')],
 'main_shim': [
  (0x2cef8f7, '488d05728afeff', 'shim loads the user main 0x2cd8370'),
  (0x2cef902, '488d353f127503', 'shim passes the main vtable at 0x6440b48'),
  (0x2cef90f, 'ff151b737f03', 'shim calls lang_start through slot 0x64e6c30')],
 'entry_start': [
  (0x1419318, '488d3dd1658d01', '_start passes main = 0x2cef8f0'),
  (0x141931f, 'ff1533610c05', '_start calls __libc_start_main through slot 0x64df458')],
 'dispatcher_a': [
  (0x15b9078, '488d7c2410', 'dispatcher builds the callback argument at rsp+0x10'),
  (0x15b907d, 'ff150d81f204', 'dispatcher calls adapter a through slot 0x64e1190')],
 'cfg_ctor': [
  (0x5cf948e, '4088abe4000000', 'cfg_ctor stores its kind argument byte at cfg +0xe4')]}
PIN_STARTS = {role: [va for va, _, _ in pins]
              for role, pins in PINS.items()}
CENSUS_TARGETS = {'wrapper_a': 0x15d6fd0, 'wrapper_b': 0x2ae1690,
                  'adapter_a': 0x155fa10, 'adapter_b': 0x2cd8370,
                  'main_shim': 0x2cef8f0, 'dispatcher_a': 0x15b8fd0}
LIMITS = (
 'Static trace only: no pinned bytes were executed and no live '
 'node, network, signer, or exchange state was used. Source '
 'identities are pinned by the panic Location structs, panic '
 'message strings, and call-graph positions the verifier '
 'recomputes; the exact Rust source text of the two functions '
 'is not recovered and no function names are claimed. Wrapper '
 'a is identified as a function of base/src/lu.rs (its own '
 'Locations name that file at lines 55, 58 and 60) and wrapper '
 'b as the node binary entry function whose runtime build is '
 'attributed to node/src/utils.rs line 66; whether wrapper b '
 'is itself defined in utils.rs or inlines a utils.rs helper '
 'is not distinguishable from the binary and is not claimed. '
 'The kind argument of cfg_ctor is the byte cfg_ctor stores at '
 'cfg +0xe4; what the builder does with the two cfg bytes is '
 'the subject of PR #2955 and is a boundary here, as are the '
 'builder body itself and the cfg drop 0x5cf1af0 (PR #2950 '
 'boundaries). For wrapper a, the once consultation on the '
 'kind-1 arm is pinned at the byte level (state dword '
 '0x64f01d8, cell 0x64f01c0, closure statics 0x63fe250 / '
 '0x63fe278, call_once_force through slot 0x64df9f0); whether '
 'the guarded global caches the built runtime or serves '
 'another once-only purpose is not resolved by the traced '
 'window and is stated as a boundary. The dispatcher 0x15b8fd0 '
 'is pinned by span, its slot call site, and its static table '
 'cell only; the subsystem that registers the adapter-a '
 'callback, the list it walks, and the callers of the '
 'dispatcher are above the traced window. The 0x3d0- and '
 '0x2c40-byte argument structs are pinned by size and by the '
 'adapters that build them; their field layouts are not '
 'traced. The lang_start body 0x5c99970 is identified by its '
 'position in the compiler main shim (the shim passes it the '
 'user-main trait object, argc, argv and a zero sigpipe '
 'argument); no symbol name is claimed for it beyond that '
 'role.')


def read(data, va, n):
    matches = [s for s in sections(data) if s['type'] != 8
               and s['address'] <= va and va + n <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('expected one file-backed mapping')
    s = matches[0]
    o = s['offset'] + va - s['address']
    return o, bytes(data[o:o + n])


def require(condition, message):
    if not condition:
        raise ValueError(message)


def relocations(data):
    sec = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    by_offset = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, off)
        by_offset.setdefault(r_offset, []).append(
         (r_info & 0xffffffff, r_info >> 32, r_addend))
    return by_offset


def dynsym_name(data, index):
    sym = next(s for s in sections(data) if s['name'] == '.dynsym')
    strs = next(s for s in sections(data) if s['name'] == '.dynstr')
    noff = struct.unpack_from('<I', data,
                              sym['offset'] + index * 24)[0]
    o = strs['offset'] + noff
    return data[o:data.index(b'\0', o)].decode()


def relative_at(by_offset, va):
    """Value a .data.rel.ro / .got cell holds after RELATIVE fixups."""
    entries = by_offset.get(va, [])
    rel = [a for t, _, a in entries if t == 8]
    if rel:
        return rel[0]
    return None


def qword(data, by_offset, va):
    v = relative_at(by_offset, va)
    if v is not None:
        return v
    return struct.unpack('<Q', read(data, va, 8)[1])[0]


def pin(body, rel, expected, message):
    require(body[rel:rel + len(expected)] == expected,
            f'{message} changed')


def call_target(body, rel, base):
    return base + rel + 5 + struct.unpack_from('<i', body, rel + 1)[0]


def branch_target(body, rel, base, size):
    return (base + rel + size
            + struct.unpack_from('<i', body, rel + size - 4)[0])


def slot_at(body, rel, base):
    """Target slot of a call QWORD PTR [rip+disp32] at rel."""
    return base + rel + 6 + struct.unpack_from('<i', body, rel + 2)[0]


def lea_target(body, rel, base, size=7):
    return base + rel + size + struct.unpack_from('<i', body, rel + 3)[0]


def body_of(data, role):
    a, b, _ = OWNERS[role]
    return a, read(data, a, b - a)[1]


def run_pins(data, role):
    base, body = body_of(data, role)
    for va, hexs, message in PINS.get(role, []):
        pin(body, va - base, bytes.fromhex(hexs), f'{role} {message}')
    return base, body


def decode_location(data, by_offset, va):
    fptr = qword(data, by_offset, va)
    flen = qword(data, by_offset, va + 8)
    line, col = struct.unpack('<II', read(data, va + 0x10, 8)[1])
    name = read(data, fptr, flen)[1].decode()
    return {'struct': hex(va), 'file': name, 'line': line, 'col': col}


def location_records(data, by_offset, table):
    out = []
    for va, (name, line, col) in sorted(table.items()):
        got = decode_location(data, by_offset, va)
        require((got['file'], got['line'], got['col']) == (name, line, col),
                f'location {va:#x} changed')
        out.append(got)
    return out


def slot_records(data, by_offset):
    out = []
    for slot, (kind, want) in sorted(SLOTS.items()):
        entries = by_offset.get(slot, [])
        if kind == 'relative':
            rel = [a for t, _, a in entries if t == 8]
            require(len(rel) == 1 and rel[0] == want,
                    f'slot {slot:#x} relocation changed')
            out.append({'slot': hex(slot), 'kind': 'R_X86_64_RELATIVE',
                        'target': hex(want)})
        else:
            gd = [(s, a) for t, s, a in entries if t == 6]
            require(len(gd) == 1, f'slot {slot:#x} glob_dat changed')
            name = dynsym_name(data, gd[0][0])
            require(name == want, f'slot {slot:#x} symbol changed')
            out.append({'slot': hex(slot), 'kind': 'R_X86_64_GLOB_DAT',
                        'symbol': name})
    return out


def string_records(data):
    out = []
    for va, (want, role) in sorted(STRINGS.items()):
        got = read(data, va, len(want))[1]
        require(got == want, f'string at {va:#x} changed')
        out.append({'address': hex(va), 'length': len(want),
                    'role': role, 'text': want.decode()})
    # The two nested-runtime message copies must be byte-identical.
    a = STRINGS[0x469d92][0]
    require(read(data, 0x60692e, len(a))[1] == a,
            'nested-runtime message copies differ')
    return out


def wrapper_a_semantics(data):
    role = 'wrapper_a'
    base, body = run_pins(data, role)
    rel = lambda va: va - base
    require(branch_target(body, rel(0x15d6fe6), base, 6) == 0x15d7099,
            'wrapper_a kind-0 branch target changed')
    require(branch_target(body, rel(0x15d6ff4), base, 6) == 0x15d71b0,
            'wrapper_a once branch target changed')
    require(call_target(body, rel(0x15d7007), base) == CFG_CTOR,
            'wrapper_a kind-1 cfg_ctor target changed')
    require(call_target(body, rel(0x15d7034), base) == CFG_DROP,
            'wrapper_a cfg drop target changed')
    require(call_target(body, rel(0x15d70a3), base) == CFG_CTOR,
            'wrapper_a kind-0 cfg_ctor target changed')
    for va in (0x15d7026, 0x15d70c2):
        require(slot_at(body, rel(va), base) == BUILDER_SLOT,
                'wrapper_a builder slot changed')
    require(slot_at(body, rel(0x15d7140), base) == 0x64df508,
            'wrapper_a memcpy slot changed')
    require(slot_at(body, rel(0x15d71f1), base) == 0x64df9f0,
            'wrapper_a call_once slot changed')
    require(branch_target(body, rel(0x15d71f7), base, 5) == 0x15d6ffa,
            'wrapper_a once fallthrough target changed')
    require(branch_target(body, rel(0x15d7041), base, 6) == 0x15d7239,
            'wrapper_a kind-1 expect branch changed')
    require(branch_target(body, rel(0x15d70d0), base, 6) == 0x15d71fc,
            'wrapper_a kind-0 expect branch changed')
    for va in (0x15d722e, 0x15d726b):
        require(slot_at(body, rel(va), base) == 0x64df6a0,
                'wrapper_a expect thunk slot changed')
    for va in (0x15d8044, 0x15d805f):
        require(slot_at(body, rel(va), base) == 0x64df6b8,
                'wrapper_a panic entry slot changed')
    require(lea_target(body, rel(0x15d71b0), base) == 0x64f01c0,
            'wrapper_a once cell changed')
    require(lea_target(body, rel(0x15d71cf), base) == 0x64f01d8,
            'wrapper_a once state changed')
    return {
     'identity': 'a runtime-runner function of the base crate, '
                 'source file base/src/lu.rs (its own builder-error '
                 'Locations are lu.rs:55:40 and lu.rs:58:76 and its '
                 'nested-runtime panic Location is lu.rs:60:13)',
     'arguments': 'edi = arm flag (stored nowhere; tested at '
                  'entry), rsi = pointer to a 0x3d0-byte argument '
                  'struct that the body memcpy\'s into its frame '
                  'after the build',
     'build_sites': [
      {'arm': 'edi != 0', 'cfg_ctor_call': '0x15d7007',
       'cfg_ctor_kind_argument': 1,
       'cfg_u16_store': '0x15d700c (0x0101 at cfg +0xe5)',
       'builder_call': '0x15d7026 through slot 0x64e1760',
       'cfg_drop_call': '0x15d7034 -> 0x5cf1af0',
       'tag_compare': '0x15d7039 (dword at out +0x0 vs 2)',
       'error_branch': '0x15d7041 -> 0x15d7239'},
      {'arm': 'edi == 0', 'cfg_ctor_call': '0x15d70a3',
       'cfg_ctor_kind_argument': 0,
       'cfg_u16_store': '0x15d70a8 (0x0101 at cfg +0xe5)',
       'builder_call': '0x15d70c2 through slot 0x64e1760',
       'post_copy_call': '0x15d712b -> 0x15de690 after the '
                         'runtime object is copied out (target '
                         'not further traced)',
       'tag_compare': '0x15d70c8 (dword at out +0x0 vs 2)',
       'error_branch': '0x15d70d0 -> 0x15d71fc'}],
     'once_global': {
      'state_dword': '0x64f01d8 (loaded at 0x15d6fec; the kind-1 '
                     'arm consults it before building)',
      'cell': '0x64f01c0 (its address is loaded at 0x15d71b0 '
              'into the call_once closure environment)',
      'closure_statics': ['0x63fe250', '0x63fe278'],
      'call': '0x15d71f1 through slot 0x64df9f0 -> '
              'call_once_force 0x5c87d50, entered only when the '
              'state dword is nonzero; control then falls into '
              'the kind-1 build at 0x15d6ffa'},
     'error_sites': [
      {'arm': 'edi != 0', 'call': '0x15d726b',
       'message': '0x469c40 "tokio_run" (length 9)',
       'error_vtable': '0x64015d0',
       'location': 'base/src/lu.rs:55:40'},
      {'arm': 'edi == 0', 'call': '0x15d722e',
       'message': '0x469c40 "tokio_run" (length 9)',
       'error_vtable': '0x64015d0',
       'location': 'base/src/lu.rs:58:76'}],
     'argument_copy': 'memcpy of 0x3d0 bytes from rsi to '
                      'rsp+0x8e8 through slot 0x64df508 '
                      '(memcpy@GLIBC) at 0x15d7140, after the '
                      '0x70-byte runtime object is copied to '
                      'rsp+0x70',
     'nested_runtime_panics': [
      {'call': '0x15d8044', 'message': '0x469d92 (387 bytes)',
       'location': 'multi_thread/mod.rs:91:9 (inlined scheduler)'},
      {'call': '0x15d805f', 'message': '0x469d92 (387 bytes)',
       'location': 'base/src/lu.rs:60:13 (the body\'s own '
                   'block_on call site)'}]}


def wrapper_b_semantics(data):
    role = 'wrapper_b'
    base, body = run_pins(data, role)
    rel = lambda va: va - base
    require(call_target(body, rel(0x2ae16d1), base) == CFG_CTOR,
            'wrapper_b cfg_ctor target changed')
    require(slot_at(body, rel(0x2ae16f2), base) == BUILDER_SLOT,
            'wrapper_b builder slot changed')
    require(branch_target(body, rel(0x2ae1700), base, 6) == 0x2ae17d3,
            'wrapper_b unwrap branch changed')
    require(slot_at(body, rel(0x2ae1768), base) == 0x64df508,
            'wrapper_b memcpy slot changed')
    require(slot_at(body, rel(0x2ae1805), base) == 0x64df6a0,
            'wrapper_b unwrap thunk slot changed')
    for va in (0x2ae21c9, 0x2ae21e7):
        require(slot_at(body, rel(va), base) == 0x64df6b8,
                'wrapper_b panic entry slot changed')
    return {
     'identity': 'the node binary\'s principal entry function: '
                 'the sole callee of the user main 0x2cd8370, '
                 'which the compiler main shim 0x2cef8f0 registers '
                 'with lang_start and _start passes to '
                 '__libc_start_main; its runtime build and '
                 'block_on call site are attributed to '
                 'node/src/utils.rs:66 (unwrap at column 70, '
                 'nested-runtime panic at column 79)',
     'arguments': 'rdi = pointer to a 0x2c40-byte struct the '
                  'user main zero-builds; the body memcpy\'s it '
                  'into its frame after the build',
     'build_site': {'cfg_ctor_call': '0x2ae16d1',
                    'cfg_ctor_kind_argument': 1,
                    'cfg_u16_store': '0x2ae16d6 (0x0101 at cfg +0xe5)',
                    'builder_call': '0x2ae16f2 through slot 0x64e1760',
                    'tag_compare': '0x2ae16f8 (dword at out +0x0 vs 2)',
                    'error_branch': '0x2ae1700 -> 0x2ae17d3'},
     'error_site': {'call': '0x2ae1805',
                    'message': '0x605542 "called `Result::unwrap()` '
                               'on an `Err` value" (length 43)',
                    'error_vtable': '0x64474a8',
                    'location': 'node/src/utils.rs:66:70'},
     'argument_copy': 'memcpy of 0x2c40 bytes from rdi to '
                      'rsp+0x86e8 through slot 0x64df508 '
                      '(memcpy@GLIBC) at 0x2ae1768, after the '
                      '0x70-byte runtime object is copied to '
                      'rsp+0xe0',
     'nested_runtime_panics': [
      {'call': '0x2ae21c9', 'message': '0x60692e (387 bytes)',
       'location': 'multi_thread/mod.rs:91:9 (inlined scheduler)'},
      {'call': '0x2ae21e7', 'message': '0x60692e (387 bytes)',
       'location': 'node/src/utils.rs:66:79 (the body\'s own '
                   'block_on call site)'}]}


def chain_semantics(data):
    run_pins(data, 'adapter_a')
    run_pins(data, 'adapter_b')
    run_pins(data, 'main_shim')
    run_pins(data, 'entry_start')
    run_pins(data, 'dispatcher_a')
    run_pins(data, 'cfg_ctor')
    a_base, a_body = body_of(data, 'adapter_a')
    require(call_target(a_body, 0x155fa46 - a_base, a_base)
            == OWNERS['wrapper_a'][0], 'adapter_a call target changed')
    b_base, b_body = body_of(data, 'adapter_b')
    require(call_target(b_body, 0x2cd83a2 - b_base, b_base)
            == OWNERS['wrapper_b'][0], 'adapter_b call target changed')
    s_base, s_body = body_of(data, 'main_shim')
    require(lea_target(s_body, 0x2cef8f7 - s_base, s_base)
            == OWNERS['adapter_b'][0], 'main shim user main changed')
    require(slot_at(s_body, 0x2cef90f - s_base, s_base) == 0x64e6c30,
            'main shim lang_start slot changed')
    e_base, e_body = body_of(data, 'entry_start')
    require(lea_target(e_body, 0x1419318 - e_base, e_base)
            == OWNERS['main_shim'][0], '_start main pointer changed')
    require(slot_at(e_body, 0x141931f - e_base, e_base) == 0x64df458,
            '_start libc_start_main slot changed')
    d_base, d_body = body_of(data, 'dispatcher_a')
    require(slot_at(d_body, 0x15b907d - d_base, d_base) == 0x64e1190,
            'dispatcher adapter slot changed')
    return {
     'wrapper_a_reach': 'static .data.rel.ro table cell '
                        '0x6400548 -> dispatcher_a 0x15b8fd0; '
                        'its only call through slot 0x64e1190 '
                        '(site 0x15b907d) invokes adapter_a '
                        '0x155fa10, which copies 0x30 bytes from '
                        'its own argument, zeroes the byte at '
                        '+0x3c8, and calls wrapper_a with '
                        'edi = 0 (site 0x155fa46) -- the only '
                        'direct caller, so only the kind-0 arm '
                        'is exercised as linked',
     'wrapper_b_reach': '_start 0x1419300 -> __libc_start_main '
                        '(main = main_shim 0x2cef8f0) -> '
                        'lang_start 0x5c99970 (user main = '
                        'adapter_b 0x2cd8370, vtable 0x6440b48) '
                        '-> adapter_b zero-builds the 0x2c40-byte '
                        'struct (zero byte at +0x21a) and calls '
                        'wrapper_b at 0x2cd83a2 -- its only '
                        'direct caller'}


def text_census(data):
    """One combined pass over .text: rel32 callers, rip-relative
    disp32 field starts, and GOT-slot call sites for the census
    targets and the builder slot."""
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    tb = data[text['offset']:text['offset'] + text['size']]
    tbase = text['address']
    _, rows, _ = fde_extents(data)
    rows.sort(key=lambda r: r['start'])
    starts = [r['start'] for r in rows]
    import bisect

    def containing(va):
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and rows[i]['start'] <= va < rows[i]['end']:
            return hex(rows[i]['start'])
        return None

    def sec_name(off):
        for s in secs:
            if s['type'] != 8 and s['offset'] <= off < s['offset'] + s['size']:
                return s['name']
        return None

    targets = set(CENSUS_TARGETS.values())
    rel32 = {t: [] for t in targets}
    disp32 = {t: [] for t in targets}
    unpack = struct.unpack_from
    slot_hits = []
    n = len(tb)
    for i in range(n - 6):
        b = tb[i]
        if b == 0xe8:
            t = tbase + i + 5 + unpack('<i', tb, i + 1)[0]
            if t in targets:
                rel32[t].append({'site': hex(tbase + i),
                                 'in_body': containing(tbase + i)})
        elif b == 0xff and tb[i + 1] in (0x15, 0x25):
            slot = tbase + i + 6 + unpack('<i', tb, i + 2)[0]
            if slot == BUILDER_SLOT:
                slot_hits.append(hex(tbase + i))
        # A disp32 field starting at i references R(i); check
        # membership for every offset (fields are unaligned).
        r = tbase + i + 4 + unpack('<i', tb, i)[0]
        if r in targets:
            disp32[r].append(hex(tbase + i))
    out = {}
    for role, target in sorted(CENSUS_TARGETS.items()):
        pat = struct.pack('<Q', target)
        imm64 = []
        pos = 0
        while True:
            j = data.find(pat, pos)
            if j < 0:
                break
            imm64.append({'file_offset': hex(j),
                          'section': sec_name(j)})
            pos = j + 1
        out[role] = {'target': hex(target),
                     'rel32_callers': rel32[target],
                     'imm64_references': imm64,
                     'disp32_field_starts': disp32[target]}
    require(slot_hits == ['0x15d7026', '0x15d70c2', '0x2ae16f2'],
            'builder slot call census changed')
    slot_census = {'slot': hex(BUILDER_SLOT), 'call_sites': slot_hits,
                   'note': 'byte-pattern census over .text; the '
                           'three sites are instruction starts in '
                           'the retained objdump exports of '
                           'wrapper_a / wrapper_b'}
    return out, slot_census


def analyze(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('pinned node115 distribution changed')
    by_offset = relocations(data)
    owners = []
    _, rows, _ = fde_extents(data)
    by_start = {r['start']: r for r in rows}
    for role, (a, b, want) in sorted(OWNERS.items()):
        row = by_start.get(a)
        require(row is not None and row['end'] == b,
                f'{role} FDE extent changed')
        digest = hashlib.sha256(read(data, a, b - a)[1]).hexdigest()
        require(digest == want, f'{role} body digest changed')
        owners.append({'role': role, 'start': hex(a), 'end': hex(b),
                       'bytes': b - a, 'sha256': digest})
    slots = slot_records(data, by_offset)
    strings = string_records(data)
    locs_a = location_records(data, by_offset, LOCATIONS_A)
    locs_b = location_records(data, by_offset, LOCATIONS_B)
    wa = wrapper_a_semantics(data)
    wb = wrapper_b_semantics(data)
    chain = chain_semantics(data)
    census, slot_census = text_census(data)
    # Census expectations: each wrapper has exactly its adapter
    # as direct caller and no other reference form.
    require(census['wrapper_a']['rel32_callers'] == [
     {'site': '0x155fa46', 'in_body': '0x155fa10'}],
     'wrapper_a caller census changed')
    require(census['wrapper_a']['imm64_references'] == []
            and census['wrapper_a']['disp32_field_starts']
            == ['0x155fa47'],
            'wrapper_a stray references changed')
    require(census['wrapper_b']['rel32_callers'] == [
     {'site': '0x2cd83a2', 'in_body': '0x2cd8370'}],
     'wrapper_b caller census changed')
    require(census['wrapper_b']['imm64_references'] == []
            and census['wrapper_b']['disp32_field_starts']
            == ['0x2cd83a3'],
            'wrapper_b stray references changed')
    require(census['adapter_a']['rel32_callers'] == []
            and census['adapter_a']['disp32_field_starts'] == []
            and len(census['adapter_a']['imm64_references']) == 1
            and census['adapter_a']['imm64_references'][0]['section']
            == '.rela.dyn', 'adapter_a reference census changed')
    require(census['adapter_b']['rel32_callers'] == []
            and census['adapter_b']['imm64_references'] == []
            and census['adapter_b']['disp32_field_starts']
            == ['0x2055ec8', '0x2cef8fa'],
            'adapter_b reference census changed')
    # The 0x2055ec8 window is not an instruction start: it lies
    # inside the mov %r12,0xc8(%rsp) at 0x2055ec6.
    require(read(data, 0x2055ec6, 8)[1]
            == bytes.fromhex('4c89a424c8000000'),
            'adapter_b false-positive window changed')
    require(census['main_shim']['rel32_callers'] == []
            and census['main_shim']['imm64_references'] == []
            and census['main_shim']['disp32_field_starts']
            == ['0x141931b'], 'main shim reference census changed')
    require(census['dispatcher_a']['rel32_callers'] == []
            and census['dispatcher_a']['disp32_field_starts'] == []
            and len(census['dispatcher_a']['imm64_references']) == 1
            and census['dispatcher_a']['imm64_references'][0]['section']
            == '.rela.dyn', 'dispatcher reference census changed')
    return {
     'artifact': 'artifacts/node/115/hl-node',
     'artifact_sha256': SHA,
     'artifact_size': SIZE,
     'question': 'PR #2950 pinned the driver builder 0x5cf9600 '
                 'and showed its only callers are two bodies '
                 'reached through GOT slot 0x64e1760, both '
                 'overwriting the cfg u16 at +0xe5 with 0x0101. '
                 'What are those two bodies at source level, and '
                 'how do they relate?',
     'answer': 'wrapper_a 0x15d6fd0 is a base/src/lu.rs '
               'runtime-runner: it builds a runtime with the '
               'builder (cfg kind from its edi flag, kind-1 arm '
               'once-guarded by a process global) and expect()s '
               'failures with the message "tokio_run", then '
               'enters the runtime in place; as linked it is '
               'reached only as a registered callback with the '
               'flag 0. wrapper_b 0x2ae1690 is the node binary\'s '
               'principal entry function -- the sole callee of '
               'the user main -- building one runtime (kind 1) '
               'with a plain unwrap attributed to '
               'node/src/utils.rs:66 and entering it in place. '
               'Same builder idiom, different crates, arguments, '
               'failure behaviour and call-graph positions; '
               'neither calls the other.',
     'owners': owners,
     'slots': slots,
     'strings': strings,
     'locations': {'wrapper_a': locs_a, 'wrapper_b': locs_b},
     'wrapper_a': wa,
     'wrapper_b': wb,
     'reach_chains': chain,
     'builder_slot_census': slot_census,
     'reference_census': census,
     'census_notes': {
      'wrapper_disp32': 'each wrapper\'s single disp32 window '
                        'is the displacement field of its sole '
                        'rel32 call (0x155fa47 inside adapter_a, '
                        '0x2cd83a3 inside adapter_b), not a '
                        'separate reference',
      'adapter_b_disp32': 'the window at 0x2055ec8 lies inside '
                          'the instruction at 0x2055ec6 '
                          '(mov %r12,0xc8(%rsp), bytes '
                          '4c89a424c8000000) and is not an '
                          'instruction start; the only '
                          'instruction-level reference to '
                          'adapter_b is the main shim lea whose '
                          'field starts at 0x2cef8fa'},
     'boundaries': {
      'cfg_bytes': 'what the builder does with the cfg kind '
                   'byte at +0xe4 and the 0x0101 pair at +0xe5 '
                   'is PR #2955 territory; this packet pins only '
                   'who writes them',
      'builder_and_cfg': 'the builder body 0x5cf9600, cfg_ctor '
                         '0x5cf93f0 beyond its kind store, and '
                         'the cfg drop bodies are PR #2950 '
                         'boundaries, cited by span pins',
      'once_semantics': 'the kind-1 arm\'s once consultation is '
                        'pinned byte-wise; whether the guarded '
                        'global caches the runtime is not '
                        'resolved (see limits)',
      'dispatcher_context': 'who registers the adapter-a '
                            'callback in the static table at '
                            '0x6400548, what list the dispatcher '
                            'walks, and who calls the dispatcher '
                            'are above the traced window',
      'argument_layouts': 'the 0x3d0- and 0x2c40-byte argument '
                          'structs are pinned by size and '
                          'construction only',
      'wrapper_b_definition_site': 'wrapper b may itself be '
                                   'defined in utils.rs or '
                                   'inline a utils.rs helper '
                                   'into the entry body; the '
                                   'binary does not distinguish '
                                   'the two'},
     'captured_code_executed': False,
     'limits': LIMITS}


def exports(data):
    out = {}
    with tempfile.TemporaryDirectory() as td:
        snapshot = Path(td) / 'hl-node'
        snapshot.write_bytes(data)
        for role, (a, b, _) in OWNERS.items():
            asm = subprocess.check_output(
             ['objdump', '-d', '-M', 'intel', '--insn-width=16',
              f'--start-address={a:#x}', f'--stop-address={b:#x}',
              str(snapshot)], text=True)
            ins = decode_export(asm, a, b, read(data, a, b - a)[1])
            for va in PIN_STARTS.get(role, []):
                require(va in ins,
                        f'{role} instruction start missing')
            out[role] = asm.replace(str(snapshot),
                                    '<authenticated-node115>')
    return out


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('pinned node115 distribution changed')
    payload = analyze(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        snapshot = Path(td) / 'hl-node'
        snapshot.write_bytes(data)
        native = subprocess.check_output(
         ['readelf', '-wf', str(snapshot)], text=True)
        wanted = []
        for a, b, _ in OWNERS.values():
            needle = f'pc={a:016x}..{b:016x}'
            wanted += [ln for ln in native.splitlines()
                       if needle in ln]
        require(len(wanted) == len(OWNERS),
                'owner frame lines missing')
        (output / 'frames.txt').write_text('\n'.join(wanted) + '\n')
        exps = exports(data)
        for role, asm in exps.items():
            (output / f'{role}.objdump.txt').write_bytes(
             asm.encode('utf-8'))
    (output / 'records.json').write_text(
     json.dumps(payload, indent=1, sort_keys=True) + '\n')
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('output', nargs='?', default=str(PACKET))
    args = parser.parse_args()
    payload = generate(TARGET, Path(args.output))
    for owner in payload['owners']:
        print(owner['role'], owner['start'], owner['end'],
              owner['bytes'], owner['sha256'])


if __name__ == '__main__':
    main()
