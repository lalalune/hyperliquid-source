#!/usr/bin/env python3
"""Pin every direct caller of the 63 consumers of the X5 GOT slot.

The X5 caller-slot packet (RE-005-node115-x5-caller-slot-consumers,
PR #3235) pinned the 63 FDE bodies that load GOT slot 0x64e7718 --
the only static holder of the X5 schedule-caller body 0x5cf5100 --
and recorded, for each consumer, only the *count* of its direct
rel32 callers.  This packet answers the question it left open: who
calls the consumers?

* a candidate scan over every executable section enumerates every
  e8/e9 byte position whose rel32 lands on a consumer start; each
  candidate is verified by decoding the instruction at the site,
  and the verified set is cross-checked against a linear disassembly
  sweep of every containing FDE body (the two sets are identical);
* every verified site is a `call rel32` -- there are 67 sites in 65
  caller bodies, no direct jumps, and no site outside an FDE body;
* the other reachability forms are excluded by independent passes:
  no relocation in .rela.dyn or .rela.plt has a consumer start as
  its addend, no stored 8-byte copy of a consumer start exists
  outside the relocation sections' own serialised entries, no
  instruction materialises a consumer start as an immediate, no
  rip-relative reference resolves to a consumer start, and no
  .dynsym entry carries a consumer start as its value (so there is
  no PLT path either);
* per site, the surrounding instruction pattern is pinned from the
  caller body's own instruction stream, which separates the sites
  into a 36-site flag-pair family (the callers of the 36 uniform
  consumers), a 28-site static-second-argument family, and 3
  residual sites;
* one level up is recorded as counts only: each caller body's raw
  direct rel32 call/jump occurrence count in .text and its
  .rela.dyn addend count.

The consumer set below is the census pinned by PR #3235; analyze()
re-derives it from the binary (verified rip-relative references to
the slot, grouped by FDE body) and fails if the derived set differs
from the pinned set in any start, end, or body hash.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
WORK_ITEM = 'RE-005-node115-x5-consumer-callers'
PACKET_DIR = ROOT / 'research/work-items' / WORK_ITEM

SLOT = 0x64e7718
SOURCE_WORK_ITEM = 'RE-005-node115-x5-caller-slot-consumers'
SOURCE_PR = 3235

# (start, end, sha256) of the 63 consumer bodies pinned by PR #3235.
CONSUMERS_PINNED = [
    (0x2b3a8c0, 0x2b3ab9c, 'ac89a78b202baec8ca95aeb2de595bab562f375b1efdf26dd4a9e3d44cd3c5c8'),
    (0x2b3aba0, 0x2b3ae7c, 'b33592b3e2458d7cc2201a464dbb439e5665a536dfedb6fed2a208c3dfa85245'),
    (0x2b3ae80, 0x2b3b12d, '2a8c82767fddcc23fe32cb3df8bfe774762d97098f9b2f807174985ebc8392d9'),
    (0x2b3b130, 0x2b3b3dd, 'd5c86b4f8a3649926a32e09b99261b2e24168ae7ab969cffe92624accd7c8bec'),
    (0x2b3b3e0, 0x2b3b6c7, 'f9e10f7430e68a4156b3536775859ea634a13ea9b8d6629f41f0ca4f9e8fba32'),
    (0x2b3b6d0, 0x2b3b97d, 'e3e32859f6f77902c884288c7852c90dc0b0f20e2970edea1bc84f0dc1459096'),
    (0x2b3b980, 0x2b3bc2d, 'edcf48a1e31b0380b53c8cf5d1c8c5e2e050c84317a0835d7f96c3593510c32b'),
    (0x2b3bc30, 0x2b3bedd, '2ff361bb17e08c0f5c0a5df63ebdc818175a71646f76356360b6121fcf597787'),
    (0x2b3bee0, 0x2b3c18d, '9b964c55b1507ea5b7e18dbc4241fd5574a3faf79430dba45ad4c3f4258d615e'),
    (0x2b3c190, 0x2b3c46c, '1cb345ff0390109743c3402ba09ed4a20876a3afa2a9344663c1c79027e5a61c'),
    (0x2b3c470, 0x2b3c71d, '14bc6986e515053845d43f6c808c6420981c74dd1fcd94c7f04005327e1d1ba8'),
    (0x2b3c720, 0x2b3c9cd, '52c13564cf7dab94271d7833da1f8ab9bed87c43ca0936fa437146b22c38d294'),
    (0x2b3c9d0, 0x2b3ccb6, '7cd872d3ced0fadd2a0a51bf5016c058dee1ca7e533463f87c66ba3d43384a04'),
    (0x2b3ccc0, 0x2b3cf95, '0fe33c0c353d1521c45a1207ececec04f91a2ed5f0dbb9d68b6d7f12309e77d0'),
    (0x2b3cfa0, 0x2b3d24d, 'de00fe49093b1c34fe7b4486a9fa8bd4ee5fa5478dcb6b7b04073e59944c16f3'),
    (0x2b3d250, 0x2b3d537, 'f5afd45d6f8c1f25aeb5ba26b6b61176ed41d962aee2ec65717038b2df8e2669'),
    (0x2b3d540, 0x2b3d7ed, '2bcb8e8225ad5507616929aa0213d6c412b944fb22c5181992b24773dc32f948'),
    (0x2b3d7f0, 0x2b3da9d, 'bf11e5383edac4025ed47facecb6f02d233c67f7f7682fcfce4a0952d6b7cec3'),
    (0x2b3daa0, 0x2b3dda3, '0fa94c11b627d246b87730a9c6ad2b82194c3298f6b9e05ceaff79fa20255692'),
    (0x2b3ddb0, 0x2b3e09b, 'e9a2c327d97ee1c5d8a33a83dc99524f6624a9f4ee5c65d3905ddb4120ae813a'),
    (0x2b3e0a0, 0x2b3e34d, 'e77d5ae028ae4126d96644de5d8296eccb36c831618227b6d442c88e0af38542'),
    (0x2b3e350, 0x2b3e5fd, 'ed0beb71ea3220e9d02103439fe3c94f5e88f4a15ac1e64252b69ce0dfbf52e5'),
    (0x2b3e600, 0x2b3e8ad, 'd0ab9743f240979400018ef4dc962ceb5debacb7226551abc9a5fb36cdac2706'),
    (0x2e8e7b0, 0x2e8ea97, 'ebd0e1fdaaa971044d8f91f114edef8c7d5594f17e49561e1cd51e8a4b2291a6'),
    (0x37136d0, 0x371397d, 'bb59befb2094ec7dc2104e0c9aba8934770a2b1f3fb43e1f2fd50bf965d5ac18'),
    (0x5a79730, 0x5a7b155, 'aae3a54b346b8e4dea39a0e991cfd7576a75c7798fb07311c9d3cd04acd50805'),
    (0x5a9c620, 0x5a9cab1, 'f6a43bb08a5906fa5b37a120384220b222a79b7722d168f1fb9b3dd2ac5a846c'),
    (0x5a9cac0, 0x5a9cf51, '92d8f82ef0de467df872de5a6b517648b95481a18490b047047d619c34dccb24'),
    (0x5a9cf60, 0x5a9d3f1, '04a2ae79e7358393f518ec27344f8f6ca12b99b8655c39ee53139d089877ff55'),
    (0x5a9d400, 0x5a9d891, '3e5dcaad7bd2edf6672ae4e8010f420064cad9ab2a3a7278b453ae7e764ba6bc'),
    (0x5a9d8a0, 0x5a9dd31, '3482a769cee1ab90b3b85cae367d9d31fe67b5eebb881fa40ba1e22d6cd996e8'),
    (0x5a9dd40, 0x5a9e1d1, '25c83a48a5bb902d5722a7c33c23b96a6ebefb9af1498fbcc7cc2e3cccf9037b'),
    (0x5a9e1e0, 0x5a9e671, '37bf9c4f16772dda8c020d57f2d3c03d6ebbd7e8cdf8d85612b56612f956dbf4'),
    (0x5a9e680, 0x5a9eb11, 'abd30102d343b80b649ba16743b520fa4049b2cdc9102321adeb36a54fc1119a'),
    (0x5a9eb20, 0x5a9efb1, 'b3a38873a2526145b150c77923e92d2a43c0c9551940d1e296849d63e76c6858'),
    (0x5a9efc0, 0x5a9f451, '870a17ca8ed2a69bac224299ebcf8baa2d4a41d782080dd40e6d2e2db1cfcf20'),
    (0x5a9f460, 0x5a9f8f1, '978592544d3d83aafe41fa87a15ce512ace5169f412111f3cc1599781ec0428f'),
    (0x5a9f900, 0x5a9fd91, 'ce531262fe852be2a39a6d5696c751eaa618fa38deec84ff07fa6d8b82aea815'),
    (0x5a9fda0, 0x5aa0231, '2122b8a4c8c24c22f74da5069ec9e21dc3afa90549af489247cd9cf2bc9e4ecc'),
    (0x5aa0240, 0x5aa06d1, '6abaaa25e977fe58f0e09ea46bd60728b3ce3c1090e5602bf079ae253d9a459d'),
    (0x5aa06e0, 0x5aa0b71, '2eab6fa53fb69060349a402c32600a4a9399dcd5fc3f626a157b685a40336d22'),
    (0x5aa0b80, 0x5aa1011, 'a1e734fda0860eada15da0bb1fe9b20a2acb01c97e8de030cb7ffe9a564b80fc'),
    (0x5aa1020, 0x5aa14b1, '52992052eec14467c75d958517947e8f6795b3c4dfc7d58213e54a62cac88a06'),
    (0x5aa14c0, 0x5aa1951, '34ae57a68b7c9f6e67ab2a670e42addbbba4c620a866152099f64294115e5961'),
    (0x5aa1960, 0x5aa1df1, '855da2913135b5e052c661b10ea9aa03f17bdb9a2dd4c61acff952fff2ce3b61'),
    (0x5aa1e00, 0x5aa2291, 'd9f42e9b0d37f4d9591f13ba32867b9754d6d685b71b8c0f4075f95d859b92a1'),
    (0x5aa22a0, 0x5aa2731, '2334b0611820133c9c4eda407e42e6bcfa3b8d2102127d9fec38e30fb773614f'),
    (0x5aa2740, 0x5aa2bd1, '88fef6dd806c91ae3c4d4020b4a05d53b3cfd7172aba92e717b3fc7f264f7fc5'),
    (0x5aa2be0, 0x5aa3071, '69a30ec38a85a771db2b12eba63f1bb4a57c7ad54604374c2214b31b01b81395'),
    (0x5aa3080, 0x5aa3511, '0fba4bac4a6b6ea33720292f18c7fd1a22a2a1f100c17b967a8699223ada9c80'),
    (0x5aa3520, 0x5aa39b1, 'cebc54a00fd9948f950c0262060490403f7e07b3e03ccd8458f8edb92db8e5ec'),
    (0x5aa39c0, 0x5aa3e51, 'c2c3833ba084b16fbe1a9df5bdc23f49912ec702e407063529c45a793a8418cf'),
    (0x5aa3e60, 0x5aa42f1, 'aeeef057fab0f941dda9559df4bef3b2a4949bf03e5d2f7b54ecc3cccc6c8047'),
    (0x5aa4300, 0x5aa4791, '5e638d8650d86afea177f136a17b6963f38a1c94f53306cd21af0abef4112c84'),
    (0x5aa47a0, 0x5aa4c31, '60b0a2730cebe99e44907f0e082837a027cbd7e8ecc851f9d40ed8eceaae808c'),
    (0x5aa4c40, 0x5aa50d1, '9f24d15d117abd7285b0fb2c821f855510dc11f0a3700a72193a62505fd07849'),
    (0x5aa50e0, 0x5aa5571, '46b895817cb99f761afd78b01d6277aac83af4e1fa198311c9573f2a30061cb6'),
    (0x5aa5580, 0x5aa5a11, '823119dffbca8df7292a4da718b72effc3e7d132406d9cfa27da16270226341a'),
    (0x5aa5a20, 0x5aa5eb1, '6346aa898bfb82a533541d4c922169188f902f4a0858f7efdfa3e1eac8228227'),
    (0x5aa5ec0, 0x5aa6351, '73d419340e134ef3419fa6c30dcb0a34bbda0a37673b636834d33df7b31dc5c8'),
    (0x5aa6360, 0x5aa67f1, '71045afcd97b2340adc546850a9e8a7a10e92f43a5182cbaa9f32a7b969634b8'),
    (0x5aa6800, 0x5aa6c91, '702ac600665d7a23e9b4c470764bf407dc23ca7087d054914b4769f7aecaff45'),
    (0x5cf4540, 0x5cf47ed, '9bf318b0b199be7f06e41b95eacbc9c67dabf8cd5d31fe3484bcdbf6cc7c02fd'),
]

UNIFORM_CONSUMERS = {s for s, _, _ in CONSUMERS_PINNED
                     if 0x5a9c620 <= s <= 0x5aa6c91}


def hx(value):
    return '0x%x' % value


def load_segments(data):
    phoff = struct.unpack_from('<Q', data, 0x20)[0]
    phentsize = struct.unpack_from('<H', data, 0x36)[0]
    phnum = struct.unpack_from('<H', data, 0x38)[0]
    segs = []
    for i in range(phnum):
        vals = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phentsize)
        if vals[0] == 1:
            segs.append((vals[3], vals[2], vals[5]))  # vaddr, offset, filesz
    return segs


def va_bytes(data, segs, va, size):
    for vaddr, offset, filesz in segs:
        if vaddr <= va and va + size <= vaddr + filesz:
            return data[offset + (va - vaddr): offset + (va - vaddr) + size]
    raise ValueError('unmapped va %#x' % va)


def va_offset(segs, va):
    for vaddr, offset, filesz in segs:
        if vaddr <= va < vaddr + filesz:
            return offset + (va - vaddr)
    raise ValueError('unmapped va %#x' % va)


def relocations(data, secs, name):
    sec = next(s for s in secs if s['name'] == name)
    out = []
    for p in range(sec['offset'], sec['offset'] + sec['size'], 24):
        r_off, r_info, r_add = struct.unpack_from('<QQq', data, p)
        out.append({'offset': r_off, 'type': r_info & 0xffffffff,
                    'addend': r_add & 0xffffffffffffffff})
    return out, sec


def fde_index(data, secs):
    _, fdes = eh_frame_records(data, secs)
    extents = sorted((f['start'], f['end']) for f in fdes)
    return extents, fdes


def body_of(extents, va):
    starts = [b for b, _ in extents]
    i = bisect.bisect_right(starts, va) - 1
    if i >= 0 and extents[i][0] <= va < extents[i][1]:
        return extents[i]
    return None


def disp_candidates(data, sec, target):
    """Positions in sec whose disp32 could end an instruction at
    target with 0..8 trailing bytes: va + 4 + k + disp == target."""
    base_va, off, size = sec['address'], sec['offset'], sec['size']
    blob = data[off:off + size]
    b = np.frombuffer(blob, dtype=np.uint8)
    n = len(b) - 3
    disp = (b[:n].astype(np.int64) | (b[1:n + 1].astype(np.int64) << 8) |
            (b[2:n + 2].astype(np.int64) << 16) |
            (b[3:n + 3].astype(np.int64) << 24))
    disp = np.where(disp >= 0x80000000, disp - 0x100000000, disp)
    dvals = disp + (base_va + np.arange(n, dtype=np.int64)) + 4
    cand = np.nonzero((dvals >= target - 8) & (dvals <= target))[0]
    return [(off + int(j), base_va + int(j), int(target - dvals[j]))
            for j in cand]


def verify_rip_refs(data, exec_secs, target, md):
    """Capstone-verified rip-relative references to target."""
    by_name = {s['name']: s for s in exec_secs.values()}
    hits = []
    cands = []
    for sec in exec_secs.values():
        cands.extend(disp_candidates(data, sec, target))
    for disp_off, disp_va, k in cands:
        end_va = disp_va + 4 + k
        sec = next(s for s in by_name.values()
                   if s['address'] <= disp_va < s['address'] + s['size'])
        end_off = sec['offset'] + (end_va - sec['address'])
        for start_off in range(max(sec['offset'], end_off - 15),
                               disp_off + 1):
            code = data[start_off:end_off]
            if len(code) < 2:
                continue
            got = list(md.disasm(code, sec['address'] +
                                 (start_off - sec['offset']), count=1))
            if not got:
                continue
            insn = got[0]
            if insn.address + insn.size != end_va:
                continue
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP \
                        and insn.address + insn.size + op.mem.disp == target:
                    hits.append({'site': insn.address,
                                 'mnemonic': insn.mnemonic,
                                 'form': 'ripmem'})
                    break
                if op.type == X86_OP_IMM and op.imm == target:
                    hits.append({'site': insn.address,
                                 'mnemonic': insn.mnemonic,
                                 'form': 'imm'})
                    break
            else:
                continue
            break
    return hits


def rel32_sites(data, exec_secs, targets, md):
    """Verified direct rel32 call/jump sites to any target."""
    candidates = []
    for sec in exec_secs:
        blob = np.frombuffer(
            data[sec['offset']:sec['offset'] + sec['size']],
            dtype=np.uint8)
        for op in (0xE8, 0xE9):
            pos = np.nonzero(blob[:-4] == op)[0]
            if not len(pos):
                continue
            rel = (blob[1:][pos].astype(np.int64) |
                   (blob[2:][pos].astype(np.int64) << 8) |
                   (blob[3:][pos].astype(np.int64) << 16) |
                   (blob[4:][pos].astype(np.int64) << 24))
            rel = np.where(rel >= 0x80000000, rel - 0x100000000, rel)
            tgt = sec['address'] + pos + 5 + rel
            for j in np.nonzero(np.isin(tgt, sorted(targets)))[0]:
                candidates.append((int(sec['address'] + pos[j]), op,
                                   int(tgt[j])))
    segs = load_segments(data)
    verified = []
    for site, op, tgt in candidates:
        off = va_offset(segs, site)
        insns = list(md.disasm(data[off:off + 5], site, count=1))
        if len(insns) == 1 and insns[0].size == 5 and \
                insns[0].mnemonic == ('call' if op == 0xE8 else 'jmp') and \
                insns[0].operands and \
                insns[0].operands[0].type == X86_OP_IMM and \
                insns[0].operands[0].imm == tgt:
            verified.append({'site': site, 'op': op, 'target': tgt})
    return verified


def linear_stream(data, segs, body, md):
    begin, end = body
    off = va_offset(segs, begin)
    return list(md.disasm(data[off:off + (end - begin)], begin))


def is_lea_rip(insn, regname):
    return insn.mnemonic == 'lea' and len(insn.operands) == 2 and \
        insn.operands[0].type == X86_OP_REG and \
        insn.reg_name(insn.operands[0].reg) == regname and \
        insn.operands[1].type == X86_OP_MEM and \
        insn.operands[1].mem.base == X86_REG_RIP


def lea_rip_target(insn):
    return insn.address + insn.size + insn.operands[1].mem.disp


def is_zero_byte_store(insn):
    return insn.mnemonic == 'mov' and len(insn.operands) == 2 and \
        insn.operands[0].type == X86_OP_MEM and \
        insn.operands[0].size == 1 and \
        insn.operands[1].type == X86_OP_IMM and \
        insn.operands[1].imm == 0 and \
        'rsp' in insn.op_str.split(',')[0]


def site_features(stream, idx):
    prev = stream[max(0, idx - 8):idx]
    prev6 = stream[max(0, idx - 6):idx]
    nxt = stream[idx + 1] if idx + 1 < len(stream) else None
    rdx_leas = [x for x in prev6 if is_lea_rip(x, 'rdx')]
    rsi_leas = [x for x in prev6 if is_lea_rip(x, 'rsi')]
    prev_insn = stream[idx - 1] if idx else None
    feat = {
        'zeroed_stack_byte_pair_before':
            sum(1 for x in prev if is_zero_byte_store(x)) >= 2,
        'lea_rdx_rip_before': bool(rdx_leas),
        'lea_rsi_rip_before': bool(rsi_leas),
        'lea_rsi_rsp_immediately_before': bool(
            prev_insn is not None and prev_insn.mnemonic == 'lea' and
            len(prev_insn.operands) == 2 and
            prev_insn.operands[0].type == X86_OP_REG and
            prev_insn.reg_name(prev_insn.operands[0].reg) == 'rsi' and
            prev_insn.operands[1].type == X86_OP_MEM and
            prev_insn.reg_name(prev_insn.operands[1].mem.base) == 'rsp'),
        'test_rax_rax_after': bool(
            nxt is not None and nxt.mnemonic == 'test' and
            nxt.op_str == 'rax, rax'),
        'mov_rdi_rax_after': bool(
            nxt is not None and nxt.mnemonic == 'mov' and
            nxt.op_str == 'rdi, rax'),
    }
    rdx_static = lea_rip_target(rdx_leas[-1]) if rdx_leas else None
    rsi_static = lea_rip_target(rsi_leas[-1]) if rsi_leas else None
    return feat, rdx_static, rsi_static, prev_insn, nxt


def family_of(feat):
    if feat['zeroed_stack_byte_pair_before'] and \
            feat['lea_rdx_rip_before'] and feat['test_rax_rax_after']:
        return 'flag_pair'
    if feat['lea_rsi_rip_before']:
        return 'static_second_argument'
    return 'residual'


def raw_direct_counts(data, secs, wanted):
    """H30's raw census: e8/e9 byte occurrences in .text whose rel32
    lands on a wanted start (counts only, unverified)."""
    text = next(s for s in secs if s['name'] == '.text')
    base, off, size = text['address'], text['offset'], text['size']
    counts = {w: 0 for w in wanted}
    for op in (0xE8, 0xE9):
        idx, limit = off, off + size - 5
        while idx < limit:
            j = data.find(bytes([op]), idx, limit + 1)
            if j < 0:
                break
            rel = struct.unpack_from('<i', data, j + 1)[0]
            tgt = base + (j - off) + 5 + rel
            if tgt in counts:
                counts[tgt] += 1
            idx = j + 1
    return counts


def stored_copies(data, rela_secs, targets):
    ranges = [(s['offset'], s['offset'] + s['size']) for s in rela_secs]
    out = []
    for target in targets:
        needle = struct.pack('<Q', target)
        idx = 0
        while True:
            j = data.find(needle, idx)
            if j < 0:
                break
            if not any(lo <= j < hi for lo, hi in ranges):
                out.append({'value': target, 'file_offset': j})
            idx = j + 1
    return out


def imm_materialisations(data, exec_secs, targets, md):
    out = []
    for target in targets:
        needle = struct.pack('<I', target)
        for sec in exec_secs:
            idx, limit = sec['offset'], sec['offset'] + sec['size'] - 4
            while idx < limit:
                j = data.find(needle, idx, limit + 1)
                if j < 0:
                    break
                for start in range(max(sec['offset'], j - 11), j + 1):
                    got = list(md.disasm(
                        data[start:j + 4],
                        sec['address'] + (start - sec['offset']), count=1))
                    if not got:
                        continue
                    insn = got[0]
                    if start + insn.size < j + 4:
                        continue
                    for op in insn.operands:
                        if op.type == X86_OP_IMM and op.imm == target:
                            out.append({'site': insn.address,
                                        'target': target})
                idx = j + 1
    return out


def analyze(data):
    if len(data) != TARGET_SIZE \
            or hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise ValueError('artifact authentication failed')
    secs = sections(data)
    segs = load_segments(data)
    extents, _ = fde_index(data, secs)
    exec_secs = {s['name']: s for s in secs
                 if s['type'] != 8 and s.get('flags', 0) & 0x4
                 and s['size']}
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    targets = {s for s, _, _ in CONSUMERS_PINNED}

    # Re-derive the consumer set from the binary: verified rip-relative
    # references to the slot, grouped by containing FDE body.
    slot_hits = [h for h in verify_rip_refs(data, exec_secs, SLOT, md)
                 if h['form'] == 'ripmem']
    assert len(slot_hits) == 63 and all(
        h['mnemonic'] == 'call' for h in slot_hits)
    derived = {}
    for h in slot_hits:
        b = body_of(extents, h['site'])
        raw = va_bytes(data, segs, b[0], b[1] - b[0])
        derived[b[0]] = (b[0], b[1], hashlib.sha256(raw).hexdigest())
    assert sorted(derived.values()) == sorted(CONSUMERS_PINNED), \
        'derived consumer set differs from the set pinned by PR #3235'

    # Verified direct rel32 sites to the consumers.
    verified = rel32_sites(data, list(exec_secs.values()), targets, md)
    sites_by_body = {}
    for v in verified:
        b = body_of(extents, v['site'])
        assert b is not None, 'site %#x outside any FDE body' % v['site']
        sites_by_body.setdefault(b, []).append(v)

    # Cross-check: linear sweep of every caller body finds the same set.
    streams = {}
    sweep = set()
    for b in sites_by_body:
        stream = linear_stream(data, segs, b, md)
        streams[b] = stream
        for insn in stream:
            if insn.mnemonic in ('call', 'jmp') and insn.operands and \
                    insn.operands[0].type == X86_OP_IMM and \
                    insn.operands[0].imm in targets:
                sweep.add((insn.address, insn.operands[0].imm))
    assert sweep == {(v['site'], v['target']) for v in verified}, \
        'candidate scan and linear sweep disagree'

    # Indirect reachability census for the consumer starts.
    rels_dyn, rela_dyn_sec = relocations(data, secs, '.rela.dyn')
    rels_plt, rela_plt_sec = relocations(data, secs, '.rela.plt')
    addend_hits = sum(1 for r in rels_dyn + rels_plt
                      if r['addend'] in targets)
    copies = stored_copies(data, [rela_dyn_sec, rela_plt_sec], targets)
    imms = imm_materialisations(data, list(exec_secs.values()),
                                targets, md)
    rip_refs = []
    for t in sorted(targets):
        rip_refs.extend(h for h in verify_rip_refs(data, exec_secs,
                                                   t, md)
                        if h['form'] == 'ripmem')
    dynsym = next(s for s in secs if s['name'] == '.dynsym')
    dynsym_hits = 0
    for i in range(dynsym['size'] // 24):
        val = struct.unpack_from('<Q', data,
                                 dynsym['offset'] + i * 24 + 8)[0]
        if val in targets:
            dynsym_hits += 1

    # One level up, counts only.
    up_counts = raw_direct_counts(data, secs,
                                  {b[0] for b in sites_by_body})
    up_addends = {b[0]: sum(1 for r in rels_dyn if r['addend'] == b[0])
                  for b in sites_by_body}

    # Per-caller records with per-site templates.
    callers = []
    per_consumer_sites = {t: [] for t in targets}
    family_counts = {'flag_pair': 0, 'static_second_argument': 0,
                     'residual': 0}
    flag_pair_rdx = []
    static_rsi = []
    flag_pair_prev_lea_rsi_rsp = 0
    for b in sorted(sites_by_body):
        stream = streams[b]
        index = {insn.address: i for i, insn in enumerate(stream)}
        raw = va_bytes(data, segs, b[0], b[1] - b[0])
        site_records = []
        for v in sorted(sites_by_body[b], key=lambda x: x['site']):
            feat, rdx_static, rsi_static, prev_insn, nxt = site_features(
                stream, index[v['site']])
            fam = family_of(feat)
            family_counts[fam] += 1
            if fam == 'flag_pair':
                flag_pair_rdx.append(rdx_static)
                if feat['lea_rsi_rsp_immediately_before']:
                    flag_pair_prev_lea_rsi_rsp += 1
            if rsi_static is not None:
                static_rsi.append(rsi_static)
            site_off = va_offset(segs, v['site'])
            site_records.append({
                'site': hx(v['site']),
                'site_bytes': data[site_off:site_off + 5].hex(),
                'consumer': hx(v['target']),
                'family': fam,
                'template': feat,
                'rdx_static': hx(rdx_static)
                if rdx_static is not None else None,
                'rsi_static': hx(rsi_static)
                if rsi_static is not None else None,
                'prev_insn': ('%s %s' % (prev_insn.mnemonic,
                                         prev_insn.op_str))
                if prev_insn is not None else None,
                'next_insn': ('%s %s' % (nxt.mnemonic, nxt.op_str))
                if nxt is not None else None,
            })
            per_consumer_sites[v['target']].append(hx(v['site']))
        callers.append({
            'body': {'start': hx(b[0]), 'end': hx(b[1]),
                     'bytes': b[1] - b[0],
                     'sha256': hashlib.sha256(raw).hexdigest()},
            'sites': site_records,
            'direct_callers': up_counts[b[0]],
            'relocation_addends': up_addends[b[0]],
        })

    assert family_counts == {'flag_pair': 36,
                             'static_second_argument': 28,
                             'residual': 3}, family_counts
    assert all(per_consumer_sites[t] for t in targets)

    consumers = []
    for start, end, digest in CONSUMERS_PINNED:
        consumers.append({
            'body': {'start': hx(start), 'end': hx(end),
                     'bytes': end - start, 'sha256': digest},
            'call_sites': sorted(per_consumer_sites[start]),
        })

    bodies_sorted = sorted(sites_by_body)
    cluster_runs = [[bodies_sorted[0]]]
    for b in bodies_sorted[1:]:
        if b[0] - cluster_runs[-1][-1][1] <= 0x100:
            cluster_runs[-1].append(b)
        else:
            cluster_runs.append([b])
    caller_clusters = [{
        'bodies': len(r),
        'first_body': hx(r[0][0]),
        'last_body': hx(r[-1][1]),
        'body_sizes': sorted({x[1] - x[0] for x in r}),
    } for r in cluster_runs]

    zero_up = sorted(hx(b[0]) for b in bodies_sorted
                     if up_counts[b[0]] == 0)
    records = {
        'artifact': {'path': 'artifacts/node/115/hl-node',
                     'sha256': TARGET_SHA256, 'size': TARGET_SIZE},
        'captured_code_executed': False,
        'question': (
            'Who calls the 63 consumers of GOT slot 0x64e7718 '
            'directly -- from which caller bodies and call sites, '
            'under what call-site conditions -- and is there any '
            'indirect path to a consumer body?'),
        'source': {
            'work_item': SOURCE_WORK_ITEM, 'pr': SOURCE_PR,
            'slot': hx(SLOT), 'consumer_count': len(CONSUMERS_PINNED),
            'note': ('The consumer set is re-derived from the binary '
                     'in analyze() and checked against the start, '
                     'end, and body hash pinned by the source '
                     'packet.'),
        },
        'census': {
            'executable_sections': sorted(exec_secs),
            'verified_direct_call_sites':
                sum(1 for v in verified if v['op'] == 0xE8),
            'verified_direct_jump_sites':
                sum(1 for v in verified if v['op'] == 0xE9),
            'caller_bodies': len(callers),
            'candidate_scan_matches_linear_sweep': True,
            'sites_outside_fde_bodies': 0,
            'rela_dyn_entries': len(rels_dyn),
            'rela_plt_entries': len(rels_plt),
            'relocations_with_addend_eq_any_consumer': addend_hits,
            'stored_qword_copies_of_consumer_starts_outside_rela':
                len(copies),
            'imm_materialisations_of_consumer_starts': len(imms),
            'rip_relative_refs_to_consumer_starts': len(rip_refs),
            'dynsym_entries_with_consumer_st_value': dynsym_hits,
            'flag_pair_rdx_statics_distinct': len(set(flag_pair_rdx)),
            'static_family_rsi_statics_distinct': len(set(static_rsi)),
            'flag_pair_prev_is_lea_rsi_rsp': flag_pair_prev_lea_rsi_rsp,
        },
        'callers': callers,
        'consumers': consumers,
        'families': {
            'flag_pair': {
                'call_sites': family_counts['flag_pair'],
                'definition': (
                    'Within the eight instructions before the call '
                    'at least two `mov byte ptr [rsp + k], 0` stores '
                    'zero a pair of stack flag bytes; within six '
                    'instructions a `lea rdx, [rip + disp]` loads a '
                    'static as the third argument; the instruction '
                    'after the call is `test rax, rax`.'),
            },
            'static_second_argument': {
                'call_sites': family_counts['static_second_argument'],
                'definition': (
                    'Within six instructions before the call a '
                    '`lea rsi, [rip + disp]` loads a static as the '
                    'second argument, and the site is not in the '
                    'flag-pair family.'),
            },
            'residual': {
                'call_sites': family_counts['residual'],
                'definition': (
                    'Neither pattern: the two callers of the large '
                    'consumer 0x5a79730 and the caller of '
                    '0x5cf4540; each site is pinned with its own '
                    'preceding and following instruction.'),
            },
        },
        'caller_clusters': caller_clusters,
        'one_level_up': {
            'zero_direct_caller_bodies': zero_up,
            'note': (
                'Every caller body with zero direct rel32 callers '
                'has exactly one .rela.dyn entry whose addend is '
                'its start; those stored pointers are counted, '
                'not followed.'),
        },
        'answer': {
            'direct_calls': (
                'Every one of the 63 consumer bodies is called '
                'directly, and only directly: 67 verified '
                '`call rel32` sites in 65 FDE caller bodies, no '
                'direct jumps, and no indirect path -- no '
                'relocation addend, no stored copy, no immediate, '
                'no rip-relative reference, and no dynamic symbol '
                'names a consumer start.'),
            'families': (
                'The 36 callers of the 36 uniform 1169-byte '
                'consumers all use the flag-pair template: two '
                'stack flag bytes are zeroed, rdi and rsi point at '
                'them, rdx takes a rip-relative static, and the '
                'return value is tested against null. 28 further '
                'sites pass a rip-relative static in rsi as the '
                'second argument. The remaining 3 sites -- the two '
                'callers of 0x5a79730 and the caller of 0x5cf4540 '
                '-- match neither pattern.'),
            'pairing': (
                '64 of the 65 caller bodies call exactly one '
                'consumer; the single exception, body 0x2b41b70, '
                'calls three (0x2b3aba0, 0x2b3b3e0, 0x2b3d250). '
                'Three consumers have more than one caller: '
                '0x2e8e7b0 has three call sites and 0x2b3c9d0 and '
                '0x5a79730 have two each.'),
        },
        'boundaries': {
            'prior_packets': (
                'RE-005-node115-x5-caller-slot-consumers (#3235) '
                'pins the 63 consumer bodies and records only the '
                'count of each consumer\'s direct rel32 callers; '
                'this packet enumerates them. Individual sites '
                'appear incidentally in earlier work: RE-017 '
                'packets record 11 of the sites as transfer/call '
                'rows (0x2b4261c, 0x4e359fc, 0x4e35c7c, 0x4e36191, '
                '0x4e3642f, 0x4e45a61, 0x4e460c1, 0x4e46e71, '
                '0x4e47938, 0x4e47cdf, 0x4e4a771), '
                'RE-011-evm-fee-history-115 records one call row '
                '(site 0x2a0afd5 into 0x2b3daa0), and '
                'RE-012-node115-startup-end-height\'s instruction '
                'window over caller body 0x2b41b70 includes its '
                'three sites (0x2b420da, 0x2b4261c, 0x2b428ab). '
                'No earlier packet enumerates the call sites of '
                'the consumer set, groups them by caller body, '
                'pins their call-site conditions, or excludes '
                'the indirect reference forms for the consumers.'),
            'one_level_up': (
                'For each caller body this packet records only '
                'two counts: raw direct rel32 call/jump byte '
                'occurrences in .text whose target is the body '
                'start, and .rela.dyn entries whose addend is '
                'the body start. Who reads the seven stored '
                'pointers, and the callers\' callers in general, '
                'are outside this packet\'s question.'),
            'runtime_behaviour': (
                'Which runtime path reaches a given call site, '
                'what the per-site statics name, and the concrete '
                'Rust types of the caller bodies are not '
                'established by static evidence.'),
        },
    }
    return records


def frames_lines(data, records):
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    wanted = {int(c['body']['start'], 16) for c in records['callers']}
    wanted |= {int(c['body']['start'], 16)
               for c in records['consumers']}
    frame_sec = next(s for s in secs if s['name'] == '.eh_frame')
    lines = []
    for f in fdes:
        if f['start'] not in wanted:
            continue
        rec_off = frame_sec['offset'] + (f['fde'] - frame_sec['address'])
        length = struct.unpack_from('<I', data, rec_off)[0] + 4
        cie_field = struct.unpack_from('<I', data, rec_off + 4)[0]
        cie_off = frame_sec['offset'] + (f['cie'] - frame_sec['address'])
        lines.append('%08x %016x %08x FDE cie=%08x pc=%016x..%016x'
                     % (rec_off, length, cie_field, cie_off,
                        f['start'], f['end']))
    return lines


def readme_text(records):
    c = records['census']
    flag_rdx = next(s['rdx_static'] for cl in records['callers']
                    for s in cl['sites'] if s['family'] == 'flag_pair')
    cl = records['caller_clusters']
    cluster_lines = '\n'.join(
        '- %d %s, %s..%s, body sizes %s'
        % (x['bodies'], 'body' if x['bodies'] == 1 else 'bodies',
           x['first_body'], x['last_body'],
           '/'.join(str(s) for s in x['body_sizes'])) for x in cl)
    return f"""# RE-005 node 115: who calls the X5 slot consumers

## Question

The caller-slot packet (`RE-005-node115-x5-caller-slot-consumers`,
PR #3235) pinned the 63 FDE bodies that load GOT slot `0x64e7718`
-- the only static holder of the X5 schedule-caller body
`0x5cf5100` -- and recorded, for each consumer, only the count of
its direct rel32 callers. It left one question open: who calls the
consumers, from which bodies and call sites, under what call-site
conditions -- and is there any indirect path to a consumer at all?

## Method

Static analysis only, against the authenticated node 115 binary
(SHA-256 `{records['artifact']['sha256']}`). The consumer set is
re-derived from the binary -- verified rip-relative references to
the slot, grouped by FDE body -- and checked against the start,
end, and body hash of every consumer pinned by PR #3235. A
candidate scan over every executable section
({', '.join(c['executable_sections'])}) enumerated every `e8`/`e9`
byte position whose rel32 lands on a consumer start; each candidate
was verified by decoding the instruction at the site, and the
verified set was cross-checked against a linear disassembly sweep
of every containing FDE body: the two sets are identical.
Independent passes excluded the indirect forms: relocation addends
across all {c['rela_dyn_entries']} `.rela.dyn` and
{c['rela_plt_entries']} `.rela.plt` entries, stored 8-byte copies
outside the relocation sections' own serialised entries,
immediate materialisations, rip-relative references resolving to a
consumer start, and `.dynsym` values.

## Answer

Every consumer is called directly, and only directly:
**{c['verified_direct_call_sites']} verified `call rel32` sites**
in **{c['caller_bodies']} caller bodies**, no direct jumps, no
site outside an FDE body, and no indirect path -- the indirect
census above is zero in every form. The caller bodies form
{len(cl)} address clusters:

{cluster_lines}

64 of the 65 caller bodies call exactly one consumer. The single
exception, body `0x2b41b70`, calls three (`0x2b3aba0`,
`0x2b3b3e0`, `0x2b3d250`). Three consumers have more than one
caller: `0x2e8e7b0` has three call sites, and `0x2b3c9d0` and
`0x5a79730` have two each.

The call sites separate into three families by the instruction
pattern around them, pinned per site in `records.json`:

- **Flag-pair family ({records['families']['flag_pair']['call_sites']}
  sites)** -- exactly the callers of the 36 uniform 1169-byte
  consumers. Within eight instructions before the call, at least
  two `mov byte ptr [rsp + k], 0` stores zero a pair of stack flag
  bytes; within six, a `lea rdx, [rip + disp]` loads the same
  static ({flag_rdx}) as the third argument at every site; the
  instruction before the
  call points `rsi` at the second flag byte in
  {c['flag_pair_prev_is_lea_rsi_rsp']} of the 36 sites, and the
  instruction after the call is `test rax, rax` at all 36.
- **Static-second-argument family
  ({records['families']['static_second_argument']['call_sites']}
  sites)** -- a `lea rsi, [rip + disp]` within six instructions
  loads a static as the second argument
  ({c['static_family_rsi_statics_distinct']} distinct statics).
- **Residual ({records['families']['residual']['call_sites']}
  sites)** -- the two callers of the large consumer `0x5a79730`
  and the caller of `0x5cf4540`; each is pinned with its own
  preceding and following instruction.

One level up is recorded as counts only (`direct_callers` and
`relocation_addends` per caller body). Seven caller bodies have
no direct rel32 callers at all; each of them has exactly one
`.rela.dyn` entry whose addend is its start, so their addresses
are held as stored pointers. Those pointers are counted here,
not followed.

## Boundaries

{records['boundaries']['prior_packets']}

{records['boundaries']['one_level_up']}

{records['boundaries']['runtime_behaviour']}
"""


def objdump_text():
    ranges = [('--start-address=0x24519c0', '--stop-address=0x2451bbe'),
              ('--start-address=0x4e35c10', '--stop-address=0x4e35e85'),
              ('--start-address=0x5ceb530', '--stop-address=0x5ceb6c3'),
              ('--start-address=0x2b425e0', '--stop-address=0x2b42640')]
    out = []
    # Run objdump from the repo root with a relative target path so the
    # file-format header it prints is checkout-independent; an absolute
    # path here made `check` pass only at the author's checkout location.
    target_rel = str(TARGET.relative_to(ROOT))
    for start, stop in ranges:
        r = subprocess.run(['objdump', '-d', start, stop, target_rel],
                           capture_output=True, text=True, check=True,
                           cwd=ROOT)
        out.append(r.stdout)
    return '\n'.join(out)


def render_files(records, data):
    files = {}
    files['records.json'] = json.dumps(records, indent=2,
                                       sort_keys=True) + '\n'
    files['frames.txt'] = '\n'.join(frames_lines(data, records)) + '\n'
    files['README.md'] = readme_text(records)
    files['caller_bodies.objdump.txt'] = objdump_text()
    manifest = ''.join(
        '%s  %s\n' % (hashlib.sha256(v.encode()).hexdigest(), k)
        for k, v in sorted(files.items()))
    files['MANIFEST.sha256'] = manifest
    return files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('command', choices=('generate', 'check'))
    args = ap.parse_args()
    data = TARGET.read_bytes()
    records = analyze(data)
    files = render_files(records, data)
    if args.command == 'generate':
        PACKET_DIR.mkdir(parents=True, exist_ok=True)
        for name, text in files.items():
            (PACKET_DIR / name).write_text(text)
        print('generated', len(files), 'files in', PACKET_DIR)
    else:
        bad = []
        for name, text in files.items():
            p = PACKET_DIR / name
            if not p.exists() or p.read_text() != text:
                bad.append(name)
        if bad:
            print('STALE:', ', '.join(sorted(bad)))
            return 1
        print('check ok:', len(files), 'files match regeneration')
    return 0


if __name__ == '__main__':
    sys.exit(main())
