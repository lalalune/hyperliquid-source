#!/usr/bin/env python3
"""Reconstruct the node #115 `Action` serializer tag dispatch and prove it against the bytes.

Six unowned monomorphized copies of one internally tagged `Serialize` body read the first
word of an `Action`, map it to a variant index through a niche formula and a jump table,
and give each arm four static strings (enum name, Rust variant name, tag key, wire name),
a payload pointer and one per-variant serializer call.  This tool:

* decodes every arm of each copy with a fixed byte-pattern evaluator that fails closed;
* checks that the arms and the prologue cover every byte of each FDE extent;
* holds an independent reconstruction (`SPEC`: variant order, serde rename rules, unit
  variants, niche base) and compares it with the byte evaluation for every tag word that
  reaches a table entry;
* runs spec and byte mutants and requires every one to be detected.

Only Python and the shared ELF/FDE parsers are used.  The node binary is never executed.
"""
import argparse
import hashlib
import json
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

BINARY = os.path.join('artifacts', 'node', '115', 'hl-node')
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
# FDE starts of the six copies examined here.  Five further copies with the same shape are
# cited by earlier packets and are deliberately not decoded by this tool.
COPIES = (0x2bce570, 0x36aef70, 0x36b3f80, 0x4d84400, 0x4d86d80, 0x4d89700)
U64 = (1 << 64) - 1


class DecodeError(Exception):
    pass


# ---------------------------------------------------------------- reconstruction (spec)
# Declaration order of `enum Action` as reconstructed.  Index i is the variant index;
# its niche tag word is NICHE_BASE + i, except the dataful variant that owns the niche.
VARIANTS = (
    'Noop', 'ApproveAgent3', 'BatchModify', 'Cancel', 'CancelByCloid', 'ClaimRewards', 'CreateSubAccount',
    'CreateVault', 'EvmRawTx', 'ForceIncreaseEpoch', 'Liquidate', 'LinkStakingUser', 'Modify',
    'NetChildVaultPositions', 'Order', 'RegisterReferrer', 'RegisterValidator', 'CValidator', 'ScheduleCancel',
    'SetDisplayName', 'VoteGlobal', 'ValidatorL1Vote', 'ValidatorL1Stream', 'ValidatorL1Status',
    'ValidatorL1UpdateReferenceOracle', 'SetGlobal', 'SetReferrer', 'SpotDeploy', 'SpotUser', 'SpotSend',
    'SignValidatorSetUpdate', 'SubAccountModify', 'SubAccountTransfer', 'SubAccountSpotTransfer', 'TokenDelegate',
    'TwapCancel', 'TwapOrder', 'UpdateIsolatedMargin', 'TopUpStrictIsolatedMargin', 'UpdateUserLeverage', 'UsdSend',
    'ValidatorSignWithdrawal', 'VaultDistribute', 'VaultModify', 'VaultTransfer', 'VoteEthDeposit',
    'VoteEthFinalizedValidatorSetUpdate', 'VoteEthFinalizedWithdrawal', 'Withdraw3', 'GovPropose', 'GovVote',
    'UsdClassTransfer', 'MultiSig', 'ConvertToMultiSigUser', 'ApproveBuilderFee', 'StartFeeTrial', 'SystemBole',
    'SystemSpotSend', 'DeployerSendToEvmForFrozenUser', 'SystemUsdClassTransfer', 'CSigner', 'CWithdraw', 'CDeposit',
    'CUserModify', 'ReassessFees', 'EvmUserModify', 'ReserveRequestWeight', 'FinalizeEvmContract', 'Hip3Deploy',
    'SendAsset', 'SystemApproveBuilderFee', 'SystemSendAsset', 'AgentEnableDexAbstraction', 'UserDexAbstraction',
    'Bole', 'SendToEvmWithData', 'UserPortfolioMargin', 'UserSetAbstraction', 'AgentSetAbstraction', 'UserOutcome',
    'GossipPriorityBid', 'AgentSendAsset', 'Hip3LiquidatorTransfer', 'L1ValidatorVoteBridgeDeposit',
    'AuthorizeAqav2Role', 'StakingLinkDisableTradingUser', 'VoteL1Hash', 'VoteAbciDigest', 'ActivateOutcomeDeployer',
    'TrailingStopOrder', 'OutcomeDeploy', 'CDeposit2',
)
# `#[serde(tag = "type", rename_all = "camelCase")]` plus two kinds of per-variant rename.
SUFFIX_ACTION = frozenset((
    'ForceIncreaseEpoch', 'NetChildVaultPositions', 'RegisterValidator', 'CValidator', 'VoteGlobal', 'SetGlobal',
    'SignValidatorSetUpdate', 'ValidatorSignWithdrawal', 'VoteEthDeposit', 'VoteEthFinalizedValidatorSetUpdate',
    'VoteEthFinalizedWithdrawal', 'SystemBole', 'SystemSpotSend', 'SystemUsdClassTransfer', 'CSigner',
    'SystemApproveBuilderFee', 'SystemSendAsset',
))
RENAMES = {
    'ApproveAgent3': 'approveAgent', 'TopUpStrictIsolatedMargin': 'topUpIsolatedOnlyMargin',
    'UpdateUserLeverage': 'updateLeverage', 'Hip3Deploy': 'perpDeploy', 'Bole': 'borrowLend',
    'TrailingStopOrder': 'trailingStop',
}
# Newtype variants whose payload is a unit struct `<Variant>Action`: serialized as the tag
# plus a unit-struct name, with no payload pointer handed on.
UNIT = frozenset(('Noop', 'ClaimRewards', 'AgentEnableDexAbstraction'))
# Variants whose payload pointer is the enum start rather than the word after the tag.
PAYLOAD_AT_ZERO = frozenset(('VoteGlobal', 'ReassessFees'))
# Copy-specific inlining: the arm loads payload words itself instead of passing a pointer.
# SpotUser carries one u32 after the tag word; ValidatorL1Stream hands on the pointer and
# length words of a three-word (capacity, pointer, length) buffer.
INLINED = {
    (0x2bce570, 'SpotUser'): 'load-u32@self+8',
    (0x36b3f80, 'ValidatorL1Stream'): 'load-u64@self+16,load-u64@self+24',
}
SPEC = dict(enum='Action', tag='type', niche_base=0x86, dataful='VoteGlobal')


def wire_name(spec, rust):
    if rust in spec['renames']:
        return spec['renames'][rust]
    if rust in spec['suffix_action']:
        return rust + 'Action'
    return rust[0].lower() + rust[1:]


def default_spec():
    return dict(SPEC, variants=list(VARIANTS), suffix_action=set(SUFFIX_ACTION), renames=dict(RENAMES),
                unit=set(UNIT), payload_at_zero=set(PAYLOAD_AT_ZERO), inlined=dict(INLINED))


def spec_serialize(spec, tag, copy=None):
    """Reconstructed behaviour for one tag word in one copy: which arm runs and what it hands on."""
    variants = spec['variants']
    index = tag - spec['niche_base'] if tag >= spec['niche_base'] else variants.index(spec['dataful'])
    if index >= len(variants):
        return ('outside-table',)
    rust = variants[index]
    if rust in spec['unit']:
        payload, unit = '-', rust + 'Action'
    elif (copy, rust) in spec['inlined']:
        payload, unit = spec['inlined'][(copy, rust)], '-'
    else:
        payload, unit = 'self+%d' % (0 if rust in spec['payload_at_zero'] else 8), '-'
    return (index, spec['enum'], rust, spec['tag'], wire_name(spec, rust), payload, unit)


# ---------------------------------------------------------------- byte evaluation
class Image:
    def __init__(self, data, secs=None, fdes=None):
        self.data = data
        self.secs = secs if secs is not None else [s for s in sections(data) if s['type'] != 8 and s['address']]
        self.fdes = fdes if fdes is not None else {r['start']: r for r in fde_extents(data)[1]}

    def patched(self, va, new):
        data = bytearray(self.data)
        off = self.file_offset(va, len(new))
        data[off:off + len(new)] = new
        return Image(bytes(data), self.secs, self.fdes)

    def file_offset(self, va, size):
        for s in self.secs:
            if s['address'] <= va and va + size <= s['address'] + s['size']:
                return s['offset'] + va - s['address']
        raise DecodeError('unmapped va %#x' % va)

    def read(self, va, size):
        off = self.file_offset(va, size)
        return self.data[off:off + size]


# A: push rbx; sub rsp,0x50; mov rax,[rsi]; sub rax,imm32; mov ecx,imm32; cmovae rcx,rax; mov rbx,rdi;
#    lea rax,[rip+table]; movsxd rcx,[rax+rcx*4]; add rcx,rax; jmp rcx   (out in rdi, self in rsi, serializer in rdx)
# B: sub rsp,0x48; mov rax,[rdi]; ... same dispatch without rbx          (self in rdi, serializer in rsi)
FORMS = (
    ('A', (b'\x53\x48\x83\xec\x50\x48\x8b\x06\x48\x2d', 4, b'\xb9', 4, b'\x48\x0f\x43\xc8\x48\x89\xfb\x48\x8d\x05', 4,
           b'\x48\x63\x0c\x88\x48\x01\xc1\xff\xe1')),
    ('B', (b'\x48\x83\xec\x48\x48\x8b\x07\x48\x2d', 4, b'\xb9', 4, b'\x48\x0f\x43\xc8\x48\x8d\x05', 4,
           b'\x48\x63\x0c\x88\x48\x01\xc1\xff\xe1')),
)
ENTRY = {'A': dict(rdi=('out',), rbx=('out',), rsi=('self', 0), rdx=('ser',), rsp=('stack', 0)),
         'B': dict(rdi=('self', 0), rsi=('ser',), rsp=('stack', 0))}
R64 = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi')


def prologue(img, start):
    b = img.read(start, 64)
    for form, parts in FORMS:
        p, vals, lea_end = 0, [], None
        for part in parts:
            if isinstance(part, int):
                vals.append(struct.unpack_from('<i', b, p)[0])
                p += 4
                if len(vals) == 3:
                    lea_end = start + p
            elif b[p:p + len(part)] == part:
                p += len(part)
            else:
                break
        else:
            return dict(form=form, base=vals[0] & U64, default=vals[1] & 0xffffffff, table=lea_end + vals[2],
                        body=start + p)
    raise DecodeError('no known prologue at %#x' % start)


def modrm(b, va):
    """REX.W 89/8b/8d with rm = rsp+disp (SIB 0x24), rip+disp32, rsi/rdi+disp8, or register."""
    if len(b) < 3 or b[0] != 0x48 or b[1] not in (0x89, 0x8b, 0x8d):
        return None
    m = b[2]
    mod, reg, rm = m >> 6, R64[(m >> 3) & 7], m & 7
    if mod == 3:
        return (3, ('mov', R64[rm], reg)) if b[1] == 0x89 else None
    if mod == 0 and rm == 5:
        n, mem = 7, ('rip', va + 7 + struct.unpack_from('<i', b, 3)[0])
    elif mod == 0 and rm == 4 and b[3] == 0x24:
        n, mem = 4, ('stack', 0)
    elif mod == 1 and rm == 4 and b[3] == 0x24:
        n, mem = 5, ('stack', b[4])
    elif mod == 1 and R64[rm] in ('rsi', 'rdi'):
        n, mem = 4, ('reg', R64[rm], b[3])
    else:
        return None
    if b[1] == 0x8d and mem[0] != 'reg':
        return n, ('set', reg, ('addr', mem[1]) if mem[0] == 'rip' else mem)
    if b[1] == 0x89 and mem[0] == 'stack':
        return n, ('slot', mem[1], reg)
    if b[1] == 0x8b and mem[0] == 'reg':
        return n, ('load', mem[1], 'u64', mem[2], reg)
    return None


NARROW_LOADS = ((b'\x8b', 'u32'), (b'\x0f\xb6', 'u8'), (b'\x0f\xb7', 'u16'))


def step(b, va):
    """(length, effect) of one whitelisted instruction; any other byte sequence fails closed."""
    def i32(p):
        return struct.unpack_from('<i', b, p)[0]
    hit = modrm(b, va)
    if hit:
        return hit
    if b[:4] == b'\x48\xc7\x04\x24':
        return 8, ('slotimm', 0, i32(4))
    if b[:4] == b'\x48\xc7\x44\x24':
        return 9, ('slotimm', b[4], i32(5))
    if b[:3] in (b'\x48\x83\xc6', b'\x48\x83\xc7'):
        return 4, ('add', 'rsi' if b[2] == 0xc6 else 'rdi', b[3])
    if b[:1] in (b'\xb9', b'\xba'):
        return 5, ('set', 'rcx' if b[0] == 0xb9 else 'rdx', ('imm', i32(1)))
    for pre, width in NARROW_LOADS:
        k = len(pre)
        if b[:k] == pre and len(b) > k + 1 and b[k] in (0x76, 0x7f):
            reg = 'rsi' if b[k] == 0x76 else 'rdi'
            return k + 2, ('load', reg, width, b[k + 1], reg)
    if b[:1] == b'\xe8':
        return 5, ('call', va + 5 + i32(1))
    if b[:1] == b'\xe9':
        return 5, ('jmp', va + 5 + i32(1))
    if b[:1] == b'\xeb':
        return 2, ('jmp', va + 2 + struct.unpack_from('<b', b, 1)[0])
    if b[:3] == b'\x48\x83\xc4':
        return 4, ('frame', b[3])
    if b[:1] == b'\x5b':
        return 1, ('pop',)
    if b[:1] == b'\xc3':
        return 1, ('ret',)
    raise DecodeError('unknown bytes %s at %#x' % (b[:8].hex(), va))


def sweep(img, body, end):
    """Linear walk without following jumps; each arm ends in ret or an unconditional jmp."""
    starts, va = [body], body
    while va < end:
        n, eff = step(img.read(va, min(16, end - va)), va)
        va += n
        if eff[0] in ('ret', 'jmp') and va < end:
            starts.append(va)
    if va != end:
        raise DecodeError('sweep overran extent')
    return starts


def run_arm(img, form, va, start, end, limit=64):
    regs = dict(ENTRY[form])
    slots, calls, path = {}, [], []
    for _ in range(limit):
        if not start <= va < end:
            raise DecodeError('arm left its extent at %#x' % va)
        n, eff = step(img.read(va, min(16, end - va)), va)
        path.append((va, n))
        kind = eff[0]
        if kind == 'set':
            regs[eff[1]] = eff[2]
        elif kind == 'mov':
            regs[eff[1]] = regs.get(eff[2], ('undef', eff[2]))
        elif kind == 'slot':
            slots[eff[1]] = regs.get(eff[2], ('undef', eff[2]))
        elif kind == 'slotimm':
            slots[eff[1]] = ('imm', eff[2])
        elif kind in ('add', 'load'):
            v = regs.get(eff[1])
            if not v or v[0] != 'self':
                raise DecodeError('%s on a non-self register at %#x' % (kind, va))
            regs[eff[1] if kind == 'add' else eff[4]] = (
                ('self', v[1] + eff[2]) if kind == 'add' else ('load', eff[2], v[1] + eff[3]))
        elif kind == 'call':
            calls.append((eff[1], dict(regs), dict(slots)))
        elif kind == 'jmp':
            va = eff[1]
            continue
        elif kind == 'ret':
            if len(calls) != 1:
                raise DecodeError('arm at %#x makes %d calls' % (path[0][0], len(calls)))
            return calls[0], path
        va += n
    raise DecodeError('arm step limit at %#x' % path[0][0])


def slice_text(img, slots, at):
    ptr, size = slots.get(at), slots.get(at + 8)
    if not ptr or ptr[0] != 'addr' or not size or size[0] != 'imm' or not 0 < size[1] < 256:
        raise DecodeError('stack slot %#x is not a static string slice' % at)
    raw = img.read(ptr[1], size[1])
    if any(c < 0x21 or c > 0x7e for c in raw):
        raise DecodeError('non-identifier bytes in slice at %#x' % ptr[1])
    return raw.decode('ascii')


def normalize(img, call):
    """Turn the call-site state into the arm's observable meaning."""
    target, regs, slots = call
    order = ('rdi', 'rsi', 'rdx', 'rcx')
    arrays = [r for r in order if regs.get(r, ('',))[0] == 'stack']
    if len(arrays) != 1:
        raise DecodeError('expected one stack array argument')
    base = regs[arrays[0]][1]
    names = tuple(slice_text(img, slots, base + 16 * k) for k in range(4))
    if slots.get(base + 0x40) != ('ser',):
        raise DecodeError('serializer handle not stored after the names')
    payloads = [regs[r] for r in order if regs.get(r, ('',))[0] in ('self', 'load')]
    units = [(regs[a], regs[b]) for a, b in zip(order, order[1:])
             if regs.get(a, ('',))[0] == 'addr' and regs.get(b, ('',))[0] == 'imm']
    if bool(payloads) == bool(units) or len(units) > 1 or (
            len(payloads) > 1 and any(p[0] != 'load' for p in payloads)):
        raise DecodeError('expected one payload pointer, loaded payload words, or one unit name')
    if payloads:
        payload = ','.join('self+%d' % p[1] if p[0] == 'self' else 'load-%s@self+%d' % (p[1], p[2])
                           for p in payloads)
        unit = '-'
    else:
        payload = '-'
        (ptr, size), = units
        unit = img.read(ptr[1], size[1]).decode('ascii')
    return names, payload, unit, target


def decode_copy(img, start):
    fde = img.fdes.get(start)
    if fde is None:
        raise DecodeError('no FDE starts at %#x' % start)
    end = fde['end']
    pro = prologue(img, start)
    starts = sweep(img, pro['body'], end)
    arm_set = set(starts)
    entries, arms, covered = [], {}, {}
    for va in range(start, pro['body']):
        covered[va] = 1
    while True:
        rel = struct.unpack('<i', img.read(pro['table'] + 4 * len(entries), 4))[0]
        target = pro['table'] + rel
        if target not in arm_set:
            break
        entries.append(target)
        if target not in arms:
            call, path = run_arm(img, pro['form'], target, start, end)
            arms[target] = (normalize(img, call), path)
            for va, n in path:
                for x in range(va, va + n):
                    covered[x] = 1
    if len(set(entries)) != len(entries) or set(entries) != arm_set:
        raise DecodeError('table entries and swept arms are not a bijection at %#x' % start)
    return dict(start=start, end=end, form=pro['form'], base=pro['base'], default=pro['default'], table=pro['table'],
                body=pro['body'], entries=entries, arms=arms, covered=len(covered),
                sha256=hashlib.sha256(img.read(start, end - start)).hexdigest(),
                stop_target=pro['table'] + struct.unpack('<i', img.read(pro['table'] + 4 * len(entries), 4))[0])


def byte_serialize(img, copy, tag):
    """Evaluate the decoded prologue arithmetic (sub, cmovae) and the selected arm for one tag word."""
    raw = (tag - copy['base']) & U64
    index = raw if tag >= copy['base'] else copy['default']
    if index >= len(copy['entries']):
        return ('outside-table',)
    (names, payload, unit, _), _ = copy['arms'][copy['entries'][index]]
    return (index,) + names + (payload, unit)


def tags_for(spec_len, base):
    """Every tag word that reaches a table entry: all values below the niche base, then each niche value."""
    return list(range(0, base)) + list(range(base, base + spec_len)) + [base + spec_len]


def compare(img, copies, spec):
    """First mismatch between the reconstruction and the byte evaluation, or None."""
    for copy in copies:
        for tag in tags_for(len(spec['variants']), SPEC['niche_base']):
            if spec_serialize(spec, tag, copy['start']) != byte_serialize(img, copy, tag):
                return copy['start'], tag
    return None


# ---------------------------------------------------------------- mutants
def spec_mutants():
    out = []
    for name, delta in (('niche_base', -1), ('niche_base', 1)):
        out.append(('spec:%s%+d' % (name, delta), dict(default_spec(), **{name: SPEC[name] + delta})))
    for other in ('ValidatorL1Vote', 'SetDisplayName'):
        out.append(('spec:dataful=' + other, dict(default_spec(), dataful=other)))
    out.append(('spec:tag=kind', dict(default_spec(), tag='kind')))
    out.append(('spec:enum=Actions', dict(default_spec(), enum='Actions')))
    for rust in sorted(SUFFIX_ACTION):
        s = default_spec()
        s['suffix_action'].discard(rust)
        out.append(('spec:drop-suffix:' + rust, s))
    for rust in sorted(RENAMES):
        s = default_spec()
        del s['renames'][rust]
        out.append(('spec:drop-rename:' + rust, s))
    for rust in sorted(UNIT):
        s = default_spec()
        s['unit'].discard(rust)
        out.append(('spec:drop-unit:' + rust, s))
    for rust in sorted(PAYLOAD_AT_ZERO):
        s = default_spec()
        s['payload_at_zero'].discard(rust)
        out.append(('spec:drop-payload0:' + rust, s))
    for key in sorted(INLINED):
        s = default_spec()
        del s['inlined'][key]
        out.append(('spec:drop-inlined:%#x:%s' % key, s))
    s = default_spec()
    s['inlined'][(COPIES[4], 'SpotUser')] = INLINED[(COPIES[0], 'SpotUser')]
    out.append(('spec:add-inlined:%#x:SpotUser' % COPIES[4], s))
    for i in range(len(VARIANTS) - 1):
        s = default_spec()
        v = s['variants']
        v[i], v[i + 1] = v[i + 1], v[i]
        out.append(('spec:swap:%d-%d' % (i, i + 1), s))
    s = default_spec()
    s['variants'] = s['variants'][:-1]
    out.append(('spec:drop-last-variant', s))
    s = default_spec()
    s['suffix_action'].add('Order')
    out.append(('spec:add-suffix:Order', s))
    return out


def byte_mutants(img, first):
    """Patched images of the first copy; each must fail closed or disagree with the spec."""
    pro = prologue(img, first)
    table = pro['table']
    e0, e1 = img.read(table, 4), img.read(table + 4, 4)
    fde_end = img.fdes[first]['end']
    yield 'bytes:swap-table-0-1', img.patched(table, e1 + e0)
    yield 'bytes:niche-base+1', img.patched(first + (10 if pro['form'] == 'A' else 9),
                                           struct.pack('<i', pro['base'] + 1))
    yield 'bytes:default-index+1', img.patched(first + (15 if pro['form'] == 'A' else 14),
                                              struct.pack('<i', pro['default'] + 1))
    yield 'bytes:first-arm-opcode', img.patched(pro['body'], b'\x90')
    yield 'bytes:last-byte-int3', img.patched(fde_end - 1, b'\xcc')
    copy = decode_copy(img, first)
    (_, path) = copy['arms'][copy['entries'][1]]
    for va, n in path:
        b = img.read(va, n)
        if b[:4] == b'\x48\xc7\x44\x24' and b[4] == 0x38 - (0 if pro['form'] == 'B' else -8):
            yield 'bytes:wire-name-length-1', img.patched(va + 5, struct.pack('<i', struct.unpack_from('<i', b, 5)[0] - 1))
            break
    else:
        raise DecodeError('no wire-name length store in arm 1')


def judge(img, copies, spec, mutant_img=None, first=None):
    if mutant_img is None:
        hit = compare(img, copies, spec)
        return ('killed', '%#x:%#x' % hit) if hit else ('survived', '-')
    try:
        mc = decode_copy(mutant_img, first)
    except DecodeError as exc:
        return 'killed', 'fail-closed: ' + str(exc).split(' at ')[0]
    hit = compare(mutant_img, [mc], spec)
    return ('killed', '%#x:%#x' % hit) if hit else ('survived', '-')


# ---------------------------------------------------------------- outputs
def effect_text(eff):
    """Stable text for one decoded effect: integers above 9 in hex, nested tuples joined by ':'."""
    def part(x):
        if isinstance(x, tuple):
            return ':'.join(part(y) for y in x)
        if isinstance(x, int):
            return '%#x' % x if x > 9 or x < 0 else str(x)
        return str(x)
    return ' '.join(part(x) for x in eff)


def tsv(rows):
    return ''.join('\t'.join(str(c) for c in row) + '\n' for row in rows)


def rust_enum(spec, copies):
    lines = [
        '// Reconstructed from node #115 (sha256 %s)' % SHA256,
        '// by tools/action_tag_serialize_115.py.  Variant order, serde names, unit payloads',
        '// and the niche layout are byte-checked; payload types are only named by variant.',
        '#[derive(Serialize)]',
        '#[serde(tag = "%s", rename_all = "camelCase")]' % spec['tag'],
        'pub enum %s {' % spec['enum'],
    ]
    first = copies[0]
    for i, rust in enumerate(spec['variants']):
        tag = 'dataful (any first word < %#x)' % spec['niche_base'] if rust == spec['dataful'] \
            else 'first word %#x' % (spec['niche_base'] + i)
        wire = wire_name(spec, rust)
        if wire != rust[0].lower() + rust[1:]:
            lines.append('    #[serde(rename = "%s")]' % wire)
        payload = rust + 'Action' if rust in spec['unit'] else rust + 'Payload'
        callee = first['arms'][first['entries'][i]][0][3]
        lines.append('    %s(%s), // index %d, %s, serializer %#x in copy %#x' % (
            rust, payload, i, tag, callee, first['start']))
    lines.append('}')
    for rust in sorted(spec['unit']):
        lines.append('pub struct %sAction; // unit struct, name emitted as the payload' % rust)
    return '\n'.join(lines) + '\n'


def build(root):
    path = os.path.join(root, BINARY)
    with open(path, 'rb') as f:
        data = f.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise SystemExit('binary sha256 mismatch: %s' % digest)
    img = Image(data)
    copies = [decode_copy(img, start) for start in COPIES]
    spec = default_spec()
    files = {}

    files['functions.tsv'] = tsv([('fde_start', 'fde_end', 'bytes', 'covered_bytes', 'form', 'niche_base',
                                   'default_index', 'table', 'arms', 'first_non_arm_entry_target', 'body_sha256')] + [
        ('%#x' % c['start'], '%#x' % c['end'], c['end'] - c['start'], c['covered'], c['form'], '%#x' % c['base'],
         c['default'], '%#x' % c['table'], len(c['entries']), '%#x' % c['stop_target'], c['sha256']) for c in copies])

    rows = [('fde_start', 'index', 'arm', 'enum', 'rust_variant', 'tag_key', 'wire_name', 'payload', 'unit_struct',
             'serializer_call', 'arm_insns')]
    for c in copies:
        for i, target in enumerate(c['entries']):
            (names, payload, unit, callee), path = c['arms'][target]
            rows.append(('%#x' % c['start'], i, '%#x' % target) + names + (payload, unit, '%#x' % callee, len(path)))
    files['arms.tsv'] = tsv(rows)

    rows = [('fde_start', 'tag_word', 'spec', 'bytes', 'match')]
    total = matched = 0
    for c in copies:
        for tag in tags_for(len(VARIANTS), SPEC['niche_base']):
            a, b = spec_serialize(spec, tag, c['start']), byte_serialize(img, c, tag)
            total += 1
            matched += a == b
            rows.append(('%#x' % c['start'], '%#x' % tag, '|'.join(map(str, a)), '|'.join(map(str, b)),
                         'yes' if a == b else 'NO'))
    files['cases.tsv'] = tsv(rows)

    rows = [('index', 'rust_variant', 'wire_name', 'rule', 'tag_word', 'payload', 'unit_struct',
             'payload_forms_across_copies', 'shares_serializer_with')]
    for i, rust in enumerate(VARIANTS):
        rule = 'rename' if rust in RENAMES else ('suffix-Action' if rust in SUFFIX_ACTION else 'camelCase')
        out = spec_serialize(spec, SPEC['niche_base'] + i if rust != SPEC['dataful'] else 0)
        forms = sorted({c['arms'][c['entries'][i]][0][1] for c in copies})
        share = sorted({VARIANTS[j] for c in copies for j, t in enumerate(c['entries'])
                        if j != i and c['arms'][t][0][3] == c['arms'][c['entries'][i]][0][3]})
        tag = '<%#x' % SPEC['niche_base'] if rust == SPEC['dataful'] else '%#x' % (SPEC['niche_base'] + i)
        rows.append((i, rust, out[4], rule, tag, out[5], out[6], ','.join(forms), ','.join(share) or '-'))
    files['variants.tsv'] = tsv(rows)

    baseline = compare(img, copies, spec)
    if baseline is not None:
        raise SystemExit('baseline reconstruction disagrees with the bytes at %#x tag %#x' % baseline)
    rows = [('mutant', 'result', 'detected_by'), ('baseline', 'matches', '-')]
    killed = 0
    smut = spec_mutants()
    for name, s in smut:
        res, why = judge(img, copies, s)
        killed += res == 'killed'
        rows.append((name, res, why))
    bmut = list(byte_mutants(img, COPIES[0]))
    for name, mimg in bmut:
        res, why = judge(img, copies, spec, mimg, COPIES[0])
        killed += res == 'killed'
        rows.append((name, res, why))
    files['mutants.tsv'] = tsv(rows)

    # One listed copy per distinct (prologue form, payload shapes) class; the others are
    # decoded and byte-covered the same way but not listed instruction by instruction.
    listed, seen = [], set()
    for c in copies:
        key = (c['form'], tuple(c['arms'][t][0][1] for t in c['entries']))
        if key not in seen:
            seen.add(key)
            listed.append(c)
    rows = [('fde_start', 'va', 'length', 'bytes', 'effect', 'used_by_indices')]
    for c in listed:
        rows.append(('%#x' % c['start'], '%#x' % c['start'], c['body'] - c['start'],
                     img.read(c['start'], c['body'] - c['start']).hex(), 'prologue-%s' % c['form'], 'all'))
        uses = {}
        for i, target in enumerate(c['entries']):
            for va, n in c['arms'][target][1]:
                uses.setdefault(va, (n, []))[1].append(i)
        for va in sorted(uses):
            n, idx = uses[va]
            eff = step(img.read(va, n), va)[1]
            rows.append(('%#x' % c['start'], '%#x' % va, n, img.read(va, n).hex(), effect_text(eff),
                         ','.join(map(str, idx))))
    files['insns.tsv'] = tsv(rows)

    files['action_enum.rs.txt'] = rust_enum(spec, copies)
    files['summary.json'] = json.dumps(dict(
        binary=BINARY, sha256=SHA256, copies=['%#x' % c for c in COPIES],
        variants=len(VARIANTS), arms_per_copy=[len(c['entries']) for c in copies],
        bytes_total=sum(c['end'] - c['start'] for c in copies), bytes_covered=sum(c['covered'] for c in copies),
        cases=total, cases_matched=matched, spec_mutants=len(smut), byte_mutants=len(bmut),
        mutants_killed=killed, rules=dict(camelCase=len(VARIANTS) - len(RENAMES) - len(SUFFIX_ACTION),
                                          suffix_action=len(SUFFIX_ACTION), renames=len(RENAMES)),
    ), indent=2, sort_keys=True) + '\n'
    return files, (matched == total and killed == len(smut) + len(bmut)
                   and all(c['covered'] == c['end'] - c['start'] for c in copies))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True)
    args = ap.parse_args(argv)
    files, ok = build(ROOT)
    os.makedirs(args.out, exist_ok=True)
    for name in sorted(files):
        with open(os.path.join(args.out, name), 'w', encoding='ascii', newline='\n') as f:
            f.write(files[name])
    if not ok:
        raise SystemExit('reconstruction does not match the bytes; see cases.tsv and mutants.tsv')


if __name__ == '__main__':
    main()
