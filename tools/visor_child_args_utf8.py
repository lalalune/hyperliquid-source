#!/usr/bin/env python3
"""RE-013: bind the complete static child-argument UTF-8 proof and support model.

This is not a concrete x86 interpreter or a general semantic-equivalence checker.
Every reviewed basic block is bound to target bytes/edges; PROOF.md supplies the
complete cursor/memory/grammar induction. Codec tests support the separate model.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT/'artifacts/visor/captured/hl-visor'
TARGET_SIZE = 8305392
TARGET_SHA256 = '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'
U64_END = 1 << 64
ISIZE_MAX = (1 << 63)-1
RANGES = {'validator':(0x49b560,0x49b757), 'adapter':(0x48dc00,0x48dc43)}
# Full reviewed encodings, successor sets and transfers, not a few selected guards.
REVIEWED_BLOCKS = {
    'validator': {
        0x49b560: (0x49b57e, '41574156534889f831ff4889d14883e90f480f43f94885d20f84a9010000', (0x49b57e, 0x49b727), 'I1/I2', 'save registers/output pointer; T=max(n-15,0); empty input -> success'),
        0x49b57e: (0x49b59e, '4c8d46074983e0f84929f031c94c8d15ec4ebeff49bb8080808080808080eb11', (0x49b5af,), 'I2/I3', 'alignment residue; cursor=0; classification table and high-bit mask; enter lead load'),
        0x49b59e: (0x49b5a0, '6690', (0x49b5a0,), 'I1', 'unreachable padding: identity XCHG AX,AX'),
        0x49b5a0: (0x49b5a6, '49ffc64c89f1', (0x49b5a6,), 'I3/I9', 'cursor=last_checked_index+1 after a valid multibyte sequence'),
        0x49b5a6: (0x49b5af, '4839d10f8378010000', (0x49b5af, 0x49b727), 'I3/I11', 'if cursor>=n -> success; invariant strengthens to cursor==n'),
        0x49b5af: (0x49b5b7, '0fb61c0e84db7859', (0x49b5b7, 0x49b610), 'I3/I7', 'load current lead; high-bit branch selects ASCII versus multibyte'),
        0x49b5b7: (0x49b5c3, '4589c14129c941f6c1077411', (0x49b5c3, 0x49b5d4), 'I4', 'alignment residue check uses low3 bits only'),
        0x49b5c3: (0x49b5c8, '48ffc1ebde', (0x49b5a6,), 'I3/I4', 'known ASCII byte advances cursor by1'),
        0x49b5c8: (0x49b5d0, '0f1f840000000000', (0x49b5d0,), 'I1', 'unreachable padding NOP'),
        0x49b5d0: (0x49b5d4, '4883c110', (0x49b5d4,), 'I3/I5', 'proved16 ASCII bytes advance cursor by16'),
        0x49b5d4: (0x49b5d9, '4839f9730e', (0x49b5d9, 0x49b5e7), 'I5', 'bulk read only if cursor<T'),
        0x49b5d9: (0x49b5e7, '4c8b4c0e084c0b0c0e4d85d974e9', (0x49b5e7, 0x49b5d0), 'I5', 'two8-byte loads OR and high-bit mask; allzero iff16 ASCII bytes'),
        0x49b5e7: (0x49b5ec, '4839d173ba', (0x49b5ec, 0x49b5a6), 'I3/I6', 'tail cursor bound; no read if cursor>=n'),
        0x49b5ec: (0x49b5f0, '0f1f4000', (0x49b5f0,), 'I1/I6', 'reachable identity NOP before tail'),
        0x49b5f0: (0x49b5f6, '803c0e0078b0', (0x49b5f6, 0x49b5a6), 'I6', 'negative byte hands unchanged cursor to multibyte dispatch'),
        0x49b5f6: (0x49b5fe, '48ffc14839ca75f2', (0x49b5fe, 0x49b5f0), 'I3/I6', 'ASCII tail byte advances cursor; repeat until n'),
        0x49b5fe: (0x49b603, 'e924010000', (0x49b727,), 'I6/I11', 'tail exhausted -> success'),
        0x49b603: (0x49b610, '666666662e0f1f840000000000', (0x49b610,), 'I1', 'unreachable prefix-NOP padding'),
        0x49b610: (0x49b61e, '460fb6341341b1014183fe04745d', (0x49b61e, 0x49b67b), 'I7/I10', 'read lead width; error-width-present flag=1; width4 dispatch'),
        0x49b61e: (0x49b624, '4183fe037429', (0x49b624, 0x49b64d), 'I7', 'width3 dispatch'),
        0x49b624: (0x49b62e, '4183fe020f850a010000', (0x49b62e, 0x49b738), 'I7/I10', 'width2 dispatch; other nonASCII lead -> invalid width1'),
        0x49b62e: (0x49b63b, '4c8d71014939d60f83f8000000', (0x49b63b, 0x49b733), 'I8', '2-byte second-byte bound; absent -> incomplete'),
        0x49b63b: (0x49b648, '42803c36bfb3010f8e58ffffff', (0x49b648, 0x49b5a0), 'I8/I9/I10', '2-byte continuation signed<=BF; accepted last index i+1; error width1 set'),
        0x49b648: (0x49b64d, 'e9f1000000', (0x49b73e,), 'I10', 'invalid second byte -> defined error protocol'),
        0x49b64d: (0x49b65a, '4c8d71014939d60f83d9000000', (0x49b65a, 0x49b733), 'I8', '3-byte second-byte bound; absent -> incomplete'),
        0x49b65a: (0x49b668, '460fb634364881fbe00000007441', (0x49b668, 0x49b6a9), 'I8', 'load second; E0 special case dispatch'),
        0x49b668: (0x49b670, '81fbed0000007554', (0x49b670, 0x49b6c4), 'I8', 'ED special case dispatch'),
        0x49b670: (0x49b676, '4180fe9f7e66', (0x49b676, 0x49b6dc), 'I8', 'ED second signed<=9F ->80..9F'),
        0x49b676: (0x49b67b, 'e9bd000000', (0x49b738,), 'I10', 'invalid ED second -> error width1'),
        0x49b67b: (0x49b688, '4c8d71014939d60f83ab000000', (0x49b688, 0x49b733), 'I8', '4-byte second-byte bound; absent -> incomplete'),
        0x49b688: (0x49b696, '460fb634364881fbf00000007422', (0x49b696, 0x49b6b8), 'I8', 'load second; F0 special case dispatch'),
        0x49b696: (0x49b69e, '81fbf40000007554', (0x49b69e, 0x49b6f2), 'I8', 'F4 special case dispatch'),
        0x49b69e: (0x49b6a4, '4180fe8f7e5c', (0x49b6a4, 0x49b700), 'I8', 'F4 second signed<=8F ->80..8F'),
        0x49b6a4: (0x49b6a9, 'e98f000000', (0x49b738,), 'I10', 'invalid F4 second -> error width1'),
        0x49b6a9: (0x49b6b3, '4180e6e04180fea07429', (0x49b6b3, 0x49b6dc), 'I8', 'E0 second AND E0==A0 ->A0..BF'),
        0x49b6b3: (0x49b6b8, 'e980000000', (0x49b738,), 'I10', 'invalid E0 second -> error width1'),
        0x49b6b8: (0x49b6c2, '4180c6704180fe30723e', (0x49b6c2, 0x49b700), 'I8', 'F0 (second+70) mod256<30 ->90..BF'),
        0x49b6c2: (0x49b6c4, 'eb74', (0x49b738,), 'I10', 'invalid F0 second -> error width1'),
        0x49b6c4: (0x49b6ce, '448d7b1f4180ff0c7208', (0x49b6ce, 0x49b6d6), 'I8', 'generic3 lead (lead+1F) mod256<0C ->E1..EC'),
        0x49b6ce: (0x49b6d6, '80e3fe80fbee7562', (0x49b6d6, 0x49b738), 'I8', 'generic3 alternative (lead AND FE)==EE ->EE/EF'),
        0x49b6d6: (0x49b6dc, '4180fec07d5c', (0x49b6dc, 0x49b738), 'I8', 'generic3 second signed<C0 ->80..BF'),
        0x49b6dc: (0x49b6e5, '4c8d71024939d6734e', (0x49b6e5, 0x49b733), 'I8', '3-byte third-byte bound; absent -> incomplete'),
        0x49b6e5: (0x49b6f0, '42803c36bf0f8eb0feffff', (0x49b6f0, 0x49b5a0), 'I8/I9', 'third signed<=BF ->80..BF; accepted last index i+2'),
        0x49b6f0: (0x49b6f2, 'eb4a', (0x49b73c,), 'I10', 'invalid third -> error width2'),
        0x49b6f2: (0x49b6fa, '80c30f80fb02773e', (0x49b6fa, 0x49b738), 'I8', 'generic4 lead (lead+0F) mod256<=2 ->F1..F3'),
        0x49b6fa: (0x49b700, '4180fec07d38', (0x49b700, 0x49b738), 'I8', 'generic4 second signed<C0 ->80..BF'),
        0x49b700: (0x49b709, '488d59024839d3732a', (0x49b709, 0x49b733), 'I8', '4-byte third-byte bound; absent -> incomplete'),
        0x49b709: (0x49b70f, '803c1ebf7f2d', (0x49b70f, 0x49b73c), 'I8/I10', 'third signed<=BF ->80..BF; else error width2'),
        0x49b70f: (0x49b718, '4c8d71034939d6731b', (0x49b718, 0x49b733), 'I8', '4-byte fourth-byte bound; absent -> incomplete'),
        0x49b718: (0x49b723, '42803c36c00f8c7dfeffff', (0x49b723, 0x49b5a0), 'I8/I9', 'fourth signed<C0 ->80..BF; accepted last index i+3'),
        0x49b723: (0x49b727, 'b303eb17', (0x49b73e,), 'I10', 'invalid fourth sets error width3'),
        0x49b727: (0x49b733, '488970084889501031c9eb1b', (0x49b74e,), 'I11', 'success stores original pointer/length and tag0'),
        0x49b733: (0x49b738, '4531c9eb06', (0x49b73e,), 'I10', 'incomplete clears presence flag; byte17 remains unqualified'),
        0x49b738: (0x49b73c, 'b301eb02', (0x49b73e,), 'I10', 'invalid lead or second sets error width1'),
        0x49b73c: (0x49b73e, 'b302', (0x49b73e,), 'I10', 'invalid third sets error width2'),
        0x49b73e: (0x49b74e, '4889480844884810885811b901000000', (0x49b74e,), 'I10', 'error stores valid-prefix cursor, presence flag, conditional width, tag1'),
        0x49b74e: (0x49b757, '4889085b415e415fc3', (), 'I2/I10/I11', 'store tag; restore registers; sole RET with RAX=output pointer'),
    },
    'adapter': {
        0x48dc00: (0x48dc15, '4883ec18488b7708488b57104889e7ff1513713500', (0x48dc15,), 'I12/I13', 'load pointer/length and call bound validator'),
        0x48dc15: (0x48dc1b, '833c2401740f', (0x48dc1b, 0x48dc2a), 'I12/I13', 'tag1 selects external diagnostic route'),
        0x48dc1b: (0x48dc2a, '488b442408488b5424104883c418c3', (), 'I12/I13', 'return validated original pointer/length'),
        0x48dc2a: (0x48dc43, '488d3d1112bfff488d1590923200be23000000ff1575703500', (0x48dc43,), 'I12/I13', 'diagnostic call; normal fallthrough outside owned range remains open'),
    },
}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _s8(value):
    return value if value < 128 else value-256


def overlaps(a, z, b, y):
    return max(a,b) < min(z,y)


def domain_arithmetic(p, n, q, stack, protected):
    """Check interval premises only; permissions/immutability/call state are assumed."""
    require(all(isinstance(x,int) and not isinstance(x,bool) for x in (p,n,q,stack)),
            'domain values must be integers')
    require(0 <= n <= ISIZE_MAX and 0 <= p < U64_END and p+n <= U64_END,
            'input interval wraps or exceeds the stated length domain')
    require(0 <= q and q+24 <= U64_END and 24 <= stack and stack+8 <= U64_END,
            'result or active stack/return interval wraps')
    frame = (stack-24,stack+8)
    require(not overlaps(q,q+24,*frame), 'result overlaps active stack or return slot')
    require(not overlaps(p,p+n,q,q+24) and not overlaps(p,p+n,*frame),
            'input overlaps result or active stack/return interval')
    for a,z in protected:
        require(0 <= a <= z <= U64_END, 'protected interval wraps')
        require(not overlaps(q,q+24,a,z) and not overlaps(*frame,a,z),
                'writable result/stack overlaps immutable image')
    return {'input':[p,p+n], 'result':[q,q+24], 'active_stack_and_return':list(frame),
            'arithmetic_nonalias_checks':True,
            'permissions_immutability_and_valid_call_return_state_checked':False}


def adapter_domain_arithmetic(p, n, stack, protected):
    require(isinstance(stack,int) and not isinstance(stack,bool)
            and stack >= 56 and stack+8 <= U64_END, 'adapter stack interval wraps')
    require(stack % 16 == 8, 'used adapter requires ordinary entry stack alignment')
    result = domain_arithmetic(p,n,stack-24,stack-32,protected)
    require(not overlaps(p,p+n,stack-56,stack+8), 'input overlaps combined adapter stack/return interval')
    require(all(not overlaps(stack-56,stack+8,a,z) for a,z in protected),
            'adapter stack overlaps immutable image')
    return {**result,'combined_adapter_stack_and_return':[stack-56,stack+8],
            'descriptor_fields_readable_and_ordinary_call_state_assumed':True}


def native_rows(raw, start, end, name, version):
    argv = ['objdump','-D','-b','binary','-m','i386:x86-64','-M','intel',
            '--insn-width=16','--adjust-vma='+hex(start),name+'.bin']
    with tempfile.TemporaryDirectory(prefix='vutf8-') as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        path = directory/(name+'.bin')
        path.write_bytes(raw)
        path.chmod(0o400)
        require(path.read_bytes() == raw, 'private native input differs before decoding')
        result = subprocess.run(argv,cwd=directory,capture_output=True,check=True)
        require(path.read_bytes() == raw, 'private native input differs after decoding')
        require(not result.stderr, 'unexpected GNU diagnostic')
    rows = []
    for line in result.stdout.decode().splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$',line)
        if match:
            address,body = int(match[1],16),bytes.fromhex(match[2])
            require(start <= address and address+len(body) <= end,'native row leaves owned span')
            require(raw[address-start:address-start+len(body)] == body,'native row bytes differ from admitted input')
            rows.append({'va':hex(address),'hex':body.hex(),'asm':match[3]})
    require(rows and int(rows[0]['va'],16) == start
            and int(rows[-1]['va'],16)+len(bytes.fromhex(rows[-1]['hex'])) == end,
            'native endpoints differ')
    require(all(int(a['va'],16)+len(bytes.fromhex(a['hex'])) == int(b['va'],16)
                for a,b in zip(rows,rows[1:])), 'native gap/overlap')
    method = {'tool':version,'argv':argv,'input_bytes':len(raw),'input_sha256':sha(raw),
              'format':'private raw binary with explicit x86-64 and linked VA',
              'original_ELF_path_reopened':False,'stdout_bytes':len(result.stdout),
              'stdout_sha256':sha(result.stdout)}
    return rows,result.stdout,method


def graph_and_blocks(rows, start, end):
    leaders = {start}
    edges,branches,calls,returns = {},[],[],[]
    prefixes = {'rep','repz','repnz','bnd','notrack','lock','data16','addr32','cs','ds','es','fs','gs','ss'}
    for row in rows:
        address,raw = int(row['va'],16),bytes.fromhex(row['hex'])
        following = address+len(raw)
        words = row['asm'].split()
        while words and words[0] in prefixes:
            words.pop(0)
        mnemonic = words[0] if words else ''
        if raw == b'\xc3':
            successors = []
            returns.append(address)
            leaders.add(following)
        elif (raw[0] in (0xe9,0xeb) or 0x70 <= raw[0] <= 0x7f
              or raw[0] == 0x0f and len(raw)>1 and 0x80 <= raw[1] <= 0x8f):
            offset = 2 if raw[0] == 0x0f else 1
            require(len(raw)-offset in (1,4),'unsupported relative branch')
            target = following+int.from_bytes(raw[offset:],'little',signed=True)
            conditional = raw[0] not in (0xe9,0xeb)
            successors = [following,target] if conditional else [target]
            branches.append({'site':hex(address),'target':hex(target),'conditional':conditional})
            leaders.update([following,target])
        elif mnemonic.startswith('call'):
            require(raw[:2] == b'\xff\x15','unsupported call encoding in owned bodies')
            slot = following+struct.unpack_from('<i',raw,2)[0]
            calls.append({'site':hex(address),'slot':hex(slot),'normal_return_edge':hex(following)})
            successors = [following]
            leaders.add(following)
        else:
            require(not mnemonic.startswith(('ret','iret','j','loop','int','sys','hlt','ud2','xbegin','xend')),
                    'unclassified control transfer')
            successors = [following]
        edges[address] = successors
    require(all(t in edges or t == end for ts in edges.values() for t in ts),
            'control edge leaves decoded boundaries')
    leaders = sorted(a for a in leaders if a < end)
    blocks = []
    for a,z in zip(leaders,leaders[1:]+[end]):
        members = [r for r in rows if a <= int(r['va'],16) < z]
        require(members and int(members[0]['va'],16)==a,'block start is not an instruction')
        blocks.append({'start':hex(a),'end':hex(z),'hex':''.join(r['hex'] for r in members),
                       'instructions':len(members),
                       'successors':[hex(t) for t in edges[int(members[-1]['va'],16)]]})
    reached,todo = set(),[start]
    while todo:
        address = todo.pop()
        if address in edges and address not in reached:
            reached.add(address)
            todo.extend(edges[address])
    return {'branches':branches,'calls':calls,'returns':[hex(a) for a in returns],
            'edges':{hex(a):[hex(t) for t in ts] for a,ts in edges.items()},
            'blocks':blocks,'decoded_instructions':len(rows),'reachable_instruction_nodes':len(reached),
            'unreachable_padding':[r['va'] for r in rows if int(r['va'],16) not in reached],
            'open_normal_boundaries':sorted({hex(t) for ts in edges.values() for t in ts if t==end})}


def bind_reviewed_blocks(kind, graph):
    expected = REVIEWED_BLOCKS[kind]
    actual = {int(b['start'],16):b for b in graph['blocks']}
    require(set(actual)==set(expected),'complete reviewed block domain differs')
    for start,(end,encoded,successors,obligations,transfer) in expected.items():
        block = actual[start]
        require((int(block['end'],16),block['hex'],tuple(int(t,16) for t in block['successors']))
                == (end,encoded,successors),f'complete semantic block binding differs at {start:#x}')
        block['obligations'] = obligations
        block['reviewed_transfer'] = transfer
    require(sum(b['instructions'] for b in graph['blocks']) == graph['decoded_instructions'],
            'instruction omitted from complete block ledger')


def byte_predicates(read):
    points = [('cont2',0x49b63f),('ed',0x49b673),('f4',0x49b6a1),
              ('e0_mask',0x49b6ac),('e0_cmp',0x49b6b0),('f0_add',0x49b6bb),('f0_cmp',0x49b6bf),
              ('generic3_add',0x49b6c7),('generic3_count',0x49b6cb),('generic3_mask',0x49b6d0),
              ('generic3_cmp',0x49b6d3),('generic3_second',0x49b6d9),('third3',0x49b6e9),
              ('generic4_add',0x49b6f4),('generic4_count',0x49b6f7),('generic4_second',0x49b6fd),
              ('third4',0x49b70c),('fourth4',0x49b71c)]
    operands = {name:{'site':hex(a),'value':read(a,1)[1][0]} for name,a in points}
    v = {name:row['value'] for name,row in operands.items()}
    sets = {
        'cont2':[x for x in range(256) if _s8(x)<=_s8(v['cont2'])],
        'ed':[x for x in range(256) if _s8(x)<=_s8(v['ed'])],
        'f4':[x for x in range(256) if _s8(x)<=_s8(v['f4'])],
        'e0':[x for x in range(256) if x&v['e0_mask']==v['e0_cmp']],
        'f0':[x for x in range(256) if ((x+v['f0_add'])&255)<v['f0_cmp']],
        'generic3_second':[x for x in range(256) if _s8(x)<_s8(v['generic3_second'])],
        'third3':[x for x in range(256) if _s8(x)<=_s8(v['third3'])],
        'generic4_second':[x for x in range(256) if _s8(x)<_s8(v['generic4_second'])],
        'third4':[x for x in range(256) if _s8(x)<=_s8(v['third4'])],
        'fourth4':[x for x in range(256) if _s8(x)<_s8(v['fourth4'])],
        'generic3_leads':[x for x in range(256) if ((x+v['generic3_add'])&255)<v['generic3_count']
                          or x&v['generic3_mask']==v['generic3_cmp']],
        'generic4_leads':[x for x in range(256) if ((x+v['generic4_add'])&255)<=v['generic4_count']],
    }
    continuation = list(range(0x80,0xc0))
    spec = {'cont2':continuation,'ed':list(range(0x80,0xa0)),'f4':list(range(0x80,0x90)),
            'e0':list(range(0xa0,0xc0)),'f0':list(range(0x90,0xc0)),
            'generic3_second':continuation,'third3':continuation,
            'generic4_second':continuation,'third4':continuation,'fourth4':continuation,
            'generic3_leads':list(range(0xe1,0xed))+[0xee,0xef],
            'generic4_leads':list(range(0xf1,0xf4))}
    require(sets==spec,'extracted finite predicates differ from strict UTF-8 classes')
    return {'operands':operands,'sets':sets,'all256ByteValuesCheckedPerPredicate':True,
            'wholePredicateEstablishedByTheseSetsAlone':False}


def contract_model(payload, table, predicates):
    """Independent high-level byte-class model, not captured-code execution/parity."""
    i,n = 0,len(payload)
    def error(present,width):
        return {'tag':1,'valid_prefix':i,'width_present':present,'error_width':width}
    while i < n:
        lead = payload[i]
        if lead < 0x80:
            i += 1
            continue
        width = table[lead]
        if width not in (2,3,4):
            return error(1,1)
        if i+1 >= n:
            return error(0,None)
        second = payload[i+1]
        if width == 2:
            allowed = predicates['cont2']
        elif width == 3:
            allowed = predicates['e0'] if lead==0xe0 else predicates['ed'] if lead==0xed else (
                predicates['generic3_second'] if lead in predicates['generic3_leads'] else [])
        else:
            allowed = predicates['f0'] if lead==0xf0 else predicates['f4'] if lead==0xf4 else (
                predicates['generic4_second'] if lead in predicates['generic4_leads'] else [])
        if second not in allowed:
            return error(1,1)
        if width >= 3:
            if i+2 >= n:
                return error(0,None)
            if payload[i+2] not in predicates['third3' if width==3 else 'third4']:
                return error(1,2)
        if width == 4:
            if i+3 >= n:
                return error(0,None)
            if payload[i+3] not in predicates['fourth4']:
                return error(1,3)
        i += width
    return {'tag':0,'input_length':n,'same_input_span':True}


def _derive(data):
    """Private target-grounded counterfactual seam; collect() also pins full input."""
    secs = sections(data)
    def read(address,size):
        matches = [s for s in secs if s['type']!=8 and s['address']<=address
                   and address+size<=s['address']+s['size']]
        require(len(matches)==1,'UTF8 span is not uniquely file-backed')
        offset = matches[0]['offset']+address-matches[0]['address']
        return offset,data[offset:offset+size]
    def window(address,size):
        offset,raw = read(address,size)
        return {'va':hex(address),'file_offset':offset,'bytes':size,'hex':raw.hex(),'sha256':sha(raw)}
    def expect(address,encoded,message):
        require(read(address,len(bytes.fromhex(encoded)))[1]==bytes.fromhex(encoded),message)
    _,fdes,_ = fde_extents(data)
    version = subprocess.run(['objdump','--version'],capture_output=True,check=True).stdout.decode().splitlines()[0]
    require(version.startswith('GNU objdump'),'GNU objdump is required')
    ranges,graphs,instructions,exports,methods = {},{},{},{},{}
    for kind,(start,end) in RANGES.items():
        found = [f for f in fdes if f['start']==start]
        require(len(found)==1 and found[0]['end']==end,'UTF8 FDE extent differs')
        ranges[kind] = {**window(start,end-start),'end':hex(end),'fde_va':hex(found[0]['fde']),
                        'cie_va':hex(found[0]['cie']),'lsda_va':found[0]['lsda']}
        rows,native,method = native_rows(read(start,end-start)[1],start,end,kind,version)
        graph = graph_and_blocks(rows,start,end)
        bind_reviewed_blocks(kind,graph)
        ranges[kind]['complete_block_count'] = len(graph['blocks'])
        graphs[kind],instructions[kind],exports[kind+'.objdump.txt'],methods[kind] = graph,rows,native,method
    validator = graphs['validator']
    require(not validator['calls'] and validator['returns']==['0x49b756']
            and not validator['open_normal_boundaries'],'validator normal control domain differs')
    require((validator['decoded_instructions'],validator['reachable_instruction_nodes'])==(143,140)
            and validator['unreachable_padding']==['0x49b59e','0x49b5c8','0x49b603'],
            'complete validator instruction/padding domain differs')
    require(graphs['adapter']['returns']==['0x48dc29']
            and graphs['adapter']['open_normal_boundaries']==['0x48dc43'],
            'adapter success/error boundary differs')
    table_offset,table_raw = read(0x8047e,256)
    table = list(table_raw)
    expected_used = [0 if b<0xc2 or b>0xf4 else 2 if b<=0xdf else 3 if b<=0xef else 4
                     for b in range(0x80,0x100)]
    require(table[0x80:]==expected_used,'used nonASCII lead widths differ from strict UTF-8')
    predicates = byte_predicates(read)

    # Every cursor write, persistent-register fact and output store belongs to
    # the full reviewed block proof. These inventories do not execute instructions.
    cursor_writes = [0x49b56a,0x49b56d,0x49b589,0x49b5a3,0x49b5c3,0x49b5d0,
                     0x49b5f6,0x49b72f,0x49b749]
    actual_cursor = []
    writing = {'mov','movabs','movzx','lea','xor','add','sub','and','or','inc','dec','cmovae','pop','xchg'}
    for row in instructions['validator']:
        words = row['asm'].split(None,1)
        if len(words)==2 and words[0] in writing:
            destination = words[1].split(',')[0].strip()
            if destination in ('rcx','ecx','cx','cl'):
                actual_cursor.append(int(row['va'],16))
    require(actual_cursor==cursor_writes,'unaccounted cursor write in complete body')
    chunk = read(0x49b5d3,1)[1][0]
    subtract = read(0x49b570,1)[1][0]
    alignment_mask = read(0x49b5c0,1)[1][0]
    checked_offsets = [read(a,1)[1][0] for a in (0x49b631,0x49b650,0x49b67e,
                                               0x49b6df,0x49b703,0x49b712)]
    require((chunk,subtract,alignment_mask,sorted(set(checked_offsets)))==(16,15,7,[1,2,3]),
            'cursor/bulk bound operands differ')
    loop_facts = {'entry_cursor':0,'length_max':ISIZE_MAX,'max_checked_offset':max(checked_offsets),
                  'ASCII_chunk_bytes':chunk,'ASCII_threshold_subtract':subtract,
                  'ASCII_alignment_modulus':alignment_mask+1,'full64_cursor_increments':[1,chunk],
                  'multibyte_join_steps':[x+1 for x in sorted(set(checked_offsets))],
                  'bulk_bound_identity':subtract==chunk-1,
                  'largest_cursor_plus_checked_offset_below_u64':ISIZE_MAX+max(checked_offsets)<U64_END,
                  'alignment_low3_survives_32bit_truncation':(1<<32)%(alignment_mask+1)==0,
                  'proof':'I3-I11 in PROOF.md, every block/edge bound above; no codec sample is a loop proof'}

    reloc_section = next(s for s in secs if s['name']=='.rela.dyn')
    require(reloc_section['size']%24==0,'RELA table stride differs')
    relocs = {}
    for offset in range(reloc_section['offset'],reloc_section['offset']+reloc_section['size'],24):
        slot,info,addend = struct.unpack_from('<QQq',data,offset)
        require(slot not in relocs,'duplicate relocation slot')
        relocs[slot] = {'slot':hex(slot),'type':info&0xffffffff,'symbol':info>>32,
                        'addend':hex(addend),'file_offset':offset}
    selected = []
    for slot,target in ((0x7e4d28,0x49b560),(0x7e4cb8,0x49ab50),(0x7e6aa0,0x48dc00)):
        row = relocs.get(slot)
        require(row is not None and (row['type'],row['symbol'],row['addend'])==(8,0,hex(target)),
                'used adapter/validator/error binding differs')
        selected.append(row)
    require(graphs['adapter']['calls']==[
        {'site':'0x48dc0f','slot':'0x7e4d28','normal_return_edge':'0x48dc15'},
        {'site':'0x48dc3d','slot':'0x7e4cb8','normal_return_edge':'0x48dc43'}],
        'adapter call slots differ')
    expect(0x5b920a,'498b41e8498b49f0488d0c49488d0cc8488944241848894c2420488b0575d8220048894424284889e7488d742418e8d3470600','upstream descriptor/collection call differs')
    expect(0x61da1e,'4889fb4c8b264c8b6e084d39ec74274c8b76104c89e741ffd6','first callback argument/dispatch differs')
    expect(0x61da7d,'4c89742440','saved callback slot differs')
    expect(0x61db85,'4989c64a8d3c22ff542440','later callback argument/dispatch differs')
    diagnostic = read(0x7ee42,35)[1]
    require(diagnostic==b'unexpected invalid UTF-8 code point','adapter diagnostic differs')
    location = read(0x7b6ec8,24)[1]
    length,line,column = struct.unpack_from('<QII',location,8)
    path_reloc = relocs.get(0x7b6ec8)
    require(path_reloc is not None and (path_reloc['type'],path_reloc['symbol'])==(8,0)
            and (length,line,column)==(66,220,28),'adapter Location binding differs')
    path_address = int(path_reloc['addend'],16)
    path_offset,path = read(path_address,length)
    require(path.endswith(b'z_vendor/clap/src/args/arg_matches.rs'),'adapter source suffix differs')
    protected = [(s['address'],s['address']+s['size']) for s in secs if s['flags']&4 and s['size']]
    protected += [(0x8047e,0x8057e),(0x7e4d28,0x7e4d30),(0x7e4cb8,0x7e4cc0),
                  (0x7e6aa0,0x7e6aa8),(0x7ee42,0x7ee65),(0x7b6ec8,0x7b6ee0),
                  (path_address,path_address+length)]
    result = {
        'schema':1,'task':'RE-013','component':'visor',
        'target':{'bytes':len(data),'sha256':sha(data)},
        'coordinates':'linked ELF VAs, with file offsets; ordinary correctly relocated image assumed',
        'ranges':ranges,'native_methods':methods,'instructions':instructions,'graphs':graphs,
        'lead_table':{'va':'0x8047e','file_offset':table_offset,'bytes':256,'sha256':sha(table_raw),
                      'entries':table,'ASCII_half_is_recorded_but_bypassed_by_ASCII_dispatch':True},
        'finite_predicate_support':predicates,'cursor_write_sites':[hex(a) for a in cursor_writes],
        'loop_lemmas':loop_facts,
        'proof_method':{'kind':'complete static basic-block/cursor/memory induction in PROOF.md',
                        'all_validator_blocks_bound':57,'all_adapter_blocks_bound':4,
                        'all_validator_instructions_bound':143,
                        'automatic_general_machine_semantic_verifier':False,
                        'high_level_model_or_codec_agreement_is_target_execution_or_equivalence':False,
                        'publication_requires_independent_complete_proof_and_source_review':True},
        'domain':{'length':'0<=n<=2^63-1','input':'immutable readable nonwrapping[p,p+n); no input read for n=0',
                  'result':'writable nonwrapping[q,q+24)',
                  'direct_stack':'entryS: valid saves[S-24,S), return slot[S,S+8); q and B disjoint full[S-24,S+8)',
                  'alias':'B disjoint q; result and active stack disjoint immutable captured code/table/bindings',
                  'used_adapter_stack':'entrySa: B disjoint full[Sa-56,Sa+8), q=[Sa-24,Sa), ordinary entrySa mod16=8',
                  'ordinary_return_state':'valid ordinary call/return-state contents assumed, not established by interval readability',
                  'theorem_endpoint':'finite arrival at local validator RET0x49b756 with defined result protocol; actual hardware return needs ordinary call state',
                  'protected_image_intervals':[[hex(a),hex(z)] for a,z in protected],
                  'memory_permissions_immutability_and_hardware_return_state_not_runtime_checked':True},
        'defined_result_protocol':{
            'success':{'qword0':0,'qword8':'original input pointer','qword16':'original input length','RAX':'original result pointer'},
            'invalid':{'qword0':1,'qword8':'first invalid/incomplete sequence start',
                       'byte16':1,'byte17':'defined error width1/2/3','bytes18to23':'unqualified'},
            'incomplete':{'qword0':1,'qword8':'incomplete sequence start','byte16':0,
                          'byte17':'unqualified','bytes18to23':'unqualified'},
            'input_unchanged':'under stated nonalias/immutable-region domain',
            'private_Rust_result_layout_claimed':False},
        'used_bindings':selected,
        'caller_witness':{'prior_PR':988,'prior_head':'0e24c1be56d8bfcfaa58951f4e263a7fee024b6a',
                          'upstream_descriptor_and_call':window(0x5b920a,51),
                          'first_argument_and_dispatch':window(0x61da1e,25),'save_callback':window(0x61da7d,5),
                          'later_argument_and_dispatch':window(0x61db85,11),
                          'revisited_witness_bytes':92,
                          'assumptions':'valid descriptor/frame and normal callee-saved ABI; complete collection semantics unclosed'},
        'adapter_error_boundary':{'diagnostic':window(0x7ee42,35),'Location':window(0x7b6ec8,24),
                                  'path':{'va':hex(path_address),'file_offset':path_offset,'bytes':length,
                                          'sha256':sha(path),'display_suffix':'z_vendor/clap/src/args/arg_matches.rs'},
                                  'line':line,'column':column,'external_helper':'0x49ab50',
                                  'normal_fallthrough_if_helper_returns':'0x48dc43',
                                  'panic_noreturn_process_or_posthelper_memory_effects_proved':False},
        'limits':['Static proof under the explicit domain, not arbitrary machine states or a general formal verifier.',
                  'The high-level model is not a concrete x86 interpreter, emulator or captured-code oracle.',
                  'No whole collection ownership/order, private Vec/str/result ABI, public CLI grammar, spawn or lifecycle policy.',
                  'No captured execution, Rust build/reconstruction, binary equivalence, function coverage or accepted gate.'],
    }
    return result,exports


def collect(data):
    require(len(data)==TARGET_SIZE and sha(data)==TARGET_SHA256,'captured visor identity differs')
    return _derive(data)


def build(data):
    return collect(data)[0]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=TARGET)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    result = build(args.binary.read_bytes())
    with args.output.open('x',encoding='utf-8',newline='\n') as output:
        output.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':'COMPLETE_STATIC_PROOF_BINDINGS_PASS',
                      'validator_blocks':57,'validator_instructions':143,
                      'code_executed_or_emulated':False,'general_machine_equivalence_claim':False}))
