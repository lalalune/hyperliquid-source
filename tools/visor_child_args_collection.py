#!/usr/bin/env python3
"""Bind visor's conditional child-argument collection proof, never execute it.

The complete normal-path induction is in PROOF.md. Opaque allocation/copy/ABI
postconditions are explicit. The high-level schedule model is support only,
not an x86 interpreter or automatic machine-equivalence verifier.
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
START,END = 0x61da10,0x61dd6c
U64_END,ISIZE_MAX = 1 << 64,(1 << 63)-1
# Full raw block bindings preserve context; only C1-C12 prove the stated domain.
REVIEWED_BLOCKS = {
    0x61da10: (0x61da2d, '554157415641554154534883ec484889fb4c8b264c8b6e084d39ec7427', (6412845, 6412884), 'C1/C2', 'save frame/output; load fixed interval; empty interval selects empty result'),
    0x61da2d: (0x61da37, '4c8b76104c89e741ffd6', (6412855,), 'C3', 'load callback and call it with first descriptor pointer'),
    0x61da37: (0x61da3c, '4885c07418', (6412860, 6412884), 'C3', 'zero callback pointer selects empty result before length inspection'),
    0x61da3c: (0x61da49, '4989d7498d5424184d85ff7934', (6412873, 6412925), 'C3/C4', 'save first length; next descriptor=start+24; negative length outside normal domain'),
    0x61da49: (0x61da54, '31ff4c89feff15ec701c00', (6412884,), 'OPEN', 'external negative-length error call; normal fallthrough recorded, no noreturn assumption'),
    0x61da54: (0x61da6b, '48c7030000000048c743080800000048c7431000000000', (6412907,), 'C2', 'write raw empty output words(0,8,0)'),
    0x61da6b: (0x61da7d, '4889d84883c4485b415c415d415e415f5dc3', (), 'C2/C11', 'return original output address; restore complete local frame'),
    0x61da7d: (0x61da89, '4c897424404889542428742e', (6412937, 6412983), 'C4', 'save callback/next pointer; flags from original length test select zero length'),
    0x61da89: (0x61da95, '4989c64c89ffff15cb701c00', (6412949,), 'C4', 'retain first source pointer; allocator request equals first positive length'),
    0x61da95: (0x61da9e, '4885c00f8405020000', (6412958, 6413475), 'C4', 'null allocation is outside normal resource contract'),
    0x61da9e: (0x61dab0, '4889c54889c74c89f64c89faff15b8701c00', (6412976,), 'C4', 'save fresh payload pointer; memcpy(fresh,source,length)'),
    0x61dab0: (0x61dab7, '498d542418eb05', (6412988,), 'C4', 'restore next descriptor pointer after copy'),
    0x61dab7: (0x61dabc, 'bd01000000', (6412988,), 'C4', 'nonzero callback with zero length uses raw pointer word1 without allocation/copy'),
    0x61dabc: (0x61db00, '4c89e84829d04889c148c1e90348beabaaaaaaaaaaaaaa480fafce4883f90441be030000004c0f43f14a8d0cf508000000488d344948b9e0ffffffffffff7f4839c8760d', (6413056, 6413069), 'C5', 'derive initial request from remaining24B interval: inverse3 after SHR3, min3+1 slots'),
    0x61db00: (0x61db02, '31ff', (6413058,), 'OPEN', 'oversize request error preparation, excluded by valid fixed-interval arithmetic'),
    0x61db02: (0x61db08, 'ff1538701c00', (6413064,), 'OPEN', 'external allocation/size error call; normal return edge retained'),
    0x61db08: (0x61db0d, 'e9ca010000', (6413527,), 'OPEN', 'if that external error call returns this route reaches UD2'),
    0x61db0d: (0x61db12, '4885f67420', (6413074, 6413106), 'C5', 'request24*C is positive under C=max(4,N), so zero-size route excluded'),
    0x61db12: (0x61db1f, '488934244889f7ff1541701c00', (6413087,), 'C5', 'allocate initial record storage for request24*C'),
    0x61db1f: (0x61db28, '4885c00f8489010000', (6413096, 6413489), 'C5', 'null initial record allocation outside normal resource contract'),
    0x61db28: (0x61db32, '49ffc6498d542418eb08', (6413114,), 'C5', 'increment pre-capacity to C and restore second descriptor pointer'),
    0x61db32: (0x61db3a, 'b8080000004531f6', (6413114,), 'OUTSIDE', 'zero request fallback is outside stated fixed-interval allocation domain'),
    0x61db3a: (0x61db61, '4c8938488968084c8978104c89742408488944241048c7442418010000004c39ea0f8423010000', (6413153, 6413444), 'C6', 'store first(length,copy_pointer,length), save(C,buffer,count1); stop if one descriptor'),
    0x61db61: (0x61db85, '4c89e94c29e14883c1d048890c24b90100000048894c243848c7442430000000004531e4', (6413189,), 'C6/C7', 'initialize remaining helper scratch, count1 and loop byte offset0'),
    0x61db85: (0x61db90, '4989c64a8d3c22ff542440', (6413200,), 'C7', 'save buffer in callee-saved register; callback(next_base+offset)'),
    0x61db90: (0x61dba4, '4989c74889d54885c0488b5424280f84e0000000', (6413220, 6413444), 'C7', 'save callback pointer/length; restore next_base; pointerzero stops before append'),
    0x61dba4: (0x61dbad, '4885ed0f881c010000', (6413229, 6413513), 'C7', 'negative nonzero-pointer length is outside normal callback contract'),
    0x61dbad: (0x61dbaf, '7440', (6413231, 6413295), 'C8', 'zero length selects pointer1 path before allocation'),
    0x61dbaf: (0x61dbb8, '4889efff15a86f1c00', (6413240,), 'C8', 'allocator request equals later positive length'),
    0x61dbb8: (0x61dbc1, '4885c00f84fe000000', (6413249, 6413503), 'C8', 'null later allocation outside normal resource contract'),
    0x61dbc1: (0x61dbd5, '48894424204889c74c89fe4889eaff15936f1c00', (6413269,), 'C8', 'save fresh payload pointer; memcpy(fresh,source,length)'),
    0x61dbd5: (0x61dbed, '488b5424284c89f04c8b7c24384c3b7c24084c8b3424741f', (6413293, 6413324), 'C9', 'restore next_base/buffer/count; equality with C selects growth, impossible j<C'),
    0x61dbed: (0x61dbef, 'eb57', (6413382,), 'C9', 'normal positive-length case jumps directly to append'),
    0x61dbef: (0x61dc0c, '4c89f0b90100000048894c24204c8b7c24384c3b7c24084c8b3424753a', (6413324, 6413382), 'C8/C9', 'zero-length row pointer1; count<C selects direct append'),
    0x61dc0c: (0x61dc3c, '4c89f248c1ea0348b8abaaaaaaaaaaaaaa480fafd048ffc2b90800000041b818000000488d7c24084c89fee8042b0000', (6413372,), 'OUTSIDE', 'generic growth call is unreachable under proved j<N<=C pre-append invariant'),
    0x61dc3c: (0x61dc46, '488b442410488b542428', (6413382,), 'OUTSIDE', 'post-growth reload, retained but not needed for conditional normal proof'),
    0x61dc46: (0x61dc84, '4a896c2018488b4c24204a894c20204a896c202849ffc74c897c24384c897c24184a8d0c224883c1184983c4184983c6e84c8934244c39e90f8501ffffff', (6413444, 6413189), 'C7/C10', 'append row at24*j; increment completed count and offset24; stop at exact interval end'),
    0x61dc84: (0x61dca3, '488b44241848894310488b442408488903488b44241048894308e9c8fdffff', (6412907,), 'C11', 'write output words(C,buffer,completed_count) then common return'),
    0x61dca3: (0x61dcb1, 'bf010000004c89feff158f6e1c00', (6413489,), 'OPEN', 'first allocation failure error call, excluded resource condition'),
    0x61dcb1: (0x61dcbf, 'bf08000000488b3424e943feffff', (6413058,), 'OPEN', 'record allocation failure error preparation, excluded resource condition'),
    0x61dcbf: (0x61dcc9, 'b8010000004889442430', (6413513,), 'OPEN', 'later allocation failure records error context, excluded resource condition'),
    0x61dcc9: (0x61dcd7, '488b7c24304889eeff15696e1c00', (6413527,), 'OPEN', 'external later negative-length/allocation error call; fallthrough retained'),
    0x61dcd7: (0x61dcd9, '0f0b', (), 'OPEN', 'UD2 terminates this normal-flow projection; no trap/process theorem'),
    0x61dcd9: (0x61dce1, '4889c34885ed7417', (6413537, 6413560), 'UNWIND', 'cold landing context: save exception and test current payload; LSDA behavior unclosed'),
    0x61dce1: (0x61dcf1, '488b7c24204889ee31d2ff158f6e1c00', (6413553,), 'UNWIND', 'cold deallocation call; not part of successful normal-path contract'),
    0x61dcf1: (0x61dcf3, 'eb05', (6413560,), 'UNWIND', 'cold cleanup join'),
    0x61dcf3: (0x61dcf5, 'eb00', (6413557,), 'UNWIND', 'cold cleanup entry jump'),
    0x61dcf5: (0x61dcf8, '4889c3', (6413560,), 'UNWIND', 'cold preserved exception word'),
    0x61dcf8: (0x61dd07, '4c8b7424104c8b7c24184d85ff7517', (6413575, 6413598), 'UNWIND', 'cold buffer/count reload and cleanup branch'),
    0x61dd07: (0x61dd11, '488b4424084885c07453', (6413585, 6413668), 'UNWIND', 'cold capacity test before record-buffer cleanup'),
    0x61dd11: (0x61dd1e, '48c1e003488d34404c89f7eb3e', (6413660,), 'UNWIND', 'cold buffer-size argument and cleanup join'),
    0x61dd1e: (0x61dd2b, '4d8d66084c8b2d576e1c00eb0e', (6413625,), 'UNWIND', 'cold per-record cursor and deallocator target load'),
    0x61dd2b: (0x61dd30, '0f1f440000', (6413616,), 'CONTEXT', 'padding NOP, retained in complete FDE bytes'),
    0x61dd30: (0x61dd39, '4983c41849ffcf74ce', (6413625, 6413575), 'UNWIND', 'cold record cleanup loop progress'),
    0x61dd39: (0x61dd43, '498b7424f84885f674ed', (6413635, 6413616), 'UNWIND', 'cold payload-length test'),
    0x61dd43: (0x61dd4c, '498b3c2431d241ffd5', (6413644,), 'UNWIND', 'cold per-record deallocation call'),
    0x61dd4c: (0x61dd4e, 'ebe2', (6413616,), 'UNWIND', 'cold cleanup backedge'),
    0x61dd4e: (0x61dd56, '4889c34d85ff740e', (6413654, 6413668), 'UNWIND', 'cold alternate cleanup entry'),
    0x61dd56: (0x61dd5c, '4889ef4c89fe', (6413660,), 'UNWIND', 'cold deallocation arguments'),
    0x61dd5c: (0x61dd64, '31d2ff151c6e1c00', (6413668,), 'UNWIND', 'cold deallocation call'),
    0x61dd64: (0x61dd6c, '4889dfe8b48a1800', (6413676,), 'OPEN', 'cold external direct call; its normal-return boundary61dd6c remains open'),
}


def require(value, message):
    if not value:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def native_rows(raw, start, end, name, version):
    argv = ['objdump','-D','-b','binary','-m','i386:x86-64','-M','intel',
            '--insn-width=16','--adjust-vma='+hex(start),name+'.bin']
    with tempfile.TemporaryDirectory(prefix='vcollect-') as temporary:
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


def graph_and_blocks(rows):
    """Normal-call/return projection only; exception/LSDA edges are not claimed."""
    leaders,edges,branches,calls,returns,traps = {START},{},[],[],[],[]
    for row in rows:
        address,raw = int(row['va'],16),bytes.fromhex(row['hex'])
        following = address+len(raw)
        if raw == b'\xc3':
            successors = []
            returns.append(hex(address))
            leaders.add(following)
        elif raw == b'\x0f\x0b':
            successors = []
            traps.append(hex(address))
            leaders.add(following)
        elif (raw[0] in (0xe9,0xeb) or 0x70 <= raw[0] <= 0x7f
              or raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f):
            offset = 2 if raw[0] == 0x0f else 1
            require(len(raw)-offset in (1,4),'unsupported relative branch')
            target = following+int.from_bytes(raw[offset:],'little',signed=True)
            conditional = raw[0] not in (0xe9,0xeb)
            successors = [following,target] if conditional else [target]
            branches.append({'site':hex(address),'target':hex(target),'conditional':conditional})
            leaders.update([following,target])
        elif (raw[0] == 0xe8 or raw[:2] in (b'\xff\x15',b'\xff\x54')
              or raw in (b'\x41\xff\xd6',b'\x41\xff\xd5')):
            if raw[0] == 0xe8:
                require(len(raw)==5,'direct call width differs')
                call = {'target':hex(following+struct.unpack_from('<i',raw,1)[0])}
            elif raw[:2] == b'\xff\x15':
                require(len(raw)==6,'RIP call width differs')
                call = {'slot':hex(following+struct.unpack_from('<i',raw,2)[0])}
            elif raw == b'\xff\x54\x24\x40':
                call = {'operand':'QWORD PTR [rsp+0x40]'}
            else:
                require(raw in (b'\x41\xff\xd6',b'\x41\xff\xd5'),'indirect call encoding differs')
                call = {'operand':'r14' if raw[-1]==0xd6 else 'r13'}
            calls.append({'site':hex(address),**call,'normal_return_edge':hex(following)})
            successors = [following]
            leaders.add(following)
        else:
            mnemonic = row['asm'].split()[0]
            require(not mnemonic.startswith(('j','ret','call','loop','int','sys','hlt','ud2')),
                    'unclassified control instruction')
            successors = [following]
        edges[address] = successors
    require(all(t in edges or t==END for ts in edges.values() for t in ts),
            'normal edge leaves an instruction boundary')
    leaders = sorted(a for a in leaders if a<END)
    blocks = []
    for a,z in zip(leaders,leaders[1:]+[END]):
        members = [r for r in rows if a<=int(r['va'],16)<z]
        require(members and int(members[0]['va'],16)==a,'block starts within instruction')
        blocks.append({'start':hex(a),'end':hex(z),'hex':''.join(r['hex'] for r in members),
                       'instructions':len(members),
                       'successors':[hex(t) for t in edges[int(members[-1]['va'],16)]]})
    actual = {int(b['start'],16):b for b in blocks}
    require(set(actual)==set(REVIEWED_BLOCKS),'complete block domain differs')
    for a,(z,raw,successors,obligations,transfer) in REVIEWED_BLOCKS.items():
        block = actual[a]
        require((int(block['end'],16),block['hex'],tuple(int(t,16) for t in block['successors']))
                ==(z,raw,successors),f'complete block binding differs at {a:#x}')
        block['obligations'],block['reviewed_transfer'] = obligations,transfer
    reached = reach(edges)
    return {'coordinate_system':'linked ELF VAs','projection':'normal call/return edges; LSDA/unwind behavior unqualified',
            'instructions':len(rows),'blocks':blocks,'branches':branches,'calls':calls,
            'returns':returns,'traps':traps,'edges':{hex(a):[hex(t) for t in ts] for a,ts in edges.items()},
            'normal_projection_reachable_instructions':len(reached),
            'unreachable_in_this_projection':[r['va'] for r in rows if int(r['va'],16) not in reached],
            'open_normal_boundaries':sorted({hex(t) for ts in edges.values() for t in ts if t==END})}


def reach(edges):
    seen,todo = set(),[START]
    while todo:
        address = todo.pop()
        if address in edges and address not in seen:
            seen.add(address)
            todo.extend(edges[address])
    return seen


def conditional_projection(graph):
    # These are proof-domain consequences, not assumptions that error calls
    # never return. PROOF.md derives each from valid intervals/lengths/resources.
    choices = {
        0x61da47:(0x61da7d,'C3: nonzero callback length is nonnegative'),
        0x61da98:(0x61da9e,'C4: positive allocation returns fresh nonnull storage'),
        0x61dafe:(0x61db0d,'C5: fixed24B interval extent<=isize_max implies exact size guard'),
        0x61db10:(0x61db12,'C5: initial request24*C>=96'),
        0x61db22:(0x61db28,'C5: initial record allocation returns fresh nonnull storage'),
        0x61dba7:(0x61dbad,'C7: later nonzero-pointer callback length is nonnegative'),
        0x61dbbb:(0x61dbc1,'C8: later positive allocation returns fresh nonnull storage'),
        0x61dbeb:(0x61dbed,'C9: completed count j<C before a positive-length append'),
        0x61dc0a:(0x61dc46,'C9: completed count j<C before a zero-length append'),
    }
    edges = {int(a,16):[int(t,16) for t in ts] for a,ts in graph['edges'].items()}
    records = []
    for site,(selected,why) in choices.items():
        require(site in edges and selected in edges[site] and len(edges[site])==2,
                'conditional proof-domain edge differs')
        records.append({'site':hex(site),'selected':hex(selected),
                        'excluded':[hex(t) for t in edges[site] if t!=selected],'reason':why})
        edges[site] = [selected]
    reached = reach(edges)
    forbidden = {0x61da4e,0x61db02,0x61dcab,0x61dcd1,0x61dc37,0x61dcd7}
    require(not reached&forbidden and not any(a>=0x61dcd9 for a in reached),
            'error/growth/unwind unexpectedly in conditional normal domain')
    calls = [row for row in graph['calls'] if int(row['site'],16) in reached]
    return {'domain_branch_choices':records,'reachable_instruction_nodes':len(reached),
            'reachable_call_sites':calls,'growth_call_reached':False,'error_call_or_trap_reached':False,
            'not_an_all_input_or_exception_CFG_claim':True}


def arithmetic_terms(read):
    value = lambda a,n:int.from_bytes(read(a,n)[1],'little')
    terms = {'record_stride':value(0x61dc72,1),'initial_next_stride':value(0x61da43,1),
             'division_shift':value(0x61dac8,1),'inverse_three':value(0x61dacb,8),
             'minimum_before_increment':value(0x61dadd,4),'selection_threshold':value(0x61dada,1),
             'slot_scale':1 << (value(0x61dae8,1)>>6),
             'slot_addend':value(0x61dae9,4),'qwords_per_record':1+(1 << (value(0x61daf0,1)>>6)),
             'remaining_bytes_guard':value(0x61daf3,8),
             'empty_output_words':[0,8,0],'zero_length_pointer_word':value(0x61dab8,4),
             'later_zero_length_pointer_word':value(0x61dbf3,4)}
    require(terms=={'record_stride':24,'initial_next_stride':24,'division_shift':3,
                   'inverse_three':0xaaaaaaaaaaaaaaab,'minimum_before_increment':3,
                   'selection_threshold':4,'slot_scale':8,'slot_addend':8,'qwords_per_record':3,
                   'remaining_bytes_guard':0x7fffffffffffffe0,'empty_output_words':[0,8,0],
                   'zero_length_pointer_word':1,'later_zero_length_pointer_word':1},
            'derived collection arithmetic/protocol operands differ')
    require(3*terms['inverse_three']%U64_END==1,'inverse-three algebra differs')
    return terms


def descriptor_domain(start,end):
    require(all(isinstance(x,int) and not isinstance(x,bool) for x in (start,end)),
            'descriptor endpoints must be integers')
    require(0<=start<=end<U64_END and end-start<=ISIZE_MAX,'descriptor interval wraps or is oversized')
    require((end-start)%24==0,'descriptor interval is not an exact24B multiple')
    return (end-start)//24


def capacity_facts(count,terms):
    """Arithmetic consequences on an allocation branch, not runtime simulation."""
    require(isinstance(count,int) and not isinstance(count,bool) and 1<=count<=ISIZE_MAX//24,
            'capacity is qualified only for nonempty fixed-interval allocation branch')
    remaining = terms['record_stride']*(count-1)
    quotient = ((remaining >> terms['division_shift'])*terms['inverse_three'])%U64_END
    before_increment = quotient if quotient>=terms['selection_threshold'] else terms['minimum_before_increment']
    capacity = before_increment+1
    request = (before_increment*terms['slot_scale']+terms['slot_addend'])*terms['qwords_per_record']
    require(quotient==count-1 and capacity==max(4,count) and request==24*capacity,
            'allocation-branch capacity algebra differs')
    require(remaining<=terms['remaining_bytes_guard'] and 96<=request<=ISIZE_MAX,
            'fixed-interval resource bound does not follow')
    return {'remaining_descriptor_bytes':remaining,'exact_remaining_descriptor_count':quotient,
            'capacity_on_allocation_branch':capacity,'record_allocation_request':request,
            'all_preappend_completed_counts':[0,count-1],
            'strict_preappend_bound':count-1<capacity,'final_completed_count_may_equal_capacity':count==capacity,
            'growth_edge_needed_on_this_domain':False}


def overlaps(a,z,b,y):
    return max(a,b)<min(z,y)


def memory_domain(argument_record,start,end,result,stack,payload_intervals,protected):
    """Arithmetic separation only; permissions, immutability and callee contracts assumed."""
    count = descriptor_domain(start,end)
    require(all(isinstance(x,int) and not isinstance(x,bool) for x in (argument_record,result,stack)),
            'result/stack values must be integers')
    require(0<=argument_record and argument_record+24<=U64_END
            and 0<=result and result+24<=U64_END and 120<=stack and stack+8<=U64_END,
            'result or complete active frame/return interval wraps')
    require(stack%16==8,'collection entry requires ordinary SysV stack alignment')
    frame = (stack-120,stack+8)
    require(not overlaps(argument_record,argument_record+24,*frame)
            and not overlaps(argument_record,argument_record+24,result,result+24),
            'argument record aliases active frame/return or result')
    require(not overlaps(result,result+24,*frame) and not overlaps(start,end,result,result+24)
            and not overlaps(start,end,*frame),'descriptor/result/active-frame alias')
    for a,z in payload_intervals:
        require(0<=a<=z<=U64_END,'payload interval wraps')
        require(not overlaps(a,z,result,result+24) and not overlaps(a,z,*frame),
                'payload aliases result or active frame/return')
    for a,z in protected:
        require(0<=a<=z<=U64_END,'protected image interval wraps')
        require(not overlaps(result,result+24,a,z) and not overlaps(*frame,a,z),
                'result/frame writes alias immutable image')
    return {'descriptor_count':count,'argument_record_interval':[argument_record,argument_record+24],
            'active_collector_frame_and_return':list(frame),
            'arithmetic_nonalias_checks':True,
            'readability_immutability_freshness_callee_frames_and_hardware_return_not_checked':True,
            'actual_UTF8_adapter_additional_frame':'B must also avoid callback frame[entryS-184,entryS-120); ordinary valid call state assumed'}


def prefix_model(count,callback_results,terms):
    """Independent symbolic prefix/resource model, not original instructions or ABI."""
    require(isinstance(count,int) and not isinstance(count,bool) and 0<=count<=ISIZE_MAX//24,
            'model count outside the stated interval domain')
    empty = {'output_words':[0,8,0],'callback_indices':[],'records':[],
             'positive_copy_requests':[],'record_allocation_request':0,'growth_calls':0}
    if count==0:
        return empty
    records,indices,copies = [],[],[]
    for index in range(count):
        require(index<len(callback_results),'model lacks required callback result')
        pointer,length = callback_results[index]
        require(isinstance(pointer,int) and not isinstance(pointer,bool) and 0<=pointer<U64_END,
                'model callback pointer outside machine-word domain')
        indices.append(index)
        if pointer==0:
            break  # Length is unqualified and deliberately not inspected on stop.
        require(isinstance(length,int) and not isinstance(length,bool) and 0<=length<=ISIZE_MAX,
                'nonzero-pointer callback length outside normal domain')
        if length:
            destination = 'fresh-payload-'+str(index)
            copies.append({'index':index,'source':pointer,'bytes':length,'destination':destination})
        else:
            destination = 1
        records.append([length,destination,length])
    if not records:
        return {**empty,'callback_indices':indices}
    facts = capacity_facts(count,terms)
    return {'output_words':[facts['capacity_on_allocation_branch'],'fresh-record-buffer',len(records)],
            'callback_indices':indices,'records':records,'positive_copy_requests':copies,
            'record_allocation_request':facts['record_allocation_request'],'growth_calls':0}


def _derive(data):
    """Private real-byte counterfactual seam; public collect additionally pins identity."""
    secs = sections(data)
    def read(address,size):
        matching = [s for s in secs if s['type']!=8 and s['address']<=address
                    and address+size<=s['address']+s['size']]
        require(len(matching)==1,'collection span not uniquely file-backed')
        offset = matching[0]['offset']+address-matching[0]['address']
        return offset,data[offset:offset+size]
    def window(address,size):
        offset,raw = read(address,size)
        return {'va':hex(address),'file_offset':offset,'bytes':size,'hex':raw.hex(),'sha256':sha(raw)}
    _,fdes,_ = fde_extents(data)
    found = [f for f in fdes if f['start']==START]
    require(len(found)==1 and found[0]['end']==END,'collection FDE extent differs')
    version = subprocess.run(['objdump','--version'],capture_output=True,check=True).stdout.decode().splitlines()[0]
    require(version.startswith('GNU objdump'),'GNU objdump required')
    rows,native,method = native_rows(read(START,END-START)[1],START,END,'collection',version)
    graph = graph_and_blocks(rows)
    require((graph['instructions'],len(graph['blocks']),len(graph['branches']),len(graph['calls']))==(220,61,33,16)
            and graph['returns']==['0x61da7c'] and graph['traps']==['0x61dcd7']
            and graph['normal_projection_reachable_instructions']==176
            and graph['open_normal_boundaries']==['0x61dd6c'],'complete collection normal projection differs')
    projection,terms = conditional_projection(graph),arithmetic_terms(read)
    relocation = next(s for s in secs if s['name']=='.rela.dyn')
    require(relocation['size']%24==0,'RELA stride differs')
    relocs = {}
    for offset in range(relocation['offset'],relocation['offset']+relocation['size'],24):
        slot,info,addend = struct.unpack_from('<QQq',data,offset)
        require(slot not in relocs,'duplicate relocation slot')
        relocs[slot] = {'slot':hex(slot),'type':info&0xffffffff,'symbol':info>>32,
                        'addend':hex(addend),'file_offset':offset}
    selected = []
    for slot,expected in ((0x7e4b40,(8,0,0x2beaf4)),(0x7e4b60,(8,0,0x70bf30)),
                          (0x7e4b68,(6,6,0)),(0x7e4b80,(8,0,0x714530)),
                          (0x7e6aa0,(8,0,0x48dc00))):
        row = relocs.get(slot)
        require(row is not None and (row['type'],row['symbol'],int(row['addend'],16))==expected,
                'collection callback/allocator/copy/context binding differs')
        selected.append(row)
    symtab = next(s for s in secs if s['name']=='.dynsym')
    strings = next(s for s in secs if s['name']=='.dynstr')
    shoff = struct.unpack_from('<Q',data,40)[0]
    shentsize = struct.unpack_from('<H',data,58)[0]
    symheader = shoff+secs.index(symtab)*shentsize
    symbol_stride = struct.unpack_from('<Q',data,symheader+56)[0]
    require(symtab['type']==11 and symbol_stride==24 and 7*24<=symtab['size'],
            'copy dynsym index/stride is not in actual dynamic symbol table')
    symbol_offset = symtab['offset']+6*24
    name = struct.unpack_from('<I',data,symbol_offset)[0]
    require(name<strings['size'],'copy symbol name leaves dynamic string table')
    begin,limit = strings['offset']+name,strings['offset']+strings['size']
    finish = data.find(b'\0',begin,limit)
    require(finish>=begin and data[begin:finish]==b'memcpy','actual copy import name differs')
    upstream = window(0x5b920a,51)
    require(upstream['hex']=='498b41e8498b49f0488d0c49488d0cc8488944241848894c2420488b0575d8220048894424284889e7488d742418e8d3470600',
            'actual child-argument descriptor/call differs')
    callback = window(0x48dc00,67)
    require(callback['sha256']=='766fb13517615d361dc601c4ea07ef9e9d696b7f68cd226af3171a61ccd963aa',
            'prior used UTF8 adapter body differs')
    # Derived scalar/row/output stores are bound by every complete block above.
    facts = {
        'empty_store_sites':['0x61da54','0x61da5b','0x61da63'],
        'first_row_store_sites':['0x61db3a','0x61db3d','0x61db41'],
        'later_row_store_sites':['0x61dc46','0x61dc50','0x61dc55'],
        'final_output_store_sites':['0x61dc89','0x61dc92','0x61dc9a'],
        'first_stop_test':'0x61da37','later_stop_test':'0x61db96',
        'loop_callback':'0x61db8c','loop_offset_step':'0x61dc6f',
        'loop_next_descriptor':'0x61dc67','loop_end_test':'0x61dc7b',
        'positive_copy_calls':['0x61daaa','0x61dbcf'],
        'no_extra_terminator_requested_or_copied_by_this_controller':True,
    }
    protected = [(s['address'],s['address']+s['size']) for s in secs if s['flags']&4 and s['size']]
    protected += [(slot,slot+8) for slot in (0x7e4b40,0x7e4b60,0x7e4b68,0x7e4b80,0x7e6aa0)]
    record = {
        'schema':1,'task':'RE-013','component':'visor','target':{'bytes':len(data),'sha256':sha(data)},
        'question':'Actual child-argument collection prefix/order/count, zero-length versus stop, and fixed-interval no-growth prerequisite.',
        'range':{**window(START,END-START),'end':hex(END),'fde_va':hex(found[0]['fde']),
                 'cie_va':hex(found[0]['cie']),'lsda_va':hex(found[0]['lsda'])},
        'native_method':method,'instructions':rows,'graph':graph,'conditional_projection':projection,
        'actual_terms':terms,'raw_protocol_sites':facts,'used_bindings':selected,
        'actual_copy_symbol':{'index':6,'name':'memcpy','symbol_file_offset':symbol_offset,'symbol_stride':symbol_stride,
                              'symbol_section_header_file_offset':symheader,
                              'name_file_offset':begin,'name_bytes':finish-begin,
                              'symbol_sha256':sha(data[symbol_offset:symbol_offset+24])},
        'used_caller':{'PR':988,'head':'0e24c1be56d8bfcfaa58951f4e263a7fee024b6a','witness':upstream},
        'actual_callback_prerequisite':{'PR':1029,'head':'d6d290bfa63021ce3c75bfa9892824f83b3ef2c9',
             'body':callback,'relationship':'External conditional static proof: successful actual UTF8 adapter returns same pointer/length; its error helper remains open. This packet does not re-prove that503B validator.',
             'nonnull_not_inferred_from_UTF8_success':'A valid empty span with pointerzero still selects collection stop; private Rust nonnull assumptions are not imported.'},
        'domain':{'descriptor_interval':'immutable readable nonwrapping[start,end),end=start+24*N,0<=24*N<=2^63-1; valid readable input record holds(start,end,callback)',
          'argument_record':'EntryRSI24 is readable immutable and disjoint result/frame/callee writes; saved-register pushes must not overwrite it before start/end/callback loads. No private descriptor type inferred.',
          'all_used_callees':'Every used callback/allocator/memcpy preserves SysV callee-saved RBX/RBP/R12-R15 and restores callerRSP, all live caller locals, immutable input/image and prior outputs except its declared fresh destination writes. Finite hardware return/freshness alone does not establish these external premises.',
          'callbacks':'Finite normal ABI returns preserving caller frame/descriptors/input; pointerzero stops before length inspection; appended nonzero-pointer length0..2^63-1 and immutable readable payload.',
          'allocator':'Opaque70bf30 on each positive request returns finite normal, fresh writable nonnull disjoint storage of at least requested size; this callee contract is assumed, not recovered.',
          'copy':'Actual GLOB_DAT memcpy binding obeys finite normal C byte-copy contract on disjoint source/fresh destination and preserves caller frame/input; implementation is not recovered.',
          'frame':'EntryS mod16=8: saves[S-48,S), locals[S-120,S-48), RET[S,S+8); valid ordinary call/return contents assumed. Callback/callee frames also valid and disjoint immutable inputs/image.',
          'alias':'Result24, descriptor/payload reads and active frame/RET separated; allocated outputs fresh/disjoint all these regions and prior outputs; code/selected relocated bindings immutable.',
          'actual_UTF8_composition':'Also satisfy1029 callback domain, including immutable argument/descriptor/payload/image and result regions disjoint from adapter/validator writes[entryS-184,entryS-120). No error-helper/exception path qualification.',
          'memory_permissions_freshness_normal_calls_not_runtime_checked':True,
          'protected_image_intervals':[[hex(a),hex(z)] for a,z in protected]},
        'conditional_result':{'empty_or_immediate_stop':'raw words(0,8,0); no initial record allocation or C=max(4,N) claim on these routes',
          'allocation_branch':'C=max(4,N),24*C requested; output words(C,fresh_record_buffer,completed_count)',
          'order':'Callbacks visit descriptor indices0..j in order until first pointerzero, or0..N-1; only preceding nonzero-pointer outputs append.',
          'raw_rows':'For positive length:(length,fresh_copy_pointer,length), with exact requested/copied length. For nonzero-pointer/zero-length:(0,1,0).',
          'growth':'Before every append, completed_count j<N<=C, hence j<C. Final completed_count can equal C; generic growth not reconstructed.',
          'endpoint':'Finite arrival at localRET61da7c under stated finite normal helper/domain contracts; valid actual hardware return separately assumed.',
          'unwind_error_failure_or_all_machine_state_theorem':False},
        'proof_method':{'kind':'Full conditional normal-path block/cursor/resource induction in PROOF.md',
            'full_FDE_context_bytes_bound':860,'normal_only_not_complete_exception_CFG':True,
            'automatic_general_machine_equivalence_verifier':False,
            'high_level_model_is_not_target_execution_or_parity':True,
            'publication_requires_independent_semantic_source_and_packet_review':True},
        'limits':['No opaque allocator/growth/copy/deallocation/error/unwind implementation recovery.',
            'No original Rust Vec/String/result ABI, public CLI syntax or spawn/lifecycle semantics.',
            'No captured execution/emulation, Rust build, binary equality, function coverage or component gate claim.'],
    }
    return record,{'collection.objdump.txt':native}


def collect(data):
    require(len(data)==TARGET_SIZE and sha(data)==TARGET_SHA256,'captured visor identity differs')
    return _derive(data)


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=TARGET)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    record,_ = collect(args.binary.read_bytes())
    with args.output.open('x',encoding='utf-8',newline='\n') as output:
        output.write(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'status':'CONDITIONAL_COLLECTION_BINDINGS_PASS','full_context_bytes':860,
                      'captured_code_executed_or_emulated':False,'general_machine_equivalence_claim':False}))
