#!/usr/bin/env python3
"""RE-013: prove the captured visor lookup's normal-return low32 cutset."""
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
START, END = 0x5d3220, 0x5d3361


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode_slice(raw):
    """Native input is only a private admitted raw slice, never an ELF pathname."""
    version = subprocess.run(['objdump', '--version'], capture_output=True, check=True).stdout.decode().splitlines()[0]
    require(version.startswith('GNU objdump'), 'GNU objdump is required')
    argv = ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
            '--insn-width=16', '--adjust-vma='+hex(START), 'lookup.bin']
    with tempfile.TemporaryDirectory(prefix='visor-lookup-') as tmp:
        directory = Path(tmp)
        directory.chmod(0o700)
        source = directory/'lookup.bin'
        source.write_bytes(raw)
        source.chmod(0o400)
        require(source.read_bytes() == raw, 'private native input differs before decoding')
        result = subprocess.run(argv, cwd=directory, capture_output=True, check=True)
        require(source.read_bytes() == raw, 'private native input differs after decoding')
        require(not result.stderr, 'unexpected native diagnostic')
    rows = []
    for line in result.stdout.decode().splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$', line)
        if match:
            address, body = int(match[1], 16), bytes.fromhex(match[2])
            require(START <= address and address+len(body) <= END, 'native row leaves lookup range')
            require(raw[address-START:address-START+len(body)] == body, 'native instruction bytes differ')
            rows.append({'va':hex(address), 'hex':body.hex(), 'asm':match[3]})
    require(rows and int(rows[0]['va'],16) == START
            and int(rows[-1]['va'],16)+len(bytes.fromhex(rows[-1]['hex'])) == END,
            'native listing does not cover lookup endpoints')
    require(all(int(a['va'],16)+len(bytes.fromhex(a['hex'])) == int(b['va'],16)
                for a,b in zip(rows, rows[1:])), 'native listing gap/overlap')
    return rows, result.stdout, {'tool':version, 'argv':argv, 'input_bytes':len(raw),
                                'input_sha256':sha(raw), 'format':'raw binary, explicit x86-64',
                                'original_ELF_path_reopened':False,
                                'stdout_bytes':len(result.stdout), 'stdout_sha256':sha(result.stdout)}


def normal_graph(rows):
    """Recompute direct edges from bytes; calls have only normal-return edges."""
    edges, branches, calls, returns = {}, [], [], []
    prefixes = {'rep', 'repz', 'repnz', 'bnd', 'notrack', 'lock', 'data16', 'addr32',
                'cs', 'ds', 'es', 'fs', 'gs', 'ss'}
    for row in rows:
        address, raw = int(row['va'],16), bytes.fromhex(row['hex'])
        following = address+len(raw)
        words = row['asm'].split()
        while words and words[0] in prefixes:
            words.pop(0)
        mnemonic = words[0] if words else ''
        if raw == b'\xc3':
            edges[address] = []
            returns.append(address)
        elif (raw[0] in (0xe9,0xeb) or 0x70 <= raw[0] <= 0x7f
              or raw[0] == 0x0f and len(raw)>1 and 0x80 <= raw[1] <= 0x8f):
            offset = 2 if raw[0] == 0x0f else 1
            width = len(raw)-offset
            require(width in (1,4), 'unsupported branch displacement width')
            target = following+int.from_bytes(raw[offset:], 'little', signed=True)
            conditional = raw[0] not in (0xe9,0xeb)
            edges[address] = [following,target] if conditional else [target]
            branches.append({'site':hex(address), 'target':hex(target), 'conditional':conditional})
        elif mnemonic.startswith('call'):
            if raw[0] == 0xe8 and len(raw) == 5:
                target = following+struct.unpack_from('<i',raw,1)[0]
                calls.append({'site':hex(address), 'kind':'rel32', 'target':hex(target)})
            else:
                require(raw[:2] == b'\xff\x15' or raw == b'\x41\xff\xd5',
                        'unsupported indirect call encoding')
                calls.append({'site':hex(address), 'kind':'opaque normal-return indirect call'})
            edges[address] = [following]
        else:
            require(not mnemonic.startswith(('ret','iret','j','loop','int','sys','hlt','ud2','xbegin','xend')),
                    'unsupported native control transfer')
            edges[address] = [following]
    require(all(target in edges for targets in edges.values() for target in targets),
            'normal edge is not on a decoded instruction boundary')
    reached, pending = set(), [START]
    while pending:
        address = pending.pop()
        if address not in reached:
            reached.add(address)
            pending.extend(edges[address])
    return edges, branches, calls, returns, reached


def _derive(data):
    """Private real-byte counterfactual seam; public collect() pins the full ELF."""
    secs = sections(data)

    def read(address, size):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= address
                   and address+size <= s['address']+s['size']]
        require(len(matches) == 1, 'lookup span is not uniquely file-backed')
        offset = matches[0]['offset']+address-matches[0]['address']
        return offset, data[offset:offset+size]

    def expect(address, encoded, message):
        require(read(address,len(bytes.fromhex(encoded)))[1] == bytes.fromhex(encoded), message)

    def window(address, size):
        offset, raw = read(address,size)
        return {'va':hex(address),'file_offset':offset,'bytes':size,'hex':raw.hex(),'sha256':sha(raw)}

    _, fdes, _ = fde_extents(data)
    boundaries = []
    for start,end in ((START,END),(0x626760,0x6268c0)):
        matches = [f for f in fdes if f['start'] == start]
        require(len(matches) == 1 and matches[0]['end'] == end, 'lookup/dependency FDE extent differs')
        boundaries.append({**window(start,end-start), 'end':hex(end), 'fde_va':hex(matches[0]['fde']),
                           'cie_va':hex(matches[0]['cie']), 'lsda_va':matches[0]['lsda']})
    raw = read(START,END-START)[1]
    rows, native, method = decode_slice(raw)
    edges, branches, calls, returns, reached = normal_graph(rows)
    require(returns == [0x5d335c], 'lookup sole normal RET differs')
    predecessor = {a:sorted(p for p,targets in edges.items() if a in targets) for a in edges}

    # No incoming branch may bypass a recorded initializer or enter the epilogue.
    expect(0x5d334e,'4883c4385b415c415d415e415f5dc3','shared epilogue differs')
    require(predecessor[0x5d334e] == [0x5d3303,0x5d334c,0x5d335f], 'normal return cutset differs')
    epilogue = [int(r['va'],16) for r in rows if 0x5d334e <= int(r['va'],16) < 0x5d335d]
    require(all(predecessor[b] == [a] for a,b in zip(epilogue,epilogue[1:])),
            'edge enters shared epilogue interior')
    expect(0x5d334c,'31c0','false exit is not full EAX zeroing')
    expect(0x5d3256,'85c0','cached true-return test is not 32-bit EAX')
    expect(0x5d3258,'0f84','cached true-return edge is not zero-conditioned')
    require(edges[0x5d3258] == [0x5d325e,0x5d335d]
            and predecessor[0x5d335d] == [0x5d3258]
            and predecessor[0x5d335f] == [0x5d335d]
            and predecessor[0x5d3258] == [0x5d3256]
            and predecessor[0x5d3256] == [0x5d3250], 'cached return zero-predicate chain differs')
    expect(0x5d32fd,'89c1','probed true-return does not capture EAX in ECX')
    expect(0x5d3301,'85c9','probed true-return test is not 32-bit ECX')
    expect(0x5d3303,'74','probed true-return edge is not zero-conditioned')
    require(edges[0x5d3303] == [0x5d3305,0x5d334e]
            and all(predecessor[b] == [a] for a,b in
                    ((0x5d32fa,0x5d32fd),(0x5d32fd,0x5d32ff),
                     (0x5d32ff,0x5d3301),(0x5d3301,0x5d3303))),
            'probed return zero-predicate chain differs')
    values = []
    for site in (0x5d335d,0x5d32ff):
        code = read(site,2)[1]
        require(code[0] == 0xb0, 'true exit is not a low-byte immediate write')
        values.append(code[1])
    require(all(value in (0,1) for value in values), 'normal-return low32 domain is not canonical')

    # Bind what supplies the zero predicates without assuming its runtime policy.
    expect(0x5d322e,'4889d34989f64989ff','incoming key/length saves differ')
    expect(0x5d3240,'48395810','cached key-length comparison differs')
    require(edges[0x5d3244] == [0x5d3246,0x5d325e]
            and read(0x5d3244,1)[1] == b'\x75', 'cached key-length rejection edge differs')
    expect(0x5d3246,'488b78084c89f64889da','cached comparison arguments differ')
    expect(0x5d32e5,'493b5cc4c0','probed key-length comparison differs')
    require(edges[0x5d32ea] == [0x5d32ec,0x5d3305]
            and read(0x5d32ea,1)[1] == b'\x75', 'probed key-length rejection edge differs')
    expect(0x5d32ec,'498d04c4488b70b84c89f74889da41ffd5','probed comparison arguments differ')
    expect(0x5d3250,'ff15221a2100','cached comparison slot call differs')
    expect(0x5d329f,'4c8b2dd2192100','probed comparison slot load differs')
    relocation_section = next(s for s in secs if s['name'] == '.rela.dyn')
    dynsym = next(s for s in secs if s['name'] == '.dynsym')
    dynstr = next(s for s in secs if s['name'] == '.dynstr')
    matches = []
    for offset in range(relocation_section['offset'],relocation_section['offset']+relocation_section['size'],24):
        slot,info,addend = struct.unpack_from('<QQq',data,offset)
        if slot == 0x7e4c78:
            matches.append((offset,info,addend))
    require(len(matches) == 1, 'comparison relocation is not unique')
    offset,info,addend = matches[0]
    require((info&0xffffffff,info>>32,addend) == (6,9,0), 'comparison GLOB_DAT binding differs')
    symbol_offset = dynsym['offset']+24*(info>>32)
    name,kind,visibility,section_index,value,size = struct.unpack_from('<IBBHQQ',data,symbol_offset)
    text = data[dynstr['offset']:dynstr['offset']+dynstr['size']]
    require(name < len(text) and b'\0' in text[name:], 'comparison symbol name leaves table')
    symbol = text[name:text.index(b'\0',name)].decode('ascii')
    require(symbol == 'bcmp' and section_index == 0, 'comparison is not the undefined bcmp symbol')
    require(next(c for c in calls if c['site']=='0x5d3273').get('target') == '0x626760',
            'opaque probe dependency target differs')
    dependency_calls = []
    for site in (0x6267b0,0x6267c7):
        code = read(site,5)[1]
        require(code[0] == 0xe8, 'probe dependency subcall opcode differs')
        target = site+5+struct.unpack_from('<i',code,1)[0]
        require(target == 0x628d00, 'probe dependency subcall target differs')
        dependency_calls.append({'site':hex(site),'target':hex(target)})
    expect(0x6267b5,'c644240fff488d74240fba010000004889df','probe suffix-byte input differs')

    # Revisit only the existing #988 field's selected use sites, crediting its scope.
    expect(0x5b907d,'4889fb','caller output-base save differs')
    expect(0x5b90f6,'488d35c9e1afffba0d0000004c89f7e816a1010089c5','skip-name caller/return save differs')
    expect(0x5b923d,'40886b18','caller low-byte output store differs')
    require(read(0xb72c6,13)[1] == b'skip-download','caller name bytes differ')
    result = {
        'schema':1,'task':'RE-013','component':'visor',
        'target':{'bytes':len(data),'sha256':sha(data)},
        'coordinates':'linked ELF virtual addresses; file offsets also supplied',
        'lookup_fde':boundaries[0], 'dependency_fde_metadata_only':boundaries[1],
        'native_method':method,'instructions':rows,
        'normal_CFG':{'branches':branches,'calls':calls,'returns':[hex(a) for a in returns],
                      'edges':{hex(a):[hex(b) for b in targets] for a,targets in edges.items()},
                      'decoded_instructions':len(rows),'reachable_nodes_in_opaque_normal_call_model':len(reached),
                      'call_model':'opaque calls may return normally at their fallthrough; exception/nonreturn behavior unqualified'},
        'return_cutset':{'shared_epilogue':'0x5d334e..0x5d335d',
                         'predecessors':[hex(a) for a in predecessor[0x5d334e]],
                         'cases':[{'case':'false initializer','site':'0x5d334c','EAX':0},
                                  {'case':'cached comparison EAX==0, then AL immediate','site':'0x5d335d','EAX':values[0]},
                                  {'case':'ECX captures comparison EAX, ECX==0, then AL immediate','site':'0x5d32ff','EAX':values[1]}],
                         'normal_return_low32_upper_bound':sorted(set([0]+values)),
                         'whole_RAX_high32_proved':False,'outcome_feasibility_or_termination_proved':False},
        'comparison_binding':{'slot':'0x7e4c78','type':6,'symbol_index':9,'addend':0,
                              'relocation_file_offset':offset,'symbol_file_offset':symbol_offset,
                              'name':symbol,'undefined':True,'symbol_info':kind,'symbol_visibility':visibility,
                              'symbol_value':value,'symbol_size':size,
                              'normal_call_sites':['0x5d3250','0x5d32fa'],
                              'arguments':'saved incoming name pointer/length; candidate length equality precedes each comparison',
                              'argument_mapping_condition':'normal calls preserve callee-saved RBX/R14/R15; helper ABI not independently reconstructed',
                              'zero_return_predicates_only':True,'runtime_DSO_or_bcmp_implementation_proved':False},
        'probe_dependency':{'calls':dependency_calls,'second_input_byte':'ff','second_input_length':1,
                            'role':'Opaque normal-return hash/probe input; no algorithm needed for the return cutset',
                            'algorithm_or_table_validity_or_completeness_proved':False},
        'caller_field':{'prior_PR':988,'prior_head':'0e24c1be56d8bfcfaa58951f4e263a7fee024b6a',
                        'name':window(0xb72c6,13),'argument_and_return_save':window(0x5b90f6,22),
                        'byte_store':window(0x5b923d,4),'output_offset':24,
                        'flow':'EAX -> EBP at0x5b910a; BPL -> [RBX+24] at0x5b923d',
                        'condition':'Normal helper calls preserve ABI callee-saved RBP/RBX; not a recovered private ABI/type',
                        'conditional_byte_upper_bound':[0,1]},
        'limits':['Normal-return low32 partition only; no dynamic reachability, termination or table/key validity proof.',
                  'bcmp is an imported-symbol binding, not proof of selected runtime implementation or equality behavior.',
                  'No public accepted CLI syntax/default/trailing/multiplicity policy, private bool/container layout or download effect.',
                  'No captured execution, source reconstruction, function-match denominator, equivalence or accepted component gate.'],
    }
    return result,native


def collect(data):
    require(len(data) == TARGET_SIZE and sha(data) == TARGET_SHA256,'captured visor identity differs')
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
    print(json.dumps({'status':'SCOPED_NORMAL_RETURN_LOW32_PASS',
                      'normal_return_low32_upper_bound':result['return_cutset']['normal_return_low32_upper_bound'],
                      'captured_binary_executed':False}))
