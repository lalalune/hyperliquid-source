"""Hosted-only bounded incoming-reference probe. Never run this on the Mac."""
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import struct
import subprocess
import sys
import time
import urllib.request

BASE = 'a8616af9432b8d8517b2af677880e117b7c28ef3'
TARGET_SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
START, END = 0x298AF40, 0x298B04D
BODY_SHA = '9573b1ff5c818a9efc8f841b1b4d5c5627cc4f5c1b966de2220341b358e2d84c'
FDE_HEADER = re.compile(r'^\s*(?:0x)?([0-9a-fA-F]+)\s+.*\bFDE\b.*\bpc=(?:0x)?([0-9a-fA-F]+)\.{2,3}(?:0x)?([0-9a-fA-F]+)')
DEADLINE = None


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(root, name, value):
    (root / 'output' / name).write_text(json.dumps(value, indent=2) + '\n')


def authenticate(data):
    require(len(data) == TARGET_SIZE and digest(data) == TARGET_SHA, 'capture identity mismatch')


def sections(data):
    require(data[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', data, 18)[0] == 62, 'ELF identity')
    offset = struct.unpack_from('<Q', data, 40)[0]
    stride, count, names = struct.unpack_from('<HHH', data, 58)
    require(stride == 64 and 0 < count < 1000 and names < count and offset + count * stride <= len(data), 'section table')
    rows = []
    for i in range(count):
        n,t,flags,va,off,size,link,info,align,step = struct.unpack_from('<IIQQQQIIQQ', data, offset+i*stride)
        require(t == 8 or off + size <= len(data), 'section exceeds capture')
        rows.append(dict(index=i, name_offset=n, type=t, flags=flags, va=va, offset=off, size=size, step=step))
    ns = rows[names]
    require(ns['type'] == 3, 'section-name STRTAB')
    names_data = data[ns['offset']:ns['offset']+ns['size']]
    for row in rows:
        require(row['name_offset'] < len(names_data), 'section-name bound')
        end = names_data.find(b'\0', row['name_offset'])
        require(end >= 0, 'section-name terminator')
        row['name'] = names_data[row['name_offset']:end].decode('ascii')
    return rows


def body(data, rows, start, end):
    owners = [r for r in rows if r['type'] != 8 and r['va'] <= start < end <= r['va']+r['size']]
    require(len(owners) == 1, 'unique file-backed section')
    row, = owners
    off = row['offset'] + start-row['va']
    return data[off:off+end-start], row


def prepare(root):
    url = f'https://media.githubusercontent.com/media/lalalune/hyperliquid-source/{BASE}/artifacts/node/115/hl-node'
    target = root / 'target/hl-node'
    total = 0
    with urllib.request.urlopen(url, timeout=90) as response, target.open('xb') as out:
        while True:
            chunk = response.read(1048576)
            if not chunk:
                break
            total += len(chunk)
            require(total <= TARGET_SIZE, 'capture download exceeds exact size')
            out.write(chunk)
    require(total == TARGET_SIZE and file_digest(target) == TARGET_SHA, 'downloaded capture identity')
    target.chmod(0o444)
    for alias, choices in {
        'objdump': ['objdump'], 'readelf': ['readelf'],
        'llvm-objdump': ['llvm-objdump', 'llvm-objdump-18', 'llvm-objdump-19', 'llvm-objdump-20', 'llvm-objdump-21'],
        'llvm-dwarfdump': ['llvm-dwarfdump', 'llvm-dwarfdump-18', 'llvm-dwarfdump-19', 'llvm-dwarfdump-20', 'llvm-dwarfdump-21'],
        'timeout': ['timeout'],
    }.items():
        found = next((p for name in choices if (p := shutil.which(name, path='/usr/bin:/bin'))), None)
        require(found is not None, 'missing existing tool: '+alias)
        (root / 'bin' / alias).symlink_to(found)
    (root / 'bin/python3').symlink_to(sys.executable)
    save(root, 'prepared.json', {'base': BASE, 'capture_url': url, 'target_sha256': TARGET_SHA,
         'target_bytes': total, 'tools': {p.name: str(p.resolve()) for p in (root/'bin').iterdir()},
         'packages_installed': False, 'compiler_installed': False})


def command(root, label, argv, large=False):
    require(time.monotonic() < DEADLINE, 'analysis deadline')
    dest = root / ('work' if large else 'output') / (label+'.log')
    error = root / 'work' / (label+'.stderr')
    with dest.open('wb') as out, error.open('wb') as err:
        result = subprocess.run(argv, stdout=out, stderr=err, cwd=root/'work', timeout=min(90, max(1, DEADLINE-time.monotonic())))
    require(dest.stat().st_size <= (256000000 if large else 2000000) and error.stat().st_size < 100000, 'native output bound')
    commands = json.loads((root/'output/commands.json').read_text())
    commands[label] = {'argv': argv, 'exit_code': result.returncode, 'stdout_bytes': dest.stat().st_size,
        'stdout_sha256': file_digest(dest), 'stderr_bytes': error.stat().st_size, 'stderr_sha256': file_digest(error),
        'full_stdout_retained': not large}
    save(root, 'commands.json', commands)
    if error.stat().st_size:
        shutil.copy2(error,root/'output'/(label+'.stderr.log'))
    require(result.returncode == 0 and not error.stat().st_size, 'native tool failure: '+label)
    return dest


def native_rows(path, start, end):
    result = []
    cursor = start
    for line in path.read_text().splitlines():
        match = re.match(r'^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)(.*)$', line)
        if match:
            va = int(match.group(1), 16)
            raw = bytes.fromhex(match.group(2))
            require(va == cursor, 'native row gap/overlap')
            result.append((va, raw, match.group(3)))
            cursor += len(raw)
    require(cursor == end, 'incomplete native body')
    return result


def decoded(root, target, start, end, label, expected):
    gnu = command(root, label+'-gnu', ['objdump','-d','-z','--insn-width=16',f'--start-address={hex(start)}',f'--stop-address={hex(end)}',str(target)])
    llvm = command(root, label+'-llvm', ['llvm-objdump','-d','--disassemble-zeroes',f'--start-address={hex(start)}',f'--stop-address={hex(end)}',str(target)])
    a,b = native_rows(gnu,start,end), native_rows(llvm,start,end)
    require([(r[0],r[1]) for r in a] == [(r[0],r[1]) for r in b], 'GNU/LLVM instruction disagreement')
    require(b''.join(r[1] for r in a) == expected, 'native bytes disagree with authenticated capture')
    return {va: {'bytes': raw.hex(), 'instruction': instruction} for va,raw,instruction in a}


def fdes(path):
    rows = []
    with path.open() as stream:
        for line in stream:
            match = FDE_HEADER.search(line)
            if match:
                off,start,end = (int(v,16) for v in match.groups())
                require(end >= start, 'FDE negative extent')
                rows.append((off,start,end))
    require(len(rows) == 135313, 'FDE inventory differs from frozen target')
    return rows


def analyze(root, parent_namespace):
    global DEADLINE
    DEADLINE = time.monotonic()+390
    resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (512000000,512000000))
    status = dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    caps = {k:status[k].strip() for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']}
    interfaces = [line.split(':',1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    require(os.getuid() == os.getgid() == 65534 and os.getgroups() == [], 'rootless identity')
    require(all(int(v,16) == 0 for v in caps.values()) and status['NoNewPrivs'].strip() == '1', 'capability isolation')
    require(os.readlink('/proc/self/ns/net') != parent_namespace and interfaces == ['lo'], 'offline namespace')
    for name in ['frozen','target','bin']:
        require(os.statvfs(root/name).f_flag & os.ST_RDONLY, 'input not readonly')
    require(os.statvfs(root/'target').f_flag & os.ST_NOEXEC and os.statvfs(root/'work').f_flag & os.ST_NOEXEC, 'noexec mounts')
    target = root/'target/hl-node'
    require(not os.access(target,os.X_OK), 'capture executable')
    save(root,'qualification.json',{'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),'capabilities':caps,
        'no_new_privs':1,'interfaces':interfaces,'network_isolated':True,'target_readonly_nonexecutable':True,
        'frozen_readonly':True,'work_noexec':True,'parent_namespace':parent_namespace,
        'analysis_namespace':os.readlink('/proc/self/ns/net')})
    data = target.read_bytes()
    authenticate(data)
    rows = sections(data)
    selected,section = body(data,rows,START,END)
    require(section['flags'] & 4 and digest(selected) == BODY_SHA, 'selected body mismatch')
    controls = {}
    for label, changed in [('truncated_capture_rejected',data[:-1]), ('modified_capture_rejected',data[:-1]+bytes([data[-1]^1]))]:
        try:
            authenticate(changed)
        except ValueError:
            controls[label] = True
        else:
            controls[label] = False
    controls['changed_selected_body_rejected'] = digest(bytes([selected[0]^1])+selected[1:]) != BODY_SHA
    require(all(controls.values()), 'identity control accepted mutation')
    save(root,'controls.json',controls)
    save(root,'commands.json',{})
    versions = {}
    for name in ['objdump','readelf','llvm-objdump','llvm-dwarfdump']:
        path = command(root,'version-'+name,[name,'--version'])
        versions[name] = path.read_text().splitlines()[0]
    versions['python'] = sys.version
    save(root,'versions.json',versions)
    native = decoded(root,target,START,END,'selected',selected)
    require(len(native) == 70, 'selected instruction partition changed')
    gnu = command(root,'all-fdes-gnu',['readelf','--debug-dump=frames-interp',str(target)],large=True)
    llvm = command(root,'all-fdes-llvm',['llvm-dwarfdump','--eh-frame',str(target)],large=True)
    fa,fb = fdes(gnu),fdes(llvm)
    require(collections.Counter(fa) == collections.Counter(fb), 'native FDE-bound disagreement')
    require((0xcbef8,START,END) in fa, 'selected FDE missing')
    intervals = sorted(set((a,b) for _,a,b in fa if b>a))
    direct, slots, rip = [], [], []
    for section in rows:
        if section['type'] == 4:
            require(section['step'] == 24 and section['size']%24 == 0, 'RELA stride')
            for at in range(section['offset'],section['offset']+section['size'],24):
                slot,info,addend = struct.unpack_from('<QQq',data,at)
                if info & 0xffffffff == 8 and addend == START:
                    slots.append({'slot':hex(slot),'type':8,'addend':hex(addend),'relocation_file_offset':hex(at)})
        if section['type'] != 8 and section['flags'] & 4:
            raw = data[section['offset']:section['offset']+section['size']]
            at = raw.find(b'\xe8')
            while at >= 0:
                if at+5 <= len(raw) and section['va']+at+5+struct.unpack_from('<i',raw,at+1)[0] == START:
                    direct.append({'kind':'E8-rel32','site':hex(section['va']+at),'destination':hex(START),'bytes':raw[at:at+5].hex()})
                at = raw.find(b'\xe8',at+1)
    require(len(slots) <= 64 and len(direct) <= 128, 'incoming-reference census bound')
    destinations = {START} | {int(r['slot'],16)+delta for r in slots for delta in [0,-8,-16,-24,-32]}
    for section in rows:
        if section['type'] == 8 or not section['flags'] & 4:
            continue
        raw = data[section['offset']:section['offset']+section['size']]
        for opcode in [0x8b,0x8d,0xff]:
            at = raw.find(bytes([opcode]))
            while at >= 0:
                if at+6 <= len(raw) and raw[at+1] & 0xc7 == 5:
                    destination = section['va']+at+6+struct.unpack_from('<i',raw,at+2)[0]
                    if destination in destinations:
                        starts = [at]
                        if at and 0x40 <= raw[at-1] <= 0x4f:
                            starts.append(at-1)
                        for start in starts:
                            rip.append({'kind':'RIP-MOV-LEA-FF','site':hex(section['va']+start),'destination':hex(destination),
                                'relation':'function entry or pointer slot / possible table base within 32 preceding bytes',
                                'bytes':raw[start:at+6].hex()})
                at = raw.find(bytes([opcode]),at+1)
    require(len(rip) <= 128, 'RIP candidate bound')
    candidates = sorted(direct+rip,key=lambda r:(int(r['site'],16),r['kind'],r['bytes']))
    cache = {}
    for row in candidates:
        site = int(row['site'],16)
        owners = [(a,b) for a,b in intervals if a <= site < b]
        row['fde_owners'] = [[hex(a),hex(b)] for a,b in owners]
        row['native_qualified'] = False
        if len(owners) != 1:
            row['limitation'] = 'no unique FDE interval'
            continue
        a,b = owners[0]
        if b-a > 16384 or ((a,b) not in cache and len(cache) >= 8):
            row['limitation'] = 'caller export cap: at most 8 intervals of at most 16 KiB each'
            continue
        if (a,b) not in cache:
            chunk, owner_section = body(data,rows,a,b)
            require(owner_section['flags'] & 4, 'caller outside executable section')
            cache[(a,b)] = decoded(root,target,a,b,'caller-'+hex(a),chunk)
        instruction = cache[(a,b)].get(site)
        row['native_qualified'] = bool(instruction and instruction['bytes'] == row['bytes'])
        if instruction:
            row['decoded_instruction'] = instruction
    for row in slots:
        address = int(row['slot'],16)
        found = [r for r in rows if r['type'] != 8 and r['va'] <= address-32 and address+64 <= r['va']+r['size']]
        if len(found) == 1:
            context,_ = body(data,rows,address-32,address+64)
            row['file_context'] = {'start':hex(address-32),'hex':context.hex(),'sha256':digest(context),
                                  'meaning':'file bytes before loader relocation; no inferred runtime layout'}
    save(root,'incoming-references.json',{'base':BASE,'target_start':hex(START),'target_end':hex(END),
        'target_body_sha256':BODY_SHA,'direct_E8_candidates':direct,'relative_pointer_slots':slots,
        'instruction_candidates':candidates,'native_qualified_candidates':sum(r['native_qualified'] for r in candidates),
        'exported_caller_intervals':len(cache),'full_FDE_headers_agree':True,'FDE_records':len(fa),
        'scope_limitations':['E8 rel32 only for direct calls','R_X86_64_RELATIVE exact addends only for slots',
            'RIP MOV/LEA/FF candidates with at most one REX prefix; no whole-ISA xref claim',
            'Addresses before pointer slots are candidate table bases only; no type/layout is assigned',
            'At most eight complete caller FDE intervals of at most 16 KiB each',
            'No arbitrary register-computed targets, runtime dispatch or source/type identity inferred']})
    require(file_digest(target) == TARGET_SHA, 'capture changed')
    require(sum(p.stat().st_size for p in (root/'output').iterdir() if p.is_file()) < 8000000, 'receipt output budget')
    save(root,'result.json',{'completed':True,'base':BASE,'target_sha256':TARGET_SHA,'target_bytes':TARGET_SIZE,
        'body_sha256':BODY_SHA,'selected_native_instruction_rows':70,'full_FDE_headers_agree':True,
        'controls':controls,'caller_intervals_exported':len(cache),'raw_E8_candidates':len(direct),
        'relative_pointer_slots':len(slots),'native_qualified_candidates':sum(r['native_qualified'] for r in candidates),
        'source_owner':'unresolved; interpret incoming-reference receipts before any attribution',
        'captured_code_executed':False,'compiler_installed':False,'repository_code_executed':False})


def collect(root, destination):
    destination.mkdir(parents=True,exist_ok=True)
    files = list((root/'output').iterdir())
    require(all(p.is_file() and not p.is_symlink() and p.suffix in ['.json','.log'] for p in files), 'receipt file types')
    total = sum(p.stat().st_size for p in files)
    if total >= 8000000 or len(files) > 45:
        record = {'error':'receipt output exceeded approved bound; full payload omitted', 'output_bytes':total,
                  'files':{p.name:{'bytes':p.stat().st_size,'sha256':file_digest(p)} for p in files}}
        (destination/'collection-error.json').write_text(json.dumps(record,indent=2)+'\n')
        return
    for path in files:
        shutil.copy2(path,destination/path.name)


if __name__ == '__main__':
    require(sys.platform == 'linux', 'hosted Linux probe only; never execute this controller on the Mac')
    root = Path(sys.argv[2]).resolve()
    try:
        if sys.argv[1] == 'prepare':
            prepare(root)
        elif sys.argv[1] == 'collect':
            collect(root,Path(sys.argv[3]).resolve())
        else:
            require(sys.argv[1] == 'analyze', 'mode')
            analyze(root,sys.argv[3])
    except Exception as error:
        save(root,'controller-error.json',{'type':type(error).__name__,'detail':str(error)[:1500]})
        raise
