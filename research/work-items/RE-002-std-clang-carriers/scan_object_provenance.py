"""Bounded static ar/ELF parsers. Data are read in memory, never extracted or executed."""
import hashlib
import struct

STAMPS = {b'clang version 21.1.0-rc2', b'clang version 22.1.0-rc2'}
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 768 * 1024 * 1024
MAX_MEMBERS = 100000


class FormatError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise FormatError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def string_at(blob, offset):
    require(0 <= offset < len(blob), 'string offset outside table')
    end = blob.find(b'\0', offset)
    require(end >= offset, 'unterminated string')
    return blob[offset:end].decode('utf-8', 'backslashreplace')


def ar_members(blob):
    require(not blob.startswith(b'!<thin>\n'), 'thin archive external references excluded')
    require(blob.startswith(b'!<arch>\n'), 'not a regular ar archive')
    records = []
    at = 8
    longnames = b''
    while at < len(blob):
        require(len(records) < MAX_MEMBERS, 'ar member limit')
        require(at + 60 <= len(blob), 'truncated ar header')
        header = blob[at:at+60]
        require(header[58:60] == b'`\n', 'invalid ar header terminator')
        try:
            size = int(header[48:58].decode('ascii').strip())
        except (ValueError, UnicodeError) as exc:
            raise FormatError('invalid ar size') from exc
        require(size >= 0 and at + 60 + size <= len(blob), 'ar member outside archive')
        field = header[:16].decode('ascii').rstrip()
        begin = at + 60
        if field == '//':
            require(not longnames, 'duplicate GNU ar long-name table')
            longnames = blob[begin:begin+size]
        records.append((field, begin, size))
        at = begin + size + (size & 1)
        require(at <= len(blob), 'missing ar alignment byte')
    for index, (field, begin, size) in enumerate(records):
        special = field in ['/', '//', '/SYM64/']
        if field.startswith('#1/'):
            try:
                n = int(field[3:])
            except ValueError as exc:
                raise FormatError('invalid BSD ar name width') from exc
            require(0 <= n <= size, 'BSD ar name outside member')
            name = blob[begin:begin+n].rstrip(b'\0').decode('utf-8', 'backslashreplace')
            begin += n
            size -= n
        elif field.startswith('/') and field[1:].isdigit():
            start = int(field[1:])
            require(start < len(longnames), 'GNU ar name offset outside table')
            end = longnames.find(b'/\n', start)
            require(end >= start, 'unterminated GNU ar long name')
            name = longnames[start:end].decode('utf-8', 'backslashreplace')
        else:
            name = field[:-1] if field.endswith('/') and not special else field
        special = special or name.startswith('__.SYMDEF')
        yield dict(index=index, name=name, offset=begin, size=size, special=special), memoryview(blob)[begin:begin+size]


def elf_sections(blob):
    require(len(blob) >= 64 and blob[:6] == b'\x7fELF\x02\x01', 'unsupported ELF class/endianness')
    typ, machine = struct.unpack_from('<HH', blob, 16)
    shoff = struct.unpack_from('<Q', blob, 40)[0]
    stride, count, names = struct.unpack_from('<HHH', blob, 58)
    require(shoff and stride >= 64 and shoff + stride <= len(blob), 'invalid ELF section header table')
    first = struct.unpack_from('<IIQQQQIIQQ', blob, shoff)
    count = count or first[5]
    names = first[6] if names == 0xffff else names
    require(0 < count < MAX_MEMBERS and names < count and shoff + count*stride <= len(blob), 'ELF section table outside file')
    rows = []
    for i in range(count):
        n,t,f,a,o,s,l,k,align,entry = struct.unpack_from('<IIQQQQIIQQ',blob,shoff+i*stride)
        require(t == 8 or o+s <= len(blob), 'ELF section payload outside file')
        rows.append(dict(index=i,name_offset=n,type=t,flags=f,address=a,offset=o,size=s,
                         link=l,info=k,alignment=align,entry_size=entry))
    table = rows[names]
    require(table['type'] == 3, 'section names are not STRTAB')
    strings = blob[table['offset']:table['offset']+table['size']]
    for row in rows:
        row['name'] = string_at(strings,row['name_offset'])
        row['sha256'] = None if row['type']==8 else digest(memoryview(blob)[row['offset']:row['offset']+row['size']])
    return typ,machine,shoff,stride,rows


def elf_details(blob, details=True):
    typ,machine,shoff,stride,secs = elf_sections(blob)
    comments = []
    matched = []
    for sec in secs:
        if sec['name'] != '.comment' or sec['type']==8:
            continue
        raw = bytes(blob[sec['offset']:sec['offset']+sec['size']])
        offset = sec['offset']
        for value in raw.split(b'\0'):
            if value:
                row = dict(section_index=sec['index'],file_offset=offset,text=value.decode('utf-8','backslashreplace'))
                comments.append(row)
                if value in STAMPS:
                    matched.append(row)
            offset += len(value)+1
    result = dict(elf_type=typ,machine=machine,section_count=len(secs),comments=comments,matching_clang_comments=matched)
    if not matched or typ != 1 or not details:
        return result
    require(machine==62, 'matching carrier is not AMD64')
    tables = {}
    symbols = []
    for sec in secs:
        if sec['type'] not in (2,11):
            continue
        step = sec['entry_size']
        require(step >= 24 and sec['size']%step==0 and sec['link']<len(secs), 'invalid ELF symbol table shape')
        names = secs[sec['link']]
        require(names['type']==3,'symbol names are not STRTAB')
        strings = blob[names['offset']:names['offset']+names['size']]
        table = []
        extended = next((r for r in secs if r['type']==18 and r['link']==sec['index']),None)
        for index,at in enumerate(range(sec['offset'],sec['offset']+sec['size'],step)):
            n,info,other,section,value,size = struct.unpack_from('<IBBHQQ',blob,at)
            if section==0xffff:
                require(extended is not None and index*4+4<=extended['size'],'missing extended symbol section index')
                section=struct.unpack_from('<I',blob,extended['offset']+4*index)[0]
            sym=dict(table_section=sec['index'],index=index,name=string_at(strings,n),
                     binding=info>>4,type=info&15,visibility=other&3,section_index=section,value=value,size=size)
            if 0 < section < len(secs) and size and (info&15) in (1,2):
                owner=secs[section]
                relative=value if typ==1 else value-owner['address']
                require(0 <= relative and relative+size<=owner['size'],'defined symbol outside owner section')
                sym['section_name']=owner['name']
                sym['section_relative_offset']=relative
                sym['file_offset']=owner['offset']+relative
                sym['payload_sha256']=None if owner['type']==8 else digest(memoryview(blob)[sym['file_offset']:sym['file_offset']+size])
            table.append(sym)
            symbols.append(sym)
        tables[sec['index']]=table
    relocations=[]
    for sec in secs:
        if sec['type'] not in (4,9):
            continue
        minimum=24 if sec['type']==4 else 16
        step=sec['entry_size']
        require(step>=minimum and sec['size']%step==0 and sec['link'] in tables and sec['info']<len(secs),'invalid relocation table shape/link')
        for index,at in enumerate(range(sec['offset'],sec['offset']+sec['size'],step)):
            offset,info=struct.unpack_from('<QQ',blob,at)
            symbol=info>>32
            require(symbol<len(tables[sec['link']]),'relocation symbol outside table')
            relocations.append(dict(table_section=sec['index'],index=index,target_section=sec['info'],
                                    offset=offset,type=info&0xffffffff,symbol_table=sec['link'],symbol_index=symbol,
                                    symbol_name=tables[sec['link']][symbol]['name'],
                                    addend=struct.unpack_from('<q',blob,at+16)[0] if sec['type']==4 else None))
    result.update(sections=secs,symbols=symbols,relocations=relocations,
                  executable_sections=[s['index'] for s in secs if s['flags']&4 and s['type']!=8 and s['size']],
                  allocated_data_sections=[s['index'] for s in secs if s['flags']&2 and not s['flags']&4 and s['size']],
                  section_header_offset=shoff,section_header_stride=stride)
    return result


def classify(blob):
    head=bytes(blob[:8])
    if head.startswith(b'\x7fELF'): return 'ELF64LE' if head[4:6]==b'\x02\x01' else 'unsupported_ELF'
    if head.startswith(b'BC\xc0\xde') or head.startswith(b'\xde\xc0\x17\x0b'):return 'LLVM_bitcode_not_decoded'
    return 'non_ELF'


def negative_controls(blob):
    controls=[]
    def rejection(label,value,parser):
        try:parser(value)
        except FormatError as exc:controls.append(dict(case=label,sha256=digest(value),rejected=True,error=str(exc)))
        else:raise AssertionError('accepted negative control '+label)
    rejection('thin_ar_excluded',b'!<thin>\n',lambda b:list(ar_members(b)))
    rejection('truncated_ar_header',b'!<arch>\n'+b'x'*20,lambda b:list(ar_members(b)))
    header=b'control.o/      '+b'0           '+b'0     '+b'0     '+b'100644  '+b'100       '+b'`\n'
    require(len(header)==60,'owned negative header shape')
    rejection('ar_member_outside_file',b'!<arch>\n'+header+b'x',lambda b:list(ar_members(b)))
    detail=elf_details(blob)
    sec=next(s for s in detail['sections'] if s['name']=='.comment')
    mutated=bytearray(blob)
    struct.pack_into('<Q',mutated,detail['section_header_offset']+sec['index']*detail['section_header_stride']+32,len(blob)+1)
    rejection('actual_carrier_comment_outside_file',mutated,elf_details)
    changed=bytearray(blob)
    at=detail['matching_clang_comments'][0]['file_offset']
    changed[at]=ord('X')
    revised=elf_details(changed)
    require(len(revised['matching_clang_comments'])==len(detail['matching_clang_comments'])-1,'stamp corruption did not remove exact match')
    controls.append(dict(case='actual_carrier_stamp_byte_corruption',source_sha256=digest(blob),sha256=digest(changed),
                         changed_file_offset=at,matching_stamp_removed=True,
                         limit='selection control only; code binding requires separate evidence'))
    return controls
