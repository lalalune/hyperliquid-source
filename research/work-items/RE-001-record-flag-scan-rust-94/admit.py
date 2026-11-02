"""Target-bound static admission, not an instruction evaluator."""
from pathlib import Path
import hashlib,importlib.util,json,struct,sys
P=Path(__file__).resolve().parent
ROOT=P.parents[2]
CONFIG={'tool': 'foundation_all_records_flag_scan', 'packet': 'foundation-all-records-flag-scan-94', 'start': 62775472, 'end': 62775563, 'fde': 1816224, 'next': 62775568, 'call': 62775500, 'target': 63024544, 'callee_fde': 5282692, 'callee_end': 63025614}
TARGET_SHA256='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
def require(ok,message):
    if not ok:raise ValueError(message)
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def source_hashes():
    old=ROOT/'research/work-items'/CONFIG['packet']
    paths=[ROOT/'tools'/f"{CONFIG['tool']}.py",ROOT/'tools/elf_index.py',*[p for p in old.iterdir() if p.is_file()]]
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
def inspect(data):
    require(len(data)==91774280 and hashlib.sha256(data).hexdigest()==TARGET_SHA256,'Wrong node94 capture')
    sys.path.insert(0,str(ROOT/'tools'))
    elf=load('scope_elf_index',ROOT/'tools/elf_index.py')
    sections=elf.sections(data);by_name={s['name']:s for s in sections}
    old=ROOT/'research/work-items'/CONFIG['packet']
    checker=load('scope_old_checker',ROOT/'tools'/f"{CONFIG['tool']}.py")
    if hasattr(checker,'run_evidence'):
        legacy=json.loads((old/'evidence.json').read_text())
        failures=checker.run_evidence(legacy,data,checker.elf_sections(data),str(old))
        require(not failures,'Existing target packet failed: '+str(failures))
    else:
        legacy=checker.analyze(data)
    regions=[]
    def region(name,va,size):
        candidates=[s for s in sections if s['type']!=8 and s['address']<=va and va+size<=s['address']+s['size']]
        require(len(candidates)==1,'Region mapping is not unique')
        s=candidates[0];off=s['offset']+va-s['address'];raw=data[off:off+size]
        require(len(raw)==size,'Truncated selected region')
        regions.append(dict(name=name,va=hex(va),file_offset=off,bytes=size,sha256=hashlib.sha256(raw).hexdigest()))
        return raw
    region('complete function',CONFIG['start'],CONFIG['end']-CONFIG['start'])
    region('following alignment',CONFIG['end'],CONFIG['next']-CONFIG['end'])
    eh=by_name['.eh_frame']
    def frame(offset,start,end):
        length=struct.unpack_from('<I',data,eh['offset']+offset)[0]
        require(16<=length<1024,'Unexpected retained FDE size')
        raw=region('FDE '+hex(start),eh['address']+offset,length+4)
        pc=eh['address']+offset+8+struct.unpack_from('<i',raw,8)[0]
        size=struct.unpack_from('<I',raw,12)[0]
        require((pc,pc+size)==(start,end),'Retained pcrel/sdata4 FDE range differs')
        cie_offset=offset+4-struct.unpack_from('<I',raw,4)[0]
        cie_length=struct.unpack_from('<I',data,eh['offset']+cie_offset)[0]
        require(8<=cie_length<128,'Unexpected retained CIE size')
        cie=region('CIE for '+hex(start),eh['address']+cie_offset,cie_length+4)
        return dict(section_offset=hex(offset),start=hex(pc),end=hex(pc+size),cie_section_offset=hex(cie_offset),cie_hex=cie.hex())
    frames=[frame(CONFIG['fde'],CONFIG['start'],CONFIG['end'])]
    calls=[]
    if 'call' in CONFIG:
        raw=region('direct call',CONFIG['call'],5)
        require(raw[0]==0xe8 and CONFIG['call']+5+struct.unpack_from('<i',raw,1)[0]==CONFIG['target'],'Direct call projection differs')
        calls.append(dict(site=hex(CONFIG['call']),target=hex(CONFIG['target'])))
    if 'callee_fde' in CONFIG:frames.append(frame(CONFIG['callee_fde'],CONFIG['target'],CONFIG['callee_end']))
    binding=None
    if CONFIG['tool']=='foundation_byte_gate_counter':
        plt=region('PLT insert-and-rebalance',0x5660550,16)
        require(plt[:2]==b'\xff\x25','Unexpected PLT entry')
        slot=0x5660550+6+struct.unpack_from('<i',plt,2)[0]
        require(slot==0x5778fd0,'PLT slot differs')
        got=region('PLT slot initial value',slot,8)
        require(struct.unpack('<Q',got)[0]==0x5660556,'Initial resolver pointer differs')
        rela=by_name['.rela.plt'];found=[]
        for off in range(0,rela['size'],24):
            r_offset,info,addend=struct.unpack_from('<QQq',data,rela['offset']+off)
            if r_offset==slot:found.append((off,info,addend))
        require(len(found)==1 and (found[0][1]&0xffffffff)==7,'Unique JUMP_SLOT binding absent')
        off,info,addend=found[0]
        region('insert-and-rebalance JUMP_SLOT',rela['address']+off,24)
        dynsym=by_name['.dynsym'];symbol_offset=dynsym['offset']+(info>>32)*24
        name_offset=struct.unpack_from('<I',data,symbol_offset)[0]
        region('bound dynamic symbol',dynsym['address']+(info>>32)*24,24)
        strings=by_name['.dynstr'];begin=strings['offset']+name_offset;end=data.index(b'\0',begin)
        name=data[begin:end].decode('ascii')
        require(name=='_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_','Dynamic symbol differs')
        region('bound dynamic symbol name',strings['address']+name_offset,end-begin+1)
        binding=dict(slot=hex(slot),symbol=name,relocation_type='R_X86_64_JUMP_SLOT',runtime_implementation_unresolved=True)
    return dict(target_sha256=TARGET_SHA256,config=CONFIG,legacy_packet=legacy,frames=frames,calls=calls,external_binding=binding,regions=regions,source_sha256=source_hashes(),captured_binary_executed=False)
def check_selected_regions(data,admitted):
    for r in admitted['regions']:
        raw=data[r['file_offset']:r['file_offset']+r['bytes']]
        require(hashlib.sha256(raw).hexdigest()==r['sha256'],'Changed selected region: '+r['name'])
