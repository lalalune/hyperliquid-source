import hashlib,importlib.util,json,os,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
TOOL='foundation_cached_pointer_refresh'
KIND='cache-refresh'
OFFSETS=[(2737392, 85405216, 85405257), (2737420, 85405264, None)]
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
def require(ok,msg):
    if not ok:raise ValueError(msg)
def inspect():
    sys.path.insert(0,str(ROOT/'tools'))
    spec=importlib.util.spec_from_file_location('legacy_checker',ROOT/'tools'/f'{TOOL}.py')
    checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
    binary=ROOT/'artifacts/node/94/hl-node';data=binary.read_bytes()
    require(len(data)==91774280 and hashlib.sha256(data).hexdigest()==TARGET,'Wrong captured target')
    if KIND=='devirt':
        retained=ROOT/'research/work-items/foundation-devirtualized-getter-94/evidence.json'
        ev=json.loads(retained.read_text());checker.run_evidence(ev,data,checker.elf_sections(data),str(retained.parent));legacy=ev
    else:legacy=checker.inspect(binary)
    from elf_index import sections
    sec={s['name']:s for s in sections(data)}['.eh_frame']
    def raw(offset,size):
        require(0<=offset and offset+size<=sec['size'],'Frame record outside section')
        return data[sec['offset']+offset:sec['offset']+offset+size]
    frames=[]
    for offset,start,end in OFFSETS:
        length=struct.unpack('<I',raw(offset,4))[0]
        require(16<=length<4096,'Unsupported frame length')
        record=raw(offset,length+4)
        cie_offset=offset+4-struct.unpack_from('<I',record,4)[0]
        cie_len=struct.unpack('<I',raw(cie_offset,4))[0];cie=raw(cie_offset,cie_len+4)
        require(struct.unpack_from('<I',cie,4)[0]==0,'Invalid CIE backreference')
        require(cie_offset in [0,0x6205d0],'Unreviewed CIE encoding')
        initial=sec['address']+offset+8+struct.unpack_from('<i',record,8)[0]
        extent=struct.unpack_from('<I',record,12)[0]
        require(initial==start and (end is None or initial+extent==end),'Frame interval changed')
        frames.append({'offset':hex(offset),'cie_offset':hex(cie_offset),'start':hex(initial),'end':hex(initial+extent),'raw_fde':record.hex(),'raw_cie':cie.hex()})
    return {'target_sha256':TARGET,'legacy':legacy,'raw_frame_records':frames,'captured_binary_executed':False,'instruction_emulator_used':False}
