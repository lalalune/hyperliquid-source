#!/usr/bin/env python3
"""Real-capture structural corruption controls; never executes/emulates node code."""
import argparse
import copy
import gzip
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import tempfile

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('shutdown_verify',HERE/'verify.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)


def controls(data):
    secs=v.sections(data);out=[]
    def changed(va,value):
        matches=[s for s in secs if s['type']!=8 and s['address']<=va and va+len(value)<=s['address']+s['size']]
        assert len(matches)==1
        s=matches[0];off=s['offset']+va-s['address'];b=bytearray(data);b[off:off+len(value)]=value;return b
    def refuses(name,call,pattern):
        try:call()
        except ValueError as error:
            if not re.search(pattern,str(error)):raise AssertionError((name,str(error),pattern))
            out.append({'name':name,'status':'rejected','reason':str(error)})
        else:raise AssertionError(name+' was accepted')
        print(json.dumps(out[-1]),flush=True)
    real=v.build(data)
    assert real==json.loads((HERE/'observations.json').read_bytes())
    assert real['completion']['rawOutputTags']=={'completion-empty':0,'completion-payload':2,'delegate-low-bit':3}
    for name,va,value in [
        ('flag-gate-inverted',0x1496f22,b'\x0f\x85'),
        ('variant-short-branch-inverted',0x1496f30,b'\x74'),
        ('variant-delegate-offset',0x1496f35,struct.pack('<I',0xf8)),
        ('plain-fd-offset',0x4f7d613,b'\x20'),
        ('shutdown-how-rdwr',0x4f7d61a,struct.pack('<I',2)),
        ('errno-shift-width',0x4f7d63a,b'\x10'),
        ('errno-low-tag',0x4f7d63e,b'\x01'),
        ('completion-load-offset',0x14970e8,struct.pack('<I',0xd0)),
        ('completion-clear-offset',0x14970ef,struct.pack('<I',0xd0)),
        ('completion-clear-nonzero',0x14970f3,struct.pack('<I',1)),
        ('empty-result-tag',0x1497108,struct.pack('<I',1)),
        ('payload-result-tag',0x14971f3,struct.pack('<I',0)),
        ('delegate-result-tag',0x1496d0f,struct.pack('<I',1)),
        ('shutdown-error-gate-inverted',0x1496fbe,b'\x0f\x85'),
        ('shutdown-wrapper-call-retarget',0x1496fac,struct.pack('<i',0)),
    ]:
        refuses(name,lambda va=va,value=value:v.observe(changed(va,value)),'Changed selected instruction')
    for slot,expected in [(0x576fbe8,0x4f7d610),(0x576fc00,0x29c7d90),(0x576e470,0x157a9f0)]:
        needle=struct.pack('<QQq',slot,8,expected);off=data.find(needle)
        assert off>=0 and data.find(needle,off+1)==-1
        b=bytearray(data);b[off+16]^=1
        refuses('relative-retarget-'+hex(slot),lambda b=b:v.observe(b),'Changed relocation')
    rel=next(s for s in secs if s['name']=='.rela.dyn')
    for slot in [0x576f440,0x576e8d8]:
        offsets=[i for i in range(rel['offset'],rel['offset']+rel['size'],24) if struct.unpack_from('<Q',data,i)[0]==slot]
        assert len(offsets)==1
        b=bytearray(data);struct.pack_into('<Q',b,offsets[0]+8,6)
        refuses('import-symbol-cleared-'+hex(slot),lambda b=b:v.observe(b),'Changed relocation')
    refuses('full-body-unanchored-byte',lambda:v.observe(changed(0x1493170,b'\x54')),'Changed complete body')
    refuses('fde-length',lambda:v.observe(changed(0xfd8648+12,struct.pack('<I',18203))),'Changed FDE extent')
    refuses('whole-input-identity',lambda:v.build(data[:-1]+bytes([data[-1]^1])),'Wrong node94 capture identity')
    original=json.loads(gzip.decompress((HERE/'disassembly.json.gz').read_bytes()))
    for name,modify,pattern in [
        ('decoder-byte',lambda d:d['1493170']['instructions'][0].update(bytes='54'),'Decoder bytes differ'),
        ('decoder-address',lambda d:d['1493170']['instructions'][0].update(va='0x1493171'),'Noncontiguous'),
        ('decoder-truncated-range',lambda d:d['1493170']['instructions'].pop(),'complete FDE'),
    ]:
        with tempfile.TemporaryDirectory(prefix='http-shutdown-control-') as tmp:
            packet=Path(tmp);shutil.copyfile(HERE/'gnu.objdump.txt.gz',packet/'gnu.objdump.txt.gz')
            damaged=copy.deepcopy(original);modify(damaged)
            (packet/'disassembly.json.gz').write_bytes(gzip.compress(json.dumps(damaged).encode(),mtime=0))
            refuses(name,lambda:v.verify_exports(data,packet),pattern)
    with tempfile.TemporaryDirectory(prefix='http-shutdown-control-') as tmp:
        packet=Path(tmp);shutil.copyfile(HERE/'disassembly.json.gz',packet/'disassembly.json.gz')
        text=gzip.decompress((HERE/'gnu.objdump.txt.gz').read_bytes()).decode('utf8')
        # Preserve valid GNU syntax while changing one actual raw-byte pair.
        text,count=re.subn(r'(1493170:\s+)55\b',r'\g<1>54',text,count=1);assert count==1
        (packet/'gnu.objdump.txt.gz').write_bytes(gzip.compress(text.encode(),mtime=0))
        refuses('independent-gnu-byte',lambda:v.verify_exports(data,packet),'Independent decoder pairs differ')
    return {'positive':'full authenticated capture and committed observations agree',
            'negativeControls':out,'rejected':len(out),'capturedExecution':False,
            'scope':'Static observer/export corruption rejection, not captured runtime behavior or an emulator.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=v.ROOT/'artifacts/node/94/hl-node')
    p.add_argument('--out',type=Path);a=p.parse_args();result=controls(a.binary.read_bytes())
    if a.out:a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'rejected':result['rejected'],'positive':result['positive']}))
if __name__=='__main__':main()
