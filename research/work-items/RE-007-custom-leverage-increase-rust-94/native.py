"""Static caller identity/edge authentication. No instruction evaluation."""
from pathlib import Path
import hashlib,importlib.util,json,struct
ROOT=Path(__file__).resolve().parents[3];HERE=Path(__file__).resolve().parent
OLD=ROOT/'research/work-items/RE-007-tier-cap-rust-94'
def need(ok,msg):
    if not ok:raise ValueError(msg)
def authenticate(raw):
    spec=importlib.util.spec_from_file_location('credited_tier_cap_identity',OLD/'native.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old);old.authenticate(raw)
    f=json.loads((HERE/'pre-source/NATIVE-FREEZE.json').read_text());elf=old.Elf(raw);body=f['function']
    need(hashlib.sha256(elf.read(int(body['start'],16),body['bytes'])).hexdigest()==body['body_sha256'],'caller body')
    for c in f['coordinate_controls']:need(elf.read(int(c['va'],16),len(bytes.fromhex(c['hex']))).hex()==c['hex'],'caller coordinate '+c['name'])
    for kind in ['gnu','llvm']:
        export=OLD/'native'/('0x37098a0.'+kind+'.txt');need(hashlib.sha256(export.read_bytes()).hexdigest()==f['export_sha256'][kind],'credited complete caller export')
    for va,op,target in [(0x3709f06,b'\x0f\x86',0x370a07d),(0x370a090,b'\x0f\x83',0x3709cfa)]:
        b=elf.read(va,6);need(b[:2]==op and va+6+struct.unpack_from('<i',b,2)[0]==target,'selected near branch')
    b=elf.read(0x370a086,2);need(b==b'\x75\x0e' and 0x370a086+2==0x370a088,'same table fallthrough')
    for va in [0x370a249,0x370a27a]:
        b=elf.read(va,6);need(b[:2]==b'\xff\x15' and va+6+struct.unpack_from('<i',b,2)[0]==0x57746f0,'excluded margin call slot')
    return {'caller_bytes':body['bytes'],'caller_instructions':body['instructions'],'coordinate_identity_controls':15,'syntactic_blocks':len(f['blocks']),'EnterCommit_is_not_success':True,'captured_execution':False}
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--target',type=Path,default=ROOT/'artifacts/node/94/hl-node');a=p.parse_args();print(json.dumps(authenticate(a.target.read_bytes()),sort_keys=True))
