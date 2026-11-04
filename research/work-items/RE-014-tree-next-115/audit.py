"""Authenticate owner bytes, actual caller transfers, unwind and source context."""
import hashlib,json,struct
import native

def audit():
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  f=json.loads((native.PACKET/'FREEZE.json').read_text())
  for owner in f['owners']:
   a,b=int(owner['start'],16),int(owner['end'],16)
   if im.view.fde(a)!=(a,b):raise ValueError('FDE boundary changed')
   if hashlib.sha256(im.view.read(a,b-a)).hexdigest()!=owner['sha256']:raise ValueError('owner bytes changed')
   for rec in owner['unwind_raw'].values():
    raw=bytes.fromhex(rec['raw_hex'])
    if im.view.read(int(rec['va'],16),len(raw))!=raw:raise ValueError('unwind changed')
  calls={0x3bcae73:0x422e280,0x422e363:0x37c4430}
  for site,target in calls.items():
   raw=im.view.read(site,5)
   if raw[0]!=0xe8 or site+5+struct.unpack_from('<i',raw,1)[0]!=target:raise ValueError('caller changed')
  if im.view.locations('base/src/quorum_policy.rs').get(0x6475bd8)!=(72,9):raise ValueError('source Location changed')
  return dict(target_sha256=native.SHA,owners=len(f['owners']),bytes=sum(o['bytes'] for o in f['owners']),instructions=sum(o['instructions'] for o in f['owners']),core_instructions=126,core_visited=121,static_calls={hex(k):hex(v) for k,v in calls.items()},source_context='base/src/quorum_policy.rs:72:9; context only',full_caller_execution=False,full_component_gates=False)
 finally:im.close()
if __name__=='__main__':print(json.dumps(audit(),indent=2))
