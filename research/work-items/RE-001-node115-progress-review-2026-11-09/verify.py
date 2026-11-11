#!/usr/bin/env python3
"""Independently re-count pinned progress snapshots; no captured code is executed."""
import argparse,collections,hashlib,json,pathlib,platform,re,struct,subprocess
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
GATES={'mapped','built','behavior','identity'}
def need(ok,detail):
 if not ok:raise ValueError(detail)
def sha(data):return hashlib.sha256(data).hexdigest()
def git(repo,*args):return subprocess.check_output(['git','-C',str(repo),*args])
def metadata(repo,ref,path):return json.loads(git(repo,'show',ref+':'+path))
def sections(data):
 need(data[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',data,18)[0]==62,'ELF64 little-endian x86-64')
 off=struct.unpack_from('<Q',data,40)[0];size,n,strings=struct.unpack_from('<HHH',data,58)
 need(size==64 and off+n*size<=len(data) and strings<n,'section-table bounds')
 rows=[struct.unpack_from('<IIQQQQIIQQ',data,off+i*size) for i in range(n)];names=rows[strings];text=data[names[4]:names[4]+names[5]];result={}
 for r in rows:
  end=text.index(0,r[0]);name=text[r[0]:end].decode();result[name]={'type':r[1],'flags':r[2],'va':r[3],'offset':r[4],'size':r[5]}
 return result

def compare(source,target,relocations):
 need(len(source)==len(target)>0,'aligned extents');mask=set()
 for r in relocations:
  offset=r['offset'];width=r.get('width',4);kind=r.get('kind',r.get('type'))
  need(type(offset)is int and type(width)is int and width==4 and kind in (2,4,9,41,42) and type(r['addend'])is int,'recorded relocation kind/width/addend')
  positions=set(range(offset,offset+4));relax=r.get('relaxation')
  if relax=='gotpcrelx-mov-lea':
   need(kind in(41,42) and offset>=2 and source[offset-2]==0x8b and target[offset-2]==0x8d,'MOV/LEA relaxation')
   need(source[offset-1]==target[offset-1] and source[offset-1]&0xc7==5,'RIP-relative ModRM')
   need(kind!=42 or(offset>=3 and 0x40<=source[offset-3]<=0x4f),'REX relaxation prefix');positions.add(offset-2)
  elif relax=='gotpcrelx-call':
   need(kind==41 and offset>=2 and source[offset-2:offset]==b'\xff\x15' and target[offset-2:offset]==b'\x67\xe8','indirect/direct call relaxation');positions.update((offset-2,offset-1))
  else:need(relax is None,'known relaxation')
  need(positions and min(positions)>=0 and max(positions)<len(source) and not(mask&positions),'nonoverlapping bounded relocation masks');mask|=positions
 need(len(mask)<len(source),'some unmasked bytes')
 diff={i for i,(a,b) in enumerate(zip(source,target)) if a!=b}
 return {'bytes':len(target),'raw_equal_bytes':len(target)-len(diff),'raw_equal_windows':int(not diff),'relocation_qualified_windows':int(not(diff-mask)),'windows':1,'masked_bytes':len(mask),'non_relocation_bytes':len(source)-len(mask)}

def snapshot(repo,provider,ref):
 commit=git(repo,'rev-parse',ref).decode().strip();tree=git(repo,'rev-parse',commit+'^{tree}').decode().strip()
 progress=metadata(repo,commit,'research/progress.json');components=metadata(repo,commit,'research/components.json')['components'];registry=metadata(repo,commit,'research/byte-windows.json');manifest=metadata(repo,commit,'provenance/artifacts.json')
 need(len(components)==23 and {c['artifact'] for c in components}=={'node115'},'sole node115 scope')
 need(set(progress['gates'])==GATES and set(progress['components'])=={c['id'] for c in components},'gate/component scopes')
 paths=[x.split('/') for x in git(repo,'ls-tree','-r','--name-only',commit,'--','src','research/work-items').decode().splitlines()]
 inventory={'rust_areas':len({p[1] for p in paths if p[0]=='src' and len(p)>=3 and p[-1].endswith('.rs')}),'cargo_manifests':sum(p[0]=='src' and len(p)==3 and p[-1]=='Cargo.toml' for p in paths),'work_items':sum(p[:2]==['research','work-items'] and len(p)==4 and p[-1]=='README.md' for p in paths)}
 groups={c['id']:c.get('implementation_paths',[]) for c in components}
 for names in groups.values():
  for path in names:need(any('/'.join(p).startswith(path+'/') and p[-1].endswith('.rs') for p in paths),'registered Rust path exists: '+path)
 gate_totals=collections.Counter();complete=0;by_component=[]
 for c in components:
  p=progress['components'][c['id']];g=p['gates'];need(set(g)==GATES and all(type(x)is bool for x in g.values()),'boolean gates')
  for k,v in g.items():gate_totals[k]+=v
  complete+=all(g.values());by_component.append({'id':c['id'],'scope':c['scope'],'registered_bounded_paths':len(groups[c['id']]),'accepted_gates':g,'complete':all(g.values()),'whole_component_function_denominator':p['total_function_windows'],'accepted_evidence':p['evidence']})
 item=next(x for x in manifest['files'] if x['path']=='artifacts/node/115/hl-node');need(set(registry['targets'])=={'node115'} and registry['targets']['node115']['sha256']==SHA and registry['targets']['node115']['path']==item['path'],'registry target binding');data=(provider/item['path']).read_bytes();need(sha(data)==item['sha256']==SHA and len(data)==item['size'],'authenticated target')
 sec=sections(data)['.text'];need(sec['flags']&4 and sec['type']==1,'executable .text denominator')
 cache={};json_cache={}
 for path,want in registry['evidence_sha256'].items():
  candidate=(provider/path).resolve();need(candidate.is_relative_to(provider.resolve()) and candidate.is_file(),'local evidence path');raw=candidate.read_bytes();need(sha(raw)==want,'evidence SHA: '+path);cache[path]=raw
 def pointer(path,keys):
  if path not in json_cache:json_cache[path]=json.loads(cache[path])
  value=json_cache[path]
  for key in keys:value=value[key]
  return value
 total=collections.Counter();deps=collections.defaultdict(collections.Counter);intervals=[];extent_mismatches=[];new_window=None
 for r in registry['windows']:
  need(r['target']=='node115' and r['component'] in groups and r.get('comparison_mode','offset-aligned') in ('offset-aligned','extent-mismatch'),'comparison owner/target/mode');start,end=r['start'],r['end'];need(type(start)is int and type(end)is int and sec['va']<=start<end<=sec['va']+sec['size'],'text bounds');intervals.append((start,end,r['id']))
  offset=sec['offset']+start-sec['va'];target=data[offset:offset+end-start];need(sha(target)==r['target_body_sha256'],'target window SHA: '+r['id'])
  s=r['source'];need(s['encoding'] in ('binary','hex'),'source encoding');source=cache[s['path']];source=bytes.fromhex(source.decode()) if s['encoding']=='hex' else source;begin=s.get('offset',0);length=s.get('length',end-start);source=source[begin:begin+length];need(len(source)==length and sha(source)==s['body_sha256'],'source window SHA: '+r['id'])
  if r.get('comparison_mode')=='extent-mismatch':
   need(len(source)!=len(target) and r.get('relocations')is None,'unaligned candidate');extent_mismatches.append({'id':r['id'],'target_bytes':len(target),'source_bytes':len(source),'credit':0});continue
  rel=r.get('relocations');relocations=pointer(rel['path'],rel['pointer']) if rel else[]
  if rel and len(rel['pointer'])==3 and rel['pointer'][0]=='records' and rel['pointer'][2]=='relocations':
   owner=pointer(rel['path'],rel['pointer'][:2]);need((owner['start'],owner['end'],owner['source_offset'],owner['source_body_sha256'])==(start,end,begin,s['body_sha256']),'relocation record ownership')
  if isinstance(relocations,dict):relocations=[relocations]
  result=compare(source,target,relocations);total.update(result);deps[r.get('dependency','first-party')].update(result)
  if r['id']=='node115-blst-portable-sha256-cfa':new_window={'id':r['id'],'dependency':r['dependency'],'target_start':start,'target_end':end,**result}
 for a,b in zip(sorted(intervals),sorted(intervals)[1:]):need(a[1]<=b[0],'no double-counted target intervals')
 percentages={'accepted_full_scope_gates':100*sum(gate_totals.values())/(23*4),'complete_components':100*complete/23,'target_text_compared':100*total['bytes']/sec['size'],'target_text_raw_equal':100*total['raw_equal_bytes']/sec['size']}
 result={'commit':commit,'tree':tree,'target_sha256':SHA,'target_file_bytes':len(data),'text_bytes':sec['size'],'inventory':inventory,'registered_rust_components':sum(bool(v) for v in groups.values()),'registered_bounded_paths':sum(map(len,groups.values())),'accepted_full_scope_gates':sum(gate_totals.values()),'total_gates':92,'complete_components':complete,'component_count':23,'gate_counts':dict(gate_totals),'percentages':percentages,'comparisons':dict(total),'dependency_comparisons':{k:dict(v) for k,v in sorted(deps.items())},'extent_mismatches':extent_mismatches,'component_assessment':by_component,'new_blst_window':new_window,'pinned_byte_evidence_files':len(cache)}
 return result

def readme_check(text, r):
 inventory=r['inventory'];need(f"**{inventory['rust_areas']} active Rust implementation areas · {inventory['cargo_manifests']} top-level Cargo manifests · {inventory['work_items']} #115 research work items.**" in text,'README tracked inventory')
 rows={'Accepted full-scope gates':(r['accepted_full_scope_gates'],92,2),'Complete node components':(r['complete_components'],23,2),'Components fully mapped':(r['gate_counts']['mapped'],23,2),'Components fully built':(r['gate_counts']['built'],23,2),'Components with full behavioral validation':(r['gate_counts']['behavior'],23,2),'Components with full code/data identity':(r['gate_counts']['identity'],23,2),'Target .text bytes compared':(r['comparisons']['bytes'],r['text_bytes'],5),'Target .text bytes raw-equal':(r['comparisons']['raw_equal_bytes'],r['text_bytes'],5)}
 for label,(n,d,precision) in rows.items():
  numeric=f'{n:,}/{d:,}' if label.startswith('Target') else f'{n}/{d}'
  need(f'| {label} | {numeric} | {100*n/d:.{precision}f}% |' in text,'README fraction: '+label)
 def frac(n,d):return f'{n:,}/{d:,} ({100*n/d:.2f}%)'
 for label,value in [('**Node #115 total**',r['comparisons']),*r['dependency_comparisons'].items()]:
  need(f"| {label} | {frac(value['raw_equal_bytes'],value['bytes'])} | {frac(value['raw_equal_windows'],value['windows'])} | {frac(value['relocation_qualified_windows'],value['windows'])} |" in text,'README comparison fractions: '+label)
 need('they do not measure whole-node completion or remaining engineering effort.' in text,'README byte-percentage limitation')
 return {'sha256':sha(text.encode()),'inventory_matches_tracked_tree':True,'completion_fraction_rows_checked':len(rows),'comparison_fraction_rows_checked':1+len(r['dependency_comparisons']),'full_scope_gate_percent':100*r['accepted_full_scope_gates']/92}

def controls():
 base=compare(b'abcd0000',b'abcd1234',[{'offset':4,'width':4,'kind':4,'addend':-4}]);need(base['relocation_qualified_windows']==1,'positive mask control')
 bad=compare(b'xbcd0000',b'abcd1234',[{'offset':4,'width':4,'kind':4,'addend':-4}]);need(bad['relocation_qualified_windows']==0,'unmasked byte control')
 for rel in ([{'offset':5,'width':4,'kind':4,'addend':-4}],[{'offset':4,'width':4,'kind':1,'addend':0}],[{'offset':4,'width':4,'kind':4,'addend':-4}]*2):
  try:compare(b'abcd0000',b'abcd1234',rel)
  except ValueError:continue
  raise ValueError('bad mask control survived')
 return {'positive_mask':1,'negative_controls_attempted':4,'negative_controls_detected':4}

def main():
 p=argparse.ArgumentParser();p.add_argument('--repo',type=pathlib.Path,required=True);p.add_argument('--provider',type=pathlib.Path,required=True);p.add_argument('--before',default='d6395549bfdcfb2237a9ce2129253fd255244eb7');p.add_argument('--after',default='91b28122e3956cef666750dc579d5f77810cdfef');p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();need(re.fullmatch('[0-9a-f]{40}',a.before) and re.fullmatch('[0-9a-f]{40}',a.after),'immutable commit IDs')
 before=snapshot(a.repo,a.provider,a.before);after=snapshot(a.repo,a.provider,a.after);before['readme_audit']=readme_check(git(a.repo,'show',before['commit']+':README.md').decode(),before);after['readme_audit']=readme_check((a.provider/'README.md').read_text(),after);need(before['accepted_full_scope_gates']==after['accepted_full_scope_gates']==0,'no unsupported gate advancement');need('first-party' not in before['dependency_comparisons'] and 'first-party' not in after['dependency_comparisons'],'all registered comparisons are dependencies')
 report={'schema_version':1,'reviewed_on':'2026-11-09','method':'Independent ELF64 section parsing, tracked-Git inventory, direct byte/relocation comparison and printed-fraction checks; production catalogue functions are not imported.','audit_source_sha256':sha(pathlib.Path(__file__).read_bytes()),'tooling':{'python':platform.python_version(),'git':git(a.repo,'--version').decode().strip()},'audit_scope':'Current remote main and a pinned pending integration snapshot; final generated README must use its actual source tree.','controls':controls(),'main':before,'pending_integration_snapshot':after,'delta':{'rust_areas':after['inventory']['rust_areas']-before['inventory']['rust_areas'],'cargo_manifests':after['inventory']['cargo_manifests']-before['inventory']['cargo_manifests'],'research_work_items':after['inventory']['work_items']-before['inventory']['work_items'],'text_bytes_compared':after['comparisons']['bytes']-before['comparisons']['bytes'],'raw_equal_bytes':after['comparisons']['raw_equal_bytes']-before['comparisons']['raw_equal_bytes'],'compared_percentage_points':after['percentages']['target_text_compared']-before['percentages']['target_text_compared'],'accepted_gates':0},'limitations':['The pending snapshot is not a merged-main claim.','Rust paths, manifests, work items and PR counts are inventories, not completion percentages.','All registered aligned comparisons are public dependencies; first-party component comparison totals remain zero.','Full component function/byte denominators, complete dependency/private-fork closure and an integrated source-built node remain unestablished.','No captured native code, networking or chain action is executed by this audit.']}
 a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'main':before['inventory'],'pending':after['inventory'],'percentages':after['percentages'],'comparisons':after['comparisons'],'controls':report['controls']},indent=2))
if __name__=='__main__':main()
