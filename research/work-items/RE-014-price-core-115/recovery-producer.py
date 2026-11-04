from pathlib import Path
import sys,json,hashlib,subprocess
P=Path('research/work-items/RE-014-price-core-115').resolve();sys.path.insert(0,str(P));import native
out=Path('work/price-core-115-build-corrected').resolve();freeze=json.loads((P/'FREEZE.json').read_text());inputs=(out/'inputs.tsv').read_bytes();expected=(out/'expected.tsv').read_bytes()
assert hashlib.sha256(native.Image().blob).hexdigest()==native.SHA==freeze['target_sha256'];assert hashlib.sha256(inputs).hexdigest()==freeze['input_sha256'];assert hashlib.sha256(expected).hexdigest()==freeze['expected_sha256']
src=native.ROOT/'src/node115-price-core';original=(src/'lib.rs').read_text();variants=[('original',original),('infinite-not-zero',original.replace('!value.is_finite() || value <= 0.0','value <= 0.0')),('equal-rejected',original.replace('if start < floor','if start <= floor')),('wrapped-add',original.replace('product.checked_add(floor).unwrap_or(floor)','product.wrapping_add(floor)')),('zero-bucket-coerced',original.replace('bucket as f64','bucket.max(1) as f64'))];results=[]
for name,text in variants:
 text=text.replace('../../research/work-items/RE-014-price-core-115/target-smoke.tsv',str(P/'target-smoke.tsv'));assert (out/(name+'.rs')).read_text()==text
 for opt in (['0','3'] if name=='original' else ['3']):
  stem=name+'-o'+opt;exe=out/(stem+'-client');result=subprocess.run([str(exe)],input=inputs,capture_output=True,check=True);actual=result.stdout;(out/(stem+'-followup.tsv')).write_bytes(actual);assert len(actual.splitlines())==len(expected.splitlines());mismatches=sum(a!=b for a,b in zip(actual.splitlines(),expected.splitlines()));assert (name=='original')==(mismatches==0)
  smoke=subprocess.run([str(out/(stem+'-test'))],capture_output=True);(out/(stem+'-followup-test.log')).write_bytes(smoke.stdout+smoke.stderr)
  assert smoke.returncode==(0 if name=='original' else 101)
  if name!='original':assert b'assertion `left == right` failed' in smoke.stdout
  if name=='original' and opt=='3':assert subprocess.run([str(exe)],input=inputs,capture_output=True,check=True).stdout==actual
  results.append({'variant':name,'opt':opt,'rows':len(expected.splitlines()),'mismatches':mismatches,'smoke_exit':smoke.returncode,'actual_sha256':hashlib.sha256(actual).hexdigest(),'client_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'rlib_sha256':hashlib.sha256((out/('lib'+stem+'.rlib')).read_bytes()).hexdigest()})
report={'target_sha256':native.SHA,'pre_rust_freeze_commit':'bc8bee97','source_sha256':hashlib.sha256((src/'lib.rs').read_bytes()).hexdigest(),'driver_sha256':hashlib.sha256((src/'input_only_driver.rs').read_bytes()).hexdigest(),'compiler':(out/'compiler.txt').read_text(),'runs':results,'captured_process_executed':False,'whole_function_or_machine_byte_equivalence':False,'pipeline_failure':'Builder completed native replay/builds/clients/smokes, then exit1/150.743s on missing SHA in report; PACKET earlier missing before compilation, exit1/87.606s. Both constants corrected.','followup':'Actual existing clients/smokes re-executed; own opt3 rlib repeated, source texts and native stream hashes checked. No recompilation or native sweep claimed in follow-up.'}
(out/'results.json').write_text(json.dumps(report,indent=2)+'\n');(P/'rust-results.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
