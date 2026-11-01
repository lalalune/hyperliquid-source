from pathlib import Path
import importlib.util,json,time
ROOT=Path('/tmp/hl-resume-20261101/readers-56c')
PACKET=ROOT/'research/work-items/RE-005-byte-bool-rust-94'
spec=importlib.util.spec_from_file_location('byte197_run',PACKET/'run.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
OUT=ROOT/'work/byte-bool-197-static1'
m.require(not OUT.exists(),'fresh static output required');OUT.mkdir()
experiment=m.Experiment(OUT)
node=Path('/tmp/beam-20261101/toolchain/node-v22.23.4-linux-x64/bin/node')
experiment.declared_env['REA_NODE']=str(node)
before=m.audit();before['selected_static_node_tool']={'path':str(node),**m.file_record(node)}
m.require(before['head']=='30f04afefa59d2203e0d3b55bd35f4ff2539ecf3' and not before['status'],'expected clean C2')
m.save(OUT/'AUDIT-BEFORE.json',before)
started=time.monotonic()
try:
    for label in ['doctor','verify','catalogue-check','reproduce']:
        experiment.command(label,['/usr/bin/make',label])
finally:
    after=m.audit();after['selected_static_node_tool']={'path':str(node),**m.file_record(node)}
    m.save(OUT/'AUDIT-AFTER.json',after)
    m.require(before==after,'static inputs changed')
result={'head':before['head'],'source_checkpoint':'56244f5c34c5ec0c2a7cab90a42d450ce757081b','root_files':len(before['files']),'pin_files':sum(len(p['tracked_physical_files']) for p in before['pins']),'pins':len(before['pins']),'provider_payloads':len(before['provider_payloads']),'provider_manifests':len(before['provider_manifests']),'unchanged':before==after,'commands':experiment.commands,'seconds':round(time.monotonic()-started,3),'expanded_current_suite':'NOT_RUN','hosted_CI':'NOT_RUN'}
m.save(OUT/'RESULT.json',result)
print(json.dumps({k:v for k,v in result.items() if k!='commands'},sort_keys=True))
