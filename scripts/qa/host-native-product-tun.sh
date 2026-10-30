#!/bin/sh
# Sourced by the installed product trial in the disconnected systemd guest.
# Native intent uses per-object ownership; legacy baseline checks remain in
# the caller. Every foreign fixture mutation here belongs to this QA.
native_product=no
native_fixture_kind=
native_fixture_receipt=
native_executor_masked=no
native_trace_dir=
native_readiness_reported=no
native_transit_receipt=

native_pending_failure_diagnostic() {
  # No recovery/service mutation. The failed op=$(pending_receipt) still has
  # the OLD shell operation, so bind only to the completed Apply receipt.
  /usr/bin/timeout --signal=KILL 5s python3 - <<'PYNATIVEPENDINGFAIL'
import json,os,re,resource,socket,stat,subprocess,sys,tempfile
def emit(label,value):
    print('PRODUCT_TUN_PENDING_DIAGNOSTIC '+label+' '+json.dumps(value,separators=(',',':')),file=sys.stderr,flush=True)
def hex32(value):
    return isinstance(value,str) and re.fullmatch('[0-9a-f]{32}',value) is not None and value!='0'*32
def strict_json(text):
    def unique(pairs):
        result={}
        for key,value in pairs:
            assert key not in result
            result[key]=value
        return result
    return json.loads(text,object_pairs_hook=unique)
def pending_invocation_summary(rows,invocation,boot,expected_operation):
    assert hex32(invocation) and hex32(boot) and hex32(expected_operation)
    assert isinstance(rows,list) and 0<len(rows)<=128
    streams=set();cursors=set();messages=[]
    for row in rows:
        assert isinstance(row,dict) and row.get('_SYSTEMD_UNIT')=='server-connect-activation-recover.service'
        assert row.get('_SYSTEMD_INVOCATION_ID')==invocation and row.get('_BOOT_ID')==boot and row.get('_TRANSPORT')=='stdout'
        stream,pid,cursor=row.get('_STREAM_ID'),row.get('_PID'),row.get('__CURSOR')
        assert hex32(stream) and isinstance(pid,str) and re.fullmatch('[1-9][0-9]{0,9}',pid) and int(pid)>1
        assert isinstance(cursor,str) and 0<len(cursor)<=1024 and cursor not in cursors
        message=row.get('MESSAGE');assert isinstance(message,str) and len(message.encode('utf-8'))<=4096
        streams.add((stream,pid));cursors.add(cursor);messages.append(message)
    assert len(streams)==1, 'mixed invocation streams'
    text='\n'.join(messages);assert len(text.encode('utf-8'))<=16384
    # ExecStart has no --json. These exact static CLI error lines are known
    # from decodeTrialJournal; no product error.code is inferred from text.
    if text in ('Error: guard trial schema invalid','Error: guard trial trailing data'):
        return {'kind':'known-static-error','message':text}
    try:receipt=strict_json(text)
    except Exception:return {'kind':'redacted','reason':'unclassified-output'}
    assert isinstance(receipt,dict)
    phases={'absent','unarmed_prepared','trial_pending','trial_stop_requested','trial_recovered','trial_cleanup_pending','trial_cleared'}
    assert receipt.get('phase') in phases and type(receipt.get('experiment_only')) is bool
    safe={'kind':'receipt','phase':receipt['phase'],'experiment_only':receipt['experiment_only']}
    operation=receipt.get('operation_id','')
    if operation:
        assert hex32(operation) and operation==expected_operation, 'different operation receipt'
        safe['operation_id']=operation
    else:assert receipt['phase'] in ('absent','unarmed_prepared')
    if 'revision' in receipt:
        assert type(receipt['revision']) is int and 0<=receipt['revision']<=5
        safe['revision']=receipt['revision']
    flags=('guard_scheduled','activation_ready','vpn_verified','recovery_verified','trial_rule_recovered','trial_route_recovered')
    for key in flags:
        if key in receipt:
            assert type(receipt[key]) is bool
            safe[key]=receipt[key]
    safe['other_fields_redacted']=bool(set(receipt)-set(flags)-{'operation_id','phase','revision','experiment_only'})
    return safe
def read(path,limit=4096):
    with open(path) as f:
        value=f.read(limit+1);assert len(value)<=limit
        return value.strip()
def private_json(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        before=os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_uid==0 and not before.st_mode&0o022 and before.st_size<=limit
        raw=f.read(limit+1);after=os.fstat(f.fileno())
        assert len(raw)<=limit and (before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns)
    return strict_json(raw)
def capture(argv,limit):
    def bound():resource.setrlimit(resource.RLIMIT_FSIZE,(limit,limit))
    with tempfile.TemporaryFile(dir='/run') as out:
        subprocess.run(argv,stdout=out,stderr=subprocess.DEVNULL,timeout=1,check=True,preexec_fn=bound)
        assert out.tell()<limit
        out.seek(0);return out.read(limit)
properties=('ActiveState','SubState','Result','ExecMainCode','ExecMainStatus',
            'ExecMainStartTimestampMonotonic','ExecMainExitTimestampMonotonic','InvocationID','Job')
def unit_snapshot():
    args=['/usr/bin/systemctl','show','server-connect-activation-recover.service']
    for key in properties:args+=['-p',key]
    fields={}
    for line in capture(args,4096).decode('utf-8').splitlines():
        key,separator,value=line.partition('=')
        assert separator and key in properties and key not in fields
        if key in ('ActiveState','SubState','Result'):assert re.fullmatch('[a-z][a-z0-9-]{0,31}',value)
        elif key=='InvocationID':assert value=='' or re.fullmatch('[0-9a-f]{32}',value)
        elif key=='Job':assert value=='' or re.fullmatch('[0-9]{1,20}',value)
        else:assert re.fullmatch('[0-9]{1,20}',value)
        fields[key]=value
    assert set(fields)==set(properties)
    return fields
step='scope'
try:
    assert os.geteuid()==0 and os.environ.get('SC_QA_TUN_PRODUCT_LAB')=='yes'
    assert os.path.isfile('/.dockerenv') and socket.gethostname()=='sc-qa' and read('/proc/1/comm')=='systemd'
    release=read('/etc/os-release').splitlines()
    assert 'ID=debian' in release and any(x in release for x in ('VERSION_ID=13','VERSION_ID="13"'))
    ns=os.stat('/proc/self/ns/net');pid1=os.stat('/proc/1/ns/net')
    assert (ns.st_dev,ns.st_ino)==(pid1.st_dev,pid1.st_ino)
    applied=private_json('/run/sc-qa-product-tun-apply.json',16384)
    assert applied.get('ok') is True and isinstance(applied.get('data'),dict)
    data=applied['data'];operation=data.get('operation_id')
    assert hex32(operation) and data.get('phase')=='trial_pending' and type(data.get('revision')) is int and data['revision']==1 and data.get('experiment_only') is True
    def current_operation():
        journal=private_json('/var/lib/server-connect/route-activation-journal.json',131072)
        assert journal['version']==4 and journal['intent_type']=='smart_tun_native_pending_trial_v1' and journal['operation_id']==operation
        assert journal['phase'] in ('trial_pending','trial_stop_requested','trial_recovered','trial_cleanup_pending')
        assert type(journal['revision']) is int and 1<=journal['revision']<=4
        assert (journal['native']['namespace_dev'],journal['native']['namespace_ino'])==(ns.st_dev,ns.st_ino)
        return {key:journal[key] for key in ('version','intent_type','operation_id','phase','revision')}
    bound=current_operation();boot=read('/proc/sys/kernel/random/boot_id').replace('-','');assert hex32(boot)
    emit('operation-before',bound)
    step='unit-snapshot';snapshot=unit_snapshot();emit('unit-before',snapshot)
    invocation=snapshot['InvocationID'];assert hex32(invocation), 'invocation unavailable'
    step='journal-sync';capture(['/usr/bin/journalctl','--sync'],4096)
    step='invocation-read'
    fields='MESSAGE,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,_BOOT_ID,_STREAM_ID,_TRANSPORT,_PID,__CURSOR'
    raw=capture(['/usr/bin/journalctl','-b','--no-pager','-n','129','-o','json','--output-fields='+fields,
                 '_SYSTEMD_UNIT=server-connect-activation-recover.service','_SYSTEMD_INVOCATION_ID='+invocation,
                 '_BOOT_ID='+boot,'_TRANSPORT=stdout'],65536)
    rows=[strict_json(line) for line in raw.decode('utf-8').splitlines() if line.strip()]
    summary=pending_invocation_summary(rows,invocation,boot,operation)
    step='attribution-recheck'
    assert unit_snapshot()==snapshot, 'unit invocation or execution state changed'
    after=current_operation()
    assert read('/proc/sys/kernel/random/boot_id').replace('-','')==boot
    emit('operation-after',after)
    emit('invocation-output',{'invocation_id':invocation,'output':summary})
except Exception:
    emit('unavailable',{'step':step,'reason':'bounded-observation-or-attribution-unavailable'})
PYNATIVEPENDINGFAIL
}

native_failure_observation() {
  # Sample silently before a probe; report only its first failure, before
  # recovery erases evidence. Neither diagnostics nor timeouts change QA status.
  case "$1" in sample) native_observer_limit=2;; apply|readiness) native_observer_limit=6;; *) return 2;; esac
  timeout --signal=KILL "${native_observer_limit}s" python3 - "$@" <<'PYNATIVEAPPLYDIAG'
import json,os,re,resource,stat,subprocess,sys,tempfile
mode=sys.argv[1]
assert (mode=='apply' and len(sys.argv)==2) or (mode=='sample' and len(sys.argv)==3) or (mode=='readiness' and len(sys.argv)==7)
if mode=='readiness':
    stage,destination,expected,before=sys.argv[3:]
    assert (stage,destination,expected) in (('domestic','5.22.0.10','10.254.72.1'),('vpn','8.8.8.8','8.8.8.8'))
prefix='PRODUCT_NATIVE_APPLY_DIAGNOSTIC' if mode=='apply' else 'PRODUCT_NATIVE_READINESS_DIAGNOSTIC'
def unavailable(label,reason):
    if mode!='sample':print(prefix+' '+label+' unavailable='+reason,flush=True)
def show(label,value):
    print(prefix+' '+label+' '+json.dumps(value,separators=(',',':')),flush=True)
def read(path,limit=4096):
    with open(path) as f:return f.read(limit)
def native_readiness_delta(before,after):
    identity=('operation_id','link_index','nft_handle','drop_handle')
    metrics=('tx_packets','rx_packets','guard_packets','guard_bytes')
    for sample in (before,after):
        assert isinstance(sample,dict) and set(sample)==set(identity+metrics)
        op=sample['operation_id']
        assert isinstance(op,str) and len(op)==32 and all(c in '0123456789abcdef' for c in op)
        assert all(type(sample[k]) is int and 0<sample[k]<2**64 for k in identity[1:])
        assert all(type(sample[k]) is int and 0<=sample[k]<2**64 for k in metrics)
    assert all(before[k]==after[k] for k in identity), 'counter owner changed'
    assert all(after[k]>=before[k] for k in metrics), 'counter reset'
    return {k:after[k]-before[k] for k in metrics}
def capture(argv):
    # A regular-file size limit bounds capture itself, not just printed output.
    def limit():resource.setrlimit(resource.RLIMIT_FSIZE,(16384,16384))
    with tempfile.TemporaryFile(dir='/run') as out:
        try:r=subprocess.run(argv,stdout=out,stderr=subprocess.DEVNULL,timeout=1,preexec_fn=limit)
        except subprocess.TimeoutExpired:raise ValueError('timeout')
        if r.returncode:raise ValueError('command-exit-'+str(r.returncode))
        if out.tell()>=16384:raise ValueError('output-limit')
        out.seek(0)
        try:return json.loads(out.read(16384))
        except (ValueError,UnicodeError):raise ValueError('invalid-json')
def observe(label,argv,check):
    try:
        value=capture(argv)
        if not check(value):raise ValueError('identity')
        show(label,value)
    except ValueError as e:unavailable(label,str(e))
    except Exception:unavailable(label,'observation-error')
try:
    assert os.geteuid()==0 and os.environ.get('SC_QA_TUN_PRODUCT_LAB')=='yes'
    assert os.path.isfile('/.dockerenv') and read('/proc/1/comm',64).strip()=='systemd'
    assert read('/proc/sys/kernel/hostname',128).strip()=='sc-qa'
    os_release=dict(line.split('=',1) for line in read('/etc/os-release').splitlines() if '=' in line)
    assert os_release.get('ID','').strip('"')=='debian' and os_release.get('VERSION_ID','').strip('"')=='13'
    ns=os.stat('/proc/self/ns/net');pid1=os.stat('/proc/1/ns/net')
    assert (ns.st_dev,ns.st_ino)==(pid1.st_dev,pid1.st_ino)
    fd=os.open('/var/lib/server-connect/route-activation-journal.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022 and st.st_size<=131072
        j=json.loads(f.read(131073))
    assert j['version']==4 and j['intent_type']=='smart_tun_native_pending_trial_v1'
    op=j['operation_id'];assert isinstance(op,str) and re.fullmatch('[0-9a-f]{32}',op)
    if mode!='apply':assert op==sys.argv[2]
    if mode=='sample':assert j['phase']=='trial_pending' and j['revision']==1
    assert j['tunnel_interface']=='sctunqa0' and j['underlay_interface']=='scqaedge0'
    n=j['native'];assert n['version']==1 and (n['namespace_dev'],n['namespace_ino'])==(ns.st_dev,ns.st_ino)
    assert n['nft_name']=='scnt_'+op and n['ipv4']['table']==42424 and n['ipv6']['table']==42426
    assert type(n['link_index']) is int and 0<=n['link_index']<2**31
    assert type(n['underlay_index']) is int and 0<n['underlay_index']<2**31
    assert int(read('/sys/class/net/scqaedge0/ifindex',64))==n['underlay_index']
except Exception:
    unavailable('scope','fixture-or-operation-identity');raise SystemExit(1)
ip=['/usr/bin/ip','-N','-j']
def nft_table(value):
    if not isinstance(value,dict) or not isinstance(value.get('nftables'),list):return False
    for item in value['nftables']:
        if 'metainfo' in item:continue
        if len(item)!=1:return False
        kind,fields=next(iter(item.items()))
        if fields.get('family')!='inet' or fields.get('name' if kind=='table' else 'table')!=n['nft_name']:return False
    return True
table_now=None
try:
    table_now=capture(['/usr/sbin/nft','-n','-j','-a','list','table','inet',n['nft_name']])
    assert nft_table(table_now)
except Exception:
    table_now=None;unavailable('nft-'+n['nft_name'],'observation-or-identity')
if mode!='sample' and table_now is not None:show('nft-'+n['nft_name'],table_now)
if mode!='apply':
    if mode=='readiness':show('probe',{'stage':stage,'destination':destination,'expected_source':expected,'operation_id':op})
    try:
        assert n['link_index']>0 and int(read('/sys/class/net/sctunqa0/ifindex',64))==n['link_index']
        assert read('/sys/class/net/sctunqa0/ifalias',128).strip()=='server-connect:'+op
        objects=table_now['nftables']
        tables=[x['table'] for x in objects if 'table' in x]
        assert len(tables)==1 and tables[0]['handle']==n['nft_handle']>0
        drops=[x['rule'] for x in objects if x.get('rule',{}).get('chain')=='guard' and {'drop':None} in x['rule']['expr']]
        assert len(drops)==1 and drops[0]['comment']=='server-connect:'+op
        assert any(x['kind']=='rule' and x['name']=='guard' and x['handle']==drops[0]['handle'] for x in n['nft_objects'][:n['nft_count']])
        counters=[x['counter'] for x in drops[0]['expr'] if 'counter' in x]
        assert len(counters)==1 and set(counters[0])=={'packets','bytes'}
        current={'operation_id':op,'link_index':n['link_index'],'nft_handle':n['nft_handle'],'drop_handle':drops[0]['handle'],
                 'guard_packets':counters[0]['packets'],'guard_bytes':counters[0]['bytes']}
        for key in ('tx_packets','rx_packets'):
            text=read('/sys/class/net/sctunqa0/statistics/'+key,64).strip()
            assert len(text)<64 and re.fullmatch('[0-9]+',text)
            current[key]=int(text)
        assert int(read('/sys/class/net/sctunqa0/ifindex',64))==n['link_index']
        native_readiness_delta(current,current)
        if mode=='sample':print(json.dumps(current,separators=(',',':')));raise SystemExit(0)
        show('counters-after',current)
        assert len(before)<=1024
        previous=json.loads(before);delta=native_readiness_delta(previous,current)
        show('counters-before',previous);show('counter-delta',delta)
    except Exception:
        unavailable('counters','missing-or-changed-owner-or-counter')
        if mode=='sample':raise SystemExit(1)
    # These lookups do not simulate OUTPUT hooks. They expose the exact
    # selected destination's initial, captured and core-bypass route choices.
    for label,mark in (('initial','0'),('capture','0x530000'),('bypass','0x540000')):
        observe('route-get-'+label,ip+['-4','route','get',destination,'from','10.254.72.1','mark',mark],
                lambda rows:isinstance(rows,list) and len(rows)==1 and rows[0].get('dst') in (destination,destination+'/32'))
try:
    assert n['link_index']>0 and int(read('/sys/class/net/sctunqa0/ifindex',64))==n['link_index']
    assert read('/sys/class/net/sctunqa0/ifalias',128).strip()=='server-connect:'+op
except Exception:unavailable('tun','operation-link-absent-or-mismatched')
else:
    def link(rows):return isinstance(rows,list) and len(rows)==1 and rows[0].get('ifindex')==n['link_index'] and rows[0].get('ifname')=='sctunqa0'
    observe('tun-detail',ip+['-s','-d','link','show','dev','sctunqa0'],lambda rows:link(rows) and rows[0].get('ifalias')=='server-connect:'+op)
    observe('tun-addresses',ip+['addr','show','dev','sctunqa0'],link)
for family,table in (('-4',42424),('-6',42426)):
    observe('routes-'+str(table),ip+[family,'route','show','table',str(table)],lambda rows:isinstance(rows,list) and all(str(r.get('table',table))==str(table) for r in rows))
    observe('rules-'+family[1:],ip+[family,'rule','show','priority','10400'],lambda rows:isinstance(rows,list) and all(r.get('priority')==10400 for r in rows))
PYNATIVEAPPLYDIAG
}

native_readiness_probe() {
  case "$1" in
    domestic) native_probe_destination=5.22.0.10; native_probe_expected=10.254.72.1;;
    vpn) native_probe_destination=8.8.8.8; native_probe_expected=8.8.8.8;;
    *) return 2;;
  esac
  native_probe_before=null
  if [ "$native_product" = yes ] && [ "$native_readiness_reported" = no ]; then
    native_probe_before=$(native_failure_observation sample "$op") || native_probe_before=null
  fi
  echo "PRODUCT_TUN_READINESS_PROBE stage=$1 destination=$native_probe_destination expected_source=$native_probe_expected"
  if expect_source "$native_probe_destination" "$native_probe_expected"; then return 0; fi
  if [ "$native_product" = yes ] && [ "$native_readiness_reported" = no ]; then
    native_readiness_reported=yes
    native_failure_observation readiness "$op" "$1" "$native_probe_destination" "$native_probe_expected" "$native_probe_before" ||
      echo 'PRODUCT_NATIVE_READINESS_DIAGNOSTIC observer unavailable=bounded-observer-failed' >&2
  fi
  return 1
}

native_ipv4_transit() {
  # This proves one real IPv4 forwarding hop, not an application connection
  # or general forwarding support. Port 19257 matches no Direct-leak witness.
  test "$edge" = scqaedge0 && test "$peer" = scqapeer || return 1
  test "$edge_added" = yes && test "$peer_added" = yes || return 1
  if [ "$1" = active ]; then assert_product_tun_policy_active || return 1; fi
  native_transit_result=$(python3 - "$1" "${op-}" "$native_transit_receipt" <<'PYNATIVEFORWARD'
import ctypes,json,os,resource,select,secrets,signal,socket,stat,struct,subprocess,sys,tempfile,time
phase,operation,receipt=sys.argv[1:]
assert phase in ('baseline','active')
def read(path):
    with open(path) as f:
        value=f.read(4097);assert len(value)<=4096
        return value.strip()
def query(*args):
    def limit():resource.setrlimit(resource.RLIMIT_FSIZE,(8192,8192))
    with tempfile.TemporaryFile(dir='/run') as out:
        subprocess.run(['/usr/bin/ip',*args],stdout=out,stderr=subprocess.DEVNULL,timeout=1,check=True,preexec_fn=limit)
        assert out.tell()<8192
        out.seek(0);return json.loads(out.read(8192))
def link(peer=False):
    rows=query(*(['-n','scqapeer'] if peer else []),'-N','-j','-d','link','show','dev','scqapeer0' if peer else 'scqaedge0')
    assert len(rows)==1 and rows[0]['linkinfo']['info_kind']=='veth'
    return {key:rows[0][key] for key in ('ifindex','ifname','link_index','address')}
def checksum(value):
    if len(value)%2:value+=b'\0'
    total=sum(struct.unpack('!%dH'%(len(value)//2),value))
    while total>>16:total=(total&65535)+(total>>16)
    return (~total)&65535
def transit_frame(source_mac,destination_mac,token,identity,ttl):
    assert len(source_mac)==len(destination_mac)==6 and len(token)==16 and 0<=identity<=65535 and ttl in (36,37)
    source=socket.inet_aton('198.51.100.42');destination=socket.inet_aton('8.8.8.8')
    payload=b'scqa-ipv4-transit:'+token
    udp=struct.pack('!HHHH',19256,19257,8+len(payload),0)+payload
    udp_sum=checksum(source+destination+struct.pack('!BBH',0,17,len(udp))+udp) or 65535
    udp=udp[:6]+struct.pack('!H',udp_sum)+udp[8:]
    header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),identity,0x4000,ttl,17,0,source,destination)
    header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
    return destination_mac+source_mac+b'\x08\x00'+header+udp
def forwarded_frame_matches(value,host_mac,peer_mac,token,identity):
    return value==transit_frame(host_mac,peer_mac,token,identity,36)
assert os.geteuid()==0 and os.environ.get('SC_QA_TUN_PRODUCT_LAB')=='yes'
assert os.path.isfile('/.dockerenv') and socket.gethostname()=='sc-qa' and read('/proc/1/comm')=='systemd'
assert 'ID=debian' in read('/etc/os-release').splitlines() and any(x in read('/etc/os-release').splitlines() for x in ('VERSION_ID=13','VERSION_ID="13"'))
ns=os.stat('/proc/self/ns/net');pid1=os.stat('/proc/1/ns/net')
assert (ns.st_dev,ns.st_ino)==(pid1.st_dev,pid1.st_ino)
peer_fd=os.open('/run/netns/scqapeer',os.O_RDONLY|os.O_NOFOLLOW)
peer_ns=os.fstat(peer_fd)
host_link,peer_link=link(),link(True)
assert host_link['ifname']=='scqaedge0' and peer_link['ifname']=='scqapeer0'
assert host_link['link_index']==peer_link['ifindex'] and peer_link['link_index']==host_link['ifindex']
assert all(type(x['ifindex']) is int and x['ifindex']>0 for x in (host_link,peer_link))
host_mac=bytes.fromhex(host_link['address'].replace(':',''));peer_mac=bytes.fromhex(peer_link['address'].replace(':',''))
assert len(host_mac)==len(peer_mac)==6 and not host_mac[0]&1 and not peer_mac[0]&1 and host_mac!=peer_mac
global_paths=('/proc/sys/net/ipv4/ip_forward','/proc/sys/net/ipv4/conf/all/forwarding','/proc/sys/net/ipv4/conf/default/forwarding')
globals_before=[read(path) for path in global_paths]
setting='/proc/sys/net/ipv4/conf/scqaedge0/forwarding';prior=read(setting)
assert prior in ('0','1') and all(x in ('0','1') for x in globals_before)
identity={'host':host_link,'peer':peer_link,'namespace':[ns.st_dev,ns.st_ino],
          'peer_namespace':[peer_ns.st_dev,peer_ns.st_ino],'forwarding':prior,'globals':globals_before}
if phase=='baseline':
    assert not receipt and not os.path.lexists('/var/lib/server-connect/route-activation-journal.json')
else:assert len(receipt)<=2048 and json.loads(receipt)==identity, 'forwarding fixture identity changed'
def check_operation():
    if phase=='baseline':return
    fd=os.open('/var/lib/server-connect/route-activation-journal.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno());assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_size<=131072
        journal=json.loads(f.read(131073))
    assert len(operation)==32 and all(c in '0123456789abcdef' for c in operation)
    assert journal['operation_id']==operation and journal['version']==4 and journal['intent_type']=='smart_tun_native_pending_trial_v1'
    assert journal['phase']=='trial_pending' and journal['revision']==1
    assert journal['native']['underlay_index']==host_link['ifindex'] and (journal['native']['namespace_dev'],journal['native']['namespace_ino'])==(ns.st_dev,ns.st_ino)
def unchanged():
    assert link()==host_link and link(True)==peer_link, 'forwarding link identity changed'
    observed=os.stat('/run/netns/scqapeer')
    assert (observed.st_dev,observed.st_ino)==(peer_ns.st_dev,peer_ns.st_ino), 'peer namespace replaced'
def interrupted(signum,frame):raise RuntimeError('forwarding witness interrupted')
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
child=None;read_fd=None;failure=False;cleanup_failure=False;stage='preflight';cleanup_stage='child'
try:
    unchanged();check_operation()
    stage='enable-owned-interface'
    # finally restores even if this write takes effect before raising.
    with open(setting,'w') as f:f.write('1')
    assert read(setting)=='1' and [read(path) for path in global_paths]==globals_before
    stage='bounded-packet-proof'
    token=secrets.token_bytes(16);packet_id=secrets.randbelow(65536)
    read_fd,write_fd=os.pipe()
    child=os.fork()
    if child==0:
        os.close(read_fd)
        try:
            assert ctypes.CDLL(None,use_errno=True).setns(peer_fd,0)==0
            actual=os.stat('/proc/self/ns/net');assert (actual.st_dev,actual.st_ino)==(peer_ns.st_dev,peer_ns.st_ino)
            assert socket.if_nametoindex('scqapeer0')==peer_link['ifindex']
            with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800)) as wire:
                wire.bind(('scqapeer0',0));wire.settimeout(0.1)
                sent=transit_frame(peer_mac,host_mac,token,packet_id,37)
                assert wire.send(sent)==len(sent)
                end=time.monotonic()+2;seen=0;matched=False
                while time.monotonic()<end and seen<64:
                    try:value,address=wire.recvfrom(512)
                    except socket.timeout:continue
                    seen+=1
                    if address[2]!=socket.PACKET_OUTGOING and forwarded_frame_matches(value,host_mac,peer_mac,token,packet_id):
                        matched=True;break
                assert matched
            os.write(write_fd,b'verified-token-ttl36-host-mac')
            os._exit(0)
        except BaseException:os._exit(1)
    os.close(write_fd)
    assert select.select([read_fd],[],[],3)[0], 'forwarding packet deadline'
    proof=os.read(read_fd,128)
    waited,status=os.waitpid(child,0);child=None
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status)==0 and proof==b'verified-token-ttl36-host-mac'
    stage='postflight'
    unchanged();check_operation()
except BaseException:failure=True
finally:
    # Finish the bounded owned-interface restoration even after termination.
    signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
    if child:
        try:os.kill(child,signal.SIGKILL)
        except ProcessLookupError:pass
        os.waitpid(child,0)
    if read_fd is not None:os.close(read_fd)
    os.close(peer_fd)
    try:
        cleanup_stage='owned-link-identity'
        assert link()==host_link, 'owned forwarding interface changed'
        cleanup_stage='restore-owned-setting'
        with open(setting,'w') as f:f.write(prior)
        cleanup_stage='readback-and-global-preservation'
        assert read(setting)==prior and [read(path) for path in global_paths]==globals_before
        cleanup_stage='peer-identity'
        unchanged()
    except BaseException:cleanup_failure=True
if cleanup_failure:raise SystemExit('PRODUCT_NATIVE_IPV4_TRANSIT=FAIL (phase='+phase+' cleanup='+cleanup_stage+')')
if failure:raise SystemExit('PRODUCT_NATIVE_IPV4_TRANSIT=FAIL (phase='+phase+' stage='+stage+')')
print(json.dumps(identity,sort_keys=True,separators=(',',':')))
PYNATIVEFORWARD
  ) || return 1
  if [ "$1" = baseline ]; then
    native_transit_receipt=$native_transit_result
    native_transit_marker=BASELINE
  else
    test "$1" = active && test "$native_transit_result" = "$native_transit_receipt" || return 1
    assert_product_tun_policy_active || return 1
    native_transit_marker=ACTIVE
  fi
  echo 'PRODUCT_NATIVE_IPV4_TRANSIT_DETAIL=token, host MAC, TTL 37 to 36; not end-to-end application proof'
  echo "PRODUCT_NATIVE_IPV4_TRANSIT_$native_transit_marker=PASS"
}

native_product_detect() {
  native_product=$(python3 - <<'PYNATIVEDETECT'
import json
with open('/var/lib/server-connect/route-activation-journal.json') as f:j=json.load(f)
assert j['version']==4 and j['intent_type'] in ('smart_tun_pending_trial_v4','smart_tun_native_pending_trial_v1')
print('yes' if j['intent_type']=='smart_tun_native_pending_trial_v1' else 'no')
PYNATIVEDETECT
  )
}

native_product_identity() {
  native_identity=$(python3 - "$op" <<'PYNATIVEIDENTITY'
import json,os,sys
with open('/var/lib/server-connect/route-activation-journal.json') as f:j=json.load(f)
assert j['operation_id']==sys.argv[1] and j['intent_type']=='smart_tun_native_pending_trial_v1'
n=j['native'];ns=os.stat('/proc/self/ns/net')
assert n['version']==1 and (n['namespace_dev'],n['namespace_ino'])==(ns.st_dev,ns.st_ino)
assert n['nft_name']=='scnt_'+j['operation_id'] and n['nft_handle']>0
assert n['link_index']==int(open('/sys/class/net/sctunqa0/ifindex').read())
assert n['ipv4']['table']==42424 and n['ipv6']['table']==42426
print(n['nft_name'],n['link_index'])
PYNATIVEIDENTITY
  ) || return 1
  native_table=${native_identity% *}
  native_link_index=${native_identity#* }
}

native_nft_snapshot() {
  # Native guard drops are observable counters, not policy mutation. Keep
  # complete object/handle/expression identity and validate every uint64.
  python3 - <<'PYNATIVENFTSNAP'
import json,subprocess
def clean(value):
    if isinstance(value,list):return [clean(x) for x in value]
    if isinstance(value,dict):
        out={key:clean(item) for key,item in value.items()};counter=out.get('counter')
        if isinstance(counter,dict) and ('packets' in counter or 'bytes' in counter):
            assert all(type(counter.get(key)) is int and 0<=counter[key]<2**64 for key in ('packets','bytes'))
            counter['packets']=counter['bytes']=0
        return out
    return value
value=json.loads(subprocess.check_output(['nft','-n','-j','-a','list','ruleset']))
for item in value['nftables']:
    if 'metainfo' in item:continue
    assert len(item)==1
    fields=next(iter(item.values()))
    assert type(fields.get('handle')) is int and fields['handle']>0, 'missing native nft handle'
print(json.dumps(clean(value),sort_keys=True,separators=(',',':')))
PYNATIVENFTSNAP
}

native_foreign_add() {
  test -z "$native_fixture_kind"
  native_fixture_kind=$1
  native_fixture_receipt=
  native_fixture_receipt=$(native_fixture create)
}

native_foreign_remove() {
  native_fixture remove || return 1
  native_fixture_kind=
  native_fixture_receipt=
}

native_executor_unmask() {
  test "$native_executor_masked" = yes || return 0
  test "$(readlink /run/systemd/system/server-connect-activation-recover.service)" = /dev/null || return 1
  systemctl unmask --runtime server-connect-activation-recover.service || return 1
  systemctl reset-failed server-connect-activation-recover.service || return 1
  native_executor_masked=no
}

native_product_cleanup() {
  # Restore only this QA owner's fixtures/mask; product recovery belongs
  # to the independently installed systemd executor.
  native_cleanup_rc=0
  if [ -n "$native_fixture_kind" ]; then native_foreign_remove || native_cleanup_rc=1; fi
  native_executor_unmask || native_cleanup_rc=1
  if [ -n "$native_trace_dir" ]; then rm -rf -- "$native_trace_dir" || native_cleanup_rc=1; native_trace_dir=; fi
  return "$native_cleanup_rc"
}

native_fixture() {
  # Inspect all parts before deletion. A partial creation without its
  # observation receipt is uncertain and remains visible to the trap.
  python3 - "$1" "$native_fixture_kind" "${native_table-}" "$native_fixture_receipt" <<'PYNATIVEFIXTURE'
import json,subprocess,sys
action,kind,table,receipt=sys.argv[1:]
def query(*args):return json.loads(subprocess.check_output(args,text=True))
def run(*args):subprocess.run(args,check=True)
def ip(family,*args):return query('ip','-N','-j',family,*args)
def routes(family,table):return [x for x in ip(family,'route','show','table','all') if str(x.get('table'))==str(table)]
def nft_identity(value):
    for item in value['nftables']:
        if 'metainfo' in item:continue
        assert len(item)==1
        fields=next(iter(item.values()))
        assert type(fields.get('handle')) is int and fields['handle']>0, 'missing fixture nft handle'
    return value
def nft_table(name):
    tables=query('nft','-n','-j','-a','list','tables')['nftables']
    if any(x.get('table',{}).get('family')=='inet' and x['table'].get('name')==name for x in tables):
        return nft_identity(query('nft','-n','-j','-a','list','table','inet',name))
def observe():
    if kind=='disjoint':
        links=[x for x in query('ip','-N','-j','-d','link','show') if x['ifname']=='scqanative0']
        link=None
        if links:
            assert len(links)==1
            x=links[0]
            link={key:x.get(key) for key in ('ifindex','ifname','ifalias','mtu','linkinfo')}
            link['addresses']=ip('-4','addr','show','dev','scqanative0')[0]['addr_info']
        result={'link':link,'nft':nft_table('scqa_native_foreign'),
                'routes4':routes('-4',52525),'routes6':routes('-6',52525),
                'rules4':[x for x in ip('-4','rule','show') if x.get('priority')==30555 or str(x.get('table'))=='52525'],
                'rules6':[x for x in ip('-6','rule','show') if x.get('priority')==30555 or str(x.get('table'))=='52525']}
        return result if any(result.values()) else None
    if kind=='address':
        links=[x for x in query('ip','-N','-j','link','show') if x['ifname']=='sctunqa0']
        if not links:return None
        rows=[x for x in ip('-4','addr','show','dev','sctunqa0')[0]['addr_info'] if x.get('local')=='172.31.98.9']
        return {'ifindex':links[0]['ifindex'],'addresses':rows} if rows else None
    if kind=='route':return [x for x in routes('-4',42424) if x.get('dst')=='198.18.61.0/24'] or None
    if kind=='rule':return [x for x in ip('-4','rule','show') if x.get('priority')==10400 and str(x.get('table'))=='52526'] or None
    assert kind=='nft-child'
    value=nft_table(table)
    if not value:return None
    if not any(x.get('chain',{}).get('name')=='qa_foreign_child' for x in value['nftables']):return None
    return nft_identity(query('nft','-n','-j','-a','list','chain','inet',table,'qa_foreign_child'))
def mutate(verb):
    add=verb=='add'
    if kind=='disjoint':
        if add:
            run('ip','link','add','scqanative0','type','dummy')
            run('ip','link','set','scqanative0','alias','scqa-native-disjoint','up')
            run('ip','-4','addr','add','172.31.96.9/32','dev','scqanative0')
            run('nft','add','table','inet','scqa_native_foreign')
        for family,destination in (('-4','198.18.60.0/24'),('-6','2001:db8:60::/64')):
            run('ip',family,'rule',verb,'priority','30555','to',destination,'lookup','52525','protocol','186')
            run('ip',family,'route',verb,destination,'dev','lo','table','52525','protocol','186')
        if not add:
            run('nft','delete','table','inet','scqa_native_foreign')
            run('ip','link','del','scqanative0')
    elif kind=='address':run('ip','-4','addr',verb,'172.31.98.9/32','dev','sctunqa0')
    elif kind=='route':run('ip','-4','route',verb,'198.18.61.0/24','dev','scqaedge0','table','42424','protocol','186','metric','10401')
    elif kind=='rule':run('ip','-4','rule',verb,'priority','10400','to','198.18.62.0/24','lookup','52526','protocol','186')
    elif add:
        run('nft','add','chain','inet',table,'qa_foreign_child')
        run('nft','add','rule','inet',table,'qa_foreign_child','counter','comment','"independent-native-QA-owner"')
    else:
        run('nft','flush','chain','inet',table,'qa_foreign_child')
        run('nft','delete','chain','inet',table,'qa_foreign_child')
before=observe()
if action=='create':
    assert before is None, 'QA foreign resource already exists'
    mutate('add');after=observe()
    assert after is not None, 'QA creation not observed'
    print(json.dumps(after,sort_keys=True,separators=(',',':')))
elif action=='verify':assert receipt and before==json.loads(receipt), 'foreign QA resource changed or disappeared'
elif action=='remove':
    if before is not None:
        assert receipt and before==json.loads(receipt), 'unresolved QA creation or changed owner; retained'
        mutate('del')
        assert observe() is None, 'QA removal not verified'
else:raise AssertionError('unknown QA fixture action')
PYNATIVEFIXTURE
}

native_require_retained() {
  test "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = inactive || return 1
  test "$(cat /sys/class/net/sctunqa0/ifindex)" = "$native_link_index" || return 1
  python3 - "$op" "$native_table" <<'PYNATIVERETAINED'
import json,subprocess,sys
with open('/var/lib/server-connect/route-activation-journal.json') as f:j=json.load(f)
assert j['operation_id']==sys.argv[1] and j['intent_type']=='smart_tun_native_pending_trial_v1'
assert j['phase']=='trial_stop_requested' and j['revision']==2 and j['native']['stop_reason'] in ('guard','off')
assert j['native']['nft_name']==sys.argv[2]
value=json.loads(subprocess.check_output(['nft','-n','-j','-a','list','table','inet',sys.argv[2]]))
chains={x['chain']['name'] for x in value['nftables'] if 'chain' in x}
assert {'capture','guard'}<=chains, 'native containment missing'
seen=set()
for obj in value['nftables']:
    if 'metainfo' in obj:continue
    kind,fields=next(iter(obj.items()))
    assert type(fields.get('handle')) is int and fields['handle']>0
    seen.add((kind,fields['chain'] if kind=='rule' else fields['name'],fields['handle']))
assert {(x['kind'],x['name'],x['handle']) for x in j['native']['nft_objects'][:j['native']['nft_count']]}<=seen, 'original native handles disappeared'
PYNATIVERETAINED
}

native_no_direct_leak() {
  # Earlier positive controls reached these same origins directly. A failed
  # request alone is insufficient; peer ingress must remain unchanged too.
  native_tcp4_before=$(direct_witness_packets)
  native_udp4_before=$(direct_udp_witness_packets)
  test "$native_tcp4_before" -gt 0 && test "$native_udp4_before" -gt 0
  if without_proxy http://8.8.8.8:19180/path >/dev/null 2>&1; then
    echo 'PRODUCT_NATIVE_FAIL_CLOSED=FAIL (IPv4 TCP reached origin)' >&2; return 1
  fi
  udp_path 8.8.8.8 none native-degraded no-reply
  test "$(direct_witness_packets)" = "$native_tcp4_before"
  test "$(direct_udp_witness_packets)" = "$native_udp4_before"
  if [ "$ipv6_trial" = yes ]; then
    native_tcp6_before=$(ipv6_foreign_tcp_direct_packets)
    native_udp6_before=$(ipv6_foreign_udp_direct_packets)
    test "$native_tcp6_before" -gt 0 && test "$native_udp6_before" -gt 0
    ipv6_path tcp 2001:db8:8::8 none no-reply
    ipv6_path udp 2001:db8:8::8 none no-reply
    test "$(ipv6_foreign_tcp_direct_packets)" = "$native_tcp6_before"
    test "$(ipv6_foreign_udp_direct_packets)" = "$native_udp6_before"
  fi
  kill -0 "$origin_pid" && kill -0 "$udp_pid"
  /bin/sh /root/qa-host-coexistence.sh probe
  expect_foreign_hosted_reply
  python3 - "$op" <<'PYNATIVENOTDIRECT'
import json,sys
with open('/var/lib/server-connect/route-activation-journal.json') as f:j=json.load(f)
assert j['operation_id']==sys.argv[1] and j['phase'] in ('trial_pending','trial_stop_requested'), 'probe raced completed deactivation'
PYNATIVENOTDIRECT
}

native_saved_reapply() {
  native_previous_op=$op
  if [ "${1-}" = trace ]; then
    native_traced_apply
  else
    "$sc" --json smart-tun-trial-apply --saved --deadline-seconds 60 >/run/sc-qa-product-tun-apply.json
  fi
  op=$(pending_receipt)
  test "$op" != "$native_previous_op"
  require_selected_ready
  native_product_identity
  test "$(saved_policy_hashes)" = "$saved_policy_before"
}

native_disjoint_off() {
  native_product_identity
  native_foreign_add disjoint
  disconnect_receipt "$op" 1
  native_fixture verify
  test ! -e /sys/class/net/sctunqa0
  test ! -e /var/lib/server-connect/route-activation-journal.json
  test ! -e /var/lib/server-connect/smart-tun-trial.json
  test "$(saved_policy_hashes)" = "$saved_policy_before"
  expect_source 8.8.8.8 10.254.72.1
  udp_path 8.8.8.8 10.254.72.1 native-disjoint-off reply
  native_foreign_remove
  require_finalized
  echo PRODUCT_NATIVE_DISJOINT_FOREIGN_SURVIVES_OFF=PASS
}

native_overlap_cases() {
  for native_overlap in address route rule nft-child; do
    if [ "$native_overlap" = address ]; then native_saved_reapply trace; else native_saved_reapply; fi
    native_foreign_add "$native_overlap"
    # The timer may already have recorded guard-origin stop intent. Permit
    # one exact-current-revision retry of the same identified operation.
    for native_attempt in 1 2; do
      native_revision=$(python3 - "$op" <<'PYNATIVEREVISION'
import json,sys
j=json.load(open('/var/lib/server-connect/route-activation-journal.json'))
assert j['operation_id']==sys.argv[1] and (j['phase'],j['revision']) in (('trial_pending',1),('trial_stop_requested',2))
print(j['revision'])
PYNATIVEREVISION
      )
      if "$sc" --json smart-tun-trial-disconnect --operation-id "$op" --revision "$native_revision" >/run/sc-qa-product-tun-conflict.json; then
        echo "PRODUCT_NATIVE_OVERLAP=FAIL ($native_overlap falsely cleared)" >&2; return 1
      fi
      native_error=$(python3 -c 'import json;r=json.load(open("/run/sc-qa-product-tun-conflict.json"));assert not r["ok"];print(r["error"]["code"])')
      test "$native_error" = activation_journal_conflict || break
    done
    python3 - "$op" <<'PYNATIVEOVERLAP'
import json,sys
with open('/run/sc-qa-product-tun-conflict.json') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='trial_resource_conflict',r
with open('/var/lib/server-connect/route-activation-journal.json') as f:j=json.load(f)
assert j['operation_id']==sys.argv[1] and j['phase']=='trial_stop_requested' and j['revision']==2
PYNATIVEOVERLAP
    native_fixture verify
    native_require_retained
    native_no_direct_leak
    native_fixture verify
    test "$(saved_policy_hashes)" = "$saved_policy_before"
    capture_executor_proof
    native_foreign_remove
    require_independent_finalization
    echo "PRODUCT_NATIVE_OVERLAP_RETAINED($native_overlap)=PASS"
  done
  echo PRODUCT_NATIVE_OVERLAP_FOREIGN_PRESERVATION=PASS
}

native_loss_cases() {
  for native_loss in route rule capture core; do
    native_saved_reapply
    test ! -e /run/systemd/system/server-connect-activation-recover.service
    test ! -L /run/systemd/system/server-connect-activation-recover.service
    native_executor_masked=yes
    # Freeze only the QA recovery executor so negative packets cannot race
    # a legitimate completed deactivation. The timer remains installed.
    systemctl mask --runtime --now server-connect-activation-recover.service
    test "$(readlink /run/systemd/system/server-connect-activation-recover.service)" = /dev/null
    case "$native_loss" in
      route)
        ip -4 route del default dev sctunqa0 table 42424 metric 100 protocol 247 scope link src 172.31.99.1
        ip -6 route del default dev sctunqa0 table 42426 metric 100 protocol 247 src fd73:99::1 ;;
      rule)
        ip -4 rule del priority 10400 fwmark 0x530000/0xff0000 table 42424 protocol 247
        ip -6 rule del priority 10400 fwmark 0x530000/0xff0000 table 42426 protocol 247 ;;
      capture)
        nft flush chain inet "$native_table" capture
        nft delete chain inet "$native_table" capture ;;
      core)
        systemctl kill --kill-who=main --signal=KILL server-connect-smart-tun.service ;;
    esac
    native_no_direct_leak
    test "$(saved_policy_hashes)" = "$saved_policy_before"
    capture_executor_proof
    killed=0
    "$sc" --json smart-tun-trial-disconnect --operation-id "$op" --revision 1 \
      --qa-kill-at after-stop-request >/dev/null 2>&1 || killed=$?
    test "$killed" = 137
    native_executor_unmask
    systemctl start server-connect-activation-recover.service
    require_independent_finalization
    echo "PRODUCT_NATIVE_LOSS_FAIL_CLOSED($native_loss)=PASS"
  done
  echo PRODUCT_NATIVE_LOSS_RECOVERY=explicit-installed-executor
  echo PRODUCT_NATIVE_ROUTE_RULE_CAPTURE_CORE_FAIL_CLOSED=PASS
}

native_visitor_origin() {
  test "$visitor_origin_baseline" -gt 0
  expect_foreign_hosted_reply
  expect_source 198.51.100.42 198.51.100.42
  test "$(visitor_origin_direct_packets)" = "$visitor_origin_baseline"
  echo PRODUCT_NATIVE_VISITOR_REPLY_AND_NEW_EGRESS=PASS
}

native_cold_neighbors() {
  # Delete only the two named fixture entries, never a namespace-wide cache.
  # Warm positive controls alone can conceal a broken ND output exception.
  python3 - <<'PYNATIVECOLD'
import json,subprocess
for prefix,interface,destination in (([], 'scqaedge0','fd73:1::2'),(['-n','scqapeer'],'scqapeer0','fd73:1::1')):
    def rows():return json.loads(subprocess.check_output(['ip',*prefix,'-6','-j','neigh','show','dev',interface,'to',destination]))
    before=rows()
    assert len(before)==1 and before[0].get('lladdr'), 'missing warm fixture neighbor positive control'
    subprocess.run(['ip',*prefix,'-6','neigh','del',destination,'dev',interface],check=True)
    assert not rows(), 'fixture neighbor did not become cold'
PYNATIVECOLD
  ipv6_path tcp 2001:db8:5::11 fd73:1::1 reply
  ipv6_path udp 2001:db8:5::11 fd73:1::1 reply
  ipv6_path tcp 2001:db8:8::8 2001:db8:8::8 reply
  ipv6_path udp 2001:db8:8::8 2001:db8:8::8 reply
  python3 - <<'PYNATIVERELEARN'
import json,subprocess
def query(args):return json.loads(subprocess.check_output(args))
peer_mac=query(['ip','-n','scqapeer','-j','link','show','dev','scqapeer0'])[0]['address']
host_mac=query(['ip','-j','link','show','dev','scqaedge0'])[0]['address']
for prefix,interface,destination,mac in (([],'scqaedge0','fd73:1::2',peer_mac),(['-n','scqapeer'],'scqapeer0','fd73:1::1',host_mac)):
    rows=query(['ip',*prefix,'-6','-j','neigh','show','dev',interface,'to',destination])
    assert len(rows)==1 and rows[0].get('lladdr')==mac and set(rows[0].get('state',[])) & {'REACHABLE','STALE','DELAY','PROBE'}, 'fixture neighbor was not relearned'
PYNATIVERELEARN
  test "$(ipv6_foreign_tcp_direct_packets)" = "$ipv6_foreign_tcp_baseline"
  test "$(ipv6_foreign_udp_direct_packets)" = "$ipv6_foreign_udp_baseline"
  icmp6_path no-reply
  test "$(public_icmp6_direct_packets)" = "$public_icmp6_baseline"
  echo PRODUCT_NATIVE_COLD_ND_AND_PUBLIC_ICMP_BOUNDARY=PASS
}

native_crash_cases() {
  # The link identity was durably bound before persistence: SIGKILL after
  # persistence is recoverable without inventing a new ownership receipt.
  killed=0
  "$sc" --json smart-tun-trial-apply --saved --deadline-seconds 8 \
    --qa-kill-at after-native-persist >/dev/null 2>&1 || killed=$?
  test "$killed" = 137
  op=$(python3 -c 'import json;j=json.load(open("/var/lib/server-connect/route-activation-journal.json"));assert j["intent_type"]=="smart_tun_native_pending_trial_v1" and not j["core_start_attempted"];print(j["operation_id"])')
  require_recovered "$op"
  clear_recovered "$op"
  test "$(saved_policy_hashes)" = "$saved_policy_before"
  echo PRODUCT_NATIVE_DURABLE_LINK_PERSIST_RECOVERY=PASS

  capture_executor_proof
  killed=0
  "$sc" --json smart-tun-trial-apply --saved --deadline-seconds 8 \
    --qa-kill-at after-native-route-effect >/dev/null 2>&1 || killed=$?
  test "$killed" = 137
  op=$(python3 -c 'import json;j=json.load(open("/var/lib/server-connect/route-activation-journal.json"));assert j["native"]["ipv4"]["route"]["stage"]=="effect_possible";print(j["operation_id"])')
  native_conflict=no
  for native_try in $(seq 1 15); do
    native_start=$(systemctl show server-connect-activation-recover.service -p ExecMainStartTimestampMonotonic --value)
    if [ "$native_start" -gt "$executor_before" ] &&
       [ "$(systemctl show server-connect-activation-recover.service -p Result --value)" = exit-code ]; then
      native_conflict=yes; break
    fi
    sleep 1
  done
  test "$native_conflict" = yes
  if "$sc" --json activation-trial-recover >/run/sc-qa-product-tun-conflict.json; then
    echo 'PRODUCT_NATIVE_AMBIGUOUS_EFFECT=FAIL (missing route receipt accepted)' >&2; return 1
  fi
  python3 - "$op" <<'PYNATIVEAMBIGUOUS'
import json,subprocess,sys
with open('/run/sc-qa-product-tun-conflict.json') as f:r=json.load(f)
assert not r['ok'] and r['error']['code']=='trial_recovery_uncertain',r
with open('/var/lib/server-connect/route-activation-journal.json') as f:j=json.load(f)
assert j['operation_id']==sys.argv[1] and j['phase']=='trial_stop_requested' and j['revision']==2 and j['native']['stop_reason']=='guard'
assert j['native']['ipv4']['route']=={'stage':'effect_possible','sha256':''}
assert j['native']['link_index']==int(open('/sys/class/net/sctunqa0/ifindex').read())
rows=json.loads(subprocess.check_output(['ip','-N','-j','-4','route','show','table','all']))
rows=[x for x in rows if str(x.get('table'))=='42424' and x.get('dst')=='default' and x.get('metric')==100]
assert len(rows)==1
x=rows[0]
assert set(x)<={'table','dst','dev','protocol','scope','prefsrc','metric','flags'} and x['dev']=='sctunqa0'
# ip -N emits IPv4 RT_SCOPE_LINK numerically; retain the exact enum only.
assert str(x['protocol'])=='247' and str(x['scope']) in ('253','link') and x['prefsrc']=='172.31.99.1'
assert set(x.get('flags',[]))<={'linkdown'}
# Explicit isolated operator remediation of the exact failed QA creation.
# Product recovery correctly refused it; the journal is never rewritten.
subprocess.run(['ip','-4','route','del','default','dev','sctunqa0','table','42424','metric','100','protocol','247','scope','link','src','172.31.99.1'],check=True)
after=json.loads(subprocess.check_output(['ip','-N','-j','-4','route','show','table','all']))
assert not any(str(x.get('table'))=='42424' and x.get('dst')=='default' and x.get('metric')==100 for x in after)
PYNATIVEAMBIGUOUS
  echo PRODUCT_NATIVE_AMBIGUOUS_ROUTE_REMEDIATION=explicit-QA-operator
  systemctl reset-failed server-connect-activation-recover.service
  systemctl start server-connect-activation-recover.service
  require_recovered "$op"
  clear_recovered "$op"
  test "$(saved_policy_hashes)" = "$saved_policy_before"
  echo PRODUCT_NATIVE_AMBIGUOUS_ROUTE_EFFECT_RETAINED=PASS

  native_saved_reapply
  capture_executor_proof
  killed=0
  "$sc" --json smart-tun-trial-disconnect --operation-id "$op" --revision 1 \
    --qa-kill-at after-native-nft-remove >/dev/null 2>&1 || killed=$?
  test "$killed" = 137
  require_independent_finalization
  test "$(saved_policy_hashes)" = "$saved_policy_before"
  echo PRODUCT_NATIVE_POST_DELETE_SIGKILL_RECOVERY=PASS
}

native_guard_graph() {
  python3 - "$1" "$op" /run/sc-qa-native-guard-loss.json <<'PYNATIVEGUARDGRAPH'
import json,subprocess,sys
from pathlib import Path
action,operation,path=sys.argv[1:]
j=json.load(open('/var/lib/server-connect/route-activation-journal.json'));n=j['native']
assert j['operation_id']==operation and j['intent_type']=='smart_tun_native_pending_trial_v1'
def query(*args):return json.loads(subprocess.check_output(args))
def run(*args):subprocess.run(args,check=True)
def nft_after_deleted_tun(saved,current,link,remaining_links,operation):
    # nftables 1.1.3 renders an indexed meta oif as a name while that link
    # exists, then as a decimal JSON string after deletion, even with -n.
    # Authenticate absence of BOTH identities before allowing this one edit.
    assert isinstance(operation,str) and len(operation)==32 and all(c in '0123456789abcdef' for c in operation)
    index=link['ifindex']
    assert type(index) is int and 0<index<2**31 and link['ifname']=='sctunqa0'
    assert link['ifalias']=='server-connect:'+operation
    assert isinstance(remaining_links,list)
    for row in remaining_links:
        assert type(row.get('ifindex')) is int and row['ifindex']>0 and isinstance(row.get('ifname'),str)
        assert row['ifindex']!=index and row['ifname']!='sctunqa0', 'deleted TUN identity still present or replaced'
    expected=json.loads(json.dumps(saved));changed=0
    match={'match':{'op':'==','left':{'meta':{'key':'oif'}},'right':'sctunqa0'}}
    for item in expected['nftables']:
        for expression in item.get('rule',{}).get('expr',[]):
            if expression==match:
                expression['match']['right']=str(index);changed+=1
    assert changed>0, 'no exact indexed TUN expression in receipt'
    # Preserve JSON types, unknown fields, every handle and all list ordering.
    return json.dumps(current,sort_keys=True,separators=(',',':'))==json.dumps(expected,sort_keys=True,separators=(',',':'))
def link_children():
    result={'addresses':query('ip','-N','-j','addr','show','dev','sctunqa0')[0]['addr_info']}
    for family,table in (('-4',42424),('-6',42426)):
        rows=query('ip','-N','-j',family,'route','show','table','all')
        assert not any(set(x)&{'nhid','nexthops','multipath','encap','via'} for x in rows), 'unobserved indirect route dependency'
        source='172.31.99.1' if family=='-4' else 'fd73:99::1'
        rows=[x for x in rows if (x.get('dev')=='sctunqa0' or x.get('prefsrc')==source) and str(x.get('table'))!=str(table)]
        for x in rows:
            if 'flags' in x:x['flags']=[f for f in x['flags'] if f!='linkdown']
        result[family]=sorted(rows,key=lambda x:json.dumps(x,sort_keys=True))
        rules=query('ip','-N','-j',family,'rule','show')
        assert not any(x.get(key) in ('sctunqa0',n['link_index']) for x in rules for key in ('iif','oif')), 'foreign rule depends on TUN'
    return result
def graph():
    link=query('ip','-N','-j','-d','link','show','dev','sctunqa0')[0]
    assert link['ifindex']==n['link_index'] and link['ifalias']=='server-connect:'+operation
    for key in ('operstate','carrier','carrier_changes','carrier_up_count','carrier_down_count'):link.pop(key,None)
    link['flags']=sorted(set(link['flags'])-{'LOWER_UP','RUNNING','NO-CARRIER'})
    data=link['linkinfo']['info_data']
    for key in ('num_queues','num_disabled_queues'):data.pop(key,None)
    result={'link':link,'children':link_children()}
    for family,table in (('-4',42424),('-6',42426)):
        rows=query('ip','-N','-j',family,'route','show','table','all')
        rows=[x for x in rows if str(x.get('table'))==str(table)]
        for x in rows:
            if 'flags' in x:x['flags']=[f for f in x['flags'] if f!='linkdown']
        result[family+'routes']=sorted(rows,key=lambda x:json.dumps(x,sort_keys=True))
        result[family+'rules']=[x for x in query('ip','-N','-j',family,'rule','show') if x.get('priority')==10400]
    result['nft']=query('nft','-n','-j','-a','list','table','inet',n['nft_name'])
    return result
if action=='remove-drop':
    assert j['phase']=='trial_pending' and j['revision']==1 and n['nft']['stage']=='observed'
    before=graph();objects=before['nft']['nftables']
    tables=[x['table'] for x in objects if 'table' in x]
    assert len(tables)==1 and tables[0]['handle']==n['nft_handle']
    drops=[x for x in objects if x.get('rule',{}).get('chain')=='guard' and any('drop' in e for e in x['rule']['expr'])]
    assert len(drops)==1 and drops[0]['rule']['comment']=='server-connect:'+operation
    known={(x['kind'],x['name'],x['handle']) for x in n['nft_objects'][:n['nft_count']]}
    observed=set()
    for obj in objects:
        if 'metainfo' in obj:continue
        assert len(obj)==1
        kind,fields=next(iter(obj.items()))
        observed.add((kind,fields['chain'] if kind=='rule' else fields['name'],fields['handle']))
    assert observed==known, 'native handles differ before destructive negative'
    before['nft']['nftables']=[x for x in objects if x!=drops[0]]
    with open(path,'x') as f:json.dump({'operation':operation,'graph':before},f,sort_keys=True)
    run('nft','delete','rule','inet',n['nft_name'],'guard','handle',str(drops[0]['rule']['handle']))
    assert graph()==before, 'drop fault changed other native objects'
else:
    saved=json.load(open(path))
    assert saved['operation']==operation and graph()==saved['graph'], 'native graph changed; operator deletion refused'
    if action=='verify':sys.exit(0)
    assert action=='operator-remove'
    # This is deliberately operator-assisted removal, not product recovery.
    # No recreated handle or edited journal is offered as ownership proof.
    for family,table,source in (('-4','42424','172.31.99.1'),('-6','42426','fd73:99::1')):
        run('ip',family,'rule','del','priority','10400','fwmark','0x530000/0xff0000','table',table,'protocol','247')
        run('ip',family,'route','del','default','dev','sctunqa0','table',table,'metric','100','protocol','247','src',source)
        run('ip',family,'route','del','unreachable','default','table',table,'metric','42760','protocol','247')
    link=query('ip','-N','-j','link','show','dev','sctunqa0')[0]
    assert link['ifindex']==n['link_index'] and link['ifname']=='sctunqa0' and link['ifalias']=='server-connect:'+operation
    assert link_children()==saved['graph']['children'], 'link children changed; retained'
    run('ip','link','del','dev','sctunqa0')
    table_now=query('nft','-n','-j','-a','list','table','inet',n['nft_name'])
    remaining_links=query('ip','-N','-j','link','show')
    assert nft_after_deleted_tun(saved['graph']['nft'],table_now,saved['graph']['link'],remaining_links,operation), 'native nft graph changed during operator teardown'
    deletion={'nftables':[{'delete':{'table':{'family':'inet','handle':n['nft_handle']}}}]}
    subprocess.run(['nft','-j','-f','-'],input=json.dumps(deletion).encode(),check=True)
    tables=query('nft','-j','list','tables')['nftables']
    assert not any(x.get('table',{}).get('name')==n['nft_name'] for x in tables)
    Path(path).unlink()
PYNATIVEGUARDGRAPH
}

native_guard_loss_last() {
  # The earlier upstream-outage case deliberately stopped this same peer.
  # Reuse its existing topology/config and obtain selected-path proof again.
  ip netns exec "$peer" "$core" run -c "$server_cfg" >/run/sc-qa-tun-server.log 2>&1 &
  server_pid=$!
  native_saved_reapply
  native_foreign_add disjoint
  native_guard_graph remove-drop
  if "$sc" --json activation-trial-recover >/run/sc-qa-product-tun-conflict.json; then
    echo 'PRODUCT_NATIVE_GUARD_LOSS=FAIL (missing guard falsely recovered)' >&2; return 1
  fi
  python3 - "$op" <<'PYNATIVEGUARDUNCERTAIN'
import json,sys
r=json.load(open('/run/sc-qa-product-tun-conflict.json'))
assert not r['ok'] and r['error']['code']=='trial_recovery_uncertain',r
j=json.load(open('/var/lib/server-connect/route-activation-journal.json'))
assert j['operation_id']==sys.argv[1] and j['phase']=='trial_stop_requested' and j['revision']==2 and j['native']['stop_reason']=='guard'
PYNATIVEGUARDUNCERTAIN
  test "$(systemctl show server-connect-smart-tun.service -p ActiveState --value)" = inactive
  native_guard_graph verify
  native_no_direct_leak
  native_guard_graph verify
  native_fixture verify
  test "$(saved_policy_hashes)" = "$saved_policy_before"
  echo PRODUCT_NATIVE_GUARD_LOSS_UNCERTAIN_CONTAINED=PASS
  test ! -e /run/systemd/system/server-connect-activation-recover.service
  test ! -L /run/systemd/system/server-connect-activation-recover.service
  native_executor_masked=yes
  systemctl mask --runtime --now server-connect-activation-recover.service
  native_guard_graph operator-remove
  native_fixture verify
  echo PRODUCT_NATIVE_GUARD_LOSS_REMEDIATION=explicit-QA-operator
  native_foreign_remove
  require_native_baseline
  native_executor_unmask
  systemctl start server-connect-activation-recover.service
  require_recovered "$op"
  clear_recovered "$op"
  require_finalized
  test "$(saved_policy_hashes)" = "$saved_policy_before"
  expect_source 8.8.8.8 10.254.72.1
  ipv6_path tcp 2001:db8:8::8 fd73:1::1 reply
  echo PRODUCT_NATIVE_GUARD_LOSS_OPERATOR_ASSISTED_DIRECT=PASS
}

native_trusted_mutator_lifetime() {
  python3 - <<'PYNATIVEMUTATOR'
import ctypes,errno,fcntl,json,os,select,signal,socket,stat,subprocess,tempfile,time
from pathlib import Path
assert os.geteuid()==0 and Path('/.dockerenv').exists() and socket.gethostname()=='sc-qa'
assert Path('/proc/1/comm').read_text().strip()=='systemd'
assert os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net')
assert 'ID=debian' in Path('/etc/os-release').read_text().splitlines()
assert any(line in ('VERSION_ID=13','VERSION_ID="13"') for line in Path('/etc/os-release').read_text().splitlines())
assert {x['ifname'] for x in json.loads(subprocess.check_output(['ip','-j','link','show']))}=={'lo'}
def line(fd):
    result=b'';end=time.monotonic()+4
    while not result.endswith(b'\n'):
        assert select.select([fd],[],[],max(0,end-time.monotonic()))[0], 'controller proof timed out'
        chunk=os.read(fd,1);assert chunk, 'controller exited before proof';result+=chunk
    return result.strip()
def identity(pid):
    try:
        row=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()
        return row[19],row[0]
    except FileNotFoundError:return None,None
libc=ctypes.CDLL(None,use_errno=True)
for name,args,late in (
    ('IP',['/usr/bin/ip','-batch','-'],b'-4 route add blackhole 198.18.250.0/24 table 52527 protocol 186\n'),
    ('NFT',['/usr/sbin/nft','-j','-f','-'],b'{"nftables":[{"add":{"table":{"family":"inet","name":"scqa_late_mutator"}}}]}\n')):
    info=os.stat(args[0]);assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
    with tempfile.TemporaryDirectory(prefix='sc-qa-mutator-',dir='/run') as directory:
        lock=Path(directory)/'lock';lock.touch(mode=0o600);expected=lock.stat()
        data_r,data_w=os.pipe();info_r,info_w=os.pipe();control_r,control_w=os.pipe()
        controller=os.fork()
        if controller==0:
            try:
                child_input,proof,control=[fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,20) for fd in (data_r,info_w,control_r)]
                for fd in (data_r,data_w,info_r,info_w,control_r,control_w):os.close(fd)
                fd=os.open(lock,os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX)
                if fd!=3:os.dup2(fd,3);os.close(fd)
                parent=os.getpid()
                def arm():
                    assert libc.prctl(1,signal.SIGKILL,0,0,0)==0
                    if os.getppid()!=parent:os._exit(97)
                child=subprocess.Popen(args,stdin=child_input,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                       env={'LC_ALL':'C','PATH':'/usr/bin:/usr/sbin:/bin'},pass_fds=(3,),preexec_fn=arm)
                os.close(child_input);os.write(proof,(str(child.pid)+'\n').encode())
                assert os.read(control,1)==b'C'
                os.close(3);os.write(proof,b'closed\n')
                os.read(control,1)
            finally:os._exit(98)
        for fd in (data_r,info_w,control_r):os.close(fd)
        child_pid=None;child_start=None;probe=None;reaped=False
        try:
            child_pid=int(line(info_r));child_start,_=identity(child_pid)
            assert child_start
            for _ in range(100):
                if os.path.realpath('/proc/'+str(child_pid)+'/exe')==os.path.realpath(args[0]):break
                time.sleep(0.01)
            assert os.path.realpath('/proc/'+str(child_pid)+'/exe')==os.path.realpath(args[0])
            assert Path('/proc/'+str(child_pid)+'/cmdline').read_bytes().rstrip(b'\0').split(b'\0')==[x.encode() for x in args]
            inherited=os.stat('/proc/'+str(child_pid)+'/fd/3')
            assert (inherited.st_dev,inherited.st_ino)==(expected.st_dev,expected.st_ino), 'wrong inherited lock inode'
            os.write(control_w,b'C');assert line(info_r)==b'closed'
            probe=os.open(lock,os.O_RDWR)
            try:fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except OSError as error:assert error.errno in (errno.EAGAIN,errno.EACCES)
            else:raise AssertionError('live trusted child failed to retain the shared flock')
            assert identity(child_pid)[0]==child_start and identity(child_pid)[1] not in (None,'Z'), 'child was not alive while holding lock'
            os.kill(controller,signal.SIGKILL);os.waitpid(controller,0);reaped=True
            for _ in range(150):
                current,state=identity(child_pid)
                if current!=child_start or state=='Z':break
                time.sleep(0.02)
            else:raise AssertionError('trusted child survived controller death')
            fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
            try:os.write(data_w,late)
            except OSError as error:assert error.errno==errno.EPIPE
            else:raise AssertionError('delayed mutation input still had a live reader')
            print('NATIVE_MUTATOR_'+name+'_FD3_DEATH=PASS',flush=True)
        finally:
            if not reaped:
                os.kill(controller,signal.SIGKILL);os.waitpid(controller,0)
            if child_pid and identity(child_pid)[0]==child_start and identity(child_pid)[1] not in (None,'Z'):
                os.kill(child_pid,signal.SIGKILL)
            for fd in (data_w,info_r,control_w):os.close(fd)
            if probe is not None:os.close(probe)
PYNATIVEMUTATOR
}

native_traced_apply() {
  native_trace_dir=$(mktemp -d /run/sc-qa-native-fds.XXXXXXXX)
  native_lock_identity=$(stat -Lc '%d:%i' /var/lib/server-connect/.lock)
  # Trace descriptor/control syscalls only: never credential or nft JSON
  # read/write payloads. This is the real installed product Apply path.
  strace -ff -yy -s 2048 \
    -e trace=execve,close,close_range,dup,dup2,dup3,fcntl,exit,exit_group \
    -o "$native_trace_dir/native" "$sc" --json smart-tun-trial-apply --saved --deadline-seconds 60 \
    >/run/sc-qa-product-tun-apply.json
  test "$(stat -Lc '%d:%i' /var/lib/server-connect/.lock)" = "$native_lock_identity"
  python3 - "$native_trace_dir" <<'PYNATIVEFDTRACE'
import json,re,sys
from pathlib import Path
lock=re.escape('/var/lib/server-connect/.lock')
files=list(Path(sys.argv[1]).glob('native.*'))
assert files and len(files)<=256
ip_modes=set();nft_seen=False;mutators=0
for file in files:
    assert file.stat().st_size<=1024*1024, 'oversized FD trace'
    lines=file.read_text().splitlines()
    for index,line in enumerate(lines):
        match=re.search(r'execve\("(/usr/(?:s?bin)/(?:ip|nft))", (\[.*?\]),.*\)\s*=\s*0$',line)
        if not match:continue
        args=json.loads(match.group(2));tool=Path(match.group(1)).name
        if tool=='ip':
            if not any(word in args for word in ('add','set','del')):continue
            mode=next((word for word in args[1:] if not word.startswith('-')),None)
            assert mode in {'link','addr','address','route','rule'}, 'ambiguous actual ip mutation'
            ip_modes.add('address' if mode=='addr' else mode)
        else:
            if args[-2:]!=['-f','-']:continue
            nft_seen=True
        mutators+=1
        before=lines[:index];after=lines[index+1:]
        bound=any(re.search(r'\bdup[23]\(\d+<'+lock+r'>,\s*3(?:<[^>]+>)?(?:,\s*0)?\)\s*=\s*3<'+lock+r'>',x) or
                  re.search(r'fcntl\(3<'+lock+r'>,\s*F_SETFD,\s*0\)\s*=\s*0',x) for x in before)
        assert bound, 'missing exact shared-lock fd3 exec handoff: '+file.name+'\n'+'\n'.join(before[-25:])
        for event in after:
            assert not re.search(r'\bclose\(3(?:<[^>]*>)?\)',event), 'mutator closed shared fd3: '+event
            interval=re.search(r'close_range\((\d+),\s*(\d+|~0U)',event)
            if interval:
                end=2**32-1 if interval.group(2)=='~0U' else int(interval.group(2))
                assert not int(interval.group(1))<=3<=end, 'mutator range-closed fd3: '+event
            assert not re.search(r'\bdup[23]\(-?\d+(?:<[^>]+>)?,\s*3(?:<[^>]+>)?(?:,|\))',event), 'mutator replaced fd3: '+event
            assert not re.search(r'\bdup\([^)]*\)\s*=\s*3(?:<|$)',event), 'mutator reused fd3: '+event
            if re.search(r'fcntl\(3(?:<[^>]*>)?,\s*F_SETFD',event):
                assert re.search(r'F_SETFD,\s*0\)',event), 'mutator changed fd3 inheritance: '+event
            assert 'execve(' not in event, 'unexpected secondary mutator exec'
        assert any('+++ exited with 0 +++' in x for x in after), 'mutator did not exit successfully'
assert ip_modes=={'link','address','route','rule'} and nft_seen and mutators>=5, (ip_modes,nft_seen,mutators)
print('PRODUCT_NATIVE_MUTATOR_FD3_COUNT='+str(mutators)+' (ip link/address/route/rule and nft stdin)')
print('PRODUCT_NATIVE_MUTATOR_FD3_ACTUAL_MODES=PASS')
PYNATIVEFDTRACE
  rm -rf -- "$native_trace_dir"
  native_trace_dir=
}

if [ "${1-}" = mutator-lifetime ]; then native_trusted_mutator_lifetime || exit 1; exit 0; fi
