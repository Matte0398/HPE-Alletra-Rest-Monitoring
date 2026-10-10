#!/usr/bin/env python3

##############################################################
## Description: Script to monitor HPE Alletra via REST API
##
## Author: Matteo Z.
##############################################################

from __future__ import annotations
import argparse, getpass, json, ssl, stat, sys, urllib.error, urllib.request
from pathlib import Path

VERSION = '1.0.0'
OK,WARN,CRIT,UNKNOWN=0,1,2,3
STATE_NAMES={0:'OK',1:'WARN',2:'CRIT',3:'UNKNOWN'}
CHECKS=('system','nodes','capacity','disks','cpgs','volumes','hosts','ports','remotecopy','alerts')
ENDPOINTS={
 'system':'/api/v1/system',
 'nodes':'/api/v1/system',
 'capacity':'/api/v1/system',
 'disks':'/api/v1/disks',
 'cpgs':'/api/v1/cpgs',
 'volumes':'/api/v1/volumes',
 'hosts':'/api/v1/hosts',
 'ports':'/api/v1/ports',
 'remotecopy':'/api/v1/remotecopygroups',
 'alerts':'/api/v1/eventlog'
}
DISK_STATES={1:('Normal',OK),2:('Degraded',CRIT),3:('New',WARN),4:('Failed',CRIT),99:('Unknown',UNKNOWN)}
PROTOCOLS={1:'FC',2:'SATA',3:'SAS',4:'NVMe',99:'Unknown'}
MEDIA_TYPES={1:'Magnetic',2:'SLC',3:'MLC',4:'cMLC',5:'3DX',6:'QLC',99:'Unknown'}
RCOPY_STATES={1:('NEW',WARN),2:('STARTING',WARN),3:('STARTED',OK),4:('RESTART',WARN),5:('STOPPED',CRIT),6:('BACKUP',OK),7:('FAILSAFE',CRIT),8:('UNKNOWN',UNKNOWN),9:('LOGGING',WARN)}
RCOPY_SYNC_STATES={
    1:('NEW',WARN),2:('SYNCING',WARN),3:('SYNCED',OK),4:('UNSYNC',CRIT),
    5:('STALE',CRIT),6:('NEWPRESYNCED',WARN),7:('NEWSYNCEDFROMSNAP',WARN),
    8:('STOPPED',CRIT),9:('FAILSAFE',CRIT),10:('UNKNOWN',UNKNOWN),11:('LOGGING',WARN),
}
PORT_MODES={1:'SUSPENDED',2:'TARGET',3:'INITIATOR',4:'PEER'}
PORT_LINK_STATES={
    1:('CONFIG_WAIT',WARN),2:('ALPA_WAIT',WARN),3:('LOGIN_WAIT',WARN),4:('READY',OK),
    5:('LOSS_SYNC',WARN),6:('ERROR_STATE',CRIT),7:('XXX',UNKNOWN),8:('NONPARTICIPATE',WARN),
    9:('COREDUMP',CRIT),10:('OFFLINE',CRIT),11:('FWDEAD',CRIT),12:('IDLE_FOR_RESET',WARN),
    13:('DHCP_IN_PROGRESS',WARN),14:('PENDING_RESET',WARN),15:('NEW',WARN),16:('DISABLED',WARN),
    17:('DOWN',CRIT),18:('FAILED',CRIT),19:('PURGING',WARN),
}
PORT_PROTOCOLS={1:'FC',2:'iSCSI',3:'FCoE',4:'IP',99:'UNKNOWN'}
PORT_HARDWARE_TYPES={1:'FC',2:'ETH',3:'iSCSI',4:'CNA',6:'COMBO',7:'NVMe',99:'UNKNOWN'}
ALERT_SEVERITIES={
    1:('FATAL',CRIT),
    2:('CRITICAL',CRIT),
    3:('MAJOR',CRIT),
    4:('MINOR',CRIT),
    5:('DEGRADED',CRIT),
    6:('INFORMATIONAL',OK),
    7:('DEBUG',OK),
    99:('UNKNOWN',UNKNOWN),
}

class MonitorError(Exception): pass


def worst(states):
    s=list(states)

    if CRIT in s:return CRIT
    if WARN in s:return WARN
    if UNKNOWN in s:return UNKNOWN

    return OK


def load_env(path):
    p=Path(path).expanduser()

    if not p.is_file(): raise MonitorError(f'Credentials file not found: {p}')

    mode=stat.S_IMODE(p.stat().st_mode)

    if mode & 0o077: raise MonitorError(f'Unsafe permissions on {p}: {oct(mode)}; expected 0600 or stricter')

    vals={}

    for n,raw in enumerate(p.read_text(encoding='utf-8').splitlines(),1):
        line=raw.strip()

        if not line or line.startswith('#'): continue
        if line.startswith('export '): line=line[7:].strip()
        if '=' not in line: raise MonitorError(f'Invalid .env syntax at {p}:{n}')

        k,v=line.split('=',1); k=k.strip(); v=v.strip()

        if len(v)>=2 and v[0]==v[-1] and v[0] in ('"',"'"): v=v[1:-1]

        vals[k]=v

    u=vals.get('ALLETRA_USER') or vals.get('HPE_ALLETRA_USER')
    pw=vals.get('ALLETRA_PASSWORD') or vals.get('HPE_ALLETRA_PASSWORD')

    if not u or not pw: raise MonitorError(f'ALLETRA_USER/ALLETRA_PASSWORD missing in {p}')

    return u,pw


def credentials(args):
    selected=sum(bool(x) for x in (args.credentials_file,args.password_stdin,args.password_id))

    if selected!=1: raise MonitorError('Choose exactly one: --credentials-file, --password-stdin or --password-id')
    if args.credentials_file:return load_env(args.credentials_file)

    if args.password_stdin:
        if not args.user:
            raise MonitorError('--user is required with --password-stdin')
        
        if sys.stdin.isatty():
            pw = getpass.getpass('Password: ')
        else:
            print('Password: ', end='', file=sys.stderr, flush=True)
            pw = sys.stdin.readline().rstrip('\r\n')

        if not pw:
            raise MonitorError('No password received on stdin')
        
        return args.user,pw
    
    if args.password_id:
        if not args.user:
            raise MonitorError('--user is required with --password-id')
        
        try:
            import cmk.utils.password_store as cmk_password_store
        except Exception as exc:
            raise MonitorError(
                '--password-id requires a Checkmk Python environment; '
                'use --credentials-file outside Checkmk'
            ) from exc
        
        try:
            store_path = getattr(cmk_password_store, 'password_store_path')

            if callable(store_path):
                store_path = store_path()

            password = cmk_password_store.lookup(Path(store_path), args.password_id)
        except ValueError as exc:
            raise MonitorError(str(exc)) from exc
        except Exception as exc:
            raise MonitorError(
                f'Unable to resolve Checkmk password-id {args.password_id!r}: {exc}'
            ) from exc
        
        return args.user, password


class Client:
    def __init__(self,host,user,password,port=443,verify=True,timeout=20,debug=False):
        self.base=f'https://{host}:{port}'; self.user=user; self.password=password; self.timeout=timeout; self.debug=debug; self.key=None
        self.ctx=ssl.create_default_context() if verify else ssl._create_unverified_context()

    def _dbg(self,msg):
        if self.debug: print('DEBUG:',msg,file=sys.stderr)

    def req(self,method,path,data=None,auth=True):
        hdr={'Accept':'application/json'}

        if auth:
            if not self.key: raise MonitorError('WSAPI session not established')

            hdr['X-HP3PAR-WSAPI-SessionKey']=self.key

        body=None

        if data is not None:
            hdr['Content-Type']='application/json'; body=json.dumps(data).encode()

        req=urllib.request.Request(self.base+path,data=body,headers=hdr,method=method); self._dbg(f'{method} {path}')

        try:
            with urllib.request.urlopen(req,context=self.ctx,timeout=self.timeout) as r:
                raw=r.read().decode(); self._dbg(f'{method} {path} -> HTTP {r.status}'); return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            b=e.read().decode(errors='replace'); raise MonitorError(f'HTTP {e.code} calling {path}: {b[:500]}')
        except urllib.error.URLError as e: raise MonitorError(f'Connection error calling {path}: {e.reason}')
        except json.JSONDecodeError: raise MonitorError(f'Invalid JSON returned by {path}')

    def login(self):
        d=self.req('POST','/api/v1/credentials',{'user':self.user,'password':self.password,'sessionType':1},False)
        self.key=d.get('key') if isinstance(d,dict) else None

        if not self.key: raise MonitorError('No WSAPI session key returned')

    def logout(self):
        if self.key:
            try:self.req('DELETE','/api/v1/credentials')
            except Exception:pass

            self.key=None

    def get(self,check,alerts_minutes=60):
        if check=='alerts':
            minutes=max(1,int(alerts_minutes))
            path=f'/api/v1/eventlog/minutes:{minutes}'

            return self.req('GET',path)
        
        return self.req('GET',ENDPOINTS[check])


def members(data):
    if isinstance(data,dict) and isinstance(data.get('members'),list): return [x for x in data['members'] if isinstance(x,dict)]
    if isinstance(data,list): return [x for x in data if isinstance(x,dict)]

    return []


def result(check,item,state,summary,details=None):return {'check':check,'item':item,'state':state,'state_name':STATE_NAMES[state],'summary':summary,'details':details}


def eval_system(d):
    err=guard_missing(d,('name','model','systemVersion'),'system')

    if err:
        return [result('system',None,UNKNOWN,err,d if isinstance(d,dict) else None)]
    
    if not isinstance(d,dict):return [result('system',None,UNKNOWN,'Unexpected /system response')]

    name=d.get('name') or d.get('systemName') or d.get('serialNumber') or 'Alletra'; model=d.get('model') or d.get('systemModel'); ver=d.get('systemVersion') or d.get('version')
    extras=[x for x in (f'model={model}' if model else None,f'version={ver}' if ver else None) if x]
    s=f'WSAPI reachable - system {name}'+((' ('+', '.join(extras)+')') if extras else '')

    return [result('system',None,OK,s,d)]


def guard_missing(obj, fields, context):
    """Return a clear guardrail message for missing required fields, else None."""
    if not isinstance(obj,dict):
        return f'{context}: expected JSON object, got {type(obj).__name__}'
    
    missing=[f for f in fields if f not in obj]

    if missing:
        return (
            f'{context}: missing required field(s): {", ".join(missing)}. '
            f'Cannot evaluate health reliably; verify WSAPI response/schema for this firmware.'
        )
    
    return None


def guard_any(obj, alternatives, context):
    """Require at least one field from alternatives."""
    if not isinstance(obj,dict):
        return f'{context}: expected JSON object, got {type(obj).__name__}'
    
    if not any(k in obj for k in alternatives):
        return (
            f'{context}: none of the required alternative fields are present: '
            f'{", ".join(alternatives)}. Cannot identify/evaluate this object.'
        )
    
    return None


def guard_members_container(d, check):
    """Validate list-style WSAPI responses."""
    if not isinstance(d,dict):
        return f'{check}: expected top-level JSON object, got {type(d).__name__}'
    
    if 'members' not in d:
        return (
            f'{check}: missing required top-level field "members". '
            f'Cannot parse WSAPI collection response.'
        )
    
    if not isinstance(d.get('members'),list):
        return (
            f'{check}: field "members" must be a list, got '
            f'{type(d.get("members")).__name__}.'
        )
    
    return None


def _pct(used,total):
    try:
        used=float(used); total=float(total)

        if total<=0:
            return None
        
        return (used/total)*100.0
    except (TypeError,ValueError,ZeroDivisionError):
        return None


def _fmt_mib(value):
    try:
        mib=float(value)
    except (TypeError,ValueError):
        return 'n/a'
    
    if mib >= 1024*1024:
        return f'{mib/(1024*1024):.2f} TiB'
    
    if mib >= 1024:
        return f'{mib/1024:.2f} GiB'
    
    return f'{mib:.0f} MiB'


def eval_nodes(d):
    err=guard_missing(d,('totalNodes','onlineNodes','clusterNodes','masterNode'),'nodes (/api/v1/system)')

    if err:
        return [result('nodes',None,UNKNOWN,err,d if isinstance(d,dict) else None)]

    if not isinstance(d.get('onlineNodes'),list):
        return [result('nodes',None,UNKNOWN,'nodes: field "onlineNodes" must be a list; cannot determine online node count',d)]
    
    if not isinstance(d.get('clusterNodes'),list):
        return [result('nodes',None,UNKNOWN,'nodes: field "clusterNodes" must be a list; cannot determine cluster membership',d)]

    total=d.get('totalNodes')
    online=d.get('onlineNodes') if isinstance(d.get('onlineNodes'),list) else []
    cluster=d.get('clusterNodes') if isinstance(d.get('clusterNodes'),list) else []
    master=d.get('masterNode')

    try:
        total_i=int(total)
    except (TypeError,ValueError):
        return [result('nodes',None,UNKNOWN,'totalNodes missing or invalid in /system response',d)]

    online_count=len(online)
    offline=sorted(set(cluster if cluster else range(total_i)) - set(online))

    state=OK
    reasons=[]

    if online_count < total_i:
        state=CRIT
        reasons.append(f'offline nodes={",".join(map(str,offline)) if offline else "unknown"}')

    if master is not None and master not in online:
        state=CRIT
        reasons.append(f'master node {master} is not online')

    if cluster and len(cluster) < total_i and state != CRIT:
        state=WARN
        reasons.append(f'cluster membership={len(cluster)}/{total_i}')

    summary=(
        f'Online nodes={online_count}/{total_i}, master={master if master is not None else "n/a"}, '
        f'cluster={",".join(map(str,cluster)) if cluster else "n/a"}'
    )

    if reasons:
        summary += ' - ' + '; '.join(reasons)

    details={
        'totalNodes':total_i,
        'onlineNodes':online,
        'clusterNodes':cluster,
        'masterNode':master,
        'offlineNodes':offline,
    }

    return [result('nodes',None,state,summary,details)]


def eval_capacity(d,warn=80.0,crit=90.0):
    err=guard_missing(
        d,
        ('totalCapacityMiB','allocatedCapacityMiB','freeCapacityMiB','failedCapacityMiB'),
        'capacity (/api/v1/system)'
    )

    if err:
        return [result('capacity',None,UNKNOWN,err,d if isinstance(d,dict) else None)]

    total=d.get('totalCapacityMiB')
    allocated=d.get('allocatedCapacityMiB')
    free=d.get('freeCapacityMiB')
    failed=d.get('failedCapacityMiB')
    pct=_pct(allocated,total)
    state=OK

    try:
        failed_f=float(failed or 0)
    except (TypeError,ValueError):
        failed_f=0.0

    if failed_f > 0:
        state=CRIT
    elif pct is None:
        state=UNKNOWN
    elif pct >= crit:
        state=CRIT
    elif pct >= warn:
        state=WARN

    summary=(
        f'Total={_fmt_mib(total)}, allocated={_fmt_mib(allocated)}, '
        f'free={_fmt_mib(free)}, failed={_fmt_mib(failed)}'
    )

    if pct is not None:
        summary += f', allocated={pct:.1f}% (warn={warn:g}%, crit={crit:g}%)'

    details={
        'totalCapacityMiB':total,
        'allocatedCapacityMiB':allocated,
        'freeCapacityMiB':free,
        'failedCapacityMiB':failed,
        'allocatedPercent':pct,
        'warnPercent':warn,
        'critPercent':crit,
    }

    return [result('capacity',None,state,summary,details)]


def _usage_totals(cpg):
    """Return best-effort used/total MiB across CPG usage objects."""
    used=0.0
    total=0.0
    found=False
    components={}

    for key in ('UsrUsage','SDUsage','SAUsage','usrUsage','sdUsage','saUsage'):
        obj=cpg.get(key)

        if not isinstance(obj,dict):
            continue

        u=obj.get('usedMiB')

        if u is None:
            # Some releases expose total/private/shared/free rather than used.
            total_space=obj.get('totalSpaceMiB',obj.get('totalMiB'))
            free_space=obj.get('freeSpaceMiB')

            if total_space is not None and free_space is not None:
                try:
                    u=float(total_space)-float(free_space)
                except (TypeError,ValueError):
                    u=None

        t=obj.get('totalSpaceMiB',obj.get('totalMiB'))

        if t is None:
            # If total isn't explicit but used+free is available, derive it.
            free_space=obj.get('freeSpaceMiB')

            if u is not None and free_space is not None:
                try:
                    t=float(u)+float(free_space)
                except (TypeError,ValueError):
                    t=None

        try:
            uf=float(u) if u is not None else None
            tf=float(t) if t is not None else None
        except (TypeError,ValueError):
            uf=tf=None

        if uf is not None or tf is not None:
            found=True
            components[key]={'usedMiB':uf,'totalMiB':tf}

        if uf is not None:
            used += uf

        if tf is not None:
            total += tf

    return (used,total,components) if found and total>0 else (None,None,components)


def eval_cpgs(d,warn=80.0,crit=90.0):
    err=guard_members_container(d,'cpgs')

    if err:
        return [result('cpgs',None,UNKNOWN,err,d if isinstance(d,dict) else None)]
    
    rows=members(d)

    if not rows:
        return [result('cpgs',None,OK,'No CPGs configured')] if isinstance(d,dict) and d.get('total')==0 else [result('cpgs',None,UNKNOWN,'Unexpected /cpgs response')]

    out=[]

    for idx,x in enumerate(rows):
        err=guard_any(x,('name','id'),f'cpgs member[{idx}]')

        if err:
            out.append(result('cpgs',str(idx),UNKNOWN,err,x if isinstance(x,dict) else None))
            continue

        item=str(x.get('name') or x.get('id') or 'unknown')
        state=OK

        # Textual health, when the firmware exposes it.
        raw_health=x.get('state',x.get('status'))
        health_name=None

        if isinstance(raw_health,str):
            health_name=raw_health.upper()

            if health_name in ('NORMAL','OK','GOOD','ONLINE'):
                health_state=OK
            elif health_name in ('DEGRADED','WARNING','WARN'):
                health_state=WARN
            elif health_name in ('FAILED','FAILURE','CRITICAL','ERROR','OFFLINE'):
                health_state=CRIT
            elif health_name in ('UNKNOWN',):
                health_state=UNKNOWN
            else:
                health_state=UNKNOWN

            state=worst((state,health_state))

        used,total,components=_usage_totals(x)
        pct=_pct(used,total)
        capacity_state=OK

        if pct is not None:
            if pct >= crit:
                capacity_state=CRIT
            elif pct >= warn:
                capacity_state=WARN

            state=worst((state,capacity_state))

        parts=[]

        if health_name:
            parts.append(f'state={health_name}')

        if pct is not None:
            parts.append(
                f'used={_fmt_mib(used)}/{_fmt_mib(total)} ({pct:.1f}%, '
                f'warn={warn:g}%, crit={crit:g}%)'
            )
        else:
            state=worst((state,UNKNOWN))
            parts.append(
                'capacity=UNKNOWN - required CPG usage fields are missing '
                '(expected one or more of UsrUsage/SDUsage/SAUsage with usable size fields)'
            )

        details=dict(x)
        details['_usedMiB']=used
        details['_totalMiB']=total
        details['_usedPercent']=pct
        details['_usageComponents']=components
        details['_healthName']=health_name
        out.append(result('cpgs',item,state,', '.join(parts),details))

    return out


def eval_alerts(d,minutes=60):
    err=guard_members_container(d,'alerts')

    if err:
        return [result('alerts',None,UNKNOWN,err,d if isinstance(d,dict) else None)]
    
    rows=members(d)

    if not rows:
        return [result('alerts',None,OK,f'No alerts in the last {minutes} minutes')]

    alert_rows=[]
    malformed=[]

    for idx,x in enumerate(rows):
        if not isinstance(x,dict):
            malformed.append(result('alerts',str(idx),UNKNOWN,f'alerts member[{idx}]: expected JSON object, got {type(x).__name__}'))
            continue

        if 'category' not in x:
            malformed.append(result(
                'alerts',
                str(x.get('id') or x.get('sequenceNumber') or idx),
                UNKNOWN,
                f'alerts member[{idx}]: missing required field "category". Cannot determine whether this event is an ALERT (category=2); verify /api/v1/eventlog schema.',
                x
            ))
            continue

        try:
            category=int(x.get('category'))
        except (TypeError,ValueError):
            malformed.append(result(
                'alerts',
                str(x.get('id') or x.get('sequenceNumber') or idx),
                UNKNOWN,
                f'alerts member[{idx}]: invalid "category" value {x.get("category")!r}; expected numeric WSAPI event category.',
                x
            ))
            continue

        if category != 2:
            continue

        if 'severity' not in x:
            malformed.append(result(
                'alerts',
                str(x.get('id') or x.get('sequenceNumber') or idx),
                UNKNOWN,
                f'alerts member[{idx}]: category=2 identifies an ALERT but required field "severity" is missing. Cannot assign OK/WARN/CRIT reliably.',
                x
            ))
            continue

        alert_rows.append(x)

    if malformed:
        return malformed

    if not alert_rows:
        return [result('alerts',None,OK,f'No alerts in the last {minutes} minutes')]

    out=[]

    for x in alert_rows:
        raw_sev=x.get('severity',99)

        try:
            sev_name,st=ALERT_SEVERITIES.get(int(raw_sev),(f'UNKNOWN({raw_sev})',UNKNOWN))
        except (TypeError,ValueError):
            sev_name=str(raw_sev if raw_sev is not None else 'UNKNOWN').upper()
            st=UNKNOWN

        item=str(
            x.get('id')
            or (x.get('alertInfo') or {}).get('alertId')
            or x.get('sequenceNumber')
            or x.get('timeSec')
            or 'event'
        )
        desc=x.get('description') or x.get('message') or x.get('resourceName') or 'No description'
        desc=' '.join(str(desc).split())
        when=x.get('time8601') or x.get('time') or x.get('timestamp') or 'n/a'
        resource=x.get('resource') or x.get('component') or 'n/a'
        alert_state=x.get('state')
        state_text=f', alert_state={alert_state}' if alert_state is not None else ''
        summary=f'{sev_name} - {desc} (resource={resource}, time={when}{state_text})'
        out.append(result('alerts',item,st,summary,x))

    return out


def eval_disks(d):
    err=guard_members_container(d,'disks')

    if err:
        return [result('disks',None,UNKNOWN,err,d if isinstance(d,dict) else None)]
    
    rows=members(d)

    if not rows:return [result('disks',None,WARN if isinstance(d,dict) and d.get('total')==0 else UNKNOWN,'No physical disks returned' if isinstance(d,dict) and d.get('total')==0 else 'Unexpected /disks response')]

    out=[]

    for idx,x in enumerate(rows):
        err=guard_missing(x,('state',),f'disks member[{idx}]')

        if err:
            out.append(result('disks',str(x.get('position') or x.get('id') or idx) if isinstance(x,dict) else str(idx),UNKNOWN,err,x if isinstance(x,dict) else None))
            continue

        err=guard_any(x,('position','id'),f'disks member[{idx}]')

        if err:
            out.append(result('disks',str(idx),UNKNOWN,err,x))
            continue

        item=str(x.get('position') or x.get('id') or x.get('WWN') or 'unknown')

        try:rs=int(x.get('state',99))
        except:rs=99

        sn,st=DISK_STATES.get(rs,(f'Unknown({x.get("state")})',UNKNOWN)); proto=PROTOCOLS.get(x.get('protocol'),str(x.get('protocol','n/a'))); media=MEDIA_TYPES.get(x.get('mediaType'),str(x.get('mediaType','n/a')))
        s=f'State={sn}, {x.get("manufacturer","n/a")} {x.get("model","n/a")}, {x.get("mfgCapacityGB","n/a")} GB, {proto}/{media}, SN={x.get("serialNumber","n/a")}, FW={x.get("fwVersion","n/a")}'
        out.append(result('disks',item,st,s,x))

    return out


def eval_rcopy(d):
    err=guard_members_container(d,'remotecopy')

    if err:
        return [result('remotecopy',None,UNKNOWN,err,d if isinstance(d,dict) else None)]
    
    rows=members(d)

    if not rows:
        return [result('remotecopy',None,OK,'No Remote Copy groups configured')] if isinstance(d,dict) and d.get('total')==0 else [result('remotecopy',None,UNKNOWN,'Unexpected Remote Copy response')]

    out=[]

    for idx,x in enumerate(rows):
        err=guard_missing(x,('name','role','targets'),'remotecopy member[%d]' % idx)

        if err:
            out.append(result('remotecopy',str(x.get('name') or x.get('id') or idx) if isinstance(x,dict) else str(idx),UNKNOWN,err,x if isinstance(x,dict) else None))
            continue

        if not isinstance(x.get('targets'),list):
            out.append(result('remotecopy',str(x.get('name') or idx),UNKNOWN,'remotecopy: field "targets" must be a list; cannot evaluate replication target state',x))
            continue

        item=str(x.get('name') or x.get('id') or 'unknown')
        role_raw=x.get('role')
        role={1:'PRIMARY',2:'SECONDARY','1':'PRIMARY','2':'SECONDARY'}.get(role_raw,str(role_raw if role_raw is not None else 'n/a'))
        raw_group_state=x.get('state')
        target_rows=[t for t in (x.get('targets') or []) if isinstance(t,dict)]
        target_states=[]

        for tidx,target in enumerate(target_rows):
            if 'state' not in target:
                target_states.append((f'MISSING_STATE',UNKNOWN,target.get('targetName') or target.get('target') or f'target[{tidx}]'))
                continue

            raw=target.get('state')

            try:
                raw_i=int(raw); name,state=RCOPY_STATES.get(raw_i,(f'UNKNOWN({raw})',UNKNOWN))
            except (TypeError,ValueError):
                name=str(raw if raw is not None else 'UNKNOWN').upper(); state=UNKNOWN

            target_states.append((name,state,target.get('targetName') or target.get('target') or 'unknown'))

        if raw_group_state is not None:
            try:
                raw_i=int(raw_group_state); mode_name,mode_state=RCOPY_STATES.get(raw_i,(f'UNKNOWN({raw_group_state})',UNKNOWN))
            except (TypeError,ValueError):
                mode_name=str(raw_group_state).upper(); mode_state=UNKNOWN
        elif target_states:
            unique_names={name for name,_,_ in target_states}
            mode_name=target_states[0][0] if len(unique_names)==1 else 'MIXED'
            mode_state=worst(state for _,state,_ in target_states)
        else:
            mode_name='UNKNOWN'; mode_state=UNKNOWN

        sync_entries=[]

        for volume in x.get('volumes') or []:
            if not isinstance(volume,dict): continue

            local_name=volume.get('localVolumeName') or str(volume.get('localVolumeID','unknown'))

            for remote in volume.get('remoteVolumes') or []:
                if not isinstance(remote,dict): continue

                if 'syncStatus' not in remote:
                    sync_entries.append((local_name,'MISSING_SYNCSTATUS',UNKNOWN))
                    continue

                raw_sync=remote.get('syncStatus')

                try:
                    raw_sync_i=int(raw_sync); sync_name,sync_state=RCOPY_SYNC_STATES.get(raw_sync_i,(f'UNKNOWN({raw_sync})',UNKNOWN))
                except (TypeError,ValueError):
                    sync_name=str(raw_sync if raw_sync is not None else 'UNKNOWN').upper(); sync_state=UNKNOWN

                sync_entries.append((local_name,sync_name,sync_state))

        if not sync_entries:
            sync_health='N/A'; sync_state=OK
        else:
            sync_state=worst(state for _,_,state in sync_entries)

            if all(name=='SYNCED' for _,name,_ in sync_entries):
                sync_health='NORMAL'
            elif any(state==CRIT for _,_,state in sync_entries):
                sync_health='DEGRADED'
            elif any(state==UNKNOWN for _,_,state in sync_entries):
                sync_health='UNKNOWN'
            else:
                sync_health='SYNCING'

        effective_state=CRIT if (mode_name=='STARTED' and sync_health=='DEGRADED') else worst((mode_state,sync_state))
        target_summary=', '.join(f'{name}:{target_name}' for name,_,target_name in target_states) or 'n/a'
        sync_summary=f'{sum(1 for _,name,_ in sync_entries if name=="SYNCED")}/{len(sync_entries)} synced' if sync_entries else 'no volume sync data'
        summary=(f'Mode={mode_name}, Status={sync_health}, role={role}, remote={x.get("remoteGroupName","n/a")}, '
                 f'targets={target_summary}, volumes={len(x.get("volumes") or [])}, {sync_summary}')
        details=dict(x)
        details['_derivedMode']=mode_name
        details['_derivedStatus']=sync_health
        out.append(result('remotecopy',item,effective_state,summary,details))

    return out


def generic(check,d):
    err=guard_members_container(d,check)

    if err:
        return [result(check,None,UNKNOWN,err,d if isinstance(d,dict) else None)]
    
    rows=members(d)

    if not rows:
        return [result(check,None,OK,f'No {check} objects configured')] if isinstance(d,dict) and d.get('total')==0 else [result(check,None,UNKNOWN,f'Unexpected /{check} response')]

    out=[]

    for x in rows:
        if check=='ports':
            err=guard_missing(x,('portPos','linkState','mode','protocol'),f'ports member[{len(out)}]')

            if err:
                out.append(result(check,str(x.get('portPos') or x.get('id') or len(out)) if isinstance(x,dict) else str(len(out)),UNKNOWN,err,x if isinstance(x,dict) else None))
                continue
    
            if not isinstance(x.get('portPos'),dict):
                out.append(result(check,str(x.get('id') or len(out)),UNKNOWN,'ports: field "portPos" must be an object containing node/slot/cardPort',x))
                continue

            pp=x.get('portPos') or x.get('position')
            item=f'{pp.get("node","?")}:{pp.get("slot","?")}:{pp.get("cardPort","?")}' if isinstance(pp,dict) else str(pp or x.get('name') or x.get('id') or 'unknown')
            raw_mode=x.get('mode'); raw_link=x.get('linkState'); raw_protocol=x.get('protocol'); raw_hw=x.get('hardwareType')

            try: mode_name=PORT_MODES.get(int(raw_mode),f'UNKNOWN({raw_mode})')
            except (TypeError,ValueError): mode_name=str(raw_mode if raw_mode is not None else 'UNKNOWN')

            try: link_name,port_state=PORT_LINK_STATES.get(int(raw_link),(f'UNKNOWN({raw_link})',UNKNOWN))
            except (TypeError,ValueError): link_name=str(raw_link if raw_link is not None else 'UNKNOWN'); port_state=UNKNOWN

            try: protocol_name=PORT_PROTOCOLS.get(int(raw_protocol),f'UNKNOWN({raw_protocol})')
            except (TypeError,ValueError): protocol_name=str(raw_protocol if raw_protocol is not None else 'UNKNOWN')

            try: hw_name=PORT_HARDWARE_TYPES.get(int(raw_hw),f'UNKNOWN({raw_hw})')
            except (TypeError,ValueError): hw_name=str(raw_hw if raw_hw is not None else 'UNKNOWN')

            fields=[f'mode={mode_name}',f'link={link_name}',f'protocol={protocol_name}',f'hardware={hw_name}']

            if x.get('portWWN'): fields.append(f'portWWN={str(x.get("portWWN")).strip()}')
            if x.get('nodeWWN'): fields.append(f'nodeWWN={str(x.get("nodeWWN")).strip()}')

            details=dict(x); details['_modeName']=mode_name; details['_linkName']=link_name; details['_protocolName']=protocol_name; details['_hardwareName']=hw_name
            out.append(result(check,item,port_state,', '.join(fields),details)); continue

        if check=='hosts':
            err=guard_any(x,('name','id'),f'hosts member[{len(out)}]')

            if err:
                out.append(result(check,str(len(out)),UNKNOWN,err,x if isinstance(x,dict) else None))
                continue

            item=str(x.get('name') or x.get('id') or 'unknown')
            fields=[]

            if x.get('persona') is not None: fields.append(f'persona={x.get("persona")}')
            if x.get('domain') is not None: fields.append(f'domain={x.get("domain")}')
            if x.get('state') is not None: fields.append(f'state={x.get("state")}')
            if x.get('status') is not None: fields.append(f'status={x.get("status")}')

            fc=x.get('FCPaths') or x.get('fcPaths') or x.get('FCWWNs')
            iscsi=x.get('iSCSIPaths') or x.get('iscsiPaths') or x.get('iSCSINames')

            if isinstance(fc,list): fields.append(f'fc_paths={len(fc)}')
            if isinstance(iscsi,list): fields.append(f'iscsi_paths={len(iscsi)}')
            if not fields: fields.append('configured')

            out.append(result(check,item,OK,', '.join(fields),x)); continue

        item=str(x.get('name') or x.get('portPos') or x.get('position') or x.get('id') or 'unknown')
        fr=['API object discovered']

        if x.get('state') is not None: fr.append(f'state={x.get("state")}')
        if x.get('status') is not None: fr.append(f'status={x.get("status")}')

        out.append(result(check,item,OK,', '.join(fr),x))

    return out


EVAL={
    'system':eval_system,
    'nodes':eval_nodes,
    'capacity':eval_capacity,
    'disks':eval_disks,
    'cpgs':eval_cpgs,
    'volumes':lambda d:generic('volumes',d),
    'hosts':lambda d:generic('hosts',d),
    'ports':lambda d:generic('ports',d),
    'remotecopy':eval_rcopy,
    'alerts':eval_alerts,
}


def collect(c,checks,cont,args):
    raw={}
    res=[]
    cache={}

    for ch in checks:
        try:
            cache_key=ENDPOINTS[ch]

            if ch=='alerts':
                cache_key=f'{cache_key}:minutes:{args.alerts_minutes}'

            if cache_key in cache:
                data=cache[cache_key]
            else:
                data=c.get(ch,args.alerts_minutes)
                cache[cache_key]=data

            raw[ch]=data

            if ch=='capacity':
                rows=eval_capacity(data,args.warn,args.crit)
            elif ch=='cpgs':
                rows=eval_cpgs(data,args.warn,args.crit)
            elif ch=='alerts':
                rows=eval_alerts(data,args.alerts_minutes)
            else:
                rows=EVAL[ch](data)

            res+=rows
        except Exception as e:
            res.append(result(ch,None,UNKNOWN,str(e)))

            if not cont:
                break

    return raw,res


def svc(r):
    base={
        'system':'Alletra System',
        'nodes':'Alletra Nodes',
        'capacity':'Alletra Capacity',
        'disks':'Alletra Disk',
        'cpgs':'Alletra CPG',
        'volumes':'Alletra Volume',
        'hosts':'Alletra Host',
        'ports':'Alletra Port',
        'remotecopy':'Alletra RemoteCopy',
        'alerts':'Alletra Alerts',
    }[r['check']]

    return f'{base} {r["item"]}' if r['item'] else base


def _short_value(r):
    check=r['check']; item=r['item']; details=r.get('details') or {}

    if item is None and not details:
        return r['summary']
    
    if check=='system':
        return r['summary']
    
    if check in ('nodes','capacity'):
        return r['summary']
    
    if check=='cpgs':
        return f'CPG "{item}", {r["summary"]}'
    
    if check=='alerts':
        if item is None:
            return r['summary']
        
        return f'Alert "{item}", {r["summary"]}'
    
    if check=='disks':
        raw_state=details.get('state')

        try: state_name=DISK_STATES.get(int(raw_state),(f'Unknown({raw_state})',UNKNOWN))[0]
        except Exception: state_name=str(raw_state if raw_state is not None else 'unknown')

        return f'Disk "{item}", state={state_name}'
    
    if check=='remotecopy':
        mode_name=details.get('_derivedMode','UNKNOWN'); status_name=details.get('_derivedStatus','UNKNOWN')
        role={1:'PRIMARY',2:'SECONDARY','1':'PRIMARY','2':'SECONDARY'}.get(details.get('role'),str(details.get('role','n/a')))

        return f'RemoteCopy "{item}", mode={mode_name}, status={status_name}, role={role}, remote="{details.get("remoteGroupName","n/a")}"'
    
    if check=='ports':
        return (f'Port "{item}", mode={details.get("_modeName","UNKNOWN")}, link={details.get("_linkName","UNKNOWN")}, '
                f'protocol={details.get("_protocolName","UNKNOWN")}, hardware={details.get("_hardwareName","UNKNOWN")}')
    
    if check=='hosts':
        fields=[]

        if details.get('persona') is not None: fields.append(f'persona={details.get("persona")}')
        if details.get('domain') is not None: fields.append(f'domain={details.get("domain")}')
        if details.get('state') is not None: fields.append(f'state={details.get("state")}')
        if details.get('status') is not None: fields.append(f'status={details.get("status")}')

        fc=details.get('FCPaths') or details.get('fcPaths') or details.get('FCWWNs')
        iscsi=details.get('iSCSIPaths') or details.get('iscsiPaths') or details.get('iSCSINames')

        if isinstance(fc,list): fields.append(f'fc_paths={len(fc)}')
        if isinstance(iscsi,list): fields.append(f'iscsi_paths={len(iscsi)}')

        return f'Host "{item}", ' + (', '.join(fields) if fields else 'configured')
    
    raw_state=details.get('state'); raw_status=details.get('status'); label=check.rstrip('s').capitalize()
    parts=[f'{label} "{item}"']

    if raw_state is not None: parts.append(f'state={raw_state}')
    if raw_status is not None: parts.append(f'status={raw_status}')
    if len(parts)==1: parts.append('state=discovered')

    return ', '.join(parts)


def out_text(res,allmode):
    if allmode:
        grouped={}

        for r in res:
            grouped.setdefault(r['check'],[]).append(r)

        for idx,(check,rows) in enumerate(grouped.items()):
            if idx:
                print()

            st=worst(r['state'] for r in rows)
            print(f'[{check.upper()}] {STATE_NAMES[st]}')

            for r in rows:
                print(f'- {STATE_NAMES[r["state"]]}: {_short_value(r)}')

        overall=worst(r['state'] for r in res)
        print()
        print(f'Overall: {STATE_NAMES[overall]}')

        return
    
    overall=worst(r['state'] for r in res)
    ok_count=sum(r['state']==OK for r in res)
    warn_count=sum(r['state']==WARN for r in res)
    crit_count=sum(r['state']==CRIT for r in res)
    unk_count=sum(r['state']==UNKNOWN for r in res)
    details=' - '.join(_short_value(r) for r in res)
    print(
        f'{STATE_NAMES[overall]} - objects={len(res)}, ok={ok_count}, '
        f'warn={warn_count}, crit={crit_count}, unknown={unk_count}'
        + (f' - {details}' if details else '')
    )


def out_checkmk(res):
    print('<<<local>>>')

    for r in res:
        name=svc(r).replace('\\','\\\\').replace('"','\\"'); summary=r['summary'].replace('\n',' ').replace('\r',' ')
        print(f'{r["state"]} "{name}" - {summary}')


def discovery_items(kind,rows):
    out=[]

    for x in rows:
        item=str(x.get('position') if kind=='disks' else (x.get('name') or x.get('portPos') or x.get('position') or x.get('id') or 'unknown'))
        out.append({'item':item,'data':x})

    return out


def parser():
    p=argparse.ArgumentParser(description='HPE Alletra Storage MP WSAPI monitor');p.add_argument('--version',action='version',version=f'%(prog)s {VERSION}')
    p.add_argument('--host',required=True);p.add_argument('--port',type=int,default=443);p.add_argument('--timeout',type=int,default=20);p.add_argument('--no-cert-check',action='store_true');p.add_argument('--debug',action='store_true')
    p.add_argument('--user');p.add_argument('--credentials-file');p.add_argument('--password-stdin',action='store_true');p.add_argument('--password-id')
    g=p.add_mutually_exclusive_group(required=True);g.add_argument('--check',choices=(*CHECKS,'all'));g.add_argument('--discover',choices=('disks','cpgs','volumes','hosts','ports','remotecopy'))
    p.add_argument('--warn',type=float,default=80.0,metavar='PCT',help='WARN threshold percentage for capacity-based checks (default: 80)')
    p.add_argument('--crit',type=float,default=90.0,metavar='PCT',help='CRIT threshold percentage for capacity-based checks (default: 90)')
    p.add_argument('--alerts-minutes',type=int,default=60,metavar='N',help='Look back N minutes for category ALERT events (default: 60)')
    p.add_argument('--output',choices=('nagios','json','checkmk','text'),default='nagios',help='Output format; text is a legacy alias of nagios');p.add_argument('--include-raw',action='store_true');return p


########## MAIN ##########

def main():
    a=parser().parse_args()

    if not (0 <= a.warn < a.crit <= 100):
        print('UNKNOWN - thresholds must satisfy 0 <= WARN < CRIT <= 100')
        return UNKNOWN
    
    if a.alerts_minutes < 1:
        print('UNKNOWN - --alerts-minutes must be >= 1')
        return UNKNOWN
    
    try:
        u,pw=credentials(a);c=Client(a.host,u,pw,a.port,not a.no_cert_check,a.timeout,a.debug);c.login()

        try:
            if a.discover:
                raw,res=collect(c,[a.discover],False,a)

                if any(r['state']==UNKNOWN and r['item'] is None for r in res):out_text(res,False);return UNKNOWN

                rows=members(raw.get(a.discover,{}))
                disc=discovery_items(a.discover,rows)

                if a.output=='json':
                    print(json.dumps(disc,indent=2,sort_keys=True,default=str))
                else:
                    for entry in disc:
                        print(entry['item'])

                return OK
            
            checks=list(CHECKS) if a.check=='all' else [a.check];raw,res=collect(c,checks,a.check=='all',a)

            if a.output=='json':
                payload={'host':a.host,'overall_state':STATE_NAMES[worst(r['state'] for r in res)],'results':res};

                if a.include_raw:payload['raw']=raw

                print(json.dumps(payload,indent=2,sort_keys=True,default=str))
            elif a.output=='checkmk':
                out_checkmk(res)
                return OK
            else:
                out_text(res,a.check=='all')

            return worst(r['state'] for r in res)
        finally:c.logout()
    except MonitorError as e:
        if a.output=='json':
            print(json.dumps({'overall_state':'UNKNOWN','error':str(e)},separators=(',',':')))
            return UNKNOWN
        elif a.output=='checkmk':
            print(f'<<<local>>>\n3 "Alletra Collector" - {str(e).replace(chr(10)," ")}')
            return OK
        else:
            print('UNKNOWN -',e)
            return UNKNOWN


if __name__=='__main__':sys.exit(main())