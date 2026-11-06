"""NVD CPE Dictionary 2.0 feed (extracted nvdcpe-2.0-chunks/*.json) -> vendor:product table with titles, vendor domains
and deprecation targets.  usage: cpedb.py <chunk-dir> <out.json>"""
import json,glob,re,sys,collections
from urllib.parse import urlparse
src=sys.argv[1]; out=sys.argv[2]
def unesc(s): return re.sub(r'\\(.)',r'\1',s)
def split(c):
    # split CPE 2.3 on unescaped colons
    return [unesc(x) for x in re.split(r'(?<!\\):',c)]
P={}
for f in sorted(glob.glob(src+'/*.json')):
    d=json.load(open(f))
    for it in d['products']:
        c=it['cpe']; p=split(c['cpeName'])
        key=p[2]+':'+p[3]+':'+p[4]
        e=P.get(key)
        if e is None: e=P[key]={'n':0,'dep':0,'titles':collections.Counter(),'doms':collections.Counter(),'depBy':set()}
        e['n']+=1
        if c.get('deprecated'):
            e['dep']+=1
            for db in c.get('deprecatedBy',[]) or []:
                q=split(db['cpeName']); e['depBy'].add(q[2]+':'+q[3]+':'+q[4])
        t=next((x['title'] for x in c.get('titles',[]) if x.get('lang')=='en'),'')
        ver=p[5]
        if ver not in ('*','-',''):
            t2=t.replace(ver,'').strip()
        else: t2=t
        t2=re.sub(r'\s+',' ',t2).strip()
        if len(e['titles'])<50 or t2 in e['titles']: e['titles'][t2]+=1
        for r in c.get('refs',[]) or []:
            if r.get('type') in ('Vendor','Product'):
                h=urlparse(r.get('ref','')).hostname or ''
                h=h.lower()
                if h.startswith('www.'): h=h[4:]
                if h and (len(e['doms'])<20 or h in e['doms']): e['doms'][h]+=1
res={k:{'n':v['n'],'dep':v['dep'],'titles':[t for t,_ in v['titles'].most_common(3)],'doms':[d for d,_ in v['doms'].most_common(5)],'depBy':sorted(v['depBy'])} for k,v in P.items()}
json.dump(res,open(out,'w'))
print(len(res),'vendor:product entries')
