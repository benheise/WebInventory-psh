"""NVD CVE JSON 2.0 feeds + CISA KEV -> vendor:product -> [CVE count, KEV count] (vulnerable criteria only, newest record
per CVE, rejected CVEs skipped).  usage: cvecpe.py <feed-dir> <known_exploited_vulnerabilities.json> <out.json>"""
import json,gzip,glob,re,sys,collections
feeds=sys.argv[1]; kevf=sys.argv[2]; out=sys.argv[3]
def unesc(s): return re.sub(r'\\(.)',r'\1',s)
def split(c): return [unesc(x) for x in re.split(r'(?<!\\):',c)]
kev=set(v['cveID'] for v in json.load(open(kevf))['vulnerabilities'])
recs={}
for f in sorted(glob.glob(feeds+'/nvdcve-2.0-*.json.gz')):
    d=json.load(gzip.open(f))
    for v in d['vulnerabilities']:
        c=v['cve']; cid=c['id']; lm=c.get('lastModified','')
        if cid in recs and recs[cid][0]>=lm: continue
        if c.get('vulnStatus')=='Rejected': recs[cid]=(lm,set()); continue
        s=set()
        for cfg in c.get('configurations',[]) or []:
            for n in cfg.get('nodes',[]):
                for m in n.get('cpeMatch',[]):
                    if m.get('vulnerable'):
                        p=split(m['criteria']); s.add(p[2]+':'+p[3]+':'+p[4])
        recs[cid]=(lm,s)
cnt=collections.Counter(); kc=collections.Counter()
for cid,(lm,s) in recs.items():
    for k in s:
        cnt[k]+=1
        if cid in kev: kc[k]+=1
json.dump({k:[cnt[k],kc[k]] for k in cnt},open(out,'w'))
print(len(recs),'cves',len(cnt),'vendor:product with vulnerable criteria',len(kc),'in KEV')
