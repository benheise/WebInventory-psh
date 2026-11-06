#!/usr/bin/env bash
# Store scenario test through the script's own command line: imports, queries, refusals, tamper detection, crash repair,
# rebuild. usage: tests/store/scenario.sh <workdir> [script]
set -u
W=${1:?workdir}; SCRIPT=${2:-$(dirname "$0")/../../dist/Invoke-WebInventory.ps1}
SCRIPT=$(readlink -f "$SCRIPT"); HERE=$(cd "$(dirname "$0")" && pwd)
rm -rf "$W"; mkdir -p "$W"; cd "$W"
python3 "$HERE/gen.py" "$W/out"
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "PASS $1"; }
bad()  { fail=$((fail+1)); echo "FAIL $1"; }
wi()   { pwsh -NoProfile -File "$SCRIPT" "$@" > "$W/last.out" 2>&1; echo $? > "$W/last.rc"; }
rc()   { cat "$W/last.rc"; }
has()  { grep -q -- "$1" "$W/last.out"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; sed 's/^/      /' "$W/last.out" | tail -8; fi; }
q()    { local name=$1; shift; rm -rf "$W/q/$name"; mkdir -p "$W/q/$name"; wi -Store "$W/store" -OutputDir "$W/q/$name" "$@"; ls "$W/q/$name"/*.csv 2>/dev/null | head -1; }
py()   { python3 - "$@"; }

for r in 1 2 3 4 5; do wi -Store "$W/store" -ImportRun "$W/out/run$r"; check "import run$r" '[ "$(rc)" = 0 ] && has "ingested run"'; done

f=$(q changes -StoreQuery Changes -NoHtml)
check "changes: every expected event and nothing else" "py '$f' <<'P'
import csv,sys
got=sorted((r['RunId'][6:8],r['Change'],r['Host']+':'+r['Port'],r['Field'],r['Rule']) for r in csv.DictReader(open(sys.argv[1],encoding='utf-8-sig')))
exp=[('01','Added',h,'','') for h in ['10.0.0.1:80','10.0.0.2:443','10.0.0.3:22','web01.corp.local:8443','app.corp.local:443','10.0.9.9:80','10.0.0.5:25','10.0.0.6:443','10.0.0.7:443','10.0.0.8:443','10.0.0.9:443']]
exp+=[('02','Changed','10.0.0.2:443','Title',''),('02','Missing','10.0.0.3:22','',''),('02','Missing','10.0.0.8:443','',''),('02','Added','10.0.0.10:443','',''),('02','Added','10.0.0.20:8080','',''),
      ('02','Rekeyed','web01.corp.local:8443','IP','same-name')]
exp+=[('02','Rekeyed','10.0.0.16:443',f,'same-reverse-dns') for f in ['Host','IP','Url','FinalUrl','CertSubject','CertSha256']]
exp+=[('02','Rekeyed','10.0.0.17:443',f,'same-certificate') for f in ['Host','IP','Url','FinalUrl','CertSubject']]
exp+=[('04','Missing','app.corp.local:443','',''),('04','Changed','10.0.0.20:8080','Server',''),('04','Retired','10.0.0.3:22','',''),('04','Retired','10.0.0.8:443','',''),
      ('05','Reappeared','app.corp.local:443','',''),('05','Reappeared','10.0.0.3:22','Products',''),('05','Reappeared','10.0.0.3:22','Banner','')]
missing=set(exp)-set(got); extra=set(got)-set(exp)
print('missing',missing,'extra',extra) if missing or extra else None
sys.exit(0 if not missing and not extra and len(got)==len(exp) else 1)
P"
f=$(q inv -StoreQuery Inventory)
check "inventory (Active+Missing): 12 services, HTML report written" "[ \$(python3 -c \"import csv;print(len(list(csv.DictReader(open('$f',encoding='utf-8-sig')))))\") = 12 ] && ls '$W/q/inv/'*.html >/dev/null"
f=$(q all -StoreQuery Inventory -Status All -NoHtml)
check "inventory -Status All: 13 including the retired one" "py '$f' <<'P'
import csv,sys
rows=list(csv.DictReader(open(sys.argv[1],encoding='utf-8-sig')))
st={r['Host']+':'+r['Port']:r['Status'] for r in rows}
sys.exit(0 if len(rows)==13 and st['10.0.0.8:443']=='Retired' and st['10.0.0.3:22']=='Active' and st['10.0.9.9:80']=='Active' else 1)
P"
f=$(q jen -StoreQuery Inventory -Filter 'Technologies=Jenkins' -NoHtml)
check "filter Technologies=Jenkins: one row, 2 versions, TLS fields kept through the -NoTlsScan run" "py '$f' <<'P'
import csv,sys
rows=list(csv.DictReader(open(sys.argv[1],encoding='utf-8-sig')))
r=rows[0] if rows else {}
sys.exit(0 if len(rows)==1 and r['Title']=='Jenkins [prod]' and r['Versions']=='2' and r['TlsSupported']=='TLS1.2,TLS1.3' and r['FirstRun']=='20261001_100000' else 1)
P"
f=$(q moved -StoreQuery Inventory -Filter 'Host=web01.corp.local' -NoHtml)
check "moved named host keeps its identity: first seen in run 1 at its new address" "py '$f' <<'P'
import csv,sys
rows=list(csv.DictReader(open(sys.argv[1],encoding='utf-8-sig')))
sys.exit(0 if len(rows)==1 and rows[0]['IP']=='10.0.0.14' and rows[0]['FirstRun']=='20261001_100000' else 1)
P"
f=$(q flag -StoreQuery Inventory -Filter 'Flags=CertExpiring -and CertDaysLeft<30' -NoHtml)
check "filter Flags=CertExpiring (flag name matches Flag:detail) -and computed CertDaysLeft<30" "[ \$(python3 -c \"import csv;print(len(list(csv.DictReader(open('$f',encoding='utf-8-sig')))))\") = 1 ]"
f=$(q flag2 -StoreQuery Inventory -Filter 'Flags=CertExpiring -and CertDaysLeft>30' -NoHtml)
check "second -and clause is applied (CertDaysLeft>30 excludes it)" "[ \$(python3 -c \"import csv;print(len(list(csv.DictReader(open('$f',encoding='utf-8-sig')))))\") = 0 ]"
wi -Store "$W/store" -StoreQuery Inventory -Filter 'Flags=CertExpiring' 'CertDaysLeft<30' -OutputDir "$W/q"
check "a stray second argument in store mode is refused, not ignored" '[ "$(rc)" = 1 ] && has "Unexpected argument"'
wi -Store "$W/store" -StoreQuery Changes -ChangeType 'Retired,Bogus' -OutputDir "$W/q"
check "invalid -ChangeType value is refused" '[ "$(rc)" = 1 ] && has "is not one of"'
f=$(q any -StoreQuery Inventory -Filter 'Any~printer1' -NoHtml)
check "filter Any~printer1" "[ \$(python3 -c \"import csv;print(len(list(csv.DictReader(open('$f',encoding='utf-8-sig')))))\") = 1 ]"
f=$(q hist -StoreQuery History -Filter 'Host=10.0.0.3' -NoHtml)
check "history of 10.0.0.3:22: added, missing, retired, reappeared with the new version" "py '$f' <<'P'
import csv,sys
got=[(r['Change'],r['Field'],r['New']) for r in csv.DictReader(open(sys.argv[1],encoding='utf-8-sig'))]
sys.exit(0 if got==[('Added','',''),('Missing','',''),('Retired','',''),('Reappeared','Products','OpenSSH 9.6p1'),('Reappeared','Banner','SSH-2.0-OpenSSH_9.6p1')] else (print(got) or 1))
P"
f=$(q type -StoreQuery Changes -ChangeType Retired,Missing -Since '2026-10-03' -NoHtml)
check "changes -ChangeType Retired,Missing -Since: run 4 only" "py '$f' <<'P'
import csv,sys
got=sorted((r['RunId'],r['Change'],r['Host']) for r in csv.DictReader(open(sys.argv[1],encoding='utf-8-sig')))
sys.exit(0 if got==[('20261004_100000','Missing','app.corp.local'),('20261004_100000','Retired','10.0.0.3'),('20261004_100000','Retired','10.0.0.8')] else (print(got) or 1))
P"
f=$(q runs -StoreQuery Runs)
check "runs: 5 runs with their counts and profiles" "py '$f' <<'P'
import csv,sys
rows=list(csv.DictReader(open(sys.argv[1],encoding='utf-8-sig')))
c=[(r['Added'],r['Changed'],r['Rekeyed'],r['Missing'],r['Retired'],r['Reappeared'],r['Incomplete']) for r in rows]
ok=c==[('11','0','0','0','0','0','0'),('2','1','3','2','0','0','0'),('0','0','0','0','0','0','1'),('0','1','0','1','2','0','0'),('0','0','0','0','0','2','0')]
sys.exit(0 if ok and 'tls=0' in rows[2]['Profile'] else (print(c) or 1))
P"
f=$(q asof -StoreQuery Inventory -AsOf '2026-10-02T12:00:00Z' -NoHtml)
check "inventory -AsOf after run 2: 13 services, 10.0.0.3 Missing" "py '$f' <<'P'
import csv,sys
rows=list(csv.DictReader(open(sys.argv[1],encoding='utf-8-sig')))
st={r['Host']+':'+r['Port']:r['Status'] for r in rows}
sys.exit(0 if len(rows)==13 and st.get('10.0.0.3:22')=='Missing' and 'web01.corp.local:8443' in st else (print(len(rows),st) or 1))
P"
wi -Store "$W/store" -StoreQuery Inventory -Filter 'Bogus=1' -OutputDir "$W/q"
check "unknown filter field is refused" '[ "$(rc)" = 1 ] && has "unknown field"'
wi -Store "$W/store" -StoreQuery Inventory -ImportRun "$W/out/run5"
check "two store modes at once are refused" '[ "$(rc)" = 1 ] && has "one of"'

# ---- import refusals
wi -Store "$W/store" -ImportRun "$W/out/run5"
check "re-importing a run is a no-op" '[ "$(rc)" = 0 ] && has "already in the store"'
wi -Store "$W/store" -ImportRun "$W/out/old"
check "a run older than the newest is refused" '[ "$(rc)" = 1 ] && has "older than the newest run"'
wi -Store "$W/store" -ImportRun "$W/out/run6"
check "an incomplete run is refused" '[ "$(rc)" = 1 ] && has "did not complete"'
wi -Store "$W/store" -ImportRun "$W/out/run6/WebInventory_20261006_100000_run.json" -Force
check "an incomplete run imports with -Force as partial (nothing it did not check goes missing)" '[ "$(rc)" = 0 ] && has "PARTIAL" && has "missing 0"'
wi -Store "$W/store2" -ImportRun "$W/out/old"
check "old output without run.json: run.json synthesised from the RunId and rows" "[ \"\$(rc)\" = 0 ] && py '$W/store2' <<'P'
import json,sys,glob
j=json.load(open(glob.glob(sys.argv[1]+'/archive/runs/2026/09/20260901_090000/run.json')[0]))
sys.exit(0 if j['synthesized'] and j['profile']['reverseDns'] is False and j['startedAt'].startswith('2026-09-01T09:00:00') else 1)
P"
wi -Store "$W/store" -StoreQuery Inventory -StoreEngine Esent -OutputDir "$W/q"
check "explicit engine different from the store's is refused" '[ "$(rc)" = 1 ]'

# ---- verification, tamper, crash repair, rebuild
wi -Store "$W/store" -VerifyStore
check "VerifyStore passes" '[ "$(rc)" = 0 ] && has "VERIFIED" && has "rebuild: 6 positions"'
G=$(ls "$W"/store/archive/runs/2026/10/20261003_100000/results.jsonl.gz); cp "$G" "$W/g.bak"
python3 -c "import sys;b=bytearray(open(sys.argv[1],'rb').read());b[-12]^=1;open(sys.argv[1],'wb').write(b)" "$G"
wi -Store "$W/store" -VerifyStore
check "an altered archive file fails VerifyStore (exit 2)" '[ "$(rc)" = 2 ] && has "altered"'
wi -Store "$W/store" -StoreQuery Runs -OutputDir "$W/q"
cp "$W/g.bak" "$G"
L=$W/store/archive/ledger.jsonl; cp "$L" "$W/ledger.bak"
python3 - "$L" <<'P'
import sys;p=sys.argv[1];l=open(p).read().splitlines();l[2]=l[2].replace('"rows":10','"rows":11');open(p,'w').write('\n'.join(l)+'\n')
P
wi -Store "$W/store" -VerifyStore
check "an edited ledger line breaks the chain (exit 2)" '[ "$(rc)" = 2 ] && has "prev"'
wi -Store "$W/store" -StoreQuery Runs -OutputDir "$W/q"
check "a store with a broken ledger refuses to open for queries/ingest" '[ "$(rc)" = 1 ] && has "integrity"'
cp "$W/ledger.bak" "$L"
# crash after the database was updated but before the ledger line was written
head -n -1 "$W/ledger.bak" > "$L"
f=$(q pend -StoreQuery Inventory -NoHtml)
check "interrupted ingest (no ledger line) is finished on the next open with the same digests" "has 'finishing run archived by an interrupted ingest' && python3 - '$L' '$W/ledger.bak' <<'P'
import json,sys
a=[json.loads(l) for l in open(sys.argv[1])][-1]; b=[json.loads(l) for l in open(sys.argv[2])][-1]
sys.exit(0 if a['runId']==b['runId'] and a['stateDigest']==b['stateDigest'] and a['changesDigest']==b['changesDigest'] else 1)
P"
# torn final ledger line
head -n -1 "$W/ledger.bak" > "$L"; tail -n 1 "$W/ledger.bak" | head -c 70 >> "$L"
wi -Store "$W/store" -StoreQuery Runs -OutputDir "$W/q"
check "a torn final ledger line is removed and that run finished again" '[ "$(rc)" = 0 ] && has "torn final line" && has "finishing run"'
wi -Store "$W/store" -VerifyStore
check "VerifyStore passes after the repairs" '[ "$(rc)" = 0 ]'
f=$(q before -StoreQuery Inventory -Status All -NoHtml); cp "$f" "$W/inv-before.csv"
rm -rf "$W/store/db"
f=$(q regen -StoreQuery Inventory -Status All -NoHtml)
check "deleted database is rebuilt from the archive; inventory identical" "has 'database is behind the archive' && cmp -s '$f' '$W/inv-before.csv'"
wi -Store "$W/store" -RebuildStore
check "RebuildStore succeeds" '[ "$(rc)" = 0 ] && has "Store rebuilt"'
f=$(q reb -StoreQuery Inventory -Status All -NoHtml)
check "inventory after RebuildStore identical" "cmp -s '$f' '$W/inv-before.csv'"
wi -Store "$W/store" -RebuildStore -StoreEngine Esent
check "RebuildStore -StoreEngine Esent off Windows is refused" '[ "$(rc)" = 1 ] && has "not available"'
wi -Store "$W/nostore" -StoreQuery Runs -OutputDir "$W/q"
check "query of a non-existent store is refused" '[ "$(rc)" = 1 ] && has "no inventory store"'
# lock: another process holding the store makes this one wait
python3 -c "
import fcntl,time,sys
f=open(sys.argv[1],'a');fcntl.flock(f,fcntl.LOCK_EX);time.sleep(4)" "$W/store/LOCK" & sleep 0.5
t0=$(date +%s.%N); wi -Store "$W/store" -StoreQuery Runs -OutputDir "$W/q"; t1=$(date +%s.%N); wait
check "a store held by another process is waited for, then used" "[ \"\$(rc)\" = 0 ] && python3 -c 'import sys;sys.exit(0 if float(sys.argv[2])-float(sys.argv[1])>=3 else 1)' $t0 $t1"
echo "store scenario: $pass passed, $fail failed"
[ $fail = 0 ]
