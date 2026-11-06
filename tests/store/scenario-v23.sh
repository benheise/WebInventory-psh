#!/usr/bin/env bash
# v2.3 store features through the command line: manual merge/split, backfill (rebase), snapshot thinning + -AsOf
# replay, ledger signatures, unique query file names. usage: tests/store/scenario-v23.sh <workdir> [script]
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
q()    { local st=$1 name=$2; shift 2; rm -rf "$W/q/$name"; mkdir -p "$W/q/$name"; wi -Store "$W/$st" -OutputDir "$W/q/$name" -NoHtml "$@"; ls "$W/q/$name"/*.csv 2>/dev/null | head -1; }
eid()  { python3 - "$1" "$2" "$3" <<'P'
import csv,sys
for r in csv.DictReader(open(sys.argv[1],encoding='utf-8-sig')):
    if r['Host']==sys.argv[2] and r['Port']==sys.argv[3]: print(r['EntityId'])
P
}
imp()  { local st=$1; shift; for r in "$@"; do wi -Store "$W/$st" -ImportRun "$W/out/run$r" -StoreEngine File; done; }
same() { python3 - "$1" "$2" <<'P'
import csv,sys
a=list(csv.DictReader(open(sys.argv[1],encoding='utf-8-sig'))); b=list(csv.DictReader(open(sys.argv[2],encoding='utf-8-sig')))
sys.exit(0 if a==b and len(a)>0 else 1)
P
}

# ---- manual merge and split
imp A 1 2 3 4 5
f=$(q A inv0 -StoreQuery Inventory -Status All)
X8=$(eid "$f" 10.0.0.8 443); X9=$(eid "$f" 10.0.0.9 443); X10=$(eid "$f" 10.0.0.10 443); K17=$(eid "$f" 10.0.0.17 443)
wi -Store "$W/A" -StoreMerge "$X9,$X10" -Reason "should be refused"
check "merge of two services seen in the same run is refused" '[ "$(rc)" = 1 ] && has "seen in the same run" && ! has "Exception calling"'
wi -Store "$W/A" -StoreMerge "$X8,$X10"
check "a correction without -Reason is refused" '[ "$(rc)" = 1 ] && has "needs -Reason"'
wi -Store "$W/A" -StoreMerge "$X10,$X8" -Reason "10.0.0.8 re-addressed to 10.0.0.10 (CHG-1)"
check "missed pairing merged (ids in any order)" '[ "$(rc)" = 0 ] && has "correction-6 recorded (merge)"'
f=$(q A inv1 -StoreQuery Inventory -Status All)
check "merged service: one entity at 10.0.0.10, first seen in run 1, 2 versions, the earlier id kept" "python3 - '$f' '$X8' <<'P'
import csv,sys
rows=list(csv.DictReader(open(sys.argv[1],encoding='utf-8-sig')))
r=[x for x in rows if x['Host'] in ('10.0.0.8','10.0.0.10')]
sys.exit(0 if len(r)==1 and r[0]['Host']=='10.0.0.10' and r[0]['FirstRun']=='20261001_100000' and r[0]['Versions']=='2' and r[0]['EntityId']==sys.argv[2] and r[0]['Status']=='Active' else 1)
P"
f=$(q A hist1 -StoreQuery History -Filter "EntityId=$X8" -Status All)
check "merged history: added, rekeyed (manual-merge, with reason), merged; the old missing/retired events are gone" "python3 - '$f' <<'P'
import csv,sys
rows=list(csv.DictReader(open(sys.argv[1],encoding='utf-8-sig')))
ch=[r['Change'] for r in rows]; seq=[]
[seq.append(c) for c in ch if not seq or seq[-1]!=c]
ok=seq==['Added','Rekeyed','Merged'] and all(r['Rule']=='manual-merge' and 'CHG-1' in r['Note'] for r in rows if r['Change']=='Rekeyed')
sys.exit(0 if ok else 1)
P"
wi -Store "$W/A" -StoreSplit "$K17" -Reason "new Kibana instance, not a move"
check "automatic pairing split" '[ "$(rc)" = 0 ] && has "correction-7 recorded (split)"'
f=$(q A inv2 -StoreQuery Inventory -Status All)
check "split: 10.0.0.7 back at its address (missing since run 2), 10.0.0.17 a new service first seen in run 2" "python3 - '$f' <<'P'
import csv,sys
rows={(r['Host'],r['Port']):r for r in csv.DictReader(open(sys.argv[1],encoding='utf-8-sig'))}
a=rows.get(('10.0.0.7','443')); b=rows.get(('10.0.0.17','443'))
sys.exit(0 if a and b and a['Status']=='Missing' and a['MissingRuns']=='1' and a['LastRun']=='20261001_100000' and a['MissingSince'].startswith('2026-10-02') and b['FirstRun']=='20261002_100000' and b['Versions']=='1' else 1)
P"
wi -Store "$W/A" -StoreSplit "$K17" -Reason "again"
check "splitting an entity with no pairing left is refused" '[ "$(rc)" = 1 ] && has "no address-move pairing"'
wi -Store "$W/A" -VerifyStore
check "VerifyStore passes with corrections (replayed at their positions)" '[ "$(rc)" = 0 ] && has "2 corrections" && has "7 positions"'
f=$(q A before -StoreQuery Inventory -Status All); cp "$f" "$W/A-before.csv"
wi -Store "$W/A" -RebuildStore
f=$(q A after -StoreQuery Inventory -Status All)
check "RebuildStore re-applies the corrections: inventory identical" "[ \"\$(rc)\" = 0 ] && same '$f' '$W/A-before.csv'"
f=$(q A ch -StoreQuery Changes -ChangeType Merged,Split)
check "Changes -ChangeType Merged,Split lists the corrections with operator reason" "[ \$(python3 -c \"import csv;print(len([r for r in csv.DictReader(open('$f',encoding='utf-8-sig')) if r['Note']]))\") = 3 ]"

# ---- backfill: the result equals importing in order
imp C 1 2 3 4 5
imp B 1 3 4 5
wi -Store "$W/B" -ImportRun "$W/out/run2"
check "older run without -Backfill is refused with a hint" '[ "$(rc)" = 1 ] && has "Backfill"'
wi -Store "$W/B" -ImportRun "$W/out/run2" -Backfill
check "-Backfill inserts the older run (rebase)" '[ "$(rc)" = 0 ] && has "rebase seq"'
fb=$(q B invb -StoreQuery Inventory -Status All); fc=$(q C invc -StoreQuery Inventory -Status All); cp "$fc" "$W/C-inv.csv"
check "backfilled store == store imported in order (inventory)" "same '$fb' '$fc'"
fb=$(q B chb -StoreQuery Changes); fc=$(q C chc -StoreQuery Changes)
check "backfilled store == store imported in order (every change event)" "same '$fb' '$fc'"
wi -Store "$W/B" -VerifyStore
check "VerifyStore replays the original order and the rebase" '[ "$(rc)" = 0 ] && has "1 rebases"'
rm -rf "$W/B/db"; fb=$(q B invb2 -StoreQuery Inventory -Status All)
check "deleted database rebuilt in the rebased order" "same '$fb' '$W/C-inv.csv'"
imp B 5
wi -Store "$W/B" -ImportRun "$W/out/run6" -Force
check "a newer run after a rebase ingests normally" '[ "$(rc)" = 0 ] && has "ingested run 20261006"'
wi -Store "$W/B" -VerifyStore
check "VerifyStore after rebase + new run" '[ "$(rc)" = 0 ]'
# corrections keep their place: D = 1,2,3,merge,5 then backfill 4  ==  E = 1,2,3,merge,4,5
imp D 1 2 3; imp E 1 2 3
for s in D E; do f=$(q $s i$s -StoreQuery Inventory -Status All); a=$(eid "$f" 10.0.0.8 443); b=$(eid "$f" 10.0.0.10 443); wi -Store "$W/$s" -StoreMerge "$a,$b" -Reason "cluster re-addressed"; done
imp D 5; imp E 4 5
wi -Store "$W/D" -ImportRun "$W/out/run4" -Backfill
fd=$(q D invd -StoreQuery Inventory -Status All); fe=$(q E inve -StoreQuery Inventory -Status All)
check "backfill keeps a correction right after the run it followed (inventory equals the in-order store)" "same '$fd' '$fe'"
wi -Store "$W/D" -VerifyStore
check "VerifyStore with correction + rebase" '[ "$(rc)" = 0 ]'

# a correction whose services change identity in the new order becomes void (recorded, no effect)
imp V 1 3 4 5
f=$(q V iv -StoreQuery Inventory -Status All); a=$(eid "$f" 10.0.0.8 443); b=$(eid "$f" 10.0.0.10 443)
wi -Store "$W/V" -StoreMerge "$a,$b" -Reason "merge that a backfill will void"
wi -Store "$W/V" -ImportRun "$W/out/run2" -Backfill
check "backfill that changes the merged services' identity records the correction as void" "[ \"\$(rc)\" = 0 ] && tail -n 1 '$W/V/archive/ledger.jsonl' | grep -q '\"void\":\"entity '"
fv=$(q V invv -StoreQuery Inventory -Status All)
check "... and the inventory equals the in-order store without the correction" "same '$fv' '$W/C-inv.csv'"
wi -Store "$W/V" -VerifyStore
check "VerifyStore with a void correction" '[ "$(rc)" = 0 ]'

# ---- snapshot thinning and -AsOf replay
wi -Store "$W/F" -SnapshotEvery 2 -StoreEngine File
check "store options recorded without a scan" '[ "$(rc)" = 0 ] && has "snapshot every 2"'
imp F 1 2 3 4 5
check "snapshots kept for runs 1, 3, 5 only" "[ -f $W/F/archive/runs/2026/10/20261001_100000/state.jsonl.gz ] && [ ! -f $W/F/archive/runs/2026/10/20261002_100000/state.jsonl.gz ] && [ -f $W/F/archive/runs/2026/10/20261003_100000/state.jsonl.gz ] && [ ! -f $W/F/archive/runs/2026/10/20261004_100000/state.jsonl.gz ]"
ff=$(q F asoff -StoreQuery Inventory -AsOf '2026-10-02 12:00:00Z' -Status All); cp "$W/last.out" "$W/asof-f.out"
fc=$(q C asofc -StoreQuery Inventory -AsOf '2026-10-02 12:00:00Z' -Status All)
check "-AsOf a run without a snapshot: replayed, identical to the snapshot of a full store" "grep -q 'replayed in memory' '$W/asof-f.out' && same '$ff' '$fc'"
wi -Store "$W/F" -VerifyStore
check "VerifyStore with thinned snapshots" '[ "$(rc)" = 0 ]'

# ---- ledger signatures (detached CMS)
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/k.pem" -out "$W/c.pem" -days 30 -subj "/CN=WebInventory ledger test" >/dev/null 2>&1
openssl pkcs12 -export -inkey "$W/k.pem" -in "$W/c.pem" -out "$W/c.pfx" -passout pass:x >/dev/null 2>&1
TP=$(pwsh -NoProfile -Command "\$c=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new('$W/c.pfx','x',[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet); \$s=[System.Security.Cryptography.X509Certificates.X509Store]::new('My','CurrentUser'); \$s.Open('ReadWrite'); \$s.Add(\$c); \$s.Close(); \$c.Thumbprint")
imp G 1
wi -Store "$W/G" -AnchorCertificate "$TP"
check "signing certificate recorded" '[ "$(rc)" = 0 ] && has "ledger signing $TP"'
imp G 2 3
check "new ledger entries are signed" "[ -f $W/G/archive/anchors/000002.p7s ] && [ -f $W/G/archive/anchors/000003.p7s ] && [ ! -f $W/G/archive/anchors/000001.p7s ]"
wi -Store "$W/G" -VerifyStore
check "VerifyStore checks the signatures" '[ "$(rc)" = 0 ] && has "2 ledger entries match their detached signatures"'
cp "$W/G/archive/anchors/000003.p7s" "$W/p7s.bak"; cp "$W/G/archive/anchors/000002.p7s" "$W/G/archive/anchors/000003.p7s"
wi -Store "$W/G" -VerifyStore
check "a signature that does not match its ledger line fails VerifyStore" '[ "$(rc)" = 2 ] && has "does not match its signature"'
rm "$W/G/archive/anchors/000003.p7s"
wi -Store "$W/G" -VerifyStore
check "a missing signature since signing began fails VerifyStore" '[ "$(rc)" = 2 ] && has "have no signature"'
cp "$W/p7s.bak" "$W/G/archive/anchors/000003.p7s"
pwsh -NoProfile -Command "\$s=[System.Security.Cryptography.X509Certificates.X509Store]::new('My','CurrentUser'); \$s.Open('ReadWrite'); foreach(\$c in @(\$s.Certificates)){ if(\$c.Thumbprint -eq '$TP'){ \$s.Remove(\$c) } }; \$s.Close()"

# ---- unique query file names
mkdir -p "$W/q/u"; wi -Store "$W/C" -StoreQuery Runs -OutputDir "$W/q/u"; wi -Store "$W/C" -StoreQuery Runs -OutputDir "$W/q/u"; wi -Store "$W/C" -StoreQuery Runs -OutputDir "$W/q/u"
check "same query three times: three files, none overwritten" "[ \$(ls $W/q/u/*.csv | wc -l) = 3 ]"
echo "store v2.3 scenario: $pass passed, $fail failed"
[ $fail = 0 ]
