#!/usr/bin/env bash
# Refresh the external lists WebInventory is built from (rule packs, NVD names, version-candidate index, coverage
# table), rebuild, run the offline tests and write a summary for review. Used by .github/workflows/refresh-lists.yml
# and runnable by hand. See tools/refresh/README.md.
#
# usage: tools/refresh/refresh.sh [--work DIR] [--feeds DIR] [--cpedict DIR] [--sources DIR] [--force]
#   --work DIR     scratch folder (default: $RUNNER_TEMP/wi-refresh or /tmp/wi-refresh); nothing is written to the
#                  repository except the refreshed files
#   --feeds DIR    use these NVD CVE 2.0 feeds (nvdcve-2.0-YYYY.json.gz) and known_exploited_vulnerabilities.json
#                  instead of downloading them
#   --cpedict DIR  use this NVD CPE Dictionary 2.0 (nvdcpe-2.0.tar.gz + nvdcpe-2.0.meta) instead of downloading it
#   --sources DIR  use the checkouts in DIR (recog, webappanalyzer, nuclei-templates, WhatWeb) instead of cloning
#   --force        re-import the rule packs even when their upstream commit did not change
# exit: 0 nothing changed; 10 files changed and every check passed; 11 files changed but a check failed (see the
#       summary); anything else: the refresh itself failed
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${RUNNER_TEMP:-/tmp}/wi-refresh
FEEDS=""; CPEDICT=""; SOURCES=""; FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --work) WORK=$2; shift 2 ;;
    --feeds) FEEDS=$2; shift 2 ;;
    --cpedict) CPEDICT=$2; shift 2 ;;
    --sources) SOURCES=$2; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$WORK"/{src,before,logs}
WORK=$(cd "$WORK" && pwd)
FAIL=()
note() { echo "[refresh] $*"; }
failed() { FAIL+=("$1"); echo "[refresh] CHECK FAILED: $1" >&2; }
fetch() {   # url file: download with retries (NVD and CISA throttle bursts)
  curl -fsSL --retry 6 --retry-delay 20 --retry-all-errors -A 'WebInventory-list-refresh (+https://github.com/benheise/WebInventory-psh)' -o "$2.part" "$1"
  mv "$2.part" "$2"
}
cd "$REPO"
SCRIPT_VERSION=$(sed -n "s/^\$ScriptVersion = '\(.*\)'.*/\1/p" src/10-header.ps1)
cp dist/WebInventory.rules.recog.json dist/WebInventory.rules.wappalyzer.json src/cpe-supplement.json \
   src/builtin-rules.json src/version-rules.json tools/version/external.json "$WORK/before/"

# ---- 1. upstream sources --------------------------------------------------------------------------------------------
declare -A URL=([recog]=https://github.com/rapid7/recog [webappanalyzer]=https://github.com/enthec/webappanalyzer
                [nuclei-templates]=https://github.com/projectdiscovery/nuclei-templates [WhatWeb]=https://github.com/urbanadventurer/WhatWeb)
declare -A SRC
for n in recog webappanalyzer nuclei-templates WhatWeb; do
  if [ -n "$SOURCES" ] && [ -d "$SOURCES/$n/.git" ]; then SRC[$n]=$SOURCES/$n
  else
    SRC[$n]=$WORK/src/$n
    if [ -d "${SRC[$n]}/.git" ]; then git -C "${SRC[$n]}" fetch -q --depth 1 origin HEAD && git -C "${SRC[$n]}" reset -q --hard FETCH_HEAD
    else git clone -q --depth 1 "${URL[$n]}" "${SRC[$n]}"; fi
  fi
  note "$n $(git -C "${SRC[$n]}" rev-parse HEAD)"
done
pack_commit() { python3 -c "import json,re,sys; s=json.load(open(sys.argv[1],encoding='utf-8-sig'))['source']; m=re.search(r'commit ([0-9a-f]{40})',s); print(m.group(1) if m else '')" "$1"; }
OLD_RECOG=$(pack_commit dist/WebInventory.rules.recog.json); NEW_RECOG=$(git -C "${SRC[recog]}" rev-parse HEAD)
OLD_WAPP=$(pack_commit dist/WebInventory.rules.wappalyzer.json); NEW_WAPP=$(git -C "${SRC[webappanalyzer]}" rev-parse HEAD)

# ---- 2. NVD and CISA data -------------------------------------------------------------------------------------------
if [ -z "$FEEDS" ]; then
  FEEDS=$WORK/feeds; mkdir -p "$FEEDS"
  for y in $(seq 2002 "$(date -u +%Y)"); do fetch "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.json.gz" "$FEEDS/nvdcve-2.0-$y.json.gz"; sleep 2; done
  fetch https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz "$FEEDS/nvdcve-2.0-modified.json.gz"
  fetch https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json "$FEEDS/known_exploited_vulnerabilities.json"
fi
if [ -z "$CPEDICT" ]; then
  CPEDICT=$WORK/cpedict; mkdir -p "$CPEDICT"
  fetch https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.meta "$CPEDICT/nvdcpe-2.0.meta"
  fetch https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz "$CPEDICT/nvdcpe-2.0.tar.gz"
fi
CHUNKS=$(find "$CPEDICT" -type d -name 'nvdcpe-2.0-chunks' | head -1)
if [ -z "$CHUNKS" ]; then mkdir -p "$WORK/dict"; tar xzf "$CPEDICT/nvdcpe-2.0.tar.gz" -C "$WORK/dict"; CHUNKS=$(find "$WORK/dict" -type d -name 'nvdcpe-2.0-chunks' | head -1); fi
python3 tools/cpe/cpedb.py "$CHUNKS" "$WORK/cpe_products.json"
python3 tools/cpe/cvecpe.py "$FEEDS" "$FEEDS/known_exploited_vulnerabilities.json" "$WORK/cve_vp.json"
python3 tools/version/coverage.py --repo . --cve "$WORK/cve_vp.json" > "$WORK/coverage.before.txt"

# ---- 3. CPE supplement: every reviewed name must still be in the dictionary; retired names follow their successor ----
if python3 tools/cpe/gen_supplement.py --work "$WORK" --repo . --meta "$CPEDICT/nvdcpe-2.0.meta" --version "$(date -u +%Y.%m.%d)" > "$WORK/logs/supplement.txt" 2>&1; then
  if python3 - "$WORK/before/cpe-supplement.json" src/cpe-supplement.json <<'PY'
import json, sys
a, b = (json.load(open(p, encoding='utf-8')) for p in sys.argv[1:3])
strip = lambda d: {k: v for k, v in d.items() if k not in ('version', 'source')}
sys.exit(0 if strip(a) == strip(b) else 1)
PY
  then cp "$WORK/before/cpe-supplement.json" src/cpe-supplement.json; cp "$WORK/before/builtin-rules.json" src/builtin-rules.json; SUP_CHANGED=0
  else SUP_CHANGED=1; fi
else
  failed "cpe-supplement: a reviewed name is no longer in the NVD dictionary (logs/supplement.txt)"
  cp "$WORK/before/cpe-supplement.json" src/cpe-supplement.json; cp "$WORK/before/builtin-rules.json" src/builtin-rules.json; SUP_CHANGED=0
fi
python3 build.py > "$WORK/logs/build.txt"

# ---- 4. rule packs from upstream (the script applies the embedded supplement while importing) -------------------------
import_pack() {   # name source-path
  (cd "$WORK/logs" && pwsh -NoProfile -File "$REPO/dist/Invoke-WebInventory.ps1" -ImportRules "$2" -ImportOutput "$REPO/dist/WebInventory.rules.$1.json") > "$WORK/logs/import-$1.txt" 2>&1 \
    || failed "import of $1 failed (logs/import-$1.txt)"
}
if [ "$FORCE" = 1 ] || [ "$SUP_CHANGED" = 1 ] || [ "$OLD_RECOG" != "$NEW_RECOG" ]; then import_pack recog "${SRC[recog]}/xml"; fi
if [ "$FORCE" = 1 ] || [ "$SUP_CHANGED" = 1 ] || [ "$OLD_WAPP" != "$NEW_WAPP" ]; then import_pack wappalyzer "${SRC[webappanalyzer]}"; fi

# ---- 5. version-only rules must still join a detection rule; candidates for products without a CPE -------------------
python3 tools/version/gen_rules.py --repo . --version "$SCRIPT_VERSION" > "$WORK/logs/version-rules.txt" 2>&1 \
  || { failed "version-only rules no longer join a detection rule (logs/version-rules.txt)"; cp "$WORK/before/version-rules.json" src/version-rules.json; }
python3 tools/cpe/gap.py --work "$WORK" --repo . --recog "${SRC[recog]}" --wappalyzer "${SRC[webappanalyzer]}" > "$WORK/logs/gap.txt" 2>&1 \
  || failed "CPE candidate search failed (logs/gap.txt)"
python3 build.py > "$WORK/logs/build.txt"

# ---- 6. version-candidate index and the coverage table ------------------------------------------------------------
python3 tools/version/external.py --repo . --whatweb "${SRC[WhatWeb]}" --nuclei "${SRC[nuclei-templates]}" \
  --webappanalyzer "${SRC[webappanalyzer]}" --recog "${SRC[recog]}" > "$WORK/logs/external.txt" 2>&1 \
  || { failed "version-candidate index failed (logs/external.txt)"; cp "$WORK/before/external.json" tools/version/external.json; }
python3 tools/version/coverage.py --repo . --cve "$WORK/cve_vp.json" --doc docs/web-inventory-coverage.md --version "$SCRIPT_VERSION" > "$WORK/coverage.after.txt"
# NVD adds CVEs every day: a coverage table whose only change is a CVE count is not worth a pull request on its own
if [ -z "$(git status --porcelain -- . ':!docs/web-inventory-coverage.md')" ]; then git checkout -q -- docs/web-inventory-coverage.md; fi

# ---- 7. offline tests (Linux PowerShell 7; the workflow repeats -SelfTest on Windows PowerShell 5.1) -----------------
(cd "$WORK/logs" && pwsh -NoProfile -File "$REPO/dist/Invoke-WebInventory.ps1" -SelfTest) > "$WORK/logs/selftest.txt" 2>&1 || failed "-SelfTest (logs/selftest.txt)"
(cd "$WORK/logs" && pwsh -NoProfile -File "$REPO/dist/Invoke-WebInventory.ps1" -TestRules) > "$WORK/logs/testrules.txt" 2>&1 || failed "-TestRules (logs/testrules.txt)"
python3 tools/refresh/sha256sums.py dist

# ---- 8. summary ---------------------------------------------------------------------------------------------------
printf '%s\n' "${FAIL[@]:-}" | sed '/^$/d' > "$WORK/failures.txt"
python3 tools/refresh/summary.py --repo . --work "$WORK" \
  --recog "$OLD_RECOG" "$NEW_RECOG" --wappalyzer "$OLD_WAPP" "$NEW_WAPP" --supplement-changed "$SUP_CHANGED" > "$WORK/summary.md"
note "summary: $WORK/summary.md"
if git diff --quiet && [ -z "$(git status --porcelain)" ]; then note 'nothing changed'; exit 0; fi
[ "${#FAIL[@]}" -eq 0 ] && exit 10 || exit 11
