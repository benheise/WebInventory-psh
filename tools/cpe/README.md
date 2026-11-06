# CPE supplement tools

`src/cpe-supplement.json` is the reviewed table that gives fingerprint rules their NVD CPE names. It is embedded in
`Invoke-WebInventory.ps1` at build time and has three parts:

| Part | Used by | What it does |
|---|---|---|
| `fill` | built-in rules (edited directly), `-ImportRules` | product name (+ kind) -> CPE template, for rule outputs that carry no CPE |
| `replace` | built-in rules, `-ImportRules` | a known-wrong upstream CPE -> the right one (or none), only while the rule still carries exactly the wrong one |
| `aliases` | `-StoreQuery Vulnerabilities` | groups of NVD names for one product (renames, retired names, software vs firmware entries) |

`decisions.py` holds the review: `ACCEPT` and `MANUAL` (mapped), `REJECT` (reviewed, left without a CPE), the
products whose CPE is deliberately not copied from a sibling rule (`SIBLING_SKIP`), `REPLACE` and the reviewed `ALIASES`.

## Refreshing

Work in a scratch folder (`$W`); the NVD files are data, keep them out of the repository.

```bash
# 1. NVD data (CPE dictionary + the CVE feeds and KEV you already use for -StoreQuery Vulnerabilities)
curl -O https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz -O https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.meta
mkdir dict && tar xzf nvdcpe-2.0.tar.gz -C dict
python3 tools/cpe/cpedb.py $W/dict/nvdcpe-2.0-chunks $W/cpe_products.json
python3 tools/cpe/cvecpe.py $W/feeds $W/feeds/known_exploited_vulnerabilities.json $W/cve_vp.json

# 2. Rule packs from upstream (the script applies the current supplement while importing)
pwsh ./dist/Invoke-WebInventory.ps1 -ImportRules <recog>/xml -ImportOutput dist/WebInventory.rules.recog.json
pwsh ./dist/Invoke-WebInventory.ps1 -ImportRules <webappanalyzer> -ImportOutput dist/WebInventory.rules.wappalyzer.json

# 3. Candidates for products not reviewed yet -> $W/review.txt; move each line into ACCEPT or REJECT in decisions.py
python3 tools/cpe/gap.py --work $W --repo . --recog <recog> --wappalyzer <webappanalyzer>

# 4. Regenerate the supplement and the built-in rules, rebuild, re-import the packs (step 2), run -SelfTest
python3 tools/cpe/gen_supplement.py --work $W --repo . --meta $W/nvdcpe-2.0.meta --version $(date +%Y.%m.%d)
python3 build.py
```

## Review rules

A candidate is accepted only when the detected thing is the product NVD names, run by the scanned host:

- a plugin is not its platform (a WordPress plugin never gets `wordpress:wordpress`);
- a third-party service a page embeds (analytics, chat, payment, CDN, maps) gets no CPE;
- generic names (`FTP server`, `HTTP`) and hardware families without a model get none;
- general-purpose operating systems (Windows releases, Linux kernels, distributions) get none: the patch level is not
  visible remotely, so every CVE of the release would be listed;
- a rule whose captured "version" is not the product's version (a protocol or component version) gets none;
- where NVD uses several names, pick the one most CVEs use and put the others in `ALIASES`;
- retired names that encode a version or model are never aliases (their `-` version would match every version).

`gen_supplement.py` fails if any name it writes is not in the NVD dictionary.
