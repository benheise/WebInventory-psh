# WebInventory v2.5.0: hosting attribution, CNAME capture, screenshot checks, exit code 4

This is the decision record for v2.5.0. It implements the four recommendations from the run-recon comparison
(`web-inventory-v2.4.0-run-recon.md`) and two open items: RDP certificates past Schannel, and the Forgejo and
Cloudflare detection issues.

The constraints are unchanged:
- stock Windows PowerShell 5.1 with .NET Framework 4.7.2 (also PowerShell 7);
- no installs;
- inventory only;
- no loss of accuracy;
- a standalone tool.

## 1. Cloud and CDN attribution from published IP ranges

**Decision.** `dist/WebInventory.cloud.json` holds the ranges that providers publish for their customers' firewalls.
`tools/cloud/build.py` takes them from each provider's own machine-readable list:
- AWS `ip-ranges.json`;
- Azure Service Tags for the public cloud, Azure Government and Azure China (the weekly file URL is read from the
  Download Center page);
- Google Cloud `cloud.json` and Google `goog.json`;
- Oracle Cloud `public_ip_ranges.json`;
- the DigitalOcean and Akamai (Linode) RFC 8805 geofeeds;
- Cloudflare `ips-v4`/`ips-v6` and Fastly `public-ip-list`.

The first build has 92,358 prefixes: Azure 65,140, AWS 11,471, Akamai (Linode) 5,505, Azure Government 3,945, Azure
China 2,601, DigitalOcean 1,238, Google Cloud 1,153, Oracle Cloud 1,118, Google 141, Fastly 24, Cloudflare 22. The
file is 3.2 MB.

The engine (`WebInv.Cloud`) looks up the longest prefix for each service's IP. It handles IPv4, IPv6 and
IPv4-mapped addresses, with one hash table per prefix length in use. The answer fills `Cloud`, `CloudRegion` and
`CloudService`.

How the ranges are merged:
- One entry per prefix.
- When several services of one provider list the same prefix, their names are joined. AWS's umbrella `AMAZON` is
  dropped wherever a specific service is listed.
- When two providers list the same prefix, the provider order decides; Google Cloud ranges also appear in Google's
  list.
- A global Azure service tag gets the region of the `AzureCloud.<region>` range that contains it.

**Cost.** Loading takes about 0.27 s. The file is loaded only when the first service on a public address answers.
No published range overlaps private, loopback, link-local, CGNAT, multicast or reserved space; this was checked over
the whole file. So an internal scan never loads it.

**Accuracy check.** A Python longest-prefix match over the same file (`tests/cloud/oracle.py`) is compared with the
engine on random addresses inside ranges, on every range edge and its neighbours, and on random addresses anywhere:
- PowerShell 7 here: 80,000 addresses, 0 mismatches.
- CI on Windows PowerShell 5.1 and on PowerShell 7: 40,000 addresses each, 0 mismatches.

**Refresh.** The weekly list refresh runs `build.py`. The previous file is kept when the ranges did not change. A
provider whose list shrinks by more than 20 % fails the check and keeps the previous ranges (truncated downloads,
format changes). The run log warns when the file is more than 45 days old.

**Store.** The three columns are material and gated by the `cloud` profile flag:
- the first run with the ranges records `Enriched`, not `Changed`;
- a run with `-NoCloud` keeps the previous values;
- a real move, for example to another service, records `Changed`.

These cases are tested in `tests/v25/gating.sh`.

**Rejected:**
- Third-party aggregated lists: there is no provenance per provider.
- RDAP/whois per IP: that is network traffic and is rate-limited.
- Geolocation databases: they need a licence, and inventory needs the operator, not the country.

**Not covered:** Akamai's CDN, IBM Cloud, Alibaba Cloud, Hetzner and OVH, because there is no official
machine-readable list. A service behind a CDN shows the CDN.

## 2. `-Cname`: CNAME chains of hostname targets

**Decision.** This is opt-in, like `-ReverseDns`. Every target given as a name gets one A query to this host's
resolvers, and the answer's CNAME records become the `Cname` column (`a.example.net;b.example.net`, in chain order).
- On Windows the query goes through `DnsQuery_W`, the system DNS client: the same servers, suffix search, cache and
  name resolution policy table as everything else on the host.
- Elsewhere, or with `-DnsServer ip[:port]`, it is a standard DNS query over UDP. The parser handles name compression
  and refuses pointer loops.
- A name that is not in DNS (hosts file, NetBIOS) has no CNAME. A resolver that does not answer is a `CNAME` error.
- SAN virtual hosts and IP targets are not looked up.
- Gated in the store like the cloud columns.

**Checks:**
- The self-test runs a loopback DNS responder: a chain with compression, no CNAME, a name not in DNS, no answer.
- CI compares the chains of five public names, which change daily, with `Resolve-DnsName` (Windows) and `dig`
  (Linux) through the same resolver cache: 5 of 5 on both.
- A lab scan with `-DnsServer` against a responder gave each row the expected chain.

## 3. Screenshot checks

**Decision.** run-recon labels each capture ok, blank, failed or suspect. WebInventory now does the same and adds a
pixel test. After the capture the browser reports `location.href`, the HTTP status of the main document
(`Network.responseReceived` of the main frame), the title and the length of the visible text (`innerText`). The PNG
is decoded (`WebInv.Png`: 8-bit grey, RGB or RGBA, all five filter types, no System.Drawing) to measure the dominant
colour.

`WebInv.ShotCheck` applies these rules, in order:
1. **failed**: no image. Also when the main document came from an origin outside the scan (the image shows the scope
   proxy's refusal), or when the browser showed its own error page.
2. **suspect**: the browser got an error status while the scan saw success.
3. **blank**: the page is empty (0-byte body), or at least 99.5 % of the image is one colour and the page shows no
   text. The reason lists the origins the page asked for that were refused; a single-page app that loads its code
   from a CDN renders blank behind the scope proxy.
4. **suspect**: the browser's title is not the scan's title, and neither contains the other.
5. **suspect**: the same image stands for services the scan saw with different titles.
6. **ok**: everything else, with a note when the image was taken before the load event.

Why text decides blank: a minimal page ("It works", one line of text) covers well under 0.5 % of a 1366×768 image.
Pixels alone would call it blank.

**Lab check** (`lab/shotcases.py`, real headless Chromium):

| Case | Result |
|---|---|
| Normal page | ok |
| Empty body | blank (0-byte body) |
| White app shell whose code comes from a CDN | blank, with the refused origin |
| Redirect to another host | failed, naming both refused origins |
| 503 to the headless browser, 200 to the scanner | suspect (status) |
| Two identical pages under two titles | suspect, both |
| Script renames the page to "Proxy Error" | suspect (title) |

## 4. Exit code 4: nothing answered

**Decision.** A completed run in which no service answered exits 4. That covers every port closed or filtered, every
name unresolved, and the network being down. Before, such a run exited 0.
- Exit 4 takes precedence over 2, logged errors: an outage usually logs errors too, and "nothing answered" is what
  the scheduler must see.
- A resumed run counts the rows of its earlier sessions.
- The store still ingests such a run; its services are recorded as missing, as before. Changing that would hide a
  real decommissioning.

Checked by new regression scenarios: a closed port only (exit 4, logged), unresolved names only (exit 4), and one
open port among closed ones (exit 0). Two more check that `-DnsServer` without `-Cname` and a missing `-CloudFile`
are refused.

## 5. RDP certificates past Schannel

**Decision.** When Schannel cannot handshake with an RDP server that selected TLS (for example a TLS 1.0-only server
on a hardened scanner host), the probe opens a fresh connection, repeats the X.224 negotiation and sends the scan
engine's raw ClientHello. This is `Tls.HelloOn`, the HTTPS probe's code now usable on an existing stream; the
extras bind it by reflection.
- The certificate fills every certificate column and flag, with `CertSource` `rdp-raw` and a note in
  `ProtocolInfo`.
- There is no chain check. The NTLM names need the full handshake and stay empty.

**Check.** `tests/v25/rdp-raw.sh`: a TLS 1.0-only fake RDP server, which the PowerShell 7/OpenSSL client refuses,
gives its certificate, TLS 1.0 and `WeakTLS:TLS1.0`. An NLA server still takes the Schannel path with its NTLM build.

## 6. Detection fixes

- **Forgejo is no longer also Gitea.** Forgejo 9 pages still carry Gitea markers, such as `i_like_gitea` and a
  `gitea` emoji in the page script, so the Recog, built-in and Wappalyzer Gitea rules fired. Two built-in Forgejo
  rules now exclude Gitea: the default `keywords` meta tag (`git,forge,forgejo`) and `<html data-theme="forgejo-…">`.
  Replayed against the container recordings:
  - Forgejo 9.0.3 and 17.0.1: Forgejo only.
  - Gitea 1.22.3 and 1.27.3: unchanged.
- **Cloudflare CPE.** NVD's `cloudflare:cloudflare` is "Cloudflare for WordPress". It was attached to the CDN
  detection, so every site behind Cloudflare matched that plugin's CVEs. The CPE supplement (2026.11.06.2) now
  clears it. The Wappalyzer pack was re-imported from the same upstream commit (d91f7e5); exactly the five Cloudflare
  rules changed.

## Behaviour changes

- **New columns (83 in all):** `Cname`, `Cloud`, `CloudRegion`, `CloudService`. Rows on public addresses in
  published ranges get the three cloud columns by default.
- **Exit code 4** for runs where nothing answered.
- **Screenshot index:** new columns `Reason`, `BrowserUrl`, `BrowserStatus`, `Capture`. `Status` is now
  ok/blank/suspect/failed; `ok-timeout` is an ok with a reason.
- **RDP rows** of TLS 1.0-only servers gain certificate data.
- **Forgejo services** lose the Gitea detection; Cloudflare-fronted services lose the plugin CPE.
