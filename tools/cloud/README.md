# Cloud / CDN IP ranges

`build.py` builds `dist/WebInventory.cloud.json` from the IP-range lists that cloud and CDN providers publish for
their customers' firewalls. The scanner matches each service's IP against it offline (longest prefix wins), so the
`Cloud`, `CloudRegion` and `CloudService` columns show which provider, region and service publish that address.
Nothing is sent to the providers or the targets while scanning.

```bash
python3 tools/cloud/build.py                                  # download every list, write dist/WebInventory.cloud.json
python3 tools/cloud/build.py --cache /tmp/cloud --offline     # rebuild from lists downloaded before
python3 tests/cloud/oracle.py --n 20000                       # cross-check the scanner's lookup against Python
```

The weekly list refresh (`tools/refresh`, `.github/workflows/refresh-lists.yml`) runs `build.py`. It keeps the
previous file when the ranges did not change. When a provider's list shrinks by more than a fifth (a truncated
download, a format change), the check fails.

| Provider (`Cloud`) | Source | `CloudRegion` | `CloudService` |
|---|---|---|---|
| AWS | `ip-ranges.amazonaws.com/ip-ranges.json` | region (`us-east-1`, `us-gov-west-1`, `GLOBAL`) | the most specific service listed (`EC2`, `S3`, `CLOUDFRONT`, ...); `AMAZON` only where no other is listed |
| Azure, Azure Government, Azure China | Service Tags (Download Center ids 56519, 57063, 57062; the file URL changes weekly and is read from the download page) | region of the tag, or of the `AzureCloud.<region>` range that contains a global tag's prefix | the tag without its region (`AppService`, `Storage`, `AzureFrontDoor.Frontend`) |
| Google Cloud | `gstatic.com/ipranges/cloud.json` | scope (`us-central1`) | |
| Google | `gstatic.com/ipranges/goog.json` (Google-owned ranges outside Google Cloud) | | |
| Oracle Cloud | `docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json` | region | tags (`OCI`, `OSN`, `OBJECT_STORAGE`) |
| DigitalOcean, Akamai (Linode) | RFC 8805 geofeeds (`digitalocean.com/geo/google.csv`, `geoip.linode.com`) | city, country | |
| Cloudflare, Fastly | `cloudflare.com/ips-v4`, `ips-v6`; `api.fastly.com/public-ip-list` | | `CDN` |

How entries are merged:

- **One entry per prefix.** When several services of one provider list the same prefix, the services are joined.
  When two providers list the same prefix, the order in `PRIORITY` decides; Google Cloud's ranges are also in
  Google's list.
- **The most specific prefix wins at lookup time.** An Azure service tag's /27 inside an `AzureCloud.eastus` /16
  gives that service with region `eastus`.
- **Not included:** providers without an official machine-readable list (Akamai's CDN, IBM Cloud, Alibaba, Hetzner,
  OVH), and SaaS front ends such as Microsoft 365.

A service behind a CDN shows the CDN (the address the scanner reached), not the origin. `-Cname` records the name
chain, which usually names the CDN or the load balancer as well.
