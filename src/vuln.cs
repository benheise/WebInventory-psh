
// ============================================================================
// WebInv store: offline vulnerability correlation (-StoreQuery Vulnerabilities)
// The current inventory's CPEs joined with NVD CVE JSON 2.0 feeds (version-aware), CISA KEV and FIRST EPSS - all
// read from files the operator downloaded; nothing is fetched and nothing is sent to a target.
// ============================================================================
namespace WebInv
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.IO.Compression;
    using System.Text;
    using System.Text.RegularExpressions;

    // CPE 2.3 formatted string, split on unescaped ':'
    public sealed class Cpe
    {
        public string Part = "", Vendor = "", Product = "", Version = "*", Update = "*", Raw = "";
        // set on the copies made for alias names: the service's own CPE, and the NVD name the copy stands for
        public Cpe Origin; public string Alias = "";
        public string Key { get { return Part + ":" + Vendor + ":" + Product; } }
        public Cpe Root { get { return Origin ?? this; } }
        public static Cpe Parse(string s)
        {
            if (string.IsNullOrEmpty(s)) return null;
            s = s.Trim();
            List<string> f = new List<string>();
            if (s.StartsWith("cpe:2.3:", StringComparison.OrdinalIgnoreCase))
            {
                StringBuilder cur = new StringBuilder();
                for (int i = 8; i < s.Length; i++)
                {
                    char c = s[i];
                    if (c == '\\' && i + 1 < s.Length) { cur.Append(s[i + 1]); i++; continue; }
                    if (c == ':') { f.Add(cur.ToString()); cur.Length = 0; continue; }
                    cur.Append(c);
                }
                f.Add(cur.ToString());
            }
            else if (s.StartsWith("cpe:/", StringComparison.OrdinalIgnoreCase)) f.AddRange(s.Substring(5).Split(':'));
            else return null;
            if (f.Count < 3) return null;
            // percent-encoding belongs to the cpe:/ URI form, but some rule data writes it into formatted strings
            // (treck:tcp%2fip, ibm:z%2fos): decode it so the name compares equal to NVD's tcp\/ip
            for (int i = 0; i < f.Count; i++) if (f[i].IndexOf('%') >= 0) f[i] = Uri.UnescapeDataString(f[i]);
            Cpe c2 = new Cpe();
            c2.Raw = s;
            c2.Part = f[0].ToLowerInvariant(); c2.Vendor = f[1].ToLowerInvariant(); c2.Product = f[2].ToLowerInvariant();
            c2.Version = f.Count > 3 && f[3].Length > 0 ? f[3] : "*";
            c2.Update = f.Count > 4 && f[4].Length > 0 ? f[4] : "*";
            return c2;
        }
        public Cpe As(string key)
        {
            string[] k = key.Split(new[] { ':' }, 3);
            Cpe c = new Cpe();
            c.Part = k[0]; c.Vendor = k[1]; c.Product = k[2]; c.Version = Version; c.Update = Update; c.Raw = Raw;
            c.Origin = Root; c.Alias = key;
            return c;
        }
        public static bool Any(string v) { return v == "*" || v == "-" || v.Length == 0; }
        public bool VersionKnown { get { return !Any(Version); } }
        public string Full { get { return Version + (Any(Update) ? "" : Update); } }
    }

    public static class VersionCmp
    {
        static readonly HashSet<string> Pre = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "alpha", "a", "beta", "b", "rc", "pre", "preview", "dev", "m", "snapshot", "cr", "c", "ea" };
        static List<string> Tokens(string v)
        {
            List<string> t = new List<string>();
            StringBuilder cur = new StringBuilder(); int kind = 0;   // 1 digit, 2 letter
            foreach (char ch in v ?? "")
            {
                int k = char.IsDigit(ch) ? 1 : (char.IsLetter(ch) ? 2 : 0);
                if (k != kind && cur.Length > 0) { t.Add(cur.ToString()); cur.Length = 0; }
                kind = k;
                if (k != 0) cur.Append(ch);
            }
            if (cur.Length > 0) t.Add(cur.ToString());
            return t;
        }
        static bool IsNum(string s) { return s.Length > 0 && char.IsDigit(s[0]); }
        static int CmpNum(string a, string b)
        {
            a = a.TrimStart('0'); b = b.TrimStart('0');
            if (a.Length != b.Length) return a.Length.CompareTo(b.Length);
            return string.CompareOrdinal(a, b);
        }
        // numeric runs compare as numbers; a trailing pre-release word (rc, beta...) sorts before the release, other
        // trailing words (p1, k, a vendor letter) after it
        public static int Compare(string x, string y)
        {
            List<string> a = Tokens(x), b = Tokens(y);
            int n = Math.Min(a.Count, b.Count);
            for (int i = 0; i < n; i++)
            {
                bool na = IsNum(a[i]), nb = IsNum(b[i]);
                int c;
                if (na && nb) c = CmpNum(a[i], b[i]);
                else if (!na && !nb) c = string.Compare(a[i], b[i], StringComparison.OrdinalIgnoreCase);
                else c = na ? 1 : -1;
                if (c != 0) return c < 0 ? -1 : 1;
            }
            if (a.Count == b.Count) return 0;
            List<string> longer = a.Count > b.Count ? a : b;
            bool zeros = true;                       // 2.4 == 2.4.0
            for (int i = n; i < longer.Count; i++) if (!IsNum(longer[i]) || longer[i].TrimStart('0').Length > 0) { zeros = false; break; }
            if (zeros) return 0;
            string next = longer[n];
            int sign = (!IsNum(next) && Pre.Contains(next)) ? -1 : 1;
            return a.Count > b.Count ? sign : -sign;
        }
    }

    public sealed class VulnResult
    {
        public string[] Columns;
        public readonly List<string[]> Rows = new List<string[]>();
        public string Provenance = "";
        public readonly List<string> Messages = new List<string>();
    }

    public static class Vulns
    {
        public static readonly string[] Columns = { "Host", "IP", "Port", "Url", "Status", "Products", "Cpe", "Cve", "Kev", "KevDateAdded", "KevDueDate", "KevRansomware",
            "Epss", "EpssPercentile", "CvssScore", "CvssSeverity", "CvssVersion", "Published", "Match", "EntityId", "Description" };

        public sealed class Service
        {
            public string Host, Ip, Port, Url, Status, Products, EntityId;
            public List<Cpe> Cpes = new List<Cpe>();
        }
        sealed class Hit { public Service Svc; public Cpe Cpe; public string Match; }
        sealed class CveInfo
        {
            public string Id, LastModified, Published, Score = "", Severity = "", CvssVersion = "", Description = "";
            public List<Hit> Hits = new List<Hit>();
        }

        // ---------------------------------------------------------------- streaming the NVD feed
        // yields the raw text of every element of the top-level "vulnerabilities" array
        public static IEnumerable<string> FeedRecords(TextReader r)
        {
            int depth = 0; bool inStr = false, esc = false, inArray = false;
            StringBuilder key = new StringBuilder(), rec = null; string lastKey = null; bool readingKey = false;
            int c;
            while ((c = r.Read()) >= 0)
            {
                char ch = (char)c;
                if (rec != null) rec.Append(ch);
                if (inStr)
                {
                    if (esc) esc = false;
                    else if (ch == '\\') esc = true;
                    else if (ch == '"') { inStr = false; if (readingKey) { lastKey = key.ToString(); readingKey = false; } }
                    else if (readingKey) key.Append(ch);
                    continue;
                }
                switch (ch)
                {
                    case '"':
                        inStr = true;
                        if (depth == 1 && !inArray) { readingKey = true; key.Length = 0; }
                        break;
                    case '{':
                        depth++;
                        if (inArray && depth == 3) { rec = new StringBuilder(4096); rec.Append('{'); }
                        break;
                    case '}':
                        depth--;
                        if (inArray && depth == 2 && rec != null) { yield return rec.ToString(); rec = null; }
                        break;
                    case '[':
                        depth++;
                        if (depth == 2 && lastKey == "vulnerabilities") inArray = true;
                        break;
                    case ']':
                        depth--;
                        if (depth == 1 && inArray) inArray = false;
                        break;
                }
            }
        }

        static readonly Regex CritRx = new Regex("\"criteria\"\\s*:\\s*\"(cpe:2\\.3:(?:[^\"\\\\]|\\\\.)*)\"", RegexOptions.CultureInvariant);
        static readonly Regex IdRx = new Regex("\"id\"\\s*:\\s*\"(CVE-[0-9]+-[0-9]+)\"", RegexOptions.CultureInvariant);
        static readonly Regex ModRx = new Regex("\"lastModified\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.CultureInvariant);

        static TextReader OpenText(string path, Sha256Acc acc, out long bytes)
        {
            FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);
            bytes = fs.Length;
            Stream s = new TeeHashStream(fs, acc);
            if (path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) s = new GZipStream(s, CompressionMode.Decompress);
            return new StreamReader(s, new UTF8Encoding(false), true, 1 << 16);
        }

        public static List<string> ExpandFeeds(string[] paths)
        {
            List<string> o = new List<string>();
            foreach (string p in paths ?? new string[0])
            {
                if (string.IsNullOrWhiteSpace(p)) continue;
                if (Directory.Exists(p))
                {
                    List<string> l = new List<string>();
                    foreach (string f in Directory.GetFiles(p)) if (Regex.IsMatch(Path.GetFileName(f), @"\.json(\.gz)?$", RegexOptions.IgnoreCase)) l.Add(f);
                    l.Sort(StringComparer.OrdinalIgnoreCase);
                    o.AddRange(l);
                }
                else if (File.Exists(p)) o.Add(p);
                else throw new FileNotFoundException("NVD feed not found: " + p);
            }
            if (o.Count == 0) throw new ArgumentException("no NVD feed files (nvdcve-2.0-*.json[.gz]) were given");
            return o;
        }

        // ---------------------------------------------------------------- matching one CVE record
        static bool Covers(Dictionary<string, object> m, Cpe e, out string how)
        {
            how = null;
            Cpe c = Cpe.Parse(StoreUtil.Str(m, "criteria"));
            if (c == null || c.Part != e.Part || c.Vendor != e.Vendor || c.Product != e.Product) return false;
            string si = StoreUtil.Str(m, "versionStartIncluding"), se = StoreUtil.Str(m, "versionStartExcluding");
            string ei = StoreUtil.Str(m, "versionEndIncluding"), ee = StoreUtil.Str(m, "versionEndExcluding");
            bool ranged = si.Length + se.Length + ei.Length + ee.Length > 0;
            if (!e.VersionKnown) { how = "product-only"; return true; }
            string ev = e.Full;
            if (!Cpe.Any(c.Version))
            {
                if (Cpe.Any(c.Update))
                {
                    // 8.9 with update '*' covers 8.9p1; update '-' means exactly 8.9
                    if (VersionCmp.Compare(ev, c.Version) == 0) { how = "version"; return true; }
                    if (c.Update == "*" && ev.StartsWith(c.Version, StringComparison.OrdinalIgnoreCase) && ev.Length > c.Version.Length && char.IsLetter(ev[c.Version.Length])) { how = "version"; return true; }
                    return false;
                }
                if (VersionCmp.Compare(ev, c.Version + c.Update) == 0 || string.Equals(ev, c.Version + c.Update, StringComparison.OrdinalIgnoreCase)) { how = "version"; return true; }
                return false;
            }
            if (!ranged) { how = "all-versions"; return true; }
            if (si.Length > 0 && VersionCmp.Compare(ev, si) < 0) return false;
            if (se.Length > 0 && VersionCmp.Compare(ev, se) <= 0) return false;
            if (ei.Length > 0 && VersionCmp.Compare(ev, ei) > 0) return false;
            if (ee.Length > 0 && VersionCmp.Compare(ev, ee) >= 0) return false;
            how = "range"; return true;
        }
        static bool Unconstrained(Dictionary<string, object> m)
        {
            Cpe c = Cpe.Parse(StoreUtil.Str(m, "criteria"));
            return c != null && Cpe.Any(c.Version) && StoreUtil.Str(m, "versionStartIncluding").Length + StoreUtil.Str(m, "versionStartExcluding").Length
                + StoreUtil.Str(m, "versionEndIncluding").Length + StoreUtil.Str(m, "versionEndExcluding").Length == 0;
        }
        static int Rank(string how) { switch (how) { case "version": case "range": return 3; case "all-versions": return 2; default: return 1; } }

        static List<object> Arr(Dictionary<string, object> o, string k) { return StoreUtil.Field(o, k) as List<object>; }

        // best match of one service against one CVE's configurations ("" = no match)
        static string Evaluate(Dictionary<string, object> cve, Service s, out Cpe matched)
        {
            matched = null;
            string best = null; int bestRank = 0;
            List<object> configs = Arr(cve, "configurations");
            if (configs == null) return "";
            foreach (object co in configs)
            {
                Dictionary<string, object> conf = co as Dictionary<string, object>;
                List<object> nodes = Arr(conf, "nodes");
                if (nodes == null) continue;
                bool andConf = StoreUtil.Str(conf, "operator").Equals("AND", StringComparison.OrdinalIgnoreCase);
                // the node holding a vulnerable entry this service matches; in an AND configuration the other nodes are
                // platform requirements, checked against this service's other CPEs
                for (int ni = 0; ni < nodes.Count; ni++)
                {
                    Dictionary<string, object> node = nodes[ni] as Dictionary<string, object>;
                    if (node == null || StoreUtil.Str(node, "negate") == "True") continue;
                    List<object> ms = Arr(node, "cpeMatch");
                    if (ms == null) continue;
                    bool nodeAnd = StoreUtil.Str(node, "operator").Equals("AND", StringComparison.OrdinalIgnoreCase);
                    foreach (Cpe e in s.Cpes)
                    {
                        string how = null;
                        foreach (object mo in ms)
                        {
                            Dictionary<string, object> m = mo as Dictionary<string, object>;
                            if (m == null || StoreUtil.Str(m, "vulnerable") != "True") continue;
                            string h;
                            if (Covers(m, e, out h) && (how == null || Rank(h) > Rank(how))) how = h;
                        }
                        if (how == null || nodeAnd) continue;   // an AND node needs every entry: not decidable from one service
                        bool platformOk = true;
                        if (andConf && nodes.Count > 1)
                            for (int nj = 0; nj < nodes.Count; nj++)
                            {
                                if (nj == ni) continue;
                                if (!NodeSatisfied(nodes[nj] as Dictionary<string, object>, s, e)) { platformOk = false; break; }
                            }
                        string label = how + (platformOk ? "" : " (platform not verified)")
                            + (e.Alias.Length > 0 ? " (as " + e.Vendor + ":" + e.Product + ")" : "");
                        int rank = Rank(how) * 2 + (platformOk ? 1 : 0);
                        if (rank > bestRank) { bestRank = rank; best = label; matched = e; }
                    }
                }
            }
            return best ?? "";
        }
        static bool NodeSatisfied(Dictionary<string, object> node, Service s, Cpe exclude)
        {
            List<object> ms = Arr(node, "cpeMatch");
            if (ms == null) return false;
            bool nodeAnd = StoreUtil.Str(node, "operator").Equals("AND", StringComparison.OrdinalIgnoreCase);
            int hits = 0;
            foreach (object mo in ms)
            {
                Dictionary<string, object> m = mo as Dictionary<string, object>;
                bool any = false;
                foreach (Cpe e in s.Cpes)
                {
                    if (exclude != null && e.Root == exclude.Root) continue;   // the matched CPE (or an alias copy of it) is no platform for itself
                    string h;
                    // a platform entry that names no version (windows:-, linux_kernel:*) is met by the product alone
                    if (Covers(m, e, out h) && (h != "product-only" || Unconstrained(m))) { any = true; break; }
                }
                if (any) { hits++; if (!nodeAnd) return true; }
                else if (nodeAnd) return false;
            }
            return nodeAnd && hits == ms.Count && hits > 0;
        }

        static void Metrics(Dictionary<string, object> cve, CveInfo ci)
        {
            Dictionary<string, object> metrics = StoreUtil.Field(cve, "metrics") as Dictionary<string, object>;
            if (metrics == null) return;
            foreach (string[] k in new[] { new[] { "cvssMetricV31", "3.1" }, new[] { "cvssMetricV40", "4.0" }, new[] { "cvssMetricV30", "3.0" }, new[] { "cvssMetricV2", "2.0" } })
            {
                List<object> l = Arr(metrics, k[0]);
                if (l == null || l.Count == 0) continue;
                Dictionary<string, object> pick = null;
                foreach (object o in l) { Dictionary<string, object> d = o as Dictionary<string, object>; if (d != null && StoreUtil.Str(d, "type") == "Primary") { pick = d; break; } }
                if (pick == null) pick = l[0] as Dictionary<string, object>;
                Dictionary<string, object> data = StoreUtil.Field(pick, "cvssData") as Dictionary<string, object>;
                if (data == null) continue;
                ci.Score = StoreUtil.Str(data, "baseScore");
                ci.Severity = StoreUtil.Str(data, "baseSeverity");
                if (ci.Severity.Length == 0) ci.Severity = StoreUtil.Str(pick, "baseSeverity");
                ci.CvssVersion = k[1];
                return;
            }
        }

        // ---------------------------------------------------------------- alias names
        // NVD files one product under several names over time (vendor renames such as pulsesecure -> ivanti, product
        // renames, firmware vs software entries). Each group from the script's CPE supplement is one product: a service's
        // CPE is also compared under the other names of its group, with the same version.
        static Dictionary<string, string[]> aliases = new Dictionary<string, string[]>(StringComparer.Ordinal);
        static string aliasVersion = "";
        // general-purpose operating systems (Ubuntu, Windows Server 2012, ...): their patch level is not visible remotely,
        // so a match without a version would list every KEV entry of the release; such rows are counted, not listed
        static List<string> platforms = new List<string>();
        static bool IsPlatform(Cpe c)
        {
            if (c == null) return false;
            foreach (string k in new[] { c.Key, c.Root.Key })
                foreach (string p in platforms)
                    if (p.EndsWith("*", StringComparison.Ordinal) ? k.StartsWith(p.Substring(0, p.Length - 1), StringComparison.Ordinal) : k == p) return true;
            return false;
        }
        public static int SetAliases(string supplementJson)
        {
            Dictionary<string, string[]> m = new Dictionary<string, string[]>(StringComparer.Ordinal);
            Dictionary<string, object> o = string.IsNullOrEmpty(supplementJson) ? null : StoreJson.Parse(supplementJson) as Dictionary<string, object>;
            List<object> groups = o != null ? StoreUtil.Field(o, "aliases") as List<object> : null;
            if (groups != null)
                foreach (object g in groups)
                {
                    List<object> gl = g as List<object>;
                    if (gl == null || gl.Count < 2) continue;
                    List<string> keys = new List<string>();
                    foreach (object k in gl) { string ks = Convert.ToString(k, CultureInfo.InvariantCulture).ToLowerInvariant(); if (ks.Split(':').Length >= 3 && !keys.Contains(ks)) keys.Add(ks); }
                    foreach (string k in keys)
                    {
                        List<string> others = new List<string>();
                        string[] prev;
                        if (m.TryGetValue(k, out prev)) others.AddRange(prev);
                        foreach (string x in keys) if (x != k && !others.Contains(x)) others.Add(x);
                        m[k] = others.ToArray();
                    }
                }
            List<string> pl = new List<string>();
            List<object> pls = o != null ? StoreUtil.Field(o, "platforms") as List<object> : null;
            if (pls != null) foreach (object x in pls) { string ps = Convert.ToString(x, CultureInfo.InvariantCulture).ToLowerInvariant(); if (ps.Length > 0) pl.Add(ps); }
            aliases = m; platforms = pl;
            aliasVersion = o != null ? StoreUtil.Str(o, "version") : "";
            return m.Count;
        }

        // ---------------------------------------------------------------- the query
        public static VulnResult Run(List<Service> services, string[] nvdPaths, string kevPath, string epssPath, List<RowFilter> filters, string storeId, string lastRun)
        {
            VulnResult res = new VulnResult(); res.Columns = Columns;
            // inventory side: vendor:product -> services
            Dictionary<string, List<Service>> byKey = new Dictionary<string, List<Service>>(StringComparer.Ordinal);
            HashSet<string> vp = new HashSet<string>(StringComparer.Ordinal);
            int withCpe = 0, unversioned = 0, aliasCopies = 0;
            Dictionary<string, string[]> al = aliases;
            foreach (Service s in services)
            {
                if (s.Cpes.Count == 0) continue;
                withCpe++;
                bool anyVer = false;
                List<Cpe> own = new List<Cpe>(s.Cpes);
                HashSet<string> have = new HashSet<string>(StringComparer.Ordinal);
                foreach (Cpe c in own) have.Add(c.Key);
                foreach (Cpe c in own)
                {
                    string[] names;
                    if (!al.TryGetValue(c.Key, out names)) continue;
                    foreach (string a in names) if (have.Add(a)) { s.Cpes.Add(c.As(a)); aliasCopies++; }
                }
                foreach (Cpe c in s.Cpes)
                {
                    if (c.VersionKnown) anyVer = true;
                    List<Service> l;
                    if (!byKey.TryGetValue(c.Key, out l)) { l = new List<Service>(); byKey[c.Key] = l; }
                    if (!l.Contains(s)) l.Add(s);
                    vp.Add(c.Vendor + ":" + c.Product);
                }
                if (!anyVer) unversioned++;
            }
            // feeds
            List<string> files = ExpandFeeds(nvdPaths);
            Dictionary<string, string> lastMod = new Dictionary<string, string>(StringComparer.Ordinal);
            Dictionary<string, CveInfo> found = new Dictionary<string, CveInfo>(StringComparer.Ordinal);
            List<string> feedProv = new List<string>();
            long records = 0, parsed = 0;
            foreach (string f in files)
            {
                Sha256Acc acc = new Sha256Acc();
                long bytes, n = 0;
                using (TextReader tr = OpenText(f, acc, out bytes))
                {
                    foreach (string rec in FeedRecords(tr))
                    {
                        n++; records++;
                        Match im = IdRx.Match(rec);
                        if (!im.Success) continue;
                        string id = im.Groups[1].Value;
                        Match mm = ModRx.Match(rec);
                        string mod = mm.Success ? mm.Groups[1].Value : "";
                        string seen;
                        if (lastMod.TryGetValue(id, out seen) && string.CompareOrdinal(seen, mod) >= 0) continue;   // an equal or newer copy was read already
                        lastMod[id] = mod;
                        bool cand = false;
                        foreach (Match cm in CritRx.Matches(rec))
                        {
                            Cpe c = Cpe.Parse(cm.Groups[1].Value.Replace("\\\\", "\\"));
                            if (c != null && vp.Contains(c.Vendor + ":" + c.Product)) { cand = true; break; }
                        }
                        if (!cand) { found.Remove(id); continue; }
                        Dictionary<string, object> o = StoreJson.Parse(rec) as Dictionary<string, object>;
                        Dictionary<string, object> cve = StoreUtil.Field(o, "cve") as Dictionary<string, object>;
                        if (cve == null) continue;
                        parsed++;
                        found.Remove(id);
                        if (StoreUtil.Str(cve, "vulnStatus").Equals("Rejected", StringComparison.OrdinalIgnoreCase)) continue;
                        CveInfo ci = new CveInfo();
                        ci.Id = id; ci.LastModified = mod; ci.Published = StoreUtil.Str(cve, "published");
                        HashSet<Service> tried = new HashSet<Service>();
                        foreach (Match cm in CritRx.Matches(rec))
                        {
                            Cpe c = Cpe.Parse(cm.Groups[1].Value.Replace("\\\\", "\\"));
                            List<Service> l;
                            if (c == null || !byKey.TryGetValue(c.Key, out l)) continue;
                            foreach (Service s in l)
                            {
                                if (!tried.Add(s)) continue;
                                Cpe which;
                                string how = Evaluate(cve, s, out which);
                                if (how.Length > 0) { Hit h = new Hit(); h.Svc = s; h.Cpe = which; h.Match = how; ci.Hits.Add(h); }
                            }
                        }
                        if (ci.Hits.Count == 0) continue;
                        Metrics(cve, ci);
                        List<object> descs = Arr(cve, "descriptions");
                        if (descs != null)
                            foreach (object d in descs)
                            {
                                Dictionary<string, object> dd = d as Dictionary<string, object>;
                                if (StoreUtil.Str(dd, "lang") == "en") { ci.Description = StoreUtil.Str(dd, "value"); break; }
                            }
                        found[id] = ci;
                    }
                }
                feedProv.Add(new JsonObj().Str("file", Path.GetFileName(f)).Str("sha256", acc.FinalHex()).Num("bytes", bytes).Num("records", n).ToString());
            }
            // KEV and EPSS
            Dictionary<string, string[]> kev = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            string kevProv = "null", epssProv = "null";
            if (!string.IsNullOrEmpty(kevPath)) kevProv = LoadKev(kevPath, kev);
            Dictionary<string, string[]> epss = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            if (!string.IsNullOrEmpty(epssPath)) epssProv = LoadEpss(epssPath, found, epss);
            // rows: product-only matches (service version unknown) are kept only for KEV-listed CVEs
            int dropped = 0, droppedOs = 0;
            List<KeyValuePair<double[], string[]>> rows = new List<KeyValuePair<double[], string[]>>();
            foreach (CveInfo ci in found.Values)
            {
                string[] k; kev.TryGetValue(ci.Id, out k);
                string[] ep; epss.TryGetValue(ci.Id, out ep);
                foreach (Hit h in ci.Hits)
                {
                    if (h.Match.StartsWith("product-only", StringComparison.Ordinal) && k == null) { dropped++; continue; }
                    if (h.Match.StartsWith("product-only", StringComparison.Ordinal) && IsPlatform(h.Cpe)) { droppedOs++; continue; }
                    Dictionary<string, string> r = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    r["Host"] = h.Svc.Host; r["IP"] = h.Svc.Ip; r["Port"] = h.Svc.Port; r["Url"] = h.Svc.Url; r["Status"] = h.Svc.Status; r["Products"] = h.Svc.Products;
                    r["Cpe"] = h.Cpe != null ? h.Cpe.Raw : ""; r["Cve"] = ci.Id; r["Kev"] = k != null ? "Yes" : "";
                    r["KevDateAdded"] = k != null ? k[0] : ""; r["KevDueDate"] = k != null ? k[1] : ""; r["KevRansomware"] = k != null ? k[2] : "";
                    r["Epss"] = ep != null ? ep[0] : ""; r["EpssPercentile"] = ep != null ? ep[1] : "";
                    r["CvssScore"] = ci.Score; r["CvssSeverity"] = ci.Severity; r["CvssVersion"] = ci.CvssVersion; r["Published"] = ci.Published.Length >= 10 ? ci.Published.Substring(0, 10) : ci.Published;
                    r["Match"] = h.Match; r["EntityId"] = h.Svc.EntityId;
                    r["Description"] = ci.Description.Length > 400 ? ci.Description.Substring(0, 400) + "..." : ci.Description;
                    if (!RowFilter.All(filters, r)) continue;
                    double ev, sc;
                    double.TryParse(r["Epss"], NumberStyles.Float, CultureInfo.InvariantCulture, out ev);
                    double.TryParse(r["CvssScore"], NumberStyles.Float, CultureInfo.InvariantCulture, out sc);
                    string[] row = new string[Columns.Length];
                    for (int i = 0; i < Columns.Length; i++) { string v; row[i] = r.TryGetValue(Columns[i], out v) ? v : ""; }
                    rows.Add(new KeyValuePair<double[], string[]>(new[] { k != null ? 1.0 : 0.0, ev, sc }, row));
                }
            }
            rows.Sort(delegate(KeyValuePair<double[], string[]> a, KeyValuePair<double[], string[]> b)
            {
                for (int i = 0; i < 3; i++) { int c = b.Key[i].CompareTo(a.Key[i]); if (c != 0) return c; }
                int x = string.Compare(a.Value[0], b.Value[0], StringComparison.OrdinalIgnoreCase); if (x != 0) return x;
                int pa, pb; int.TryParse(a.Value[2], out pa); int.TryParse(b.Value[2], out pb); if (pa != pb) return pa.CompareTo(pb);
                return string.CompareOrdinal(a.Value[7], b.Value[7]);
            });
            foreach (KeyValuePair<double[], string[]> kvp in rows) res.Rows.Add(kvp.Value);
            int kevRows = 0; foreach (string[] r2 in res.Rows) if (r2[8] == "Yes") kevRows++;
            res.Messages.Add(string.Format(CultureInfo.InvariantCulture, "{0} services with a CPE ({1} without a version); {2} NVD records read from {3} files, {4} matched; {5} service/CVE rows ({6} on the KEV list){7}",
                withCpe, unversioned, records, files.Count, found.Count, res.Rows.Count, kevRows,
                (dropped > 0 ? "; " + dropped + " version-unknown matches not listed (only KEV entries are listed when the service hides its version)" : "")
                + (droppedOs > 0 ? "; " + droppedOs + " KEV entries of general-purpose operating systems without a known version not listed (patch level not visible remotely)" : "")));
            res.Provenance = new JsonObj().Str("generated", StoreUtil.Iso(DateTimeOffset.Now)).Str("storeId", storeId).Str("inventoryAfterRun", lastRun)
                .Raw("nvd", "[" + string.Join(",", feedProv) + "]").Raw("kev", kevProv).Raw("epss", epssProv)
                .Raw("counts", new JsonObj().Num("servicesWithCpe", withCpe).Num("servicesWithoutVersion", unversioned).Num("nvdRecords", records).Num("nvdRecordsParsed", parsed)
                    .Num("cvesMatched", found.Count).Num("rows", res.Rows.Count).Num("kevRows", kevRows).Num("versionUnknownNotListed", dropped).Num("osVersionUnknownKevNotListed", droppedOs).Num("aliasNamesCompared", aliasCopies).ToString())
                .Raw("cpeAliases", new JsonObj().Str("supplement", aliasVersion).Num("names", al.Count).Num("platforms", platforms.Count).ToString())
                .Str("method", "CPE 2.3 vendor/product match (plus the other NVD names of the same product from the CPE supplement); version, update and NVD ranges compared numerically; AND configurations check platform nodes against the same service's other CPEs; version-unknown services listed only for KEV CVEs, and not for general-purpose operating systems").ToString();
            return res;
        }

        static string LoadKev(string path, Dictionary<string, string[]> kev)
        {
            long bytes;
            string sha = StoreUtil.FileSha256(path, out bytes);
            string text = StoreUtil.ReadText(path);
            string catalog = "", released = "";
            if (text.TrimStart().StartsWith("{", StringComparison.Ordinal))
            {
                Dictionary<string, object> o = StoreJson.Parse(text) as Dictionary<string, object>;
                catalog = StoreUtil.Str(o, "catalogVersion"); released = StoreUtil.Str(o, "dateReleased");
                List<object> l = StoreUtil.Field(o, "vulnerabilities") as List<object>;
                if (l == null) throw new InvalidDataException("KEV file has no 'vulnerabilities' array: " + path);
                foreach (object x in l)
                {
                    Dictionary<string, object> d = x as Dictionary<string, object>;
                    string id = StoreUtil.Str(d, "cveID");
                    if (id.Length > 0) kev[id] = new[] { StoreUtil.Str(d, "dateAdded"), StoreUtil.Str(d, "dueDate"), StoreUtil.Str(d, "knownRansomwareCampaignUse") };
                }
            }
            else
            {
                string[] head = null;
                foreach (string line in CsvLines(text))
                {
                    string[] f = SplitCsv(line);
                    if (head == null) { head = f; continue; }
                    int ic = Array.IndexOf(head, "cveID"), ia = Array.IndexOf(head, "dateAdded"), idue = Array.IndexOf(head, "dueDate"), ir = Array.IndexOf(head, "knownRansomwareCampaignUse");
                    if (ic < 0) throw new InvalidDataException("KEV CSV has no cveID column: " + path);
                    if (f.Length > ic && f[ic].Length > 0) kev[f[ic]] = new[] { ia >= 0 && f.Length > ia ? f[ia] : "", idue >= 0 && f.Length > idue ? f[idue] : "", ir >= 0 && f.Length > ir ? f[ir] : "" };
                }
            }
            return new JsonObj().Str("file", Path.GetFileName(path)).Str("sha256", sha).Num("bytes", bytes).Str("catalogVersion", catalog).Str("dateReleased", released).Num("entries", kev.Count).ToString();
        }

        static string LoadEpss(string path, Dictionary<string, CveInfo> want, Dictionary<string, string[]> epss)
        {
            long bytes;
            string sha = StoreUtil.FileSha256(path, out bytes);
            string model = "", date = ""; long n = 0;
            int ic = -1, ie = -1, ip = -1;
            foreach (string line in StoreUtil.ReadLines(path))
            {
                if (line.StartsWith("#", StringComparison.Ordinal))
                {
                    Match m1 = Regex.Match(line, @"model_version:([^,]+)"), m2 = Regex.Match(line, @"score_date:([^,\s]+)");
                    if (m1.Success) model = m1.Groups[1].Value.Trim(); if (m2.Success) date = m2.Groups[1].Value.Trim();
                    continue;
                }
                string[] f = line.Split(',');
                if (ic < 0) { ic = Array.IndexOf(f, "cve"); ie = Array.IndexOf(f, "epss"); ip = Array.IndexOf(f, "percentile"); if (ic < 0 || ie < 0) throw new InvalidDataException("EPSS file has no cve/epss header: " + path); continue; }
                n++;
                if (f.Length <= Math.Max(ic, Math.Max(ie, ip)) || !want.ContainsKey(f[ic])) continue;
                epss[f[ic]] = new[] { f[ie], ip >= 0 ? f[ip] : "" };
            }
            return new JsonObj().Str("file", Path.GetFileName(path)).Str("sha256", sha).Num("bytes", bytes).Str("modelVersion", model).Str("scoreDate", date).Num("rows", n).ToString();
        }

        static IEnumerable<string> CsvLines(string text)
        {
            // records may contain quoted newlines
            StringBuilder cur = new StringBuilder(); bool q = false;
            foreach (char ch in text)
            {
                if (ch == '"') q = !q;
                if ((ch == '\n') && !q) { string l = cur.ToString().TrimEnd('\r'); if (l.Length > 0) yield return l; cur.Length = 0; continue; }
                cur.Append(ch);
            }
            if (cur.Length > 0) yield return cur.ToString().TrimEnd('\r');
        }
        static string[] SplitCsv(string line)
        {
            List<string> f = new List<string>(); StringBuilder cur = new StringBuilder(); bool q = false;
            for (int i = 0; i < line.Length; i++)
            {
                char ch = line[i];
                if (q) { if (ch == '"') { if (i + 1 < line.Length && line[i + 1] == '"') { cur.Append('"'); i++; } else q = false; } else cur.Append(ch); }
                else if (ch == '"') q = true;
                else if (ch == ',') { f.Add(cur.ToString()); cur.Length = 0; }
                else cur.Append(ch);
            }
            f.Add(cur.ToString());
            return f.ToArray();
        }
    }

    // read-through stream that hashes every byte it passes on (feed provenance without a second read)
    sealed class TeeHashStream : Stream
    {
        readonly Stream inner; readonly Sha256Acc acc;
        public TeeHashStream(Stream s, Sha256Acc a) { inner = s; acc = a; }
        public override int Read(byte[] buffer, int offset, int count) { int n = inner.Read(buffer, offset, count); if (n > 0) acc.Append(buffer, offset, n); return n; }
        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { return inner.Length; } }
        public override long Position { get { return inner.Position; } set { throw new NotSupportedException(); } }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
    }
}
