
// ============================================================================
// Store self-test helpers (used by -SelfTest): key-value engine conformance, SHA-256 accumulator vectors, and a
// synthetic three-run history. On Windows the same checks run against ESENT and the portable engine, and the
// self-test requires both to produce byte-identical change and state digests.
// ============================================================================
namespace WebInv
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Text;

    public static class StoreSelfTest
    {
        static KvEngine Make(string engine, string dir)
        {
            switch (engine)
            {
                case "memory": return new FileKv(null);
                case "file": Directory.CreateDirectory(dir); return new FileKv(Path.Combine(dir, "inventory.kv"));
                case "esent": return new EsentKv(dir);
            }
            throw new ArgumentException(engine);
        }
        static string Hex(byte[] b) { return StoreUtil.Hex(b); }
        static string Dump(KvEngine kv)
        {
            StringBuilder sb = new StringBuilder();
            foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(new byte[0])) sb.Append(Hex(e.Key)).Append('=').Append(e.Value.Length).Append(':').Append(StoreUtil.Sha256Hex(e.Value).Substring(0, 8)).Append(';');
            return sb.ToString();
        }
        static bool Throws(Action a) { try { a(); return false; } catch (Exception) { return true; } }

        // returns "" when the engine meets the KvEngine contract, else the first deviation
        public static string KvConformance(string engine, string dir)
        {
            KvEngine kv = Make(engine, dir);
            try
            {
                List<byte[]> keys = new List<byte[]>();
                foreach (string s in new[] { "a", "ab", "b", "a\u0001", "abc", "c" }) keys.Add(StoreUtil.B(s));
                keys.Add(new byte[] { (byte)'a', 0 }); keys.Add(new byte[] { (byte)'a', 0, (byte)'b' }); keys.Add(new byte[] { 0xff });
                keys.Add(new byte[] { 0x00, 0x01 }); keys.Add(new byte[] { 0x7f, 0x80, 0xfe });
                byte[] longKey = new byte[KvEngine.MaxKey]; for (int i = 0; i < longKey.Length; i++) longKey[i] = (byte)(i % 251 + 1);
                keys.Add(longKey);
                byte[] longKey2 = (byte[])longKey.Clone(); longKey2[KvEngine.MaxKey - 1]++;
                keys.Add(longKey2);
                Random rnd = new Random(5);
                Dictionary<byte[], byte[]> model = new Dictionary<byte[], byte[]>(ByteOrder.Instance);
                kv.Begin();
                int n = 0;
                foreach (byte[] k in keys)
                {
                    byte[] v = new byte[n == 3 ? 0 : (n == 5 ? 200000 : rnd.Next(1, 300))];
                    rnd.NextBytes(v);
                    kv.Put(k, v); model[k] = v; n++;
                }
                for (int i = 0; i < 3000; i++)
                {
                    byte[] k = StoreUtil.B("p\0" + rnd.Next(0, 1000000).ToString("D7", CultureInfo.InvariantCulture));
                    byte[] v = StoreUtil.B(i.ToString(CultureInfo.InvariantCulture));
                    kv.Put(k, v); model[k] = v;
                }
                kv.Commit(true);
                List<byte[]> sorted = new List<byte[]>(model.Keys); sorted.Sort(ByteOrder.Instance);
                string want = Expect(sorted, model);
                string got = Dump(kv);
                if (got != want) return "full scan order/content differs from the reference ordering";
                foreach (byte[] k in keys) { byte[] v = kv.Get(k); if (v == null || !ByteOrder.Instance.Equals(v, model[k])) return "Get(" + Hex(k) + ") returned the wrong value"; }
                if (kv.Get(StoreUtil.B("zz")) != null) return "Get of a missing key returned a value";
                // prefix scans and paging after a key
                List<KeyValuePair<byte[], byte[]>> pa = kv.ScanPage(StoreUtil.B("a"), null, 100);
                string pas = Keys(pa);
                string pexp = Keys(Filter(sorted, model, StoreUtil.B("a"), null));
                if (pas != pexp) return "prefix scan 'a' differs: " + pas + " vs " + pexp;
                List<KeyValuePair<byte[], byte[]>> pb = kv.ScanPage(StoreUtil.B("a"), new byte[] { (byte)'a', 0 }, 100);
                if (Keys(pb) != Keys(Filter(sorted, model, StoreUtil.B("a"), new byte[] { (byte)'a', 0 }))) return "scan after a key differs";
                int count = 0; byte[] last = null;
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(StoreUtil.B("p\0")))
                {
                    if (last != null && ByteOrder.Instance.Compare(last, e.Key) >= 0) return "paged scan out of order";
                    last = e.Key; count++;
                }
                int pcount = 0; foreach (byte[] k in sorted) if (KvEngine.StartsWith(k, StoreUtil.B("p\0"))) pcount++;
                if (count != pcount) return "paged scan returned " + count + " of " + pcount + " keys";
                if (kv.ScanPage(StoreUtil.B("q"), null, 10).Count != 0) return "scan of an absent prefix returned rows";
                // rollback restores everything; commit applies
                string before = Dump(kv);
                kv.Begin();
                kv.Put(StoreUtil.B("ab"), new byte[] { 1, 2, 3 }); kv.Delete(StoreUtil.B("b")); kv.Put(StoreUtil.B("new"), new byte[] { 9 }); kv.Delete(StoreUtil.B("new"));
                kv.Put(StoreUtil.B("new2"), new byte[] { 9 });
                kv.Rollback();
                if (Dump(kv) != before) return "rollback did not restore the previous state";
                kv.Begin();
                if (!kv.Delete(new byte[] { (byte)'a', 0, (byte)'b' })) return "Delete of an existing key returned false";
                if (kv.Delete(StoreUtil.B("missing"))) return "Delete of a missing key returned true";
                kv.Put(StoreUtil.B("c"), new byte[0]);
                kv.Commit(true);
                model.Remove(new byte[] { (byte)'a', 0, (byte)'b' }); model[StoreUtil.B("c")] = new byte[0];
                sorted = new List<byte[]>(model.Keys); sorted.Sort(ByteOrder.Instance);
                want = Expect(sorted, model);
                if (Dump(kv) != want) return "state after delete/overwrite differs";
                // contract violations are refused
                KvEngine k2 = kv;
                if (!Throws(delegate { k2.Put(StoreUtil.B("x"), new byte[1]); })) return "write outside a transaction was accepted";
                k2.Begin();
                if (!Throws(delegate { k2.Put(new byte[KvEngine.MaxKey + 1], new byte[1]); })) return "over-long key was accepted";
                if (!Throws(delegate { k2.Put(new byte[0], new byte[1]); })) return "empty key was accepted";
                if (!Throws(delegate { k2.Begin(); })) return "nested transaction was accepted";
                k2.Rollback();
                // durability: reopen
                if (engine != "memory")
                {
                    kv.Dispose();
                    kv = Make(engine, dir);
                    if (Dump(kv) != want) return "state after reopen differs";
                }
                return "";
            }
            catch (Exception ex) { return "exception: " + ex.GetType().Name + ": " + ex.Message; }
            finally { kv.Dispose(); }
        }
        static string Expect(List<byte[]> sorted, Dictionary<byte[], byte[]> model)
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte[] k in sorted) sb.Append(Hex(k)).Append('=').Append(model[k].Length).Append(':').Append(StoreUtil.Sha256Hex(model[k]).Substring(0, 8)).Append(';');
            return sb.ToString();
        }
        static List<KeyValuePair<byte[], byte[]>> Filter(List<byte[]> sorted, Dictionary<byte[], byte[]> model, byte[] prefix, byte[] after)
        {
            List<KeyValuePair<byte[], byte[]>> r = new List<KeyValuePair<byte[], byte[]>>();
            foreach (byte[] k in sorted)
                if (KvEngine.StartsWith(k, prefix) && (after == null || ByteOrder.Instance.Compare(k, after) > 0)) r.Add(new KeyValuePair<byte[], byte[]>(k, model[k]));
            return r;
        }
        static string Keys(List<KeyValuePair<byte[], byte[]>> l) { StringBuilder sb = new StringBuilder(); foreach (KeyValuePair<byte[], byte[]> e in l) sb.Append(Hex(e.Key)).Append(','); return sb.ToString(); }

        // SHA-256: known vectors on both paths, then the managed accumulator (fed in random-sized pieces) against the
        // platform provider at every block-boundary length
        public static string HashCheck()
        {
            foreach (bool managed in new[] { false, true })
                using (Sha256Acc a = new Sha256Acc(managed))
                {
                    a.Append(StoreUtil.B("abc"));
                    if (a.FinalHex() != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") return "abc vector (" + (managed ? "managed" : "platform") + ")";
                    if (a.FinalHex() != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") return "empty vector after reset (" + (managed ? "managed" : "platform") + ")";
                    a.Append(StoreUtil.B("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
                    if (a.FinalHex() != "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") return "448-bit vector (" + (managed ? "managed" : "platform") + ")";
                }
            Random r = new Random(3);
            foreach (int len in new[] { 0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 1000, 70000 })
            {
                byte[] d = new byte[len]; r.NextBytes(d);
                string want;
                using (Sha256Acc p = new Sha256Acc()) { p.Append(d); want = p.FinalHex(); }
                using (Sha256Acc a = new Sha256Acc(true))
                {
                    int i = 0;
                    while (i < len) { int c = Math.Min(r.Next(1, 97), len - i); a.Append(d, i, c); i += c; }
                    if (a.FinalHex() != want) return "managed accumulator differs from the platform at length " + len;
                }
            }
            return "";
        }

        // Three synthetic runs: run 2 changes titles, drops, adds and moves named hosts; run 3 is a -NoTlsScan run that
        // brings some services back. Returns the sources in run order.
        public static RunSources[] WriteRuns(string dir, int n)
        {
            List<RunSources> list = new List<RunSources>();
            string[] ids = { "20260105_080000", "20260106_080000", "20260107_080000" };
            for (int k = 0; k < 3; k++)
            {
                string d = Path.Combine(dir, "run" + (k + 1));
                Directory.CreateDirectory(d);
                string b = Path.Combine(d, "WebInventory_" + ids[k]);
                List<string> rows = new List<string>(), chk = new List<string>();
                for (int i = 0; i < n; i++)
                {
                    bool named = i % 20 == 0;
                    string ip = "10.9." + (i / 250).ToString(CultureInfo.InvariantCulture) + "." + (i % 250 + 1).ToString(CultureInfo.InvariantCulture);
                    if (named && k >= 1 && i % 40 == 0) ip = "10.8." + (i / 250).ToString(CultureInfo.InvariantCulture) + "." + (i % 250 + 1).ToString(CultureInfo.InvariantCulture);   // moved
                    string host = named ? "svc" + i.ToString(CultureInfo.InvariantCulture) + ".test.local" : ip;
                    int port = i % 3 == 0 ? 443 : 80;
                    chk.Add(host + "|" + ip + "|" + port.ToString(CultureInfo.InvariantCulture));
                    bool gone = (k == 1 && i % 33 == 5) || (k == 2 && i % 33 == 5 && i % 2 == 0);
                    if (gone) continue;
                    bool tls = port == 443;
                    JsonObj o = new JsonObj().Str("RunId", ids[k]).Str("ScanTag", "selftest").Str("ScannedAt", "2026-01-0" + (5 + k) + "T08:00:01").Str("Host", host).Str("IP", ip)
                        .Num("Port", port).Bool("Vhost", false).Str("VhostOf", "").Str("State", "open").Bool("IsWeb", true).Str("Service", tls ? "https" : "http")
                        .Str("Scheme", tls ? "https" : "http").Str("Url", (tls ? "https://" : "http://") + host + ":" + port + "/")
                        .Num("StatusCode", 200).Str("Title", "Service " + (i % 17) + (k >= 1 && i % 25 == 1 ? " (updated)" : ""))
                        .Str("Server", "nginx/1." + (i % 9)).Str("Products", "nginx 1." + (i % 9)).Str("Technologies", "nginx").Num("ResponseMs", 10 + (i * 7 + k) % 300)
                        .Str("BodySha256", StoreUtil.Sha256Hex(StoreUtil.B(i + "/" + k)));
                    if (tls)
                    {
                        o.Str("TlsVersion", "Tls12").Str("CertSha256", StoreUtil.Sha256Hex(StoreUtil.B("cert" + i))).Str("CertNotAfter", "2026-02-01T00:00:00").Num("CertDaysLeft", 27 - k)
                         .Str("Flags", "CertExpiring:" + (27 - k) + "d");
                        if (k != 2) o.Str("TlsSupported", "TLS1.2,TLS1.3").Str("Alpn", "h2").Bool("Http2", true);
                    }
                    rows.Add(o.Raw("Detections", "[]").ToString());
                }
                if (k == 1) for (int j = 0; j < n / 50; j++)
                    {
                        string ip = "10.7.0." + (j + 1).ToString(CultureInfo.InvariantCulture);
                        chk.Add(ip + "|" + ip + "|80");
                        rows.Add(new JsonObj().Str("RunId", ids[k]).Str("Host", ip).Str("IP", ip).Num("Port", 80).Bool("Vhost", false).Str("State", "open").Bool("IsWeb", true)
                            .Str("Url", "http://" + ip + ":80/").Str("Title", "New " + j).Raw("Detections", "[]").ToString());
                    }
                File.WriteAllText(b + ".jsonl", string.Join("\n", rows) + "\n", StoreUtil.Utf8);
                File.WriteAllText(b + "_progress.txt", string.Join("\n", chk) + "\n", StoreUtil.Utf8);
                RunInfo ri = new RunInfo();
                ri.RunId = ids[k]; ri.StartedAt = "2026-01-0" + (5 + k) + "T08:00:00+00:00"; ri.FinishedAt = ri.StartedAt; ri.Scanner = "selftest"; ri.Tag = "selftest";
                ri.TlsScan = k != 2; ri.ReverseDns = true; ri.ProbeSans = true; ri.Options = true; ri.IdentifyPaths = true; ri.Checks = chk.Count;
                File.WriteAllText(b + "_run.json", ri.ToJson() + "\n", StoreUtil.Utf8);
                RunSources s = new RunSources(); s.RunId = ids[k]; s.Jsonl = b + ".jsonl"; s.Progress = b + "_progress.txt"; s.RunJson = b + "_run.json";
                list.Add(s);
            }
            return list.ToArray();
        }

        // seq:runId:changes:state for every run in a store's ledger (what must be identical across engines and after repair)
        public static string LedgerDigests(string root)
        {
            StringBuilder sb = new StringBuilder();
            foreach (string l in StoreUtil.ReadLines(Path.Combine(Path.Combine(root, "archive"), "ledger.jsonl")))
            {
                Dictionary<string, object> o = StoreJson.Parse(l) as Dictionary<string, object>;
                string ty = StoreUtil.Str(o, "type");
                if (ty == "rebase")
                {
                    // a rebase restates every position: list its plan instead
                    sb.Append("rebase\n");
                    foreach (object it in (List<object>)StoreUtil.Field(o, "plan"))
                    {
                        Dictionary<string, object> d = (Dictionary<string, object>)it;
                        sb.Append(StoreUtil.Str(d, "runId")).Append(':').Append(StoreUtil.Str(d, "changesDigest")).Append(':').Append(StoreUtil.Str(d, "stateDigest")).Append('\n');
                    }
                    continue;
                }
                if (ty != "run" && ty != "correction") continue;
                sb.Append(StoreUtil.Str(o, "seq")).Append(':').Append(StoreUtil.Str(o, "runId")).Append(':').Append(StoreUtil.Str(o, "changesDigest")).Append(':').Append(StoreUtil.Str(o, "stateDigest")).Append('\n');
            }
            return sb.ToString();
        }
        // digest of the inventory after the last applied position (plan aware)
        public static string FinalState(string root)
        {
            string last = "";
            foreach (string l in StoreUtil.ReadLines(Path.Combine(Path.Combine(root, "archive"), "ledger.jsonl")))
            {
                Dictionary<string, object> o = StoreJson.Parse(l) as Dictionary<string, object>;
                string ty = StoreUtil.Str(o, "type");
                if (ty == "run" || ty == "correction") { if (StoreUtil.Str(o, "stateDigest").Length > 0) last = StoreUtil.Str(o, "stateDigest"); }
                else if (ty == "rebase") { List<object> pl = (List<object>)StoreUtil.Field(o, "plan"); last = StoreUtil.Str((Dictionary<string, object>)pl[pl.Count - 1], "stateDigest"); }
            }
            return last;
        }
        public static string LedgerCounts(string root)
        {
            StringBuilder sb = new StringBuilder();
            foreach (string l in StoreUtil.ReadLines(Path.Combine(Path.Combine(root, "archive"), "ledger.jsonl")))
            {
                Dictionary<string, object> o = StoreJson.Parse(l) as Dictionary<string, object>;
                if (StoreUtil.Str(o, "type") != "run") continue;
                Dictionary<string, object> c = StoreUtil.Field(o, "counts") as Dictionary<string, object>;
                sb.Append(StoreUtil.Str(o, "seq"));
                foreach (string f in new[] { "rows", "added", "changed", "reappeared", "rekeyed", "missing", "retired", "active", "missingTotal", "retiredTotal" })
                    sb.Append(' ').Append(f).Append('=').Append(StoreUtil.Str(c, f));
                sb.Append('\n');
            }
            return sb.ToString();
        }
    
        // offline vulnerability correlation on a hand-made feed: exact, update, range, all-versions, platform (AND),
        // version-unknown (KEV only), rejected records and the newest copy of a record winning
        public static string VulnCheck(string dir)
        {
            List<string> bad = new List<string>();
            string[][] cmp = { new[] { "8.9p1", "9.3", "-1" }, new[] { "9.3p1", "9.3", "1" }, new[] { "2.0rc1", "2.0", "-1" }, new[] { "1.0.2k", "1.0.2", "1" },
                new[] { "2.4.49", "2.4.5", "1" }, new[] { "10.0", "10", "0" }, new[] { "15.2(7)E8", "15.2(7)E10", "-1" }, new[] { "1.18.0", "1.20.0", "-1" } };
            foreach (string[] c in cmp) if (VersionCmp.Compare(c[0], c[1]).ToString(CultureInfo.InvariantCulture) != c[2]) bad.Add("compare " + c[0] + " vs " + c[1]);
            Directory.CreateDirectory(dir);
            Func<string, string, string> rec = delegate(string id, string body) { return "{\"cve\":{\"id\":\"" + id + "\",\"published\":\"2026-01-01T00:00:00.000\",\"lastModified\":\"2026-02-01T00:00:00.000\",\"vulnStatus\":\"Analyzed\",\"descriptions\":[{\"lang\":\"en\",\"value\":\"test " + id + "\"}],\"metrics\":{\"cvssMetricV31\":[{\"type\":\"Primary\",\"cvssData\":{\"baseScore\":9.8,\"baseSeverity\":\"CRITICAL\"}}]},\"configurations\":" + body + "}}"; };
            Func<string, string> one = delegate(string m) { return "[{\"nodes\":[{\"operator\":\"OR\",\"negate\":false,\"cpeMatch\":[" + m + "]}]}]"; };
            Func<string, string, string> cm = delegate(string crit, string extra) { return "{\"vulnerable\":true,\"criteria\":\"" + crit + "\"" + extra + ",\"matchCriteriaId\":\"X\"}"; };
            string feed = "{\"resultsPerPage\":9,\"format\":\"NVD_CVE\",\"vulnerabilities\":[" + string.Join(",", new[] {
                rec("CVE-2026-0001", one(cm("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", ",\"versionEndExcluding\":\"9.3p2\""))),
                rec("CVE-2026-0002", one(cm("cpe:2.3:a:openbsd:openssh:9.3:p1:*:*:*:*:*:*", ""))),
                rec("CVE-2026-0003", one(cm("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", ""))),
                rec("CVE-2026-0004", one(cm("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", ",\"versionStartIncluding\":\"2.4.50\",\"versionEndExcluding\":\"2.4.60\""))),
                rec("CVE-2026-0005", "[{\"operator\":\"AND\",\"nodes\":[{\"operator\":\"OR\",\"negate\":false,\"cpeMatch\":[" + cm("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", ",\"versionEndExcluding\":\"8.1.29\"") + "]},{\"operator\":\"OR\",\"negate\":false,\"cpeMatch\":[{\"vulnerable\":false,\"criteria\":\"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*\",\"matchCriteriaId\":\"Y\"}]}]}]"),
                rec("CVE-2026-0006", one(cm("cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*", ",\"versionEndIncluding\":\"2.441\""))),
                rec("CVE-2026-0007", one(cm("cpe:2.3:a:jenkins:jenkins:*:*:*:*:lts:*:*:*", ",\"versionEndIncluding\":\"2.426.2\""))),
                rec("CVE-2026-0008", one(cm("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", ""))).Replace("Analyzed", "Rejected"),
                rec("CVE-2026-0009", one(cm("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*", ""))),
                // filed under the product's former NVD name (alias), and percent-encoded rule data (tcp%2fip == tcp\/ip)
                rec("CVE-2026-0010", one(cm("cpe:2.3:a:pulsesecure:pulse_connect_secure:9.1:r8:*:*:*:*:*:*", ""))),
                rec("CVE-2026-0011", one(cm("cpe:2.3:a:treck:tcp\\\\/ip:*:*:*:*:*:*:*:*", ",\"versionEndExcluding\":\"6.0.1.66\""))),
                // an alias copy of the matched CPE must not count as its own platform
                rec("CVE-2026-0012", "[{\"operator\":\"AND\",\"nodes\":[{\"operator\":\"OR\",\"negate\":false,\"cpeMatch\":[" + cm("cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*", ",\"versionEndExcluding\":\"22.7\"") + "]},{\"operator\":\"OR\",\"negate\":false,\"cpeMatch\":[{\"vulnerable\":false,\"criteria\":\"cpe:2.3:a:pulsesecure:pulse_connect_secure:-:*:*:*:*:*:*:*\",\"matchCriteriaId\":\"Z\"}]}]}]"),
                // a KEV entry of a general-purpose OS, service version unknown: counted, not listed
                rec("CVE-2026-0013", one(cm("cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*", ",\"versionEndExcluding\":\"12.0\"")))
            }) + "]}";
            // a later copy of CVE-2026-0009 that no longer applies (the newest record decides)
            string mod = "{\"vulnerabilities\":[" + rec("CVE-2026-0009", one(cm("cpe:2.3:a:f5:nginx:1.17.0:*:*:*:*:*:*:*", ""))).Replace("2026-02-01", "2026-03-01") + "]}";
            File.WriteAllText(Path.Combine(dir, "nvdcve-2.0-2026.json"), feed);
            using (FileStream fs = File.Create(Path.Combine(dir, "nvdcve-2.0-modified.json.gz")))
            using (System.IO.Compression.GZipStream gz = new System.IO.Compression.GZipStream(fs, System.IO.Compression.CompressionMode.Compress))
            { byte[] b = Encoding.UTF8.GetBytes(mod); gz.Write(b, 0, b.Length); }
            string kev = Path.Combine(dir, "kev.json");
            File.WriteAllText(kev, "{\"catalogVersion\":\"t\",\"dateReleased\":\"2026-03-01\",\"vulnerabilities\":[{\"cveID\":\"CVE-2026-0006\",\"dateAdded\":\"2026-02-02\",\"dueDate\":\"2026-02-23\",\"knownRansomwareCampaignUse\":\"Known\"},{\"cveID\":\"CVE-2026-0013\",\"dateAdded\":\"2026-02-02\",\"dueDate\":\"2026-02-23\",\"knownRansomwareCampaignUse\":\"Unknown\"}]}");
            string epss = Path.Combine(dir, "epss.csv");
            File.WriteAllText(epss, "#model_version:v2026.06.15,score_date:2026-03-01T00:00:00Z\ncve,epss,percentile\nCVE-2026-0001,0.5,0.9\nCVE-2026-0006,0.9,0.99\n");
            List<Vulns.Service> svcs = new List<Vulns.Service>();
            Func<string, string, Vulns.Service> svc = delegate(string host, string cpes)
            {
                Vulns.Service x = new Vulns.Service(); x.Host = host; x.Ip = "10.0.0.1"; x.Port = "443"; x.Url = ""; x.Status = "Active"; x.Products = ""; x.EntityId = host;
                foreach (string c in cpes.Split(';')) x.Cpes.Add(Cpe.Parse(c));
                svcs.Add(x); return x;
            };
            svc("ssh-a", "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*");
            svc("ssh-b", "cpe:2.3:a:openbsd:openssh:9.3p1:*:*:*:*:*:*:*");
            svc("ssh-c", "cpe:2.3:a:openbsd:openssh:9.8p1:*:*:*:*:*:*:*");
            svc("web-a", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*");
            svc("web-b", "cpe:2.3:a:apache:http_server:2.4.55:*:*:*:*:*:*:*");
            svc("php-win", "cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*;cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*");
            svc("php-lin", "cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*");
            svc("ci", "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*");
            svc("ngx", "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*");
            svc("vpn", "cpe:2.3:a:ivanti:connect_secure:9.1r8:*:*:*:*:*:*:*");
            svc("iot", "cpe:2.3:a:treck:tcp%2fip:6.0.1.41:*:*:*:*:*:*:*");
            svc("deb", "cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*");
            Vulns.SetAliases(null);
            VulnResult r0 = Vulns.Run(svcs, new[] { dir }, kev, epss, new List<RowFilter>(), "t", "t");
            foreach (string[] row in r0.Rows) if (row[7] == "CVE-2026-0010") bad.Add("former-name CVE matched without the alias table");
            bool osRow = false; foreach (string[] row in r0.Rows) if (row[0] == "deb" && row[7] == "CVE-2026-0013") osRow = true;
            if (!osRow) bad.Add("OS KEV entry missing without the platform list");
            Vulns.SetAliases("{\"version\":\"t\",\"aliases\":[[\"a:ivanti:connect_secure\",\"a:pulsesecure:pulse_connect_secure\"]],\"platforms\":[\"o:debian:debian_linux\",\"o:microsoft:windows*\"]}");
            VulnResult r = Vulns.Run(svcs, new[] { dir }, kev, epss, new List<RowFilter>(), "t", "t");
            Vulns.SetAliases(null);
            List<string> got = new List<string>();
            foreach (string[] row in r.Rows) got.Add(row[0] + " " + row[7] + " " + row[18] + (row[8] == "Yes" ? " kev" : "") + (row[12].Length > 0 ? " epss=" + row[12] : ""));
            got.Sort(StringComparer.Ordinal);
            string want = "ci CVE-2026-0006 product-only kev epss=0.9|ci CVE-2026-0007 product-only (dropped)|php-lin CVE-2026-0005 range (platform not verified)|php-win CVE-2026-0005 range|" +
                "ssh-a CVE-2026-0001 range epss=0.5|ssh-b CVE-2026-0001 range epss=0.5|ssh-b CVE-2026-0002 version|web-a CVE-2026-0003 version|web-b CVE-2026-0004 range|" +
                "vpn CVE-2026-0010 version (as pulsesecure:pulse_connect_secure)|iot CVE-2026-0011 range|vpn CVE-2026-0012 range (platform not verified)";
            List<string> w = new List<string>(want.Split('|'));
            w.RemoveAll(delegate(string x) { return x.EndsWith("(dropped)", StringComparison.Ordinal); });
            w.Sort(StringComparer.Ordinal);
            if (string.Join("|", got) != string.Join("|", w)) bad.Add("rows: " + string.Join("|", got));
            return string.Join("; ", bad);
        }
}
}
