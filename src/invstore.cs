
// ============================================================================
// WebInv inventory store
//   <Store>\STORE.json            identity, engine, schema, retire threshold
//   <Store>\LOCK                  held (FileShare.None) while a process has the store open
//   <Store>\store.log             what the store did, append-only
//   <Store>\db\                   working database (ESENT inventory.edb + logs, or inventory.kv) - rebuildable
//   <Store>\archive\ledger.jsonl  one line per run / correction / rebase, each carrying the SHA-256 of the previous line
//   <Store>\archive\corrections\<seq>-<op>\   manual merge/split: correction.json + derived changes
//   <Store>\archive\rebase\<seq>\<pos>\      derived files of a replay in a new order (backfilled runs)
//   <Store>\archive\anchors\<seq>.p7s         optional detached signatures of ledger lines
//   <Store>\archive\runs\yyyy\MM\<RunId>\   immutable inputs (results, checked keys, run.json, CSV, HTML, logs,
//                                 manifest) + INPUTS.json, and derived changes.jsonl.gz / state.jsonl.gz
// Database keys (seq = position in the applied plan; equal to the ledger seq until a rebase): m (meta), r/<seq> run or correction, ri/<runId>, k/<sha(natural key)> -> entity id, e/<eid> entity,
// v/<eid>/<ver> version, c/<seq>/<eid> change event, x/<eid>/<seq> per-entity event index.
// ============================================================================
namespace WebInv
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Text;

    public sealed class LedgerEntry
    {
        public long Seq;
        public int RetireAfter;
        public bool Snapshot = true, Backfill;
        public string Type = "", RunId = "", RunStarted = "", Path = "", StateDigest = "", ChangesDigest = "", Line = "", Hash = "", Prev = "";
        public Dictionary<string, object> Obj;
    }

    public sealed class IngestSummary
    {
        public string RunId = "", Archive = "", StateDigest = "", ChangesDigest = "", LedgerHead = "", Profile = "";
        public long Seq, Rows, Duplicates, Incomplete, Added, Changed, Enriched, Reappeared, Rekeyed, Missing, Retired, Active, MissingTotal, RetiredTotal;
        public bool AlreadyPresent, Partial;
        public string Void = "";
        public double Seconds;
        public readonly List<string> Phases = new List<string>();
        Stopwatch lap = Stopwatch.StartNew();
        public void Lap(string name) { Phases.Add(name + "=" + lap.Elapsed.TotalSeconds.ToString("0.00", CultureInfo.InvariantCulture)); lap.Restart(); }
        public string Text()
        {
            return string.Format(CultureInfo.InvariantCulture,
                "run {0} (seq {1}): {2} rows -> added {3}, changed {4}, reappeared {5}, rekeyed {6}, missing {7}, retired {8}; inventory now {9} active, {10} missing, {11} retired{12}{13}{15} in {14:0.0}s",
                RunId, Seq, Rows, Added, Changed, Reappeared, Rekeyed, Missing, Retired, Active, MissingTotal, RetiredTotal,
                Duplicates > 0 ? "; " + Duplicates + " duplicate rows ignored" : "", Incomplete > 0 ? "; " + Incomplete + " incomplete observations (no version change)" : "", Seconds,
                Enriched > 0 ? "; " + Enriched + " enriched by newly enabled probes" : "");
        }
    }

    public sealed partial class InventoryStore : IDisposable
    {
        public const int Format = 1;
        public readonly string Root, DbDir, ArchiveDir, RunsDir, LedgerPath, StoreJsonPath, LogPath;
        public string Engine { get; private set; }
        public string StoreId { get; private set; }
        public int RetireAfter { get; private set; }
        public string ScannerVersion = "";
        public readonly List<string> Messages = new List<string>();
        string created = "";
        KvEngine kv;
        FileStream lockFs;
        bool shadow;
        const int Batch = 200;
        // self-test hook: "rows:N" (after the Nth row batch) | "absence" | "derived" - flush what is committed, then fail
        // the way a crash would; the next open must finish the run with identical results
        public static string FailPoint = "";
        void Fail(string point)
        {
            if (FailPoint.Length == 0 || FailPoint != point) return;
            FailPoint = "";
            kv.Flush();
            throw new IOException("failpoint " + point);
        }
        static readonly string Zero64 = new string('0', 64);

        InventoryStore(string root)
        {
            Root = Path.GetFullPath(root);
            DbDir = Path.Combine(Root, "db");
            ArchiveDir = Path.Combine(Root, "archive");
            RunsDir = Path.Combine(ArchiveDir, "runs");
            LedgerPath = Path.Combine(ArchiveDir, "ledger.jsonl");
            StoreJsonPath = Path.Combine(Root, "STORE.json");
            LogPath = Path.Combine(Root, "store.log");
            Engine = ""; StoreId = ""; RetireAfter = 3;
        }

        public static string ResolveEngine(string requested)
        {
            string r = (requested ?? "auto").Trim().ToLowerInvariant();
            if (r.Length == 0 || r == "auto") return EsentKv.Available ? "esent" : "file";
            if (r != "esent" && r != "file") throw new ArgumentException("unknown store engine '" + requested + "' (Auto, Esent or File)");
            if (r == "esent" && !EsentKv.Available) throw new InvalidOperationException("ESENT (esent.dll) is not available on this system; use -StoreEngine File");
            return r;
        }

        // mode: write = create if missing + bring the database up to date with the archive; read = must exist, same
        // catch-up; verify / rebuild = must exist, no catch-up (verify opens an existing database read-mostly, rebuild none)
        public static InventoryStore Open(string root, string engine, int retireAfter, string scannerVersion, string mode, int lockWaitMs)
        {
            InventoryStore s = new InventoryStore(root);
            s.ScannerVersion = scannerVersion ?? "";
            bool exists = File.Exists(s.StoreJsonPath);
            if (!exists && mode != "write") throw new FileNotFoundException("no inventory store at " + s.Root + " (STORE.json not found)");
            try
            {
                Directory.CreateDirectory(s.Root);
                s.AcquireLock(lockWaitMs);
                if (!exists) s.Create(engine, retireAfter);
                else s.Load(engine, retireAfter, mode);
                if (mode == "verify")
                {
                    if (s.DbExists() && (s.Engine != "esent" || EsentKv.Available)) s.kv = s.OpenEngine();
                }
                else if (mode != "rebuild")
                {
                    s.kv = s.OpenEngine();
                    s.Reconcile();
                }
                return s;
            }
            catch { s.Dispose(); throw; }
        }

        bool DbExists() { return File.Exists(Path.Combine(DbDir, Engine == "esent" ? "inventory.edb" : "inventory.kv")); }
        KvEngine OpenEngine()
        {
            Directory.CreateDirectory(DbDir);
            if (Engine == "esent") return new EsentKv(DbDir);
            return new FileKv(Path.Combine(DbDir, "inventory.kv"));
        }

        void AcquireLock(int waitMs)
        {
            string p = Path.Combine(Root, "LOCK");
            DateTime until = DateTime.UtcNow.AddMilliseconds(Math.Max(0, waitMs));
            while (true)
            {
                try { lockFs = new FileStream(p, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); break; }
                catch (IOException)
                {
                    if (DateTime.UtcNow >= until) throw new IOException("the inventory store " + Root + " is in use by another process");
                    System.Threading.Thread.Sleep(250);
                }
            }
            byte[] b = StoreUtil.B(string.Format(CultureInfo.InvariantCulture, "pid={0} host={1} since={2}\n", Process.GetCurrentProcess().Id, Environment.MachineName, StoreUtil.Iso(DateTimeOffset.Now)));
            lockFs.SetLength(0); lockFs.Write(b, 0, b.Length); lockFs.Flush();
        }

        void Log(string m)
        {
            Messages.Add(m);
            if (shadow) return;
            try { File.AppendAllText(LogPath, StoreUtil.Iso(DateTimeOffset.Now) + " " + m + "\r\n", StoreUtil.Utf8); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }

        // ---------------------------------------------------------------- STORE.json
        void Create(string engine, int retireAfter)
        {
            Engine = ResolveEngine(engine);
            RetireAfter = retireAfter > 0 ? retireAfter : 3;
            Directory.CreateDirectory(RunsDir);
            created = StoreUtil.Iso(DateTimeOffset.Now);
            List<string> problems = new List<string>();
            List<LedgerEntry> led = File.Exists(LedgerPath) ? ReadLedger(problems) : new List<LedgerEntry>();
            if (led.Count > 0 && led[0].Type == "genesis")
            {
                StoreId = StoreUtil.Str(led[0].Obj, "storeId");
                created = StoreUtil.Str(led[0].Obj, "created");
                Log("STORE.json was missing; recreated it from the archive ledger (store " + StoreId + ")");
            }
            else
            {
                if (led.Count > 0) throw new InvalidDataException("archive ledger exists but has no genesis line: " + LedgerPath);
                StoreId = Guid.NewGuid().ToString("D");
                AppendLedger(new JsonObj().Num("seq", 0).Str("type", "genesis").Str("storeId", StoreId).Str("created", created).Num("format", Format).Num("schema", InvSchema.Version), Zero64);
                WriteReadme();
                Log(string.Format(CultureInfo.InvariantCulture, "created store {0} at {1} (engine {2}, a service is retired after {3} consecutive in-scope runs without it)", StoreId, Root, Engine, RetireAfter));
            }
            SaveStoreJson();
        }

        void SaveStoreJson()
        {
            JsonObj jo = new JsonObj().Num("format", Format).Num("schema", InvSchema.Version).Str("storeId", StoreId).Str("created", created).Str("engine", Engine)
                .Num("retireAfter", RetireAfter);
            if (SnapshotEvery > 1) jo.Num("snapshotEvery", SnapshotEvery);
            if (AnchorEventLog) jo.Bool("anchorEventLog", true);
            if (AnchorCertificate.Length > 0) jo.Str("anchorCertificate", AnchorCertificate).Num("anchorFrom", AnchorFrom);
            string j = jo.Str("updatedBy", "WebInventory " + ScannerVersion).Str("updated", StoreUtil.Iso(DateTimeOffset.Now)).ToString();
            StoreUtil.WriteAllTextAtomic(StoreJsonPath, j + "\n");
        }

        void Load(string engine, int retireAfter, string mode)
        {
            Dictionary<string, object> o = StoreJson.Parse(File.ReadAllText(StoreJsonPath, StoreUtil.Utf8)) as Dictionary<string, object>;
            if (o == null) throw new InvalidDataException("STORE.json is not a JSON object");
            if (StoreUtil.Num(o, "format") > Format) throw new InvalidDataException("the store was created by a newer WebInventory version (format " + StoreUtil.Str(o, "format") + ")");
            if (StoreUtil.Num(o, "schema") != InvSchema.Version) throw new InvalidDataException("the store uses inventory schema " + StoreUtil.Str(o, "schema") + "; this version uses " + InvSchema.Version);
            StoreId = StoreUtil.Str(o, "storeId"); created = StoreUtil.Str(o, "created"); Engine = StoreUtil.Str(o, "engine");
            int ra = (int)StoreUtil.Num(o, "retireAfter"); RetireAfter = ra > 0 ? ra : 3;
            int se = (int)StoreUtil.Num(o, "snapshotEvery"); SnapshotEvery = se > 0 ? se : 1;
            AnchorEventLog = StoreUtil.Str(o, "anchorEventLog") == "True"; AnchorCertificate = StoreUtil.Str(o, "anchorCertificate"); AnchorFrom = StoreUtil.Num(o, "anchorFrom");
            string req = (engine ?? "auto").Trim().ToLowerInvariant();
            if (mode != "rebuild" && req != "" && req != "auto" && req != Engine)
                throw new InvalidOperationException("the store database uses the " + Engine + " engine; to switch, rebuild it from the archive: -RebuildStore -StoreEngine " + req);
            if (mode != "rebuild" && mode != "verify" && Engine == "esent" && !EsentKv.Available)
                throw new InvalidOperationException("the store database uses ESENT, which this system does not have; -RebuildStore -StoreEngine File builds a portable database from the archive");
            if (retireAfter > 0 && retireAfter != RetireAfter && mode != "verify")
            {
                Log(string.Format(CultureInfo.InvariantCulture, "retire threshold changed from {0} to {1} (applies to runs ingested from now on; earlier runs keep theirs)", RetireAfter, retireAfter));
                RetireAfter = retireAfter;
                SaveStoreJson();
            }
        }

        void WriteReadme()
        {
            string t = "WebInventory inventory store\r\n" +
                "============================\r\n\r\n" +
                "archive\\        the long-term record. Never edit or delete files here.\r\n" +
                "  ledger.jsonl  one JSON line per ingested run; each line holds the SHA-256 of the line before it\r\n" +
                "                (\"prev\"), the SHA-256 of every file archived for the run, and digests of the derived files.\r\n" +
                "  runs\\yyyy\\MM\\<RunId>\\\r\n" +
                "    results.jsonl.gz   the scan's JSONL output, as written      results.csv.gz / report.html.gz  as written\r\n" +
                "    checked.txt.gz     every host|ip|port the run checked (decides what counts as absent)\r\n" +
                "    run.json           when, how (probe switches) and by whom the run was made\r\n" +
                "    INPUTS.json        hashes of the files above (archive copy and original)\r\n" +
                "    changes.jsonl.gz   change events this run produced (added/changed/missing/retired/reappeared/rekeyed)\r\n" +
                "    state.jsonl.gz     the whole inventory after this run (one JSON object per service)\r\n" +
                "db\\             working database (ESENT or file). Disposable: Invoke-WebInventory.ps1 -Store <here> -RebuildStore\r\n" +
                "                recreates it from archive\\ and checks every digest in the ledger.\r\n" +
                "Verify:         Invoke-WebInventory.ps1 -Store <here> -VerifyStore\r\n" +
                "Back up / move: copy archive\\ (and STORE.json). db\\ is tied to this Windows installation.\r\n";
            File.WriteAllText(Path.Combine(Root, "README.txt"), t, StoreUtil.Utf8);
        }

        // ---------------------------------------------------------------- ledger
        public List<LedgerEntry> ReadLedger(List<string> problems)
        {
            List<LedgerEntry> r = new List<LedgerEntry>();
            if (!File.Exists(LedgerPath)) { problems.Add("ledger not found: " + LedgerPath); return r; }
            string prev = Zero64; long expect = 0; int n = 0;
            foreach (string line in StoreUtil.ReadLines(LedgerPath))
            {
                n++;
                LedgerEntry e = new LedgerEntry();
                e.Line = line; e.Hash = StoreUtil.Sha256Hex(line);
                try { e.Obj = StoreJson.Parse(line) as Dictionary<string, object>; }
                catch (Exception ex) { problems.Add("ledger line " + n + " is not valid JSON (" + ex.Message + ")"); break; }
                if (e.Obj == null) { problems.Add("ledger line " + n + " is not a JSON object"); break; }
                e.Seq = StoreUtil.Num(e.Obj, "seq"); e.Type = StoreUtil.Str(e.Obj, "type"); e.Prev = StoreUtil.Str(e.Obj, "prev");
                e.RunId = StoreUtil.Str(e.Obj, "runId"); e.RunStarted = StoreUtil.Str(e.Obj, "runStarted"); e.Path = StoreUtil.Str(e.Obj, "path");
                e.StateDigest = StoreUtil.Str(e.Obj, "stateDigest"); e.ChangesDigest = StoreUtil.Str(e.Obj, "changesDigest");
                e.RetireAfter = (int)StoreUtil.Num(e.Obj, "retireAfter");
                e.Snapshot = StoreUtil.Str(e.Obj, "snapshot") != "False"; e.Backfill = StoreUtil.Str(e.Obj, "backfill") == "True";
                if (e.Prev != prev) problems.Add("ledger line " + n + " (seq " + e.Seq + "): 'prev' does not match the SHA-256 of the line before it");
                if (e.Seq != expect) problems.Add("ledger line " + n + ": seq " + e.Seq + ", expected " + expect);
                if (n == 1 && e.Type != "genesis") problems.Add("ledger line 1 is not the genesis line");
                if (n > 1 && e.Type != "run" && e.Type != "correction" && e.Type != "rebase") problems.Add("ledger line " + n + ": unknown type '" + e.Type + "'");
                prev = e.Hash; expect = e.Seq + 1;
                r.Add(e);
            }
            return r;
        }

        string AppendLedger(JsonObj o, string prev)
        {
            string line = o.Str("prev", prev).ToString();
            byte[] b = StoreUtil.B(line + "\n");
            using (FileStream fs = new FileStream(LedgerPath, FileMode.Append, FileAccess.Write, FileShare.Read))
            {
                fs.Write(b, 0, b.Length);
                fs.Flush(true);
            }
            string h = StoreUtil.Sha256Hex(line);
            Appended.Add(new string[] { StoreUtil.Str(StoreJson.Parse(line) as Dictionary<string, object>, "seq"), h, line });
            return h;
        }

        // a crash while appending can leave a torn final line: drop it (its run folder is then finished again as pending)
        bool RepairLedgerTail()
        {
            byte[] all = File.ReadAllBytes(LedgerPath);
            if (all.Length == 0 || all[all.Length - 1] == (byte)'\n') return false;
            int cut = Array.LastIndexOf(all, (byte)'\n') + 1;
            using (FileStream fs = new FileStream(LedgerPath, FileMode.Open, FileAccess.Write, FileShare.None)) { fs.SetLength(cut); fs.Flush(true); }
            Log("ledger: removed a torn final line (" + (all.Length - cut) + " bytes) left by an interrupted write");
            return true;
        }

        List<LedgerEntry> ReadLedgerStrict()
        {
            List<string> problems = new List<string>();
            List<LedgerEntry> led = ReadLedger(problems);
            if (problems.Count > 0 && !shadow && RepairLedgerTail()) { problems.Clear(); led = ReadLedger(problems); }
            if (problems.Count > 0) throw new InvalidDataException("archive ledger failed its integrity check: " + problems[0] + " (-VerifyStore reports everything)");
            return led;
        }

        public string LedgerHead()
        {
            List<string> problems = new List<string>();
            List<LedgerEntry> led = ReadLedger(problems);
            return led.Count > 0 ? led[led.Count - 1].Hash : "";
        }

        // ---------------------------------------------------------------- keys and records
        static readonly byte[] MetaKey = StoreUtil.B("m\0");
        static byte[] P(string t) { return StoreUtil.B(t + "\0"); }
        static byte[] P(string t, string a) { return StoreUtil.B(t + "\0" + a + "\0"); }
        static byte[] K(string t, string a) { return StoreUtil.B(t + "\0" + a); }
        static byte[] K(string t, string a, string b) { return StoreUtil.B(t + "\0" + a + "\0" + b); }
        static byte[] NkKey(string nk)
        {
            Sha256Acc a = Sha256Acc.Shared;
            a.Append(StoreUtil.B(nk));
            byte[] h = a.Final();
            byte[] k = new byte[18]; k[0] = (byte)'k'; k[1] = 0; Buffer.BlockCopy(h, 0, k, 2, 16);
            return k;
        }
        static byte[] EntKey(string eid) { return K("e", eid); }
        static byte[] VerKey(string eid, long ver) { return K("v", eid, StoreUtil.D10(ver)); }
        static byte[] EvKey(long seq, string eid) { return K("c", StoreUtil.D10(seq), eid); }
        static byte[] XKey(string eid, long seq) { return K("x", eid, StoreUtil.D10(seq)); }
        static byte[] RunKey(long seq) { return K("r", StoreUtil.D10(seq)); }
        static byte[] RunIdKey(string runId) { return K("ri", runId); }
        Rec Get(byte[] k) { return Rec.Decode(kv.Get(k)); }
        void Put(byte[] k, Rec r) { kv.Put(k, r.Encode()); }
        Rec RunByRunId(string runId)
        {
            byte[] s = kv.Get(RunIdKey(runId));
            return s == null ? null : Get(RunKey(long.Parse(StoreUtil.S(s), CultureInfo.InvariantCulture)));
        }
        Rec Ver(string eid, long ver)
        {
            Rec v = Get(VerKey(eid, ver));
            if (v == null) throw new InvalidDataException("entity " + eid + " has no version " + ver);
            return v;
        }

        // ---------------------------------------------------------------- bring the database up to the archive
        // (Reconcile: see invstore2.cs - plan based, handles corrections and rebases)

        // archived run folders (relative paths, '/' separated), oldest first by run start
        List<string> ArchivedFolders()
        {
            List<KeyValuePair<DateTimeOffset, string>> r = new List<KeyValuePair<DateTimeOffset, string>>();
            if (!Directory.Exists(RunsDir)) return new List<string>();
            foreach (string y in Directory.GetDirectories(RunsDir))
                foreach (string m in Directory.GetDirectories(y))
                    foreach (string d in Directory.GetDirectories(m))
                    {
                        DateTimeOffset t = DateTimeOffset.MinValue;
                        string rj = Path.Combine(d, "run.json");
                        try { if (File.Exists(rj)) t = RunInfo.Parse(File.ReadAllText(rj, StoreUtil.Utf8)).Started; } catch (Exception) { }
                        r.Add(new KeyValuePair<DateTimeOffset, string>(t, "runs/" + Path.GetFileName(y) + "/" + Path.GetFileName(m) + "/" + Path.GetFileName(d)));
                    }
            r.Sort(delegate(KeyValuePair<DateTimeOffset, string> a, KeyValuePair<DateTimeOffset, string> b) { int c = a.Key.CompareTo(b.Key); return c != 0 ? c : string.CompareOrdinal(a.Value, b.Value); });
            List<string> o = new List<string>();
            foreach (KeyValuePair<DateTimeOffset, string> kv2 in r) o.Add(kv2.Value);
            return o;
        }
        string AbsRun(string rel) { return Path.Combine(ArchiveDir, rel.Replace('/', Path.DirectorySeparatorChar)); }

        // ---------------------------------------------------------------- ingest a finished scan
        static readonly System.Text.RegularExpressions.Regex RunIdRx = new System.Text.RegularExpressions.Regex(@"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$");

        public IngestSummary Ingest(RunSources src, bool allowPartial)
        {
            if (kv == null || shadow) throw new InvalidOperationException("store not open for writing");
            Stopwatch sw = Stopwatch.StartNew();
            List<LedgerEntry> led = ReadLedgerStrict();
            RunInfo run; LedgerEntry dupEntry, lastRun;
            CheckRun(src, allowPartial, led, out run, out dupEntry, out lastRun);
            if (dupEntry != null)
            {
                IngestSummary dup = new IngestSummary(); dup.RunId = run.RunId; dup.Seq = dupEntry.Seq; dup.AlreadyPresent = true; dup.Archive = dupEntry.Path;
                return dup;
            }
            if (lastRun != null && run.Started < StoreUtil.ParseIso(lastRun.RunStarted))
                throw new InvalidOperationException("run " + run.RunId + " (started " + run.StartedAt + ") is older than the newest run in the store (" + lastRun.RunId + ", " + lastRun.RunStarted + "); add -Backfill to insert it in time order (the database is then replayed)");
            double tValidate, tCopy; long rows;
            string rel = ArchiveRun(src, run, out rows, out tValidate, out tCopy);
            List<PlanItem> plan = BuildPlan(led);
            long seq = plan.Count + 1;
            bool snap = SnapshotFor(plan, true);
            IngestSummary s = ApplyArchived(rel, seq, RetireAfter, AbsRun(rel), snap);
            s.Phases.Insert(0, "validate=" + tValidate.ToString("0.00", CultureInfo.InvariantCulture)); s.Phases.Insert(1, "archive=" + tCopy.ToString("0.00", CultureInfo.InvariantCulture));
            s.LedgerHead = AppendRunLedger(rel, s, RetireAfter, led, snap);
            s.Partial = !run.Complete;
            if (rows != s.Rows + s.Duplicates) throw new InvalidDataException("row count changed while ingesting (" + rows + " vs " + (s.Rows + s.Duplicates) + ")");
            s.Seconds = sw.Elapsed.TotalSeconds;
            Log("ingested " + s.Text() + "; ledger head " + s.LedgerHead);
            Log("ingest phases (s): " + string.Join(" ", s.Phases));
            return s;
        }

        void CheckRun(RunSources src, bool allowPartial, List<LedgerEntry> led, out RunInfo run, out LedgerEntry dup, out LedgerEntry lastRun)
        {
            if (src.RunId == null || !RunIdRx.IsMatch(src.RunId)) throw new ArgumentException("invalid RunId '" + src.RunId + "'");
            if (string.IsNullOrEmpty(src.Jsonl) || !File.Exists(src.Jsonl)) throw new FileNotFoundException("results file not found: " + src.Jsonl);
            if (string.IsNullOrEmpty(src.Progress) || !File.Exists(src.Progress))
                throw new FileNotFoundException("progress file not found: " + src.Progress + " (it lists the checks the run made; without it a missing service cannot be told from one that was not scanned)");
            bool haveRunJson = !string.IsNullOrEmpty(src.RunJson) && File.Exists(src.RunJson);
            run = haveRunJson ? RunInfo.Parse(File.ReadAllText(src.RunJson, StoreUtil.Utf8)) : RunInfo.Synthesize(src.RunId, src.Jsonl, src.Progress);
            if (run.RunId != src.RunId) throw new InvalidDataException("run.json is for run " + run.RunId + ", not " + src.RunId);
            dup = null; lastRun = null;
            DateTimeOffset newest = DateTimeOffset.MinValue;
            foreach (LedgerEntry e in led)
            {
                if (e.Type != "run") continue;
                if (e.RunId == run.RunId) dup = e;
                DateTimeOffset t = StoreUtil.ParseIso(e.RunStarted);
                if (lastRun == null || t >= newest) { lastRun = e; newest = t; }
            }
            if (dup == null && !run.Complete && !allowPartial) throw new InvalidOperationException("run " + run.RunId + " did not complete; finish it with -Resume (or import the partial run with -Force)");
        }

        // validates the run's files and copies them into archive\runs\yyyy\MM\<RunId> (INPUTS.json last)
        string ArchiveRun(RunSources src, RunInfo run, out long rows, out double tValidate, out double tCopy)
        {
            Stopwatch ph = Stopwatch.StartNew();
            rows = ValidateResults(src.Jsonl);
            tValidate = ph.Elapsed.TotalSeconds; ph.Restart();
            foreach (string l in StoreUtil.ReadLines(src.Progress)) { string t = l.Trim(); if (t.Length > 0 && t.Split('|').Length < 3) throw new InvalidDataException("progress file line is not host|ip|port: '" + t + "'"); }
            bool haveRunJson = !string.IsNullOrEmpty(src.RunJson) && File.Exists(src.RunJson);
            DateTimeOffset st = run.Started;
            string rel = "runs/" + st.ToString("yyyy", CultureInfo.InvariantCulture) + "/" + st.ToString("MM", CultureInfo.InvariantCulture) + "/" + run.RunId;
            string dir = AbsRun(rel);
            Directory.CreateDirectory(dir);
            string inputsPath = Path.Combine(dir, "INPUTS.json");
            if (File.Exists(inputsPath)) File.Delete(inputsPath);
            List<string> inputs = new List<string>();
            inputs.Add(CopyIn(src.Jsonl, dir, "results.jsonl.gz", true));
            inputs.Add(CopyIn(src.Progress, dir, "checked.txt.gz", true));
            if (haveRunJson) inputs.Add(CopyIn(src.RunJson, dir, "run.json", false));
            else { File.WriteAllText(Path.Combine(dir, "run.json"), run.ToJson() + "\n", StoreUtil.Utf8); inputs.Add(Describe(dir, "run.json", "(synthesized at import)", "", 0)); }
            if (!string.IsNullOrEmpty(src.Csv) && File.Exists(src.Csv)) inputs.Add(CopyIn(src.Csv, dir, "results.csv.gz", true));
            if (!string.IsNullOrEmpty(src.Html) && File.Exists(src.Html)) inputs.Add(CopyIn(src.Html, dir, "report.html.gz", true));
            if (!string.IsNullOrEmpty(src.Delta) && File.Exists(src.Delta)) inputs.Add(CopyIn(src.Delta, dir, "delta.csv.gz", true));
            if (!string.IsNullOrEmpty(src.Manifest) && File.Exists(src.Manifest)) inputs.Add(CopyIn(src.Manifest, dir, "manifest.txt", false));
            HashSet<string> logNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string lg in src.Logs)
            {
                if (string.IsNullOrEmpty(lg) || !File.Exists(lg)) continue;
                string nm = Path.GetFileName(lg) + ".gz";
                if (!logNames.Add(nm)) continue;
                Directory.CreateDirectory(Path.Combine(dir, "logs"));
                inputs.Add(CopyIn(lg, dir, "logs/" + nm, true));
            }
            StoreUtil.WriteAllTextAtomic(inputsPath, new JsonObj().Str("runId", run.RunId).Raw("files", "[" + string.Join(",", inputs) + "]").ToString() + "\n");
            tCopy = ph.Elapsed.TotalSeconds;
            return rel;
        }

        static long ValidateResults(string path)
        {
            long n = 0, line = 0;
            foreach (string l in StoreUtil.ReadLines(path))
            {
                line++;
                if (l.Length == 0) continue;
                Dictionary<string, object> o;
                try { o = StoreJson.Parse(l) as Dictionary<string, object>; }
                catch (Exception ex) { throw new InvalidDataException("results line " + line + " is not valid JSON: " + ex.Message); }
                if (o == null || StoreUtil.Str(o, "Host").Length == 0 || StoreUtil.Str(o, "Port").Length == 0)
                    throw new InvalidDataException("results line " + line + " has no Host/Port");
                n++;
            }
            return n;
        }

        string CopyIn(string src, string dir, string name, bool gz)
        {
            string dst = Path.Combine(dir, name.Replace('/', Path.DirectorySeparatorChar));
            long srcBytes;
            string srcSha;
            if (gz) srcSha = StoreUtil.CopyToGz(src, dst, out srcBytes);
            else { File.Copy(src, dst, true); srcSha = StoreUtil.FileSha256(dst, out srcBytes); }
            return Describe(dir, name, Path.GetFileName(src), srcSha, srcBytes);
        }
        static string Describe(string dir, string name, string source, string srcSha, long srcBytes)
        {
            long bytes;
            string sha = StoreUtil.FileSha256(Path.Combine(dir, name.Replace('/', Path.DirectorySeparatorChar)), out bytes);
            JsonObj o = new JsonObj().Str("name", name).Str("sha256", sha).Num("bytes", bytes).Str("source", source);
            if (srcSha.Length > 0) o.Str("sourceSha256", srcSha).Num("sourceBytes", srcBytes);
            return o.ToString();
        }

        string AppendRunLedger(string rel, IngestSummary s, int retireAfter, List<LedgerEntry> led, bool snapshot)
        {
            string dir = AbsRun(rel);
            Dictionary<string, object> inputs = StoreJson.Parse(File.ReadAllText(Path.Combine(dir, "INPUTS.json"), StoreUtil.Utf8)) as Dictionary<string, object>;
            List<string> files = new List<string>();
            foreach (object f in (System.Collections.IEnumerable)StoreUtil.Field(inputs, "files"))
            {
                Dictionary<string, object> d = (Dictionary<string, object>)f;
                files.Add(new JsonObj().Str("name", StoreUtil.Str(d, "name")).Str("sha256", StoreUtil.Str(d, "sha256")).Num("bytes", StoreUtil.Num(d, "bytes")).ToString());
            }
            long b;
            files.Add(new JsonObj().Str("name", "INPUTS.json").Str("sha256", StoreUtil.FileSha256(Path.Combine(dir, "INPUTS.json"), out b)).Num("bytes", b).ToString());
            List<string> derived = new List<string>();
            foreach (string n in snapshot ? new[] { "changes.jsonl.gz", "state.jsonl.gz" } : new[] { "changes.jsonl.gz" })
                derived.Add(new JsonObj().Str("name", n).Str("sha256", StoreUtil.FileSha256(Path.Combine(dir, n), out b)).Num("bytes", b).ToString());
            RunInfo run = RunInfo.Parse(File.ReadAllText(Path.Combine(dir, "run.json"), StoreUtil.Utf8));
            JsonObj counts = new JsonObj().Num("rows", s.Rows).Num("duplicates", s.Duplicates).Num("incomplete", s.Incomplete).Num("added", s.Added).Num("changed", s.Changed).Num("enriched", s.Enriched)
                .Num("reappeared", s.Reappeared).Num("rekeyed", s.Rekeyed).Num("missing", s.Missing).Num("retired", s.Retired)
                .Num("active", s.Active).Num("missingTotal", s.MissingTotal).Num("retiredTotal", s.RetiredTotal);
            long lseq = led.Count > 0 ? led[led.Count - 1].Seq + 1 : 1;
            JsonObj o = new JsonObj().Num("seq", lseq).Str("type", "run").Str("runId", s.RunId).Str("runStarted", run.StartedAt).Str("path", rel)
                .Bool("complete", run.Complete).Num("retireAfter", retireAfter).Str("profile", run.Profile).Str("engine", Engine).Str("ingestedBy", "WebInventory " + ScannerVersion)
                .Str("ingestedAt", StoreUtil.Iso(DateTimeOffset.Now)).Raw("files", "[" + string.Join(",", files) + "]").Raw("derived", "[" + string.Join(",", derived) + "]")
                .Str("changesDigest", s.ChangesDigest).Str("stateDigest", s.StateDigest).Raw("counts", counts.ToString());
            if (!snapshot) o.Bool("snapshot", false);
            if (lseq != s.Seq) o.Num("pos", s.Seq);
            string prev = led.Count > 0 ? led[led.Count - 1].Hash : Zero64;
            string head = AppendLedger(o, prev);
            kv.Begin();
            Rec meta = Get(MetaKey) ?? new Rec();
            meta["ledgerHead"] = head; Put(MetaKey, meta);
            kv.Commit(true); kv.Flush();
            return head;
        }

        // ---------------------------------------------------------------- apply one archived run (idempotent)
        sealed class Obs
        {
            public string Nk, Host, Ip, Port, Vh, Url;
            public Rec Mat = new Rec(), Seen = new Rec();
            public bool Incomplete;
            public static Obs From(Dictionary<string, object> o)
            {
                Obs b = new Obs();
                b.Host = StoreUtil.Str(o, "Host"); b.Ip = StoreUtil.Str(o, "IP").ToLowerInvariant(); b.Port = StoreUtil.Str(o, "Port");
                b.Vh = StoreUtil.Str(o, "Vhost") == "True" ? "v" : "";
                b.Nk = b.Host.ToLowerInvariant() + "|" + b.Ip + "|" + b.Port + "|" + b.Vh;
                foreach (string f in InvSchema.Material) { string v = StoreUtil.Str(o, f); if (v.Length > 0) b.Mat[f] = v; }
                foreach (string f in InvSchema.Observed) { string v = StoreUtil.Str(o, f); if (v.Length > 0) b.Seen[f] = v; }
                b.Url = b.Mat["Url"];
                b.Incomplete = b.Seen["Notes"].IndexOf("incomplete:", StringComparison.OrdinalIgnoreCase) >= 0;
                return b;
            }
        }

        IngestSummary ApplyArchived(string rel, long seq, int retireAfter, string derivedDir, bool snapshot)
        {
            bool writeDerived = derivedDir != null;
            if (writeDerived) Directory.CreateDirectory(derivedDir);
            Stopwatch sw = Stopwatch.StartNew();
            string dir = AbsRun(rel);
            CheckInputs(dir);
            RunInfo run = RunInfo.Parse(File.ReadAllText(Path.Combine(dir, "run.json"), StoreUtil.Utf8));
            string at = StoreUtil.Iso(run.Started);
            HashSet<string> hostPort = new HashSet<string>(StringComparer.Ordinal), ipPort = new HashSet<string>(StringComparer.Ordinal);
            foreach (string l in StoreUtil.ReadLines(Path.Combine(dir, "checked.txt.gz")))
            {
                string[] p = l.Trim().Split('|');
                if (p.Length < 3) continue;
                hostPort.Add(p[0].ToLowerInvariant() + "|" + p[2]);
                ipPort.Add(p[1].ToLowerInvariant() + "|" + p[2]);
            }
            Rec rr = RunByRunId(run.RunId);
            if (rr != null && rr.Long("seq") != seq)
                throw new InvalidDataException("run " + run.RunId + " is seq " + rr["seq"] + " in the database but seq " + seq + " in the archive; rebuild the database: -RebuildStore");
            if (rr == null)
            {
                rr = new Rec();
                rr.SetLong("seq", seq); rr["runId"] = run.RunId; rr["state"] = "ingesting"; rr["startedAt"] = run.StartedAt; rr["finishedAt"] = run.FinishedAt;
                rr["tag"] = run.Tag; rr["scanner"] = run.Scanner; rr["complete"] = run.Complete ? "True" : "False"; rr["profile"] = run.Profile;
                rr["archive"] = rel; rr.SetLong("retireAfter", retireAfter); rr["kind"] = "run";
                kv.Begin(); Put(RunKey(seq), rr); kv.Put(RunIdKey(run.RunId), StoreUtil.B(seq.ToString(CultureInfo.InvariantCulture))); kv.Commit(false);
            }
            IngestSummary s = new IngestSummary();
            s.RunId = run.RunId; s.Seq = seq; s.Archive = rel; s.Profile = run.Profile;
            s.Lap("inputs");
            ApplyRows(Path.Combine(dir, "results.jsonl.gz"), run, seq, at, s);
            s.Lap("rows");
            ApplyAbsence(run, seq, at, retireAfter, hostPort, ipPort);
            s.Lap("absence");
            ApplyRekeys(run, seq, at);
            s.Lap("rekey");
            Fail("derived");
            // derived files and counts (deterministic: key order)
            using (DigestWriter cw = new DigestWriter(writeDerived ? Path.Combine(derivedDir, "changes.jsonl.gz") : null))
            {
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("c", StoreUtil.D10(seq))))
                {
                    Rec ev = Rec.Decode(e.Value);
                    switch (ev["type"])
                    {
                        case "merged": case "split": break;
                        case "added": s.Added++; break;
                        case "changed": s.Changed++; break;
                        case "enriched": s.Enriched++; break;
                        case "reappeared": s.Reappeared++; break;
                        case "rekeyed": s.Rekeyed++; break;
                        case "missing": s.Missing++; break;
                        case "retired": s.Retired++; break;
                    }
                    cw.Line(EventJson(ev));
                }
                s.ChangesDigest = cw.Close();
            }
            s.Lap("changes");
            using (DigestWriter stw = new DigestWriter(writeDerived && snapshot ? Path.Combine(derivedDir, "state.jsonl.gz") : null))
            {
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
                {
                    Rec ent = Rec.Decode(e.Value);
                    switch (ent["st"]) { case "active": s.Active++; break; case "missing": s.MissingTotal++; break; default: s.RetiredTotal++; break; }
                    stw.Line(StateJson(InventoryRow(ent, Ver(ent["id"], ent.Long("ver")))));
                }
                s.StateDigest = stw.Close();
            }
            s.Lap("state");
            rr = Get(RunKey(seq));
            rr["state"] = "ingested"; rr["changesDigest"] = s.ChangesDigest; rr["stateDigest"] = s.StateDigest;
            rr.SetLong("rows", s.Rows); rr.SetLong("duplicates", s.Duplicates); rr.SetLong("incomplete", s.Incomplete);
            rr.SetLong("added", s.Added); rr.SetLong("changed", s.Changed); rr.SetLong("enriched", s.Enriched); rr.SetLong("reappeared", s.Reappeared); rr.SetLong("rekeyed", s.Rekeyed);
            rr.SetLong("missing", s.Missing); rr.SetLong("retired", s.Retired); rr.SetLong("active", s.Active); rr.SetLong("missingTotal", s.MissingTotal); rr.SetLong("retiredTotal", s.RetiredTotal);
            kv.Begin();
            Put(RunKey(seq), rr);
            Rec meta = Get(MetaKey) ?? new Rec();
            meta.SetLong("seq", seq); meta["runId"] = run.RunId; meta["stateDigest"] = s.StateDigest;
            Put(MetaKey, meta);
            kv.Commit(true);
            kv.Flush();
            s.Lap("commit");
            s.Seconds = sw.Elapsed.TotalSeconds;
            return s;
        }

        void CheckInputs(string dir)
        {
            string ip = Path.Combine(dir, "INPUTS.json");
            if (!File.Exists(ip)) throw new FileNotFoundException("archive folder has no INPUTS.json: " + dir);
            Dictionary<string, object> o = StoreJson.Parse(File.ReadAllText(ip, StoreUtil.Utf8)) as Dictionary<string, object>;
            System.Collections.IEnumerable files = StoreUtil.Field(o, "files") as System.Collections.IEnumerable;
            if (files == null) throw new InvalidDataException("INPUTS.json lists no files: " + dir);
            foreach (object f in files)
            {
                Dictionary<string, object> d = (Dictionary<string, object>)f;
                string name = StoreUtil.Str(d, "name"), path = Path.Combine(dir, name.Replace('/', Path.DirectorySeparatorChar));
                if (!File.Exists(path)) throw new FileNotFoundException("archived file missing: " + path);
                long bytes;
                if (StoreUtil.FileSha256(path, out bytes) != StoreUtil.Str(d, "sha256")) throw new InvalidDataException("archived file altered (SHA-256 mismatch): " + path);
            }
        }

        void ApplyRows(string results, RunInfo run, long seq, string at, IngestSummary s)
        {
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            int n = 0, batches = 0;
            kv.Begin();
            try
            {
                foreach (string line in StoreUtil.ReadLines(results))
                {
                    if (line.Length == 0) continue;
                    Obs ob = Obs.From((Dictionary<string, object>)StoreJson.Parse(line));
                    if (!seen.Add(ob.Nk)) { s.Duplicates++; continue; }
                    s.Rows++;
                    if (ob.Incomplete) s.Incomplete++;
                    Observe(ob, run, seq, at);
                    if (++n >= Batch) { kv.Commit(false); Fail("rows:" + (++batches).ToString(CultureInfo.InvariantCulture)); kv.Begin(); n = 0; }
                }
                kv.Commit(false);
            }
            catch { kv.Rollback(); throw; }
        }

        static string MakeId(string nk, string runId, int n)
        {
            return StoreUtil.Sha256Hex(nk + "\n" + runId + (n > 0 ? "\n" + n.ToString(CultureInfo.InvariantCulture) : "")).Substring(0, 16);
        }

        void Observe(Obs ob, RunInfo run, long seq, string at)
        {
            byte[] idb = kv.Get(NkKey(ob.Nk));
            if (idb == null) { AddEntity(ob, run, seq, at); return; }
            string eid = StoreUtil.S(idb);
            Rec ent = Get(EntKey(eid));
            if (ent == null) throw new InvalidDataException("key index points to a missing entity " + eid);
            if (ent.Long("ap") == seq) return;                  // applied before an interruption
            long curVer = ent.Long("ver");
            Rec cur = null;
            Rec mat = ob.Mat;
            if (run.NeedsCarryOver) { cur = Ver(eid, curVer); InvSchema.CarryOver(mat, cur, run); }
            string h = InvSchema.Hash(mat);
            bool absent = ent["st"] != "active";
            string type = null;
            List<string> diff = null;
            long to = curVer;
            if (!ob.Incomplete && h != ent["h"])
            {
                if (cur == null) cur = Ver(eid, curVer);
                diff = InvSchema.Diff(cur, mat);
                to = curVer + 1;
                PutVersion(eid, to, mat, seq, run, at, h);
                ent.SetLong("ver", to); ent["h"] = h; ent["ca"] = at;
                type = absent ? "reappeared" : (InvSchema.IsEnrichment(diff, cur, mat) ? "enriched" : "changed");
            }
            else if (absent) type = "reappeared";
            if (type != null)
            {
                Rec ev = NewEvent(type, seq, run, at, eid, ob.Host, ob.Ip, ob.Port, ob.Vh, ob.Url != "" ? ob.Url : (cur != null ? cur["Url"] : ""), curVer, to);
                if (diff != null) AddDiff(ev, diff, cur, mat);
                if (diff != null && cur["_prof"] != run.Profile) ev["pd"] = cur["_prof"] + " -> " + run.Profile;
                if (ob.Incomplete) ev["inc"] = "True";
                PutEvent(seq, eid, ev);
            }
            MarkSeen(ent, ob, run, seq, at);
            Put(EntKey(eid), ent);
        }

        void AddEntity(Obs ob, RunInfo run, long seq, string at)
        {
            string eid = null;
            for (int n = 0; n < 100; n++)
            {
                string c = MakeId(ob.Nk, run.RunId, n);
                Rec other = Get(EntKey(c));
                if (other == null || other["nk"] == ob.Nk) { eid = c; break; }
            }
            if (eid == null) throw new InvalidDataException("could not allocate an entity id for " + ob.Nk);
            string h = InvSchema.Hash(ob.Mat);
            PutVersion(eid, 1, ob.Mat, seq, run, at, h);
            Rec ent = new Rec();
            ent["id"] = eid; ent["nk"] = ob.Nk; ent["host"] = ob.Host; ent["ip"] = ob.Ip; ent["port"] = ob.Port; ent["vh"] = ob.Vh;
            ent["fa"] = at; ent["fr"] = run.RunId; ent.SetLong("ver", 1); ent["h"] = h; ent["ca"] = at;
            MarkSeen(ent, ob, run, seq, at);
            Put(EntKey(eid), ent);
            kv.Put(NkKey(ob.Nk), StoreUtil.B(eid));
            PutEvent(seq, eid, NewEvent("added", seq, run, at, eid, ob.Host, ob.Ip, ob.Port, ob.Vh, ob.Url, 0, 1));
        }

        static void MarkSeen(Rec ent, Obs ob, RunInfo run, long seq, string at)
        {
            ent["st"] = "active"; ent["la"] = at; ent["lr"] = run.RunId; ent.SetLong("ap", seq);
            ent.Remove("ms"); ent.Remove("mr"); ent.Remove("ra");
            ent.RemovePrefix("o:");
            foreach (string f in ob.Seen.Names) ent["o:" + f] = ob.Seen[f];
        }

        void PutVersion(string eid, long ver, Rec mat, long seq, RunInfo run, string at, string h)
        {
            Rec v = InvSchema.MaterialOf(mat);
            v.SetLong("_ver", ver); v.SetLong("_seq", seq); v["_run"] = run.RunId; v["_at"] = at; v["_h"] = h; v["_prof"] = run.Profile;
            Put(VerKey(eid, ver), v);
        }

        static Rec NewEvent(string type, long seq, RunInfo run, string at, string eid, string host, string ip, string port, string vh, string url, long from, long to)
        {
            Rec ev = new Rec();
            ev["type"] = type; ev.SetLong("seq", seq); ev["run"] = run.RunId; ev["at"] = at; ev["eid"] = eid;
            ev["host"] = host; ev["ip"] = ip; ev["port"] = port; ev["vh"] = vh; ev["url"] = url;
            ev.SetLong("from", from); ev.SetLong("to", to);
            return ev;
        }
        static void AddDiff(Rec ev, List<string> diff, Rec oldm, Rec newm)
        {
            if (diff.Count == 0) return;
            ev["fields"] = (ev["fields"].Length > 0 ? ev["fields"] + ";" : "") + string.Join(";", diff);
            foreach (string f in diff) { ev["was:" + f] = oldm == null ? "" : oldm[f]; ev["now:" + f] = newm[f]; }
        }
        void PutEvent(long seq, string eid, Rec ev)
        {
            Put(EvKey(seq, eid), ev);
            kv.Put(XKey(eid, seq), StoreUtil.B(ev["type"]));
        }

        // services the run checked (host|port, or for SAN virtual hosts the ip|port they were found on) but did not see
        void ApplyAbsence(RunInfo run, long seq, string at, int retireAfter, HashSet<string> hostPort, HashSet<string> ipPort)
        {
            int n = 0;
            kv.Begin();
            try
            {
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
                {
                    Rec ent = Rec.Decode(e.Value);
                    string st = ent["st"];
                    if (st == "retired" || ent.Long("ap") == seq) continue;
                    bool inScope = ent["vh"] == "v"
                        ? run.ProbeSans && ipPort.Contains(ent["ip"] + "|" + ent["port"])
                        : hostPort.Contains(ent["host"].ToLowerInvariant() + "|" + ent["port"]);
                    if (!inScope) continue;
                    long mr = ent.Long("mr") + 1;
                    ent.SetLong("mr", mr); ent.SetLong("ap", seq);
                    string type = null;
                    if (st == "active") ent["ms"] = at;
                    if (mr >= retireAfter) { ent["st"] = "retired"; ent["ra"] = at; type = "retired"; }
                    else if (st == "active") { ent["st"] = "missing"; type = "missing"; }
                    Put(EntKey(ent["id"]), ent);
                    if (type != null)
                    {
                        long ver = ent.Long("ver");
                        PutEvent(seq, ent["id"], NewEvent(type, seq, run, at, ent["id"], ent["host"], ent["ip"], ent["port"], ent["vh"], Ver(ent["id"], ver)["Url"], ver, ver));
                    }
                    if (++n >= Batch) { kv.Commit(false); kv.Begin(); n = 0; }
                }
                kv.Commit(false);
                Fail("absence");
            }
            catch { kv.Rollback(); throw; }
        }

        // An address change shows up as one service gone and one added in the same run. Pair them only when unambiguous:
        //   R1 same DNS name and port (scanned by name, the address moved)
        //   R2 scanned by address: same reverse-DNS name and port
        //   R3 scanned by address: same certificate (SHA-256), port, title, server and products
        // A signature must be held by exactly one added and one gone service, and by no other service seen in this run.
        sealed class Cand { public string Eid; public Rec Ent, Mat; }
        string Sig(int rule, Cand c)
        {
            string host = c.Ent["host"], port = c.Ent["port"], vh = c.Ent["vh"];
            bool byIp = StoreUtil.IsIp(host);
            switch (rule)
            {
                case 1: return byIp ? null : "1|" + host.ToLowerInvariant() + "|" + port + "|" + vh;
                case 2: return (!byIp || vh != "" || c.Mat["ReverseDns"].Length == 0) ? null : "2|" + c.Mat["ReverseDns"].ToLowerInvariant() + "|" + port;
                default:
                    return (!byIp || vh != "" || c.Mat["CertSha256"].Length == 0) ? null
                        : "3|" + c.Mat["CertSha256"] + "|" + port + "|" + c.Mat["Title"] + "|" + c.Mat["Server"] + "|" + c.Mat["Products"];
            }
        }

        void ApplyRekeys(RunInfo run, long seq, string at)
        {
            // event types come from the per-entity index (no record decoding); candidates are loaded only when both sides exist
            List<string> addedIds = new List<string>(), goneIds = new List<string>();
            string sq = StoreUtil.D10(seq);
            foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("c", sq)))
            {
                string k = StoreUtil.S(e.Key), eid = k.Substring(k.LastIndexOf('\0') + 1);
                byte[] tb = kv.Get(XKey(eid, seq));
                string t = tb == null ? "" : StoreUtil.S(tb);
                if (t == "added") addedIds.Add(eid); else if (t == "missing" || t == "retired") goneIds.Add(eid);
            }
            if (addedIds.Count == 0 || goneIds.Count == 0) return;
            List<Cand> added = new List<Cand>(), gone = new List<Cand>();
            foreach (string id in addedIds) { Cand c = new Cand(); c.Eid = id; c.Ent = Get(EntKey(id)); c.Mat = Ver(id, c.Ent.Long("ver")); added.Add(c); }
            foreach (string id in goneIds) { Cand c = new Cand(); c.Eid = id; c.Ent = Get(EntKey(id)); c.Mat = Ver(id, c.Ent.Long("ver")); gone.Add(c); }
            HashSet<string> used = new HashSet<string>(StringComparer.Ordinal);
            for (int rule = 1; rule <= 3; rule++)
            {
                Dictionary<string, List<Cand>> A = Group(rule, added, used), G = Group(rule, gone, used);
                List<string> sigs = new List<string>();
                foreach (string k in A.Keys) if (A[k].Count == 1 && G.ContainsKey(k) && G[k].Count == 1) sigs.Add(k);
                if (sigs.Count == 0) continue;
                // no other service seen in this run may share the signature
                HashSet<string> want = new HashSet<string>(sigs, StringComparer.Ordinal), clash = new HashSet<string>(StringComparer.Ordinal);
                HashSet<string> addedSet = new HashSet<string>(addedIds, StringComparer.Ordinal);
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
                {
                    Rec ent = Rec.Decode(e.Value);
                    if (ent["st"] != "active" || ent.Long("ap") != seq || addedSet.Contains(ent["id"])) continue;
                    Cand c = new Cand(); c.Eid = ent["id"]; c.Ent = ent;
                    c.Mat = rule == 1 ? new Rec() : Ver(c.Eid, ent.Long("ver"));
                    string sg = Sig(rule, c);
                    if (sg != null && want.Contains(sg)) clash.Add(sg);
                }
                sigs.Sort(StringComparer.Ordinal);
                foreach (string k in sigs)
                {
                    if (clash.Contains(k)) continue;
                    Merge(G[k][0], A[k][0], rule, run, seq, at);
                    used.Add(G[k][0].Eid); used.Add(A[k][0].Eid);
                }
            }
        }
        Dictionary<string, List<Cand>> Group(int rule, List<Cand> list, HashSet<string> used)
        {
            Dictionary<string, List<Cand>> d = new Dictionary<string, List<Cand>>(StringComparer.Ordinal);
            foreach (Cand c in list)
            {
                if (used.Contains(c.Eid)) continue;
                string s = Sig(rule, c);
                if (s == null) continue;
                List<Cand> l;
                if (!d.TryGetValue(s, out l)) { l = new List<Cand>(); d[s] = l; }
                l.Add(c);
            }
            return d;
        }

        void Merge(Cand g, Cand a, int rule, RunInfo run, long seq, string at)
        {
            kv.Begin();
            try
            {
                Rec gEnt = Get(EntKey(g.Eid)), aEnt = Get(EntKey(a.Eid));
                Rec gCur = Ver(g.Eid, gEnt.Long("ver"));
                string pla = gEnt["la"], plr = gEnt["lr"];
                Rec mat = InvSchema.MaterialOf(Ver(a.Eid, 1));
                if (run.NeedsCarryOver) InvSchema.CarryOver(mat, gCur, run);
                string h = InvSchema.Hash(mat);
                long from = gEnt.Long("ver"), to = from;
                List<string> diff = InvSchema.Diff(gCur, mat);
                if (h != gEnt["h"]) { to = from + 1; PutVersion(g.Eid, to, mat, seq, run, at, h); gEnt.SetLong("ver", to); gEnt["h"] = h; gEnt["ca"] = at; }
                string oldNk = gEnt["nk"], oldHost = gEnt["host"], oldIp = gEnt["ip"];
                kv.Delete(NkKey(oldNk));
                kv.Put(NkKey(aEnt["nk"]), StoreUtil.B(g.Eid));
                gEnt["nk"] = aEnt["nk"]; gEnt["host"] = aEnt["host"]; gEnt["ip"] = aEnt["ip"]; gEnt["port"] = aEnt["port"]; gEnt["vh"] = aEnt["vh"];
                gEnt["st"] = "active"; gEnt["la"] = at; gEnt["lr"] = run.RunId; gEnt.SetLong("ap", seq);
                gEnt.Remove("ms"); gEnt.Remove("mr"); gEnt.Remove("ra");
                gEnt.RemovePrefix("o:");
                foreach (string f in aEnt.Names.ToArray()) if (f.StartsWith("o:", StringComparison.Ordinal)) gEnt[f] = aEnt[f];
                Put(EntKey(g.Eid), gEnt);
                // the added service never existed separately
                kv.Delete(EntKey(a.Eid)); kv.Delete(VerKey(a.Eid, 1)); kv.Delete(EvKey(seq, a.Eid)); kv.Delete(XKey(a.Eid, seq));
                Rec ev = NewEvent("rekeyed", seq, run, at, g.Eid, gEnt["host"], gEnt["ip"], gEnt["port"], gEnt["vh"], mat["Url"], from, to);
                ev["rule"] = rule == 1 ? "same-name" : (rule == 2 ? "same-reverse-dns" : "same-certificate");
                ev["okey"] = oldNk; ev["pla"] = pla; ev["plr"] = plr;
                List<string> keyDiff = new List<string>();
                Rec was = new Rec(), now = new Rec();
                if (oldHost != gEnt["host"]) { keyDiff.Add("Host"); was["Host"] = oldHost; now["Host"] = gEnt["host"]; }
                if (oldIp != gEnt["ip"]) { keyDiff.Add("IP"); was["IP"] = oldIp; now["IP"] = gEnt["ip"]; }
                AddDiff(ev, keyDiff, was, now);
                AddDiff(ev, diff, gCur, mat);
                if (diff.Count > 0 && gCur["_prof"] != run.Profile) ev["pd"] = gCur["_prof"] + " -> " + run.Profile;
                PutEvent(seq, g.Eid, ev);
                kv.Commit(false);
            }
            catch { kv.Rollback(); throw; }
        }

        // ---------------------------------------------------------------- rows, JSON
        static readonly string[] Lifecycle = { "FirstSeen", "LastSeen", "LastChange", "Versions", "MissingSince", "MissingRuns", "RetiredAt", "FirstRun", "LastRun", "EntityId" };
        public static readonly string[] InventoryColumns = Concat(new[] { "Status", "Host", "IP", "Port", "Vhost" }, InvSchema.Material, Lifecycle, InvSchema.Observed);
        public static readonly string[] ChangeColumns = { "At", "RunId", "Change", "Host", "IP", "Port", "Vhost", "Url", "Field", "Old", "New", "Rule", "OldKey", "ProfileChange", "EntityId", "Status", "Note" };
        public static readonly string[] RunColumns = { "Seq", "RunId", "StartedAt", "FinishedAt", "Tag", "Scanner", "Complete", "Rows", "Added", "Changed", "Enriched", "Reappeared", "Rekeyed",
            "Missing", "Retired", "Active", "MissingTotal", "RetiredTotal", "Incomplete", "Duplicates", "RetireAfter", "Profile", "Archive", "StateDigest" };
        static string[] Concat(params string[][] a) { List<string> l = new List<string>(); foreach (string[] x in a) l.AddRange(x); return l.ToArray(); }
        static string Cap(string s) { return s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s.Substring(1); }

        static Dictionary<string, string> InventoryRow(Rec ent, Rec ver)
        {
            Dictionary<string, string> r = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            r["Status"] = Cap(ent["st"]); r["Host"] = ent["host"]; r["IP"] = ent["ip"]; r["Port"] = ent["port"]; r["Vhost"] = ent["vh"] == "v" ? "True" : "False";
            foreach (string f in InvSchema.Material) r[f] = ver[f];
            r["FirstSeen"] = ent["fa"]; r["LastSeen"] = ent["la"]; r["LastChange"] = ent["ca"]; r["Versions"] = ent["ver"];
            r["MissingSince"] = ent["ms"]; r["MissingRuns"] = ent["mr"]; r["RetiredAt"] = ent["ra"]; r["FirstRun"] = ent["fr"]; r["LastRun"] = ent["lr"]; r["EntityId"] = ent["id"];
            foreach (string f in InvSchema.Observed) r[f] = ent["o:" + f];
            return r;
        }
        static string StateJson(Dictionary<string, string> row)
        {
            JsonObj j = new JsonObj();
            foreach (string c in InventoryColumns) { string v; if (row.TryGetValue(c, out v) && !string.IsNullOrEmpty(v)) j.Str(c, v); }
            return j.ToString();
        }
        static string EventJson(Rec ev)
        {
            JsonObj j = new JsonObj().Str("run", ev["run"]).Num("seq", ev.Long("seq")).Str("at", ev["at"]).Str("change", ev["type"]).Str("entity", ev["eid"])
                .Str("host", ev["host"]).Str("ip", ev["ip"]).Str("port", ev["port"]).Bool("vhost", ev["vh"] == "v").StrIf("url", ev["url"])
                .Num("fromVersion", ev.Long("from")).Num("toVersion", ev.Long("to")).StrIf("rule", ev["rule"]).StrIf("oldKey", ev["okey"]).StrIf("profileChange", ev["pd"]).StrIf("note", ev["note"]);
            if (ev["inc"] == "True") j.Bool("incompleteObservation", true);
            if (ev["fields"].Length > 0)
            {
                List<string> fs = new List<string>();
                foreach (string f in ev["fields"].Split(';')) fs.Add(new JsonObj().Str("field", f).Str("old", ev["was:" + f]).Str("new", ev["now:" + f]).ToString());
                j.Raw("fields", "[" + string.Join(",", fs) + "]");
            }
            return j.ToString();
        }

        // ---------------------------------------------------------------- queries
        public QueryResult Query(string kind, string[] filters, string[] statuses, string[] changeTypes, string since, string until, string asOf)
        {
            if (kv == null) throw new InvalidOperationException("store database not open");
            DateTimeOffset? from = OptTime(since, "Since"), to = OptTime(until, "Until"), asof = OptTime(asOf, "AsOf");
            HashSet<string> st = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (statuses != null) foreach (string s in statuses) if (!string.IsNullOrEmpty(s)) st.Add(s);
            if (st.Count == 0) { st.Add("Active"); st.Add("Missing"); }
            bool allStatus = st.Contains("All");
            HashSet<string> ct = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (changeTypes != null) foreach (string c in changeTypes) if (!string.IsNullOrEmpty(c)) ct.Add(c);
            DateTimeOffset now = asof ?? DateTimeOffset.Now;
            switch ((kind ?? "").ToLowerInvariant())
            {
                case "inventory": return Inventory(RowFilter.Parse(filters, InventoryColumns), st, allStatus, from, to, asof, now);
                case "changes": return Changes(filters, ct, from, to, null);
                case "history":
                    {
                        // History: every event of the services matching -Filter/-Status (any status by default), by host and port
                        List<RowFilter> fl = RowFilter.Parse(filters, InventoryColumns);
                        bool anyStatus = allStatus || statuses == null || statuses.Length == 0;
                        List<string[]> hit = new List<string[]>();
                        foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
                        {
                            Rec ent = Rec.Decode(e.Value);
                            Dictionary<string, string> row = InventoryRow(ent, Ver(ent["id"], ent.Long("ver")));
                            row["CertDaysLeft"] = DaysLeft(row["CertNotAfter"], now);
                            if ((anyStatus || st.Contains(row["Status"])) && RowFilter.All(fl, row)) hit.Add(new[] { ent["host"], ent["port"], ent["id"] });
                        }
                        hit.Sort(delegate(string[] a, string[] b)
                        {
                            int c = string.Compare(a[0], b[0], StringComparison.OrdinalIgnoreCase);
                            if (c == 0) c = PortNum(a[1]).CompareTo(PortNum(b[1]));
                            return c != 0 ? c : string.CompareOrdinal(a[2], b[2]);
                        });
                        List<string> ids = new List<string>();
                        foreach (string[] h in hit) ids.Add(h[2]);
                        return Changes(null, ct, from, to, ids);
                    }
                case "runs": return Runs(RowFilter.Parse(filters, RunColumns), from, to);
            }
            throw new ArgumentException("unknown query '" + kind + "' (Inventory, Changes, History, Runs, Vulnerabilities)");
        }

        // -StoreQuery Vulnerabilities: current inventory (Active and Missing by default) joined offline with NVD/KEV/EPSS files
        public VulnResult Vulnerabilities(string[] nvd, string kev, string epss, string[] filters, string[] statuses)
        {
            if (kv == null) throw new InvalidOperationException("store database not open");
            HashSet<string> st = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (statuses != null) foreach (string x in statuses) if (!string.IsNullOrEmpty(x)) st.Add(x);
            if (st.Count == 0) { st.Add("Active"); st.Add("Missing"); }
            bool all = st.Contains("All");
            List<RowFilter> fl = RowFilter.Parse(filters, Vulns.Columns);
            List<Vulns.Service> svcs = new List<Vulns.Service>();
            foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
            {
                Rec ent = Rec.Decode(e.Value);
                if (!all && !st.Contains(Cap(ent["st"]))) continue;
                Rec ver = Ver(ent["id"], ent.Long("ver"));
                string cpes = ver["CPEs"];
                if (cpes.Length == 0) continue;
                Vulns.Service s = new Vulns.Service();
                s.Host = ent["host"]; s.Ip = ent["ip"]; s.Port = ent["port"]; s.Url = ver["Url"]; s.Status = Cap(ent["st"]); s.Products = ver["Products"]; s.EntityId = ent["id"];
                foreach (string c in cpes.Split(';')) { Cpe x = Cpe.Parse(c); if (x != null) s.Cpes.Add(x); }
                if (s.Cpes.Count > 0) svcs.Add(s);
            }
            Rec meta = Get(MetaKey) ?? new Rec();
            VulnResult r = Vulns.Run(svcs, nvd, kev, epss, fl, StoreId, meta["runId"]);
            foreach (string m in r.Messages) Messages.Add(m);
            return r;
        }

        static DateTimeOffset? OptTime(string s, string name)
        {
            if (string.IsNullOrEmpty(s)) return null;
            DateTimeOffset t;
            if (!StoreUtil.TryIso(s, out t)) throw new ArgumentException("-" + name + " is not a date/time: '" + s + "'");
            return t;
        }
        static bool InWindow(string at, DateTimeOffset? from, DateTimeOffset? to)
        {
            if (from == null && to == null) return true;
            DateTimeOffset t;
            if (!StoreUtil.TryIso(at, out t)) return false;
            return (from == null || t >= from.Value) && (to == null || t <= to.Value);
        }
        static string DaysLeft(string notAfter, DateTimeOffset reference)
        {
            DateTime na;
            if (string.IsNullOrEmpty(notAfter) || !DateTime.TryParse(notAfter, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out na)) return "";
            return ((long)Math.Floor((new DateTimeOffset(na) - reference).TotalDays)).ToString(CultureInfo.InvariantCulture);
        }
        static int PortNum(string p) { int n; return int.TryParse(p, NumberStyles.Integer, CultureInfo.InvariantCulture, out n) ? n : 0; }
        static string[] Project(string[] cols, Dictionary<string, string> row)
        {
            string[] a = new string[cols.Length];
            for (int i = 0; i < cols.Length; i++) { string v; a[i] = row.TryGetValue(cols[i], out v) ? (v ?? "") : ""; }
            return a;
        }

        QueryResult Inventory(List<RowFilter> fl, HashSet<string> st, bool allStatus, DateTimeOffset? from, DateTimeOffset? to, DateTimeOffset? asof, DateTimeOffset now)
        {
            QueryResult q = new QueryResult(); q.Columns = InventoryColumns;
            List<Dictionary<string, string>> rows = new List<Dictionary<string, string>>();
            Func<Dictionary<string, string>, bool> keep = delegate(Dictionary<string, string> row)
            {
                if (!allStatus && !st.Contains(row["Status"])) return false;
                if (!InWindow(row["LastSeen"], from, to)) return false;
                row["CertDaysLeft"] = DaysLeft(row["CertNotAfter"], now);
                return RowFilter.All(fl, row);
            };
            if (asof != null)
            {
                // the inventory as it stood after the last run that started at or before -AsOf: its archived state file,
                // or (snapshot thinned out by -SnapshotEvery) the history replayed in memory up to that run
                foreach (Dictionary<string, string> row in AsOfRows(asof.Value)) if (keep(row)) q.Rows.Add(Project(q.Columns, row));
            }
            else
            {
                // rows are filtered as they are read: only matching rows are kept in memory
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
                {
                    Rec ent = Rec.Decode(e.Value);
                    if (!allStatus && !st.Contains(Cap(ent["st"]))) continue;
                    Dictionary<string, string> row = InventoryRow(ent, Ver(ent["id"], ent.Long("ver")));
                    if (keep(row)) q.Rows.Add(Project(q.Columns, row));
                }
            }
            int hi = Array.IndexOf(q.Columns, "Host"), pi = Array.IndexOf(q.Columns, "Port"), ii = Array.IndexOf(q.Columns, "IP"), vi = Array.IndexOf(q.Columns, "Vhost");
            q.Rows.Sort(delegate(string[] a, string[] b)
            {
                int c = string.Compare(a[hi], b[hi], StringComparison.OrdinalIgnoreCase); if (c != 0) return c;
                c = PortNum(a[pi]).CompareTo(PortNum(b[pi])); if (c != 0) return c;
                c = string.CompareOrdinal(a[ii], b[ii]); if (c != 0) return c;
                return string.CompareOrdinal(a[vi], b[vi]);
            });
            return q;
        }

        QueryResult Changes(string[] filters, HashSet<string> ct, DateTimeOffset? from, DateTimeOffset? to, List<string> onlyIds)
        {
            QueryResult q = new QueryResult(); q.Columns = ChangeColumns;
            List<string> known = new List<string>(ChangeColumns); known.AddRange(InventoryColumns);
            List<RowFilter> fl = RowFilter.Parse(filters, known);
            Dictionary<string, Dictionary<string, string>> entCache = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);
            List<long> seqs = new List<long>();
            foreach (KeyValuePair<byte[], byte[]> r in kv.Scan(P("r")))
            {
                Rec rr = Rec.Decode(r.Value);
                if (rr["state"] == "ingested" && InWindow(rr["startedAt"], from, to)) seqs.Add(rr.Long("seq"));
            }
            List<KeyValuePair<string, Rec>> evs = new List<KeyValuePair<string, Rec>>();
            if (onlyIds != null)
            {
                HashSet<long> ok = new HashSet<long>(seqs);
                foreach (string id in onlyIds)
                    foreach (KeyValuePair<byte[], byte[]> x in kv.Scan(P("x", id)))
                    {
                        string k = StoreUtil.S(x.Key);
                        long sq = long.Parse(k.Substring(k.LastIndexOf('\0') + 1), CultureInfo.InvariantCulture);
                        if (!ok.Contains(sq)) continue;
                        Rec ev = Get(EvKey(sq, id));
                        if (ev != null) evs.Add(new KeyValuePair<string, Rec>(id, ev));
                    }
            }
            else
                foreach (long sq in seqs)
                    foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("c", StoreUtil.D10(sq))))
                    {
                        Rec ev = Rec.Decode(e.Value);
                        evs.Add(new KeyValuePair<string, Rec>(ev["eid"], ev));
                    }
            // Changes: runs in order, within a run by host and port (History keeps its per-service order)
            if (onlyIds == null)
                evs.Sort(delegate(KeyValuePair<string, Rec> a, KeyValuePair<string, Rec> b)
                {
                    int c = a.Value.Long("seq").CompareTo(b.Value.Long("seq"));
                    if (c == 0) c = string.Compare(a.Value["host"], b.Value["host"], StringComparison.OrdinalIgnoreCase);
                    if (c == 0) c = PortNum(a.Value["port"]).CompareTo(PortNum(b.Value["port"]));
                    return c != 0 ? c : string.CompareOrdinal(a.Key, b.Key);
                });
            foreach (KeyValuePair<string, Rec> pe in evs)
            {
                Rec ev = pe.Value;
                if (ct.Count > 0 && !ct.Contains(ev["type"])) continue;
                Dictionary<string, string> er;
                if (!entCache.TryGetValue(pe.Key, out er))
                {
                    Rec ent = Get(EntKey(pe.Key));
                    er = ent == null ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) : InventoryRow(ent, Ver(pe.Key, ent.Long("ver")));
                    entCache[pe.Key] = er;
                }
                string[] fields = ev["fields"].Length > 0 ? ev["fields"].Split(';') : new[] { "" };
                foreach (string f in fields)
                {
                    Dictionary<string, string> row = new Dictionary<string, string>(er, StringComparer.OrdinalIgnoreCase);
                    row["At"] = ev["at"]; row["RunId"] = ev["run"]; row["Change"] = Cap(ev["type"]); row["Host"] = ev["host"]; row["IP"] = ev["ip"]; row["Port"] = ev["port"];
                    row["Vhost"] = ev["vh"] == "v" ? "True" : "False"; row["Url"] = ev["url"]; row["Field"] = f;
                    row["Old"] = f.Length > 0 ? ev["was:" + f] : ""; row["New"] = f.Length > 0 ? ev["now:" + f] : "";
                    row["Rule"] = ev["rule"]; row["OldKey"] = ev["okey"]; row["ProfileChange"] = ev["pd"]; row["EntityId"] = pe.Key; row["Note"] = ev["note"];
                    string sv; row["Status"] = er.TryGetValue("Status", out sv) ? sv : "";
                    if (!RowFilter.All(fl, row)) continue;
                    q.Rows.Add(Project(q.Columns, row));
                }
            }
            return q;
        }

        QueryResult Runs(List<RowFilter> fl, DateTimeOffset? from, DateTimeOffset? to)
        {
            QueryResult q = new QueryResult(); q.Columns = RunColumns;
            foreach (KeyValuePair<byte[], byte[]> r in kv.Scan(P("r")))
            {
                Rec rr = Rec.Decode(r.Value);
                if (!InWindow(rr["startedAt"], from, to)) continue;
                Dictionary<string, string> row = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                row["Seq"] = rr["seq"]; row["RunId"] = rr["runId"]; row["StartedAt"] = rr["startedAt"]; row["FinishedAt"] = rr["finishedAt"]; row["Tag"] = rr["tag"];
                row["Scanner"] = rr["scanner"]; row["Complete"] = rr["complete"]; row["Profile"] = rr["profile"]; row["Archive"] = rr["archive"]; row["StateDigest"] = rr["stateDigest"];
                row["RetireAfter"] = rr["retireAfter"];
                foreach (string c in new[] { "rows", "added", "changed", "enriched", "reappeared", "rekeyed", "missing", "retired", "active", "missingTotal", "retiredTotal", "incomplete", "duplicates" })
                    row[Cap(c)] = rr[c];
                if (rr["state"] != "ingested") row["Complete"] = "ingesting";
                if (!RowFilter.All(fl, row)) continue;
                q.Rows.Add(Project(q.Columns, row));
            }
            return q;
        }

        // ---------------------------------------------------------------- statistics, verification, rebuild
        public Dictionary<string, string> Stats()
        {
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            d["Root"] = Root; d["StoreId"] = StoreId; d["Engine"] = Engine; d["RetireAfter"] = RetireAfter.ToString(CultureInfo.InvariantCulture);
            if (kv == null) return d;
            long a = 0, m = 0, r = 0, runs = 0;
            foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e"))) { string s = Rec.Decode(e.Value)["st"]; if (s == "active") a++; else if (s == "missing") m++; else r++; }
            foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("r"))) runs++;
            Rec meta = Get(MetaKey) ?? new Rec();
            d["Active"] = a.ToString(CultureInfo.InvariantCulture); d["Missing"] = m.ToString(CultureInfo.InvariantCulture); d["Retired"] = r.ToString(CultureInfo.InvariantCulture);
            d["Runs"] = runs.ToString(CultureInfo.InvariantCulture); d["LastRun"] = meta["runId"]; d["LedgerHead"] = LedgerHead();
            return d;
        }

        string LiveStateDigest()
        {
            using (DigestWriter w = new DigestWriter(null))
            {
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
                {
                    Rec ent = Rec.Decode(e.Value);
                    w.Line(StateJson(InventoryRow(ent, Ver(ent["id"], ent.Long("ver")))));
                }
                return w.Close();
            }
        }

        // Verify: see invstore2.cs

        public void Rebuild(string engine)
        {
            string req = (engine ?? "auto").Trim().ToLowerInvariant();
            string target = (req == "" || req == "auto") ? ((Engine == "esent" && !EsentKv.Available) ? "file" : (Engine.Length > 0 ? Engine : ResolveEngine("auto"))) : ResolveEngine(req);
            if (kv != null) { kv.Dispose(); kv = null; }
            string prev = DbDir + ".previous";
            if (Directory.Exists(prev)) Directory.Delete(prev, true);
            if (Directory.Exists(DbDir)) Directory.Move(DbDir, prev);
            string was = Engine;
            Engine = target;
            Log("rebuilding the " + target + " database from the archive (previous database kept in db.previous)");
            Stopwatch sw = Stopwatch.StartNew();
            kv = OpenEngine();
            Reconcile();
            SaveStoreJson();
            Log(string.Format(CultureInfo.InvariantCulture, "rebuild complete in {0:0.0}s{1}", sw.Elapsed.TotalSeconds, was != target ? " (engine " + was + " -> " + target + ")" : ""));
        }

        public void Dispose()
        {
            if (kv != null) { try { kv.Dispose(); } catch (Exception) { } kv = null; }
            if (lockFs != null) { try { lockFs.Dispose(); } catch (Exception) { } lockFs = null; }
        }
    }
}
