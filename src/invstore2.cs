
// ============================================================================
// WebInv inventory store, part 2: the applied plan (runs, corrections, rebases), manual merge/split, backfill,
// snapshot thinning, -AsOf replay and verification. Everything here is a deterministic function of the archive:
// a correction is a ledger entry applied at its position, a backfill appends a "rebase" entry with the new order -
// nothing already written is ever rewritten.
// ============================================================================
namespace WebInv
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Text;

    public sealed class PlanItem
    {
        public LedgerEntry E;
        public long Pos;
        public string ChangesDigest = "", StateDigest = "", Void = "", Derived = "";
        public bool Snapshot = true;
        public bool IsRun { get { return E.Type == "run"; } }
    }

    public sealed partial class InventoryStore
    {
        public int SnapshotEvery = 1;
        public bool AnchorEventLog;
        public string AnchorCertificate = "";
        public long AnchorFrom;
        // ledger lines appended by this process: { seq, sha256 of the line, line } (for event-log / signature anchors)
        public readonly List<string[]> Appended = new List<string[]>();

        static string D6(long n) { return n.ToString("D6", CultureInfo.InvariantCulture); }

        // ---------------------------------------------------------------- plan
        public List<PlanItem> BuildPlan(List<LedgerEntry> led)
        {
            List<PlanItem> plan = new List<PlanItem>();
            Dictionary<long, LedgerEntry> bySeq = new Dictionary<long, LedgerEntry>();
            foreach (LedgerEntry e in led)
            {
                bySeq[e.Seq] = e;
                if (e.Type == "run" || e.Type == "correction")
                {
                    PlanItem it = new PlanItem();
                    it.E = e; it.Pos = plan.Count + 1; it.ChangesDigest = e.ChangesDigest; it.StateDigest = e.StateDigest; it.Snapshot = e.Snapshot && e.Type == "run";
                    it.Void = StoreUtil.Str(e.Obj, "void"); it.Derived = AbsRun(e.Path);
                    plan.Add(it);
                }
                else if (e.Type == "rebase")
                {
                    plan = new List<PlanItem>();
                    List<object> items = StoreUtil.Field(e.Obj, "plan") as List<object>;
                    if (items == null) throw new InvalidDataException("rebase entry seq " + e.Seq + " has no plan");
                    foreach (object o in items)
                    {
                        Dictionary<string, object> d = (Dictionary<string, object>)o;
                        long s = StoreUtil.Num(d, "seq");
                        LedgerEntry src;
                        if (!bySeq.TryGetValue(s, out src)) throw new InvalidDataException("rebase entry seq " + e.Seq + " names unknown ledger seq " + s);
                        PlanItem it = new PlanItem();
                        it.E = src; it.Pos = plan.Count + 1; it.ChangesDigest = StoreUtil.Str(d, "changesDigest"); it.StateDigest = StoreUtil.Str(d, "stateDigest");
                        it.Snapshot = StoreUtil.Str(d, "snapshot") != "False" && src.Type == "run"; it.Void = StoreUtil.Str(d, "void");
                        it.Derived = AbsRun(e.Path + "/" + D6(it.Pos));
                        plan.Add(it);
                    }
                }
            }
            return plan;
        }
        static string LastRebase(List<LedgerEntry> led)
        {
            string r = "";
            foreach (LedgerEntry e in led) if (e.Type == "rebase") r = e.Seq.ToString(CultureInfo.InvariantCulture);
            return r;
        }
        static bool PendingBackfill(List<LedgerEntry> led)
        {
            bool pending = false;
            foreach (LedgerEntry e in led) { if (e.Type == "rebase") pending = false; else if (e.Type == "run" && e.Backfill) pending = true; }
            return pending;
        }
        // first run, then every SnapshotEvery-th run keeps its full state file
        bool SnapshotFor(List<PlanItem> planBefore, bool isRun)
        {
            if (!isRun) return false;
            if (SnapshotEvery <= 1) return true;
            int runs = 1;
            foreach (PlanItem it in planBefore) if (it.IsRun) runs++;
            return runs % SnapshotEvery == 1;
        }
        int RetireOf(LedgerEntry e) { return e.RetireAfter > 0 ? e.RetireAfter : RetireAfter; }

        IngestSummary ApplyItem(PlanItem it, string derivedDir)
        {
            if (it.IsRun) return ApplyArchived(it.E.Path, it.Pos, RetireOf(it.E), derivedDir, it.Snapshot);
            return ApplyCorrection(it.E.Path, it.Pos, derivedDir, false);
        }

        void ResetDb()
        {
            if (kv != null) { kv.Dispose(); kv = null; }
            string prev = DbDir + ".previous";
            if (Directory.Exists(prev)) Directory.Delete(prev, true);
            if (Directory.Exists(DbDir)) Directory.Move(DbDir, prev);
            kv = OpenEngine();
        }

        InventoryStore NewShadow()
        {
            InventoryStore sh = new InventoryStore(Root);
            sh.shadow = true; sh.kv = new FileKv(null); sh.Engine = "memory"; sh.StoreId = StoreId; sh.RetireAfter = RetireAfter; sh.SnapshotEvery = SnapshotEvery;
            return sh;
        }

        // ---------------------------------------------------------------- bring the database up to the archive
        void Reconcile()
        {
            List<LedgerEntry> led = ReadLedgerStrict();
            if (PendingBackfill(led)) { Log("finishing an interrupted backfill: replaying the history in run order"); Rebase(led, "backfill (finished after an interruption)"); led = ReadLedgerStrict(); }
            List<PlanItem> plan = BuildPlan(led);
            string rb = LastRebase(led);
            Rec meta = Get(MetaKey) ?? new Rec();
            if (meta.Long("seq") > 0 && meta["rebase"] != rb)
            {
                Log("the ledger holds a newer replay order (rebase seq " + rb + "); rebuilding the working database");
                ResetDb(); meta = new Rec();
            }
            long dbSeq = meta.Long("seq");
            HashSet<string> ledgered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (LedgerEntry e in led) if (e.Type == "run" || e.Type == "correction") ledgered.Add(e.Path);
            foreach (PlanItem it in plan)
            {
                if (it.Pos <= dbSeq) continue;
                if (it.IsRun)
                {
                    Rec rr = RunByRunId(it.E.RunId);
                    if (rr != null && rr["state"] == "ingested" && rr.Long("seq") == it.Pos && rr["stateDigest"] == it.StateDigest)
                    {
                        kv.Begin(); meta["runId"] = it.E.RunId; meta.SetLong("seq", it.Pos); meta["stateDigest"] = it.StateDigest; meta["rebase"] = rb; Put(MetaKey, meta); kv.Commit(true); kv.Flush();
                        continue;
                    }
                }
                Log("database is behind the archive: applying " + (it.IsRun ? "run " + it.E.RunId : it.E.RunId) + " (position " + it.Pos + ") from archive\\" + it.E.Path.Replace('/', '\\'));
                IngestSummary s = ApplyItem(it, null);
                if (s.StateDigest != it.StateDigest || s.ChangesDigest != it.ChangesDigest)
                    throw new InvalidDataException("re-applying " + it.E.RunId + " from the archive does not reproduce the digests in the ledger (state " + s.StateDigest + " vs " + it.StateDigest + "); the archive or the database has been altered - run -VerifyStore");
                meta = Get(MetaKey) ?? new Rec();
            }
            if (meta["rebase"] != rb) { kv.Begin(); meta["rebase"] = rb; Put(MetaKey, meta); kv.Commit(true); kv.Flush(); }
            // runs archived but not yet in the ledger (an earlier ingest stopped part-way): finish them
            foreach (string rel in ArchivedFolders())
            {
                if (ledgered.Contains(rel)) continue;
                string dir = AbsRun(rel);
                if (!File.Exists(Path.Combine(dir, "INPUTS.json")))
                {
                    Log("WARNING: archive\\" + rel.Replace('/', '\\') + " is incomplete (the copy did not finish); import that run again with -ImportRun");
                    continue;
                }
                long seq = plan.Count + 1;
                bool snap = SnapshotFor(plan, true);
                Log("finishing run archived by an interrupted ingest: archive\\" + rel.Replace('/', '\\') + " (position " + seq + ")");
                IngestSummary s = ApplyArchived(rel, seq, RetireAfter, dir, snap);
                s.LedgerHead = AppendRunLedger(rel, s, RetireAfter, led, snap);
                led = ReadLedgerStrict(); plan = BuildPlan(led);
                Log("ingested " + s.Text());
            }
            // a correction applied to the database whose ledger entry was not written yet
            meta = Get(MetaKey) ?? new Rec();
            string pend = meta["pending"];
            if (pend.Length > 0)
            {
                if (ledgered.Contains(pend)) { kv.Begin(); meta.Remove("pending"); Put(MetaKey, meta); kv.Commit(true); }
                else if (meta.Long("seq") == plan.Count + 1)
                {
                    Log("finishing correction " + pend + " (applied, not yet in the ledger)");
                    IngestSummary s = CorrectionDerived(pend, plan.Count + 1, AbsRun(pend));
                    AppendCorrectionLedger(pend, s, led);
                    meta = Get(MetaKey); meta.Remove("pending"); kv.Begin(); Put(MetaKey, meta); kv.Commit(true); kv.Flush();
                    led = ReadLedgerStrict(); plan = BuildPlan(led);
                }
            }
            string cdir = Path.Combine(ArchiveDir, "corrections");
            if (Directory.Exists(cdir))
                foreach (string d in Directory.GetDirectories(cdir))
                {
                    string rel = "corrections/" + Path.GetFileName(d);
                    if (ledgered.Contains(rel) || rel == pend || rel.EndsWith(".abandoned", StringComparison.Ordinal)) continue;
                    bool inLedger = false;
                    foreach (LedgerEntry e in led) if (e.Path == rel) inLedger = true;
                    if (inLedger) continue;
                    Directory.Move(d, d + ".abandoned");
                    Log("WARNING: correction " + rel + " was never applied (interrupted before the database changed); kept as " + rel + ".abandoned - run the command again");
                }
            meta = Get(MetaKey) ?? new Rec();
            if (meta.Long("seq") > plan.Count)
                throw new InvalidDataException("the database holds runs the archive ledger does not (database position " + meta["seq"] + ", ledger " + plan.Count + "); rebuild it from the archive: -RebuildStore");
        }

        // ---------------------------------------------------------------- corrections (manual merge / split)
        public IngestSummary Correct(string op, string[] ids, string splitAt, string reason, string operatorName)
        {
            if (kv == null || shadow) throw new InvalidOperationException("store not open for writing");
            if (string.IsNullOrWhiteSpace(reason)) throw new ArgumentException("a correction needs -Reason (it is kept in the ledger)");
            op = (op ?? "").ToLowerInvariant();
            if (op == "merge" && (ids == null || ids.Length != 2)) throw new ArgumentException("-StoreMerge takes exactly two entity ids");
            if (op == "split" && (ids == null || ids.Length != 1)) throw new ArgumentException("-StoreSplit takes one entity id");
            if (op != "merge" && op != "split") throw new ArgumentException("unknown correction '" + op + "'");
            List<LedgerEntry> led = ReadLedgerStrict();
            List<PlanItem> plan = BuildPlan(led);
            long pos = plan.Count + 1, lseq = led[led.Count - 1].Seq + 1;
            string at = StoreUtil.Iso(DateTimeOffset.Now), label = "correction-" + lseq.ToString(CultureInfo.InvariantCulture);
            string why = op == "merge" ? DoMerge(ids[0].Trim(), ids[1].Trim(), pos, at, label, reason, true) : DoSplit(ids[0].Trim(), splitAt ?? "", pos, at, label, reason, true);
            if (why.Length > 0) throw new InvalidOperationException(why);
            string rel = "corrections/" + D6(lseq) + "-" + op;
            string dir = AbsRun(rel);
            Directory.CreateDirectory(dir);
            JsonObj c = new JsonObj().Num("seq", lseq).Str("op", op).Str("at", at).Str("operator", operatorName ?? "").Str("reason", reason);
            if (op == "merge") c.Raw("ids", "[" + Q(ids[0].Trim()) + "," + Q(ids[1].Trim()) + "]"); else c.Str("id", ids[0].Trim()).Str("splitAt", splitAt ?? "");
            StoreUtil.WriteAllTextAtomic(Path.Combine(dir, "correction.json"), c.ToString() + "\n");
            IngestSummary s = ApplyCorrection(rel, pos, dir, true);
            Fail("correction");
            s.LedgerHead = AppendCorrectionLedger(rel, s, led);
            Rec meta = Get(MetaKey); meta.Remove("pending"); kv.Begin(); Put(MetaKey, meta); kv.Commit(true); kv.Flush();
            Log(string.Format(CultureInfo.InvariantCulture, "correction {0} ({1}) recorded at position {2}: {3}; ledger head {4}", label, op, pos, reason, s.LedgerHead));
            return s;
        }
        static string Q(string s) { StringBuilder b = new StringBuilder(); StoreUtil.JsonString(b, s); return b.ToString(); }

        IngestSummary ApplyCorrection(string rel, long pos, string derivedDir, bool live)
        {
            string dir = AbsRun(rel);
            Dictionary<string, object> c = StoreJson.Parse(File.ReadAllText(Path.Combine(dir, "correction.json"), StoreUtil.Utf8)) as Dictionary<string, object>;
            string op = StoreUtil.Str(c, "op"), at = StoreUtil.Str(c, "at"), reason = StoreUtil.Str(c, "reason");
            long lseq = StoreUtil.Num(c, "seq");
            string label = "correction-" + lseq.ToString(CultureInfo.InvariantCulture);
            Rec existing = Get(RunKey(pos));
            if (existing != null && existing["runId"] != label) throw new InvalidDataException("position " + pos + " holds " + existing["runId"] + ", not " + label + "; rebuild the database: -RebuildStore");
            string voidWhy = "";
            if (existing == null)
            {
                kv.Begin();
                try
                {
                    if (op == "merge")
                    {
                        List<object> ids = StoreUtil.Field(c, "ids") as List<object>;
                        voidWhy = DoMerge(StoreUtil.Scalar(ids[0]), StoreUtil.Scalar(ids[1]), pos, at, label, reason, false);
                    }
                    else if (op == "split") voidWhy = DoSplit(StoreUtil.Str(c, "id"), StoreUtil.Str(c, "splitAt"), pos, at, label, reason, false);
                    else throw new InvalidDataException("unknown correction op '" + op + "' in " + rel);
                    Rec rr = new Rec();
                    rr.SetLong("seq", pos); rr["runId"] = label; rr["kind"] = "correction"; rr["state"] = "ingested"; rr["startedAt"] = at; rr["finishedAt"] = at;
                    rr["tag"] = op + ": " + reason + (voidWhy.Length > 0 ? " (void: " + voidWhy + ")" : ""); rr["scanner"] = "correction (" + op + ")"; rr["complete"] = "True";
                    rr["profile"] = ""; rr["archive"] = rel; rr["void"] = voidWhy;
                    Put(RunKey(pos), rr); kv.Put(RunIdKey(label), StoreUtil.B(pos.ToString(CultureInfo.InvariantCulture)));
                    Rec meta = Get(MetaKey) ?? new Rec();
                    meta.SetLong("seq", pos); meta["runId"] = label;
                    if (live) meta["pending"] = rel;
                    Put(MetaKey, meta);
                    kv.Commit(true);
                }
                catch { kv.Rollback(); throw; }
            }
            else voidWhy = existing["void"];
            IngestSummary s = CorrectionDerived(rel, pos, derivedDir);
            s.Void = voidWhy;
            return s;
        }

        IngestSummary CorrectionDerived(string rel, long pos, string derivedDir)
        {
            IngestSummary s = new IngestSummary();
            Rec rr = Get(RunKey(pos));
            s.RunId = rr["runId"]; s.Seq = pos; s.Archive = rel; s.Void = rr["void"];
            if (derivedDir != null) Directory.CreateDirectory(derivedDir);
            using (DigestWriter cw = new DigestWriter(derivedDir != null ? Path.Combine(derivedDir, "changes.jsonl.gz") : null))
            {
                foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("c", StoreUtil.D10(pos)))) cw.Line(EventJson(Rec.Decode(e.Value)));
                s.ChangesDigest = cw.Close();
            }
            s.StateDigest = LiveStateDigest();
            foreach (KeyValuePair<byte[], byte[]> e in kv.Scan(P("e")))
                switch (Rec.Decode(e.Value)["st"]) { case "active": s.Active++; break; case "missing": s.MissingTotal++; break; default: s.RetiredTotal++; break; }
            kv.Begin();
            rr["changesDigest"] = s.ChangesDigest; rr["stateDigest"] = s.StateDigest;
            Put(RunKey(pos), rr);
            Rec meta = Get(MetaKey) ?? new Rec(); meta["stateDigest"] = s.StateDigest; Put(MetaKey, meta);
            kv.Commit(true); kv.Flush();
            return s;
        }

        string AppendCorrectionLedger(string rel, IngestSummary s, List<LedgerEntry> led)
        {
            string dir = AbsRun(rel);
            Dictionary<string, object> c = StoreJson.Parse(File.ReadAllText(Path.Combine(dir, "correction.json"), StoreUtil.Utf8)) as Dictionary<string, object>;
            long b;
            string files = "[" + new JsonObj().Str("name", "correction.json").Str("sha256", StoreUtil.FileSha256(Path.Combine(dir, "correction.json"), out b)).Num("bytes", b) + "]";
            string derived = "[" + new JsonObj().Str("name", "changes.jsonl.gz").Str("sha256", StoreUtil.FileSha256(Path.Combine(dir, "changes.jsonl.gz"), out b)).Num("bytes", b) + "]";
            long lseq = led[led.Count - 1].Seq + 1;
            JsonObj o = new JsonObj().Num("seq", lseq).Str("type", "correction").Str("op", StoreUtil.Str(c, "op")).Str("runId", s.RunId).Str("runStarted", StoreUtil.Str(c, "at"))
                .Str("path", rel).Str("reason", StoreUtil.Str(c, "reason")).Str("operator", StoreUtil.Str(c, "operator")).Bool("snapshot", false)
                .Str("engine", Engine).Str("ingestedBy", "WebInventory " + ScannerVersion).Str("ingestedAt", StoreUtil.Iso(DateTimeOffset.Now))
                .Raw("files", files).Raw("derived", derived).Str("changesDigest", s.ChangesDigest).Str("stateDigest", s.StateDigest);
            if (s.Void.Length > 0) o.Str("void", s.Void);
            if (lseq != s.Seq) o.Num("pos", s.Seq);
            string head = AppendLedger(o, led[led.Count - 1].Hash);
            kv.Begin(); Rec meta = Get(MetaKey) ?? new Rec(); meta["ledgerHead"] = head; Put(MetaKey, meta); kv.Commit(true); kv.Flush();
            return head;
        }

        long PosOfRun(string runId)
        {
            Rec rr = RunByRunId(runId);
            if (rr == null) throw new InvalidDataException("run " + runId + " is not in the database");
            return rr.Long("seq");
        }
        List<long> EventSeqs(string eid, out List<string> types)
        {
            List<long> seqs = new List<long>(); types = new List<string>();
            foreach (KeyValuePair<byte[], byte[]> x in kv.Scan(P("x", eid)))
            {
                string k = StoreUtil.S(x.Key);
                seqs.Add(long.Parse(k.Substring(k.LastIndexOf('\0') + 1), CultureInfo.InvariantCulture));
                types.Add(StoreUtil.S(x.Value));
            }
            return seqs;
        }
        void DropEvent(long seq, string eid) { kv.Delete(EvKey(seq, eid)); kv.Delete(XKey(eid, seq)); }
        static Rec Copy(Rec r) { return Rec.Decode(r.Encode()); }

        // Fold the later service into the earlier one. Allowed only when the earlier one was last seen before the later
        // one first appeared (the case an automatic pairing missed). Returns "" or why the merge cannot be applied.
        string DoMerge(string idA, string idB, long pos, string at, string label, string reason, bool dry)
        {
            if (idA == idB) return "the two entity ids are the same";
            Rec a = Get(EntKey(idA)), b = Get(EntKey(idB));
            if (a == null) return "entity " + idA + " not found (ids come from the EntityId column of an Inventory or History query)";
            if (b == null) return "entity " + idB + " not found (ids come from the EntityId column of an Inventory or History query)";
            long fa = PosOfRun(a["fr"]), fb = PosOfRun(b["fr"]);
            Rec S = (fa < fb || (fa == fb && string.CompareOrdinal(idA, idB) < 0)) ? a : b, O = S == a ? b : a;
            long sLast = PosOfRun(S["lr"]), oFirst = PosOfRun(O["fr"]);
            if (sLast >= oFirst) return "both services were seen in the same run(s) (" + S["id"] + " last seen in " + S["lr"] + ", " + O["id"] + " first seen in " + O["fr"] + "); only a service that ended before the other began can be merged";
            if (dry) return "";
            string sId = S["id"], oId = O["id"];
            long sVer = S.Long("ver"), oVer = O.Long("ver");
            Rec sCur = Ver(sId, sVer);
            Dictionary<long, long> map = new Dictionary<long, long>();
            long next = sVer;
            for (long k = 1; k <= oVer; k++)
            {
                Rec v = Ver(oId, k);
                kv.Delete(VerKey(oId, k));
                if (k == 1 && v["_h"] == sCur["_h"]) { map[k] = sVer; continue; }
                Rec nv = Copy(v); next++; nv.SetLong("_ver", next); Put(VerKey(sId, next), nv); map[k] = next;
            }
            // the earlier service's absences from the moment the later one appeared are replaced by the later one's history
            List<string> types;
            List<long> sSeqs = EventSeqs(sId, out types);
            for (int i = 0; i < sSeqs.Count; i++) if (sSeqs[i] >= oFirst && (types[i] == "missing" || types[i] == "retired")) DropEvent(sSeqs[i], sId);
            List<long> oSeqs = EventSeqs(oId, out types);
            foreach (long sq in oSeqs)
            {
                Rec ev = Get(EvKey(sq, oId));
                DropEvent(sq, oId);
                if (ev == null) continue;
                if (ev["type"] == "added")
                {
                    Rec ne = Copy(ev);
                    ne["type"] = "rekeyed"; ne["eid"] = sId; ne.SetLong("from", sVer); ne.SetLong("to", map[1]);
                    ne["rule"] = "manual-merge"; ne["okey"] = S["nk"]; ne["pla"] = S["la"]; ne["plr"] = S["lr"]; ne["note"] = reason;
                    List<string> keyDiff = new List<string>(); Rec was = new Rec(), now = new Rec();
                    if (S["host"] != ev["host"]) { keyDiff.Add("Host"); was["Host"] = S["host"]; now["Host"] = ev["host"]; }
                    if (S["ip"] != ev["ip"]) { keyDiff.Add("IP"); was["IP"] = S["ip"]; now["IP"] = ev["ip"]; }
                    if (S["port"] != ev["port"]) { keyDiff.Add("Port"); was["Port"] = S["port"]; now["Port"] = ev["port"]; }
                    AddDiff(ne, keyDiff, was, now);
                    if (map[1] != sVer) { Rec v1 = Ver(sId, map[1]); AddDiff(ne, InvSchema.Diff(sCur, v1), sCur, v1); }
                    ev = ne;
                }
                else
                {
                    ev["eid"] = sId;
                    long f = ev.Long("from"), t = ev.Long("to");
                    if (map.ContainsKey(f)) ev.SetLong("from", map[f]);
                    if (map.ContainsKey(t)) ev.SetLong("to", map[t]);
                }
                PutEvent(sq, sId, ev);
            }
            kv.Delete(NkKey(S["nk"]));
            kv.Put(NkKey(O["nk"]), StoreUtil.B(sId));
            foreach (string f in new[] { "nk", "host", "ip", "port", "vh", "st", "la", "lr", "ap", "ms", "mr", "ra" }) { if (O[f].Length > 0) S[f] = O[f]; else S.Remove(f); }
            S.RemovePrefix("o:");
            foreach (string f in O.Names.ToArray()) if (f.StartsWith("o:", StringComparison.Ordinal)) S[f] = O[f];
            S.SetLong("ver", map[oVer]); S["h"] = O["h"];
            if (map[oVer] > sVer) S["ca"] = O["ca"];
            Put(EntKey(sId), S);
            kv.Delete(EntKey(oId));
            Rec me = new Rec();
            me["type"] = "merged"; me.SetLong("seq", pos); me["run"] = label; me["at"] = at; me["eid"] = sId;
            me["host"] = S["host"]; me["ip"] = S["ip"]; me["port"] = S["port"]; me["vh"] = S["vh"]; me["url"] = Ver(sId, S.Long("ver"))["Url"];
            me.SetLong("from", S.Long("ver")); me.SetLong("to", S.Long("ver")); me["rule"] = "manual"; me["okey"] = "entity " + oId; me["note"] = reason;
            PutEvent(pos, sId, me);
            return "";
        }

        // Undo an address-move pairing (automatic or a manual merge): everything from that run on becomes a separate
        // service again; the original goes back to its old address with its absences recomputed from the archive.
        string DoSplit(string id, string splitAt, long pos, string at, string label, string reason, bool dry)
        {
            Rec E = Get(EntKey(id));
            if (E == null) return "entity " + id + " not found (ids come from the EntityId column of an Inventory or History query)";
            List<string> types;
            List<long> seqs = EventSeqs(id, out types);
            long P = -1;
            for (int i = 0; i < seqs.Count; i++)
            {
                if (types[i] != "rekeyed") continue;
                if (splitAt.Length == 0) P = seqs[i];
                else { Rec ev0 = Get(EvKey(seqs[i], id)); if (ev0 != null && ev0["run"] == splitAt) P = seqs[i]; }
            }
            if (P < 0) return "entity " + id + " has no address-move pairing (rekeyed event)" + (splitAt.Length > 0 ? " in run " + splitAt : "") + " to split";
            Rec rk = Get(EvKey(P, id));
            string okey = rk["okey"];
            if (okey.Length == 0 || okey.Split('|').Length != 4) return "the pairing in run " + rk["run"] + " has no previous key recorded";
            byte[] other = kv.Get(NkKey(okey));
            if (other != null && StoreUtil.S(other) != id)
                return "the old address (" + okey + ") has since been seen again as entity " + StoreUtil.S(other) + "; split is not possible (merge that entity instead)";
            if (dry) return "";
            string newNk = rk["host"].ToLowerInvariant() + "|" + rk["ip"] + "|" + rk["port"] + "|" + rk["vh"];
            // versions: the one current at P (or the one P created) starts the new service
            long ev = E.Long("ver"), vb = 0;
            List<long> moved = new List<long>();
            for (long k = 1; k <= ev; k++) { long sq = Ver(id, k).Long("_seq"); if (sq < P) vb = k; else moved.Add(k); }
            if (vb == 0) throw new InvalidDataException("entity " + id + " has no version before the pairing in run " + rk["run"]);
            string nid = null;
            for (int n = 0; n < 100; n++)
            {
                string cand = MakeId(newNk, rk["run"], n);
                if (cand != id && Get(EntKey(cand)) == null) { nid = cand; break; }
            }
            if (nid == null) throw new InvalidDataException("could not allocate an entity id for the split");
            Dictionary<long, long> map = new Dictionary<long, long>();
            long nv = 0;
            if (moved.Count == 0 || Ver(id, moved[0]).Long("_seq") != P)
            {
                Rec v1 = Copy(Ver(id, vb)); v1.SetLong("_ver", 1); v1.SetLong("_seq", P); v1["_run"] = rk["run"]; v1["_at"] = rk["at"];
                Put(VerKey(nid, 1), v1); nv = 1; map[vb] = 1;
            }
            foreach (long k in moved)
            {
                Rec v = Copy(Ver(id, k)); nv++; v.SetLong("_ver", nv); Put(VerKey(nid, nv), v); map[k] = nv;
                kv.Delete(VerKey(id, k));
            }
            // events from P on belong to the new service; the pairing itself becomes its "added"
            for (int i = 0; i < seqs.Count; i++)
            {
                long sq = seqs[i];
                if (sq < P) continue;
                Rec e2 = Get(EvKey(sq, id));
                DropEvent(sq, id);
                if (e2 == null) continue;
                if (sq == P)
                {
                    Rec ad = new Rec();
                    ad["type"] = "added"; ad.SetLong("seq", P); ad["run"] = rk["run"]; ad["at"] = rk["at"]; ad["eid"] = nid;
                    ad["host"] = rk["host"]; ad["ip"] = rk["ip"]; ad["port"] = rk["port"]; ad["vh"] = rk["vh"]; ad["url"] = rk["url"];
                    ad.SetLong("from", 0); ad.SetLong("to", 1);
                    e2 = ad;
                }
                else
                {
                    e2["eid"] = nid;
                    long f = e2.Long("from"), t = e2.Long("to");
                    if (map.ContainsKey(f)) e2.SetLong("from", map[f]);
                    if (map.ContainsKey(t)) e2.SetLong("to", map[t]);
                }
                PutEvent(sq, nid, e2);
            }
            Rec N = new Rec();
            N["id"] = nid;
            foreach (string f in new[] { "nk", "host", "ip", "port", "vh", "st", "la", "lr", "ap", "ms", "mr", "ra" }) if (E[f].Length > 0) N[f] = E[f];
            foreach (string f in E.Names.ToArray()) if (f.StartsWith("o:", StringComparison.Ordinal)) N[f] = E[f];
            N["fa"] = rk["at"]; N["fr"] = rk["run"]; N.SetLong("ver", nv);
            Rec nlast = Ver(nid, nv); N["h"] = nlast["_h"]; N["ca"] = nlast["_at"];
            Put(EntKey(nid), N);
            kv.Put(NkKey(E["nk"]), StoreUtil.B(nid));
            // the original returns to its old key; last seen = its last sighting before the pairing
            string[] ok = okey.Split('|');
            string oldHost = rk["was:Host"].Length > 0 ? rk["was:Host"] : (ok[0] == E["host"].ToLowerInvariant() ? E["host"] : ok[0]);
            E["nk"] = okey; E["host"] = oldHost; E["ip"] = rk["was:IP"].Length > 0 ? rk["was:IP"] : ok[1]; E["port"] = ok[2]; E["vh"] = ok[3];
            Rec vbr = Ver(id, vb);
            E.SetLong("ver", vb); E["h"] = vbr["_h"]; E["ca"] = vbr["_at"];
            E["la"] = rk["pla"].Length > 0 ? rk["pla"] : vbr["_at"]; E["lr"] = rk["plr"].Length > 0 ? rk["plr"] : vbr["_run"];
            E.RemovePrefix("o:");
            kv.Put(NkKey(okey), StoreUtil.B(id));
            RecomputeAbsence(E, PosOfRun(E["lr"]), pos);
            Put(EntKey(id), E);
            foreach (string[] side in new[] { new[] { id, nid }, new[] { nid, id } })
            {
                Rec me = new Rec(); Rec ent = side[0] == id ? E : N;
                me["type"] = "split"; me.SetLong("seq", pos); me["run"] = label; me["at"] = at; me["eid"] = side[0];
                me["host"] = ent["host"]; me["ip"] = ent["ip"]; me["port"] = ent["port"]; me["vh"] = ent["vh"]; me["url"] = Ver(side[0], ent.Long("ver"))["Url"];
                me.SetLong("from", ent.Long("ver")); me.SetLong("to", ent.Long("ver")); me["rule"] = "manual"; me["okey"] = "entity " + side[1]; me["note"] = reason;
                PutEvent(pos, side[0], me);
            }
            return "";
        }

        // absence of one service replayed from the archive: every run after its last sighting that checked its key
        // (same rule as ApplyAbsence, same per-run retire threshold)
        void RecomputeAbsence(Rec ent, long lastSeenPos, long beforePos)
        {
            string id = ent["id"];
            List<string> types;
            List<long> seqs = EventSeqs(id, out types);
            for (int i = 0; i < seqs.Count; i++) if (seqs[i] > lastSeenPos && seqs[i] < beforePos && (types[i] == "missing" || types[i] == "retired")) DropEvent(seqs[i], id);
            string st = "active"; long mr = 0; string ms = "", ra = "";
            long ap = lastSeenPos;
            List<Rec> runs = new List<Rec>();
            foreach (KeyValuePair<byte[], byte[]> r in kv.Scan(P("r"))) runs.Add(Rec.Decode(r.Value));
            foreach (Rec rr in runs)
            {
                long p = rr.Long("seq");
                if (p <= lastSeenPos || p >= beforePos || rr["kind"] == "correction" || rr["state"] != "ingested") continue;
                if (st == "retired") break;
                string dir = AbsRun(rr["archive"]);
                RunInfo run = RunInfo.Parse(File.ReadAllText(Path.Combine(dir, "run.json"), StoreUtil.Utf8));
                bool inScope = false;
                string want = ent["vh"] == "v" ? ent["ip"] + "|" + ent["port"] : ent["host"].ToLowerInvariant() + "|" + ent["port"];
                if (ent["vh"] != "v" || run.ProbeSans)
                    foreach (string l in StoreUtil.ReadLines(Path.Combine(dir, "checked.txt.gz")))
                    {
                        string[] f = l.Trim().Split('|');
                        if (f.Length < 3) continue;
                        string k = ent["vh"] == "v" ? f[1].ToLowerInvariant() + "|" + f[2] : f[0].ToLowerInvariant() + "|" + f[2];
                        if (k == want) { inScope = true; break; }
                    }
                if (!inScope) continue;
                string at = StoreUtil.Iso(run.Started);
                mr++; ap = p;
                string type = null;
                if (st == "active") ms = at;
                long ret = rr.Long("retireAfter") > 0 ? rr.Long("retireAfter") : RetireAfter;
                if (mr >= ret) { st = "retired"; ra = at; type = "retired"; }
                else if (st == "active") { st = "missing"; type = "missing"; }
                if (type != null)
                {
                    long ver = ent.Long("ver");
                    PutEvent(p, id, NewEvent(type, p, run, at, id, ent["host"], ent["ip"], ent["port"], ent["vh"], Ver(id, ver)["Url"], ver, ver));
                }
            }
            ent["st"] = st; ent.SetLong("ap", ap);
            if (mr > 0) ent.SetLong("mr", mr); else ent.Remove("mr");
            if (ms.Length > 0) ent["ms"] = ms; else ent.Remove("ms");
            if (ra.Length > 0) ent["ra"] = ra; else ent.Remove("ra");
        }

        // ---------------------------------------------------------------- backfill: insert older runs, replay in order
        public List<IngestSummary> Backfill(List<RunSources> list, bool allowPartial)
        {
            if (kv == null || shadow) throw new InvalidOperationException("store not open for writing");
            List<IngestSummary> res = new List<IngestSummary>();
            List<LedgerEntry> led = ReadLedgerStrict();
            List<string> added = new List<string>();
            foreach (RunSources src in list)
            {
                RunInfo run; LedgerEntry dup, last;
                CheckRun(src, allowPartial, led, out run, out dup, out last);
                if (dup != null) { IngestSummary d = new IngestSummary(); d.RunId = run.RunId; d.Seq = dup.Seq; d.AlreadyPresent = true; d.Archive = dup.Path; res.Add(d); continue; }
                long rows; double tv, tc;
                string rel = ArchiveRun(src, run, out rows, out tv, out tc);
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
                long lseq = led[led.Count - 1].Seq + 1;
                JsonObj o = new JsonObj().Num("seq", lseq).Str("type", "run").Str("runId", run.RunId).Str("runStarted", run.StartedAt).Str("path", rel)
                    .Bool("complete", run.Complete).Num("retireAfter", RetireAfter).Str("profile", run.Profile).Bool("backfill", true).Str("engine", Engine)
                    .Str("ingestedBy", "WebInventory " + ScannerVersion).Str("ingestedAt", StoreUtil.Iso(DateTimeOffset.Now)).Raw("files", "[" + string.Join(",", files) + "]");
                AppendLedger(o, led[led.Count - 1].Hash);
                led = ReadLedgerStrict();
                added.Add(run.RunId);
                Log("backfill: archived run " + run.RunId + " (started " + run.StartedAt + ")");
            }
            if (added.Count == 0) return res;
            Dictionary<string, IngestSummary> sums = Rebase(led, "backfill of " + string.Join(", ", added.ToArray()));
            foreach (string r in added) { IngestSummary s; if (sums.TryGetValue(r, out s)) res.Add(s); }
            return res;
        }

        // replays the whole history in run order into a fresh working database and appends a "rebase" entry with
        // the new order and every position's digests. Corrections stay right after the run they followed.
        Dictionary<string, IngestSummary> Rebase(List<LedgerEntry> led, string why)
        {
            Stopwatch sw = Stopwatch.StartNew();
            List<PlanItem> old = BuildPlan(led);
            List<PlanItem> runs = new List<PlanItem>();
            Dictionary<PlanItem, List<PlanItem>> after = new Dictionary<PlanItem, List<PlanItem>>();
            PlanItem anchor = null;
            foreach (PlanItem it in old)
            {
                if (it.IsRun) { runs.Add(it); anchor = it; continue; }
                if (anchor == null) throw new InvalidDataException("a correction precedes every run in the ledger");
                List<PlanItem> l; if (!after.TryGetValue(anchor, out l)) { l = new List<PlanItem>(); after[anchor] = l; } l.Add(it);
            }
            runs.Sort(delegate(PlanItem x, PlanItem y)
            {
                int c = StoreUtil.ParseIso(x.E.RunStarted).CompareTo(StoreUtil.ParseIso(y.E.RunStarted));
                return c != 0 ? c : x.E.Seq.CompareTo(y.E.Seq);
            });
            List<PlanItem> plan = new List<PlanItem>();
            foreach (PlanItem r in runs)
            {
                plan.Add(r);
                List<PlanItem> l; if (after.TryGetValue(r, out l)) plan.AddRange(l);
            }
            long R = led[led.Count - 1].Seq + 1;
            string rdir = "rebase/" + D6(R);
            if (Directory.Exists(AbsRun(rdir))) Directory.Delete(AbsRun(rdir), true);
            ResetDb();
            List<string> items = new List<string>(), derived = new List<string>();
            Dictionary<string, IngestSummary> sums = new Dictionary<string, IngestSummary>(StringComparer.Ordinal);
            List<PlanItem> done = new List<PlanItem>();
            foreach (PlanItem src in plan)
            {
                PlanItem it = new PlanItem();
                it.E = src.E; it.Pos = done.Count + 1; it.Snapshot = SnapshotFor(done, src.IsRun);
                string dd = AbsRun(rdir + "/" + D6(it.Pos));
                IngestSummary s = ApplyItem(it, dd);
                it.ChangesDigest = s.ChangesDigest; it.StateDigest = s.StateDigest; it.Void = s.Void;
                done.Add(it);
                sums[it.E.RunId] = s;
                JsonObj io = new JsonObj().Num("seq", it.E.Seq).Str("runId", it.E.RunId).Str("changesDigest", s.ChangesDigest).Str("stateDigest", s.StateDigest);
                if (!it.Snapshot) io.Bool("snapshot", false);
                if (s.Void.Length > 0) io.Str("void", s.Void);
                items.Add(io.ToString());
                long b;
                foreach (string n in it.Snapshot ? new[] { "changes.jsonl.gz", "state.jsonl.gz" } : new[] { "changes.jsonl.gz" })
                    derived.Add(new JsonObj().Str("name", D6(it.Pos) + "/" + n).Str("sha256", StoreUtil.FileSha256(Path.Combine(dd, n), out b)).Num("bytes", b).ToString());
            }
            JsonObj o = new JsonObj().Num("seq", R).Str("type", "rebase").Str("reason", why).Str("path", rdir).Str("engine", Engine)
                .Str("ingestedBy", "WebInventory " + ScannerVersion).Str("ingestedAt", StoreUtil.Iso(DateTimeOffset.Now))
                .Raw("plan", "[" + string.Join(",", items) + "]").Raw("derived", "[" + string.Join(",", derived) + "]");
            string head = AppendLedger(o, led[led.Count - 1].Hash);
            kv.Begin(); Rec meta = Get(MetaKey) ?? new Rec(); meta["rebase"] = R.ToString(CultureInfo.InvariantCulture); meta["ledgerHead"] = head; Put(MetaKey, meta); kv.Commit(true); kv.Flush();
            foreach (IngestSummary s in sums.Values) s.LedgerHead = head;
            Log(string.Format(CultureInfo.InvariantCulture, "rebase seq {0}: {1} runs and {2} corrections replayed in run order in {3:0.0}s ({4}); ledger head {5}",
                R, runs.Count, plan.Count - runs.Count, sw.Elapsed.TotalSeconds, why, head));
            return sums;
        }

        // ---------------------------------------------------------------- -AsOf
        List<Dictionary<string, string>> AsOfRows(DateTimeOffset asof)
        {
            List<Dictionary<string, string>> rows = new List<Dictionary<string, string>>();
            List<LedgerEntry> led = ReadLedgerStrict();
            List<PlanItem> plan = BuildPlan(led);
            PlanItem pick = null;
            foreach (PlanItem it in plan) if (it.IsRun && StoreUtil.ParseIso(it.E.RunStarted) <= asof) pick = it;
            if (pick == null) { Messages.Add("no run in the store started at or before " + StoreUtil.Iso(asof)); return rows; }
            string sf = Path.Combine(pick.Derived, "state.jsonl.gz");
            if (pick.Snapshot && File.Exists(sf))
            {
                Messages.Add("inventory as of run " + pick.E.RunId + " (" + pick.E.RunStarted + ")");
                foreach (string l in StoreUtil.ReadLines(sf))
                {
                    if (l.Length == 0) continue;
                    Dictionary<string, object> o = (Dictionary<string, object>)StoreJson.Parse(l);
                    Dictionary<string, string> row = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (string c in InventoryColumns) row[c] = StoreUtil.Str(o, c);
                    rows.Add(row);
                }
                return rows;
            }
            Stopwatch sw = Stopwatch.StartNew();
            InventoryStore sh = NewShadow();
            try
            {
                foreach (PlanItem it in plan) { if (it.Pos > pick.Pos) break; sh.ApplyItem(it, null); }
                foreach (KeyValuePair<byte[], byte[]> e in sh.kv.Scan(P("e")))
                {
                    Rec ent = Rec.Decode(e.Value);
                    rows.Add(InventoryRow(ent, sh.Ver(ent["id"], ent.Long("ver"))));
                }
            }
            finally { sh.kv.Dispose(); }
            Messages.Add(string.Format(CultureInfo.InvariantCulture, "inventory as of run {0} ({1}); no snapshot kept for that run, history replayed in memory ({2} positions, {3:0.0}s)",
                pick.E.RunId, pick.E.RunStarted, pick.Pos, sw.Elapsed.TotalSeconds));
            return rows;
        }

        // ---------------------------------------------------------------- options kept in STORE.json
        // snapshotEvery 0 = keep; anchorEventLog -1 = keep, 0 = off, 1 = on; anchorCertificate null = keep, "" = off
        // (PowerShell passes $null to a string parameter as "", hence the explicit setCertificate flag)
        public void SetOptions(int snapshotEvery, int anchorEventLog, bool setCertificate, string anchorCertificate)
        {
            if (!setCertificate) anchorCertificate = null;
            bool dirty = false;
            if (snapshotEvery > 0 && snapshotEvery != SnapshotEvery) { Log(string.Format(CultureInfo.InvariantCulture, "snapshot interval changed from {0} to {1} (runs ingested from now on)", SnapshotEvery, snapshotEvery)); SnapshotEvery = snapshotEvery; dirty = true; }
            if (anchorEventLog >= 0 && (anchorEventLog == 1) != AnchorEventLog) { AnchorEventLog = anchorEventLog == 1; Log("event-log anchoring " + (AnchorEventLog ? "on" : "off")); dirty = true; }
            if (anchorCertificate != null && anchorCertificate != AnchorCertificate)
            {
                AnchorCertificate = anchorCertificate;
                List<string> pr = new List<string>(); List<LedgerEntry> led = ReadLedger(pr);
                AnchorFrom = anchorCertificate.Length > 0 && led.Count > 0 ? led[led.Count - 1].Seq + 1 : 0;
                Log(anchorCertificate.Length > 0 ? "ledger entries from seq " + AnchorFrom + " on are signed with certificate " + anchorCertificate : "ledger signing off");
                dirty = true;
            }
            if (dirty && !shadow) SaveStoreJson();
        }

        public List<string[]> LedgerLines()
        {
            List<string[]> o = new List<string[]>();
            List<string> pr = new List<string>();
            foreach (LedgerEntry e in ReadLedger(pr)) o.Add(new[] { e.Seq.ToString(CultureInfo.InvariantCulture), e.Hash, e.Line, e.Type });
            return o;
        }

        // ---------------------------------------------------------------- verification
        // Ledger chain, archived file hashes, the whole history replayed in memory (every rebase replayed again from
        // scratch) compared position by position with the ledger, and the working database against the last state.
        public bool Verify(List<string> report)
        {
            bool ok = true;
            List<string> problems = new List<string>();
            List<LedgerEntry> led = ReadLedger(problems);
            foreach (string p in problems) { report.Add("FAIL ledger: " + p); ok = false; }
            int runs = 0, corrections = 0, rebases = 0;
            foreach (LedgerEntry e in led) { if (e.Type == "run") runs++; else if (e.Type == "correction") corrections++; else if (e.Type == "rebase") rebases++; }
            if (problems.Count == 0) report.Add(string.Format(CultureInfo.InvariantCulture, "ok   ledger: {0} lines, chain intact, head {1}", led.Count, led.Count > 0 ? led[led.Count - 1].Hash : "-"));
            HashSet<string> ledgered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int filesOk = 0;
            foreach (LedgerEntry e in led)
            {
                if (e.Type == "genesis") continue;
                if (e.Type != "rebase") ledgered.Add(e.Path);
                string dir = AbsRun(e.Path);
                if (!Directory.Exists(dir)) { report.Add("FAIL " + e.Type + " " + e.RunId + ": archive folder missing (" + e.Path + ")"); ok = false; continue; }
                foreach (string arr in new[] { "files", "derived" })
                {
                    if (e.Type == "rebase" && arr == "files") continue;
                    System.Collections.IEnumerable files = StoreUtil.Field(e.Obj, arr) as System.Collections.IEnumerable;
                    if (files == null)
                    {
                        if (arr == "derived" && e.Backfill) continue;
                        report.Add("FAIL " + e.Type + " " + e.RunId + ": ledger entry lists no " + arr); ok = false; continue;
                    }
                    foreach (object f in files)
                    {
                        Dictionary<string, object> d = (Dictionary<string, object>)f;
                        string name = StoreUtil.Str(d, "name"), path = Path.Combine(dir, name.Replace('/', Path.DirectorySeparatorChar));
                        if (!File.Exists(path)) { report.Add("FAIL " + e.Type + " " + e.RunId + " seq " + e.Seq + ": " + name + " missing"); ok = false; continue; }
                        long b;
                        if (StoreUtil.FileSha256(path, out b) != StoreUtil.Str(d, "sha256")) { report.Add("FAIL " + e.Type + " " + e.RunId + " seq " + e.Seq + ": " + name + " altered (SHA-256 differs from the ledger)"); ok = false; }
                        else filesOk++;
                    }
                }
            }
            report.Add(string.Format(CultureInfo.InvariantCulture, "{0} archive: {1} runs, {2} corrections, {3} rebases, {4} files checked against the ledger", ok ? "ok  " : "FAIL", runs, corrections, rebases, filesOk));
            foreach (string rel in ArchivedFolders())
                if (!ledgered.Contains(rel))
                    report.Add("note archive\\" + rel.Replace('/', '\\') + " is not in the ledger yet (" + (File.Exists(Path.Combine(AbsRun(rel), "INPUTS.json")) ? "finished on the next open" : "incomplete copy; re-import the run") + ")");
            // independent replay (portable engine, in memory)
            Stopwatch sw = Stopwatch.StartNew();
            bool rebuildOk = true;
            string lastState = "";
            int applied = 0;
            InventoryStore sh = NewShadow();
            List<PlanItem> cur = new List<PlanItem>();
            try
            {
                foreach (LedgerEntry e in led)
                {
                    if (!rebuildOk) break;
                    if (e.Type == "run" || e.Type == "correction")
                    {
                        PlanItem it = new PlanItem(); it.E = e; it.Pos = cur.Count + 1; it.Snapshot = e.Snapshot && e.Type == "run";
                        cur.Add(it);
                        if (e.Backfill && e.StateDigest.Length == 0) continue;   // placed by the rebase that follows
                        IngestSummary s;
                        try { s = sh.ApplyItem(it, null); applied++; }
                        catch (Exception ex) { report.Add("FAIL replay at " + e.RunId + ": " + ex.Message); rebuildOk = false; break; }
                        if (s.ChangesDigest != e.ChangesDigest) { report.Add("FAIL replay " + e.RunId + ": change events differ from the ledger"); rebuildOk = false; }
                        if (s.StateDigest != e.StateDigest) { report.Add("FAIL replay " + e.RunId + ": inventory state differs from the ledger"); rebuildOk = false; }
                        lastState = e.StateDigest;
                    }
                    else if (e.Type == "rebase")
                    {
                        sh.kv.Dispose(); sh = NewShadow();
                        List<LedgerEntry> upto = new List<LedgerEntry>();
                        foreach (LedgerEntry x in led) { upto.Add(x); if (x == e) break; }
                        cur = BuildPlan(upto);
                        foreach (PlanItem it in cur)
                        {
                            IngestSummary s;
                            try { s = sh.ApplyItem(it, null); applied++; }
                            catch (Exception ex) { report.Add("FAIL replay of rebase seq " + e.Seq + " at " + it.E.RunId + ": " + ex.Message); rebuildOk = false; break; }
                            if (s.ChangesDigest != it.ChangesDigest || s.StateDigest != it.StateDigest) { report.Add("FAIL replay of rebase seq " + e.Seq + " at position " + it.Pos + " (" + it.E.RunId + "): digests differ from the ledger"); rebuildOk = false; }
                            lastState = it.StateDigest;
                        }
                    }
                }
            }
            finally { sh.kv.Dispose(); }
            if (rebuildOk) report.Add(string.Format(CultureInfo.InvariantCulture, "ok   rebuild: {0} positions re-applied from the archive in memory, every change and state digest matches the ledger ({1:0.0}s)", applied, sw.Elapsed.TotalSeconds));
            ok &= rebuildOk;
            if (kv == null) report.Add("note working database not present or not openable here (" + Engine + "); archive checks only");
            else
            {
                Rec meta = Get(MetaKey) ?? new Rec();
                long lastPos = 0;
                try { lastPos = BuildPlan(led).Count; } catch (Exception) { }
                if (meta["rebase"] != LastRebase(led) && meta.Long("seq") > 0) report.Add("note working database predates the latest rebase; it is rebuilt on the next open");
                else if (meta.Long("seq") < lastPos) report.Add("note working database is behind the archive (position " + meta.Long("seq") + " of " + lastPos + "); it catches up on the next open");
                else if (meta.Long("seq") > lastPos) { report.Add("FAIL working database has positions the ledger does not (" + meta.Long("seq") + " vs " + lastPos + "): -RebuildStore"); ok = false; }
                else
                {
                    string live = LiveStateDigest();
                    if (lastPos > 0 && live != lastState) { report.Add("FAIL working database (" + Engine + ") differs from the archive's last state; -RebuildStore recreates it"); ok = false; }
                    else report.Add("ok   working database (" + Engine + ") matches the archive's last state digest");
                }
            }
            return ok;
        }
    }
}
