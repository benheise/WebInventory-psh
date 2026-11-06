
// ============================================================================
// WebInv store - inventory history (first/last seen, versions, change events) kept in a working database
// that is a rebuildable cache of an append-only archive (per-run folders + hash-chained ledger).
//   * ESENT engine: esent.dll (part of Windows) through direct P/Invoke; one process opens a store at a time.
//   * File engine: in-memory ordered map saved atomically to one file; identical semantics (PowerShell 7 on
//     Linux/macOS, and the reference the ESENT engine is checked against).
// C# 5 / .NET Framework 4.7.2. Nothing here runs during a scan: ingest reads the finished run's output files.
// ============================================================================
namespace WebInv
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.IO.Compression;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.RegularExpressions;

    // ------------------------------------------------------------------ ESENT interop
    // Declarations follow ManagedEsent (MIT; github.com/microsoft/ManagedEsent): ANSI entry points for ASCII object
    // names, W entry points for paths. JET_INSTANCE/JET_SESID/JET_TABLEID are pointer-sized, JET_DBID/JET_COLUMNID/
    // JET_GRBIT are 32-bit.
    [StructLayout(LayoutKind.Sequential)]
    internal struct JetColumnDef
    {
        public uint cbStruct;
        public uint columnid;
        public uint coltyp;
        public ushort wCountry;
        public ushort langid;
        public ushort cp;
        public ushort wCollate;
        public uint cbMax;
        public uint grbit;
    }

    internal static class EsentNative
    {
        const string Dll = "esent.dll";
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int JetCreateInstance2W(out IntPtr instance, string szInstanceName, string szDisplayName, uint grbit);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetInit(ref IntPtr instance);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetTerm2(IntPtr instance, uint grbit);
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true, EntryPoint = "JetSetSystemParameterW")]
        public static extern int JetSetSystemParameterInstance(ref IntPtr pinstance, IntPtr sesid, uint paramid, IntPtr lParam, string szParam);
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true, EntryPoint = "JetSetSystemParameterW")]
        public static extern int JetSetSystemParameterGlobal(IntPtr pinstanceNull, IntPtr sesid, uint paramid, IntPtr lParam, string szParam);
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int JetBeginSessionW(IntPtr instance, out IntPtr sesid, string username, string password);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetEndSession(IntPtr sesid, uint grbit);
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int JetCreateDatabaseW(IntPtr sesid, string szFilename, string szConnect, out uint dbid, uint grbit);
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int JetAttachDatabaseW(IntPtr sesid, string szFilename, uint grbit);
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int JetDetachDatabaseW(IntPtr sesid, string szFilename);
        [DllImport(Dll, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int JetOpenDatabaseW(IntPtr sesid, string szFilename, string szConnect, out uint dbid, uint grbit);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetCloseDatabase(IntPtr sesid, uint dbid, uint grbit);
        [DllImport(Dll, CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern int JetCreateTable(IntPtr sesid, uint dbid, string szTableName, int pages, int density, out IntPtr tableid);
        [DllImport(Dll, CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern int JetAddColumn(IntPtr sesid, IntPtr tableid, string szColumnName, [In] ref JetColumnDef columndef, [In] byte[] pvDefault, uint cbDefault, out uint columnid);
        [DllImport(Dll, CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern int JetCreateIndex(IntPtr sesid, IntPtr tableid, string szIndexName, uint grbit, string szKey, uint cbKey, uint lDensity);
        [DllImport(Dll, CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern int JetOpenTable(IntPtr sesid, uint dbid, string szTableName, byte[] pvParameters, uint cbParameters, uint grbit, out IntPtr tableid);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetCloseTable(IntPtr sesid, IntPtr tableid);
        [DllImport(Dll, CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern int JetGetTableColumnInfo(IntPtr sesid, IntPtr tableid, string szColumnName, ref JetColumnDef columndef, uint cbMax, uint infoLevel);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetBeginTransaction(IntPtr sesid);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetCommitTransaction(IntPtr sesid, uint grbit);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetRollback(IntPtr sesid, uint grbit);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetMakeKey(IntPtr sesid, IntPtr tableid, byte[] pvData, uint cbData, uint grbit);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetSeek(IntPtr sesid, IntPtr tableid, uint grbit);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetMove(IntPtr sesid, IntPtr tableid, int cRow, uint grbit);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetRetrieveColumn(IntPtr sesid, IntPtr tableid, uint columnid, [Out] byte[] pvData, uint cbData, out uint cbActual, uint grbit, IntPtr pretinfo);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetSetColumn(IntPtr sesid, IntPtr tableid, uint columnid, [In] byte[] pvData, uint cbData, uint grbit, IntPtr psetinfo);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetPrepareUpdate(IntPtr sesid, IntPtr tableid, uint prep);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetUpdate(IntPtr sesid, IntPtr tableid, [Out] byte[] pvBookmark, uint cbBookmark, out uint cbActual);
        [DllImport(Dll, ExactSpelling = true)]
        public static extern int JetDelete(IntPtr sesid, IntPtr tableid);

        // JET_param
        public const uint ParamSystemPath = 0, ParamTempPath = 1, ParamLogFilePath = 2, ParamBaseName = 3, ParamMaxVerPages = 9,
            ParamCircularLog = 17, ParamNoInformationEvent = 50, ParamDatabasePageSize = 64, ParamCreatePathIfNotExist = 100;
        // JET_coltyp, column/index grbits
        public const uint ColtypBinary = 9, ColtypLongBinary = 11, ColumnNotNull = 0x4;
        public const uint IndexUnique = 0x1, IndexPrimary = 0x2, IndexDisallowNull = 0x4;
        // seek / move / makekey / prepare / set / commit / term
        public const uint SeekEQ = 0x1, SeekGE = 0x8, SeekGT = 0x10, NewKey = 0x1;
        public const int MoveFirst = int.MinValue, MoveNext = 1;
        public const uint PrepInsert = 0, PrepReplace = 2, PrepCancel = 3, SetZeroLength = 0x20, CommitLazyFlush = 0x1, TermComplete = 0x1;
        // errors (negative) and warnings (positive) handled explicitly
        public const int ErrRecordNotFound = -1601, ErrNoCurrentRecord = -1603;
        public const int WrnColumnNull = 1004, WrnBufferTruncated = 1006;
    }

    public class EsentException : Exception
    {
        public readonly int Code;
        public EsentException(int code, string call) : base(Describe(code, call)) { Code = code; }
        static string Describe(int code, string call)
        {
            string what;
            switch (code)
            {
                case -550: what = "database was not shut down cleanly and its transaction logs are missing or do not match (rebuild the store from its archive: -RebuildStore)"; break;
                case -1032: what = "access denied to a database or log file (another process may have the store open)"; break;
                case -1215: what = "database file is in use by another process"; break;
                case -1213: what = "database page size does not match this process (another ESENT user in this process?)"; break;
                case -1209: case -514: what = "database or log format is newer than this Windows version supports"; break;
                case -1206: case -1018: case -1121: what = "database corruption detected (rebuild the store from its archive: -RebuildStore)"; break;
                case -1808: case -529: case -1012: what = "disk full"; break;
                case -1069: what = "version store exhausted"; break;
                case -1023: what = "invalid path"; break;
                case -501: case -528: case -543: case -515: what = "transaction log files are missing or corrupt (rebuild the store from its archive: -RebuildStore)"; break;
                default: what = "ESENT error"; break;
            }
            return string.Format(CultureInfo.InvariantCulture, "{0} failed: {1} ({2})", call, what, code);
        }
    }

    // ------------------------------------------------------------------ ordered key-value engines
    // Contract (identical on both engines, enforced by the conformance self-test):
    //  * keys: 1..MaxKey bytes, ordered as unsigned bytes (a prefix sorts before its extensions); values any length
    //  * every Put/Delete inside Begin()..Commit()/Rollback(); one transaction at a time; Rollback undoes everything
    //    since Begin
    //  * ScanPage(prefix, after, max): up to max pairs with the prefix and key > after (after null = from the prefix),
    //    in key order, copied out - callers may modify the store between pages
    //  * Commit(durable: false) may be lost on a crash; Commit(true) and Flush() are durability points
    public abstract class KvEngine : IDisposable
    {
        // ESENT normalises a binary key column in 8-byte chunks plus a count byte (+1 header byte) and the key limit is
        // 255 normalised bytes: 200 raw bytes -> 226 normalised
        public const int MaxKey = 200;
        public abstract string Name { get; }
        public abstract byte[] Get(byte[] key);
        public abstract void Put(byte[] key, byte[] value);
        public abstract bool Delete(byte[] key);
        public abstract List<KeyValuePair<byte[], byte[]>> ScanPage(byte[] prefix, byte[] after, int max);
        public abstract void Begin();
        public abstract void Commit(bool durable);
        public abstract void Rollback();
        public abstract bool InTransaction { get; }
        public virtual void Flush() { }
        public abstract void Dispose();

        public IEnumerable<KeyValuePair<byte[], byte[]>> Scan(byte[] prefix)
        {
            byte[] after = null;
            while (true)
            {
                List<KeyValuePair<byte[], byte[]>> page = ScanPage(prefix, after, 512);
                foreach (KeyValuePair<byte[], byte[]> kv in page) yield return kv;
                if (page.Count < 512) yield break;
                after = page[page.Count - 1].Key;
            }
        }

        protected static void CheckKey(byte[] key)
        {
            if (key == null || key.Length == 0 || key.Length > MaxKey) throw new ArgumentException("key length must be 1.." + MaxKey + " bytes (got " + (key == null ? 0 : key.Length) + ")");
        }
        public static bool StartsWith(byte[] k, byte[] prefix)
        {
            if (k.Length < prefix.Length) return false;
            for (int i = 0; i < prefix.Length; i++) if (k[i] != prefix[i]) return false;
            return true;
        }
    }

    public sealed class ByteOrder : IComparer<byte[]>, IEqualityComparer<byte[]>
    {
        public static readonly ByteOrder Instance = new ByteOrder();
        public int Compare(byte[] a, byte[] b)
        {
            int n = Math.Min(a.Length, b.Length);
            for (int i = 0; i < n; i++) { int d = a[i] - b[i]; if (d != 0) return d; }
            return a.Length - b.Length;
        }
        public bool Equals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }
        public int GetHashCode(byte[] a)
        {
            unchecked { uint h = 2166136261; for (int i = 0; i < a.Length; i++) { h ^= a[i]; h *= 16777619; } return (int)h; }
        }
    }

    // Sorted key index: a list of sorted chunks (bounded inserts, binary-searched lower bound)
    sealed class KeyIndex
    {
        const int Chunk = 512;
        readonly List<List<byte[]>> chunks = new List<List<byte[]>>();
        public int Count;
        static int Lower(List<byte[]> l, byte[] k)
        {
            int lo = 0, hi = l.Count;
            while (lo < hi) { int m = (lo + hi) >> 1; if (ByteOrder.Instance.Compare(l[m], k) < 0) lo = m + 1; else hi = m; }
            return lo;
        }
        int ChunkFor(byte[] k)
        {
            // last chunk whose first key <= k (or 0)
            int lo = 0, hi = chunks.Count - 1, r = 0;
            while (lo <= hi) { int m = (lo + hi) >> 1; if (ByteOrder.Instance.Compare(chunks[m][0], k) <= 0) { r = m; lo = m + 1; } else hi = m - 1; }
            return r;
        }
        public void Add(byte[] k)
        {
            if (chunks.Count == 0) { chunks.Add(new List<byte[]> { k }); Count++; return; }
            int c = ChunkFor(k);
            List<byte[]> l = chunks[c];
            l.Insert(Lower(l, k), k); Count++;
            if (l.Count > 2 * Chunk)
            {
                List<byte[]> tail = l.GetRange(Chunk, l.Count - Chunk);
                l.RemoveRange(Chunk, l.Count - Chunk);
                chunks.Insert(c + 1, tail);
            }
        }
        public void Remove(byte[] k)
        {
            if (chunks.Count == 0) return;
            int c = ChunkFor(k);
            List<byte[]> l = chunks[c];
            int i = Lower(l, k);
            if (i < l.Count && ByteOrder.Instance.Compare(l[i], k) == 0) { l.RemoveAt(i); Count--; if (l.Count == 0) chunks.RemoveAt(c); }
        }
        // keys >= start (or > start when exclusive), in order
        public IEnumerable<byte[]> From(byte[] start, bool exclusive)
        {
            if (chunks.Count == 0) yield break;
            int c = ChunkFor(start);
            int i = Lower(chunks[c], start);
            for (; c < chunks.Count; c++, i = 0)
            {
                List<byte[]> l = chunks[c];
                for (; i < l.Count; i++)
                {
                    if (exclusive && ByteOrder.Instance.Compare(l[i], start) == 0) continue;
                    yield return l[i];
                }
            }
        }
        public IEnumerable<byte[]> All() { foreach (List<byte[]> l in chunks) foreach (byte[] k in l) yield return k; }
        public void Clear() { chunks.Clear(); Count = 0; }
    }

    // Portable engine: ordered map in memory, saved to one file atomically on Flush (path null = memory only)
    public sealed class FileKv : KvEngine
    {
        static readonly byte[] Magic = Encoding.ASCII.GetBytes("WIKV1\n");
        readonly KeyIndex index = new KeyIndex();
        readonly Dictionary<byte[], byte[]> vals = new Dictionary<byte[], byte[]>(ByteOrder.Instance);
        readonly List<KeyValuePair<byte[], byte[]>> journal = new List<KeyValuePair<byte[], byte[]>>();
        readonly HashSet<byte[]> journaled = new HashSet<byte[]>(ByteOrder.Instance);
        readonly string path;
        bool inTx, dirty;
        public FileKv(string path)
        {
            this.path = path;
            if (path != null && File.Exists(path)) Load();
        }
        public override string Name { get { return path == null ? "memory" : "file"; } }
        public int Count { get { return vals.Count; } }
        public override bool InTransaction { get { return inTx; } }
        public override byte[] Get(byte[] key) { CheckKey(key); byte[] v; return vals.TryGetValue(key, out v) ? v : null; }
        void Journal(byte[] key)
        {
            if (!inTx) throw new InvalidOperationException("write outside a transaction");
            if (journaled.Add(key)) { byte[] old; journal.Add(new KeyValuePair<byte[], byte[]>(key, vals.TryGetValue(key, out old) ? old : null)); }
        }
        public override void Put(byte[] key, byte[] value)
        {
            CheckKey(key);
            if (value == null) throw new ArgumentNullException("value");
            key = (byte[])key.Clone();
            Journal(key);
            if (!vals.ContainsKey(key)) index.Add(key);
            vals[key] = (byte[])value.Clone();
            dirty = true;
        }
        public override bool Delete(byte[] key)
        {
            CheckKey(key);
            if (!inTx) throw new InvalidOperationException("write outside a transaction");
            if (!vals.ContainsKey(key)) return false;
            key = (byte[])key.Clone();
            Journal(key);
            vals.Remove(key); index.Remove(key); dirty = true;
            return true;
        }
        public override List<KeyValuePair<byte[], byte[]>> ScanPage(byte[] prefix, byte[] after, int max)
        {
            List<KeyValuePair<byte[], byte[]>> r = new List<KeyValuePair<byte[], byte[]>>();
            IEnumerable<byte[]> seq = (after == null) ? (prefix.Length == 0 ? index.All() : index.From(prefix, false)) : index.From(after, true);
            foreach (byte[] k in seq)
            {
                if (!StartsWith(k, prefix)) break;
                r.Add(new KeyValuePair<byte[], byte[]>((byte[])k.Clone(), vals[k]));
                if (r.Count >= max) break;
            }
            return r;
        }
        public override void Begin() { if (inTx) throw new InvalidOperationException("transaction already open"); inTx = true; }
        public override void Commit(bool durable) { if (!inTx) throw new InvalidOperationException("no transaction"); journal.Clear(); journaled.Clear(); inTx = false; if (durable) Flush(); }
        public override void Rollback()
        {
            if (!inTx) return;
            for (int i = journal.Count - 1; i >= 0; i--)
            {
                byte[] k = journal[i].Key, old = journal[i].Value;
                bool had = vals.ContainsKey(k);
                if (old == null) { if (had) { vals.Remove(k); index.Remove(k); } }
                else { if (!had) index.Add(k); vals[k] = old; }
            }
            journal.Clear(); journaled.Clear(); inTx = false;
        }
        public override void Flush()
        {
            if (path == null || !dirty) return;
            if (inTx) throw new InvalidOperationException("flush inside a transaction");
            string tmp = path + ".tmp";
            using (FileStream fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                fs.Write(Magic, 0, Magic.Length);
                using (GZipStream gz = new GZipStream(fs, CompressionLevel.Fastest, true))
                using (BinaryWriter w = new BinaryWriter(gz))
                using (Sha256Acc h = new Sha256Acc())
                {
                    foreach (byte[] k in index.All())
                    {
                        byte[] v = vals[k];
                        w.Write(k.Length); w.Write(k); w.Write(v.Length); w.Write(v);
                        h.Append(BitConverter.GetBytes(k.Length)); h.Append(k); h.Append(BitConverter.GetBytes(v.Length)); h.Append(v);
                    }
                    w.Write(-1);
                    w.Write(h.Final());
                }
                fs.Flush(true);
            }
            if (File.Exists(path)) File.Replace(tmp, path, null); else File.Move(tmp, path);
            dirty = false;
        }
        void Load()
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                byte[] m = new byte[Magic.Length];
                if (fs.Read(m, 0, m.Length) != m.Length || !ByteOrder.Instance.Equals(m, Magic)) throw new InvalidDataException("not a WebInventory store file: " + path);
                using (GZipStream gz = new GZipStream(fs, CompressionMode.Decompress))
                using (BinaryReader r = new BinaryReader(gz))
                using (Sha256Acc h = new Sha256Acc())
                {
                    while (true)
                    {
                        int kl = r.ReadInt32();
                        if (kl == -1) break;
                        if (kl <= 0 || kl > MaxKey) throw new InvalidDataException("corrupt store file (key length) " + path);
                        byte[] k = r.ReadBytes(kl);
                        int vl = r.ReadInt32();
                        if (vl < 0) throw new InvalidDataException("corrupt store file (value length) " + path);
                        byte[] v = r.ReadBytes(vl);
                        if (k.Length != kl || v.Length != vl) throw new InvalidDataException("truncated store file " + path);
                        h.Append(BitConverter.GetBytes(kl)); h.Append(k); h.Append(BitConverter.GetBytes(vl)); h.Append(v);
                        if (!vals.ContainsKey(k)) index.Add(k);
                        vals[k] = v;
                    }
                    byte[] want = r.ReadBytes(32), got = h.Final();
                    if (!ByteOrder.Instance.Equals(want, got)) throw new InvalidDataException("store file checksum mismatch " + path);
                }
            }
        }
        public override void Dispose() { Rollback(); }
    }

    // ESENT engine: one table "kv" (k Binary(255) primary key, v LongBinary)
    public sealed class EsentKv : KvEngine
    {
        IntPtr inst = IntPtr.Zero, ses = IntPtr.Zero, tab = IntPtr.Zero;
        uint dbid, colK, colV;
        bool dbOpen, attached, inTx;
        readonly string dbFile;
        byte[] buf = new byte[65536];
        static int instances;
        public override string Name { get { return "esent"; } }
        public override bool InTransaction { get { return inTx; } }
        public string DatabaseFile { get { return dbFile; } }

        public static bool Available
        {
            get
            {
                if (Environment.OSVersion.Platform != PlatformID.Win32NT) return false;
                return File.Exists(Path.Combine(Environment.SystemDirectory, "esent.dll"));
            }
        }

        static void Check(int err, string call) { if (err < 0) throw new EsentException(err, call); }

        public EsentKv(string dir)
        {
            dir = Path.GetFullPath(dir);
            if (!dir.EndsWith("\\", StringComparison.Ordinal)) dir += "\\";
            Directory.CreateDirectory(dir);
            Directory.CreateDirectory(dir + "tmp");
            dbFile = dir + "inventory.edb";
            // process-wide; fails harmlessly when another instance already set it (then the open reports any mismatch)
            EsentNative.JetSetSystemParameterGlobal(IntPtr.Zero, IntPtr.Zero, EsentNative.ParamDatabasePageSize, (IntPtr)8192, null);
            string name = string.Format(CultureInfo.InvariantCulture, "WebInv-{0}-{1}", System.Diagnostics.Process.GetCurrentProcess().Id, System.Threading.Interlocked.Increment(ref instances));
            Check(EsentNative.JetCreateInstance2W(out inst, name, "WebInventory store", 0), "JetCreateInstance2");
            try
            {
                SetPath(EsentNative.ParamSystemPath, dir);
                SetPath(EsentNative.ParamLogFilePath, dir);
                SetPath(EsentNative.ParamTempPath, dir + "tmp\\");
                SetPath(EsentNative.ParamBaseName, "wiv");
                SetInt(EsentNative.ParamCircularLog, 1);            // the archive is the backup; keep the log set small
                SetInt(EsentNative.ParamNoInformationEvent, 1);
                SetInt(EsentNative.ParamCreatePathIfNotExist, 1);
                SetInt(EsentNative.ParamMaxVerPages, 4096);         // headroom for batched ingest transactions
                Check(EsentNative.JetInit(ref inst), "JetInit");     // soft recovery from the logs happens here
                Check(EsentNative.JetBeginSessionW(inst, out ses, "", ""), "JetBeginSession");
                if (File.Exists(dbFile))
                {
                    Check(EsentNative.JetAttachDatabaseW(ses, dbFile, 0), "JetAttachDatabase"); attached = true;
                    Check(EsentNative.JetOpenDatabaseW(ses, dbFile, null, out dbid, 0), "JetOpenDatabase"); dbOpen = true;
                }
                else
                {
                    Check(EsentNative.JetCreateDatabaseW(ses, dbFile, null, out dbid, 0), "JetCreateDatabase"); attached = true; dbOpen = true;
                    CreateSchema();
                }
                Check(EsentNative.JetOpenTable(ses, dbid, "kv", null, 0, 0, out tab), "JetOpenTable");
                colK = ColumnId("k"); colV = ColumnId("v");
            }
            catch { Dispose(); throw; }
        }
        void SetPath(uint param, string value) { Check(EsentNative.JetSetSystemParameterInstance(ref inst, IntPtr.Zero, param, IntPtr.Zero, value), "JetSetSystemParameter(" + param + ")"); }
        void SetInt(uint param, int value) { Check(EsentNative.JetSetSystemParameterInstance(ref inst, IntPtr.Zero, param, (IntPtr)value, null), "JetSetSystemParameter(" + param + ")"); }
        void CreateSchema()
        {
            IntPtr t;
            Check(EsentNative.JetBeginTransaction(ses), "JetBeginTransaction");
            try
            {
                Check(EsentNative.JetCreateTable(ses, dbid, "kv", 16, 90, out t), "JetCreateTable");
                uint id;
                JetColumnDef ck = new JetColumnDef();
                ck.cbStruct = (uint)Marshal.SizeOf(typeof(JetColumnDef)); ck.coltyp = EsentNative.ColtypBinary; ck.cbMax = 255; ck.grbit = EsentNative.ColumnNotNull;
                Check(EsentNative.JetAddColumn(ses, t, "k", ref ck, null, 0, out id), "JetAddColumn(k)");
                JetColumnDef cv = new JetColumnDef();
                cv.cbStruct = (uint)Marshal.SizeOf(typeof(JetColumnDef)); cv.coltyp = EsentNative.ColtypLongBinary;
                Check(EsentNative.JetAddColumn(ses, t, "v", ref cv, null, 0, out id), "JetAddColumn(v)");
                Check(EsentNative.JetCreateIndex(ses, t, "pk", EsentNative.IndexUnique | EsentNative.IndexPrimary | EsentNative.IndexDisallowNull, "+k\0\0", 4, 90), "JetCreateIndex");
                Check(EsentNative.JetCloseTable(ses, t), "JetCloseTable");
                Check(EsentNative.JetCommitTransaction(ses, 0), "JetCommitTransaction");
            }
            catch { EsentNative.JetRollback(ses, 0); throw; }
        }
        uint ColumnId(string name)
        {
            JetColumnDef d = new JetColumnDef();
            d.cbStruct = (uint)Marshal.SizeOf(typeof(JetColumnDef));
            Check(EsentNative.JetGetTableColumnInfo(ses, tab, name, ref d, d.cbStruct, 0), "JetGetTableColumnInfo(" + name + ")");
            return d.columnid;
        }
        bool SeekEq(byte[] key)
        {
            Check(EsentNative.JetMakeKey(ses, tab, key, (uint)key.Length, EsentNative.NewKey), "JetMakeKey");
            int e = EsentNative.JetSeek(ses, tab, EsentNative.SeekEQ);
            if (e == EsentNative.ErrRecordNotFound) return false;
            Check(e, "JetSeek");
            return true;
        }
        byte[] Retrieve(uint col)
        {
            uint actual;
            int e = EsentNative.JetRetrieveColumn(ses, tab, col, buf, (uint)buf.Length, out actual, 0, IntPtr.Zero);
            if (e == EsentNative.WrnColumnNull) return new byte[0];
            if (e == EsentNative.WrnBufferTruncated)
            {
                byte[] big = new byte[actual];
                uint again;
                Check(EsentNative.JetRetrieveColumn(ses, tab, col, big, actual, out again, 0, IntPtr.Zero), "JetRetrieveColumn");
                if (again == actual) return big;
                byte[] r2 = new byte[again]; Buffer.BlockCopy(big, 0, r2, 0, (int)Math.Min(again, actual)); return r2;
            }
            Check(e, "JetRetrieveColumn");
            byte[] r = new byte[actual];
            Buffer.BlockCopy(buf, 0, r, 0, (int)actual);
            return r;
        }
        public override byte[] Get(byte[] key) { CheckKey(key); return SeekEq(key) ? Retrieve(colV) : null; }
        public override void Put(byte[] key, byte[] value)
        {
            CheckKey(key);
            if (value == null) throw new ArgumentNullException("value");
            if (!inTx) throw new InvalidOperationException("write outside a transaction");
            bool exists = SeekEq(key);
            Check(EsentNative.JetPrepareUpdate(ses, tab, exists ? EsentNative.PrepReplace : EsentNative.PrepInsert), "JetPrepareUpdate");
            try
            {
                if (!exists) Check(EsentNative.JetSetColumn(ses, tab, colK, key, (uint)key.Length, 0, IntPtr.Zero), "JetSetColumn(k)");
                Check(EsentNative.JetSetColumn(ses, tab, colV, value, (uint)value.Length, value.Length == 0 ? EsentNative.SetZeroLength : 0, IntPtr.Zero), "JetSetColumn(v)");
                uint act;
                Check(EsentNative.JetUpdate(ses, tab, null, 0, out act), "JetUpdate");
            }
            catch { EsentNative.JetPrepareUpdate(ses, tab, EsentNative.PrepCancel); throw; }
        }
        public override bool Delete(byte[] key)
        {
            CheckKey(key);
            if (!inTx) throw new InvalidOperationException("write outside a transaction");
            if (!SeekEq(key)) return false;
            Check(EsentNative.JetDelete(ses, tab), "JetDelete");
            return true;
        }
        public override List<KeyValuePair<byte[], byte[]>> ScanPage(byte[] prefix, byte[] after, int max)
        {
            List<KeyValuePair<byte[], byte[]>> r = new List<KeyValuePair<byte[], byte[]>>();
            byte[] start = after ?? prefix;
            int e;
            if (start.Length == 0) e = EsentNative.JetMove(ses, tab, EsentNative.MoveFirst, 0);
            else
            {
                Check(EsentNative.JetMakeKey(ses, tab, start, (uint)start.Length, EsentNative.NewKey), "JetMakeKey");
                e = EsentNative.JetSeek(ses, tab, after != null ? EsentNative.SeekGT : EsentNative.SeekGE);
            }
            if (e == EsentNative.ErrRecordNotFound || e == EsentNative.ErrNoCurrentRecord) return r;
            Check(e, "JetSeek");
            while (r.Count < max)
            {
                byte[] k = Retrieve(colK);
                if (!StartsWith(k, prefix)) break;
                r.Add(new KeyValuePair<byte[], byte[]>(k, Retrieve(colV)));
                int m = EsentNative.JetMove(ses, tab, EsentNative.MoveNext, 0);
                if (m == EsentNative.ErrNoCurrentRecord) break;
                Check(m, "JetMove");
            }
            return r;
        }
        public override void Begin()
        {
            if (inTx) throw new InvalidOperationException("transaction already open");
            Check(EsentNative.JetBeginTransaction(ses), "JetBeginTransaction"); inTx = true;
        }
        public override void Commit(bool durable)
        {
            if (!inTx) throw new InvalidOperationException("no transaction");
            Check(EsentNative.JetCommitTransaction(ses, durable ? 0 : EsentNative.CommitLazyFlush), "JetCommitTransaction"); inTx = false;
        }
        public override void Rollback()
        {
            if (!inTx) return;
            inTx = false;
            Check(EsentNative.JetRollback(ses, 0), "JetRollback");
        }
        public override void Dispose()
        {
            // best effort, in reverse order; JetTerm2(Complete) leaves the database in a clean-shutdown state
            if (ses != IntPtr.Zero)
            {
                if (inTx) { try { EsentNative.JetRollback(ses, 0); } catch { } inTx = false; }
                if (tab != IntPtr.Zero) { EsentNative.JetCloseTable(ses, tab); tab = IntPtr.Zero; }
                if (dbOpen) { EsentNative.JetCloseDatabase(ses, dbid, 0); dbOpen = false; }
                if (attached) { EsentNative.JetDetachDatabaseW(ses, dbFile); attached = false; }
                EsentNative.JetEndSession(ses, 0); ses = IntPtr.Zero;
            }
            if (inst != IntPtr.Zero) { EsentNative.JetTerm2(inst, EsentNative.TermComplete); inst = IntPtr.Zero; }
        }
    }
}
