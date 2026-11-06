
// ============================================================================
// WebInv inventory store logic: archive (per-run folders + hash-chained ledger) -> working database (KvEngine).
// The database is a deterministic function of the archive: rebuilding from the archive reproduces every entity id,
// version, change event and digest. Ingest is idempotent per run, so a crash at any point is repaired by re-applying.
// ============================================================================
namespace WebInv
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.IO.Compression;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.RegularExpressions;

    // SHA-256 accumulator: platform provider, or (when policy refuses it) an incremental managed implementation
    public sealed class Sha256Acc : IDisposable
    {
        IncrementalHash ih;
        uint[] H, w;
        byte[] block;
        int blen;
        long total;
        // one reusable accumulator per thread (Final() resets it) for the many small hashes of an ingest
        [ThreadStatic] static Sha256Acc shared;
        public static Sha256Acc Shared { get { if (shared == null) shared = new Sha256Acc(); return shared; } }
        static readonly uint[] K256 = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
        public Sha256Acc() : this(false) { }
        public Sha256Acc(bool managed)
        {
            if (!managed)
            {
                try { ih = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); }
                catch (Exception) { ih = null; }
            }
            if (ih == null) Reset();
        }
        void Reset()
        {
            H = new uint[] { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
            w = new uint[64]; block = new byte[64]; blen = 0; total = 0;
        }
        public bool Platform { get { return ih != null; } }
        public void Append(byte[] d) { Append(d, 0, d.Length); }
        public void Append(byte[] d, int off, int n)
        {
            if (ih != null) { ih.AppendData(d, off, n); return; }
            total += n;
            while (n > 0)
            {
                int c = Math.Min(64 - blen, n);
                Buffer.BlockCopy(d, off, block, blen, c);
                blen += c; off += c; n -= c;
                if (blen == 64) { Compress(); blen = 0; }
            }
        }
        public byte[] Final()
        {
            if (ih != null) return ih.GetHashAndReset();
            long bits = total * 8;
            byte[] pad = new byte[(blen < 56 ? 56 - blen : 120 - blen) + 8];
            pad[0] = 0x80;
            for (int i = 0; i < 8; i++) pad[pad.Length - 1 - i] = (byte)(bits >> (8 * i));
            Append(pad, 0, pad.Length);
            byte[] o = new byte[32];
            for (int i = 0; i < 8; i++) { o[i * 4] = (byte)(H[i] >> 24); o[i * 4 + 1] = (byte)(H[i] >> 16); o[i * 4 + 2] = (byte)(H[i] >> 8); o[i * 4 + 3] = (byte)H[i]; }
            Reset();
            return o;
        }
        public string FinalHex() { return StoreUtil.Hex(Final()); }
        static uint Rotr(uint x, int n) { return (x >> n) | (x << (32 - n)); }
        void Compress()
        {
            for (int i = 0; i < 16; i++) w[i] = ((uint)block[i * 4] << 24) | ((uint)block[i * 4 + 1] << 16) | ((uint)block[i * 4 + 2] << 8) | block[i * 4 + 3];
            for (int i = 16; i < 64; i++)
            {
                uint s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                uint s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            uint a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
            for (int i = 0; i < 64; i++)
            {
                uint t1 = h + (Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
                uint t2 = (Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
                h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
            }
            H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
        }
        public void Dispose() { if (ih != null) ih.Dispose(); }
    }

    public static class StoreUtil
    {
        public const string Version = "2.4.1";
        public static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);
        public static string Hex(byte[] h)
        {
            StringBuilder sb = new StringBuilder(h.Length * 2);
            foreach (byte x in h) sb.Append(x.ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }
        public static string Sha256Hex(byte[] d) { Sha256Acc a = Sha256Acc.Shared; a.Append(d); return a.FinalHex(); }
        // a parsed JSON value as text, as the scanner's CSV writer renders it (bool True/False, numbers invariant, null "")
        public static string Scalar(object v)
        {
            if (v == null) return "";
            if (v is string) return (string)v;
            if (v is bool) return (bool)v ? "True" : "False";
            IFormattable f = v as IFormattable;
            if (f != null) return f.ToString(null, CultureInfo.InvariantCulture);
            return v.ToString();
        }
        // JSON string with HTML-sensitive characters escaped (same form as the scanner's JSONL writer)
        public static void JsonString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append('\\').Append('"'); break;
                    case '\\': sb.Append('\\').Append('\\'); break;
                    case '\n': sb.Append('\\').Append('n'); break;
                    case '\r': sb.Append('\\').Append('r'); break;
                    case '\t': sb.Append('\\').Append('t'); break;
                    case '\b': sb.Append('\\').Append('b'); break;
                    case '\f': sb.Append('\\').Append('f'); break;
                    default:
                        if (c < 0x20 || c == '<' || c == '>' || c == '&' || c == '\'' || c == (char)0x2028 || c == (char)0x2029)
                            sb.Append('\\').Append('u').Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }
        public static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
        public static byte[] B(string s) { return Utf8.GetBytes(s); }
        public static string S(byte[] b) { return Utf8.GetString(b); }
        public static string Iso(DateTimeOffset t) { return t.ToString("yyyy-MM-dd'T'HH:mm:sszzz", Inv); }
        public static DateTimeOffset ParseIso(string s) { return DateTimeOffset.Parse(s, Inv, DateTimeStyles.AssumeLocal); }
        public static bool TryIso(string s, out DateTimeOffset t) { return DateTimeOffset.TryParse(s, Inv, DateTimeStyles.AssumeLocal, out t); }
        public static string D10(long n) { return n.ToString("D10", Inv); }
        public static string Sha256Hex(string s) { Sha256Acc a = Sha256Acc.Shared; a.Append(B(s)); return a.FinalHex(); }
        public static string FileSha256(string path, out long bytes)
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (Sha256Acc a = new Sha256Acc())
            {
                byte[] buf = new byte[1 << 20]; int n; bytes = 0;
                while ((n = fs.Read(buf, 0, buf.Length)) > 0) { a.Append(buf, 0, n); bytes += n; }
                return a.FinalHex();
            }
        }
        // lines of a UTF-8 text file (optionally .gz); BOM tolerant; \r\n or \n
        public static IEnumerable<string> ReadLines(string path)
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                Stream s = fs;
                GZipStream gz = null;
                if (path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) { gz = new GZipStream(fs, CompressionMode.Decompress); s = gz; }
                using (StreamReader r = new StreamReader(s, Utf8, true, 1 << 16))
                {
                    string l;
                    while ((l = r.ReadLine()) != null) yield return l;
                }
                if (gz != null) gz.Dispose();
            }
        }
        public static string ReadText(string path)
        {
            StringBuilder sb = new StringBuilder();
            foreach (string l in ReadLines(path)) sb.Append(l).Append('\n');
            return sb.ToString();
        }
        // gzip copy of a file; returns the source SHA-256 and size
        public static string CopyToGz(string src, string dst, out long srcBytes)
        {
            using (FileStream i = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (FileStream o = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None))
            using (Sha256Acc a = new Sha256Acc())
            {
                using (GZipStream gz = new GZipStream(o, CompressionLevel.Optimal, true))
                {
                    byte[] buf = new byte[1 << 20]; int n; srcBytes = 0;
                    while ((n = i.Read(buf, 0, buf.Length)) > 0) { a.Append(buf, 0, n); gz.Write(buf, 0, n); srcBytes += n; }
                }
                o.Flush(true);
                return a.FinalHex();
            }
        }
        public static void WriteAllTextAtomic(string path, string text)
        {
            string tmp = path + ".tmp";
            using (FileStream fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                byte[] b = B(text);
                fs.Write(b, 0, b.Length);
                fs.Flush(true);
            }
            if (File.Exists(path)) File.Replace(tmp, path, null); else File.Move(tmp, path);
        }
        public static bool IsIp(string s) { System.Net.IPAddress a; return System.Net.IPAddress.TryParse(s, out a); }
        public static object Field(Dictionary<string, object> o, string k) { object v; return o != null && o.TryGetValue(k, out v) ? v : null; }
        public static string Str(Dictionary<string, object> o, string k) { return StoreUtil.Scalar(Field(o, k)); }
        public static long Num(Dictionary<string, object> o, string k) { long v; return long.TryParse(Str(o, k), NumberStyles.Integer, Inv, out v) ? v : 0; }
    }

    // JSON reader: objects -> Dictionary<string,object>, arrays -> List<object>, numbers -> double
    public static class StoreJson
    {
        public static object Parse(string s) { int i = 0; object v = Value(s, ref i); Ws(s, ref i); if (i != s.Length) throw new FormatException("trailing data at " + i); return v; }
        static void Ws(string s, ref int i) { while (i < s.Length && char.IsWhiteSpace(s[i])) i++; }
        static object Value(string s, ref int i)
        {
            Ws(s, ref i);
            if (i >= s.Length) throw new FormatException("unexpected end");
            char c = s[i];
            if (c == '{')
            {
                Dictionary<string, object> d = new Dictionary<string, object>(StringComparer.Ordinal);
                i++; Ws(s, ref i);
                if (i < s.Length && s[i] == '}') { i++; return d; }
                while (true)
                {
                    Ws(s, ref i); string k = Str(s, ref i); Ws(s, ref i);
                    if (i >= s.Length || s[i] != ':') throw new FormatException("expected ':' at " + i);
                    i++; d[k] = Value(s, ref i); Ws(s, ref i);
                    if (i < s.Length && s[i] == ',') { i++; continue; }
                    if (i < s.Length && s[i] == '}') { i++; return d; }
                    throw new FormatException("expected ',' or '}' at " + i);
                }
            }
            if (c == '[')
            {
                List<object> l = new List<object>();
                i++; Ws(s, ref i);
                if (i < s.Length && s[i] == ']') { i++; return l; }
                while (true)
                {
                    l.Add(Value(s, ref i)); Ws(s, ref i);
                    if (i < s.Length && s[i] == ',') { i++; continue; }
                    if (i < s.Length && s[i] == ']') { i++; return l; }
                    throw new FormatException("expected ',' or ']' at " + i);
                }
            }
            if (c == '"') return Str(s, ref i);
            if (string.CompareOrdinal(s, i, "true", 0, 4) == 0) { i += 4; return true; }
            if (string.CompareOrdinal(s, i, "false", 0, 5) == 0) { i += 5; return false; }
            if (string.CompareOrdinal(s, i, "null", 0, 4) == 0) { i += 4; return null; }
            int st = i;
            while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
            if (st == i) throw new FormatException("unexpected character at " + i);
            return double.Parse(s.Substring(st, i - st), NumberStyles.Float, CultureInfo.InvariantCulture);
        }
        static string Str(string s, ref int i)
        {
            if (i >= s.Length || s[i] != '"') throw new FormatException("expected string at " + i);
            i++;
            int start = i;
            while (i < s.Length && s[i] != '"' && s[i] != '\\') i++;
            if (i < s.Length && s[i] == '"') { string plain = s.Substring(start, i - start); i++; return plain; }
            StringBuilder sb = new StringBuilder(s, start, i - start, Math.Max(16, (i - start) * 2));
            while (i < s.Length)
            {
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                if (i >= s.Length) break;
                char e = s[i++];
                switch (e)
                {
                    case 'n': sb.Append('\n'); break;
                    case 't': sb.Append('\t'); break;
                    case 'r': sb.Append('\r'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'u':
                        if (i + 4 > s.Length) throw new FormatException("bad \\u escape at " + i);
                        sb.Append((char)Convert.ToInt32(s.Substring(i, 4), 16)); i += 4; break;
                    default: sb.Append(e); break;
                }
            }
            throw new FormatException("unterminated string");
        }
    }

    // Canonical line writer: JSON objects with a fixed key order, LF line ends; SHA-256 digest of the bytes written
    public sealed class DigestWriter : IDisposable
    {
        readonly Sha256Acc acc = new Sha256Acc();
        FileStream fs; GZipStream gz;
        public long Lines;
        public DigestWriter(string gzPath)
        {
            if (gzPath != null) { fs = new FileStream(gzPath, FileMode.Create, FileAccess.Write, FileShare.None); gz = new GZipStream(fs, CompressionLevel.Optimal, true); }
        }
        public void Line(string s)
        {
            byte[] b = StoreUtil.B(s + "\n");
            acc.Append(b);
            if (gz != null) gz.Write(b, 0, b.Length);
            Lines++;
        }
        public string Close()
        {
            if (gz != null) { gz.Dispose(); gz = null; fs.Flush(true); fs.Dispose(); fs = null; }
            return acc.FinalHex();
        }
        public void Dispose() { if (gz != null) gz.Dispose(); if (fs != null) fs.Dispose(); acc.Dispose(); }
    }

    public sealed class JsonObj
    {
        readonly StringBuilder sb = new StringBuilder(256);
        bool first = true;
        public JsonObj() { sb.Append('{'); }
        void Name(string n) { if (!first) sb.Append(','); first = false; StoreUtil.JsonString(sb, n); sb.Append(':'); }
        public JsonObj Str(string n, string v) { Name(n); StoreUtil.JsonString(sb, v ?? ""); return this; }
        public JsonObj StrIf(string n, string v) { if (!string.IsNullOrEmpty(v)) Str(n, v); return this; }
        public JsonObj Num(string n, long v) { Name(n); sb.Append(v.ToString(CultureInfo.InvariantCulture)); return this; }
        public JsonObj Bool(string n, bool v) { Name(n); sb.Append(v ? "true" : "false"); return this; }
        public JsonObj Raw(string n, string json) { Name(n); sb.Append(json); return this; }
        public override string ToString() { return sb.ToString() + "}"; }
    }

    // Ordered string record with a compact binary encoding (the database value format)
    public sealed class Rec
    {
        public readonly List<string> Names = new List<string>();
        readonly Dictionary<string, string> map = new Dictionary<string, string>(StringComparer.Ordinal);
        public string this[string n]
        {
            get { string v; return map.TryGetValue(n, out v) ? v : ""; }
            set { if (value == null) value = ""; if (!map.ContainsKey(n)) Names.Add(n); map[n] = value; }
        }
        public bool Has(string n) { return map.ContainsKey(n); }
        public void Remove(string n) { if (map.Remove(n)) Names.Remove(n); }
        public long Long(string n) { long v; return long.TryParse(this[n], NumberStyles.Integer, CultureInfo.InvariantCulture, out v) ? v : 0; }
        public void SetLong(string n, long v) { this[n] = v.ToString(CultureInfo.InvariantCulture); }
        public void RemovePrefix(string p) { foreach (string n in Names.ToArray()) if (n.StartsWith(p, StringComparison.Ordinal)) Remove(n); }
        public byte[] Encode()
        {
            MemoryStream ms = new MemoryStream(256);
            ms.WriteByte(1);
            Var(ms, Names.Count);
            foreach (string n in Names) { Bytes(ms, n); Bytes(ms, map[n]); }
            return ms.ToArray();
        }
        static void Var(MemoryStream ms, int v) { uint u = (uint)v; while (u >= 0x80) { ms.WriteByte((byte)(u | 0x80)); u >>= 7; } ms.WriteByte((byte)u); }
        static void Bytes(MemoryStream ms, string s) { byte[] b = StoreUtil.B(s); Var(ms, b.Length); ms.Write(b, 0, b.Length); }
        public static Rec Decode(byte[] b)
        {
            if (b == null) return null;
            if (b.Length == 0 || b[0] != 1) throw new InvalidDataException("unknown record format");
            int i = 1;
            int n = ReadVar(b, ref i);
            Rec r = new Rec();
            for (int k = 0; k < n; k++) { string name = ReadStr(b, ref i); r[name] = ReadStr(b, ref i); }
            return r;
        }
        static int ReadVar(byte[] b, ref int i)
        {
            uint v = 0; int shift = 0;
            while (true)
            {
                if (i >= b.Length || shift > 28) throw new InvalidDataException("corrupt record");
                byte x = b[i++]; v |= (uint)(x & 0x7f) << shift;
                if ((x & 0x80) == 0) return (int)v;
                shift += 7;
            }
        }
        static string ReadStr(byte[] b, ref int i)
        {
            int len = ReadVar(b, ref i);
            if (len < 0 || i + len > b.Length) throw new InvalidDataException("corrupt record");
            string s = StoreUtil.Utf8.GetString(b, i, len); i += len; return s;
        }
    }

    // Which result fields define a service version, which are per-observation detail, and which a probe switch controls
    public static class InvSchema
    {
        public const int Version = 1;   // changing Material/Norm changes every hash: bump and migrate, never edit in place
        public static readonly string[] Material = {
            "ReverseDns", "State", "IsWeb", "Service", "Scheme", "Url", "FinalUrl", "StatusCode", "Title", "Server", "PoweredBy", "Generator",
            "ContentType", "RedirectChain", "Auth", "Cookies", "CookieFlagIssues", "MissingSecHeaders", "HstsMaxAge", "AltSvc",
            "Products", "Technologies", "Categories", "CPEs", "OsHint", "Hardware", "FaviconPath", "FaviconMmh3", "FaviconMd5",
            "Robots", "SecurityTxt", "AllowedMethods", "RiskyMethods", "IdentifiedPaths", "TlsVersion", "TlsCipher", "TlsKeyExchange",
            "TlsSupported", "TlsCiphersByVersion", "TlsWeakCipher", "Alpn", "Http2", "CertSubject", "CertIssuer", "CertSANs",
            "CertNotBefore", "CertNotAfter", "CertSelfSigned", "CertSigAlg", "CertKeyAlg", "CertKeySize", "CertSerial", "CertSha1",
            "CertSha256", "CertPolicyErrors", "CertChainStatus", "CertSource", "Flags", "Advisories", "Banner",
            // v2.3: appended (empty values do not enter the hash, so every earlier version keeps its hash)
            "DeviceName", "Domain", "ProtocolInfo", "Jarm", "Ja4s",
            // v2.4: appended
            "VersionPaths" };
        // recorded with each sighting, never a reason for a new version (response time, dynamic page hashes, scan clock)
        public static readonly string[] Observed = { "ScannedAt", "VhostOf", "BodyLength", "BodySha256", "ResponseMs", "CertDaysLeft", "Notes", "ScanTag" };
        // profile flag -> fields that only that probe collects; a run without the probe keeps the previous values
        public static readonly string[][] Gated = {
            new[] { "tlsScan", "TlsSupported", "TlsCiphersByVersion", "TlsWeakCipher", "Alpn", "Http2" },
            new[] { "favicon", "FaviconPath", "FaviconMmh3", "FaviconMd5" },
            new[] { "extras", "Robots", "SecurityTxt" },
            new[] { "options", "AllowedMethods", "RiskyMethods" },
            new[] { "identifyPaths", "IdentifiedPaths" },
            new[] { "versionPaths", "VersionPaths" },
            new[] { "reverseDns", "ReverseDns" },
            new[] { "tlsFingerprint", "Jarm" },
            new[] { "ja4s", "Ja4s" } };
        static readonly HashSet<string> MaterialSet = new HashSet<string>(Material, StringComparer.Ordinal);
        public static bool IsMaterial(string f) { return MaterialSet.Contains(f); }

        static readonly Regex BannerTime = new Regex(@"\b\d{1,2}:\d{2}(?::\d{2})?(?:[.,]\d+)?\b", RegexOptions.CultureInvariant);
        static readonly Regex BannerIsoDate = new Regex(@"\b\d{4}-\d{2}-\d{2}\b", RegexOptions.CultureInvariant);
        static readonly Regex BannerDate = new Regex(@"\b(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*,?\s+)?(?:\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2}),?\s+\d{4}\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        static readonly Regex FlagDays = new Regex(@"\bCertExpiring:\d+d\b", RegexOptions.CultureInvariant);
        // comparison form: banners lose clock/date text (SMTP/FTP greetings), certificate-expiry flags lose the day count
        public static string Norm(string field, string v)
        {
            if (string.IsNullOrEmpty(v)) return "";
            if (field == "Banner") return BannerTime.Replace(BannerIsoDate.Replace(BannerDate.Replace(v, "<date>"), "<date>"), "<time>");
            if (field == "Flags") return FlagDays.Replace(v, "CertExpiring");
            return v;
        }
        public static string Hash(Rec mat)
        {
            StringBuilder sb = new StringBuilder(2048);
            foreach (string f in Material)
            {
                string v = Norm(f, mat[f]);
                if (v.Length == 0) continue;
                sb.Append(f).Append('\u001f').Append(v).Append('\u001e');
            }
            Sha256Acc a = Sha256Acc.Shared;
            a.Append(StoreUtil.B(sb.ToString()));
            return a.FinalHex().Substring(0, 32);
        }
        public static List<string> Diff(Rec oldm, Rec newm)
        {
            List<string> d = new List<string>();
            foreach (string f in Material) if (Norm(f, oldm == null ? "" : oldm[f]) != Norm(f, newm[f])) d.Add(f);
            return d;
        }
        public static void CarryOver(Rec mat, Rec prev, RunInfo run)
        {
            if (prev == null) return;
            foreach (string[] g in Gated)
            {
                if (run.Collected(g[0])) continue;
                for (int i = 1; i < g.Length; i++) { string v = prev[g[i]]; if (v.Length > 0) mat[g[i]] = v; else mat.Remove(g[i]); }
            }
        }
        // A difference only in fields that a probe newly switched on filled in (previous version made without that probe,
        // previous value empty) is an enrichment, not a change of the service
        public static bool IsEnrichment(List<string> diff, Rec oldm, Rec newm)
        {
            if (diff == null || diff.Count == 0 || oldm == null) return false;
            string prof = oldm["_prof"];
            foreach (string f in diff)
            {
                if (oldm[f].Length > 0 || newm[f].Length == 0) return false;
                string gate = null;
                foreach (string[] g in Gated) for (int i = 1; i < g.Length; i++) if (g[i] == f) gate = g[0];
                if (gate == null || RunInfo.ProfileHas(prof, gate)) return false;
            }
            return true;
        }
        public static Rec MaterialOf(Rec r)
        {
            Rec m = new Rec();
            foreach (string f in Material) { string v = r[f]; if (v.Length > 0) m[f] = v; }
            return m;
        }
    }

    // run.json written by the scanner at the end of each session (or synthesised when importing older output)
    public sealed class RunInfo
    {
        public string RunId = "", StartedAt = "", FinishedAt = "", Tag = "", Scanner = "", Operator = "", Computer = "";
        public bool Complete = true, Synthesized;
        public bool TlsScan = true, Favicon = true, Extras = true, Options, IdentifyPaths, ProbeSans, ReverseDns;
        public bool TlsFingerprint, Ja4s, Smb, Rdp, Snmp;   // v2.3 opt-in probes (appended to Profile only when on)
        public bool VersionPaths;                            // v2.4 opt-in (appended to Profile only when on)
        public long Checks;
        public bool Collected(string flag)
        {
            switch (flag)
            {
                case "tlsScan": return TlsScan;
                case "favicon": return Favicon;
                case "extras": return Extras;
                case "options": return Options;
                case "identifyPaths": return IdentifyPaths;
                case "reverseDns": return ReverseDns;
                case "probeSans": return ProbeSans;
                case "tlsFingerprint": return TlsFingerprint;
                case "ja4s": return Ja4s;
                case "versionPaths": return VersionPaths;
            }
            return true;
        }
        public bool NeedsCarryOver { get { return !(TlsScan && Favicon && Extras && Options && IdentifyPaths && ReverseDns && TlsFingerprint && Ja4s && VersionPaths); } }
        // flag as written in a Profile string ("tls=1 favicon=1 ..."); missing = off (flags added later are appended only when on)
        public static bool ProfileHas(string profile, string flag)
        {
            string key = flag == "tlsScan" ? "tls" : flag;
            if (string.IsNullOrEmpty(profile)) return false;
            foreach (string kvp in profile.Split(' ')) if (kvp == key + "=1") return true;
            return false;
        }
        public string Profile
        {
            get
            {
                return string.Format(CultureInfo.InvariantCulture, "tls={0} favicon={1} extras={2} options={3} identifyPaths={4} probeSans={5} reverseDns={6}",
                    TlsScan ? 1 : 0, Favicon ? 1 : 0, Extras ? 1 : 0, Options ? 1 : 0, IdentifyPaths ? 1 : 0, ProbeSans ? 1 : 0, ReverseDns ? 1 : 0)
                    + (TlsFingerprint ? " tlsFingerprint=1" : "") + (Ja4s ? " ja4s=1" : "") + (Smb ? " smb=1" : "") + (Rdp ? " rdp=1" : "") + (Snmp ? " snmp=1" : "") + (VersionPaths ? " versionPaths=1" : "");
            }
        }
        public DateTimeOffset Started { get { return StoreUtil.ParseIso(StartedAt); } }

        static bool Flag(Dictionary<string, object> p, string k, bool dflt)
        {
            object v = StoreUtil.Field(p, k);
            if (v is bool) return (bool)v;
            return dflt;
        }
        public static RunInfo Parse(string json)
        {
            Dictionary<string, object> o = StoreJson.Parse(json) as Dictionary<string, object>;
            if (o == null) throw new InvalidDataException("run.json is not a JSON object");
            RunInfo r = new RunInfo();
            r.RunId = StoreUtil.Str(o, "runId"); r.StartedAt = StoreUtil.Str(o, "startedAt"); r.FinishedAt = StoreUtil.Str(o, "finishedAt");
            r.Tag = StoreUtil.Str(o, "tag"); r.Scanner = StoreUtil.Str(o, "scanner"); r.Operator = StoreUtil.Str(o, "operator"); r.Computer = StoreUtil.Str(o, "computer");
            r.Complete = Flag(o, "complete", true); r.Synthesized = Flag(o, "synthesized", false); r.Checks = StoreUtil.Num(o, "checks");
            Dictionary<string, object> p = StoreUtil.Field(o, "profile") as Dictionary<string, object>;
            if (p != null)
            {
                r.TlsScan = Flag(p, "tlsScan", true); r.Favicon = Flag(p, "favicon", true); r.Extras = Flag(p, "extras", true);
                r.Options = Flag(p, "options", false); r.IdentifyPaths = Flag(p, "identifyPaths", false); r.ProbeSans = Flag(p, "probeSans", false);
                r.ReverseDns = Flag(p, "reverseDns", false);
                r.TlsFingerprint = Flag(p, "tlsFingerprint", false); r.Ja4s = Flag(p, "ja4s", false); r.Smb = Flag(p, "smb", false); r.Rdp = Flag(p, "rdp", false); r.Snmp = Flag(p, "snmp", false);
                r.VersionPaths = Flag(p, "versionPaths", false);
            }
            if (r.RunId.Length == 0) throw new InvalidDataException("run.json has no runId");
            DateTimeOffset t;
            if (!StoreUtil.TryIso(r.StartedAt, out t)) throw new InvalidDataException("run.json startedAt is not a timestamp: '" + r.StartedAt + "'");
            return r;
        }
        public string ToJson()
        {
            JsonObj p = new JsonObj().Bool("tlsScan", TlsScan).Bool("favicon", Favicon).Bool("extras", Extras).Bool("options", Options)
                .Bool("identifyPaths", IdentifyPaths).Bool("probeSans", ProbeSans).Bool("reverseDns", ReverseDns);
            if (TlsFingerprint) p.Bool("tlsFingerprint", true);
            if (Ja4s) p.Bool("ja4s", true);
            if (Smb) p.Bool("smb", true);
            if (Rdp) p.Bool("rdp", true);
            if (Snmp) p.Bool("snmp", true);
            if (VersionPaths) p.Bool("versionPaths", true);
            return new JsonObj().Num("format", 1).Str("runId", RunId).Str("startedAt", StartedAt).Str("finishedAt", FinishedAt).Bool("complete", Complete)
                .Bool("synthesized", Synthesized).Str("scanner", Scanner).Str("tag", Tag).Str("operator", Operator).Str("computer", Computer)
                .Num("checks", Checks).Raw("profile", p.ToString()).ToString();
        }
        // Older output without run.json: start time from the RunId stamp, probe switches inferred from what the rows hold
        public static RunInfo Synthesize(string runId, string jsonlPath, string progressPath)
        {
            RunInfo r = new RunInfo();
            r.RunId = runId; r.Synthesized = true; r.Complete = true; r.Scanner = "unknown (imported)";
            DateTime stamp;
            if (!DateTime.TryParseExact(runId, "yyyyMMdd_HHmmss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out stamp))
                stamp = File.GetLastWriteTime(jsonlPath);
            r.StartedAt = StoreUtil.Iso(new DateTimeOffset(stamp));
            r.FinishedAt = StoreUtil.Iso(new DateTimeOffset(File.GetLastWriteTime(jsonlPath)));
            bool tls = false, anyTlsRow = false, fav = false, anyWeb = false, extras = false;
            foreach (string l in StoreUtil.ReadLines(jsonlPath))
            {
                if (l.Length == 0) continue;
                Dictionary<string, object> o = StoreJson.Parse(l) as Dictionary<string, object>;
                if (o == null) continue;
                if (r.Tag.Length == 0) r.Tag = StoreUtil.Str(o, "ScanTag");
                if (StoreUtil.Str(o, "TlsSupported").Length > 0) tls = true;
                if (StoreUtil.Str(o, "TlsVersion").Length > 0 || StoreUtil.Str(o, "CertSha256").Length > 0) anyTlsRow = true;
                if (StoreUtil.Str(o, "IsWeb") == "True") anyWeb = true;
                if (StoreUtil.Str(o, "FaviconMmh3").Length > 0) fav = true;
                if (StoreUtil.Str(o, "Robots").Length > 0 || StoreUtil.Str(o, "SecurityTxt").Length > 0) extras = true;
                if (StoreUtil.Str(o, "AllowedMethods").Length > 0) r.Options = true;
                if (StoreUtil.Str(o, "IdentifiedPaths").Length > 0) r.IdentifyPaths = true;
                if (StoreUtil.Str(o, "VersionPaths").Length > 0) r.VersionPaths = true;
                if (StoreUtil.Str(o, "Vhost") == "True") r.ProbeSans = true;
                if (StoreUtil.Str(o, "ReverseDns").Length > 0) r.ReverseDns = true;
                if (StoreUtil.Str(o, "Jarm").Length > 0) r.TlsFingerprint = true;
                if (StoreUtil.Str(o, "Ja4s").Length > 0) r.Ja4s = true;
            }
            // absent evidence on a run that had candidates means the probe was off; no candidates -> assume the default
            r.TlsScan = tls || !anyTlsRow; r.Favicon = fav || !anyWeb; r.Extras = extras || !anyWeb;
            long n = 0; foreach (string l in StoreUtil.ReadLines(progressPath)) if (l.Trim().Length > 0) n++;
            r.Checks = n;
            return r;
        }
    }

    // Source files of one scan run (paths in the scanner's output and log folders)
    public sealed class RunSources
    {
        public string RunId, Jsonl, Progress, RunJson, Csv, Html, Delta, Manifest;
        public readonly List<string> Logs = new List<string>();
    }

    public sealed class QueryResult
    {
        public string[] Columns;
        public readonly List<string[]> Rows = new List<string[]>();
    }

    // -Filter clauses: Field op Value, op one of = != ~ !~ < <= > >= ; all clauses must match
    public sealed class RowFilter
    {
        public string Field, Op, Value;
        static readonly Regex Rx = new Regex(@"^\s*([A-Za-z][A-Za-z0-9]*)\s*(!=|!~|<=|>=|=|~|<|>)\s*(.*?)\s*$", RegexOptions.CultureInvariant);
        public static List<RowFilter> Parse(string[] specs, IEnumerable<string> fields)
        {
            HashSet<string> known = new HashSet<string>(fields, StringComparer.OrdinalIgnoreCase);
            known.Add("Any");
            List<RowFilter> r = new List<RowFilter>();
            if (specs == null) return r;
            foreach (string s in specs)
            {
                if (string.IsNullOrWhiteSpace(s)) continue;
                Match m = Rx.Match(s);
                if (!m.Success) throw new ArgumentException("filter '" + s + "' is not 'Field<op>Value' (ops: = != ~ !~ < <= > >=)");
                if (!known.Contains(m.Groups[1].Value)) throw new ArgumentException("filter '" + s + "': unknown field '" + m.Groups[1].Value + "'");
                RowFilter f = new RowFilter(); f.Field = m.Groups[1].Value; f.Op = m.Groups[2].Value; f.Value = m.Groups[3].Value.Trim('\'', '"');
                r.Add(f);
            }
            return r;
        }
        public static bool All(List<RowFilter> fs, Dictionary<string, string> row)
        {
            foreach (RowFilter f in fs) if (!f.Match(row)) return false;
            return true;
        }
        bool Match(Dictionary<string, string> row)
        {
            if (Field.Equals("Any", StringComparison.OrdinalIgnoreCase))
            {
                // Any: positive operators match when some field matches; != and !~ when no field matches = / ~
                if (Op == "!=") return !AnyField("=", row);
                if (Op == "!~") return !AnyField("~", row);
                return AnyField(Op, row);
            }
            string val; row.TryGetValue(Field, out val);
            return Test(Op, val ?? "");
        }
        bool AnyField(string op, Dictionary<string, string> row)
        {
            foreach (string v in row.Values) if (Test(op, v ?? "")) return true;
            return false;
        }
        bool Test(string op, string v)
        {
            switch (op)
            {
                case "=": return Eq(v);
                case "!=": return !Eq(v);
                case "~": return v.IndexOf(Value, StringComparison.OrdinalIgnoreCase) >= 0;
                case "!~": return v.IndexOf(Value, StringComparison.OrdinalIgnoreCase) < 0;
            }
            if (v.Length == 0) return false;
            int c;
            double a, b; DateTimeOffset ta, tb;
            if (double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out a) && double.TryParse(Value, NumberStyles.Float, CultureInfo.InvariantCulture, out b)) c = a.CompareTo(b);
            else if (StoreUtil.TryIso(v, out ta) && StoreUtil.TryIso(Value, out tb)) c = ta.CompareTo(tb);
            else c = string.Compare(v, Value, StringComparison.OrdinalIgnoreCase);
            switch (op) { case "<": return c < 0; case "<=": return c <= 0; case ">": return c > 0; default: return c >= 0; }
        }
        // whole value, or one ';'-separated item, or a flag name ("CertExpiring" matches "CertExpiring:12d")
        bool Eq(string v)
        {
            if (v.Equals(Value, StringComparison.OrdinalIgnoreCase)) return true;
            if (v.IndexOf(';') < 0 && v.IndexOf(':') < 0) return false;
            foreach (string part in v.Split(';'))
            {
                string p = part.Trim();
                if (p.Equals(Value, StringComparison.OrdinalIgnoreCase)) return true;
                if (p.Length > Value.Length && p[Value.Length] == ':' && p.StartsWith(Value, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }
}
