
// ============================================================================
// WebInv extras - opt-in identification probes, compiled only when a run enables one of them
// (-TlsFingerprint, -Smb, -Rdp, -Snmp, -Screenshot, -Cname). C# 5 / .NET Framework 4.7.2. No credentials are ever guessed:
// SMB and RDP stop after the server's NTLM challenge (the first, unauthenticated leg); SNMP uses only the community
// or v3 user the operator supplies.
//   JARM  - port of salesforce/jarm 1.0 (BSD 3-Clause, Copyright (c) 2020 salesforce.com, inc.)
//   JA4S  - FoxIO JA4+ method (FoxIO License 1.1: internal, non-monetised use; https://github.com/FoxIO-LLC/ja4)
// ============================================================================
namespace WebInv
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.IO.Compression;
    using System.Net;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;

    public delegate TcpClient TcpConnector(string ip, int port, int timeoutMs, out string state);
    public delegate byte[] RawCertReader(Stream s, string sni, string mode, out int version, out string error);

    public static class Extras
    {
        public const string Version = "2.6.1";
        // set to WebInv.Net.Connect, so these probes share the scanner's connect semantics and its CONNECT proxy
        public static TcpConnector Connect;
        // set to WebInv.Tls.CertOverStream: the scan engine's raw ClientHello, for RDP servers Schannel cannot handshake with
        public static RawCertReader RawCert;
        static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        // binds Connect to WebInv.Net.Connect of the scan engine loaded in this AppDomain (no compile-time reference:
        // the engine is an in-memory Add-Type assembly)
        public static bool BindEngine()
        {
            foreach (System.Reflection.Assembly a in AppDomain.CurrentDomain.GetAssemblies())
            {
                Type t;
                try { t = a.GetType("WebInv.Net", false); } catch (Exception) { continue; }
                if (t == null) continue;
                System.Reflection.MethodInfo mi = t.GetMethod("Connect", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static, null,
                    new Type[] { typeof(string), typeof(int), typeof(int), typeof(string).MakeByRefType() }, null);
                if (mi == null) continue;
                Connect = (TcpConnector)Delegate.CreateDelegate(typeof(TcpConnector), mi);
                Type tt = null;
                try { tt = a.GetType("WebInv.Tls", false); } catch (Exception) { }
                System.Reflection.MethodInfo rc = tt == null ? null : tt.GetMethod("CertOverStream", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static, null,
                    new Type[] { typeof(Stream), typeof(string), typeof(string), typeof(int).MakeByRefType(), typeof(string).MakeByRefType() }, null);
                if (rc != null) RawCert = (RawCertReader)Delegate.CreateDelegate(typeof(RawCertReader), rc);
                return true;
            }
            return false;
        }

        internal static TcpClient Open(string ip, int port, int timeoutMs, out string state)
        {
            if (Connect != null) return Connect(ip, port, timeoutMs, out state);
            TcpClient c = new TcpClient(ip.IndexOf(':') >= 0 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
            try
            {
                IAsyncResult ar = c.BeginConnect(ip, port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) { state = "filtered"; c.Close(); return null; }
                c.EndConnect(ar); state = "open"; return c;
            }
            catch (SocketException se) { state = se.SocketErrorCode == SocketError.ConnectionRefused ? "closed" : "filtered"; c.Close(); return null; }
        }
        internal static void Close(TcpClient c) { try { if (c != null) c.Close(); } catch { } }
        internal static byte[] Random(int n) { byte[] b = new byte[n]; lock (Rng) Rng.GetBytes(b); return b; }
        internal static bool ReadExact(Stream s, byte[] b, int off, int n)
        {
            while (n > 0) { int r = s.Read(b, off, n); if (r <= 0) return false; off += r; n -= r; }
            return true;
        }
        internal static string Hex(byte[] b, int off, int n)
        {
            StringBuilder sb = new StringBuilder(n * 2);
            for (int i = 0; i < n && off + i < b.Length; i++) sb.Append(b[off + i].ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }
        internal static string Sha256Hex(string s)
        {
            byte[] d = Encoding.UTF8.GetBytes(s);
            try { using (IncrementalHash h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256)) { h.AppendData(d); return Hex(h.GetHashAndReset(), 0, 32); } }
            catch (Exception) { using (HashAlgorithm h = (HashAlgorithm)CryptoConfig.CreateFromName("System.Security.Cryptography.SHA256CryptoServiceProvider")) return Hex(h.ComputeHash(d), 0, 32); }
        }
        internal static ushort U16(byte[] b, int o) { return (ushort)(b[o] | (b[o + 1] << 8)); }
        internal static uint U32(byte[] b, int o) { return (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)); }
        internal static void W16(MemoryStream m, int v) { m.WriteByte((byte)v); m.WriteByte((byte)(v >> 8)); }
        internal static void W32(MemoryStream m, uint v) { m.WriteByte((byte)v); m.WriteByte((byte)(v >> 8)); m.WriteByte((byte)(v >> 16)); m.WriteByte((byte)(v >> 24)); }
        internal static void WB(MemoryStream m, byte[] b) { m.Write(b, 0, b.Length); }
        internal static int IndexOf(byte[] hay, byte[] needle, int start)
        {
            for (int i = Math.Max(0, start); i + needle.Length <= hay.Length; i++)
            {
                int j = 0;
                while (j < needle.Length && hay[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }
        // reads whatever arrives within the timeout, up to max bytes, stopping early once 'enough' says so
        internal static byte[] ReadSome(Stream s, int max, int timeoutMs, Func<byte[], int, bool> enough, out bool timedOut)
        {
            byte[] buf = new byte[max]; int n = 0; timedOut = false;
            Stopwatch sw = Stopwatch.StartNew();
            try
            {
                while (n < max)
                {
                    int r = s.Read(buf, n, max - n);
                    if (r <= 0) break;
                    n += r;
                    if (enough != null && enough(buf, n)) break;
                    if (sw.ElapsedMilliseconds > timeoutMs) break;
                }
            }
            catch (IOException) { timedOut = n == 0; }
            catch (ObjectDisposedException) { }
            byte[] o = new byte[n]; Buffer.BlockCopy(buf, 0, o, 0, n); return o;
        }
    }

    // ------------------------------------------------------------------ JARM (10 ClientHellos, fuzzy hash of the replies)
    public static class Jarm
    {
        static readonly ushort[] AllCiphers = { 0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3, 0x009f, 0x0045, 0x00be, 0x0088, 0x00c4, 0x009a,
            0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024, 0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0x1302, 0x1301, 0xcc14, 0xc007, 0xc012, 0xc013,
            0xc027, 0xc02f, 0xc014, 0xc028, 0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8, 0x1305, 0x1304, 0x1303, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0,
            0x009c, 0x0035, 0x003d, 0xc09d, 0xc0a1, 0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0, 0x0007, 0x0004, 0x0005 };
        static readonly ushort[] No13Ciphers = { 0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3, 0x009f, 0x0045, 0x00be, 0x0088, 0x00c4, 0x009a,
            0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024, 0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0xcc14, 0xc007, 0xc012, 0xc013, 0xc027, 0xc02f,
            0xc014, 0xc028, 0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0, 0x009c, 0x0035, 0x003d, 0xc09d, 0xc0a1,
            0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0, 0x0007, 0x0004, 0x0005 };
        static readonly ushort[] HashOrder = { 0x0004, 0x0005, 0x0007, 0x000a, 0x0016, 0x002f, 0x0033, 0x0035, 0x0039, 0x003c, 0x003d, 0x0041, 0x0045, 0x0067, 0x006b, 0x0084,
            0x0088, 0x009a, 0x009c, 0x009d, 0x009e, 0x009f, 0x00ba, 0x00be, 0x00c0, 0x00c4, 0xc007, 0xc008, 0xc009, 0xc00a, 0xc011, 0xc012, 0xc013, 0xc014, 0xc023, 0xc024,
            0xc027, 0xc028, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xc060, 0xc061, 0xc072, 0xc073, 0xc076, 0xc077, 0xc09c, 0xc09d, 0xc09e, 0xc09f, 0xc0a0, 0xc0a1, 0xc0a2, 0xc0a3,
            0xc0ac, 0xc0ad, 0xc0ae, 0xc0af, 0xcc13, 0xcc14, 0xcca8, 0xcca9, 0x1301, 0x1302, 0x1303, 0x1304, 0x1305 };
        static readonly string[] AlpnAll = { "http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3", "h2", "h2c", "hq" };
        static readonly string[] AlpnRare = { "http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3", "h2c", "hq" };
        // version, cipher list, cipher order, grease, alpn, supported_versions, extension order (jarm.py main())
        static readonly string[][] Queue = {
            new[] { "TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.2_SUPPORT", "REVERSE" },
            new[] { "TLS_1.2", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.2_SUPPORT", "FORWARD" },
            new[] { "TLS_1.2", "ALL", "TOP_HALF", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD" },
            new[] { "TLS_1.2", "ALL", "BOTTOM_HALF", "NO_GREASE", "RARE_APLN", "NO_SUPPORT", "FORWARD" },
            new[] { "TLS_1.2", "ALL", "MIDDLE_OUT", "GREASE", "RARE_APLN", "NO_SUPPORT", "REVERSE" },
            new[] { "TLS_1.1", "ALL", "FORWARD", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD" },
            new[] { "TLS_1.3", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "REVERSE" },
            new[] { "TLS_1.3", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD" },
            new[] { "TLS_1.3", "NO1.3", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD" },
            new[] { "TLS_1.3", "ALL", "MIDDLE_OUT", "GREASE", "APLN", "1.3_SUPPORT", "REVERSE" } };
        static readonly ushort[] Grease = { 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa };
        public const string Empty = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||";

        public static List<T> Mung<T>(List<T> c, string req)
        {
            List<T> o = new List<T>();
            int n = c.Count;
            if (req == "REVERSE") { for (int i = n - 1; i >= 0; i--) o.Add(c[i]); }
            else if (req == "BOTTOM_HALF") { for (int i = (n % 2 == 1) ? n / 2 + 1 : n / 2; i < n; i++) o.Add(c[i]); }
            else if (req == "TOP_HALF") { if (n % 2 == 1) o.Add(c[n / 2]); o.AddRange(Mung(Mung(c, "REVERSE"), "BOTTOM_HALF")); }
            else if (req == "MIDDLE_OUT")
            {
                int m = n / 2;
                if (n % 2 == 1) { o.Add(c[m]); for (int i = 1; i <= m; i++) { o.Add(c[m + i]); o.Add(c[m - i]); } }
                else for (int i = 1; i <= m; i++) { o.Add(c[m - 1 + i]); o.Add(c[m - i]); }
            }
            else o.AddRange(c);
            return o;
        }

        static void U16(MemoryStream m, int v) { m.WriteByte((byte)(v >> 8)); m.WriteByte((byte)v); }

        public static byte[] Build(string[] d, string host)
        {
            string ver = d[0];
            MemoryStream ch = new MemoryStream();
            int rec, hello;
            if (ver == "TLS_1.3") { rec = 0x0301; hello = 0x0303; } else if (ver == "TLS_1.1") { rec = 0x0302; hello = 0x0302; } else { rec = 0x0303; hello = 0x0303; }
            U16(ch, hello);
            Extras.WB(ch, Extras.Random(32));
            byte[] sid = Extras.Random(32);
            ch.WriteByte(32); Extras.WB(ch, sid);
            bool grease = d[3] == "GREASE";
            List<ushort> cs = new List<ushort>(d[1] == "ALL" ? AllCiphers : No13Ciphers);
            if (d[2] != "FORWARD") cs = Mung(cs, d[2]);
            if (grease) cs.Insert(0, PickGrease());
            U16(ch, cs.Count * 2);
            foreach (ushort c in cs) U16(ch, c);
            ch.WriteByte(1); ch.WriteByte(0);
            byte[] ext = Extensions(d, host, grease);
            U16(ch, ext.Length); Extras.WB(ch, ext);
            byte[] body = ch.ToArray();
            MemoryStream hs = new MemoryStream();
            hs.WriteByte(1); hs.WriteByte(0); U16(hs, body.Length); Extras.WB(hs, body);
            byte[] hsb = hs.ToArray();
            MemoryStream p = new MemoryStream();
            p.WriteByte(0x16); U16(p, rec); U16(p, hsb.Length); Extras.WB(p, hsb);
            return p.ToArray();
        }
        static ushort PickGrease() { return Grease[Extras.Random(1)[0] % Grease.Length]; }

        static byte[] Extensions(string[] d, string host, bool grease)
        {
            MemoryStream e = new MemoryStream();
            if (grease) { U16(e, PickGrease()); U16(e, 0); }
            byte[] h = Encoding.UTF8.GetBytes(host ?? "");
            U16(e, 0x0000); U16(e, h.Length + 5); U16(e, h.Length + 3); e.WriteByte(0); U16(e, h.Length); Extras.WB(e, h);
            Extras.WB(e, new byte[] { 0x00, 0x17, 0x00, 0x00 });                       // extended_master_secret
            Extras.WB(e, new byte[] { 0x00, 0x01, 0x00, 0x01, 0x01 });                 // max_fragment_length
            Extras.WB(e, new byte[] { 0xff, 0x01, 0x00, 0x01, 0x00 });                 // renegotiation_info
            Extras.WB(e, new byte[] { 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19 });   // supported_groups
            Extras.WB(e, new byte[] { 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00 });           // ec_point_formats
            Extras.WB(e, new byte[] { 0x00, 0x23, 0x00, 0x00 });                       // session_ticket
            List<string> alpns = new List<string>(d[4] == "RARE_APLN" ? AlpnRare : AlpnAll);
            if (d[6] != "FORWARD") alpns = Mung(alpns, d[6]);
            MemoryStream al = new MemoryStream();
            foreach (string a in alpns) { byte[] ab = Encoding.ASCII.GetBytes(a); al.WriteByte((byte)ab.Length); Extras.WB(al, ab); }
            byte[] alb = al.ToArray();
            U16(e, 0x0010); U16(e, alb.Length + 2); U16(e, alb.Length); Extras.WB(e, alb);
            Extras.WB(e, new byte[] { 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01 });
            MemoryStream ks = new MemoryStream();
            if (grease) { U16(ks, PickGrease()); Extras.WB(ks, new byte[] { 0x00, 0x01, 0x00 }); }
            U16(ks, 0x001d); U16(ks, 32); Extras.WB(ks, Extras.Random(32));
            byte[] ksb = ks.ToArray();
            U16(e, 0x0033); U16(e, ksb.Length + 2); U16(e, ksb.Length); Extras.WB(e, ksb);
            Extras.WB(e, new byte[] { 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01 });           // psk_key_exchange_modes
            if (d[0] == "TLS_1.3" || d[5] == "1.2_SUPPORT")
            {
                List<ushort> tv = new List<ushort>(d[5] == "1.2_SUPPORT" ? new ushort[] { 0x0301, 0x0302, 0x0303 } : new ushort[] { 0x0301, 0x0302, 0x0303, 0x0304 });
                if (d[6] != "FORWARD") tv = Mung(tv, d[6]);
                MemoryStream vs = new MemoryStream();
                if (grease) U16(vs, PickGrease());
                foreach (ushort v in tv) U16(vs, v);
                byte[] vsb = vs.ToArray();
                U16(e, 0x002b); U16(e, vsb.Length + 1); e.WriteByte((byte)vsb.Length); Extras.WB(e, vsb);
            }
            return e.ToArray();
        }

        // Python slicing never throws; indexing a single byte past the end does (the reference then returns "|||")
        static byte[] Slice(byte[] d, int a, int b) { a = Math.Max(0, Math.Min(a, d.Length)); b = Math.Max(a, Math.Min(b, d.Length)); byte[] r = new byte[b - a]; Buffer.BlockCopy(d, a, r, 0, b - a); return r; }
        static int Idx(byte[] d, int i) { if (i < 0 || i >= d.Length) throw new IndexOutOfRangeException(); return d[i]; }
        static int ParseHex(byte[] two) { if (two.Length == 0) throw new FormatException(); int v = 0; foreach (byte x in two) v = (v << 8) | x; return v; }

        public static string Read(byte[] data)
        {
            try
            {
                if (data == null) return "|||";
                if (Idx(data, 0) == 21) return "|||";
                if (Idx(data, 0) == 22 && Idx(data, 5) == 2)
                {
                    int shl = ParseHex(Slice(data, 3, 5));
                    int counter = Idx(data, 43);
                    string cipher = Extras.Hex(Slice(data, counter + 44, counter + 46), 0, 2);
                    string version = Extras.Hex(Slice(data, 9, 11), 0, 2);
                    return cipher + "|" + version + "|" + ExtInfo(data, counter, shl);
                }
                return "|||";
            }
            catch (Exception) { return "|||"; }
        }

        static string ExtInfo(byte[] data, int counter, int shl)
        {
            List<byte[]> types = new List<byte[]>(); List<byte[]> values = new List<byte[]>();
            try
            {
                if (Idx(data, counter + 47) == 11) return "|";
                byte[] a = Slice(data, counter + 50, counter + 53), b = Slice(data, 82, 85);
                if ((a.Length == 3 && a[0] == 0x0e && a[1] == 0xac && a[2] == 0x0b) || (b.Length == 3 && b[0] == 0x0f && b[1] == 0xf0 && b[2] == 0x0b)) return "|";
                if (counter + 42 >= shl) return "|";
                int count = 49 + counter;
                int length = ParseHex(Slice(data, counter + 47, counter + 49));   // FormatException escapes to Read => "|||"
                int maximum = length + (count - 1);
                while (count < maximum)
                {
                    types.Add(Slice(data, count, count + 2));
                    int el = ParseHex(Slice(data, count + 2, count + 4));
                    if (el == 0) { count += 4; values.Add(null); }
                    else { values.Add(Slice(data, count + 4, count + 4 + el)); count += el + 4; }
                }
            }
            catch (IndexOutOfRangeException) { return "|"; }
            string alpn = "";
            for (int i = 0; i < types.Count; i++)
                if (types[i].Length == 2 && types[i][0] == 0x00 && types[i][1] == 0x10)
                {
                    if (values[i] == null) throw new FormatException();          // reference: str has no decode() => "|||"
                    byte[] v = Slice(values[i], 3, values[i].Length);
                    alpn = new UTF8Encoding(false, true).GetString(v);
                    break;
                }
            StringBuilder sb = new StringBuilder(alpn).Append('|');
            for (int i = 0; i < types.Count; i++) { if (i > 0) sb.Append('-'); sb.Append(Extras.Hex(types[i], 0, types[i].Length)); }
            return sb.ToString();
        }

        public static string Hash(string raw)
        {
            if (raw == Empty) return new string('0', 62);
            StringBuilder fuzzy = new StringBuilder(); StringBuilder ae = new StringBuilder();
            foreach (string hs in raw.Split(','))
            {
                string[] c = hs.Split('|');
                fuzzy.Append(CipherByte(c[0])).Append(VersionByte(c[1]));
                ae.Append(c[2]).Append(c[3]);
            }
            return fuzzy.ToString() + Extras.Sha256Hex(ae.ToString()).Substring(0, 32);
        }
        static string CipherByte(string c)
        {
            if (c.Length == 0) return "00";
            int count = 1;
            foreach (ushort x in HashOrder) { if (c == x.ToString("x4", CultureInfo.InvariantCulture)) break; count++; }
            return count.ToString("x2", CultureInfo.InvariantCulture);
        }
        static string VersionByte(string v)
        {
            if (v.Length == 0) return "0";
            return "abcdef"[int.Parse(v.Substring(3, 1), NumberStyles.HexNumber, CultureInfo.InvariantCulture)].ToString();
        }

        // One probe: connect, send, read the reply (up to 1,484 bytes as the reference does). Timeout => null + timedOut.
        static byte[] Send(string ip, int port, int timeoutMs, byte[] pkt, out bool timedOut)
        {
            string st; timedOut = false;
            TcpClient c = Extras.Open(ip, port, timeoutMs, out st);
            if (c == null) { timedOut = st == "filtered"; return null; }
            try
            {
                c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs;
                NetworkStream s = c.GetStream();
                s.Write(pkt, 0, pkt.Length);
                bool to;
                byte[] d = Extras.ReadSome(s, 1484, timeoutMs, delegate(byte[] b, int n) { return n >= 5 && n >= Math.Min(1484, 5 + ((b[3] << 8) | b[4])); }, out to);
                if (to && d.Length == 0) { timedOut = true; return null; }
                return d;
            }
            catch (Exception) { return null; }
            finally { Extras.Close(c); }
        }

        public static string Compute(string ip, int port, string host, int timeoutMs, out string raw, out int probes)
        {
            List<string> parts = new List<string>();
            probes = 0;
            foreach (string[] q in Queue)
            {
                probes++;
                bool to;
                byte[] reply = Send(ip, port, timeoutMs, Build(q, host), out to);
                if (to) { raw = Empty; return Hash(raw); }
                parts.Add(Read(reply));
            }
            raw = string.Join(",", parts.ToArray());
            return Hash(raw);
        }
    }

    // ------------------------------------------------------------------ JA4S (from the scanner's TLS 1.3 ClientHello reply)
    public static class Ja4s
    {
        // info = version|cipher|ext,ext,...|alpn as recorded by the raw TLS probe (WebInv.TlsScanResult.HelloInfo)
        public static string FromHelloInfo(string info)
        {
            if (string.IsNullOrEmpty(info)) return "";
            string[] p = info.Split('|');
            if (p.Length < 4) return "";
            string ver;
            switch (p[0].ToLowerInvariant()) { case "0304": ver = "13"; break; case "0303": ver = "12"; break; case "0302": ver = "11"; break; case "0301": ver = "10"; break; case "0300": ver = "s3"; break; case "0002": ver = "s2"; break; default: ver = "00"; break; }
            List<string> exts = new List<string>();
            foreach (string e in p[2].Split(',')) if (e.Length > 0) exts.Add(e.ToLowerInvariant());
            string alpn = "00";
            if (p[3].Length > 0)
            {
                char f = p[3][0], l = p[3][p[3].Length - 1];
                alpn = (f < 128 ? f.ToString() : "9") + (l < 128 ? l.ToString() : "9");
            }
            string hash = exts.Count > 0 ? Extras.Sha256Hex(string.Join(",", exts.ToArray())).Substring(0, 12) : "000000000000";
            return "t" + ver + Math.Min(exts.Count, 99).ToString("D2", CultureInfo.InvariantCulture) + alpn + "_" + p[1].ToLowerInvariant() + "_" + hash;
        }
    }

    // ------------------------------------------------------------------ NTLM challenge (server names and OS version)
    public sealed class NtlmInfo
    {
        public string NbComputer = "", NbDomain = "", DnsComputer = "", DnsDomain = "", DnsTree = "", Version = "";
        public int Major, Minor, Build;
        public bool Ok;
        public string Summary()
        {
            List<string> p = new List<string>();
            if (DnsComputer.Length > 0) p.Add("dnsComputer=" + DnsComputer);
            if (NbComputer.Length > 0) p.Add("computer=" + NbComputer);
            if (DnsDomain.Length > 0) p.Add("dnsDomain=" + DnsDomain);
            if (NbDomain.Length > 0) p.Add("domain=" + NbDomain);
            if (DnsTree.Length > 0 && DnsTree != DnsDomain) p.Add("forest=" + DnsTree);
            if (Version.Length > 0) p.Add("ntlmVersion=" + Version);
            return string.Join("; ", p.ToArray());
        }
    }

    public static class Ntlm
    {
        static readonly byte[] Sig = { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 };
        // NEGOTIATE (type 1): unicode, request target, NTLM, always sign, extended session security, target info, version, 128/56
        public static byte[] Negotiate()
        {
            MemoryStream m = new MemoryStream();
            Extras.WB(m, Sig); Extras.W32(m, 1);
            Extras.W32(m, 0xE2088297);
            Extras.WB(m, new byte[16]);
            Extras.WB(m, new byte[] { 10, 0, 0x63, 0x45, 0, 0, 0, 15 });   // client version 10.0.17763, NTLM revision 15
            return m.ToArray();
        }
        public static NtlmInfo ParseChallenge(byte[] buf)
        {
            NtlmInfo n = new NtlmInfo();
            if (buf == null) return n;
            int o = Extras.IndexOf(buf, Sig, 0);
            if (o < 0 || o + 48 > buf.Length || Extras.U32(buf, o + 8) != 2) return n;
            uint flags = Extras.U32(buf, o + 20);
            int tiLen = Extras.U16(buf, o + 40), tiOff = (int)Extras.U32(buf, o + 44);
            int tnOff = (int)Extras.U32(buf, o + 16);
            bool hasVersion = (flags & 0x02000000) != 0 || (tnOff >= 56 && (tiOff >= 56 || tiLen == 0));
            if (hasVersion && o + 56 <= buf.Length && buf[o + 48] > 0)
            {
                n.Major = buf[o + 48]; n.Minor = buf[o + 49]; n.Build = Extras.U16(buf, o + 50);
                n.Version = n.Major + "." + n.Minor + "." + n.Build;
            }
            int p = o + tiOff, end = Math.Min(buf.Length, p + tiLen);
            while (tiLen > 0 && p + 4 <= end)
            {
                int id = Extras.U16(buf, p), len = Extras.U16(buf, p + 2);
                if (id == 0 || p + 4 + len > end) break;
                string v = Encoding.Unicode.GetString(buf, p + 4, len);
                switch (id) { case 1: n.NbComputer = v; break; case 2: n.NbDomain = v; break; case 3: n.DnsComputer = v; break; case 4: n.DnsDomain = v; break; case 5: n.DnsTree = v; break; }
                p += 4 + len;
            }
            n.Ok = n.Version.Length > 0 || n.NbComputer.Length > 0 || n.DnsComputer.Length > 0;
            return n;
        }
        // SPNEGO NegTokenInit offering NTLMSSP only, wrapped in a GSS-API InitialContextToken
        public static byte[] SpnegoInit(byte[] ntlm)
        {
            byte[] mechTok = Der(0xa2, Der(0x04, ntlm));
            byte[] mechTypes = Der(0xa0, Der(0x30, new byte[] { 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a }));
            byte[] init = Der(0xa0, Der(0x30, Cat(mechTypes, mechTok)));
            return Der(0x60, Cat(new byte[] { 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 }, init));
        }
        internal static byte[] Cat(params byte[][] parts) { MemoryStream m = new MemoryStream(); foreach (byte[] p in parts) Extras.WB(m, p); return m.ToArray(); }
        internal static byte[] Der(int tag, byte[] content)
        {
            MemoryStream m = new MemoryStream();
            m.WriteByte((byte)tag);
            int n = content.Length;
            if (n < 128) m.WriteByte((byte)n);
            else if (n < 256) { m.WriteByte(0x81); m.WriteByte((byte)n); }
            else if (n < 65536) { m.WriteByte(0x82); m.WriteByte((byte)(n >> 8)); m.WriteByte((byte)n); }
            else { m.WriteByte(0x83); m.WriteByte((byte)(n >> 16)); m.WriteByte((byte)(n >> 8)); m.WriteByte((byte)n); }
            Extras.WB(m, content);
            return m.ToArray();
        }
    }

    // ------------------------------------------------------------------ SMB: dialect, signing, SMBv1, NTLM server info
    public sealed class SmbResult
    {
        public bool Smb2, SigningEnabled, SigningRequired;
        public string Dialect = "", Smb1 = "", NativeOs = "", NativeLm = "", Error = "", ServerTime = "";
        public NtlmInfo Ntlm = new NtlmInfo();
        public int Probes;
        public string Summary()
        {
            List<string> p = new List<string>();
            if (Dialect.Length > 0) p.Add("dialect=" + Dialect);
            if (Smb2 || Smb1 == "enabled") p.Add("signing=" + (SigningRequired ? "required" : SigningEnabled ? "enabled" : "disabled"));
            if (Smb1.Length > 0) p.Add("smbv1=" + Smb1);
            if (NativeOs.Length > 0) p.Add("nativeOs=" + NativeOs);
            if (NativeLm.Length > 0) p.Add("nativeLm=" + NativeLm);
            return string.Join("; ", p.ToArray());
        }
    }

    public static class Smb
    {
        static byte[] Frame(byte[] smb)
        {
            byte[] f = new byte[smb.Length + 4];
            f[1] = (byte)(smb.Length >> 16); f[2] = (byte)(smb.Length >> 8); f[3] = (byte)smb.Length;
            Buffer.BlockCopy(smb, 0, f, 4, smb.Length);
            return f;
        }
        static byte[] ReadFrame(Stream s)
        {
            byte[] h = new byte[4];
            if (!Extras.ReadExact(s, h, 0, 4)) return null;
            int len = (h[1] << 16) | (h[2] << 8) | h[3];
            if (len <= 0 || len > 1 << 20) return null;
            byte[] b = new byte[len];
            return Extras.ReadExact(s, b, 0, len) ? b : null;
        }
        static byte[] Smb2Header(int command, ulong messageId)
        {
            MemoryStream m = new MemoryStream();
            Extras.WB(m, new byte[] { 0xfe, 0x53, 0x4d, 0x42 });
            Extras.W16(m, 64); Extras.W16(m, 1); Extras.W32(m, 0); Extras.W16(m, command); Extras.W16(m, 31);
            Extras.W32(m, 0); Extras.W32(m, 0);
            Extras.W32(m, (uint)messageId); Extras.W32(m, (uint)(messageId >> 32));
            Extras.W32(m, 0xfeff); Extras.W32(m, 0); Extras.WB(m, new byte[8]); Extras.WB(m, new byte[16]);
            return m.ToArray();
        }
        static byte[] Smb2Negotiate()
        {
            ushort[] dialects = { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 };
            MemoryStream b = new MemoryStream();
            Extras.W16(b, 36); Extras.W16(b, dialects.Length); Extras.W16(b, 1); Extras.W16(b, 0); Extras.W32(b, 0x7f);
            Extras.WB(b, Extras.Random(16));
            int ctxOffset = 64 + 36 + dialects.Length * 2;
            int pad = (8 - ctxOffset % 8) % 8;
            ctxOffset += pad;
            Extras.W32(b, (uint)ctxOffset); Extras.W16(b, 2); Extras.W16(b, 0);
            foreach (ushort d in dialects) Extras.W16(b, d);
            Extras.WB(b, new byte[pad]);
            // PREAUTH_INTEGRITY_CAPABILITIES (SHA-512, 32-byte salt), then ENCRYPTION_CAPABILITIES (AES-128-GCM, AES-128-CCM)
            Extras.W16(b, 1); Extras.W16(b, 38); Extras.W32(b, 0); Extras.W16(b, 1); Extras.W16(b, 32); Extras.W16(b, 1); Extras.WB(b, Extras.Random(32));
            Extras.WB(b, new byte[2]);   // align next context to 8
            Extras.W16(b, 2); Extras.W16(b, 6); Extras.W32(b, 0); Extras.W16(b, 2); Extras.W16(b, 2); Extras.W16(b, 1);
            return Ntlm.Cat(Smb2Header(0, 0), b.ToArray());
        }
        static byte[] Smb2SessionSetup(byte[] blob)
        {
            MemoryStream b = new MemoryStream();
            Extras.W16(b, 25); b.WriteByte(0); b.WriteByte(1); Extras.W32(b, 1); Extras.W32(b, 0);
            Extras.W16(b, 64 + 24); Extras.W16(b, blob.Length); Extras.WB(b, new byte[8]); Extras.WB(b, blob);
            return Ntlm.Cat(Smb2Header(1, 1), b.ToArray());
        }
        static byte[] Smb1Header(byte command, ushort flags2, ushort mid)
        {
            MemoryStream m = new MemoryStream();
            Extras.WB(m, new byte[] { 0xff, 0x53, 0x4d, 0x42, command, 0, 0, 0, 0, 0x18 });
            Extras.W16(m, flags2); Extras.W16(m, 0); Extras.WB(m, new byte[8]); Extras.W16(m, 0); Extras.W16(m, 0xffff); Extras.W16(m, 0xfeff); Extras.W16(m, 0); Extras.W16(m, mid);
            return m.ToArray();
        }

        public static SmbResult Probe(string ip, int port, int timeoutMs)
        {
            SmbResult r = new SmbResult();
            ProbeSmb2(ip, port, timeoutMs, r);
            ProbeSmb1(ip, port, timeoutMs, r);
            return r;
        }

        static void ProbeSmb2(string ip, int port, int timeoutMs, SmbResult r)
        {
            string st;
            r.Probes++;
            TcpClient c = Extras.Open(ip, port, timeoutMs, out st);
            if (c == null) { r.Error = "smb2 connect " + st; return; }
            try
            {
                c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs;
                NetworkStream s = c.GetStream();
                byte[] neg = Frame(Smb2Negotiate());
                s.Write(neg, 0, neg.Length);
                byte[] resp = ReadFrame(s);
                if (resp == null || resp.Length < 64 + 65 || resp[0] != 0xfe || resp[1] != 0x53) { r.Error = "no SMB2 negotiate response"; return; }
                uint status = Extras.U32(resp, 8);
                if (status != 0) { r.Error = "SMB2 negotiate status 0x" + status.ToString("x8", CultureInfo.InvariantCulture); return; }
                r.Smb2 = true;
                int b = 64;
                ushort sec = Extras.U16(resp, b + 2), dialect = Extras.U16(resp, b + 4);
                r.SigningEnabled = (sec & 1) != 0; r.SigningRequired = (sec & 2) != 0;
                r.Dialect = DialectName(dialect);
                long ft = (long)(Extras.U32(resp, b + 40) | ((ulong)Extras.U32(resp, b + 44) << 32));
                if (ft > 0) { try { r.ServerTime = DateTime.FromFileTimeUtc(ft).ToString("s", CultureInfo.InvariantCulture) + "Z"; } catch (ArgumentException) { } }
                byte[] ss = Frame(Smb2SessionSetup(Ntlm.SpnegoInit(Ntlm.Negotiate())));
                s.Write(ss, 0, ss.Length);
                byte[] sr = ReadFrame(s);
                if (sr != null && sr.Length > 64) r.Ntlm = Ntlm.ParseChallenge(sr);
            }
            catch (Exception ex) { if (r.Error.Length == 0) r.Error = "smb2: " + ex.Message; }
            finally { Extras.Close(c); }
        }

        static string DialectName(ushort d)
        {
            switch (d) { case 0x0202: return "2.0.2"; case 0x0210: return "2.1"; case 0x0300: return "3.0"; case 0x0302: return "3.0.2"; case 0x0311: return "3.1.1"; case 0x02ff: return "2.??"; }
            return "0x" + d.ToString("x4", CultureInfo.InvariantCulture);
        }

        // SMBv1: a negotiate offering only "NT LM 0.12"; when accepted with extended security, one session-setup leg
        // returns NativeOS / NativeLanMan and the NTLM challenge (no authentication is attempted).
        static void ProbeSmb1(string ip, int port, int timeoutMs, SmbResult r)
        {
            string st;
            r.Probes++;
            TcpClient c = Extras.Open(ip, port, timeoutMs, out st);
            if (c == null) return;
            try
            {
                c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs;
                NetworkStream s = c.GetStream();
                byte[] dial = Encoding.ASCII.GetBytes("\u0002NT LM 0.12\0");
                MemoryStream m = new MemoryStream();
                Extras.WB(m, Smb1Header(0x72, 0xc801, 1)); m.WriteByte(0); Extras.W16(m, dial.Length); Extras.WB(m, dial);
                byte[] f = Frame(m.ToArray());
                s.Write(f, 0, f.Length);
                byte[] resp;
                try { resp = ReadFrame(s); } catch (IOException) { resp = null; }
                if (resp == null || resp.Length < 37 || resp[0] != 0xff || resp[1] != 0x53 || resp[4] != 0x72) { r.Smb1 = "disabled"; return; }
                if (Extras.U32(resp, 5) != 0 || resp[32] < 17 || Extras.U16(resp, 33) == 0xffff) { r.Smb1 = "disabled"; return; }
                r.Smb1 = "enabled";
                byte secMode = resp[35];
                if (!r.Smb2) { r.SigningEnabled = (secMode & 4) != 0; r.SigningRequired = (secMode & 8) != 0; r.Dialect = "NT LM 0.12"; }
                uint caps = Extras.U32(resp, 33 + 19);
                if ((caps & 0x80000000) == 0) return;   // no extended security: stop (no null-session login)
                byte[] blob = Ntlm.SpnegoInit(Ntlm.Negotiate());
                MemoryStream q = new MemoryStream();
                Extras.WB(q, Smb1Header(0x73, 0xc807, 2));
                q.WriteByte(12); q.WriteByte(0xff); q.WriteByte(0); Extras.W16(q, 0); Extras.W16(q, 4356); Extras.W16(q, 10); Extras.W16(q, 1);
                Extras.W32(q, 0); Extras.W16(q, blob.Length); Extras.W32(q, 0); Extras.W32(q, 0x8000d05c);
                byte[] tail = Ntlm.Cat(blob, new byte[] { 0, 0, 0, 0, 0 });
                Extras.W16(q, tail.Length); Extras.WB(q, tail);
                byte[] f2 = Frame(q.ToArray());
                s.Write(f2, 0, f2.Length);
                byte[] sr = ReadFrame(s);
                if (sr == null || sr.Length < 41 || sr[4] != 0x73) return;
                if (!r.Ntlm.Ok) r.Ntlm = Ntlm.ParseChallenge(sr);
                int wc = sr[32];
                if (wc != 4) return;
                int blobLen = Extras.U16(sr, 33 + 6);
                int bytesStart = 33 + wc * 2 + 2;
                int p = bytesStart + blobLen;
                if ((p & 1) == 1) p++;   // unicode strings are 2-byte aligned from the SMB header
                r.NativeOs = ReadUnicodeZ(sr, ref p);
                r.NativeLm = ReadUnicodeZ(sr, ref p);
            }
            catch (Exception) { if (r.Smb1.Length == 0) r.Smb1 = "disabled"; }
            finally { Extras.Close(c); }
        }
        static string ReadUnicodeZ(byte[] b, ref int p)
        {
            int start = p;
            while (p + 1 < b.Length && !(b[p] == 0 && b[p + 1] == 0)) p += 2;
            string v = p > start ? Encoding.Unicode.GetString(b, start, p - start) : "";
            p += 2;
            return v.Trim();
        }
    }

    // ------------------------------------------------------------------ RDP: security protocols, certificate, NTLM info
    public sealed class RdpResult
    {
        public string Selected = "", Nla = "", StandardRdp = "", Error = "", TlsProtocol = "", PolicyErrors = "", ChainStatus = "";
        public byte[] CertDer;
        public string CertVia = "";      // "" = Schannel handshake; "raw" = raw ClientHello after Schannel failed (no chain check)
        public NtlmInfo Ntlm = new NtlmInfo();
        public int Probes;
        public bool IsRdp;
        public string Summary()
        {
            List<string> p = new List<string>();
            if (Selected.Length > 0) p.Add("security=" + Selected);
            if (Nla.Length > 0) p.Add("nla=" + Nla);
            if (StandardRdp.Length > 0) p.Add("standardRdpSecurity=" + StandardRdp);
            if (CertVia == "raw") p.Add("certificate=raw ClientHello (Schannel handshake failed)");
            return string.Join("; ", p.ToArray());
        }
    }

    public static class Rdp
    {
        public const int ProtoRdp = 0, ProtoSsl = 1, ProtoHybrid = 2, ProtoHybridEx = 8;
        static byte[] ConnectionRequest(int protocols)
        {
            return new byte[] { 3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, (byte)protocols, (byte)(protocols >> 8), (byte)(protocols >> 16), (byte)(protocols >> 24) };
        }
        // returns: >=0 selected protocol; -1-failureCode on RDP_NEG_FAILURE; -100 no negotiation data (legacy RDP); -200 not RDP
        static int Negotiate(Stream s, int protocols)
        {
            byte[] cr = ConnectionRequest(protocols);
            s.Write(cr, 0, cr.Length);
            byte[] h = new byte[4];
            if (!Extras.ReadExact(s, h, 0, 4) || h[0] != 3) return -200;
            int len = (h[2] << 8) | h[3];
            if (len < 11 || len > 512) return -200;
            byte[] b = new byte[len - 4];
            if (!Extras.ReadExact(s, b, 0, b.Length) || b[1] != 0xd0) return -200;
            if (b.Length < 15) return -100;
            int type = b[7];
            int val = (int)Extras.U32(b, 11);
            if (type == 2) return val;
            if (type == 3) return -1 - val;
            return -100;
        }
        static string ProtoName(int p)
        {
            switch (p) { case ProtoRdp: return "rdp"; case ProtoSsl: return "tls"; case ProtoHybrid: return "hybrid"; case ProtoHybridEx: return "hybrid-ex"; case 4: return "rdstls"; }
            return "0x" + p.ToString("x", CultureInfo.InvariantCulture);
        }

        public static RdpResult Probe(string ip, int port, string sni, int timeoutMs, int sslProtocols)
        {
            RdpResult r = new RdpResult();
            string st;
            r.Probes++;
            TcpClient c = Extras.Open(ip, port, timeoutMs, out st);
            if (c == null) { r.Error = "connect " + st; return r; }
            int sel;
            try
            {
                c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs;
                NetworkStream s = c.GetStream();
                sel = Negotiate(s, ProtoSsl | ProtoHybrid | ProtoHybridEx);
                if (sel == -200) { r.Error = "not RDP"; return r; }
                r.IsRdp = true;
                if (sel == -100) { r.Selected = "rdp (legacy, no negotiation)"; r.StandardRdp = "accepted"; return r; }
                if (sel < 0) r.Selected = "tls/hybrid refused (" + FailureName(-1 - sel) + ")";
                else
                {
                    r.Selected = ProtoName(sel);
                    if (sel != ProtoRdp) TlsAndCredSsp(s, sni, timeoutMs, sslProtocols, sel != ProtoSsl, r);
                }
            }
            catch (Exception ex) { r.Error = ex.Message; return r; }
            finally { Extras.Close(c); }
            // TLS was selected but Schannel could not complete the handshake (a TLS 1.0-only server on a host where TLS 1.0
            // is disabled): read the certificate with the scan engine's raw ClientHello on a fresh connection
            if (r.CertDer == null && sel > 0 && sel != ProtoRdp && Extras.RawCert != null) RawCertificate(ip, port, sni, timeoutMs, sel, r);
            // NLA enforced? ask for TLS only: HYBRID_REQUIRED_BY_SERVER (5) means yes
            if (sel == ProtoHybrid || sel == ProtoHybridEx)
            {
                int t = Ask(ip, port, timeoutMs, ProtoSsl, r);
                r.Nla = t == ProtoSsl ? "not required" : (t == -6 ? "required" : "");
                if (t == ProtoSsl) { int u = Ask(ip, port, timeoutMs, ProtoRdp, r); r.StandardRdp = u == ProtoRdp ? "accepted" : (u < 0 && u > -100 ? "refused" : ""); }
                else r.StandardRdp = "refused";
            }
            else if (sel == ProtoSsl || sel < 0)
            {
                // TLS without CredSSP, or TLS/CredSSP refused outright: standard RDP security is the remaining option
                int u = Ask(ip, port, timeoutMs, ProtoRdp, r);
                r.StandardRdp = u == ProtoRdp ? "accepted" : (u < 0 && u > -100 ? "refused" : "");
                if (sel == ProtoSsl || u == ProtoRdp) r.Nla = "not required";
                if (sel < 0 && u == ProtoRdp) r.Selected = "rdp only (" + r.Selected + ")";
            }
            return r;
        }
        static void RawCertificate(string ip, int port, string sni, int timeoutMs, int sel, RdpResult r)
        {
            foreach (string mode in new[] { "tls12", "tls10" })
            {
                string st;
                r.Probes++;
                TcpClient c = Extras.Open(ip, port, timeoutMs, out st);
                if (c == null) return;
                try
                {
                    c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs;
                    NetworkStream s = c.GetStream();
                    if (Negotiate(s, ProtoSsl | ProtoHybrid | ProtoHybridEx) != sel) return;
                    int ver; string err;
                    byte[] der = Extras.RawCert(s, sni, mode, out ver, out err);
                    if (der != null && der.Length > 0)
                    {
                        r.CertDer = der; r.CertVia = "raw";
                        r.TlsProtocol = ver == 0x0303 ? "Tls12" : ver == 0x0302 ? "Tls11" : ver == 0x0301 ? "Tls" : ver == 0x0300 ? "Ssl3" : r.TlsProtocol;
                        return;
                    }
                }
                catch (Exception) { }
                finally { Extras.Close(c); }
            }
        }
        static string FailureName(int code)
        {
            switch (code)
            {
                case 1: return "SSL_REQUIRED_BY_SERVER"; case 2: return "SSL_NOT_ALLOWED_BY_SERVER"; case 3: return "SSL_CERT_NOT_ON_SERVER";
                case 4: return "INCONSISTENT_FLAGS"; case 5: return "HYBRID_REQUIRED_BY_SERVER"; case 6: return "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER";
            }
            return "code " + code.ToString(CultureInfo.InvariantCulture);
        }
        static int Ask(string ip, int port, int timeoutMs, int protocols, RdpResult r)
        {
            string st;
            r.Probes++;
            TcpClient c = Extras.Open(ip, port, timeoutMs, out st);
            if (c == null) return -300;
            try { c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs; return Negotiate(c.GetStream(), protocols); }
            catch (Exception) { return -300; }
            finally { Extras.Close(c); }
        }
        static void TlsAndCredSsp(Stream s, string sni, int timeoutMs, int sslProtocols, bool credssp, RdpResult r)
        {
            SslStream ssl = new SslStream(s, true, delegate(object o, X509Certificate cert, X509Chain ch, SslPolicyErrors e)
            {
                try
                {
                    if (cert != null) r.CertDer = cert.GetRawCertData();
                    r.PolicyErrors = e.ToString();
                    if (ch != null && ch.ChainStatus != null)
                    {
                        List<string> cs = new List<string>();
                        foreach (X509ChainStatus x in ch.ChainStatus) if (x.Status != X509ChainStatusFlags.NoError) cs.Add(x.Status.ToString());
                        r.ChainStatus = string.Join(",", cs.ToArray());
                    }
                }
                catch { }
                return true;
            });
            try
            {
                ssl.AuthenticateAsClient(sni, null, (SslProtocols)sslProtocols, false);
                r.TlsProtocol = TlsName(ssl.SslProtocol);
                if (!credssp) return;
                // CredSSP TSRequest { version 6, negoTokens { { negoToken NTLM NEGOTIATE } } }
                byte[] ts = Ntlm.Der(0x30, Ntlm.Cat(Ntlm.Der(0xa0, new byte[] { 0x02, 0x01, 0x06 }),
                    Ntlm.Der(0xa1, Ntlm.Der(0x30, Ntlm.Der(0x30, Ntlm.Der(0xa0, Ntlm.Der(0x04, Ntlm.Negotiate())))))));
                ssl.Write(ts, 0, ts.Length);
                ssl.Flush();
                bool to;
                byte[] resp = Extras.ReadSome(ssl, 8192, timeoutMs, delegate(byte[] b, int n)
                {
                    if (n < 2 || b[0] != 0x30) return n > 0;
                    int need = b[1] < 0x80 ? 2 + b[1] : (b[1] == 0x81 && n > 2 ? 3 + b[2] : (b[1] == 0x82 && n > 3 ? 4 + ((b[2] << 8) | b[3]) : int.MaxValue));
                    return n >= need;
                }, out to);
                r.Ntlm = Ntlm.ParseChallenge(resp);
            }
            catch (Exception ex) { if (r.Error.Length == 0) r.Error = "tls: " + ex.Message; }
            finally { try { ssl.Dispose(); } catch { } }
        }
        static string TlsName(SslProtocols p)
        {
            switch ((int)p) { case 12288: return "Tls13"; case 3072: return "Tls12"; case 768: return "Tls11"; case 192: return "Tls"; case 48: return "Ssl3"; }
            return p.ToString();
        }
    }

    // ------------------------------------------------------------------ SNMP: v1/v2c (supplied community) and v3 (USM)
    public sealed class SnmpResult
    {
        public string State = "filtered", Version = "", Error = "", EngineId = "";
        public readonly Dictionary<string, string> Values = new Dictionary<string, string>(StringComparer.Ordinal);
        public int Probes;
        public string Get(string oid) { string v; return Values.TryGetValue(oid, out v) ? v : ""; }
    }

    public sealed class SnmpCredential
    {
        public string Version = "2c";        // 1 | 2c | 3
        public string Community = "";
        public string User = "", AuthProtocol = "SHA", AuthPassword = "", PrivProtocol = "AES", PrivPassword = "";
    }

    public static class Snmp
    {
        public static readonly string[] SystemOids = { "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.6.0" };

        // ---- BER
        internal static byte[] Tlv(int tag, byte[] v) { return Ntlm.Der(tag, v); }
        internal static byte[] Int(long v)
        {
            List<byte> b = new List<byte>();
            do { b.Insert(0, (byte)(v & 0xff)); v >>= 8; } while (v != 0 && v != -1);
            if ((v == 0 && (b[0] & 0x80) != 0)) b.Insert(0, 0);
            if ((v == -1 && (b[0] & 0x80) == 0)) b.Insert(0, 0xff);
            return Tlv(0x02, b.ToArray());
        }
        internal static byte[] Oct(byte[] v) { return Tlv(0x04, v ?? new byte[0]); }
        internal static byte[] Oid(string dotted)
        {
            string[] p = dotted.Trim('.').Split('.');
            List<byte> b = new List<byte>();
            b.Add((byte)(int.Parse(p[0], CultureInfo.InvariantCulture) * 40 + int.Parse(p[1], CultureInfo.InvariantCulture)));
            for (int i = 2; i < p.Length; i++)
            {
                ulong n = ulong.Parse(p[i], CultureInfo.InvariantCulture);
                List<byte> t = new List<byte>();
                t.Insert(0, (byte)(n & 0x7f)); n >>= 7;
                while (n > 0) { t.Insert(0, (byte)(0x80 | (n & 0x7f))); n >>= 7; }
                b.AddRange(t);
            }
            return Tlv(0x06, b.ToArray());
        }
        internal static byte[] Seq(params byte[][] parts) { return Tlv(0x30, Ntlm.Cat(parts)); }

        internal sealed class Node { public int Tag; public byte[] Raw; public int Start, Len; public List<Node> Kids; }
        internal static Node Parse(byte[] b, int p, out int next)
        {
            Node n = new Node(); n.Raw = b; n.Tag = b[p];
            int q = p + 1;
            int len = b[q++];
            if ((len & 0x80) != 0) { int k = len & 0x7f; if (k > 4) throw new FormatException("BER length"); len = 0; for (int i = 0; i < k; i++) len = (len << 8) | b[q++]; }
            if (q + len > b.Length) throw new FormatException("BER truncated");
            n.Start = q; n.Len = len; next = q + len;
            if ((n.Tag & 0x20) != 0)
            {
                n.Kids = new List<Node>();
                int c = q;
                while (c < q + len) { int nx; n.Kids.Add(Parse(b, c, out nx)); c = nx; }
            }
            return n;
        }
        internal static byte[] Bytes(Node n) { byte[] o = new byte[n.Len]; Buffer.BlockCopy(n.Raw, n.Start, o, 0, n.Len); return o; }
        internal static long Long(Node n) { long v = (n.Len > 0 && (n.Raw[n.Start] & 0x80) != 0) ? -1 : 0; for (int i = 0; i < n.Len; i++) v = (v << 8) | n.Raw[n.Start + i]; return v; }
        internal static string OidText(Node n)
        {
            if (n.Len == 0) return "";
            StringBuilder sb = new StringBuilder();
            int f = n.Raw[n.Start];
            sb.Append(f / 40).Append('.').Append(f % 40);
            ulong v = 0;
            for (int i = 1; i < n.Len; i++) { byte x = n.Raw[n.Start + i]; v = (v << 7) | (uint)(x & 0x7f); if ((x & 0x80) == 0) { sb.Append('.').Append(v); v = 0; } }
            return sb.ToString();
        }
        static string ValueText(Node v)
        {
            switch (v.Tag)
            {
                case 0x04:
                    byte[] b = Bytes(v);
                    try { return new UTF8Encoding(false, true).GetString(b).TrimEnd('\0'); } catch (DecoderFallbackException) { return Encoding.GetEncoding(28591).GetString(b).TrimEnd('\0'); }
                case 0x06: return OidText(v);
                case 0x02: case 0x41: case 0x42: case 0x43: case 0x46: return Long(v).ToString(CultureInfo.InvariantCulture);
                case 0x40: return v.Len == 4 ? string.Format(CultureInfo.InvariantCulture, "{0}.{1}.{2}.{3}", v.Raw[v.Start], v.Raw[v.Start + 1], v.Raw[v.Start + 2], v.Raw[v.Start + 3]) : "";
                default: return "";   // NULL, noSuchObject, noSuchInstance, endOfMibView
            }
        }
        static byte[] GetPdu(int requestId, string[] oids, int tag)
        {
            List<byte[]> vbs = new List<byte[]>();
            foreach (string o in oids) vbs.Add(Seq(Oid(o), new byte[] { 0x05, 0x00 }));
            return Tlv(tag, Ntlm.Cat(Int(requestId), Int(0), Int(0), Seq(vbs.ToArray())));
        }
        static void ReadVarbinds(Node pdu, SnmpResult r)
        {
            if (pdu.Kids == null || pdu.Kids.Count < 4) return;
            long err = Long(pdu.Kids[1]);
            if (err != 0) r.Error = "SNMP error-status " + err;
            foreach (Node vb in pdu.Kids[3].Kids)
                if (vb.Kids != null && vb.Kids.Count == 2) { string t = ValueText(vb.Kids[1]); if (t.Length > 0) r.Values[OidText(vb.Kids[0])] = t; }
        }

        // ---- UDP exchange: null on timeout; closed => ICMP port unreachable
        static byte[] Exchange(Socket u, byte[] msg, int timeoutMs, int retries, SnmpResult r, out bool closed)
        {
            closed = false;
            byte[] buf = new byte[65535];
            for (int a = 0; a <= retries; a++)
            {
                r.Probes++;
                try
                {
                    u.Send(msg);
                    if (!u.Poll(timeoutMs * 1000, SelectMode.SelectRead)) continue;
                    int n = u.Receive(buf);
                    byte[] o = new byte[n]; Buffer.BlockCopy(buf, 0, o, 0, n); return o;
                }
                catch (SocketException se)
                {
                    if (se.SocketErrorCode == SocketError.ConnectionReset || se.SocketErrorCode == SocketError.ConnectionRefused) { closed = true; return null; }
                    if (se.SocketErrorCode == SocketError.TimedOut) continue;
                    throw;
                }
            }
            return null;
        }

        public static SnmpResult Query(string ip, int port, int timeoutMs, int retries, SnmpCredential cred, string[] oids)
        {
            SnmpResult r = new SnmpResult();
            r.Version = cred.Version;
            IPAddress addr = IPAddress.Parse(ip);
            using (Socket u = new Socket(addr.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
            {
                try { u.Connect(new IPEndPoint(addr, port)); }
                catch (SocketException se) { r.State = "error"; r.Error = se.Message; return r; }
                try
                {
                    if (cred.Version == "3") QueryV3(u, timeoutMs, retries, cred, oids, r);
                    else QueryV12(u, timeoutMs, retries, cred, oids, r);
                }
                catch (Exception ex) { if (r.State != "open") r.State = "error"; r.Error = ex.Message; }
            }
            return r;
        }

        static void QueryV12(Socket u, int timeoutMs, int retries, SnmpCredential cred, string[] oids, SnmpResult r)
        {
            int rid = BitConverter.ToInt32(Extras.Random(4), 0) & 0x7fffffff;
            byte[] msg = Seq(Int(cred.Version == "1" ? 0 : 1), Oct(Encoding.UTF8.GetBytes(cred.Community)), GetPdu(rid, oids, 0xa0));
            bool closed;
            byte[] resp = Exchange(u, msg, timeoutMs, retries, r, out closed);
            if (closed) { r.State = "closed"; return; }
            if (resp == null) { r.State = "filtered"; return; }   // silence: wrong community, ACL, or nothing listening
            int nx;
            Node m = Parse(resp, 0, out nx);
            if (m.Kids == null || m.Kids.Count < 3 || m.Kids[2].Tag != 0xa2) { r.State = "error"; r.Error = "unexpected SNMP reply"; return; }
            r.State = "open";
            ReadVarbinds(m.Kids[2], r);
        }

        // ---- SNMPv3 USM (RFC 3414; AES-128-CFB RFC 3826; HMAC-SHA-256-192 RFC 7860)
        static HashAlgorithmName AuthHash(string p)
        {
            switch ((p ?? "").ToUpperInvariant()) { case "MD5": return HashAlgorithmName.MD5; case "SHA256": case "SHA-256": return HashAlgorithmName.SHA256; default: return HashAlgorithmName.SHA1; }
        }
        static int MacLen(string p) { return AuthHash(p) == HashAlgorithmName.SHA256 ? 24 : 12; }
        static byte[] Digest(HashAlgorithmName h, byte[] data)
        {
            using (IncrementalHash ih = IncrementalHash.CreateHash(h)) { ih.AppendData(data); return ih.GetHashAndReset(); }
        }
        public static byte[] LocalizeKey(string auth, string password, byte[] engineId)
        {
            HashAlgorithmName h = AuthHash(auth);
            byte[] pw = Encoding.UTF8.GetBytes(password);
            if (pw.Length == 0) throw new ArgumentException("empty SNMPv3 password");
            byte[] ku;
            using (IncrementalHash ih = IncrementalHash.CreateHash(h))
            {
                byte[] block = new byte[64]; int idx = 0;
                for (int count = 0; count < 1048576; count += 64)
                {
                    for (int i = 0; i < 64; i++) block[i] = pw[idx++ % pw.Length];
                    ih.AppendData(block);
                }
                ku = ih.GetHashAndReset();
            }
            return Digest(h, Ntlm.Cat(ku, engineId, ku));
        }
        static byte[] Hmac(string auth, byte[] key, byte[] msg)
        {
            using (IncrementalHash ih = IncrementalHash.CreateHMAC(AuthHash(auth), key)) { ih.AppendData(msg); byte[] f = ih.GetHashAndReset(); byte[] o = new byte[MacLen(auth)]; Buffer.BlockCopy(f, 0, o, 0, o.Length); return o; }
        }
        static byte[] AesCfb(byte[] key16, byte[] iv, byte[] data, bool encrypt)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None; aes.Key = key16;
                using (ICryptoTransform ecb = aes.CreateEncryptor())
                {
                    byte[] o = new byte[data.Length]; byte[] fb = (byte[])iv.Clone(); byte[] ks = new byte[16];
                    for (int i = 0; i < data.Length; i += 16)
                    {
                        ecb.TransformBlock(fb, 0, 16, ks, 0);
                        int n = Math.Min(16, data.Length - i);
                        for (int j = 0; j < n; j++) o[i + j] = (byte)(data[i + j] ^ ks[j]);
                        if (n == 16) Buffer.BlockCopy(encrypt ? o : data, i, fb, 0, 16);
                    }
                    return o;
                }
            }
        }
        static byte[] DesCbc(byte[] privKey, byte[] salt, byte[] data, bool encrypt)
        {
            byte[] key = new byte[8], iv = new byte[8];
            Buffer.BlockCopy(privKey, 0, key, 0, 8);
            for (int i = 0; i < 8; i++) iv[i] = (byte)(privKey[8 + i] ^ salt[i]);
            using (DES des = DES.Create())
            {
                des.Mode = CipherMode.CBC; des.Padding = PaddingMode.None; des.Key = key; des.IV = iv;
                byte[] input = data;
                if (encrypt && data.Length % 8 != 0) { input = new byte[(data.Length + 7) / 8 * 8]; Buffer.BlockCopy(data, 0, input, 0, data.Length); }
                using (ICryptoTransform t = encrypt ? des.CreateEncryptor() : des.CreateDecryptor()) return t.TransformFinalBlock(input, 0, input.Length - input.Length % 8);
            }
        }

        static byte[] V3Message(int msgId, byte flags, byte[] engineId, int boots, int time, string user, byte[] authParams, byte[] privParams, byte[] scopedOrEncrypted, out int authOffset)
        {
            byte[] global = Seq(Int(msgId), Int(65507), Oct(new[] { flags }), Int(3));
            byte[] usmInner = Ntlm.Cat(Oct(engineId), Int(boots), Int(time), Oct(Encoding.UTF8.GetBytes(user)), Oct(authParams), Oct(privParams));
            byte[] usm = Tlv(0x30, usmInner);
            byte[] secParams = Oct(usm);
            byte[] body = Ntlm.Cat(Int(3), global, secParams, scopedOrEncrypted);
            byte[] msg = Tlv(0x30, body);
            // offset of the authentication parameters' value: message header + version + global + octet header + USM header + fields
            int hdr = msg.Length - body.Length;
            int secHdr = secParams.Length - usm.Length;
            int usmHdr = usm.Length - usmInner.Length;
            int before = Oct(engineId).Length + Int(boots).Length + Int(time).Length + Oct(Encoding.UTF8.GetBytes(user)).Length;
            int authHdr = Oct(authParams).Length - authParams.Length;
            authOffset = hdr + Int(3).Length + global.Length + secHdr + usmHdr + before + authHdr;
            return msg;
        }

        static void QueryV3(Socket u, int timeoutMs, int retries, SnmpCredential cred, string[] oids, SnmpResult r)
        {
            bool closed;
            int msgId = BitConverter.ToInt32(Extras.Random(4), 0) & 0x7fffffff;
            int ao;
            // 1. discovery: unauthenticated, reportable, empty engine id and user
            byte[] disc = V3Message(msgId, 0x04, new byte[0], 0, 0, "", new byte[0], new byte[0],
                Seq(Oct(new byte[0]), Oct(new byte[0]), GetPdu(msgId, new string[0], 0xa0)), out ao);
            byte[] dr = Exchange(u, disc, timeoutMs, retries, r, out closed);
            if (closed) { r.State = "closed"; return; }
            if (dr == null) { r.State = "filtered"; return; }
            r.State = "open";
            int nx;
            Node dm = Parse(dr, 0, out nx);
            Node dusm = Parse(Bytes(dm.Kids[2]), 0, out nx);
            byte[] engineId = Bytes(dusm.Kids[0]);
            int boots = (int)Long(dusm.Kids[1]), etime = (int)Long(dusm.Kids[2]);
            Stopwatch since = Stopwatch.StartNew();
            r.EngineId = Extras.Hex(engineId, 0, engineId.Length);
            if (engineId.Length == 0) { r.Error = "agent did not report an engine id"; return; }
            if (cred.User.Length == 0) return;   // discovery only: no user was supplied, nothing more is sent
            bool auth = cred.AuthPassword.Length > 0, priv = auth && cred.PrivPassword.Length > 0 && !string.Equals(cred.PrivProtocol, "None", StringComparison.OrdinalIgnoreCase);
            byte[] authKey = auth ? LocalizeKey(cred.AuthProtocol, cred.AuthPassword, engineId) : null;
            byte[] privKey = priv ? LocalizeKey(cred.AuthProtocol, cred.PrivPassword, engineId) : null;
            bool des = string.Equals(cred.PrivProtocol, "DES", StringComparison.OrdinalIgnoreCase);
            for (int attempt = 0; attempt < 2; attempt++)
            {
                int now = etime + (int)(since.ElapsedMilliseconds / 1000);
                int rid = BitConverter.ToInt32(Extras.Random(4), 0) & 0x7fffffff;
                byte[] scoped = Seq(Oct(engineId), Oct(new byte[0]), GetPdu(rid, oids, 0xa0));
                byte[] privParams = new byte[0];
                byte[] data = scoped;
                if (priv)
                {
                    privParams = Extras.Random(8);
                    if (des) { Buffer.BlockCopy(BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(boots)), 0, privParams, 0, 4); data = Oct(DesCbc(privKey, privParams, scoped, true)); }
                    else
                    {
                        byte[] iv = new byte[16];
                        iv[0] = (byte)(boots >> 24); iv[1] = (byte)(boots >> 16); iv[2] = (byte)(boots >> 8); iv[3] = (byte)boots;
                        iv[4] = (byte)(now >> 24); iv[5] = (byte)(now >> 16); iv[6] = (byte)(now >> 8); iv[7] = (byte)now;
                        Buffer.BlockCopy(privParams, 0, iv, 8, 8);
                        byte[] k16 = new byte[16]; Buffer.BlockCopy(privKey, 0, k16, 0, 16);
                        data = Oct(AesCfb(k16, iv, scoped, true));
                    }
                }
                byte flags = (byte)(0x04 | (auth ? 1 : 0) | (priv ? 2 : 0));
                byte[] msg = V3Message(msgId + 1 + attempt, flags, engineId, boots, now, cred.User, auth ? new byte[MacLen(cred.AuthProtocol)] : new byte[0], privParams, data, out ao);
                if (auth) { byte[] mac = Hmac(cred.AuthProtocol, authKey, msg); Buffer.BlockCopy(mac, 0, msg, ao, mac.Length); }
                byte[] resp = Exchange(u, msg, timeoutMs, retries, r, out closed);
                if (resp == null) { r.Error = "no reply to the SNMPv3 request (check user and keys)"; return; }
                Node m = Parse(resp, 0, out nx);
                Node usmN = Parse(Bytes(m.Kids[2]), 0, out nx);
                byte rflags = Bytes(m.Kids[1].Kids[2])[0];
                if (auth && (rflags & 1) != 0)
                {
                    byte[] got = Bytes(usmN.Kids[4]);
                    byte[] zeroed = (byte[])resp.Clone();
                    int at = Extras.IndexOf(resp, got, 0);
                    if (at < 0) { r.Error = "SNMPv3 reply authentication parameters not found"; return; }
                    for (int i = 0; i < got.Length; i++) zeroed[at + i] = 0;
                    byte[] want = Hmac(cred.AuthProtocol, authKey, zeroed);
                    if (!ByteEq(want, got)) { r.Error = "SNMPv3 reply failed authentication"; return; }
                }
                byte[] pduBytes;
                Node d = m.Kids[3];
                if (d.Tag == 0x04)
                {
                    if (!priv) { r.Error = "encrypted SNMPv3 reply without a privacy key"; return; }
                    byte[] salt = Bytes(usmN.Kids[5]);
                    int rboots = (int)Long(usmN.Kids[1]), rtime = (int)Long(usmN.Kids[2]);
                    byte[] enc = Bytes(d);
                    if (des) pduBytes = DesCbc(privKey, salt, enc, false);
                    else
                    {
                        byte[] iv = new byte[16];
                        iv[0] = (byte)(rboots >> 24); iv[1] = (byte)(rboots >> 16); iv[2] = (byte)(rboots >> 8); iv[3] = (byte)rboots;
                        iv[4] = (byte)(rtime >> 24); iv[5] = (byte)(rtime >> 16); iv[6] = (byte)(rtime >> 8); iv[7] = (byte)rtime;
                        Buffer.BlockCopy(salt, 0, iv, 8, 8);
                        byte[] k16 = new byte[16]; Buffer.BlockCopy(privKey, 0, k16, 0, 16);
                        pduBytes = AesCfb(k16, iv, enc, false);
                    }
                }
                else pduBytes = ByteRange(resp, d);
                Node sp = Parse(pduBytes, 0, out nx);
                Node pdu = sp.Kids[2];
                if (pdu.Tag == 0xa8)
                {
                    string rep = pdu.Kids.Count >= 4 && pdu.Kids[3].Kids.Count > 0 ? OidText(pdu.Kids[3].Kids[0].Kids[0]) : "";
                    if (rep.StartsWith("1.3.6.1.6.3.15.1.1.2", StringComparison.Ordinal) && attempt == 0)   // usmStatsNotInTimeWindows: resync and retry
                    { boots = (int)Long(usmN.Kids[1]); etime = (int)Long(usmN.Kids[2]); since = Stopwatch.StartNew(); continue; }
                    r.Error = "SNMPv3 report " + ReportName(rep);
                    return;
                }
                ReadVarbinds(pdu, r);
                return;
            }
        }
        static byte[] ByteRange(byte[] all, Node n)
        {
            int hdr = 2; int l = n.Len;
            if (l >= 128) hdr += l < 256 ? 1 : (l < 65536 ? 2 : 3);
            byte[] o = new byte[hdr + l]; Buffer.BlockCopy(all, n.Start - hdr, o, 0, o.Length); return o;
        }
        static bool ByteEq(byte[] a, byte[] b) { if (a.Length != b.Length) return false; int d = 0; for (int i = 0; i < a.Length; i++) d |= a[i] ^ b[i]; return d == 0; }
        static string ReportName(string oid)
        {
            switch (oid)
            {
                case "1.3.6.1.6.3.15.1.1.1.0": return "unsupported security level";
                case "1.3.6.1.6.3.15.1.1.2.0": return "not in time window";
                case "1.3.6.1.6.3.15.1.1.3.0": return "unknown user name";
                case "1.3.6.1.6.3.15.1.1.4.0": return "unknown engine id";
                case "1.3.6.1.6.3.15.1.1.5.0": return "wrong digest (authentication password or protocol)";
                case "1.3.6.1.6.3.15.1.1.6.0": return "decryption error (privacy password or protocol)";
            }
            return oid;
        }
    }

    // ------------------------------------------------------------------ CNAME chains of hostname targets (-Cname)
    // One A query per name to the resolvers this host already uses; the answer carries the CNAME records. Nothing is
    // sent to the targets. Windows: the system DNS client (DnsQuery_W: same servers, suffix search and policy table as
    // the OS); elsewhere, or with -DnsServer, a standard DNS query over UDP.
    public static class Cname
    {
        [System.Runtime.InteropServices.DllImport("dnsapi.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, EntryPoint = "DnsQuery_W")]
        static extern int DnsQuery(string name, ushort type, uint options, IntPtr extra, out IntPtr results, IntPtr reserved);
        [System.Runtime.InteropServices.DllImport("dnsapi.dll", EntryPoint = "DnsRecordListFree")]
        static extern void DnsRecordListFree(IntPtr list, int freeType);

        public static bool IsWindows { get { return Environment.OSVersion.Platform == PlatformID.Win32NT; } }

        // name -> CNAME targets in order ("" = no CNAME); errors[name] for names whose lookup failed
        public static Dictionary<string, string> Many(string[] names, string server, int timeoutMs, int parallel, Dictionary<string, string> errors)
        {
            Dictionary<string, string> res = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            object gate = new object();
            System.Threading.Tasks.ParallelOptions po = new System.Threading.Tasks.ParallelOptions();
            po.MaxDegreeOfParallelism = Math.Max(1, parallel);
            System.Threading.Tasks.Parallel.ForEach(names, po, delegate(string n)
            {
                string err;
                string[] chain = Chain(n, server, timeoutMs, out err);
                lock (gate) { if (chain != null) res[n] = string.Join(";", chain); if (err != null) errors[n] = err; }
            });
            return res;
        }

        public static string[] Chain(string name, string server, int timeoutMs, out string error)
        {
            error = null;
            try
            {
                if (string.IsNullOrEmpty(server) && IsWindows) return SystemChain(name, out error);
                return UdpChain(name, server, timeoutMs, out error);
            }
            catch (Exception ex) { error = ex.Message; return null; }
        }

        static string[] SystemChain(string name, out string error)
        {
            error = null;
            IntPtr list;
            int rc = DnsQuery(name, 1, 0, IntPtr.Zero, out list, IntPtr.Zero);
            List<string[]> recs = new List<string[]>();
            try
            {
                if (rc == 9003) return new string[0];   // not in DNS (a hosts-file or NetBIOS name): no CNAME
                if (rc != 0 && rc != 9501) { error = "DnsQuery error " + rc; return null; }
                int ps = IntPtr.Size;
                for (IntPtr r = list; r != IntPtr.Zero; r = System.Runtime.InteropServices.Marshal.ReadIntPtr(r))
                {
                    ushort type = (ushort)System.Runtime.InteropServices.Marshal.ReadInt16(r, 2 * ps);
                    uint flags = (uint)System.Runtime.InteropServices.Marshal.ReadInt32(r, 2 * ps + 4);
                    if (type != 5 || (flags & 3) != 1) continue;            // CNAME records of the answer section
                    string owner = System.Runtime.InteropServices.Marshal.PtrToStringUni(System.Runtime.InteropServices.Marshal.ReadIntPtr(r, ps));
                    string target = System.Runtime.InteropServices.Marshal.PtrToStringUni(System.Runtime.InteropServices.Marshal.ReadIntPtr(r, 2 * ps + 16));
                    recs.Add(new string[] { owner, target });
                }
            }
            finally { if (list != IntPtr.Zero) DnsRecordListFree(list, 1); }
            return Follow(recs);
        }

        // the chain from the queried name: the CNAME whose owner is no other record's target, then each target in turn
        public static string[] Follow(List<string[]> recs)
        {
            Dictionary<string, string> next = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            HashSet<string> targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string[] r in recs) { string o = r[0].TrimEnd('.'), t = r[1].TrimEnd('.'); if (!next.ContainsKey(o)) next[o] = t; targets.Add(t); }
            string head = null;
            foreach (string[] r in recs) { string o = r[0].TrimEnd('.'); if (!targets.Contains(o)) { head = o; break; } }
            List<string> chain = new List<string>();
            string cur = head;
            while (cur != null && next.ContainsKey(cur) && chain.Count < 16) { cur = next[cur]; chain.Add(cur.ToLowerInvariant()); }
            return chain.ToArray();
        }

        static List<IPEndPoint> Resolvers(string server)
        {
            List<IPEndPoint> l = new List<IPEndPoint>();
            if (!string.IsNullOrEmpty(server))
            {
                foreach (string one in server.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)) l.Add(ParseServer(one));
                return l;
            }
            HashSet<string> seen = new HashSet<string>();
            foreach (System.Net.NetworkInformation.NetworkInterface ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up && ni.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback) continue;
                System.Net.NetworkInformation.IPAddressCollection dns;
                try { dns = ni.GetIPProperties().DnsAddresses; } catch (Exception) { continue; }
                foreach (IPAddress a in dns)
                {
                    if (a.AddressFamily == AddressFamily.InterNetworkV6 && a.IsIPv6SiteLocal && a.ToString().StartsWith("fec0:", StringComparison.OrdinalIgnoreCase)) continue;  // deprecated well-known placeholders
                    if (seen.Add(a.ToString())) l.Add(new IPEndPoint(a, 53));
                }
            }
            if (l.Count == 0 && File.Exists("/etc/resolv.conf"))
                foreach (string line in File.ReadAllLines("/etc/resolv.conf"))
                {
                    string[] f = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    IPAddress a;
                    if (f.Length >= 2 && f[0] == "nameserver" && IPAddress.TryParse(f[1], out a) && seen.Add(a.ToString())) l.Add(new IPEndPoint(a, 53));
                }
            if (l.Count == 0) throw new InvalidOperationException("no DNS server configured on this host (use -DnsServer)");
            return l;
        }

        public static IPEndPoint ParseServer(string s)
        {
            s = s.Trim();
            IPAddress a; int port = 53;
            if (s.StartsWith("[", StringComparison.Ordinal))
            {
                int e = s.IndexOf(']');
                if (e < 0) throw new FormatException("bad DNS server '" + s + "'");
                if (e + 1 < s.Length && s[e + 1] == ':') port = int.Parse(s.Substring(e + 2), CultureInfo.InvariantCulture);
                s = s.Substring(1, e - 1);
            }
            else if (s.IndexOf(':') >= 0 && s.IndexOf(':') == s.LastIndexOf(':'))   // host:port (a bare IPv6 address has several colons)
            {
                int c2 = s.IndexOf(':');
                port = int.Parse(s.Substring(c2 + 1), CultureInfo.InvariantCulture); s = s.Substring(0, c2);
            }
            if (!IPAddress.TryParse(s, out a) || port < 1 || port > 65535) throw new FormatException("bad DNS server '" + s + "' (an IP address, optionally :port)");
            return new IPEndPoint(a, port);
        }

        static List<string> SearchList()
        {
            List<string> l = new List<string>();
            try
            {
                if (File.Exists("/etc/resolv.conf"))
                    foreach (string line in File.ReadAllLines("/etc/resolv.conf"))
                    {
                        string[] f = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                        if (f.Length >= 2 && (f[0] == "search" || f[0] == "domain")) { l.Clear(); for (int i = 1; i < f.Length; i++) l.Add(f[i].TrimEnd('.')); }
                    }
            }
            catch (Exception) { }
            return l;
        }

        static string[] UdpChain(string name, string server, int timeoutMs, out string error)
        {
            error = null;
            List<IPEndPoint> rs = Resolvers(server);
            List<string> cands = new List<string>();
            string n0 = name.TrimEnd('.');
            if (n0.IndexOf('.') < 0 && string.IsNullOrEmpty(server)) foreach (string sfx in SearchList()) cands.Add(n0 + "." + sfx);
            cands.Add(n0);
            string lastErr = null; bool nx = false;
            foreach (string q in cands)
            {
                int rcode; bool tc; string perr;
                List<string[]> recs = Query(q, rs, timeoutMs, out rcode, out tc, out perr);
                if (recs == null) { lastErr = perr; continue; }
                if (rcode == 3) { nx = true; continue; }
                if (rcode != 0) { lastErr = "DNS error rcode " + rcode; continue; }
                if (tc && recs.Count == 0) { error = "answer truncated (UDP)"; return null; }
                return Follow(recs);
            }
            // NXDOMAIN for every candidate: the name is not in DNS (it resolved from a hosts file or NetBIOS): no CNAME
            if (nx && lastErr == null) return new string[0];
            error = lastErr ?? "no answer";
            return null;
        }

        static readonly Random Rnd = new Random();
        static List<string[]> Query(string name, List<IPEndPoint> servers, int timeoutMs, out int rcode, out bool tc, out string error)
        {
            rcode = -1; tc = false; error = null;
            ushort id; lock (Rnd) id = (ushort)Rnd.Next(1, 65535);
            byte[] q = BuildQuery(id, name, 1);
            foreach (IPEndPoint ep in servers)
            {
                using (Socket s = new Socket(ep.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
                {
                    try
                    {
                        s.ReceiveTimeout = Math.Max(500, timeoutMs);
                        s.SendTo(q, ep);
                        byte[] buf = new byte[4096];
                        Stopwatch sw = Stopwatch.StartNew();
                        while (sw.ElapsedMilliseconds < Math.Max(500, timeoutMs))
                        {
                            EndPoint from = new IPEndPoint(ep.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
                            int n = s.ReceiveFrom(buf, ref from);
                            if (n < 12 || buf[0] != (byte)(id >> 8) || buf[1] != (byte)(id & 0xff) || (buf[2] & 0x80) == 0) continue;   // not our answer
                            byte[] msg = new byte[n]; Buffer.BlockCopy(buf, 0, msg, 0, n);
                            string perr;
                            List<string[]> recs = Parse(msg, out rcode, out tc, out perr);
                            if (recs == null) { error = perr; break; }
                            if (rcode == 2 || rcode == 5) { error = "server " + ep + " answered rcode " + rcode; break; }  // SERVFAIL / REFUSED: next server
                            return recs;
                        }
                    }
                    catch (SocketException ex) { error = "server " + ep + ": " + (ex.SocketErrorCode == SocketError.TimedOut ? "no answer within " + timeoutMs + " ms" : ex.Message); }
                }
            }
            return null;
        }

        public static byte[] BuildQuery(ushort id, string name, ushort type)
        {
            MemoryStream m = new MemoryStream();
            m.Write(new byte[] { (byte)(id >> 8), (byte)(id & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 }, 0, 12);   // RD, one question
            foreach (string label in name.TrimEnd('.').Split('.'))
            {
                byte[] b = Encoding.ASCII.GetBytes(IdnLabel(label));
                if (b.Length == 0 || b.Length > 63) throw new FormatException("bad DNS name '" + name + "'");
                m.WriteByte((byte)b.Length); m.Write(b, 0, b.Length);
            }
            m.WriteByte(0);
            m.Write(new byte[] { (byte)(type >> 8), (byte)(type & 0xff), 0, 1 }, 0, 4);   // QTYPE, QCLASS IN
            return m.ToArray();
        }
        static string IdnLabel(string label)
        {
            foreach (char c in label) if (c > 127) return new IdnMapping().GetAscii(label);
            return label;
        }

        // CNAME records of a DNS answer (owner, target); null when the message is malformed
        public static List<string[]> Parse(byte[] m, out int rcode, out bool tc, out string error)
        {
            rcode = -1; tc = false; error = null;
            try
            {
                if (m.Length < 12) { error = "short DNS message"; return null; }
                rcode = m[3] & 0x0f; tc = (m[2] & 0x02) != 0;
                int qd = (m[4] << 8) + m[5], an = (m[6] << 8) + m[7];
                int p = 12;
                for (int i = 0; i < qd; i++) { ReadName(m, ref p); p += 4; }
                List<string[]> recs = new List<string[]>();
                for (int i = 0; i < an; i++)
                {
                    string owner = ReadName(m, ref p);
                    if (p + 10 > m.Length) throw new IndexOutOfRangeException();
                    int type = (m[p] << 8) + m[p + 1], rdlen = (m[p + 8] << 8) + m[p + 9];
                    p += 10;
                    if (p + rdlen > m.Length) throw new IndexOutOfRangeException();
                    if (type == 5) { int q = p; recs.Add(new string[] { owner, ReadName(m, ref q) }); }
                    p += rdlen;
                }
                return recs;
            }
            catch (Exception) { error = "malformed DNS answer"; return null; }
        }

        static string ReadName(byte[] m, ref int p)
        {
            StringBuilder sb = new StringBuilder();
            int q = p, jumps = 0; bool jumped = false;
            while (true)
            {
                int len = m[q];
                if (len == 0) { q++; break; }
                if ((len & 0xC0) == 0xC0)
                {
                    int ptr = ((len & 0x3F) << 8) + m[q + 1];
                    if (!jumped) p = q + 2;
                    jumped = true;
                    if (++jumps > 32 || ptr >= m.Length) throw new InvalidDataException("DNS name pointer loop");
                    q = ptr; continue;
                }
                if (q + 1 + len > m.Length) throw new IndexOutOfRangeException();
                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.ASCII.GetString(m, q + 1, len));
                q += 1 + len;
                if (sb.Length > 255) throw new InvalidDataException("DNS name too long");
            }
            if (!jumped) p = q;
            return sb.ToString();
        }
    }

    // Loopback DNS responder for the self-test: answers A queries from a table (name -> CNAME chain, or NXDOMAIN),
    // with name compression, so the UDP path is tested end to end without the network
    public sealed class DnsTestResponder : IDisposable
    {
        readonly Socket sock; readonly Dictionary<string, string[]> table; volatile bool stop;
        public int Port { get { return ((IPEndPoint)sock.LocalEndPoint).Port; } }
        public int Queries;
        public DnsTestResponder(Dictionary<string, string[]> chains)
        {
            table = new Dictionary<string, string[]>(chains, StringComparer.OrdinalIgnoreCase);
            sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            sock.ReceiveTimeout = 200;
            Thread t = new Thread(Loop); t.IsBackground = true; t.Start();
        }
        void Loop()
        {
            byte[] buf = new byte[1500];
            while (!stop)
            {
                EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                int n;
                try { n = sock.ReceiveFrom(buf, ref from); } catch (Exception) { continue; }
                Interlocked.Increment(ref Queries);
                try { byte[] r = Answer(buf, n); if (r != null) sock.SendTo(r, from); } catch (Exception) { }
            }
        }
        byte[] Answer(byte[] q, int n)
        {
            int p = 12; StringBuilder sb = new StringBuilder();
            while (q[p] != 0) { if (sb.Length > 0) sb.Append('.'); sb.Append(Encoding.ASCII.GetString(q, p + 1, q[p])); p += 1 + q[p]; }
            int qend = p + 5;
            string name = sb.ToString();
            string[] chain;
            bool known = table.TryGetValue(name, out chain);
            if (known && chain.Length == 1 && chain[0] == "SILENT") return null;
            MemoryStream m = new MemoryStream();
            m.Write(q, 0, 2);
            m.WriteByte(0x81); m.WriteByte((byte)(known ? 0x80 : 0x83));            // QR RD, RA (+NXDOMAIN)
            int an = known ? chain.Length + 1 : 0;
            m.Write(new byte[] { 0, 1, (byte)(an >> 8), (byte)an, 0, 0, 0, 0 }, 0, 8);
            m.Write(q, 12, qend - 12);
            if (known)
            {
                int ownerPtr = 12;                     // the question's name
                foreach (string target in chain)
                {
                    m.WriteByte((byte)(0xC0 | (ownerPtr >> 8))); m.WriteByte((byte)ownerPtr);
                    m.Write(new byte[] { 0, 5, 0, 1, 0, 0, 0, 60 }, 0, 8);
                    byte[] tn = EncodeName(target);
                    m.WriteByte((byte)(tn.Length >> 8)); m.WriteByte((byte)tn.Length);
                    ownerPtr = (int)m.Position;
                    m.Write(tn, 0, tn.Length);
                }
                m.WriteByte((byte)(0xC0 | (ownerPtr >> 8))); m.WriteByte((byte)ownerPtr);
                m.Write(new byte[] { 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7 }, 0, 14);   // A 192.0.2.7
            }
            return m.ToArray();
        }
        static byte[] EncodeName(string name)
        {
            MemoryStream m = new MemoryStream();
            foreach (string l in name.TrimEnd('.').Split('.')) { byte[] b = Encoding.ASCII.GetBytes(l); m.WriteByte((byte)b.Length); m.Write(b, 0, b.Length); }
            m.WriteByte(0);
            return m.ToArray();
        }
        public void Dispose() { stop = true; try { sock.Close(); } catch { } }
    }

    // ------------------------------------------------------------------ Screenshot capture over the DevTools protocol
    // The browser is started by the caller with --remote-debugging-port=0 and a fresh --user-data-dir; it writes its
    // port to <profile>\DevToolsActivePort. One page: set the viewport, navigate, wait for the load event (or the
    // budget), capture a PNG. Runs on its own thread; the caller polls Done.
    public sealed class CdpCapture
    {
        public volatile bool Done;
        public string Status = "", NavError = "", Title = "";
        public string FinalUrl = "";      // location.href when the image was taken (chrome-error://... for the browser's own error page)
        public int MainStatus;            // HTTP status of the page's main document as the browser received it (0 = unknown)
        public string MainUrl = "";
        public int TextLength = -1;       // characters of visible text (document.body.innerText), -1 = unknown
        public long Ms;
        string mainFrame;
        readonly string profile, url, file;
        readonly int width, height, budgetMs;
        System.Net.WebSockets.ClientWebSocket ws;
        int nextId;

        public CdpCapture(string profileDir, string url, string pngFile, int width, int height, int budgetMs)
        {
            profile = profileDir; this.url = url; file = pngFile; this.width = width; this.height = height; this.budgetMs = budgetMs;
        }
        public void Start() { Thread t = new Thread(Run); t.IsBackground = true; t.Start(); }

        void Run()
        {
            Stopwatch sw = Stopwatch.StartNew();
            try { Status = Capture(sw); }
            catch (Exception ex) { Status = "failed: " + (ex.InnerException != null ? ex.InnerException.Message : ex.Message); }
            finally
            {
                try { if (ws != null) ws.Abort(); } catch { }
                Ms = sw.ElapsedMilliseconds; Done = true;
            }
        }

        string Capture(Stopwatch sw)
        {
            string portFile = Path.Combine(profile, "DevToolsActivePort");
            int port = 0;
            while (sw.ElapsedMilliseconds < Math.Min(20000, budgetMs))
            {
                try { if (File.Exists(portFile)) { string[] l = File.ReadAllLines(portFile); if (l.Length > 0 && int.TryParse(l[0].Trim(), out port) && port > 0) break; } } catch (IOException) { }
                Thread.Sleep(100);
            }
            if (port <= 0) return "failed: the browser did not open its DevTools port (headless mode or remote debugging blocked by policy?)";
            string wsUrl = null;
            while (wsUrl == null && sw.ElapsedMilliseconds < Math.Min(25000, budgetMs))
            {
                // the page target appears a moment after the port does
                System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(HttpGet(port, "/json/list"), "\"webSocketDebuggerUrl\"\\s*:\\s*\"(ws://[^\"]+/devtools/page/[^\"]+)\"");
                if (m.Success) wsUrl = m.Groups[1].Value; else Thread.Sleep(150);
            }
            if (wsUrl == null) return "failed: no page target in the browser";
            ws = new System.Net.WebSockets.ClientWebSocket();
            ws.Options.Proxy = null;
            ws.ConnectAsync(new Uri(wsUrl), CancellationToken.None).Wait(10000);
            if (ws.State != System.Net.WebSockets.WebSocketState.Open) return "failed: DevTools connection not open";
            Call("Page.enable", "{}", 10000);
            Call("Network.enable", "{}", 10000);
            Call("Emulation.setDeviceMetricsOverride", "{\"width\":" + width + ",\"height\":" + height + ",\"deviceScaleFactor\":1,\"mobile\":false}", 10000);
            string nav = Call("Page.navigate", "{\"url\":" + JsonStr(url) + "}", 15000);
            System.Text.RegularExpressions.Match fm = System.Text.RegularExpressions.Regex.Match(nav, "\"frameId\"\\s*:\\s*\"([^\"]+)\"");
            if (fm.Success) lock (Requests) mainFrame = fm.Groups[1].Value;
            System.Text.RegularExpressions.Match ne = System.Text.RegularExpressions.Regex.Match(nav, "\"errorText\"\\s*:\\s*\"([^\"]*)\"");
            if (ne.Success && ne.Groups[1].Value.Length > 0) { NavError = ne.Groups[1].Value; return "failed: " + NavError; }
            bool loaded = WaitEvent("Page.loadEventFired", (int)Math.Max(1000, budgetMs - sw.ElapsedMilliseconds - 3000));
            Thread.Sleep(400);   // let late layout/paint settle
            string shot = Call("Page.captureScreenshot", "{\"format\":\"png\"}", 15000);
            System.Text.RegularExpressions.Match d = System.Text.RegularExpressions.Regex.Match(shot, "\"data\"\\s*:\\s*\"([A-Za-z0-9+/=]+)\"");
            if (!d.Success) return "failed: no screenshot data";
            File.WriteAllBytes(file, Convert.FromBase64String(d.Groups[1].Value));
            try
            {
                string t = Call("Runtime.evaluate", "{\"expression\":\"document.title\",\"returnByValue\":true}", 3000);
                System.Text.RegularExpressions.Match tm = System.Text.RegularExpressions.Regex.Match(t, "\"value\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
                if (tm.Success) Title = System.Text.RegularExpressions.Regex.Unescape(tm.Groups[1].Value);
                string h = Call("Runtime.evaluate", "{\"expression\":\"location.href\",\"returnByValue\":true}", 3000);
                System.Text.RegularExpressions.Match hm = System.Text.RegularExpressions.Regex.Match(h, "\"value\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
                if (hm.Success) FinalUrl = System.Text.RegularExpressions.Regex.Unescape(hm.Groups[1].Value);
                string n = Call("Runtime.evaluate", "{\"expression\":\"(document.body && document.body.innerText || '').trim().length\",\"returnByValue\":true}", 3000);
                System.Text.RegularExpressions.Match nm = System.Text.RegularExpressions.Regex.Match(n, "\"value\"\\s*:\\s*(\\d+)");
                if (nm.Success) TextLength = int.Parse(nm.Groups[1].Value, CultureInfo.InvariantCulture);
            }
            catch (Exception) { }
            ResolveMain();
            return loaded ? "ok" : "ok-timeout";
        }

        static string JsonStr(string s)
        {
            StringBuilder b = new StringBuilder("\"");
            foreach (char c in s) { if (c == '"' || c == '\\') b.Append('\\').Append(c); else if (c < 32) b.AppendFormat("\\u{0:x4}", (int)c); else b.Append(c); }
            return b.Append('"').ToString();
        }

        static string HttpGet(int port, string path)
        {
            using (TcpClient c = new TcpClient())
            {
                c.Connect(IPAddress.Loopback, port);
                c.ReceiveTimeout = 10000;
                NetworkStream s = c.GetStream();
                byte[] rq = Encoding.ASCII.GetBytes("GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\nConnection: close\r\n\r\n");
                s.Write(rq, 0, rq.Length);
                // the DevTools HTTP endpoint keeps the connection open: read the header, then Content-Length bytes
                MemoryStream ms = new MemoryStream(); byte[] buf = new byte[8192]; int n, hdrEnd = -1, want = -1;
                while ((n = s.Read(buf, 0, buf.Length)) > 0)
                {
                    ms.Write(buf, 0, n);
                    byte[] all = ms.ToArray();
                    if (hdrEnd < 0)
                    {
                        hdrEnd = Extras.IndexOf(all, new byte[] { 13, 10, 13, 10 }, 0);
                        if (hdrEnd >= 0)
                        {
                            System.Text.RegularExpressions.Match cl = System.Text.RegularExpressions.Regex.Match(Encoding.ASCII.GetString(all, 0, hdrEnd), @"(?im)^Content-Length:\s*(\d+)");
                            want = cl.Success ? int.Parse(cl.Groups[1].Value, CultureInfo.InvariantCulture) : -1;
                        }
                    }
                    if (hdrEnd >= 0 && want >= 0 && all.Length - hdrEnd - 4 >= want) return Encoding.UTF8.GetString(all, hdrEnd + 4, want);
                }
                byte[] r = ms.ToArray();
                return hdrEnd >= 0 ? Encoding.UTF8.GetString(r, hdrEnd + 4, r.Length - hdrEnd - 4) : Encoding.UTF8.GetString(r);
            }
        }

        readonly Queue<string> events = new Queue<string>();
        // every URL the page itself requested (Network.requestWillBeSent): tells page resources from browser chatter
        public readonly List<string> Requests = new List<string>();
        static readonly System.Text.RegularExpressions.Regex ReqUrl = new System.Text.RegularExpressions.Regex("\"request\"\\s*:\\s*\\{\\s*\"url\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        static readonly System.Text.RegularExpressions.Regex RespStatus = new System.Text.RegularExpressions.Regex("\"response\"\\s*:\\s*\\{\\s*\"url\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"[^{}]*?\"status\"\\s*:\\s*(\\d{3})");
        static readonly System.Text.RegularExpressions.Regex RespFrame = new System.Text.RegularExpressions.Regex("\"frameId\"\\s*:\\s*\"([^\"]+)\"");
        readonly Dictionary<string, KeyValuePair<int, string>> docResp = new Dictionary<string, KeyValuePair<int, string>>();
        void Note(string msg)
        {
            if (msg.IndexOf("\"Network.responseReceived\"", StringComparison.Ordinal) >= 0 && msg.IndexOf("\"type\":\"Document\"", StringComparison.Ordinal) >= 0)
            {
                // the last document response per frame; the main frame's is the page the image shows
                System.Text.RegularExpressions.Match rm = RespStatus.Match(msg), fr = RespFrame.Match(msg);
                if (rm.Success && fr.Success)
                    lock (Requests)
                    {
                        docResp[fr.Groups[1].Value] = new KeyValuePair<int, string>(int.Parse(rm.Groups[2].Value, CultureInfo.InvariantCulture), System.Text.RegularExpressions.Regex.Unescape(rm.Groups[1].Value));
                        KeyValuePair<int, string> kv;
                        if (mainFrame != null && docResp.TryGetValue(mainFrame, out kv)) { MainStatus = kv.Key; MainUrl = kv.Value; }
                    }
                return;
            }
            if (msg.IndexOf("\"Network.requestWillBeSent\"", StringComparison.Ordinal) < 0) return;
            System.Text.RegularExpressions.Match m = ReqUrl.Match(msg);
            if (m.Success) lock (Requests) { if (Requests.Count < 2000) Requests.Add(System.Text.RegularExpressions.Regex.Unescape(m.Groups[1].Value)); }
        }
        // the main frame's document response, also when its event arrived before Page.navigate answered with the frame id
        public void ResolveMain()
        {
            lock (Requests)
            {
                KeyValuePair<int, string> kv;
                if (mainFrame != null && docResp.TryGetValue(mainFrame, out kv)) { MainStatus = kv.Key; MainUrl = kv.Value; }
            }
        }
        string Receive(int timeoutMs)
        {
            MemoryStream ms = new MemoryStream();
            byte[] buf = new byte[65536];
            while (true)
            {
                System.Threading.Tasks.Task<System.Net.WebSockets.WebSocketReceiveResult> t = ws.ReceiveAsync(new ArraySegment<byte>(buf), CancellationToken.None);
                if (!t.Wait(timeoutMs)) return null;
                if (t.Result.MessageType == System.Net.WebSockets.WebSocketMessageType.Close) throw new IOException("DevTools connection closed");
                ms.Write(buf, 0, t.Result.Count);
                if (t.Result.EndOfMessage) { string msg = Encoding.UTF8.GetString(ms.ToArray()); Note(msg); return msg; }
            }
        }
        string Call(string method, string paramsJson, int timeoutMs)
        {
            int id = ++nextId;
            byte[] b = Encoding.UTF8.GetBytes("{\"id\":" + id + ",\"method\":\"" + method + "\",\"params\":" + paramsJson + "}");
            if (!ws.SendAsync(new ArraySegment<byte>(b), System.Net.WebSockets.WebSocketMessageType.Text, true, CancellationToken.None).Wait(timeoutMs)) throw new TimeoutException(method + " not sent");
            Stopwatch sw = Stopwatch.StartNew();
            string idTag = "\"id\":" + id + ",", idEnd = "\"id\":" + id + "}";
            while (sw.ElapsedMilliseconds < timeoutMs)
            {
                string msg = Receive((int)Math.Max(100, timeoutMs - sw.ElapsedMilliseconds));
                if (msg == null) break;
                if (msg.StartsWith("{\"id\":", StringComparison.Ordinal) && (msg.IndexOf(idTag, StringComparison.Ordinal) == 1 || msg.IndexOf(idEnd, StringComparison.Ordinal) == 1)) return msg;
                if (msg.IndexOf("\"method\"", StringComparison.Ordinal) >= 0) events.Enqueue(msg);
            }
            throw new TimeoutException(method + ": no answer");
        }
        bool WaitEvent(string method, int timeoutMs)
        {
            string tag = "\"method\":\"" + method + "\"";
            foreach (string e in events) if (e.IndexOf(tag, StringComparison.Ordinal) >= 0) return true;
            Stopwatch sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < timeoutMs)
            {
                string msg = Receive((int)Math.Max(100, timeoutMs - sw.ElapsedMilliseconds));
                if (msg == null) return false;
                if (msg.IndexOf(tag, StringComparison.Ordinal) >= 0) return true;
            }
            return false;
        }
    }

    // ------------------------------------------------------------------ Screenshot checks: does the image show the service?
    // PNG pixels (8-bit grey/RGB/RGBA, non-interlaced: what Chromium writes) and the page state the browser reported
    public static class Png
    {
        // {width, height, dominant colour share in permille, dominant colour 0xRRGGBB, distinct colours (4 bits per channel)}
        // or null when the file is not a PNG this decoder reads
        public static int[] Analyze(byte[] png)
        {
            byte[] px; int w, h, bpp;
            if (!Decode(png, out px, out w, out h, out bpp)) return null;
            int[] hist = new int[4096];
            long total = (long)w * h;
            for (long i = 0; i < total; i++)
            {
                long o = i * bpp;
                int r, g, b;
                if (bpp >= 3) { r = px[o]; g = px[o + 1]; b = px[o + 2]; } else { r = g = b = px[o]; }
                hist[((r >> 4) << 8) | ((g >> 4) << 4) | (b >> 4)]++;
            }
            int best = 0, distinct = 0;
            for (int i = 0; i < 4096; i++) { if (hist[i] > 0) distinct++; if (hist[i] > hist[best]) best = i; }
            int share = total == 0 ? 0 : (int)(1000L * hist[best] / total);
            int rgb = (((best >> 8) & 15) * 17 << 16) | (((best >> 4) & 15) * 17 << 8) | ((best & 15) * 17);
            return new int[] { w, h, share, rgb, distinct };
        }

        public static bool Decode(byte[] d, out byte[] px, out int w, out int h, out int bpp)
        {
            px = null; w = h = bpp = 0;
            byte[] sig = { 137, 80, 78, 71, 13, 10, 26, 10 };
            if (d == null || d.Length < 33) return false;
            for (int i = 0; i < 8; i++) if (d[i] != sig[i]) return false;
            int p = 8, depth = 0, ctype = -1, inter = 0;
            MemoryStream idat = new MemoryStream();
            while (p + 8 <= d.Length)
            {
                int len = (d[p] << 24) | (d[p + 1] << 16) | (d[p + 2] << 8) | d[p + 3];
                string type = Encoding.ASCII.GetString(d, p + 4, 4);
                if (len < 0 || p + 12 + len > d.Length) return false;
                if (type == "IHDR")
                {
                    w = (d[p + 8] << 24) | (d[p + 9] << 16) | (d[p + 10] << 8) | d[p + 11];
                    h = (d[p + 12] << 24) | (d[p + 13] << 16) | (d[p + 14] << 8) | d[p + 15];
                    depth = d[p + 16]; ctype = d[p + 17]; inter = d[p + 20];
                }
                else if (type == "IDAT") idat.Write(d, p + 8, len);
                else if (type == "IEND") break;
                p += 12 + len;
            }
            bpp = ctype == 0 ? 1 : ctype == 4 ? 2 : ctype == 2 ? 3 : ctype == 6 ? 4 : 0;
            if (depth != 8 || bpp == 0 || inter != 0 || w <= 0 || h <= 0 || (long)w * h > 40000000L || idat.Length < 3) return false;
            byte[] z = idat.ToArray();
            int stride = w * bpp;
            byte[] raw = new byte[(long)(stride + 1) * h];
            using (DeflateStream ds = new DeflateStream(new MemoryStream(z, 2, z.Length - 2), CompressionMode.Decompress))
            {
                int got = 0, n;
                while (got < raw.Length && (n = ds.Read(raw, got, raw.Length - got)) > 0) got += n;
                if (got < raw.Length) return false;
            }
            px = new byte[(long)stride * h];
            for (int y = 0; y < h; y++)
            {
                int f = raw[(long)y * (stride + 1)];
                long src = (long)y * (stride + 1) + 1, dst = (long)y * stride, up = dst - stride;
                for (int x = 0; x < stride; x++)
                {
                    int a = x >= bpp ? px[dst + x - bpp] : 0;
                    int b = y > 0 ? px[up + x] : 0;
                    int c = (x >= bpp && y > 0) ? px[up + x - bpp] : 0;
                    int v = raw[src + x];
                    switch (f)
                    {
                        case 0: break;
                        case 1: v += a; break;
                        case 2: v += b; break;
                        case 3: v += (a + b) >> 1; break;
                        case 4: { int pp = a + b - c, pa = Math.Abs(pp - a), pb = Math.Abs(pp - b), pc = Math.Abs(pp - c); v += (pa <= pb && pa <= pc) ? a : (pb <= pc ? b : c); break; }
                        default: return false;
                    }
                    px[dst + x] = (byte)v;
                }
            }
            return true;
        }

        // test images for the self-test: rows cycle through the five filter types
        public static byte[] Encode(int w, int h, byte[] rgb)
        {
            int stride = w * 3;
            MemoryStream raw = new MemoryStream();
            for (int y = 0; y < h; y++)
            {
                int f = y % 5;
                raw.WriteByte((byte)f);
                for (int x = 0; x < stride; x++)
                {
                    int cur = rgb[y * stride + x];
                    int a = x >= 3 ? rgb[y * stride + x - 3] : 0, b = y > 0 ? rgb[(y - 1) * stride + x] : 0, c = (x >= 3 && y > 0) ? rgb[(y - 1) * stride + x - 3] : 0;
                    int pr = f == 0 ? 0 : f == 1 ? a : f == 2 ? b : f == 3 ? (a + b) >> 1 : Paeth(a, b, c);
                    raw.WriteByte((byte)(cur - pr));
                }
            }
            byte[] rb = raw.ToArray();
            MemoryStream z = new MemoryStream();
            z.WriteByte(0x78); z.WriteByte(0x9C);
            using (DeflateStream ds = new DeflateStream(z, CompressionMode.Compress, true)) ds.Write(rb, 0, rb.Length);
            uint s1 = 1, s2 = 0; foreach (byte x in rb) { s1 = (s1 + x) % 65521; s2 = (s2 + s1) % 65521; }
            uint ad = (s2 << 16) | s1;
            z.WriteByte((byte)(ad >> 24)); z.WriteByte((byte)(ad >> 16)); z.WriteByte((byte)(ad >> 8)); z.WriteByte((byte)ad);
            MemoryStream o = new MemoryStream();
            o.Write(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }, 0, 8);
            byte[] ihdr = { (byte)(w >> 24), (byte)(w >> 16), (byte)(w >> 8), (byte)w, (byte)(h >> 24), (byte)(h >> 16), (byte)(h >> 8), (byte)h, 8, 2, 0, 0, 0 };
            Chunk(o, "IHDR", ihdr); Chunk(o, "IDAT", z.ToArray()); Chunk(o, "IEND", new byte[0]);
            return o.ToArray();
        }
        static int Paeth(int a, int b, int c) { int p = a + b - c, pa = Math.Abs(p - a), pb = Math.Abs(p - b), pc = Math.Abs(p - c); return (pa <= pb && pa <= pc) ? a : (pb <= pc ? b : c); }
        static uint[] crcTable;
        static void Chunk(Stream o, string type, byte[] data)
        {
            if (crcTable == null)
            {
                uint[] t = new uint[256];
                for (uint n = 0; n < 256; n++) { uint c = n; for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1; t[n] = c; }
                crcTable = t;
            }
            byte[] tb = Encoding.ASCII.GetBytes(type);
            o.WriteByte((byte)(data.Length >> 24)); o.WriteByte((byte)(data.Length >> 16)); o.WriteByte((byte)(data.Length >> 8)); o.WriteByte((byte)data.Length);
            o.Write(tb, 0, 4); o.Write(data, 0, data.Length);
            uint crc = 0xFFFFFFFFu;
            foreach (byte x in tb) crc = crcTable[(crc ^ x) & 0xff] ^ (crc >> 8);
            foreach (byte x in data) crc = crcTable[(crc ^ x) & 0xff] ^ (crc >> 8);
            crc ^= 0xFFFFFFFFu;
            o.WriteByte((byte)(crc >> 24)); o.WriteByte((byte)(crc >> 16)); o.WriteByte((byte)(crc >> 8)); o.WriteByte((byte)crc);
        }
    }

    public static class ShotCheck
    {
        public const int BlankPermille = 995;   // 99.5 % of the pixels one colour (4 bits per channel)

        static string Norm(string s)
        {
            StringBuilder b = new StringBuilder();
            foreach (char c in (s ?? "").ToLowerInvariant()) if (char.IsLetterOrDigit(c)) b.Append(c);
            return b.ToString();
        }

        // {status, reason}: ok | blank | suspect | failed. image = Png.Analyze result (null: none or unreadable);
        // blocked = origins outside the scan the page asked for (refused by the scope proxy), ';'-separated
        public static string[] Classify(string capture, bool hasImage, int[] image, string scanTitle, string browserTitle, string scanStatus,
            int browserStatus, string finalUrl, bool finalInScope, string scanBodyLength, string blocked, int textLength)
        {
            capture = capture ?? "";
            string[] bl = (blocked ?? "").Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            string blockedNote = bl.Length == 0 ? "" : "; the page went to or asked for " + (bl.Length == 1 ? "an origin" : bl.Length + " origins")
                + " outside the scan, refused by the scope proxy (" + string.Join(", ", bl, 0, Math.Min(3, bl.Length)) + (bl.Length > 3 ? ", ..." : "") + ")";
            if (!hasImage || !capture.StartsWith("ok", StringComparison.Ordinal))
            {
                string why = capture.StartsWith("failed: ", StringComparison.Ordinal) ? capture.Substring(8) : (capture.Length > 0 && !capture.StartsWith("ok", StringComparison.Ordinal) ? capture : "no image");
                return new[] { "failed", why + blockedNote };
            }
            string fu = finalUrl ?? "";
            if (fu.StartsWith("http", StringComparison.OrdinalIgnoreCase) && !finalInScope)
            {
                Uri u; string origin = Uri.TryCreate(fu, UriKind.Absolute, out u) ? u.Scheme + "://" + u.Authority : fu;
                return new[] { "failed", "the page went to " + origin + ", outside the scanned origins (refused by the scope proxy): the image does not show this service" };
            }
            if (fu.StartsWith("chrome-error:", StringComparison.OrdinalIgnoreCase) || fu.StartsWith("edge-error:", StringComparison.OrdinalIgnoreCase) || fu.StartsWith("about:neterror", StringComparison.OrdinalIgnoreCase))
                return new[] { "failed", "the browser showed its own error page" + (browserStatus > 0 ? " (HTTP " + browserStatus + ")" : "") + ", not the service's" + blockedNote };
            // one colour: blank unless the page shows text (a short line of text covers well under 0.5 % of the image)
            bool oneColour = image != null && (textLength == 0 ? image[2] >= BlankPermille : textLength < 0 && image[2] >= 999);
            string colourNote = image == null ? "" : string.Format(CultureInfo.InvariantCulture, "the image is {0} one colour (#{1}, {2:0.0} %)",
                image[2] >= 1000 ? "entirely" : "almost entirely", image[3].ToString("x6", CultureInfo.InvariantCulture), image[2] / 10.0);
            int ss;
            bool scanOk = int.TryParse(scanStatus, NumberStyles.None, CultureInfo.InvariantCulture, out ss) && ss > 0 && ss < 400;
            if (browserStatus >= 400 && scanOk)
                return new[] { "suspect", "the browser received HTTP " + browserStatus + ", the scan HTTP " + ss + (oneColour ? "; " + colourNote : "") };
            if (scanBodyLength == "0" && (oneColour || textLength <= 0))
                return new[] { "blank", "the page is empty (0-byte body)" };
            if (oneColour)
                return new[] { "blank", colourNote + (textLength == 0 ? "; the page shows no text" : "") + blockedNote };
            string a = Norm(scanTitle), b = Norm(browserTitle);
            if (a.Length > 0 && b.Length > 0 && a.IndexOf(b, StringComparison.Ordinal) < 0 && b.IndexOf(a, StringComparison.Ordinal) < 0)
                return new[] { "suspect", "the browser rendered '" + Trunc(browserTitle) + "', the scan saw '" + Trunc(scanTitle) + "'" };
            if (capture == "ok-timeout") return new[] { "ok", "captured before the page finished loading (no load event within the time limit)" };
            return new[] { "ok", "" };
        }
        static string Trunc(string s) { s = (s ?? "").Trim(); return s.Length > 80 ? s.Substring(0, 80) + "..." : s; }
    }

    // ------------------------------------------------------------------ Screenshot scope proxy (loopback only)
    // The headless browser is pointed at this proxy; it forwards only to the scanned origin(s) - always to the IP the
    // scanner used - and refuses everything else (third-party scripts, fonts, telemetry, other hosts, redirects off
    // the origin). Upstream connections go through Extras.Connect, so a -Proxy jump host is honoured too.
    public sealed class ScopeProxy : IDisposable
    {
        readonly TcpListener listener;
        readonly Dictionary<string, string> allow = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly int timeoutMs;
        volatile bool stopped;
        public int Port { get; private set; }
        public int Allowed, Denied;
        public readonly List<string> DeniedOrigins = new List<string>();

        public ScopeProxy(System.Collections.IDictionary allowed, int timeoutMs)
        {
            foreach (System.Collections.DictionaryEntry e in allowed) allow[Convert.ToString(e.Key, CultureInfo.InvariantCulture).Trim('[', ']')] = Convert.ToString(e.Value, CultureInfo.InvariantCulture);
            this.timeoutMs = timeoutMs;
            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start(64);
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            Thread t = new Thread(AcceptLoop); t.IsBackground = true; t.Start();
        }
        void AcceptLoop()
        {
            while (!stopped)
            {
                TcpClient c;
                try { c = listener.AcceptTcpClient(); } catch (Exception) { return; }
                Thread t = new Thread(delegate() { Handle(c); }); t.IsBackground = true; t.Start();
            }
        }
        string Lookup(string hostPort)
        {
            string ip;
            string key = hostPort.ToLowerInvariant();
            int b = key.IndexOf(']');
            if (key.StartsWith("[", StringComparison.Ordinal) && b > 0) key = key.Substring(1, b - 1) + key.Substring(b + 1);
            return allow.TryGetValue(key, out ip) ? ip : null;
        }
        void Refuse(Stream s, string origin)
        {
            Interlocked.Increment(ref Denied);
            lock (DeniedOrigins) { if (DeniedOrigins.Count < 25 && !DeniedOrigins.Contains(origin)) DeniedOrigins.Add(origin); }
            byte[] r = Encoding.ASCII.GetBytes("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            try { s.Write(r, 0, r.Length); } catch { }
        }
        void Handle(TcpClient c)
        {
            TcpClient up = null;
            try
            {
                c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs;
                NetworkStream s = c.GetStream();
                MemoryStream head = new MemoryStream();
                int x; int matched = 0;
                while (head.Length < 65536 && (x = s.ReadByte()) >= 0)
                {
                    head.WriteByte((byte)x);
                    matched = (x == '\r' && (matched == 0 || matched == 2)) ? matched + 1 : (x == '\n' && (matched == 1 || matched == 3)) ? matched + 1 : 0;
                    if (matched == 4) break;
                }
                string h = Encoding.ASCII.GetString(head.ToArray());
                string[] lines = h.Split(new[] { "\r\n" }, StringSplitOptions.None);
                string[] first = lines[0].Split(' ');
                if (first.Length < 3) return;
                string method = first[0].ToUpperInvariant(), target = first[1];
                if (method == "CONNECT")
                {
                    int colon = target.LastIndexOf(':');
                    int port = colon > 0 ? int.Parse(target.Substring(colon + 1), CultureInfo.InvariantCulture) : 443;
                    string ip = Lookup(target);
                    if (ip == null) { Refuse(s, target); return; }
                    string st;
                    up = Extras.Open(ip, port, timeoutMs, out st);
                    if (up == null) { byte[] f = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"); s.Write(f, 0, f.Length); return; }
                    Interlocked.Increment(ref Allowed);
                    byte[] ok = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
                    s.Write(ok, 0, ok.Length);
                    Pipe(s, up.GetStream());
                    return;
                }
                Uri u;
                if (!Uri.TryCreate(target, UriKind.Absolute, out u) || u.Scheme != "http") { Refuse(s, target); return; }
                string origin = u.Host + ":" + u.Port.ToString(CultureInfo.InvariantCulture);
                string uip = Lookup(origin);
                if (uip == null) { Refuse(s, origin); return; }
                string st2;
                up = Extras.Open(uip, u.Port, timeoutMs, out st2);
                if (up == null) { byte[] f = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"); s.Write(f, 0, f.Length); return; }
                Interlocked.Increment(ref Allowed);
                StringBuilder rq = new StringBuilder();
                rq.Append(first[0]).Append(' ').Append(u.PathAndQuery).Append(' ').Append(first[2]).Append("\r\n");
                for (int i = 1; i < lines.Length; i++)
                {
                    string l = lines[i];
                    if (l.Length == 0) continue;
                    string n = l.Split(':')[0].Trim().ToLowerInvariant();
                    if (n == "proxy-connection" || n == "proxy-authorization" || n == "connection" || n == "keep-alive") continue;
                    rq.Append(l).Append("\r\n");
                }
                rq.Append("Connection: close\r\n\r\n");
                byte[] rb = Encoding.ASCII.GetBytes(rq.ToString());
                NetworkStream us = up.GetStream();
                us.Write(rb, 0, rb.Length);
                Pipe(s, us);
            }
            catch (Exception) { }
            finally { Extras.Close(up); try { c.Close(); } catch { } }
        }
        void Pipe(Stream a, Stream b)
        {
            Thread t = new Thread(delegate() { Copy(b, a); }); t.IsBackground = true; t.Start();
            Copy(a, b);
            t.Join(timeoutMs);
        }
        static void Copy(Stream from, Stream to)
        {
            byte[] buf = new byte[16384];
            try { int n; while ((n = from.Read(buf, 0, buf.Length)) > 0) { to.Write(buf, 0, n); to.Flush(); } }
            catch (Exception) { }
            try { to.Close(); } catch { }
        }
        public void Dispose() { stopped = true; try { listener.Stop(); } catch { } }
    }
}
