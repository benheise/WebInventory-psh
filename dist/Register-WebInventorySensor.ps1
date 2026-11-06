<#
.SYNOPSIS
    Enrolls this host as a Tideline sensor with step-ca, renews its certificate with a new key, or shows it.
    Nothing to install: certreq.exe and .NET Framework 4.7.2 on Windows, .NET on PowerShell 7 elsewhere.

.DESCRIPTION
    Enroll (-Token): the Tideline administrator makes a one-time token on the CA, for example
        step ca token wi-scan01 --san urn:tideline:sensor:wi-scan01
    and hands it over (it is valid for five minutes). The token names the CA, the root fingerprint and the sensor's
    names. This script fetches the root by that fingerprint, checks the CA's TLS certificate against it, creates
    the key, sends a certificate request with the token, and installs the certificate:
      - Windows: certreq.exe creates a non-exportable ECDSA P-256 key in the machine key store; the issued
        certificate goes to LocalMachine\My and certutil -repairstore binds it to that key (run elevated). The CA's
        intermediate goes to LocalMachine\CA; the root is pinned, never added to the machine's Trusted Root store.
      - Elsewhere: an ECDSA P-256 key and the certificate in ~/.config/webinventory/tideline-sensor.pfx (mode 0600).
    The pinned root goes to %ProgramData%\WebInventory\tideline-root.crt (~/.config/webinventory/ elsewhere), with
    tideline-sensor.json recording the CA URL. Invoke-WebInventory.ps1 -ShipTo and Send-WebInventoryRun.ps1 use both
    by default.

    Renew (-Renew): when a third or less of the certificate's lifetime is left (or with -Force), a new key and a
    request go to step-ca's rekey endpoint over mutual TLS with the current certificate; step-ca copies the
    certificate's names, so a renewal cannot change the sensor's identity. The previous certificate and its key are
    then removed (-KeepPrevious keeps them). Schedule it daily; a certificate that has expired cannot renew and must
    be enrolled again with a new token.

    Exit codes: 0 = done or not due; 1 = refused (arguments, token, elevation, no certificate); 2 = the CA refused or
    could not be reached.

.PARAMETER Token
    One-time token from 'step ca token' (JWK provisioner).
.PARAMETER Renew
    Renew the current sensor certificate with a new key (when due, or with -Force).
.PARAMETER Show
    Show the sensor certificate(s), the pinned root and the CA URL.
.PARAMETER CaUrl
    The CA (https://ca:9000). Default: from the token; for -Renew from tideline-sensor.json.
.PARAMETER NotAfter
    Requested lifetime, for example 720h (the CA's provisioner limits apply).
.PARAMETER Thumbprint
    -Renew: the certificate to renew (default: the newest valid sensor certificate).
.PARAMETER PfxPath
    Off Windows: where the certificate and key are kept (default ~/.config/webinventory/tideline-sensor.pfx).
.PARAMETER GrantKeyAccess
    Windows: accounts that may use the private key (for example the account of the scheduled scan), besides
    SYSTEM and Administrators. Written to the key's own security descriptor; a renewal carries it over.
.PARAMETER KeepPrevious
    -Renew: leave the previous certificate and key in place.
.PARAMETER Force
    -Renew: renew now, whatever time is left.

.EXAMPLE
    .\Register-WebInventorySensor.ps1 -Token (Get-Content .\token.txt) -GrantKeyAccess 'CORP\svc-webinv'
.EXAMPLE
    .\Register-WebInventorySensor.ps1 -Renew
#>
[CmdletBinding(DefaultParameterSetName = 'Show')]
param(
    [Parameter(ParameterSetName = 'Enroll', Mandatory = $true)][string]$Token,
    [Parameter(ParameterSetName = 'Renew', Mandatory = $true)][switch]$Renew,
    [Parameter(ParameterSetName = 'Show')][switch]$Show,
    [string]$CaUrl,
    [string]$NotAfter,
    [Parameter(ParameterSetName = 'Renew')][string]$Thumbprint,
    [string]$PfxPath,
    [string[]]$GrantKeyAccess,
    [Parameter(ParameterSetName = 'Renew')][switch]$KeepPrevious,
    [Parameter(ParameterSetName = 'Renew')][switch]$Force,
    [ValidateRange(5, 600)][int]$TimeoutSec = 30
)
$ErrorActionPreference = 'Stop'
$ScriptVersion = '2.6.0'

$ShipSource = @'
// Tideline result shipping: shared by Invoke-WebInventory.ps1 (-ShipTo), Send-WebInventoryRun.ps1 and
// Register-WebInventorySensor.ps1. C# 5 / .NET Framework 4.7.2 (Windows PowerShell 5.1), also .NET 8+ (PowerShell 7).
// Reads a finished run's files and sends them unchanged; nothing here touches scanning.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace WebInv
{
    // ---------- JSON: ordered objects, deterministic ASCII output ----------
    public sealed class JObj
    {
        public readonly List<string> Keys = new List<string>();
        readonly Dictionary<string, object> map = new Dictionary<string, object>(StringComparer.Ordinal);
        public JObj Add(string k, object v) { if (!map.ContainsKey(k)) Keys.Add(k); map[k] = v; return this; }
        public object this[string k] { get { object v; return map.TryGetValue(k, out v) ? v : null; } }
        public bool Has(string k) { return map.ContainsKey(k); }
        public string Str(string k) { object v = this[k]; return v == null ? null : Convert.ToString(v, CultureInfo.InvariantCulture); }
        public JObj Obj(string k) { return this[k] as JObj; }
        public List<object> Arr(string k) { return this[k] as List<object>; }
        public bool Remove(string k) { if (!map.Remove(k)) return false; Keys.Remove(k); return true; }
    }

    public static class TJson
    {
        public static object Parse(string s)
        {
            int p = 0;
            object v = Value(s, ref p, 0);
            Ws(s, ref p);
            if (p != s.Length) throw new FormatException("JSON: unexpected text at position " + p);
            return v;
        }
        static void Ws(string s, ref int p) { while (p < s.Length && (s[p] == ' ' || s[p] == '\t' || s[p] == '\r' || s[p] == '\n')) p++; }
        static object Value(string s, ref int p, int depth)
        {
            if (depth > 64) throw new FormatException("JSON: nested too deeply");
            Ws(s, ref p);
            if (p >= s.Length) throw new FormatException("JSON: unexpected end");
            char c = s[p];
            if (c == '{')
            {
                p++; JObj o = new JObj(); Ws(s, ref p);
                if (p < s.Length && s[p] == '}') { p++; return o; }
                while (true)
                {
                    Ws(s, ref p);
                    if (p >= s.Length || s[p] != '"') throw new FormatException("JSON: expected a name at position " + p);
                    string k = Str(s, ref p); Ws(s, ref p);
                    if (p >= s.Length || s[p] != ':') throw new FormatException("JSON: expected ':' at position " + p);
                    p++; o.Add(k, Value(s, ref p, depth + 1)); Ws(s, ref p);
                    if (p < s.Length && s[p] == ',') { p++; continue; }
                    if (p < s.Length && s[p] == '}') { p++; return o; }
                    throw new FormatException("JSON: expected ',' or '}' at position " + p);
                }
            }
            if (c == '[')
            {
                p++; List<object> a = new List<object>(); Ws(s, ref p);
                if (p < s.Length && s[p] == ']') { p++; return a; }
                while (true)
                {
                    a.Add(Value(s, ref p, depth + 1)); Ws(s, ref p);
                    if (p < s.Length && s[p] == ',') { p++; continue; }
                    if (p < s.Length && s[p] == ']') { p++; return a; }
                    throw new FormatException("JSON: expected ',' or ']' at position " + p);
                }
            }
            if (c == '"') return Str(s, ref p);
            if (string.CompareOrdinal(s, p, "true", 0, 4) == 0) { p += 4; return true; }
            if (string.CompareOrdinal(s, p, "false", 0, 5) == 0) { p += 5; return false; }
            if (string.CompareOrdinal(s, p, "null", 0, 4) == 0) { p += 4; return null; }
            int st = p;
            if (p < s.Length && s[p] == '-') p++;
            while (p < s.Length && (char.IsDigit(s[p]) || s[p] == '.' || s[p] == 'e' || s[p] == 'E' || s[p] == '+' || s[p] == '-')) p++;
            string num = s.Substring(st, p - st);
            if (num.Length == 0) throw new FormatException("JSON: unexpected character at position " + st);
            long l;
            if (num.IndexOfAny(new char[] { '.', 'e', 'E' }) < 0 && long.TryParse(num, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out l)) return l;
            double d;
            if (double.TryParse(num, NumberStyles.Float, CultureInfo.InvariantCulture, out d)) return d;
            throw new FormatException("JSON: bad number at position " + st);
        }
        static string Str(string s, ref int p)
        {
            p++; StringBuilder sb = new StringBuilder();
            while (p < s.Length)
            {
                char c = s[p++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                if (p >= s.Length) break;
                char e = s[p++];
                switch (e)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        if (p + 4 > s.Length) throw new FormatException("JSON: bad \\u escape");
                        sb.Append((char)int.Parse(s.Substring(p, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture)); p += 4; break;
                    default: throw new FormatException("JSON: bad escape at position " + (p - 1));
                }
            }
            throw new FormatException("JSON: unterminated string");
        }

        public static string Write(object v) { StringBuilder sb = new StringBuilder(); W(sb, v, 0); return sb.ToString(); }
        static void W(StringBuilder sb, object v, int depth)
        {
            if (depth > 64) throw new InvalidOperationException("JSON: nested too deeply");
            if (v == null) { sb.Append("null"); return; }
            if (v is string) { Q(sb, (string)v); return; }
            if (v is bool) { sb.Append((bool)v ? "true" : "false"); return; }
            if (v is int || v is long || v is short || v is uint || v is ulong || v is byte) { sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); return; }
            if (v is double || v is float || v is decimal) { sb.Append(((IFormattable)v).ToString("R", CultureInfo.InvariantCulture)); return; }
            JObj o = v as JObj;
            if (o != null)
            {
                sb.Append('{');
                for (int i = 0; i < o.Keys.Count; i++) { if (i > 0) sb.Append(','); Q(sb, o.Keys[i]); sb.Append(':'); W(sb, o[o.Keys[i]], depth + 1); }
                sb.Append('}'); return;
            }
            System.Collections.IEnumerable en = v as System.Collections.IEnumerable;
            if (en != null)
            {
                sb.Append('['); bool first = true;
                foreach (object x in en) { if (!first) sb.Append(','); first = false; W(sb, x, depth + 1); }
                sb.Append(']'); return;
            }
            Q(sb, Convert.ToString(v, CultureInfo.InvariantCulture));
        }
        // ASCII only, so the exact bytes survive any round trip through a text file
        static void Q(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                if (c == '"') sb.Append("\\\"");
                else if (c == '\\') sb.Append("\\\\");
                else if (c == '\n') sb.Append("\\n");
                else if (c == '\r') sb.Append("\\r");
                else if (c == '\t') sb.Append("\\t");
                else if (c < 0x20 || c > 0x7e) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                else sb.Append(c);
            }
            sb.Append('"');
        }
    }

    // ---------- TLS: the server must chain to a pinned root (not the machine trust store) ----------
    public sealed class PinnedTls
    {
        public X509Certificate2Collection Roots = new X509Certificate2Collection();
        public bool Bootstrap;              // accept and record (only to fetch a root whose fingerprint is checked afterwards)
        public X509Certificate2 Server;     // what the server presented
        public X509Certificate2Collection Presented = new X509Certificate2Collection();
        public SslPolicyErrors Errors;
        public string LastError = "";

        public bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            Errors = errors; Presented = new X509Certificate2Collection(); Server = null;
            if (certificate == null) { LastError = "the server presented no certificate"; return false; }
            Server = new X509Certificate2(certificate.GetRawCertData());
            if (chain != null) foreach (X509ChainElement e in chain.ChainElements) Presented.Add(new X509Certificate2(e.Certificate.RawData));
            if (Bootstrap) return true;
            string why;
            if (!Check(out why)) { LastError = why; return false; }
            return true;
        }

        public bool Check(out string why)
        {
            why = "";
            if (Server == null) { why = "the server presented no certificate"; return false; }
            if ((Errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) { why = "the server certificate does not name the host (" + Server.Subject + ")"; return false; }
            if (Roots.Count == 0) { why = "no pinned root"; return false; }
            return ChainsTo(Server, Presented, Roots, true, out why);
        }

        // the chain from leaf must end at one of the pinned roots, with no problem other than that root being unknown to
        // the machine
        public static bool ChainsTo(X509Certificate2 leaf, X509Certificate2Collection extra, X509Certificate2Collection roots, bool serverAuth, out string why)
        {
            why = "";
            using (X509Chain ch = new X509Chain())
            {
                ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                ch.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                if (serverAuth) ch.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                if (extra != null) ch.ChainPolicy.ExtraStore.AddRange(extra);
                ch.ChainPolicy.ExtraStore.AddRange(roots);
                ch.Build(leaf);
                if (ch.ChainElements.Count == 0) { why = "no chain could be built for " + leaf.Subject; return false; }
                X509Certificate2 top = ch.ChainElements[ch.ChainElements.Count - 1].Certificate;
                bool pinned = false;
                foreach (X509Certificate2 r in roots) if (Same(r, top)) { pinned = true; break; }
                if (!pinned) { why = "the server certificate does not chain to the pinned root (chain ends at " + top.Subject + ")"; return false; }
                foreach (X509ChainElement e in ch.ChainElements)
                    foreach (X509ChainStatus s in e.ChainElementStatus)
                    {
                        if (s.Status == X509ChainStatusFlags.UntrustedRoot || s.Status == X509ChainStatusFlags.NoError) continue;
                        why = "certificate chain problem at " + e.Certificate.Subject + ": " + s.Status + " " + (s.StatusInformation ?? "").Trim();
                        return false;
                    }
                foreach (X509ChainStatus s in ch.ChainStatus)
                {
                    if (s.Status == X509ChainStatusFlags.UntrustedRoot || s.Status == X509ChainStatusFlags.NoError) continue;
                    why = "certificate chain problem: " + s.Status + " " + (s.StatusInformation ?? "").Trim();
                    return false;
                }
            }
            return true;
        }
        static bool Same(X509Certificate2 a, X509Certificate2 b)
        {
            byte[] x = a.RawData, y = b.RawData;
            if (x.Length != y.Length) return false;
            for (int i = 0; i < x.Length; i++) if (x[i] != y[i]) return false;
            return true;
        }
    }

    // ---------- HTTPS/1.1 over SslStream (one connection per request; TLS 1.2 or later) ----------
    public sealed class ShipHttpResponse
    {
        public int Status;
        public string Reason = "";
        public Dictionary<string, string> Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public byte[] Body = new byte[0];
        public string Protocol = "";
        public string Text { get { return Encoding.UTF8.GetString(Body); } }
        public JObj Json { get { try { return TJson.Parse(Text) as JObj; } catch { return null; } } }
    }

    public static class Https
    {
        public const int MaxResponse = 4 * 1024 * 1024;
        public static string UserAgent = "WebInventory (authorized asset inventory)";

        public static ShipHttpResponse Send(Uri baseUri, string method, string path, Dictionary<string, string> headers, byte[] body,
            X509Certificate2 client, PinnedTls pin, int timeoutMs)
        {
            string host = baseUri.DnsSafeHost;
            int port = baseUri.Port;
            using (TcpClient tc = Connect(host, port, timeoutMs))
            {
                tc.NoDelay = true;
                NetworkStream ns = tc.GetStream();
                ns.ReadTimeout = timeoutMs; ns.WriteTimeout = timeoutMs;
                X509Certificate2 cc = client;
                using (SslStream ssl = new SslStream(ns, false, pin.Validate, delegate(object s, string t, X509CertificateCollection l, X509Certificate r, string[] a) { return cc; }))
                {
                    X509CertificateCollection certs = new X509CertificateCollection();
                    if (client != null) certs.Add(client);
                    try { ssl.AuthenticateAsClient(host, certs, Protocols(), false); }
                    catch (AuthenticationException ex)
                    {
                        string why = pin.LastError.Length > 0 ? pin.LastError : ex.Message;
                        Exception inner = ex.InnerException;
                        if (pin.LastError.Length == 0 && inner != null) why += " (" + inner.Message + ")";
                        throw new AuthenticationException("TLS handshake with " + host + ":" + port + " failed: " + why);
                    }
                    if ((int)ssl.SslProtocol < 3072) throw new AuthenticationException("TLS " + ssl.SslProtocol + " negotiated; TLS 1.2 or later is required");
                    StringBuilder h = new StringBuilder();
                    h.Append(method).Append(' ').Append(path).Append(" HTTP/1.1\r\n");
                    h.Append("Host: ").Append(baseUri.Authority).Append("\r\n");
                    h.Append("User-Agent: ").Append(UserAgent).Append("\r\n");
                    h.Append("Accept: application/json\r\n");
                    h.Append("Connection: close\r\n");
                    if (headers != null) foreach (KeyValuePair<string, string> kv in headers) h.Append(kv.Key).Append(": ").Append(kv.Value).Append("\r\n");
                    if (body != null || method == "POST" || method == "PUT") h.Append("Content-Length: ").Append(body == null ? 0 : body.Length).Append("\r\n");
                    h.Append("\r\n");
                    byte[] hb = Encoding.ASCII.GetBytes(h.ToString());
                    ShipHttpResponse r;
                    try
                    {
                        ssl.Write(hb, 0, hb.Length);
                        if (body != null && body.Length > 0) ssl.Write(body, 0, body.Length);
                        ssl.Flush();
                        r = Read(ssl);
                    }
                    catch (IOException ex)
                    {
                        // with TLS 1.3 the server checks the client certificate after the client's side of the handshake
                        // is done: a refused certificate shows as a reset here, not as a handshake error
                        if (client != null && ssl.SslProtocol == (SslProtocols)12288 && !ex.Message.Contains("timed out"))
                            throw new IOException(ex.Message + " (right after the TLS 1.3 handshake: if this repeats, Tideline may not accept the sensor certificate " + client.Thumbprint + ")", ex);
                        throw;
                    }
                    r.Protocol = ssl.SslProtocol.ToString();
                    return r;
                }
            }
        }

        static TcpClient Connect(string host, int port, int timeoutMs)
        {
            System.Net.IPAddress ip;
            System.Net.IPAddress[] addrs = System.Net.IPAddress.TryParse(host, out ip) ? new System.Net.IPAddress[] { ip } : System.Net.Dns.GetHostAddresses(host);
            if (addrs.Length == 0) throw new IOException(host + " does not resolve");
            Exception last = null;
            foreach (System.Net.IPAddress a in addrs)
            {
                TcpClient tc = new TcpClient(a.AddressFamily);
                try
                {
                    IAsyncResult ar = tc.BeginConnect(a, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) throw new IOException("connect to " + a + ":" + port + " timed out");
                    tc.EndConnect(ar);
                    return tc;
                }
                catch (Exception ex) { last = ex; try { tc.Close(); } catch { } }
            }
            throw new IOException("cannot connect to " + host + ":" + port + ": " + (last == null ? "" : last.Message));
        }

        static SslProtocols Protocols()
        {
            // TLS 1.3 where the runtime offers it (.NET 5+); .NET Framework 4.7.2 gets TLS 1.2 (Schannel picks the suites)
            return Environment.Version.Major >= 5 ? (SslProtocols)(3072 | 12288) : (SslProtocols)3072;
        }

        static ShipHttpResponse Read(Stream s)
        {
            MemoryStream head = new MemoryStream();
            int state = 0;
            while (true)
            {
                int b = s.ReadByte();
                if (b < 0) throw new IOException("the server closed the connection before answering");
                head.WriteByte((byte)b);
                if (head.Length > 65536) throw new IOException("response headers too long");
                if (b == '\r' && (state == 0 || state == 2)) state++;
                else if (b == '\n' && (state == 1 || state == 3)) { state++; if (state == 4) break; }
                else state = 0;
            }
            string[] lines = Encoding.ASCII.GetString(head.ToArray()).Split(new string[] { "\r\n" }, StringSplitOptions.None);
            ShipHttpResponse r = new ShipHttpResponse();
            string[] st = lines[0].Split(new char[] { ' ' }, 3);
            if (st.Length < 2 || !st[0].StartsWith("HTTP/1.", StringComparison.Ordinal) || !int.TryParse(st[1], out r.Status)) throw new IOException("not an HTTP response: " + lines[0]);
            r.Reason = st.Length > 2 ? st[2] : "";
            for (int i = 1; i < lines.Length; i++)
            {
                int c = lines[i].IndexOf(':');
                if (c > 0) r.Headers[lines[i].Substring(0, c).Trim()] = lines[i].Substring(c + 1).Trim();
            }
            MemoryStream body = new MemoryStream();
            string te, cl;
            if (r.Headers.TryGetValue("Transfer-Encoding", out te) && te.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                while (true)
                {
                    string len = Line(s);
                    int semi = len.IndexOf(';'); if (semi >= 0) len = len.Substring(0, semi);
                    int n = int.Parse(len.Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                    if (n == 0) { while (Line(s).Length > 0) { } break; }
                    if (body.Length + n > MaxResponse) throw new IOException("response too large");
                    Copy(s, body, n); Line(s);
                }
            }
            else if (r.Headers.TryGetValue("Content-Length", out cl))
            {
                long n = long.Parse(cl, CultureInfo.InvariantCulture);
                if (n > MaxResponse) throw new IOException("response too large");
                Copy(s, body, (int)n);
            }
            else if (r.Status != 204 && r.Status != 304)
            {
                byte[] buf = new byte[8192]; int k;
                while ((k = s.Read(buf, 0, buf.Length)) > 0) { body.Write(buf, 0, k); if (body.Length > MaxResponse) throw new IOException("response too large"); }
            }
            r.Body = body.ToArray();
            return r;
        }
        static string Line(Stream s)
        {
            StringBuilder sb = new StringBuilder();
            while (true)
            {
                int b = s.ReadByte();
                if (b < 0) throw new IOException("connection closed in a chunked body");
                if (b == '\n') break;
                if (b != '\r') sb.Append((char)b);
                if (sb.Length > 1024) throw new IOException("bad chunk header");
            }
            return sb.ToString();
        }
        static void Copy(Stream s, Stream d, int n)
        {
            byte[] buf = new byte[8192];
            while (n > 0)
            {
                int k = s.Read(buf, 0, Math.Min(buf.Length, n));
                if (k <= 0) throw new IOException("connection closed in the response body");
                d.Write(buf, 0, k); n -= k;
            }
        }
    }

    // ---------- sensor certificates: identity is the URI SAN urn:tideline:sensor:<id> ----------
    public static class SensorCert
    {
        public const string UrnPrefix = "urn:tideline:sensor:";
        public static bool ValidId(string id)
        {
            if (string.IsNullOrEmpty(id) || id.Length > 64) return false;
            for (int i = 0; i < id.Length; i++)
            {
                char c = id[i];
                bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || (i > 0 && (c == '.' || c == '_' || c == '-'));
                if (!ok) return false;
            }
            return true;
        }

        // GeneralNames of the subjectAltName extension: [6] uniformResourceIdentifier
        public static List<string> Uris(X509Certificate2 c)
        {
            List<string> r = new List<string>();
            foreach (X509Extension e in c.Extensions)
            {
                if (e.Oid == null || e.Oid.Value != "2.5.29.17") continue;
                byte[] d = e.RawData; int p = 0;
                if (d.Length < 2 || d[p] != 0x30) continue;
                p++; int len = Len(d, ref p); int end = Math.Min(d.Length, p + len);
                while (p < end)
                {
                    byte tag = d[p++]; int l = Len(d, ref p);
                    if (l < 0 || p + l > end) break;
                    if (tag == 0x86) r.Add(Encoding.ASCII.GetString(d, p, l));
                    p += l;
                }
            }
            return r;
        }
        static int Len(byte[] d, ref int p)
        {
            if (p >= d.Length) return -1;
            int b = d[p++];
            if (b < 0x80) return b;
            int n = b & 0x7f; if (n == 0 || n > 3) return -1;
            int v = 0; for (int i = 0; i < n; i++) { if (p >= d.Length) return -1; v = (v << 8) | d[p++]; }
            return v;
        }

        public static string SensorId(X509Certificate2 c)
        {
            string found = null;
            foreach (string u in Uris(c))
            {
                if (!u.StartsWith(UrnPrefix, StringComparison.OrdinalIgnoreCase)) continue;
                string id = u.Substring(UrnPrefix.Length);
                if (!ValidId(id)) continue;
                if (found != null && !string.Equals(found, id, StringComparison.Ordinal)) return null;   // two identities: refuse
                found = id;
            }
            return found;
        }

        public static bool ClientAuth(X509Certificate2 c)
        {
            foreach (X509Extension e in c.Extensions)
            {
                X509EnhancedKeyUsageExtension eku = e as X509EnhancedKeyUsageExtension;
                if (eku == null) continue;
                foreach (Oid o in eku.EnhancedKeyUsages) if (o.Value == "1.3.6.1.5.5.7.3.2" || o.Value == "2.5.29.37.0") return true;
                return false;
            }
            return true;
        }

        // newest valid sensor certificate with a private key: LocalMachine\My, then CurrentUser\My (or one thumbprint)
        public static X509Certificate2 Find(string thumbprint, out string error)
        {
            error = "";
            string want = string.IsNullOrEmpty(thumbprint) ? "" : thumbprint.Replace(" ", "").Replace(":", "").ToUpperInvariant();
            List<X509Certificate2> cands = new List<X509Certificate2>();
            List<string> skipped = new List<string>();
            DateTime now = DateTime.Now;
            foreach (StoreLocation loc in new StoreLocation[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
            {
                X509Store st = new X509Store(StoreName.My, loc);
                try { st.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly); }
                catch { continue; }
                try
                {
                    foreach (X509Certificate2 c in st.Certificates)
                    {
                        if (want.Length > 0)
                        {
                            if (c.Thumbprint.ToUpperInvariant() != want) continue;
                            if (!c.HasPrivateKey) { error = "certificate " + want + " (" + loc + "\\My) has no private key"; return null; }
                            if (SensorId(c) == null) { error = "certificate " + want + " has no " + UrnPrefix + "<id> subject alternative name"; return null; }
                            return c;
                        }
                        if (SensorId(c) == null || !c.HasPrivateKey) continue;
                        if (c.NotBefore > now || c.NotAfter < now) { skipped.Add(c.Thumbprint + " (" + loc + ", valid " + c.NotBefore.ToString("u") + " to " + c.NotAfter.ToString("u") + ")"); continue; }
                        if (!ClientAuth(c)) { skipped.Add(c.Thumbprint + " (no client authentication usage)"); continue; }
                        cands.Add(c);
                    }
                }
                finally { st.Close(); }
            }
            if (want.Length > 0) { error = "no certificate with thumbprint " + want + " in LocalMachine\\My or CurrentUser\\My"; return null; }
            if (cands.Count == 0)
            {
                error = "no valid Tideline sensor certificate (" + UrnPrefix + "<id>, with its private key) in LocalMachine\\My or CurrentUser\\My";
                if (skipped.Count > 0) error += "; not usable: " + string.Join("; ", skipped.ToArray());
                error += ". Enroll with Register-WebInventorySensor.ps1, or pass -ShipCertThumbprint / -ShipCertPath.";
                return null;
            }
            HashSet<string> ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (X509Certificate2 c in cands) ids.Add(SensorId(c));
            if (ids.Count > 1)
            {
                List<string> l = new List<string>(ids); l.Sort(StringComparer.Ordinal);
                error = "certificates of several sensors are installed (" + string.Join(", ", l.ToArray()) + "); pass -ShipCertThumbprint";
                return null;
            }
            cands.Sort(delegate(X509Certificate2 a, X509Certificate2 b) { int x = b.NotAfter.CompareTo(a.NotAfter); return x != 0 ? x : b.NotBefore.CompareTo(a.NotBefore); });
            return cands[0];
        }

        // the CA certificates that came with a PFX (an export bundle carries them with the leaf)
        public static readonly X509Certificate2Collection Intermediates = new X509Certificate2Collection();
        public static X509Certificate2 LoadPfx(string path, string password)
        {
            X509KeyStorageFlags fl = X509KeyStorageFlags.DefaultKeySet;
            if (Environment.OSVersion.Platform == PlatformID.Win32NT) fl = X509KeyStorageFlags.UserKeySet;   // no machine key container is created
            X509Certificate2Collection all = new X509Certificate2Collection();
            all.Import(File.ReadAllBytes(path), password, fl);
            X509Certificate2 leaf = null;
            foreach (X509Certificate2 c in all)
            {
                if (c.HasPrivateKey) { if (leaf == null) leaf = c; }
                else if (c.Subject != c.Issuer) Intermediates.Add(c);
            }
            if (leaf == null) throw new CryptographicException(path + " holds no certificate with a private key");
            return leaf;
        }

        public static X509Certificate2Collection LoadPem(string path)
        {
            X509Certificate2Collection r = new X509Certificate2Collection();
            foreach (byte[] der in PemBlocks(File.ReadAllText(path), "CERTIFICATE")) r.Add(new X509Certificate2(der));
            if (r.Count == 0)
            {
                byte[] raw = File.ReadAllBytes(path);
                if (raw.Length > 0 && raw[0] == 0x30) r.Add(new X509Certificate2(raw));   // a DER file
            }
            if (r.Count == 0) throw new CryptographicException(path + " holds no certificate");
            return r;
        }

        public static List<byte[]> PemBlocks(string text, string label)
        {
            List<byte[]> r = new List<byte[]>();
            string begin = "-----BEGIN " + label + "-----", end = "-----END " + label + "-----";
            int p = 0;
            while ((p = text.IndexOf(begin, p, StringComparison.Ordinal)) >= 0)
            {
                int s = p + begin.Length, e = text.IndexOf(end, s, StringComparison.Ordinal);
                if (e < 0) break;
                r.Add(Convert.FromBase64String(text.Substring(s, e - s).Replace("\r", "").Replace("\n", "").Replace(" ", "")));
                p = e + end.Length;
            }
            return r;
        }

        public static string Pem(byte[] der, string label)
        {
            string b = Convert.ToBase64String(der);
            StringBuilder sb = new StringBuilder();
            sb.Append("-----BEGIN ").Append(label).Append("-----\n");
            for (int i = 0; i < b.Length; i += 64) sb.Append(b.Substring(i, Math.Min(64, b.Length - i))).Append('\n');
            sb.Append("-----END ").Append(label).Append("-----\n");
            return sb.ToString();
        }

        public static string Sha256Hex(byte[] b)
        {
            using (SHA256 h = SHA256.Create()) return Hex(h.ComputeHash(b));
        }
        public static string Hex(byte[] b)
        {
            StringBuilder sb = new StringBuilder(b.Length * 2);
            foreach (byte x in b) sb.Append(x.ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct KeyProvInfo
        {
            public string ContainerName, ProvName;
            public int ProvType, Flags, ProvParamCount;
            public IntPtr ProvParams;
            public int KeySpec;
        }
        [DllImport("crypt32.dll", SetLastError = true)]
        static extern bool CertGetCertificateContextProperty(IntPtr context, int propId, IntPtr data, ref int size);

        // where a Windows certificate's key lives: provider, container, machine or user (CERT_KEY_PROV_INFO_PROP_ID)
        public static string[] KeyLocation(X509Certificate2 cert)
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT) return null;
            int size = 0;
            if (!CertGetCertificateContextProperty(cert.Handle, 2, IntPtr.Zero, ref size) || size <= 0) return null;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (!CertGetCertificateContextProperty(cert.Handle, 2, buf, ref size)) return null;
                KeyProvInfo k = (KeyProvInfo)Marshal.PtrToStructure(buf, typeof(KeyProvInfo));
                return new string[] { k.ProvName ?? "", k.ContainerName ?? "", (k.Flags & 0x20) != 0 ? "machine" : "user", k.ProvType.ToString(CultureInfo.InvariantCulture) };
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        // the certificate's private key. .NET Framework's GetECDsaPrivateKey can refuse a persisted machine key bound to
        // its certificate by certutil -repairstore ("detected to be ephemeral"); the key is then opened by the provider
        // and container the certificate records, which is the same key Schannel uses
        public static ECDsa PrivateKey(X509Certificate2 cert)
        {
            Exception first = null;
            try { ECDsa k = cert.GetECDsaPrivateKey(); if (k != null) return k; }
            catch (Exception ex) { first = ex; }
            string[] loc = KeyLocation(cert);
            if (loc != null && loc[3] == "0" && loc[1].Length > 0)
            {
                try
                {
                    CngKey key = CngKey.Open(loc[1], new CngProvider(loc[0].Length > 0 ? loc[0] : CngProvider.MicrosoftSoftwareKeyStorageProvider.Provider),
                        loc[2] == "machine" ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None);
                    return new ECDsaCng(key);
                }
                catch (Exception ex) { if (first == null) first = ex; }
            }
            if (first != null) throw new CryptographicException(first.Message, first);
            return null;
        }

        // who may use a Windows CNG key: its own security descriptor (NCRYPT_SECURITY_DESCR_PROPERTY), which the key
        // storage provider keeps with the key; editing the key file's NTFS ACL is not the documented way for CNG keys
        const CngPropertyOptions DaclInfo = (CngPropertyOptions)0x4;   // DACL_SECURITY_INFORMATION
        static CommonSecurityDescriptor KeyDescriptor(CngKey key)
        {
            byte[] sd = key.GetProperty("Security Descr", DaclInfo).GetValue();
            return new CommonSecurityDescriptor(false, false, sd, 0);
        }
        public static string[] KeyReaders(X509Certificate2 cert)
        {
            List<string> r = new List<string>();
            using (ECDsa e = PrivateKey(cert))
            {
                ECDsaCng k = e as ECDsaCng;
                if (k == null) return r.ToArray();
                foreach (GenericAce a in KeyDescriptor(k.Key).DiscretionaryAcl)
                {
                    CommonAce c = a as CommonAce;
                    if (c == null || c.AceQualifier != AceQualifier.AccessAllowed) continue;
                    string n;
                    try { n = c.SecurityIdentifier.Translate(typeof(NTAccount)).Value; } catch { n = c.SecurityIdentifier.Value; }
                    if (!r.Contains(n)) r.Add(n);
                }
            }
            return r.ToArray();
        }
        public static void GrantKeyRead(X509Certificate2 cert, string account)
        {
            SecurityIdentifier sid = account.StartsWith("S-1-", StringComparison.Ordinal) ? new SecurityIdentifier(account) : (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier));
            using (ECDsa e = PrivateKey(cert))
            {
                ECDsaCng k = e as ECDsaCng;
                if (k == null) throw new CryptographicException("the key of " + cert.Thumbprint + " is not a Windows CNG key");
                CommonSecurityDescriptor d = KeyDescriptor(k.Key);
                d.DiscretionaryAcl.AddAccess(AccessControlType.Allow, sid, unchecked((int)0x80000000), InheritanceFlags.None, PropagationFlags.None);   // GENERIC_READ: use the key
                byte[] b = new byte[d.BinaryLength];
                d.GetBinaryForm(b, 0);
                k.Key.SetProperty(new CngProperty("Security Descr", b, DaclInfo));
            }
        }

        // ES256 (ECDSA P-256, SHA-256) over the exact bytes; IEEE P1363 (r || s), as .NET produces it
        public static string SignatureHeader(byte[] data, X509Certificate2 cert)
        {
            ECDsa k;
            try { k = PrivateKey(cert); }
            catch (CryptographicException ex) { throw new CryptographicException("the private key of " + cert.Thumbprint + " cannot be used by this account (" + ex.Message + "); run as the account the key was issued to, or grant it read access to the key"); }
            if (k == null) throw new CryptographicException("certificate " + cert.Thumbprint + " has no ECDSA private key (the sensor key must be ECDSA P-256)");
            using (k)
            {
                if (k.KeySize != 256) throw new CryptographicException("the sensor key is ECDSA P-" + k.KeySize + "; ES256 needs P-256");
                byte[] sig = k.SignData(data, HashAlgorithmName.SHA256);
                return "alg=ES256; enc=p1363; sig=" + Convert.ToBase64String(sig);
            }
        }

        // the certificates that go with the leaf (intermediates, not the root), for an export bundle
        public static List<X509Certificate2> ChainOf(X509Certificate2 leaf, X509Certificate2Collection roots)
        {
            List<X509Certificate2> r = new List<X509Certificate2>();
            r.Add(leaf);
            using (X509Chain ch = new X509Chain())
            {
                ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                ch.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                if (roots != null) ch.ChainPolicy.ExtraStore.AddRange(roots);
                ch.ChainPolicy.ExtraStore.AddRange(Intermediates);
                ch.Build(leaf);
                for (int i = 1; i < ch.ChainElements.Count; i++)
                {
                    X509Certificate2 c = ch.ChainElements[i].Certificate;
                    if (c.Subject == c.Issuer) break;   // a self-signed root
                    r.Add(c);
                }
            }
            return r;
        }
    }

    // ---------- a finished run, as the parts of a Tideline envelope ----------
    public sealed class ShipPart
    {
        public int N;
        public string Kind = "", Schema = "", Media = "", Role = "", Name = "", Path = "", Sha256 = "", FileSha256 = "";
        public long Records = -1, Bytes, Offset, FileBytes;
        public bool Gzip, Ndjson;
        public int Chunk, Chunks;
    }

    public sealed class ShipRun
    {
        public const string Envelope = "tideline-envelope/1";
        public static long ChunkBytes = 32L * 1024 * 1024;   // NDJSON files above this go as several parts, split at line ends
        public string Dir = "", RunJson = "", ToolRun = "", RunUuid = "", Engagement = "", ToolVersion = "", Started = "", Finished = "", Computer = "", ToolManifestSha256 = "";
        public object ExitCode;
        public JObj Profile;
        public readonly List<ShipPart> Parts = new List<ShipPart>();
        public readonly List<string> Notes = new List<string>();
        Dictionary<string, string[]> toolManifest = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

        public static ShipRun Collect(string runJsonPath)
        {
            ShipRun r = new ShipRun();
            r.RunJson = System.IO.Path.GetFullPath(runJsonPath);
            r.Dir = System.IO.Path.GetDirectoryName(r.RunJson);
            JObj info = TJson.Parse(File.ReadAllText(r.RunJson, Encoding.UTF8).TrimStart('\uFEFF')) as JObj;
            if (info == null) throw new InvalidDataException(r.RunJson + " is not a run.json object");
            r.ToolRun = info.Str("runId") ?? "";
            if (r.ToolRun.Length == 0) throw new InvalidDataException(r.RunJson + " has no runId");
            if (!(info["complete"] is bool) || !(bool)info["complete"]) throw new InvalidDataException("run " + r.ToolRun + " is not complete (interrupted or time limit); resume it first, an incomplete run is never shipped");
            string scanner = info.Str("scanner") ?? "";
            r.ToolVersion = scanner.StartsWith("WebInventory ", StringComparison.Ordinal) ? scanner.Substring(13) : scanner;
            r.RunUuid = info.Str("runUuid") ?? "";
            r.Engagement = info.Str("engagement") ?? "";
            r.ExitCode = info["exitCode"];
            r.Computer = info.Str("computer") ?? "";
            r.Started = Utc(info.Str("startedAt"));
            r.Finished = Utc(info.Str("finishedAt"));
            r.Profile = info.Obj("profile") ?? new JObj();

            string stem = System.IO.Path.Combine(r.Dir, "WebInventory_" + r.ToolRun);
            string tm = stem + "_manifest.txt";
            if (!File.Exists(tm)) throw new FileNotFoundException("the run's manifest " + tm + " is missing; it is written when a run finishes");
            byte[] tmb = File.ReadAllBytes(tm);
            r.ToolManifestSha256 = SensorCert.Sha256Hex(tmb);
            foreach (string line in Encoding.UTF8.GetString(tmb).Split('\n'))
            {
                string l = line.TrimEnd('\r');
                if (l.Length == 0 || l[0] == '#') continue;
                string[] f = l.Split(new string[] { "  " }, 3, StringSplitOptions.None);
                if (f.Length == 3) r.toolManifest[f[2].Replace('\\', '/')] = new string[] { f[0], f[1] };
            }

            if (!File.Exists(stem + ".jsonl")) throw new FileNotFoundException("the run's results " + stem + ".jsonl are missing");
            r.AddNdjson("services", "webinventory.service/1", stem + ".jsonl");
            r.AddNdjson("delta", "webinventory.delta/1", stem + "_delta.jsonl");
            r.AddNdjson("screenshots", "webinventory.screenshot/1", stem + "_screenshots.jsonl");
            r.AddNdjson("vulns", "webinventory.vuln/1", stem + "_vulns.jsonl");
            r.AddNdjson("errors", "webinventory.error/1", stem + "_errors.jsonl");
            r.AddFile("run-info", "application/json", r.RunJson, true);
            r.AddFile("tool-manifest", "text/plain; charset=utf-8", tm, true);
            r.AddFile("vuln-provenance", "application/json", stem + "_vulns.provenance.json", false);
            // the run and error logs of each session (written to the folder the run was started from)
            List<object> sessions = info.Arr("sessions");
            HashSet<string> logs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (sessions != null)
                foreach (object so in sessions)
                {
                    JObj s = so as JObj; if (s == null) continue;
                    foreach (string k in new string[] { "runLog", "errorLog" })
                    {
                        string p = s.Str(k);
                        if (string.IsNullOrEmpty(p) || !logs.Add(p)) continue;
                        if (File.Exists(p)) r.AddFile("log", "text/plain; charset=utf-8", p, true);
                        else r.Notes.Add("log not found, not shipped: " + p);
                    }
                }
            // screenshot images named by the index
            string shots = stem + "_screenshots.jsonl";
            if (File.Exists(shots))
            {
                List<string> files = new List<string>();
                foreach (string line in File.ReadAllLines(shots, Encoding.UTF8))
                {
                    if (line.Trim().Length == 0) continue;
                    JObj o = TJson.Parse(line) as JObj;
                    string f = o == null ? null : o.Str("File");
                    if (string.IsNullOrEmpty(f)) continue;
                    f = f.Replace('\\', '/');
                    if (f.StartsWith("/", StringComparison.Ordinal) || f.Contains("..") || f.Contains(":")) { r.Notes.Add("screenshot path refused: " + f); continue; }
                    if (!files.Contains(f)) files.Add(f);
                }
                files.Sort(StringComparer.Ordinal);
                foreach (string f in files)
                {
                    string p = System.IO.Path.Combine(r.Dir, f.Replace('/', System.IO.Path.DirectorySeparatorChar));
                    if (File.Exists(p)) r.AddFile("screenshot", "image/png", p, false, f);
                    else r.Notes.Add("screenshot not found, not shipped: " + f);
                }
            }
            for (int i = 0; i < r.Parts.Count; i++) r.Parts[i].N = i + 1;
            return r;
        }

        static string Utc(string iso)
        {
            if (string.IsNullOrEmpty(iso)) return "";
            DateTimeOffset t;
            if (!DateTimeOffset.TryParse(iso, CultureInfo.InvariantCulture, DateTimeStyles.None, out t)) return iso;
            return t.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        }

        string Rel(string path)
        {
            string b = Dir.TrimEnd(System.IO.Path.DirectorySeparatorChar) + System.IO.Path.DirectorySeparatorChar;
            return path.StartsWith(b, StringComparison.OrdinalIgnoreCase) ? path.Substring(b.Length).Replace('\\', '/') : System.IO.Path.GetFileName(path);
        }

        // the file as the run wrote it must still be what the run's own manifest recorded
        void CheckTool(string name, string sha, long bytes)
        {
            string[] e;
            if (!toolManifest.TryGetValue(name, out e)) return;
            if (!string.Equals(e[0], sha, StringComparison.OrdinalIgnoreCase) || e[1] != bytes.ToString(CultureInfo.InvariantCulture))
                throw new InvalidDataException(name + " changed after the run's manifest was written (manifest " + e[0].Substring(0, Math.Min(12, e[0].Length)) + ", file " + sha.Substring(0, 12) + "); it is not shipped");
        }

        void AddNdjson(string kind, string schema, string path)
        {
            if (!File.Exists(path)) return;
            string name = Rel(path);
            byte[] all = File.ReadAllBytes(path);
            string fileSha = SensorCert.Sha256Hex(all);
            CheckTool(name, fileSha, all.LongLength);
            // split at line ends into chunks of at most ChunkBytes
            List<long[]> chunks = new List<long[]>();
            long start = 0;
            while (start < all.LongLength)
            {
                long end = Math.Min(all.LongLength, start + ChunkBytes);
                if (end < all.LongLength)
                {
                    long nl = end - 1;
                    while (nl > start && all[nl] != (byte)'\n') nl--;
                    if (nl == start) throw new InvalidDataException(name + " has a line longer than " + ChunkBytes + " bytes");
                    end = nl + 1;
                }
                chunks.Add(new long[] { start, end - start });
                start = end;
            }
            if (chunks.Count == 0) chunks.Add(new long[] { 0, 0 });
            for (int i = 0; i < chunks.Count; i++)
            {
                ShipPart p = new ShipPart();
                p.Kind = kind; p.Schema = schema; p.Media = "application/x-ndjson"; p.Name = name; p.Path = path; p.Ndjson = true;
                p.Offset = chunks[i][0]; p.Bytes = chunks[i][1];
                p.Gzip = p.Bytes > 0;   // an empty part goes as it is: .NET 9's GZipStream writes no gzip member for no data
                long rec = 0; long last = p.Offset - 1;
                for (long j = p.Offset; j < p.Offset + p.Bytes; j++)
                    if (all[j] == (byte)'\n') { if (j - last > 1 && !(j - last == 2 && all[j - 1] == (byte)'\r')) rec++; last = j; }
                if (p.Offset + p.Bytes - 1 > last) rec++;   // a last line without a line end
                p.Records = rec;
                using (SHA256 h = SHA256.Create()) p.Sha256 = SensorCert.Hex(h.ComputeHash(all, (int)p.Offset, (int)p.Bytes));
                if (chunks.Count > 1) { p.Chunk = i + 1; p.Chunks = chunks.Count; p.FileSha256 = fileSha; p.FileBytes = all.LongLength; }
                Parts.Add(p);
            }
        }

        void AddFile(string role, string media, string path, bool gzip) { AddFile(role, media, path, gzip, null); }
        void AddFile(string role, string media, string path, bool gzip, string name)
        {
            if (!File.Exists(path)) return;
            byte[] b = File.ReadAllBytes(path);
            ShipPart p = new ShipPart();
            p.Kind = "artifact"; p.Role = role; p.Media = media; p.Name = name ?? Rel(path); p.Path = path; p.Gzip = gzip && b.LongLength > 0;
            p.Bytes = b.LongLength; p.Sha256 = SensorCert.Sha256Hex(b);
            CheckTool(p.Name, p.Sha256, p.Bytes);
            Parts.Add(p);
        }

        // a run made before run.json recorded runUuid gets a name-based UUID, so shipping it twice gives the same id
        public string DerivedUuid()
        {
            byte[] h;
            using (SHA256 s = SHA256.Create()) h = s.ComputeHash(Encoding.UTF8.GetBytes("webinventory|" + Computer + "|" + ToolRun + "|" + ToolManifestSha256));
            h[6] = (byte)((h[6] & 0x0f) | 0x50); h[8] = (byte)((h[8] & 0x3f) | 0x80);
            string x = SensorCert.Hex(h).Substring(0, 32);
            return x.Substring(0, 8) + "-" + x.Substring(8, 4) + "-" + x.Substring(12, 4) + "-" + x.Substring(16, 4) + "-" + x.Substring(20, 12);
        }

        // deterministic bytes: the same run, sensor and engagement always give the same manifest
        public byte[] Manifest(string sensor, string runId, string engagement)
        {
            JObj m = new JObj();
            m.Add("schema", Envelope).Add("run_id", runId).Add("tool", "webinventory").Add("tool_version", ToolVersion).Add("tool_run", ToolRun);
            m.Add("sensor", sensor).Add("engagement", string.IsNullOrEmpty(engagement) ? null : engagement).Add("job_id", null);
            m.Add("started", Started).Add("finished", Finished).Add("exit_code", ExitCode);
            m.Add("profile", Profile).Add("tool_manifest_sha256", ToolManifestSha256);
            List<object> parts = new List<object>();
            foreach (ShipPart p in Parts)
            {
                JObj o = new JObj();
                o.Add("n", (long)p.N).Add("kind", p.Kind);
                if (p.Ndjson) o.Add("schema", p.Schema);
                else o.Add("role", p.Role);
                o.Add("media", p.Media).Add("name", p.Name);
                if (p.Ndjson) o.Add("records", p.Records);
                o.Add("bytes", p.Bytes).Add("sha256", p.Sha256).Add("encoding", p.Gzip ? "gzip" : "identity");
                if (p.Chunks > 1) o.Add("chunk", (long)p.Chunk).Add("chunks", (long)p.Chunks).Add("file_bytes", p.FileBytes).Add("file_sha256", p.FileSha256);
                parts.Add(o);
            }
            m.Add("parts", parts);
            return Encoding.ASCII.GetBytes(TJson.Write(m));
        }

        // the bytes of one part as uploaded (gzip for NDJSON and text); checked against the manifest first
        public static byte[] Body(ShipPart p)
        {
            byte[] raw = new byte[p.Bytes];
            using (FileStream fs = new FileStream(p.Path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                fs.Seek(p.Offset, SeekOrigin.Begin);
                int got = 0;
                while (got < raw.Length) { int k = fs.Read(raw, got, raw.Length - got); if (k <= 0) break; got += k; }
                if (got != raw.Length) throw new InvalidDataException(p.Name + " is shorter than when the manifest was made; it changed and is not shipped");
            }
            string sha = SensorCert.Sha256Hex(raw);
            if (sha != p.Sha256) throw new InvalidDataException(p.Name + " changed since the manifest was made (part " + p.N + "); it is not shipped");
            if (!p.Gzip) return raw;
            using (MemoryStream ms = new MemoryStream())
            {
                using (GZipStream gz = new GZipStream(ms, CompressionLevel.Optimal, true)) gz.Write(raw, 0, raw.Length);
                return ms.ToArray();
            }
        }
    }

    public sealed class ShipResult
    {
        public bool Ok, Retryable, AlreadyComplete;
        public string State = "", Error = "", RunId = "", Sensor = "", ManifestSha256 = "";
        public int PartsSent, PartsTotal, Attempts;
        public long BytesSent;
        public readonly List<string> Log = new List<string>();
    }

    // ---------- the shipping protocol (POST manifest, PUT missing parts, POST complete), with ship-state.json ----------
    public sealed class Shipper
    {
        public Uri Target;
        public X509Certificate2 Cert;
        public X509Certificate2Collection Roots = new X509Certificate2Collection();
        public int TimeoutMs = 60000, Retries = 3, RetryDelayMs = 5000;
        public string ToolVersion = "";

        public static string StateFile(ShipRun run) { return System.IO.Path.Combine(run.Dir, "WebInventory_" + run.ToolRun + "_ship-state.json"); }
        string Key { get { return Target.GetLeftPart(UriPartial.Authority).ToLowerInvariant() + Target.AbsolutePath.TrimEnd('/'); } }
        string ApiBase { get { return Target.AbsolutePath.TrimEnd('/'); } }

        static JObj LoadState(string path)
        {
            if (!File.Exists(path)) return new JObj().Add("format", 1L).Add("targets", new JObj());
            JObj s = TJson.Parse(File.ReadAllText(path, Encoding.UTF8)) as JObj;
            if (s == null || s.Obj("targets") == null) throw new InvalidDataException(path + " is not a ship-state file");
            return s;
        }
        static void SaveState(string path, JObj s)
        {
            string tmp = path + ".tmp";
            File.WriteAllText(tmp, TJson.Write(s) + "\n", new UTF8Encoding(false));
            if (File.Exists(path)) File.Replace(tmp, path, null); else File.Move(tmp, path);
        }

        public static string Now() { return DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture); }

        public JObj Entry(ShipRun run)
        {
            JObj s = LoadState(StateFile(run));
            return s.Obj("targets").Obj(Key);
        }

        // a run this URL already confirmed, from its run.json path alone (a folder sweep skips it without re-reading the run)
        public bool DeliveredBefore(string runJsonPath)
        {
            string name = System.IO.Path.GetFileName(runJsonPath);
            if (!name.StartsWith("WebInventory_", StringComparison.Ordinal) || !name.EndsWith("_run.json", StringComparison.Ordinal)) return false;
            string sp = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(runJsonPath)), name.Substring(0, name.Length - 9) + "_ship-state.json");
            if (!File.Exists(sp)) return false;
            try { JObj e = LoadState(sp).Obj("targets").Obj(Key); return e != null && e.Str("state") == "complete"; }
            catch { return false; }
        }

        // the manifest this run is shipped under: the one Tideline accepted for this target (it must not change once
        // accepted), else a new one. Manifests are deterministic, so a new one is the same bytes unless the sensor,
        // the engagement or the run's files changed.
        public byte[] Prepare(ShipRun run, string engagement, out string runId, out string sensor, out JObj state, out JObj entry)
        {
            sensor = SensorCert.SensorId(Cert);
            if (sensor == null) throw new CryptographicException("the certificate " + Cert.Thumbprint + " has no single " + SensorCert.UrnPrefix + "<id> name");
            state = LoadState(StateFile(run));
            entry = state.Obj("targets").Obj(Key);
            if (entry != null && entry.Str("manifest") != null && entry["accepted"] is bool && (bool)entry["accepted"])
            {
                byte[] mb = Encoding.ASCII.GetBytes(entry.Str("manifest"));
                JObj m = TJson.Parse(entry.Str("manifest")) as JObj;
                if (m == null || m.Str("sensor") != sensor)
                    throw new InvalidDataException("this run was prepared for Tideline as sensor '" + (m == null ? "?" : m.Str("sensor")) + "', the certificate is sensor '" + sensor + "'; ship it with that sensor's certificate");
                if (!string.IsNullOrEmpty(engagement) && m.Str("engagement") != engagement)
                    throw new InvalidDataException("this run was prepared for engagement '" + m.Str("engagement") + "'; -Engagement '" + engagement + "' cannot change it");
                runId = m.Str("run_id");
                return mb;
            }
            string eng = run.Engagement;
            if (!string.IsNullOrEmpty(engagement))
            {
                if (eng.Length > 0 && eng != engagement) throw new InvalidDataException("the run was made for engagement '" + eng + "'; -Engagement '" + engagement + "' cannot change it");
                eng = engagement;
            }
            runId = run.RunUuid.Length > 0 ? run.RunUuid : run.DerivedUuid();
            byte[] bytes = run.Manifest(sensor, runId, eng);
            JObj previous = entry;
            entry = new JObj();
            entry.Add("target", Target.ToString()).Add("run_id", runId).Add("sensor", sensor).Add("state", "prepared").Add("accepted", false)
                 .Add("manifest_sha256", SensorCert.Sha256Hex(bytes)).Add("manifest", Encoding.ASCII.GetString(bytes))
                 .Add("parts_sent", new List<object>()).Add("attempts", previous != null && previous.Arr("attempts") != null ? previous.Arr("attempts") : new List<object>());
            state.Obj("targets").Add(Key, entry);
            SaveState(StateFile(run), state);
            return bytes;
        }

        ShipHttpResponse Call(string method, string path, Dictionary<string, string> h, byte[] body)
        {
            PinnedTls pin = new PinnedTls(); pin.Roots = Roots;
            return Https.Send(Target, method, ApiBase + path, h, body, Cert, pin, TimeoutMs);
        }

        static string Brief(ShipHttpResponse r)
        {
            string t = r.Text.Trim();
            JObj j = r.Json;
            if (j != null && j.Str("error") != null) t = j.Str("error") + (j.Has("lines") ? " lines " + TJson.Write(j["lines"]) : "") + (j.Str("reason") != null ? " (" + j.Str("reason") + ")" : "");
            if (t.Length > 300) t = t.Substring(0, 300) + "...";
            return "HTTP " + r.Status + (t.Length > 0 ? ": " + t : "");
        }
        static bool Transient(int status) { return status == 408 || status == 429 || status >= 500; }

        static List<int> Missing(JObj j, int total)
        {
            List<int> r = new List<int>();
            List<object> m = j == null ? null : j.Arr("missing");
            if (m == null) { for (int i = 1; i <= total; i++) r.Add(i); return r; }
            foreach (object o in m) { long n; if (o is long) { n = (long)o; if (n >= 1 && n <= total && !r.Contains((int)n)) r.Add((int)n); } }
            r.Sort();
            return r;
        }

        public ShipResult Ship(ShipRun run, string engagement, bool force)
        {
            ShipResult res = new ShipResult();
            string runId, sensor; JObj state, entry;
            byte[] manifest = Prepare(run, engagement, out runId, out sensor, out state, out entry);
            res.RunId = runId; res.Sensor = sensor; res.PartsTotal = run.Parts.Count; res.ManifestSha256 = SensorCert.Sha256Hex(manifest);
            string sp = StateFile(run);
            if (entry.Str("state") == "complete" && !force)
            {
                res.Ok = true; res.AlreadyComplete = true; res.State = "complete";
                res.Log.Add("already shipped to " + Target + " (run " + runId + ", " + entry.Str("completed_at") + ")");
                return res;
            }
            // the parts must match the manifest this run was prepared under
            JObj mobj = TJson.Parse(Encoding.ASCII.GetString(manifest)) as JObj;
            List<object> mparts = mobj.Arr("parts");
            if (mparts == null || mparts.Count != run.Parts.Count) throw new InvalidDataException("the run's files differ from the manifest prepared earlier (" + (mparts == null ? 0 : mparts.Count) + " parts then, " + run.Parts.Count + " now)");
            for (int i = 0; i < run.Parts.Count; i++)
            {
                JObj q = mparts[i] as JObj;
                if (q == null || q.Str("sha256") != run.Parts[i].Sha256 || q.Str("name") != run.Parts[i].Name) throw new InvalidDataException("part " + (i + 1) + " (" + run.Parts[i].Name + ") differs from the manifest prepared earlier");
            }
            string sig = SensorCert.SignatureHeader(manifest, Cert);
            List<object> sent = entry.Arr("parts_sent") ?? new List<object>();
            for (int attempt = 0; attempt <= Retries; attempt++)
            {
                res.Attempts = attempt + 1;
                if (attempt > 0)
                {
                    int wait = (int)Math.Min(300000, RetryDelayMs * Math.Pow(3, attempt - 1));
                    res.Log.Add("retrying in " + (wait / 1000) + " s");
                    Thread.Sleep(wait);
                }
                string error = ""; bool transient = true;
                try
                {
                    Dictionary<string, string> h = new Dictionary<string, string>();
                    h["Content-Type"] = "application/json"; h["Tideline-Signature"] = sig;
                    ShipHttpResponse r = Call("POST", "/v1/runs", h, manifest);
                    if (r.Status == 409) { transient = false; throw new IOException("Tideline already holds run " + runId + " with a different manifest (" + Brief(r) + ")"); }
                    if (r.Status != 200 && r.Status != 201) { transient = Transient(r.Status); throw new IOException("opening the run: " + Brief(r)); }
                    if (!(entry["accepted"] is bool) || !(bool)entry["accepted"]) { entry.Add("accepted", true); SaveState(sp, state); }
                    JObj j = r.Json;
                    string st = j == null ? "" : (j.Str("state") ?? "");
                    if (st == "verified" || st == "normalized")
                    {
                        Record(entry, sp, state, "complete", "");
                        res.Ok = true; res.State = st; res.AlreadyComplete = r.Status == 200;
                        res.Log.Add("Tideline already has run " + runId + " complete (" + st + ")");
                        return res;
                    }
                    if (st == "rejected") { transient = false; throw new IOException("Tideline rejected run " + runId + ": " + (j.Str("reason") ?? "")); }
                    List<int> missing = Missing(j, run.Parts.Count);
                    res.Log.Add(string.Format(CultureInfo.InvariantCulture, "run {0} open ({1}); {2} of {3} parts to send", runId, r.Status == 201 ? "new" : "resumed", missing.Count, run.Parts.Count));
                    foreach (int n in missing)
                    {
                        ShipPart p = run.Parts[n - 1];
                        byte[] body = ShipRun.Body(p);
                        Dictionary<string, string> ph = new Dictionary<string, string>();
                        ph["Content-Type"] = p.Media;
                        if (p.Gzip) ph["Content-Encoding"] = "gzip";
                        ShipHttpResponse pr = Call("PUT", "/v1/runs/" + runId + "/parts/" + n.ToString(CultureInfo.InvariantCulture), ph, body);
                        if (pr.Status == 204 || pr.Status == 200)
                        {
                            res.PartsSent++; res.BytesSent += body.Length;
                            if (!sent.Contains((long)n)) sent.Add((long)n);
                            entry.Add("parts_sent", sent); entry.Add("state", "receiving"); SaveState(sp, state);
                            continue;
                        }
                        transient = Transient(pr.Status);
                        throw new IOException("part " + n + " (" + p.Name + (p.Chunks > 1 ? " chunk " + p.Chunk + "/" + p.Chunks : "") + "): " + Brief(pr));
                    }
                    ShipHttpResponse cr = Call("POST", "/v1/runs/" + runId + "/complete", null, new byte[0]);
                    if (cr.Status == 202 || cr.Status == 200)
                    {
                        JObj cj = cr.Json;
                        Record(entry, sp, state, "complete", "");
                        res.Ok = true; res.State = cj == null ? "verified" : (cj.Str("state") ?? "verified");
                        res.Log.Add(string.Format(CultureInfo.InvariantCulture, "run {0} complete at Tideline ({1}); {2} parts, {3:N0} bytes sent", runId, res.State, res.PartsSent, res.BytesSent));
                        return res;
                    }
                    if (cr.Status == 409) { error = "closing the run: " + Brief(cr) + "; the missing parts are sent again"; transient = true; throw new IOException(error); }
                    transient = Transient(cr.Status);
                    throw new IOException("closing the run: " + Brief(cr));
                }
                catch (Exception ex)
                {
                    if (ex is InvalidDataException || ex is CryptographicException) transient = false;
                    if (ex is AuthenticationException) transient = false;
                    error = ex.Message;
                    res.Log.Add("attempt " + (attempt + 1) + ": " + error);
                    Record(entry, sp, state, transient ? "receiving" : "rejected", error);
                    res.Error = error; res.Retryable = transient;
                    if (!transient) { res.State = "rejected"; return res; }
                }
            }
            res.State = "pending";
            return res;
        }

        void Record(JObj entry, string sp, JObj state, string st, string error)
        {
            List<object> at = entry.Arr("attempts") ?? new List<object>();
            at.Add(new JObj().Add("at", Now()).Add("result", st).Add("error", error.Length > 0 ? error : null).Add("by", ToolVersion));
            while (at.Count > 50) at.RemoveAt(0);
            entry.Add("attempts", at).Add("state", st == "rejected" ? "failed" : st).Add("last_error", error.Length > 0 ? error : null);
            if (st == "complete") entry.Add("completed_at", Now());
            SaveState(sp, state);
        }

        public ShipHttpResponse Status(string runId)
        {
            return Call("GET", "/v1/runs/" + runId, null, null);
        }

        // one file to carry by hand: manifest, signature, the sensor's certificate chain and the parts as they would be uploaded
        public static int Export(ShipRun run, X509Certificate2 cert, X509Certificate2Collection roots, string engagement, string zipPath, string toolVersion)
        {
            string sensor = SensorCert.SensorId(cert);
            if (sensor == null) throw new CryptographicException("the certificate " + cert.Thumbprint + " has no single " + SensorCert.UrnPrefix + "<id> name");
            string eng = run.Engagement;
            if (!string.IsNullOrEmpty(engagement))
            {
                if (eng.Length > 0 && eng != engagement) throw new InvalidDataException("the run was made for engagement '" + eng + "'; -Engagement '" + engagement + "' cannot change it");
                eng = engagement;
            }
            string runId = run.RunUuid.Length > 0 ? run.RunUuid : run.DerivedUuid();
            byte[] manifest = run.Manifest(sensor, runId, eng);
            string sig = SensorCert.SignatureHeader(manifest, cert);
            string tmp = zipPath + ".tmp";
            if (File.Exists(tmp)) File.Delete(tmp);
            JObj index = new JObj();
            index.Add("format", "tideline-bundle/1").Add("run_id", runId).Add("created", Now()).Add("created_by", "WebInventory " + toolVersion);
            List<object> files = new List<object>();
            using (FileStream fs = new FileStream(tmp, FileMode.CreateNew))
            using (ZipArchive z = new ZipArchive(fs, ZipArchiveMode.Create))
            {
                ZipPut(z, "manifest.json", manifest, CompressionLevel.Optimal);
                ZipPut(z, "manifest.sig", Encoding.ASCII.GetBytes(sig + "\n"), CompressionLevel.Optimal);
                StringBuilder chain = new StringBuilder();
                foreach (X509Certificate2 c in SensorCert.ChainOf(cert, roots)) chain.Append(SensorCert.Pem(c.RawData, "CERTIFICATE"));
                ZipPut(z, "sensor-chain.pem", Encoding.ASCII.GetBytes(chain.ToString()), CompressionLevel.Optimal);
                foreach (ShipPart p in run.Parts)
                {
                    string name = "parts/" + p.N.ToString("D4", CultureInfo.InvariantCulture) + (p.Gzip ? ".gz" : ".bin");
                    ZipPut(z, name, ShipRun.Body(p), CompressionLevel.NoCompression);
                    files.Add(new JObj().Add("n", (long)p.N).Add("path", name).Add("encoding", p.Gzip ? "gzip" : "identity").Add("media", p.Media));
                }
                index.Add("parts", files);
                ZipPut(z, "bundle.json", Encoding.ASCII.GetBytes(TJson.Write(index) + "\n"), CompressionLevel.Optimal);
            }
            if (File.Exists(zipPath)) File.Delete(zipPath);
            File.Move(tmp, zipPath);
            return run.Parts.Count;
        }
        static void ZipPut(ZipArchive z, string name, byte[] data, CompressionLevel level)
        {
            ZipArchiveEntry e = z.CreateEntry(name, level);
            using (Stream s = e.Open()) s.Write(data, 0, data.Length);
        }
    }

    public static class ShipInfo { public static string Version = "2.6.0"; }
}
'@

#region ---------- Tideline shipping: shared by Invoke-WebInventory.ps1, Send-WebInventoryRun.ps1, Register-WebInventorySensor.ps1 ----------
function Get-TidelineDir {
    # where Register-WebInventorySensor.ps1 keeps the pinned root, the sensor record and (off Windows) the sensor PFX
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { Join-Path $env:ProgramData 'WebInventory' }
    else { Join-Path ([Environment]::GetFolderPath('UserProfile')) '.config/webinventory' }
}
function Get-TidelineDefault([string]$Name) {
    $p = Join-Path (Get-TidelineDir) $Name
    if (Test-Path -LiteralPath $p -PathType Leaf) { $p } else { $null }
}

function Initialize-ShipCode([string]$Version) {
    if ('WebInv.Shipper' -as [type]) {
        if ([WebInv.ShipInfo]::Version -ne $Version) { throw ("WebInv shipping code v{0} is already loaded in this PowerShell session (script is v{1}). Open a new PowerShell window." -f [WebInv.ShipInfo]::Version, $Version) }
        return
    }
    $addType = @{ TypeDefinition = $ShipSource; ErrorAction = 'Stop'; IgnoreWarnings = $true; WarningAction = 'SilentlyContinue' }
    if ($PSVersionTable.PSEdition -ne 'Core') {
        Add-Type -AssemblyName System.IO.Compression
        $addType.ReferencedAssemblies = @('System.Core', 'System.IO.Compression')
    }
    Add-Type @addType
    [WebInv.Https]::UserAgent = "WebInventory/$Version (authorized asset inventory)"
}

function Get-InnerMessage($ErrorRecord) {
    $x = if ($ErrorRecord -is [Exception]) { $ErrorRecord } else { $ErrorRecord.Exception }
    while ($x -is [System.Management.Automation.MethodInvocationException] -and $x.InnerException) { $x = $x.InnerException }
    $x.Message
}

function Test-EngagementId([string]$Id) { $Id -cmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' }

function ConvertTo-TidelineUri([string]$Url) {
    $u = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$u) -or $u.Scheme -ne 'https' -or -not $u.Host) { throw "'$Url' is not an https:// URL" }
    if ($u.UserInfo) { throw "'$Url': no credentials in the URL (the sensor certificate authenticates)" }
    if ($u.Query -or $u.Fragment) { throw "'$Url': no query or fragment" }
    $u
}

# the sensor certificate: a PFX (-ShipCertPath), one thumbprint, or the newest valid sensor certificate in the stores
function Resolve-ShipCert([string]$Thumbprint, [string]$Path, [string]$PasswordFile) {
    if ($Thumbprint -and $Path) { throw 'give the certificate thumbprint or the PFX path, not both' }
    if (-not $Thumbprint -and -not $Path -and [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { $Path = Get-TidelineDefault 'tideline-sensor.pfx' }
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "certificate file not found: $Path" }
        $pw = ''
        if ($PasswordFile) {
            if (-not (Test-Path -LiteralPath $PasswordFile -PathType Leaf)) { throw "password file not found: $PasswordFile" }
            $pw = ([IO.File]::ReadAllLines((Resolve-Path -LiteralPath $PasswordFile).ProviderPath) | Select-Object -First 1)
            if ($null -eq $pw) { $pw = '' }
        }
        $c = [WebInv.SensorCert]::LoadPfx((Resolve-Path -LiteralPath $Path).ProviderPath, $pw)
    }
    else {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'no sensor certificate: pass -ShipCertPath (a PFX), or enroll with Register-WebInventorySensor.ps1' }
        $err = ''
        $c = [WebInv.SensorCert]::Find($Thumbprint, [ref]$err)
        if (-not $c) { throw $err }
    }
    if (-not [WebInv.SensorCert]::SensorId($c)) { throw ("certificate {0} has no single {1}<id> name" -f $c.Thumbprint, [WebInv.SensorCert]::UrnPrefix) }
    $now = Get-Date
    if ($c.NotAfter -lt $now -or $c.NotBefore -gt $now) { throw ("certificate {0} is not valid now (valid {1:u} to {2:u})" -f $c.Thumbprint, $c.NotBefore, $c.NotAfter) }
    $c
}

function Resolve-ShipRoots([string]$CaFile) {
    if (-not $CaFile) { $CaFile = Get-TidelineDefault 'tideline-root.crt' }
    if (-not $CaFile) { throw ("no Tideline root CA: pass -ShipCaFile, or enroll with Register-WebInventorySensor.ps1 (it saves the root to {0})" -f (Join-Path (Get-TidelineDir) 'tideline-root.crt')) }
    if (-not (Test-Path -LiteralPath $CaFile -PathType Leaf)) { throw "CA file not found: $CaFile" }
    [WebInv.SensorCert]::LoadPem((Resolve-Path -LiteralPath $CaFile).ProviderPath)
}

# the run.json of a run folder or of any file of the run (newest run when a folder holds several)
function Get-RunJsonPaths([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { throw "not found: $Path" }
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) { return @(Get-ChildItem -LiteralPath $item.FullName -Filter 'WebInventory_*_run.json' -File | Sort-Object Name | ForEach-Object { $_.FullName }) }
    if ($item.Name -match '^WebInventory_(.+?)(?:_run\.json|\.jsonl|\.csv|_manifest\.txt|_progress\.txt|_ship-state\.json)$') {
        $rj = Join-Path $item.DirectoryName ('WebInventory_{0}_run.json' -f $Matches[1])
        if (Test-Path -LiteralPath $rj) { return @($rj) }
        throw "the run.json of $($item.Name) is missing ($rj)"
    }
    throw "$Path is not a run folder or a WebInventory run file"
}
#endregion

$onWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
function Write-Line([string]$Text, [string]$Color = 'Gray') { Write-Host $Text -ForegroundColor $Color }
function Stop-With([int]$Code, [string]$Text) { Write-Line $(if ($Code -eq 1) { "REFUSED: $Text" } else { "FAILED: $Text" }) 'Red'; exit $Code }
function Get-Inner($e) { Get-InnerMessage $e }
function ConvertFrom-B64Url([string]$S) { $t = $S.Replace('-', '+').Replace('_', '/'); switch ($t.Length % 4) { 2 { $t += '==' } 3 { $t += '=' } }; [Convert]::FromBase64String($t) }

try { Initialize-ShipCode $ScriptVersion } catch { Stop-With 1 "shipping code compile failed: $(Get-Inner $_)" }
$dir = Get-TidelineDir
$rootFile = Join-Path $dir 'tideline-root.crt'
$infoFile = Join-Path $dir 'tideline-sensor.json'
if (-not $PfxPath) { $PfxPath = Join-Path $dir 'tideline-sensor.pfx' }
if ($onWindows -and $PSBoundParameters.ContainsKey('PfxPath')) { Stop-With 1 '-PfxPath is for hosts without a Windows certificate store; on Windows the key stays in the machine key store' }
if ($GrantKeyAccess -and -not $onWindows) { Stop-With 1 '-GrantKeyAccess is for Windows (the PFX is readable by its owner only)' }
$timeout = $TimeoutSec * 1000

function Test-Admin { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }

function Get-CaBase([string]$Url) {
    $u = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$u) -or $u.Scheme -ne 'https') { throw "'$Url' is not an https:// CA URL" }
    $p = $u.AbsolutePath -replace '/1\.0/sign$', '' -replace '/$', ''
    [Uri]($u.GetLeftPart([UriPartial]::Authority) + $p + '/')
}

# a CA call; $Client = $null for enrollment, the current certificate for rekey (mutual TLS)
function Invoke-Ca([Uri]$Base, [string]$Method, [string]$Path, [string]$Json, $Client, $Roots) {
    $pin = New-Object WebInv.PinnedTls; $pin.Roots = $Roots
    $h = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    $body = $null
    if ($null -ne $Json) { $h['Content-Type'] = 'application/json'; $body = [Text.Encoding]::UTF8.GetBytes($Json) }
    $path = $Base.AbsolutePath.TrimEnd('/') + $Path
    [WebInv.Https]::Send($Base, $Method, $path, $h, $body, $Client, $pin, $timeout)
}
function Get-CaError($r) { $j = $r.Json; $m = if ($j -and $j.Str('message')) { $j.Str('message') } else { $r.Text.Trim() }; "HTTP {0}: {1}" -f $r.Status, $m }

# the root from the CA, accepted only when its SHA-256 is the fingerprint the token carries; then the CA's own TLS
# certificate must chain to it and name the host
function Get-PinnedRoot([Uri]$Base, [string]$Fingerprint) {
    $pin = New-Object WebInv.PinnedTls; $pin.Bootstrap = $true
    $r = [WebInv.Https]::Send($Base, 'GET', ($Base.AbsolutePath.TrimEnd('/') + '/root/' + $Fingerprint), $null, $null, $null, $pin, $timeout)
    if ($r.Status -ne 200) { throw ("fetching the root: {0}" -f (Get-CaError $r)) }
    $pem = $r.Json.Str('ca')
    if (-not $pem) { throw 'the CA answered without a root certificate' }
    $der = @([WebInv.SensorCert]::PemBlocks($pem, 'CERTIFICATE'))
    if ($der.Count -ne 1) { throw 'the CA answered with no single root certificate' }
    $fp = [WebInv.SensorCert]::Sha256Hex($der[0])
    if ($fp -ne $Fingerprint.ToLowerInvariant()) { throw "the root the CA sent has fingerprint $fp, the token names $Fingerprint" }
    $roots = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
    [void]$roots.Add((New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, [byte[]]$der[0])))
    $pin.Roots = $roots
    $why = ''
    if (-not $pin.Check([ref]$why)) { throw "the CA's TLS certificate does not check out against that root: $why" }
    $roots
}

function Save-TidelineFiles($Roots, [Uri]$Base, [string]$Sensor, $Cert) {
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        if (-not $onWindows) { [IO.File]::SetUnixFileMode($dir, [IO.UnixFileMode]'UserRead, UserWrite, UserExecute') }
    }
    [IO.File]::WriteAllText($rootFile, [WebInv.SensorCert]::Pem($Roots[0].RawData, 'CERTIFICATE'), (New-Object Text.UTF8Encoding($false)))
    $info = [ordered]@{ format = 1; caUrl = $Base.ToString().TrimEnd('/'); rootFingerprint = [WebInv.SensorCert]::Sha256Hex($Roots[0].RawData); sensor = $Sensor
        thumbprint = $Cert.Thumbprint; notBefore = $Cert.NotBefore.ToUniversalTime().ToString('o'); notAfter = $Cert.NotAfter.ToUniversalTime().ToString('o')
        store = $(if ($onWindows) { 'LocalMachine\My' } else { $PfxPath }); updated = (Get-Date).ToUniversalTime().ToString('o'); by = "Register-WebInventorySensor $ScriptVersion" }
    [IO.File]::WriteAllText($infoFile, ((ConvertTo-Json -InputObject $info) + "`n"), (New-Object Text.UTF8Encoding($false)))
}

# ---- Windows: certreq.exe makes a non-exportable ECDSA P-256 key in the machine key store ----
function New-WindowsRequest([string]$Subject, [string[]]$Sans, [string]$Work) {
    # the pending request (a placeholder certificate holding the new key) is found again by this friendly name
    $marker = 'Tideline sensor request ' + [guid]::NewGuid().ToString('N').Substring(0, 12)
    $script:PendingMarker = $marker
    $sanText = @(foreach ($s in $Sans) {
            $ip = $null
            if ($s -match '^[a-z][a-z0-9+.-]*:' -and $s -notmatch '@') { 'url={0}' -f $s }
            elseif ([Net.IPAddress]::TryParse($s, [ref]$ip)) { 'ipaddress={0}' -f $s }
            elseif ($s -match '@') { 'email={0}' -f $s }
            else { 'dns={0}' -f $s }
        })
    $inf = @('[Version]', 'Signature="$Windows NT$"', '', '[NewRequest]', ('Subject = "CN={0}"' -f $Subject),
        'KeyAlgorithm = ECDSA_P256', 'KeyLength = 256', 'HashAlgorithm = SHA256', 'MachineKeySet = TRUE', 'Exportable = FALSE',
        'ProviderName = "Microsoft Software Key Storage Provider"', 'KeyUsage = "CERT_DIGITAL_SIGNATURE_KEY_USAGE"', 'RequestType = PKCS10',
        'SMIME = FALSE', ('FriendlyName = "{0}"' -f $marker), '', '[EnhancedKeyUsageExtension]', 'OID = 1.3.6.1.5.5.7.3.2', '',
        '[Extensions]', '2.5.29.17 = "{text}"')
    foreach ($t in $sanText) { $inf += ('_continue_ = "{0}&"' -f $t) }
    $infPath = Join-Path $Work 'sensor.inf'; $reqPath = Join-Path $Work 'sensor.req'
    [IO.File]::WriteAllLines($infPath, [string[]]$inf, [Text.Encoding]::ASCII)
    $ErrorActionPreference = 'Continue'   # (Windows PowerShell 5.1: a stderr line of a native tool is otherwise terminating)
    $out = & certreq.exe -new -q -machine $infPath $reqPath 2>&1
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $reqPath)) { throw ("certreq -new failed ({0}): {1}" -f $LASTEXITCODE, (($out | Out-String) -replace '\s+', ' ').Trim()) }
    $b64 = ([IO.File]::ReadAllText($reqPath) -replace '-----[A-Z ]+-----', '' -replace '\s', '')
    @{ Pem = [WebInv.SensorCert]::Pem([Convert]::FromBase64String($b64), 'CERTIFICATE REQUEST'); Marker = $marker }
}
# the placeholder certreq left in LocalMachine\REQUEST; with -DeleteKey also its key (a request that was not issued)
function Remove-PendingRequest([string]$Marker, [switch]$DeleteKey) {
    $rq = New-Object Security.Cryptography.X509Certificates.X509Store('REQUEST', 'LocalMachine')
    try { $rq.Open('ReadWrite') } catch { return }
    try {
        foreach ($c in @($rq.Certificates | Where-Object { $_.FriendlyName -eq $Marker })) {
            $k = $null
            if ($DeleteKey) { try { $k = [WebInv.SensorCert]::PrivateKey($c) } catch { } }
            $rq.Remove($c)
            if ($k) { try { $k.Key.Delete() } catch { } finally { $k.Dispose() } }
        }
    }
    finally { $rq.Close() }
}
# certreq -accept would insist on a chain to a root in the machine's trust store, and the Tideline root is pinned, not
# trusted machine-wide. So the issued certificate goes into LocalMachine\My as it is, and certutil -repairstore binds it
# to the key certreq made (it finds the key by the certificate's public key).
function Install-WindowsCert([string]$LeafPem, [string[]]$ChainPem, [string]$Work, [string]$Marker) {
    $leaf = New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, [byte[]]@([WebInv.SensorCert]::PemBlocks($LeafPem, 'CERTIFICATE'))[0])
    # intermediates, so that Schannel sends the chain
    $ca = New-Object Security.Cryptography.X509Certificates.X509Store('CA', 'LocalMachine'); $ca.Open('ReadWrite')
    try { foreach ($p in $ChainPem) { foreach ($d in [WebInv.SensorCert]::PemBlocks($p, 'CERTIFICATE')) { $x = New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, [byte[]]$d); if ($x.Thumbprint -ne $leaf.Thumbprint -and $x.Subject -ne $x.Issuer) { $ca.Add($x) } } } } finally { $ca.Close() }
    $my = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine'); $my.Open('ReadWrite')
    try { $my.Add($leaf) } finally { $my.Close() }
    $c = $null; $log = @()
    foreach ($attempt in @(@(), @('-csp', 'Microsoft Software Key Storage Provider'))) {
        $ErrorActionPreference = 'Continue'
        $out = & certutil.exe -silent @attempt -repairstore my $leaf.SerialNumber 2>&1
        $rc = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        $log += ('certutil {0}-repairstore ({1}): {2}' -f $(if ($attempt.Count) { '-csp KSP ' } else { '' }), $rc, (($out | Out-String) -replace '\s+', ' ').Trim())
        $st = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine'); $st.Open('ReadOnly')
        try { $c = @($st.Certificates.Find('FindByThumbprint', $leaf.Thumbprint, $false))[0] } finally { $st.Close() }
        if ($c -and $c.HasPrivateKey) { break }
    }
    if (-not $c -or -not $c.HasPrivateKey) {
        $my = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine'); $my.Open('ReadWrite')
        try { foreach ($x in @($my.Certificates.Find('FindByThumbprint', $leaf.Thumbprint, $false))) { $my.Remove($x) } } finally { $my.Close() }
        throw ("the certificate {0} could not be bound to its key: {1}" -f $leaf.Thumbprint, ($log -join ' | '))
    }
    try { $c.FriendlyName = 'Tideline sensor ' + [WebInv.SensorCert]::SensorId($c) } catch { }
    Remove-PendingRequest $Marker
    $script:PendingMarker = $null
    $c
}
function Grant-Key($Cert, [string[]]$Accounts) {
    foreach ($a in @($Accounts | Where-Object { $_ })) {
        [WebInv.SensorCert]::GrantKeyRead($Cert, $a)
        Write-Line ("  key usable by {0}" -f $a)
    }
    if (@($Accounts | Where-Object { $_ }).Count) {
        $now = @([WebInv.SensorCert]::KeyReaders($Cert))
        foreach ($a in @($Accounts | Where-Object { $_ })) { if ($now -notcontains $a -and $now -notcontains ((New-Object Security.Principal.NTAccount($a)).Translate([Security.Principal.SecurityIdentifier]).Translate([Security.Principal.NTAccount]).Value)) { throw "the key's security descriptor does not list $a after the change (it lists: $($now -join ', '))" } }
    }
}
function Test-NotExportable($Cert) {
    try { [void]$Cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12); $false } catch { $true }
}
function Remove-WindowsCert($Cert) {
    $st = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine'); $st.Open('ReadWrite')
    try {
        $k = $null; try { $k = [WebInv.SensorCert]::PrivateKey($Cert) } catch { Write-Line ("  the previous key could not be opened to delete it: {0}" -f (Get-Inner $_)) 'Yellow' }
        $st.Remove($Cert)
        if ($k) { try { $k.Key.Delete() } finally { $k.Dispose() } }
    }
    finally { $st.Close() }
}

# ---- elsewhere: a key in memory, written with the certificate to a PFX readable by the owner only ----
function New-PortableRequest([string]$Subject, [string[]]$Sans) {
    $ec = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $req = [Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=$Subject", $ec, [Security.Cryptography.HashAlgorithmName]::SHA256)
    $b = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    foreach ($s in $Sans) {
        $ip = $null
        if ($s -match '^[a-z][a-z0-9+.-]*:' -and $s -notmatch '@') { $b.AddUri([Uri]$s) }
        elseif ([Net.IPAddress]::TryParse($s, [ref]$ip)) { $b.AddIpAddress($ip) }
        elseif ($s -match '@') { $b.AddEmailAddress($s) }
        else { $b.AddDnsName($s) }
    }
    $req.CertificateExtensions.Add($b.Build())
    @{ Key = $ec; Pem = [WebInv.SensorCert]::Pem($req.CreateSigningRequest(), 'CERTIFICATE REQUEST') }
}
function Save-Pfx($Key, [string]$LeafPem, [string[]]$ChainPem) {
    $leaf = [Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]@([WebInv.SensorCert]::PemBlocks($LeafPem, 'CERTIFICATE'))[0])
    $with = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($leaf, $Key)
    $col = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    [void]$col.Add($with)
    foreach ($p in $ChainPem) { foreach ($d in [WebInv.SensorCert]::PemBlocks($p, 'CERTIFICATE')) { $x = [Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$d); if ($x.Thumbprint -ne $leaf.Thumbprint -and $x.Subject -ne $x.Issuer) { [void]$col.Add($x) } } }
    $bytes = $col.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, '')
    $pdir = Split-Path -Parent $PfxPath
    if (-not (Test-Path -LiteralPath $pdir)) { New-Item -ItemType Directory -Path $pdir -Force | Out-Null; [IO.File]::SetUnixFileMode($pdir, [IO.UnixFileMode]'UserRead, UserWrite, UserExecute') }
    $tmp = $PfxPath + '.new'
    [IO.File]::WriteAllBytes($tmp, [byte[]]@()); [IO.File]::SetUnixFileMode($tmp, [IO.UnixFileMode]'UserRead, UserWrite')
    [IO.File]::WriteAllBytes($tmp, $bytes)
    if ($KeepPrevious -and (Test-Path -LiteralPath $PfxPath)) { Copy-Item -LiteralPath $PfxPath -Destination ($PfxPath + '.previous') -Force }
    Move-Item -LiteralPath $tmp -Destination $PfxPath -Force
    [WebInv.SensorCert]::LoadPfx($PfxPath, '')
}

function Show-Cert($C, [string]$Where) {
    Write-Line ("  {0}  sensor {1}  {2}  valid {3:u} to {4:u}  {5}" -f $C.Thumbprint, [WebInv.SensorCert]::SensorId($C), $C.Subject, $C.NotBefore, $C.NotAfter, $Where)
}

# ======================================================================== -Show
if ($PSCmdlet.ParameterSetName -eq 'Show') {
    Write-Line ("Tideline sensor files: {0}" -f $dir) 'Cyan'
    if (Test-Path -LiteralPath $infoFile) { Get-Content -LiteralPath $infoFile | ForEach-Object { Write-Line "  $_" } } else { Write-Line '  (not enrolled: no tideline-sensor.json)' }
    if (Test-Path -LiteralPath $rootFile) { $r = [WebInv.SensorCert]::LoadPem($rootFile)[0]; Write-Line ("Pinned root: {0} (sha256 {1})" -f $r.Subject, [WebInv.SensorCert]::Sha256Hex($r.RawData)) }
    Write-Line 'Sensor certificates:' 'Cyan'
    if ($onWindows) {
        foreach ($loc in 'LocalMachine', 'CurrentUser') {
            $st = New-Object Security.Cryptography.X509Certificates.X509Store('My', $loc); $st.Open('ReadOnly')
            try { foreach ($c in $st.Certificates) { if ([WebInv.SensorCert]::SensorId($c)) { Show-Cert $c ("$loc\My" + $(if ($c.HasPrivateKey) { '' } else { ' (no key)' })) } } } finally { $st.Close() }
        }
    }
    elseif (Test-Path -LiteralPath $PfxPath) { Show-Cert ([WebInv.SensorCert]::LoadPfx($PfxPath, '')) $PfxPath }
    exit 0
}

if ($onWindows -and -not (Test-Admin)) { Stop-With 1 'run from an elevated PowerShell: the key and certificate go to the machine store (LocalMachine\My)' }
$work = Join-Path ([IO.Path]::GetTempPath()) ('wi-sensor-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
    # ==================================================================== enroll
    if ($PSCmdlet.ParameterSetName -eq 'Enroll') {
        $parts = $Token.Trim().Split('.')
        if ($parts.Count -ne 3) { Stop-With 1 'the token is not a JWT (three dot-separated parts)' }
        try { $claims = [Text.Encoding]::UTF8.GetString((ConvertFrom-B64Url $parts[1])) | ConvertFrom-Json } catch { Stop-With 1 "the token payload is not readable: $(Get-Inner $_)" }
        $exp = [DateTimeOffset]::FromUnixTimeSeconds([long]$claims.exp)
        if ($exp -lt [DateTimeOffset]::UtcNow) { Stop-With 1 ("the token expired at {0:u}; ask for a new one (tokens are valid for five minutes)" -f $exp.UtcDateTime) }
        $sans = @($claims.sans | Where-Object { $_ })
        $urns = @($sans | Where-Object { $_ -like "$([WebInv.SensorCert]::UrnPrefix)*" })
        if ($urns.Count -ne 1) { Stop-With 1 ("the token must name exactly one {0}<id> (it names: {1}); make it with --san {0}<id>" -f [WebInv.SensorCert]::UrnPrefix, ($sans -join ', ')) }
        $sensor = $urns[0].Substring([WebInv.SensorCert]::UrnPrefix.Length)
        if (-not [WebInv.SensorCert]::ValidId($sensor)) { Stop-With 1 "sensor id '$sensor': letters, digits, '.', '_' and '-', up to 64" }
        $sub = [string]$claims.sub
        if (-not $sub -or $sub -match '["=,+;<>\\]') { Stop-With 1 "the token subject '$sub' cannot be a certificate subject" }
        $fp = [string]$claims.sha
        if ($fp -notmatch '^[0-9a-fA-F]{64}$') { Stop-With 1 'the token carries no root fingerprint (sha); make it with step ca token' }
        try { $base = Get-CaBase $(if ($CaUrl) { $CaUrl } else { [string]$claims.aud }) } catch { Stop-With 1 (Get-Inner $_) }
        Write-Line ("Enrolling sensor {0} with {1} (token for {2}, expires {3:u})" -f $sensor, $base, $sub, $exp.UtcDateTime) 'Cyan'
        try { $roots = Get-PinnedRoot $base $fp } catch { Stop-With 2 (Get-Inner $_) }
        Write-Line ("  root {0} matches the token's fingerprint; the CA's certificate chains to it" -f $roots[0].Subject)
        $req = if ($onWindows) { New-WindowsRequest $sub $sans $work } else { New-PortableRequest $sub $sans }
        $body = [ordered]@{ csr = $req.Pem; ott = $Token.Trim() }
        if ($NotAfter) { $body.notAfter = $NotAfter }
        try { $r = Invoke-Ca $base 'POST' '/1.0/sign' (ConvertTo-Json -InputObject $body -Compress) $null $roots } catch { Stop-With 2 (Get-Inner $_) }
        if ($r.Status -ne 201 -and $r.Status -ne 200) { Stop-With 2 ("the CA refused the request: {0}" -f (Get-CaError $r)) }
        $j = $r.Json
        $chain = @(); $cc = $j.Arr('certChain'); if ($cc) { $chain = @($cc | ForEach-Object { [string]$_ }) } elseif ($j.Str('ca')) { $chain = @($j.Str('ca')) }
        if ($onWindows) {
            $cert = Install-WindowsCert $j.Str('crt') $chain $work $req.Marker
            Grant-Key $cert $GrantKeyAccess
            Write-Line ("  key: ECDSA P-256 in the machine key store, {0}" -f $(if (Test-NotExportable $cert) { 'not exportable' } else { 'EXPORTABLE (unexpected)' }))
            $where = 'LocalMachine\My'
        }
        else { $cert = Save-Pfx $req.Key $j.Str('crt') $chain; $where = $PfxPath }
        Save-TidelineFiles $roots $base $sensor $cert
        Write-Line ("Enrolled: sensor {0}, certificate {1} in {2}, valid until {3:u}" -f $sensor, $cert.Thumbprint, $where, $cert.NotAfter) 'Green'
        Write-Line ("  pinned root: {0}" -f $rootFile)
        Write-Line '  renew daily from a scheduled task: Register-WebInventorySensor.ps1 -Renew'
        exit 0
    }

    # ==================================================================== renew
    if (-not (Test-Path -LiteralPath $infoFile) -or -not (Test-Path -LiteralPath $rootFile)) { Stop-With 1 "not enrolled here ($infoFile / $rootFile missing): enroll with -Token first" }
    $info = Get-Content -Raw -LiteralPath $infoFile | ConvertFrom-Json
    $roots = [WebInv.SensorCert]::LoadPem($rootFile)
    try { $base = Get-CaBase $(if ($CaUrl) { $CaUrl } else { [string]$info.caUrl }) } catch { Stop-With 1 (Get-Inner $_) }
    if ($onWindows) { $err = ''; $old = [WebInv.SensorCert]::Find($Thumbprint, [ref]$err); if (-not $old) { Stop-With 1 $err } }
    else { if (-not (Test-Path -LiteralPath $PfxPath)) { Stop-With 1 "no sensor certificate at $PfxPath" }; $old = [WebInv.SensorCert]::LoadPfx($PfxPath, '') }
    $sensor = [WebInv.SensorCert]::SensorId($old)
    $life = ($old.NotAfter - $old.NotBefore).TotalSeconds
    $left = ($old.NotAfter - (Get-Date)).TotalSeconds
    if ($left -le 0) { Stop-With 1 ("certificate {0} expired at {1:u}; it cannot renew. Enroll again with a new token." -f $old.Thumbprint, $old.NotAfter) }
    if (-not $Force -and $left -gt $life / 3) { Write-Line ("Sensor {0}: certificate {1} valid until {2:u}; renewal due after {3:u} (-Force renews now)" -f $sensor, $old.Thumbprint, $old.NotAfter, $old.NotAfter.AddSeconds(-$life / 3)) 'Cyan'; exit 0 }
    Write-Line ("Renewing sensor {0} (certificate {1}, valid until {2:u}) with a new key at {3}" -f $sensor, $old.Thumbprint, $old.NotAfter, $base) 'Cyan'
    $cn = if ($old.Subject -match 'CN=([^,]+)') { $Matches[1] } else { $sensor }
    $sans = @([WebInv.SensorCert]::Uris($old))
    $req = if ($onWindows) { New-WindowsRequest $cn $sans $work } else { New-PortableRequest $cn $sans }
    try { $r = Invoke-Ca $base 'POST' '/1.0/rekey' (ConvertTo-Json -InputObject ([ordered]@{ csr = $req.Pem }) -Compress) $old $roots } catch { Stop-With 2 (Get-Inner $_) }
    if ($r.Status -ne 201 -and $r.Status -ne 200) { Stop-With 2 ("the CA refused the renewal: {0}" -f (Get-CaError $r)) }
    $j = $r.Json
    $chain = @(); $cc = $j.Arr('certChain'); if ($cc) { $chain = @($cc | ForEach-Object { [string]$_ }) } elseif ($j.Str('ca')) { $chain = @($j.Str('ca')) }
    if ($onWindows) {
        $cert = Install-WindowsCert $j.Str('crt') $chain $work $req.Marker
        $grant = @($GrantKeyAccess | Where-Object { $_ })   # (@($null) would count 1)
        if (-not $grant.Count) {
            # the accounts that could use the previous key keep that right on the new one
            $was = @(); try { $was = @([WebInv.SensorCert]::KeyReaders($old)) } catch { Write-Line ("  the previous key's readers could not be read: {0}" -f (Get-Inner $_)) 'Yellow' }
            $already = @(); try { $already = @([WebInv.SensorCert]::KeyReaders($cert)) } catch { }
            $grant = @($was | Where-Object { $already -notcontains $_ })
        }
        Grant-Key $cert $grant
        $where = 'LocalMachine\My'
    }
    else { $cert = Save-Pfx $req.Key $j.Str('crt') $chain; $where = $PfxPath }
    if ([WebInv.SensorCert]::SensorId($cert) -ne $sensor) { Stop-With 2 ("the renewed certificate names sensor {0}, not {1}; it was installed but not used ({2})" -f [WebInv.SensorCert]::SensorId($cert), $sensor, $cert.Thumbprint) }
    if ($onWindows -and -not $KeepPrevious) { Remove-WindowsCert $old; Write-Line ("  previous certificate {0} and its key removed" -f $old.Thumbprint) }
    Save-TidelineFiles $roots $base $sensor $cert
    Write-Line ("Renewed: sensor {0}, certificate {1} in {2}, valid until {3:u}" -f $sensor, $cert.Thumbprint, $where, $cert.NotAfter) 'Green'
    exit 0
}
finally {
    # a request that was never issued leaves no placeholder or key behind
    if ($onWindows -and $script:PendingMarker) { Remove-PendingRequest $script:PendingMarker -DeleteKey }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
