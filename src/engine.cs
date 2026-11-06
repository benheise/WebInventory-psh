// ============================================================================
// WebInv engine - C# 5 / .NET Framework 4.7.2 compatible (also runs on .NET 8)
// Sockets, HTTP read, raw TLS ClientHello probing, DER helpers, hashing,
// fingerprint rule engine. No external dependencies.
// ============================================================================
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace WebInv
{
    // ------------------------------------------------------------------ HTTP / TCP
    public class RawResponse
    {
        public string State;
        public bool TlsOk;
        public string TlsError;
        public string TlsProtocol;
        public string Cipher;
        public int CipherBits;
        public string Hash;
        public string KeyExchange;
        public X509Certificate2 Cert;
        public string CertPolicyErrors;
        public string ChainStatus;
        public byte[] Raw = new byte[0];
        public bool ServerFirst;
        public string Error;
        public long Ms;
        public long ConnectMs;
        public long BytesIn;        // bytes received from the server (TLS: including handshake records)
        public bool TimedOut;       // the last read ended on the receive timeout (silence), not on close/reset
    }

    // Counts bytes read through it (lets the caller tell a silent listener from one that answered and then failed)
    public class CountingStream : Stream
    {
        readonly Stream inner;
        public long BytesRead;
        public CountingStream(Stream inner) { this.inner = inner; }
        public override bool CanRead { get { return inner.CanRead; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return inner.CanWrite; } }
        public override bool CanTimeout { get { return inner.CanTimeout; } }
        public override int ReadTimeout { get { return inner.ReadTimeout; } set { inner.ReadTimeout = value; } }
        public override int WriteTimeout { get { return inner.WriteTimeout; } set { inner.WriteTimeout = value; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override void Flush() { inner.Flush(); }
        public override int Read(byte[] buffer, int offset, int count) { int n = inner.Read(buffer, offset, count); if (n > 0) BytesRead += n; return n; }
        public override void Write(byte[] buffer, int offset, int count) { inner.Write(buffer, offset, count); }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
    }

    public static class Net
    {
        // Connect scan semantics (nmap -sT): RST => closed; timeout/unreachable => filtered.
        // Non-blocking connect + Socket.Select on the calling thread: no thread-pool completion is involved, so a busy or
        // starved thread pool can never turn a fast RST into a false "filtered" (seen with BeginConnect at high rates).
        public static bool SelectConnect = true;   // false = legacy BeginConnect path (benchmark A/B only)
        public static long LocalWaits;             // connects delayed by local socket exhaustion (ephemeral ports / buffers)
        public static long LocalFailures;          // connects that still could not get a local socket after backing off

        // Running out of local ephemeral ports or socket buffers is a scanner-side condition, not a property of the
        // target: back off and retry instead of reporting the port as filtered; give up as "error" (resumable).
        static bool IsLocalExhaustion(SocketError e)
        {
            return e == SocketError.AddressAlreadyInUse || e == SocketError.AddressNotAvailable || e == SocketError.NoBufferSpaceAvailable || e == SocketError.TooManyOpenSockets;
        }

        // HTTP CONNECT proxy (scanning from a jump host): when set, every TCP connection of every probe is a tunnel
        // through the proxy and the port state comes from the proxy's answer (see ConnectViaProxy).
        public static string ProxyIp;               // proxy address (resolved once, before the scan)
        public static int ProxyPort;
        public static string ProxyAuthorization;    // "Basic ..." or null
        public static long ProxyRefusals;           // CONNECTs the proxy refused by policy/authentication (state "error")
        public static string ProxyLastRefusal = "";

        public static TcpClient Connect(string ip, int port, int timeoutMs, out string state)
        {
            if (ProxyIp != null) return ConnectViaProxy(ip, port, timeoutMs, out state);
            return ConnectDirect(ip, port, timeoutMs, out state);
        }

        static TcpClient ConnectDirect(string ip, int port, int timeoutMs, out string state)
        {
            IPAddress addr;
            if (!SelectConnect || !IPAddress.TryParse(ip, out addr)) return ConnectAsyncWait(ip, port, timeoutMs, out state);
            for (int attempt = 0; ; attempt++)
            {
                SocketError local;
                TcpClient c = ConnectOnce(addr, port, timeoutMs, out state, out local);
                if (state != "local") return c;
                if (attempt >= 8) { System.Threading.Interlocked.Increment(ref LocalFailures); state = "error"; return null; }
                System.Threading.Interlocked.Increment(ref LocalWaits);
                System.Threading.Thread.Sleep(250 * (attempt + 1));
            }
        }

        // CONNECT ip:port through the proxy. 200 => open (the socket is returned positioned after the proxy's header);
        // 502/503 => closed (or filtered when Squid's X-Squid-Error carries ETIMEDOUT/EHOSTUNREACH); 504 or no answer
        // within the timeout => filtered; 400/403/405/407 and anything else => "error" (refused by the proxy, never
        // recorded as a port state, so -Resume retries it). The proxy itself unreachable => "error".
        static TcpClient ConnectViaProxy(string ip, int port, int timeoutMs, out string state)
        {
            Stopwatch sw = Stopwatch.StartNew();
            string pst;
            TcpClient c = ConnectDirect(ProxyIp, ProxyPort, timeoutMs, out pst);
            if (c == null) { state = "error"; NoteRefusal("proxy " + ProxyIp + ":" + ProxyPort + " not reachable (" + pst + ")"); return null; }
            try
            {
                int left = (int)Math.Max(200, timeoutMs - sw.ElapsedMilliseconds);
                c.ReceiveTimeout = left; c.SendTimeout = left;
                string target = (ip.IndexOf(':') >= 0 ? "[" + ip + "]" : ip) + ":" + port.ToString(System.Globalization.CultureInfo.InvariantCulture);
                StringBuilder rq = new StringBuilder();
                rq.Append("CONNECT ").Append(target).Append(" HTTP/1.1\r\nHost: ").Append(target).Append("\r\n");
                if (ProxyAuthorization != null) rq.Append("Proxy-Authorization: ").Append(ProxyAuthorization).Append("\r\n");
                rq.Append("\r\n");
                byte[] b = Encoding.ASCII.GetBytes(rq.ToString());
                NetworkStream ns = c.GetStream();
                ns.Write(b, 0, b.Length);
                // read the header byte by byte: anything after it belongs to the tunnelled service
                StringBuilder hdr = new StringBuilder();
                int one;
                while (hdr.Length < 16384)
                {
                    try { one = ns.ReadByte(); }
                    catch (IOException) { state = "filtered"; SafeClose(c); return null; }   // proxy still waiting on the target
                    if (one < 0) break;
                    hdr.Append((char)one);
                    if (hdr.Length >= 4 && hdr[hdr.Length - 1] == '\n' && hdr.ToString(hdr.Length - 4, 4) == "\r\n\r\n") break;
                }
                string h = hdr.ToString();
                Match m = Regex.Match(h, @"^HTTP/1\.[01] (\d{3})");
                if (!m.Success) { state = "error"; NoteRefusal("proxy answered " + (h.Length == 0 ? "nothing" : "'" + h.Split('\r')[0] + "'") + " to CONNECT " + target); SafeClose(c); return null; }
                int code = int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
                if (code == 200) { c.ReceiveTimeout = 0; c.SendTimeout = 0; state = "open"; return c; }
                SafeClose(c);
                if (code == 502 || code == 503)
                {
                    Match sq = Regex.Match(h, @"(?im)^X-Squid-Error:\s*\S+\s+(\d+)");
                    int errno = sq.Success ? int.Parse(sq.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture) : 0;
                    state = (errno == 110 || errno == 113 || errno == 101 || errno == 10060 || errno == 10065) ? "filtered" : "closed";
                    return null;
                }
                if (code == 504) { state = "filtered"; return null; }
                state = "error";
                NoteRefusal("proxy refused CONNECT " + target + ": " + h.Split('\r')[0]);
                return null;
            }
            catch (Exception ex) { state = "error"; NoteRefusal("proxy CONNECT failed: " + Flatten(ex)); SafeClose(c); return null; }
        }
        static void NoteRefusal(string why) { System.Threading.Interlocked.Increment(ref ProxyRefusals); ProxyLastRefusal = why; }

        static TcpClient ConnectOnce(IPAddress addr, int port, int timeoutMs, out string state, out SocketError local)
        {
            local = SocketError.Success;
            Socket s;
            try { s = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp); }
            catch (SocketException se) { local = se.SocketErrorCode; state = IsLocalExhaustion(se.SocketErrorCode) ? "local" : "error"; return null; }
            try
            {
                s.NoDelay = true;
                s.Blocking = false;
                try { s.Connect(new IPEndPoint(addr, port)); }
                catch (SocketException se)
                {
                    if (se.SocketErrorCode != SocketError.WouldBlock && se.SocketErrorCode != SocketError.InProgress && se.SocketErrorCode != SocketError.AlreadyInProgress)
                    {
                        local = se.SocketErrorCode;
                        state = IsLocalExhaustion(se.SocketErrorCode) ? "local" : se.SocketErrorCode == SocketError.ConnectionRefused ? "closed" : "filtered";
                        s.Close(); return null;
                    }
                    System.Collections.ArrayList w = new System.Collections.ArrayList(), e = new System.Collections.ArrayList();
                    w.Add(s); e.Add(s);
                    Socket.Select(null, w, e, (int)Math.Min(int.MaxValue, Math.Max(1, timeoutMs) * 1000L));
                    if (w.Count == 0 && e.Count == 0) { state = "filtered"; s.Close(); return null; }   // no answer within the timeout
                    int err = (int)s.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Error);
                    if (err != 0 || e.Count > 0)
                    {
                        state = (err == (int)SocketError.ConnectionRefused || err == 111 || err == 61) ? "closed"
                              : IsLocalExhaustion((SocketError)err) || err == 99 || err == 98 ? "local" : "filtered";
                        s.Close(); return null;
                    }
                }
                s.Blocking = true;
                TcpClient c = new TcpClient(addr.AddressFamily);
                Socket orig = c.Client;
                c.Client = s;
                try { orig.Close(); } catch { }
                state = "open";
                return c;
            }
            catch (SocketException se)
            {
                local = se.SocketErrorCode;
                state = IsLocalExhaustion(se.SocketErrorCode) ? "local" : "filtered";
                try { s.Close(); } catch { }
                return null;
            }
            catch (Exception)
            {
                state = "filtered";
                try { s.Close(); } catch { }
                return null;
            }
        }

        static TcpClient ConnectAsyncWait(string ip, int port, int timeoutMs, out string state)
        {
            IPAddress addr;
            AddressFamily fam = AddressFamily.InterNetwork;
            if (IPAddress.TryParse(ip, out addr)) fam = addr.AddressFamily;
            TcpClient c = new TcpClient(fam);
            c.NoDelay = true;
            try
            {
                IAsyncResult ar = c.BeginConnect(ip, port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) { state = "filtered"; SafeClose(c); return null; }
                c.EndConnect(ar);
                state = "open";
                return c;
            }
            catch (SocketException se)
            {
                state = (se.SocketErrorCode == SocketError.ConnectionRefused) ? "closed" : "filtered";
                SafeClose(c);
                return null;
            }
            catch (Exception)
            {
                state = "filtered";
                SafeClose(c);
                return null;
            }
        }

        public static void SafeClose(TcpClient c) { try { if (c != null) c.Close(); } catch { } }

        public static RawResponse Probe(string ip, int port, bool tls, string sni, byte[] request,
                                        int timeoutMs, int maxBytes, int sslProtocols, int bannerWaitMs)
        {
            RawResponse r = new RawResponse();
            Stopwatch sw = Stopwatch.StartNew();
            string st;
            TcpClient c = Connect(ip, port, timeoutMs, out st);
            r.State = st;
            r.ConnectMs = sw.ElapsedMilliseconds;
            if (c == null) { r.Ms = sw.ElapsedMilliseconds; return r; }
            try
            {
                c.ReceiveTimeout = timeoutMs;
                c.SendTimeout = timeoutMs;
                Stream s = c.GetStream();
                CountingStream counted = null;
                if (!tls && bannerWaitMs > 0)
                {
                    // nmap-style NULL probe: speak-first services (SSH/FTP/SMTP/MySQL...) send a banner unprompted
                    if (c.Client.Poll(bannerWaitMs * 1000, SelectMode.SelectRead) && c.Client.Available > 0)
                    {
                        r.ServerFirst = true;
                        r.Raw = ReadBanner(s, c, 4096, timeoutMs);
                        r.Ms = sw.ElapsedMilliseconds;
                        return r;
                    }
                }
                if (tls)
                {
                    X509Certificate2 captured = null; string pol = null; string chainSt = null;
                    counted = new CountingStream(s);
                    // Per-connection callback: accept any certificate FOR INVENTORY ONLY, record it and its policy errors.
                    SslStream ssl = new SslStream(counted, false, delegate(object o, X509Certificate cert, X509Chain ch, SslPolicyErrors e)
                    {
                        try
                        {
                            if (cert != null) captured = new X509Certificate2(cert);
                            pol = e.ToString();
                            if (ch != null && ch.ChainStatus != null)
                            {
                                StringBuilder sb = new StringBuilder();
                                foreach (X509ChainStatus cs in ch.ChainStatus)
                                {
                                    if (cs.Status == X509ChainStatusFlags.NoError) continue;
                                    if (sb.Length > 0) sb.Append(',');
                                    sb.Append(cs.Status.ToString());
                                }
                                chainSt = sb.ToString();
                            }
                        }
                        catch { }
                        return true;
                    });
                    try { ssl.AuthenticateAsClient(sni, null, (SslProtocols)sslProtocols, false); }
                    catch (Exception ex)
                    {
                        r.TlsError = Flatten(ex); r.Cert = captured; r.CertPolicyErrors = pol; r.ChainStatus = chainSt;
                        r.TimedOut = IsTimeout(ex); r.BytesIn = counted.BytesRead;
                        r.Ms = sw.ElapsedMilliseconds; SafeClose(c); return r;
                    }
                    r.TlsOk = true; r.Cert = captured; r.CertPolicyErrors = pol; r.ChainStatus = chainSt;
                    r.TlsProtocol = ProtoName((int)ssl.SslProtocol);
                    try
                    {
                        r.Cipher = ssl.CipherAlgorithm.ToString(); r.CipherBits = ssl.CipherStrength;
                        r.Hash = ssl.HashAlgorithm.ToString(); r.KeyExchange = ssl.KeyExchangeAlgorithm.ToString();
                    }
                    catch { }
                    s = ssl;
                }
                s.Write(request, 0, request.Length);
                s.Flush();
                bool to; long got;
                r.Raw = Read(s, maxBytes, timeoutMs, sw, out to, out got);
                r.TimedOut = to; r.BytesIn += got;
                if (counted != null) r.BytesIn = counted.BytesRead;
            }
            catch (Exception ex) { r.Error = Flatten(ex); }
            finally { SafeClose(c); }
            r.Ms = sw.ElapsedMilliseconds;
            return r;
        }

        public static string ProtoName(int p)
        {
            switch (p)
            {
                case 12288: return "TLS1.3";
                case 3072: return "TLS1.2";
                case 768: return "TLS1.1";
                case 192: return "TLS1.0";
                case 48: return "SSL3";
                case 12: return "SSL2";
                default: return p.ToString();
            }
        }

        static byte[] ReadBanner(Stream s, TcpClient c, int maxBytes, int timeoutMs)
        {
            MemoryStream ms = new MemoryStream();
            byte[] buf = new byte[4096];
            try
            {
                int n = s.Read(buf, 0, buf.Length);
                if (n > 0) ms.Write(buf, 0, n);
                // multi-line banners (FTP "220-") arrive in pieces; give them a moment
                Stopwatch sw = Stopwatch.StartNew();
                while (ms.Length < maxBytes && sw.ElapsedMilliseconds < Math.Min(750, timeoutMs))
                {
                    if (!c.Client.Poll(150 * 1000, SelectMode.SelectRead) || c.Client.Available == 0) break;
                    n = s.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    ms.Write(buf, 0, n);
                }
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
            catch (SocketException) { }
            return ms.ToArray();
        }

        static byte[] Read(Stream s, int maxBytes, int timeoutMs, Stopwatch sw, out bool timedOut, out long got)
        {
            MemoryStream ms = new MemoryStream();
            byte[] buf = new byte[16384];
            long deadline = sw.ElapsedMilliseconds + timeoutMs * 3L;
            timedOut = false;
            try
            {
                while (ms.Length < maxBytes && sw.ElapsedMilliseconds < deadline)
                {
                    int n = s.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    ms.Write(buf, 0, n);
                    if (Complete(ms.GetBuffer(), (int)ms.Length)) break;
                }
            }
            catch (IOException ex) { timedOut = IsTimeout(ex); }
            catch (ObjectDisposedException) { }
            catch (SocketException ex) { timedOut = ex.SocketErrorCode == SocketError.TimedOut; }
            got = ms.Length;
            byte[] all = ms.ToArray();
            if (all.Length > maxBytes) Array.Resize(ref all, maxBytes);
            return all;
        }

        public static int HeaderEnd(byte[] b, int len)
        {
            for (int i = 0; i + 3 < len; i++)
                if (b[i] == 13 && b[i + 1] == 10 && b[i + 2] == 13 && b[i + 3] == 10) return i;
            return -1;
        }

        static bool Complete(byte[] b, int len)
        {
            if (len < 5) return false;
            if (!(b[0] == 'H' && b[1] == 'T' && b[2] == 'T' && b[3] == 'P')) return true;   // non-HTTP: stop after first chunk
            int he = HeaderEnd(b, len);
            if (he < 0) return false;
            string head = Encoding.ASCII.GetString(b, 0, he).ToLowerInvariant();
            int bodyLen = len - (he + 4);
            // 1xx/204/304 have no body
            if (head.Length > 12 && (head.Substring(9, 3) == "204" || head.Substring(9, 3) == "304")) return true;
            int ci = head.IndexOf("\ncontent-length:");
            if (ci >= 0)
            {
                int eol = head.IndexOf('\r', ci + 1); if (eol < 0) eol = head.Length;
                long cl;
                if (long.TryParse(head.Substring(ci + 16, eol - ci - 16).Trim(), out cl)) return bodyLen >= cl;
            }
            if (head.Contains("transfer-encoding: chunked") || head.Contains("transfer-encoding:chunked"))
                return len >= 5 && b[len - 5] == '0' && b[len - 4] == 13 && b[len - 3] == 10 && b[len - 2] == 13 && b[len - 1] == 10;
            return false;
        }

        public static byte[] Body(byte[] raw, out string head)
        {
            Encoding latin1 = Encoding.GetEncoding(28591);
            int he = HeaderEnd(raw, raw.Length);
            if (he < 0) { head = latin1.GetString(raw); return new byte[0]; }
            head = latin1.GetString(raw, 0, he);
            byte[] body = new byte[raw.Length - he - 4];
            Buffer.BlockCopy(raw, he + 4, body, 0, body.Length);
            string lh = head.ToLowerInvariant();
            if (lh.Contains("transfer-encoding: chunked") || lh.Contains("transfer-encoding:chunked")) body = Dechunk(body);
            if (lh.Contains("content-encoding: gzip") || lh.Contains("content-encoding:gzip"))
            {
                try
                {
                    using (GZipStream gz = new GZipStream(new MemoryStream(body), CompressionMode.Decompress))
                    using (MemoryStream o = new MemoryStream()) { gz.CopyTo(o); body = o.ToArray(); }
                }
                catch { }
            }
            return body;
        }

        static byte[] Dechunk(byte[] b)
        {
            MemoryStream ms = new MemoryStream();
            int i = 0;
            while (i < b.Length)
            {
                int eol = -1;
                for (int j = i; j < b.Length - 1; j++) if (b[j] == 13 && b[j + 1] == 10) { eol = j; break; }
                if (eol < 0) break;
                string line = Encoding.ASCII.GetString(b, i, eol - i);
                int semi = line.IndexOf(';'); if (semi >= 0) line = line.Substring(0, semi);
                int size;
                if (!int.TryParse(line.Trim(), System.Globalization.NumberStyles.HexNumber, null, out size)) break;
                i = eol + 2;
                if (size == 0) break;
                int n = Math.Min(size, b.Length - i);
                if (n <= 0) break;
                ms.Write(b, i, n);
                i += n + 2;
            }
            return ms.ToArray();
        }

        public static bool IsTimeout(Exception ex)
        {
            for (Exception e = ex; e != null; e = e.InnerException)
            {
                SocketException se = e as SocketException;
                if (se != null && se.SocketErrorCode == SocketError.TimedOut) return true;
                if (e is TimeoutException) return true;
            }
            return false;
        }

        public static string Flatten(Exception ex)
        {
            StringBuilder sb = new StringBuilder();
            while (ex != null)
            {
                if (sb.Length > 0) sb.Append(" -> ");
                sb.Append(ex.GetType().Name + ": " + ex.Message);
                ex = ex.InnerException;
            }
            return sb.ToString();
        }

        // ---- DNS (parallel, bounded, with timeout) ----
        // Sliding window: up to `parallel` lookups in flight; each name gets its own timeout from its own start, and a
        // slow name no longer holds back the rest of a batch.
        public static Func<string, Task<IPAddress[]>> Resolver;   // test hook; null = Dns.GetHostAddressesAsync
        public static bool SlidingDns = true;                       // false = legacy fixed batches (benchmark A/B only)
        public static Dictionary<string, string[]> ResolveMany(string[] names, int timeoutMs, int parallel, Dictionary<string, string> errors)
        {
            if (!SlidingDns) return ResolveBatched(names, timeoutMs, parallel, errors);
            Dictionary<string, string[]> res = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            if (parallel < 1) parallel = 1;
            Stopwatch sw = Stopwatch.StartNew();
            List<Task<IPAddress[]>> live = new List<Task<IPAddress[]>>();
            List<string> liveName = new List<string>();
            List<long> liveDue = new List<long>();
            int next = 0;
            while (next < names.Length || live.Count > 0)
            {
                while (live.Count < parallel && next < names.Length)
                {
                    string nm = names[next++];
                    Task<IPAddress[]> t;
                    try { t = Resolver != null ? Resolver(nm) : Dns.GetHostAddressesAsync(nm); }
                    catch (Exception ex) { errors[nm] = Flatten(ex); continue; }
                    live.Add(t); liveName.Add(nm); liveDue.Add(sw.ElapsedMilliseconds + timeoutMs);
                }
                if (live.Count == 0) continue;
                long due = long.MaxValue;
                foreach (long d in liveDue) if (d < due) due = d;
                int wait = (int)Math.Max(0, Math.Min(int.MaxValue, due - sw.ElapsedMilliseconds));
                try { Task.WaitAny(live.ToArray(), wait); } catch (Exception) { }
                long now = sw.ElapsedMilliseconds;
                for (int i = live.Count - 1; i >= 0; i--)
                {
                    Task<IPAddress[]> t = live[i];
                    if (!t.IsCompleted && now < liveDue[i]) continue;
                    Harvest(liveName[i], t, timeoutMs, res, errors);
                    live.RemoveAt(i); liveName.RemoveAt(i); liveDue.RemoveAt(i);
                }
            }
            return res;
        }

        static void Harvest(string nm, Task<IPAddress[]> t, int timeoutMs, Dictionary<string, string[]> res, Dictionary<string, string> errors)
        {
            if (t.Status == TaskStatus.RanToCompletion)
            {
                List<string> a = new List<string>();
                foreach (IPAddress ip in t.Result) a.Add(ip.ToString());
                if (a.Count > 0) res[nm] = a.ToArray(); else errors[nm] = "no addresses";
            }
            else if (t.IsFaulted)
            {
                Exception ex = t.Exception != null ? t.Exception.GetBaseException() : null;
                errors[nm] = ex != null ? ex.Message : "lookup failed";
            }
            else errors[nm] = "DNS timeout after " + timeoutMs + "ms";
        }

        static Dictionary<string, string[]> ResolveBatched(string[] names, int timeoutMs, int parallel, Dictionary<string, string> errors)
        {
            Dictionary<string, string[]> res = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            if (parallel < 1) parallel = 1;
            for (int i = 0; i < names.Length; i += parallel)
            {
                int n = Math.Min(parallel, names.Length - i);
                Task<IPAddress[]>[] ts = new Task<IPAddress[]>[n];
                for (int j = 0; j < n; j++)
                {
                    try { ts[j] = Resolver != null ? Resolver(names[i + j]) : Dns.GetHostAddressesAsync(names[i + j]); }
                    catch (Exception ex) { errors[names[i + j]] = Flatten(ex); ts[j] = null; }
                }
                List<Task> live = new List<Task>();
                foreach (Task t in ts) if (t != null) live.Add(t);
                try { Task.WaitAll(live.ToArray(), timeoutMs); } catch (AggregateException) { } catch (Exception) { }
                for (int j = 0; j < n; j++) if (ts[j] != null) Harvest(names[i + j], ts[j], timeoutMs, res, errors);
            }
            return res;
        }

        // benchmark helper: a resolver whose latency is pctSlow% slowMs, otherwise fastMs (deterministic per name)
        public static Func<string, Task<IPAddress[]>> FakeResolver(int pctSlow, int slowMs, int fastMs)
        {
            return delegate(string name)
            {
                int h = 0; foreach (char c in name) h = unchecked(h * 31 + c);
                int ms = (Math.Abs(h % 100) < pctSlow) ? slowMs : fastMs;
                return Task.Delay(ms).ContinueWith(delegate(Task x) { return new IPAddress[] { IPAddress.Loopback }; });
            };
        }

        // Pre-initialise the certificate chain engine and TLS types before many workers hit them at once
        public static long WarmUp(byte[] certDer)
        {
            Stopwatch sw = Stopwatch.StartNew();
            try
            {
                using (X509Certificate2 c = new X509Certificate2(certDer))
                using (X509Chain ch = new X509Chain())
                {
                    ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    ch.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
                    ch.Build(c);
                }
                Tls.BuildClientHello("tls12", "warmup.invalid");
            }
            catch { }
            return sw.ElapsedMilliseconds;
        }

        public static string ReverseLookup(string ip, int timeoutMs)
        {
            try
            {
                IPAddress a;
                if (!IPAddress.TryParse(ip, out a)) return null;
                Task<IPHostEntry> t = Dns.GetHostEntryAsync(a);
                if (t.Wait(timeoutMs) && t.Status == TaskStatus.RanToCompletion && t.Result != null)
                {
                    string h = t.Result.HostName;
                    if (string.IsNullOrEmpty(h) || h == ip) return null;
                    return h;
                }
            }
            catch { }
            return null;
        }
    }

    // ------------------------------------------------------------------ Hashing
    public static class Hash
    {
        // MurmurHash3 x86_32, seed 0, signed (Python mmh3.hash compatible)
        public static int Mmh3(byte[] d)
        {
            const uint c1 = 0xcc9e2d51, c2 = 0x1b873593;
            uint h1 = 0;
            int len = d.Length, nb = len / 4;
            for (int i = 0; i < nb; i++)
            {
                int o = i * 4;
                uint k1 = (uint)(d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24));
                k1 *= c1; k1 = (k1 << 15) | (k1 >> 17); k1 *= c2;
                h1 ^= k1; h1 = (h1 << 13) | (h1 >> 19); h1 = h1 * 5 + 0xe6546b64;
            }
            uint k = 0; int t = nb * 4;
            switch (len & 3)
            {
                case 3: k ^= (uint)d[t + 2] << 16; goto case 2;
                case 2: k ^= (uint)d[t + 1] << 8; goto case 1;
                case 1: k ^= d[t]; k *= c1; k = (k << 15) | (k >> 17); k *= c2; h1 ^= k; break;
            }
            h1 ^= (uint)len; h1 ^= h1 >> 16; h1 *= 0x85ebca6b; h1 ^= h1 >> 13; h1 *= 0xc2b2ae35; h1 ^= h1 >> 16;
            return unchecked((int)h1);
        }

        // Shodan/httpx/runZero favicon hash: mmh3 over Python base64.encodebytes() output
        // (newline every 76 chars AND a trailing newline)
        public static int FaviconHash(byte[] d)
        {
            string b = Convert.ToBase64String(d);
            StringBuilder sb = new StringBuilder(b.Length + b.Length / 76 + 2);
            for (int i = 0; i < b.Length; i += 76) { sb.Append(b, i, Math.Min(76, b.Length - i)); sb.Append('\n'); }
            return Mmh3(Encoding.ASCII.GetBytes(sb.ToString()));
        }

        // Managed MD5 (RFC 1321). Used only for content fingerprint matching (Recog/Nmap favicon DBs),
        // never for security. Works on hosts with the Windows FIPS policy enforced.
        static readonly int[] S = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                                    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };
        static readonly uint[] K = {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

        public static string Md5Hex(byte[] msg)
        {
            uint a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
            long bitLen = (long)msg.Length * 8;
            int padLen = ((msg.Length + 8) / 64 + 1) * 64;
            byte[] m = new byte[padLen];
            Buffer.BlockCopy(msg, 0, m, 0, msg.Length);
            m[msg.Length] = 0x80;
            for (int i = 0; i < 8; i++) m[padLen - 8 + i] = (byte)(bitLen >> (8 * i));
            uint[] M = new uint[16];
            for (int off = 0; off < padLen; off += 64)
            {
                for (int i = 0; i < 16; i++)
                {
                    int o = off + i * 4;
                    M[i] = (uint)(m[o] | (m[o + 1] << 8) | (m[o + 2] << 16) | (m[o + 3] << 24));
                }
                uint A = a0, B = b0, C = c0, D = d0;
                for (int i = 0; i < 64; i++)
                {
                    uint F; int g;
                    if (i < 16) { F = (B & C) | (~B & D); g = i; }
                    else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
                    else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
                    else { F = C ^ (B | ~D); g = (7 * i) % 16; }
                    F = F + A + K[i] + M[g];
                    A = D; D = C; C = B;
                    B = B + ((F << S[i]) | (F >> (32 - S[i])));
                }
                a0 += A; b0 += B; c0 += C; d0 += D;
            }
            byte[] o16 = new byte[16];
            uint[] w = { a0, b0, c0, d0 };
            for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) o16[i * 4 + j] = (byte)(w[i] >> (8 * j));
            return Hex(o16);
        }

        // SHA-256 via the platform provider (CNG on Windows). If the platform refuses (policy), fall back to a managed
        // implementation: these hashes are content identifiers for inventory/diffing, not security controls.
        public static string Sha256Provider = "";
        public static string Sha256Hex(byte[] d)
        {
            if (Sha256Provider != "managed")
            {
                try
                {
                    using (IncrementalHash h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
                    {
                        h.AppendData(d);
                        Sha256Provider = "platform";
                        return Hex(h.GetHashAndReset());
                    }
                }
                catch (Exception) { Sha256Provider = "managed"; }
            }
            return Hex(Sha256Managed(d));
        }

        static readonly uint[] K256 = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

        static uint Rotr(uint x, int n) { return (x >> n) | (x << (32 - n)); }

        public static byte[] Sha256Managed(byte[] msg)
        {
            uint[] H = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
            long bitLen = (long)msg.Length * 8;
            int padLen = ((msg.Length + 8) / 64 + 1) * 64;
            byte[] m = new byte[padLen];
            Buffer.BlockCopy(msg, 0, m, 0, msg.Length);
            m[msg.Length] = 0x80;
            for (int i = 0; i < 8; i++) m[padLen - 1 - i] = (byte)(bitLen >> (8 * i));
            uint[] w = new uint[64];
            for (int off = 0; off < padLen; off += 64)
            {
                for (int i = 0; i < 16; i++)
                {
                    int o = off + i * 4;
                    w[i] = ((uint)m[o] << 24) | ((uint)m[o + 1] << 16) | ((uint)m[o + 2] << 8) | m[o + 3];
                }
                for (int i = 16; i < 64; i++)
                {
                    uint s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                    uint s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
                }
                uint a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
                for (int i = 0; i < 64; i++)
                {
                    uint S1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
                    uint ch = (e & f) ^ (~e & g);
                    uint t1 = h + S1 + ch + K256[i] + w[i];
                    uint S0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
                    uint maj = (a & b) ^ (a & c) ^ (b & c);
                    uint t2 = S0 + maj;
                    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
                }
                H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
            }
            byte[] outb = new byte[32];
            for (int i = 0; i < 8; i++) { outb[i * 4] = (byte)(H[i] >> 24); outb[i * 4 + 1] = (byte)(H[i] >> 16); outb[i * 4 + 2] = (byte)(H[i] >> 8); outb[i * 4 + 3] = (byte)H[i]; }
            return outb;
        }

        public static string Hex(byte[] h)
        {
            StringBuilder sb = new StringBuilder(h.Length * 2);
            foreach (byte x in h) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }
    }

    // ------------------------------------------------------------------ DER helpers
    public static class Der
    {
        public static bool Tlv(byte[] d, int pos, int end, out int tag, out int hdrLen, out int len)
        {
            tag = 0; hdrLen = 0; len = 0;
            if (d == null || pos < 0 || pos + 2 > end) return false;
            tag = d[pos];
            int p = pos + 1;
            int b = d[p++];
            if (b < 0x80) len = b;
            else
            {
                int n = b & 0x7f;
                if (n == 0 || n > 3 || p + n > end) return false;
                for (int i = 0; i < n; i++) len = (len << 8) | d[p++];
            }
            hdrLen = p - pos;
            return len >= 0 && pos + hdrLen + len <= end;
        }

        public static string[] SubjectAltNames(X509Certificate2 c)
        {
            try
            {
                foreach (X509Extension e in c.Extensions)
                    if (e.Oid != null && e.Oid.Value == "2.5.29.17") return ParseSan(e.RawData).ToArray();
            }
            catch { }
            return new string[0];
        }

        // Locale-independent SAN parse (X509Extension.Format() output varies by OS language)
        public static List<string> ParseSan(byte[] d)
        {
            List<string> o = new List<string>();
            int tag, hl, len;
            if (d == null || !Tlv(d, 0, d.Length, out tag, out hl, out len) || tag != 0x30) return o;
            int p = hl, end = hl + len;
            while (p < end)
            {
                if (!Tlv(d, p, end, out tag, out hl, out len)) break;
                int cs = p + hl;
                switch (tag)
                {
                    case 0x82: o.Add("DNS:" + Encoding.ASCII.GetString(d, cs, len)); break;
                    case 0x81: o.Add("EMAIL:" + Encoding.ASCII.GetString(d, cs, len)); break;
                    case 0x86: o.Add("URI:" + Encoding.ASCII.GetString(d, cs, len)); break;
                    case 0x87:
                        if (len == 4 || len == 16)
                        {
                            byte[] ip = new byte[len]; Buffer.BlockCopy(d, cs, ip, 0, len);
                            o.Add("IP:" + new IPAddress(ip).ToString());
                        }
                        break;
                }
                p = cs + len;
            }
            return o;
        }

        static string Oid(byte[] d, int p, int len)
        {
            StringBuilder sb = new StringBuilder();
            long v = 0; bool first = true;
            for (int i = 0; i < len; i++)
            {
                v = (v << 7) + (d[p + i] & 0x7f);   // low 7 bits are free after the shift (no sign-extended OR, csc CS0675)
                if ((d[p + i] & 0x80) == 0)
                {
                    if (first)
                    {
                        long a = v < 40 ? 0 : (v < 80 ? 1 : 2);
                        sb.Append(a).Append('.').Append(v - a * 40);
                        first = false;
                    }
                    else sb.Append('.').Append(v);
                    v = 0;
                }
            }
            return sb.ToString();
        }

        static string DecodeString(int tag, byte[] d, int p, int len, out bool isString)
        {
            isString = true;
            switch (tag)
            {
                case 0x0c: return Encoding.UTF8.GetString(d, p, len);
                case 0x13: case 0x16: case 0x12: case 0x1a: return Encoding.ASCII.GetString(d, p, len);
                case 0x14: return Encoding.GetEncoding(28591).GetString(d, p, len);
                case 0x1e: return Encoding.BigEndianUnicode.GetString(d, p, len);
                case 0x1c: return new UTF32Encoding(true, false).GetString(d, p, len);
            }
            isString = false;
            return null;
        }

        static readonly Dictionary<string, string> GoNames = new Dictionary<string, string> {
            { "2.5.4.6", "C" }, { "2.5.4.10", "O" }, { "2.5.4.11", "OU" }, { "2.5.4.3", "CN" }, { "2.5.4.5", "SERIALNUMBER" },
            { "2.5.4.7", "L" }, { "2.5.4.8", "ST" }, { "2.5.4.9", "STREET" }, { "2.5.4.17", "POSTALCODE" } };
        // Go pkix.Name.String() order (reverse of ToRDNSequence)
        static readonly string[] GoOrder = { "2.5.4.5", "2.5.4.3", "2.5.4.11", "2.5.4.10", "2.5.4.17", "2.5.4.9", "2.5.4.7", "2.5.4.8", "2.5.4.6" };

        static string GoEscape(string v)
        {
            StringBuilder sb = new StringBuilder();
            for (int k = 0; k < v.Length; k++)
            {
                char c = v[k]; bool esc = false;
                switch (c)
                {
                    case ',': case '+': case '"': case '\\': case '<': case '>': case ';': esc = true; break;
                    case ' ': esc = (k == 0 || k == v.Length - 1); break;
                    case '#': esc = (k == 0); break;
                }
                if (esc) sb.Append('\\');
                sb.Append(c);
            }
            return sb.ToString();
        }

        static bool GoPrintable(string s)
        {
            foreach (char c in s)
            {
                bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                          (c >= '\'' && c <= ')') || (c >= '+' && c <= '/') || c == ' ' || c == ':' || c == '=' || c == '?';
                if (!ok) return false;
            }
            return true;
        }

        static byte[] DerEncode(int tag, byte[] content)
        {
            MemoryStream ms = new MemoryStream();
            ms.WriteByte((byte)tag);
            int l = content.Length;
            if (l < 0x80) ms.WriteByte((byte)l);
            else if (l < 0x100) { ms.WriteByte(0x81); ms.WriteByte((byte)l); }
            else if (l < 0x10000) { ms.WriteByte(0x82); ms.WriteByte((byte)(l >> 8)); ms.WriteByte((byte)l); }
            else { ms.WriteByte(0x83); ms.WriteByte((byte)(l >> 16)); ms.WriteByte((byte)(l >> 8)); ms.WriteByte((byte)l); }
            ms.Write(content, 0, content.Length);
            return ms.ToArray();
        }

        // Distinguished name formatted exactly like Go's pkix.Name.String() - the format Recog x509 rules use.
        public static string GoName(byte[] d)
        {
            try
            {
                List<string[]> atvs = new List<string[]>(); // {oid, goValueString}
                int tag, hl, len;
                if (!Tlv(d, 0, d.Length, out tag, out hl, out len) || tag != 0x30) return "";
                int p = hl, end = hl + len;
                while (p < end)
                {
                    int t2, h2, l2;
                    if (!Tlv(d, p, end, out t2, out h2, out l2) || t2 != 0x31) break;
                    int sp = p + h2, se = sp + l2;
                    while (sp < se)
                    {
                        int t3, h3, l3;
                        if (!Tlv(d, sp, se, out t3, out h3, out l3) || t3 != 0x30) break;
                        int ap = sp + h3, ae = ap + l3;
                        int t4, h4, l4;
                        if (!Tlv(d, ap, ae, out t4, out h4, out l4) || t4 != 0x06) break;
                        string oid = Oid(d, ap + h4, l4);
                        int vp = ap + h4 + l4;
                        int t5, h5, l5;
                        if (!Tlv(d, vp, ae, out t5, out h5, out l5)) break;
                        bool isStr;
                        string val = DecodeString(t5, d, vp + h5, l5, out isStr);
                        string goVal;
                        if (GoNames.ContainsKey(oid)) goVal = isStr ? GoEscape(val) : "#" + Hash.Hex(Slice(d, vp, h5 + l5));
                        else if (isStr)
                        {
                            byte[] content = Encoding.UTF8.GetBytes(val);
                            goVal = "#" + Hash.Hex(DerEncode(GoPrintable(val) ? 0x13 : 0x0c, content));
                        }
                        else goVal = "#" + Hash.Hex(Slice(d, vp, h5 + l5));
                        atvs.Add(new string[] { oid, goVal });
                        sp = ae;
                    }
                    p = se;
                }
                List<string> parts = new List<string>();
                foreach (string o in GoOrder)
                {
                    List<string> vals = new List<string>();
                    foreach (string[] a in atvs) if (a[0] == o) vals.Add(GoNames[o] + "=" + a[1]);
                    if (vals.Count > 0) parts.Add(string.Join("+", vals.ToArray()));
                }
                for (int i = atvs.Count - 1; i >= 0; i--)
                    if (!GoNames.ContainsKey(atvs[i][0])) parts.Add(atvs[i][0] + "=" + atvs[i][1]);
                return string.Join(",", parts.ToArray());
            }
            catch { return ""; }
        }

        static byte[] Slice(byte[] d, int p, int n) { byte[] o = new byte[n]; Buffer.BlockCopy(d, p, o, 0, n); return o; }
    }

    // ------------------------------------------------------------------ Raw TLS probing
    public class TlsHello
    {
        public bool Connected;
        public bool IsTls;          // a TLS record came back
        public bool NotTls;         // something non-TLS came back (e.g. plaintext HTTP)
        public int Version;         // negotiated (0x0304 for TLS1.3)
        public int Cipher = -1;
        public string Alpn;
        public byte[] CertDer;
        public int Alert = -1;
        public string Error;
        public string ServerExts = "";   // ServerHello extension types in order, 4 hex digits, comma separated
    }

    public class TlsScanResult
    {
        public bool IsTls;
        public string Versions = "";
        public string CipherByVersion = "";
        public string Alpn = "";
        public bool Http2;
        public string WeakCipher = "";
        public byte[] CertDer;
        public string CertSourceVersion = "";
        public string Errors = "";
        public int Probes;
        // the first ServerHello of the scan (the TLS 1.3 probe when it is answered): version|cipher|extensions|alpn
        public string HelloInfo = "";
    }

    public static class Tls
    {
        public static readonly Dictionary<int, string> Names = new Dictionary<int, string> {
            {0x1301,"TLS_AES_128_GCM_SHA256"},{0x1302,"TLS_AES_256_GCM_SHA384"},{0x1303,"TLS_CHACHA20_POLY1305_SHA256"},
            {0xC02B,"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},{0xC02C,"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
            {0xC02F,"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},{0xC030,"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
            {0xCCA8,"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},{0xCCA9,"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
            {0xC023,"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"},{0xC024,"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
            {0xC027,"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},{0xC028,"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"},
            {0xC009,"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},{0xC00A,"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"},
            {0xC013,"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},{0xC014,"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
            {0x009E,"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},{0x009F,"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"},
            {0xCCAA,"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},{0x0067,"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"},
            {0x006B,"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"},{0x0033,"TLS_DHE_RSA_WITH_AES_128_CBC_SHA"},{0x0039,"TLS_DHE_RSA_WITH_AES_256_CBC_SHA"},
            {0x009C,"TLS_RSA_WITH_AES_128_GCM_SHA256"},{0x009D,"TLS_RSA_WITH_AES_256_GCM_SHA384"},
            {0x003C,"TLS_RSA_WITH_AES_128_CBC_SHA256"},{0x003D,"TLS_RSA_WITH_AES_256_CBC_SHA256"},
            {0x002F,"TLS_RSA_WITH_AES_128_CBC_SHA"},{0x0035,"TLS_RSA_WITH_AES_256_CBC_SHA"},
            {0x0041,"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"},{0x0084,"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"},
            {0xC012,"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},{0xC008,"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"},
            {0x0016,"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"},{0x000A,"TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
            {0xC011,"TLS_ECDHE_RSA_WITH_RC4_128_SHA"},{0xC007,"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"},
            {0x0005,"TLS_RSA_WITH_RC4_128_SHA"},{0x0004,"TLS_RSA_WITH_RC4_128_MD5"},
            {0x0009,"TLS_RSA_WITH_DES_CBC_SHA"},{0x0015,"TLS_DHE_RSA_WITH_DES_CBC_SHA"},
            {0x0003,"TLS_RSA_EXPORT_WITH_RC4_40_MD5"},{0x0006,"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"},
            {0x0008,"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"},{0x0014,"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"},
            {0x0062,"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"},{0x0064,"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"},
            {0x0001,"TLS_RSA_WITH_NULL_MD5"},{0x0002,"TLS_RSA_WITH_NULL_SHA"},{0x003B,"TLS_RSA_WITH_NULL_SHA256"},
            {0xC010,"TLS_ECDHE_RSA_WITH_NULL_SHA"},{0xC006,"TLS_ECDHE_ECDSA_WITH_NULL_SHA"},
            {0x0018,"TLS_DH_anon_WITH_RC4_128_MD5"},{0x001B,"TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"},
            {0x0034,"TLS_DH_anon_WITH_AES_128_CBC_SHA"},{0x003A,"TLS_DH_anon_WITH_AES_256_CBC_SHA"},
            {0xC018,"TLS_ECDH_anon_WITH_AES_128_CBC_SHA"},{0xC019,"TLS_ECDH_anon_WITH_AES_256_CBC_SHA"},
            {0xC016,"TLS_ECDH_anon_WITH_RC4_128_SHA"} };

        static readonly int[] Tls13Suites = { 0x1301, 0x1302, 0x1303 };
        static readonly int[] ModernSuites = { 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0x009E, 0x009F, 0xCCAA, 0xC023, 0xC027, 0xC024, 0xC028,
                                               0xC009, 0xC013, 0xC00A, 0xC014, 0x0067, 0x006B, 0x0033, 0x0039, 0x009C, 0x009D, 0x003C, 0x003D,
                                               0x002F, 0x0035, 0x0041, 0x0084, 0xC012, 0xC008, 0x0016, 0x000A, 0xC011, 0xC007, 0x0005, 0x0004 };
        static readonly int[] WeakSuites = { 0xC011, 0xC007, 0x0005, 0x0004, 0xC012, 0xC008, 0x0016, 0x000A, 0x0009, 0x0015, 0x0003, 0x0006, 0x0008,
                                             0x0014, 0x0062, 0x0064, 0x0001, 0x0002, 0x003B, 0xC010, 0xC006, 0x0018, 0x001B, 0x0034, 0x003A,
                                             0xC018, 0xC019, 0xC016 };

        public static string SuiteName(int id)
        {
            string n;
            if (Names.TryGetValue(id, out n)) return n;
            return "0x" + id.ToString("X4");
        }

        public static string VersionName(int v)
        {
            switch (v)
            {
                case 0x0304: return "TLS1.3";
                case 0x0303: return "TLS1.2";
                case 0x0302: return "TLS1.1";
                case 0x0301: return "TLS1.0";
                case 0x0300: return "SSL3";
                default: return "0x" + v.ToString("X4");
            }
        }

        public static bool IsWeakSuite(int id)
        {
            string n = SuiteName(id);
            return n.Contains("_NULL_") || n.Contains("EXPORT") || n.Contains("_anon_") || n.Contains("RC4") ||
                   n.Contains("_DES_") || n.Contains("3DES") || n.Contains("RC2");
        }

        static void U16(MemoryStream m, int v) { m.WriteByte((byte)(v >> 8)); m.WriteByte((byte)v); }
        static void U24(MemoryStream m, int v) { m.WriteByte((byte)(v >> 16)); m.WriteByte((byte)(v >> 8)); m.WriteByte((byte)v); }
        static void Ext(MemoryStream exts, int type, byte[] body) { U16(exts, type); U16(exts, body.Length); exts.Write(body, 0, body.Length); }

        // mode: "tls13" | "tls12" | "tls11" | "tls10" | "ssl3" | "weak"
        public static byte[] BuildClientHello(string mode, string sni)
        {
            int ver; int[] suites; bool exts = true, tls13 = false, alpn = false, sigalgs = true;
            switch (mode)
            {
                case "tls13": ver = 0x0303; tls13 = true; alpn = true; suites = Concat(Tls13Suites, ModernSuites); break;
                case "tls12": ver = 0x0303; alpn = true; suites = ModernSuites; break;
                case "tls11": ver = 0x0302; sigalgs = false; suites = ModernSuites; break;
                case "tls10": ver = 0x0301; sigalgs = false; suites = ModernSuites; break;
                case "ssl3": ver = 0x0300; exts = false; sigalgs = false; suites = ModernSuites; break;
                case "weak": ver = 0x0303; suites = WeakSuites; break;
                default: throw new ArgumentException("mode");
            }
            Random rnd = new Random(Guid.NewGuid().GetHashCode());
            MemoryStream body = new MemoryStream();
            U16(body, ver);
            byte[] random = new byte[32]; rnd.NextBytes(random); body.Write(random, 0, 32);
            byte[] sid = new byte[32]; rnd.NextBytes(sid);
            if (mode == "ssl3") body.WriteByte(0); else { body.WriteByte(32); body.Write(sid, 0, 32); }
            int nSuites = suites.Length + (mode == "ssl3" ? 0 : 1);
            U16(body, nSuites * 2);
            foreach (int s in suites) U16(body, s);
            if (mode != "ssl3") U16(body, 0x00FF);              // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
            body.WriteByte(1); body.WriteByte(0);               // compression: null
            if (exts)
            {
                MemoryStream e = new MemoryStream();
                IPAddress tmp;
                if (!string.IsNullOrEmpty(sni) && !IPAddress.TryParse(sni, out tmp))
                {
                    byte[] h = Encoding.ASCII.GetBytes(sni.TrimEnd('.'));
                    MemoryStream sn = new MemoryStream(); U16(sn, h.Length + 3); sn.WriteByte(0); U16(sn, h.Length); sn.Write(h, 0, h.Length);
                    Ext(e, 0x0000, sn.ToArray());
                }
                Ext(e, 0x000a, new byte[] { 0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00 }); // groups
                Ext(e, 0x000b, new byte[] { 0x01, 0x00 });                                                               // ec_point_formats
                if (sigalgs)
                    Ext(e, 0x000d, new byte[] { 0x00, 0x1a, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
                                                0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01, 0x04, 0x02, 0x02, 0x02 });
                if (alpn)
                    Ext(e, 0x0010, new byte[] { 0x00, 0x0c, 0x02, (byte)'h', (byte)'2', 0x08, (byte)'h', (byte)'t', (byte)'t', (byte)'p',
                                                (byte)'/', (byte)'1', (byte)'.', (byte)'1' });
                Ext(e, 0x0017, new byte[0]);                    // extended_master_secret
                Ext(e, 0xff01, new byte[] { 0x00 });            // renegotiation_info
                if (tls13)
                {
                    Ext(e, 0x002b, new byte[] { 0x02, 0x03, 0x04 });          // supported_versions: TLS1.3 only
                    Ext(e, 0x002d, new byte[] { 0x01, 0x01 });                // psk_key_exchange_modes
                    byte[] ks = new byte[32]; rnd.NextBytes(ks);              // any 32 bytes is a valid x25519 public value
                    MemoryStream k = new MemoryStream(); U16(k, 36); U16(k, 0x001d); U16(k, 32); k.Write(ks, 0, 32);
                    Ext(e, 0x0033, k.ToArray());
                }
                byte[] eb = e.ToArray();
                U16(body, eb.Length); body.Write(eb, 0, eb.Length);
            }
            byte[] b = body.ToArray();
            MemoryStream hs = new MemoryStream();
            hs.WriteByte(0x01); U24(hs, b.Length); hs.Write(b, 0, b.Length);
            byte[] h2 = hs.ToArray();
            MemoryStream rec = new MemoryStream();
            rec.WriteByte(0x16); U16(rec, mode == "ssl3" ? 0x0300 : 0x0301); U16(rec, h2.Length); rec.Write(h2, 0, h2.Length);
            return rec.ToArray();
        }

        static int[] Concat(int[] a, int[] b) { int[] o = new int[a.Length + b.Length]; a.CopyTo(o, 0); b.CopyTo(o, a.Length); return o; }

        static bool ReadExact(Stream s, byte[] buf, int n)
        {
            int got = 0;
            while (got < n) { int r = s.Read(buf, got, n - got); if (r <= 0) return false; got += r; }
            return true;
        }

        public static TlsHello Hello(string ip, int port, string sni, string mode, int timeoutMs, bool wantCert)
        {
            TlsHello h = new TlsHello();
            string st;
            TcpClient c = Net.Connect(ip, port, timeoutMs, out st);
            if (c == null) { h.Error = "connect " + st; return h; }
            h.Connected = true;
            try
            {
                c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs;
                NetworkStream s = c.GetStream();
                byte[] ch = BuildClientHello(mode, sni);
                s.Write(ch, 0, ch.Length);
                MemoryStream hsBuf = new MemoryStream();
                byte[] hdr = new byte[5];
                int total = 0; bool haveHello = false;
                while (total < 262144)
                {
                    if (!ReadExact(s, hdr, 5)) break;
                    int ct = hdr[0];
                    if (ct < 20 || ct > 23 || hdr[1] > 3)
                    {
                        if (!h.IsTls) h.NotTls = true;
                        break;
                    }
                    int rl = (hdr[3] << 8) | hdr[4];
                    if (rl > 18432) { h.Error = "oversized record"; break; }
                    byte[] frag = new byte[rl];
                    if (!ReadExact(s, frag, rl)) break;
                    total += rl + 5;
                    h.IsTls = true;
                    if (ct == 21) { if (rl >= 2) h.Alert = frag[1]; break; }
                    if (ct == 20 || ct == 23) { if (haveHello) break; continue; }
                    if (ct != 22) break;
                    hsBuf.Write(frag, 0, frag.Length);
                    byte[] hb = hsBuf.ToArray();
                    int p = 0; bool done = false;
                    while (p + 4 <= hb.Length)
                    {
                        int mt = hb[p]; int ml = (hb[p + 1] << 16) | (hb[p + 2] << 8) | hb[p + 3];
                        if (p + 4 + ml > hb.Length) break;
                        int b = p + 4;
                        if (mt == 2) { ParseServerHello(hb, b, ml, h); haveHello = true; if (h.Version == 0x0304 || !wantCert) done = true; }
                        else if (mt == 11 && ml >= 6)
                        {
                            int cl = (hb[b + 3] << 16) | (hb[b + 4] << 8) | hb[b + 5];
                            if (cl > 0 && b + 6 + cl <= b + ml) { h.CertDer = new byte[cl]; Buffer.BlockCopy(hb, b + 6, h.CertDer, 0, cl); }
                            done = true;
                        }
                        else if (mt == 14) done = true;
                        p += 4 + ml;
                    }
                    if (p > 0) { MemoryStream rest = new MemoryStream(); rest.Write(hb, p, hb.Length - p); hsBuf = rest; }
                    if (done) break;
                }
            }
            catch (Exception ex) { h.Error = Net.Flatten(ex); }
            finally { Net.SafeClose(c); }
            return h;
        }

        static void ParseServerHello(byte[] d, int p, int len, TlsHello h)
        {
            int end = p + len;
            if (len < 38) return;
            h.Version = (d[p] << 8) | d[p + 1];
            int q = p + 2 + 32;
            int sl = d[q]; q += 1 + sl;
            if (q + 3 > end) return;
            h.Cipher = (d[q] << 8) | d[q + 1]; q += 3;
            if (q + 2 > end) return;
            int el = (d[q] << 8) | d[q + 1]; q += 2;
            int ee = Math.Min(end, q + el);
            StringBuilder exts = new StringBuilder();
            while (q + 4 <= ee)
            {
                int et = (d[q] << 8) | d[q + 1]; int len2 = (d[q + 2] << 8) | d[q + 3]; int eb = q + 4;
                if (exts.Length > 0) exts.Append(',');
                exts.Append(et.ToString("x4"));
                h.ServerExts = exts.ToString();
                if (eb + len2 > ee) break;
                if (et == 0x002b && len2 == 2) h.Version = (d[eb] << 8) | d[eb + 1];
                if (et == 0x0010 && len2 >= 3) { int pl = d[eb + 2]; if (eb + 3 + pl <= eb + len2) h.Alpn = Encoding.ASCII.GetString(d, eb + 3, pl); }
                q = eb + len2;
            }
        }

        static readonly string[][] Plan = {
            new string[] { "tls13", "TLS1.3" }, new string[] { "tls12", "TLS1.2" }, new string[] { "tls11", "TLS1.1" },
            new string[] { "tls10", "TLS1.0" }, new string[] { "ssl3", "SSL3" } };

        // Version support matrix + ALPN/h2 + weak-cipher acceptance + leaf certificate (from a TLS<=1.2 handshake),
        // all independent of the scanning host's Schannel configuration. Handshakes stop after ServerHello/Certificate.
        public static TlsScanResult Scan(string ip, int port, string sni, int timeoutMs, bool weakProbe) { return Scan(ip, port, sni, timeoutMs, weakProbe, false); }

        // parallel: send the version probes concurrently (used for listeners that stayed silent to HTTP and to Schannel,
        // where serial probes would each wait the full timeout); results are combined in the same order and with the
        // same rules as the serial scan, so the outcome is identical.
        public static TlsScanResult Scan(string ip, int port, string sni, int timeoutMs, bool weakProbe, bool parallel)
        {
            TlsScanResult r = new TlsScanResult();
            List<string> vers = new List<string>(); List<string> ciphers = new List<string>(); List<string> errs = new List<string>();
            TlsHello[] pre = null;
            if (parallel)
            {
                pre = new TlsHello[Plan.Length];
                Task[] ts = new Task[Plan.Length];
                for (int i = 0; i < Plan.Length; i++)
                {
                    int k = i;
                    ts[i] = Task.Factory.StartNew(delegate { pre[k] = Hello(ip, port, sni, Plan[k][0], timeoutMs, true); }, TaskCreationOptions.LongRunning);
                }
                Task.WaitAll(ts);
            }
            for (int pi = 0; pi < Plan.Length; pi++)
            {
                string[] step = Plan[pi];
                TlsHello h = parallel ? pre[pi] : Hello(ip, port, sni, step[0], timeoutMs, true);
                r.Probes++;
                if (!h.Connected) { errs.Add(step[1] + ":" + h.Error); if (step[0] == "tls13") break; continue; }
                if (h.NotTls && !r.IsTls) { errs.Add("not TLS"); break; }
                if (h.IsTls) r.IsTls = true;
                if (r.HelloInfo.Length == 0 && h.Cipher >= 0 && h.Version > 0)
                    r.HelloInfo = h.Version.ToString("x4") + "|" + h.Cipher.ToString("x4") + "|" + h.ServerExts + "|" + (h.Alpn ?? "");
                if (h.Cipher >= 0 && h.Version > 0 && VersionName(h.Version) == step[1])
                {
                    vers.Add(step[1]);
                    ciphers.Add(step[1] + "=" + SuiteName(h.Cipher));
                    if (!string.IsNullOrEmpty(h.Alpn) && string.IsNullOrEmpty(r.Alpn)) r.Alpn = h.Alpn;
                    if (h.CertDer != null && r.CertDer == null) { r.CertDer = h.CertDer; r.CertSourceVersion = step[1]; }
                }
                else if (h.Error != null) errs.Add(step[1] + ":" + h.Error);
                else if (h.Alert >= 0) errs.Add(step[1] + ":alert" + h.Alert);
            }
            if (parallel) r.Probes = Plan.Length;
            if (r.IsTls && weakProbe)
            {
                TlsHello w = Hello(ip, port, sni, "weak", timeoutMs, false);
                r.Probes++;
                if (w.Cipher >= 0 && IsWeakSuite(w.Cipher)) r.WeakCipher = VersionName(w.Version) + ":" + SuiteName(w.Cipher);
            }
            r.Versions = string.Join(";", vers.ToArray());
            r.CipherByVersion = string.Join(";", ciphers.ToArray());
            r.Http2 = r.Alpn == "h2";
            r.Errors = string.Join(";", errs.ToArray());
            return r;
        }
    }

    // ------------------------------------------------------------------ Fingerprint rules
    [DataContract]
    public class CondDef
    {
        [DataMember(Name = "f")] public string F;
        [DataMember(Name = "r")] public string R;
        [DataMember(Name = "o", EmitDefaultValue = false)] public string O;
        [DataMember(Name = "not", EmitDefaultValue = false)] public bool Not;
    }

    [DataContract]
    public class OutDef
    {
        [DataMember(Name = "t", EmitDefaultValue = false)] public string T;    // service|os|hw|flag
        [DataMember(Name = "n", EmitDefaultValue = false)] public string N;    // display name
        [DataMember(Name = "c", EmitDefaultValue = false)] public string C;    // category
        [DataMember(Name = "v", EmitDefaultValue = false)] public string V;    // version template e.g. "{1}"
        [DataMember(Name = "p", EmitDefaultValue = false)] public string P;    // CPE template ({v} = version)
        [DataMember(Name = "k", EmitDefaultValue = false)] public int K;       // confidence 1-100
        [DataMember(Name = "im", EmitDefaultValue = false)] public string[] Im;
        [DataMember(Name = "xs", EmitDefaultValue = false)] public string[] Xs;
        [DataMember(Name = "rq", EmitDefaultValue = false)] public string[] Rq;
        [DataMember(Name = "rc", EmitDefaultValue = false)] public string[] Rc;   // requires a detection in one of these categories
        [DataMember(Name = "flag", EmitDefaultValue = false)] public string Flag;
        [DataMember(Name = "h", EmitDefaultValue = false)] public string H;    // host name template
        // version-only: the output adds its version to a product another rule detected (same kind and CPE product or name)
        // and is discarded otherwise; it never creates a detection, never sets name/category/confidence, and never replaces
        // a version that a detection rule captured
        [DataMember(Name = "vo", EmitDefaultValue = false)] public bool Vo;
    }

    [DataContract]
    public class RuleDef
    {
        [DataMember(Name = "id", EmitDefaultValue = false)] public string Id;
        [DataMember(Name = "f")] public string F;
        [DataMember(Name = "r")] public string R;
        [DataMember(Name = "o", EmitDefaultValue = false)] public string O;    // i=ignorecase s=dot-all a=absolute anchors b=base64 value
        [DataMember(Name = "and", EmitDefaultValue = false)] public CondDef[] And;
        [DataMember(Name = "ports", EmitDefaultValue = false)] public int[] Ports;
        [DataMember(Name = "src", EmitDefaultValue = false)] public string Src;
        [DataMember(Name = "out", EmitDefaultValue = false)] public OutDef[] Out;
        // single-output shorthand
        [DataMember(Name = "t", EmitDefaultValue = false)] public string T;
        [DataMember(Name = "n", EmitDefaultValue = false)] public string N;
        [DataMember(Name = "c", EmitDefaultValue = false)] public string C;
        [DataMember(Name = "v", EmitDefaultValue = false)] public string V;
        [DataMember(Name = "p", EmitDefaultValue = false)] public string P;
        [DataMember(Name = "k", EmitDefaultValue = false)] public int K;
        [DataMember(Name = "im", EmitDefaultValue = false)] public string[] Im;
        [DataMember(Name = "xs", EmitDefaultValue = false)] public string[] Xs;
        [DataMember(Name = "rq", EmitDefaultValue = false)] public string[] Rq;
        [DataMember(Name = "rc", EmitDefaultValue = false)] public string[] Rc;
        [DataMember(Name = "flag", EmitDefaultValue = false)] public string Flag;
        [DataMember(Name = "vo", EmitDefaultValue = false)] public bool Vo;
        // -VersionPaths: the fixed path a version-only rule reads; its field is path:<get>.<part>
        [DataMember(Name = "get", EmitDefaultValue = false)] public string Get;
        // self-test vector
        [DataMember(Name = "ex", EmitDefaultValue = false)] public string Ex;
        [DataMember(Name = "exv", EmitDefaultValue = false)] public string Exv;
    }

    [DataContract]
    public class RulePack
    {
        [DataMember(Name = "name")] public string Name;
        [DataMember(Name = "version", EmitDefaultValue = false)] public string Version;
        [DataMember(Name = "source", EmitDefaultValue = false)] public string Source;
        [DataMember(Name = "license", EmitDefaultValue = false)] public string License;
        [DataMember(Name = "generated", EmitDefaultValue = false)] public string Generated;
        [DataMember(Name = "rules")] public RuleDef[] Rules;
    }

    public class Rule
    {
        public string Id; public string Field; public Regex Re; public Cond[] And; public int[] Ports; public string Src; public OutDef[] Out;
        public string Ex; public string Exv;
        public bool B64;   // o contains 'b': the value is base64 text; the regex runs on its UTF-8 decoding (no literal prefilter)
        public string Get; // -VersionPaths: path requested only when this rule's product is detected without a version
        public string[][] Lits; public int[][] LitIds;   // requirement formula (OR of AND-sets of folded literals) + ids in the field automaton
    }

    // ------------------------------------------------------------------ Literal prefilter (Aho-Corasick)
    // A rule regex is only run on a value that contains the rule's required literal. Literals are ASCII and compared after
    // case folding, so the filter is a necessary condition for a match under both case-sensitive and IgnoreCase regexes.
    public static class Lit
    {
        public static readonly char[] FoldMap = BuildFold();
        static char[] BuildFold()
        {
            char[] f = new char[65536];
            for (int i = 0; i < 65536; i++)
            {
                char c = (char)i;
                if (c < 128) { f[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; continue; }
                // anything that case-maps onto an ASCII letter (Kelvin sign, long s, dotted I...) folds onto it,
                // so the filter can only be more permissive than the regex engine's IgnoreCase equivalences
                char l = char.ToLowerInvariant(c), u = char.ToUpperInvariant(c);
                if (l < 128) f[i] = (l >= 'A' && l <= 'Z') ? (char)(l + 32) : l;
                else if (u < 128) f[i] = (u >= 'A' && u <= 'Z') ? (char)(u + 32) : u;
                else f[i] = c;
            }
            return f;
        }
        public static string Fold(string s)
        {
            char[] a = s.ToCharArray();
            for (int i = 0; i < a.Length; i++) a[i] = FoldMap[a[i]];
            return new string(a);
        }

        static readonly Regex FreeSpacing = new Regex(@"\(\?[imnsx\-]*x[imnsx\-]*[:)]", RegexOptions.CultureInvariant);

        // Requirement formula of a pattern: an OR of AND-sets of folded literals (each >= 3 chars) such that every match
        // of the pattern satisfies at least one AND-set. null = no requirement (the rule always runs). Built by a small
        // recursive-descent pass over the pattern; anything not understood, and any blow-up past the size caps, only
        // ever weakens the formula (drops literals or whole terms), so it stays a necessary condition for a match.
        public const int MaxTerms = 16, MaxLitsPerTerm = 6;

        public static string[][] Requirement(string p)
        {
            if (string.IsNullOrEmpty(p) || FreeSpacing.IsMatch(p)) return null;
            try
            {
                int i = 0;
                List<List<string>> d = Alt(p, ref i, 0);
                if (i != p.Length || d == null) return null;
                string[][] o = new string[d.Count][];
                for (int k = 0; k < d.Count; k++) { if (d[k].Count == 0) return null; o[k] = d[k].ToArray(); }
                return o;
            }
            catch (FormatException) { return null; }
        }

        // longest single literal of the formula (diagnostics / spot checks)
        public static string Required(string p)
        {
            string[][] d = Requirement(p);
            if (d == null || d.Length != 1) return null;
            string best = null;
            foreach (string l in d[0]) if (best == null || l.Length > best.Length) best = l;
            return best;
        }

        // does the folded text satisfy the formula?
        public static bool Satisfies(string[][] dnf, string folded)
        {
            if (dnf == null) return true;
            foreach (string[] t in dnf)
            {
                bool all = true;
                foreach (string l in t) if (folded.IndexOf(l, StringComparison.Ordinal) < 0) { all = false; break; }
                if (all) return true;
            }
            return false;
        }

        static List<List<string>> Alt(string p, ref int i, int depth)
        {
            if (depth > 24) throw new FormatException();
            List<List<string>> r = Concat(p, ref i, depth);
            while (i < p.Length && p[i] == '|') { i++; r = Or(r, Concat(p, ref i, depth)); }
            return r;
        }

        static List<List<string>> Concat(string p, ref int i, int depth)
        {
            int n = p.Length;
            List<List<string>> r = null;                       // TRUE
            StringBuilder cur = new StringBuilder();
            while (i < n && p[i] != '|' && p[i] != ')')
            {
                char c = p[i];
                bool lit = false, isGroup = false;
                List<List<string>> g = null;
                if (c == '\\')
                {
                    if (i + 1 >= n) throw new FormatException();
                    char e = p[i + 1];
                    if (e >= 0x20 && e < 0x7F && !char.IsLetterOrDigit(e) && e != '_') { cur.Append(FoldMap[e]); lit = true; i += 2; }
                    else
                    {
                        r = Run(r, cur);
                        i += 2;
                        if ((e == 'p' || e == 'P') && i < n && p[i] == '{') { int j = p.IndexOf('}', i); if (j < 0) throw new FormatException(); i = j + 1; }
                        else if (e == 'k' && i < n && (p[i] == '<' || p[i] == '\'')) { int j = p.IndexOf(p[i] == '<' ? '>' : '\'', i + 1); if (j < 0) throw new FormatException(); i = j + 1; }
                        else if (e == 'x') i += 2;
                        else if (e == 'u') i += 4;
                        else if (e == 'c') i += 1;
                        else if (char.IsDigit(e)) { while (i < n && char.IsDigit(p[i])) i++; }
                        if (i > n) throw new FormatException();
                    }
                }
                else if (c == '[') { r = Run(r, cur); int j = SkipClass(p, i); if (j < 0) throw new FormatException(); i = j; }
                else if (c == '(')
                {
                    r = Run(r, cur);
                    int j = i + 1; bool opaque = false;
                    if (j < n && p[j] == '?')
                    {
                        if (j + 1 >= n) throw new FormatException();
                        char k = p[j + 1];
                        if (k == '#') { int e2 = p.IndexOf(')', j); if (e2 < 0) throw new FormatException(); i = e2 + 1; continue; }
                        if (k == '=' || k == '!' || k == '(' || (k == '<' && j + 2 < n && (p[j + 2] == '=' || p[j + 2] == '!'))) opaque = true;
                        else if (k == ':' || k == '>') j += 2;
                        else if (k == '<' || k == '\'') { int e2 = p.IndexOf(k == '<' ? '>' : '\'', j + 2); if (e2 < 0) throw new FormatException(); j = e2 + 1; }
                        else
                        {
                            int q = j + 1;
                            while (q < n && "imnsx-".IndexOf(p[q]) >= 0) q++;
                            if (q < n && p[q] == ')') { i = q + 1; continue; }        // inline option setter: no content
                            if (q < n && p[q] == ':') j = q + 1; else throw new FormatException();
                        }
                    }
                    if (opaque) { i = SkipGroup(p, i); g = null; }
                    else
                    {
                        i = j;
                        g = Alt(p, ref i, depth + 1);
                        if (i >= n || p[i] != ')') throw new FormatException();
                        i++;
                    }
                    isGroup = true;
                }
                else if (c == '*' || c == '+' || c == '?') throw new FormatException();
                else if (c == '.' || c == '^' || c == '$' || c == '{' || c == '}' || c < 0x20 || c >= 0x7F) { r = Run(r, cur); i++; }
                else { cur.Append(FoldMap[c]); lit = true; i++; }
                int qmin, ql = Quant(p, i, out qmin);
                if (ql > 0)
                {
                    if (lit && qmin == 0) cur.Length--;
                    r = Run(r, cur);
                    if (isGroup && qmin == 0) g = null;
                    i += ql;
                }
                if (isGroup) r = And(r, g);
            }
            return Run(r, cur);
        }

        static List<List<string>> Run(List<List<string>> r, StringBuilder cur)
        {
            if (cur.Length >= 3)
            {
                List<List<string>> one = new List<List<string>>();
                one.Add(new List<string>(new string[] { cur.ToString() }));
                r = And(r, one);
            }
            cur.Length = 0;
            return r;
        }

        static List<List<string>> And(List<List<string>> a, List<List<string>> b)
        {
            if (a == null) return b;
            if (b == null) return a;
            if (a.Count * b.Count > MaxTerms) return a.Count <= b.Count ? a : b;    // weaken: keep one side
            List<List<string>> o = new List<List<string>>();
            foreach (List<string> x in a)
                foreach (List<string> y in b)
                {
                    List<string> t = new List<string>(x);
                    foreach (string l in y) if (!t.Contains(l)) t.Add(l);
                    if (t.Count > MaxLitsPerTerm) { t.Sort(delegate(string u, string v) { return v.Length.CompareTo(u.Length); }); t.RemoveRange(MaxLitsPerTerm, t.Count - MaxLitsPerTerm); }
                    o.Add(t);
                }
            return o;
        }

        static List<List<string>> Or(List<List<string>> a, List<List<string>> b)
        {
            if (a == null || b == null) return null;                                 // TRUE absorbs
            if (a.Count + b.Count > MaxTerms) return null;                            // weaken to TRUE
            List<List<string>> o = new List<List<string>>(a); o.AddRange(b);
            return o;
        }

        static int SkipGroup(string p, int i)
        {
            int depth = 1, j = i + 1;
            while (j < p.Length && depth > 0)
            {
                if (p[j] == '\\') { j += 2; continue; }
                if (p[j] == '[') { int k = SkipClass(p, j); if (k < 0) throw new FormatException(); j = k; continue; }
                if (p[j] == '(') depth++;
                else if (p[j] == ')') depth--;
                j++;
            }
            if (depth > 0) throw new FormatException();
            return j;
        }

        static int SkipClass(string p, int i)
        {
            int j = i + 1, n = p.Length;
            if (j < n && p[j] == '^') j++;
            if (j < n && p[j] == ']') j++;
            while (j < n && p[j] != ']')
            {
                if (p[j] == '\\') { j += 2; continue; }
                if (p[j] == '[' ) return -1;   // class subtraction or nested bracket: give up
                j++;
            }
            return j < n ? j + 1 : -1;
        }

        static int Quant(string p, int i, out int min)
        {
            min = 1;
            if (i >= p.Length) return 0;
            int len = 0;
            char c = p[i];
            if (c == '*' || c == '?') { min = 0; len = 1; }
            else if (c == '+') { min = 1; len = 1; }
            else if (c == '{')
            {
                int j = i + 1; int a = 0; bool digits = false;
                while (j < p.Length && char.IsDigit(p[j])) { a = Math.Min(100000, a * 10 + (p[j] - '0')); j++; digits = true; }
                if (!digits) return 0;
                if (j < p.Length && p[j] == ',') { j++; while (j < p.Length && char.IsDigit(p[j])) j++; }
                if (j >= p.Length || p[j] != '}') return 0;
                min = a; len = j - i + 1;
            }
            else return 0;
            if (i + len < p.Length && p[i + len] == '?') len++;   // lazy
            return len;
        }
    }

    public class AhoCorasick
    {
        readonly Dictionary<long, int> go = new Dictionary<long, int>();
        readonly int[] rootGo = new int[128];
        readonly List<int> fail = new List<int>();
        readonly List<int> outId = new List<int>();
        readonly List<int> dict = new List<int>();
        readonly List<List<KeyValuePair<char, int>>> kids = new List<List<KeyValuePair<char, int>>>();
        public int Count;
        public AhoCorasick() { NewNode(); }
        int NewNode() { fail.Add(0); outId.Add(-1); dict.Add(0); kids.Add(null); return fail.Count - 1; }
        static long K(int node, char c) { return ((long)node << 16) | c; }
        public void Add(string lit, int id)
        {
            int node = 0;
            foreach (char c in lit)
            {
                int nx;
                if (!go.TryGetValue(K(node, c), out nx))
                {
                    nx = NewNode(); go[K(node, c)] = nx;
                    if (kids[node] == null) kids[node] = new List<KeyValuePair<char, int>>();
                    kids[node].Add(new KeyValuePair<char, int>(c, nx));
                }
                node = nx;
            }
            outId[node] = id;
            if (id + 1 > Count) Count = id + 1;
        }
        public void Build()
        {
            Queue<int> q = new Queue<int>();
            if (kids[0] != null) foreach (KeyValuePair<char, int> kv in kids[0]) { fail[kv.Value] = 0; dict[kv.Value] = 0; q.Enqueue(kv.Value); if (kv.Key < 128) rootGo[kv.Key] = kv.Value; }
            while (q.Count > 0)
            {
                int u = q.Dequeue();
                if (kids[u] == null) continue;
                foreach (KeyValuePair<char, int> kv in kids[u])
                {
                    int v = kv.Value, f = fail[u], t;
                    while (true)
                    {
                        if (go.TryGetValue(K(f, kv.Key), out t)) break;
                        if (f == 0) { t = 0; break; }
                        f = fail[f];
                    }
                    fail[v] = t == v ? 0 : t;
                    dict[v] = outId[fail[v]] >= 0 ? fail[v] : dict[fail[v]];
                    q.Enqueue(v);
                }
            }
            kids.Clear();
        }
        // marks every literal id that occurs in s[0..len) (after case folding)
        public bool[] Scan(string s, int len)
        {
            bool[] hit = new bool[Count];
            char[] fm = Lit.FoldMap;
            int node = 0;
            for (int i = 0; i < len; i++)
            {
                char c = fm[s[i]];
                if (c >= 128) { node = 0; continue; }
                while (true)
                {
                    int nx;
                    if (node == 0) { node = rootGo[c]; break; }
                    if (go.TryGetValue(K(node, c), out nx)) { node = nx; break; }
                    node = fail[node];
                }
                int t = outId[node] >= 0 ? node : dict[node];
                while (t != 0) { hit[outId[t]] = true; t = dict[t]; }
            }
            return hit;
        }
    }

    public class Cond { public string Field; public Regex Re; public bool Not; }

    public class Detection
    {
        public string Kind = "service";
        public string Name;
        public string Version = "";
        public string Category = "";
        public int Confidence;
        public string Cpe = "";
        public string Source = "";
        public string Field = "";
        public string Evidence = "";
        public string Flag = "";
        public string HostName = "";
        public string[] Implies;
        public string[] Excludes;
        public string[] Requires;
        public string[] RequiresCategory;
        public bool VersionOnly;   // only version-only outputs contributed so far (discarded unless a detection rule joins)
        public bool VoVersion;     // Version came from a version-only output
        public bool FixedVersion;  // Version is written into the rule (e.g. "1.5.0+" for a favicon), not captured
        public override string ToString() { return Name + (string.IsNullOrEmpty(Version) ? "" : " " + Version); }
    }

    public class Observation
    {
        public Dictionary<string, List<string>> F = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        public int Port;
        public void Add(string key, string value)
        {
            if (string.IsNullOrEmpty(key) || value == null) return;
            List<string> l;
            if (!F.TryGetValue(key, out l)) { l = new List<string>(); F[key] = l; }
            l.Add(value);
        }
        public bool Has(string key) { return F.ContainsKey(key); }
    }

    public static class Matcher
    {
        static List<Rule> rules = new List<Rule>();
        static Dictionary<string, List<Rule>> byField = new Dictionary<string, List<Rule>>(StringComparer.OrdinalIgnoreCase);
        static List<Rule> getRules = new List<Rule>();   // version-only rules with a fixed path (-VersionPaths)
        // first literal definition of each technology name: lets implied detections inherit kind/category/CPE
        static Dictionary<string, OutDef> nameInfo = new Dictionary<string, OutDef>(StringComparer.OrdinalIgnoreCase);
        // per-field literal prefilter (fields with enough literal-bearing rules); see Lit / AhoCorasick
        static Dictionary<string, AhoCorasick> fieldAc = new Dictionary<string, AhoCorasick>(StringComparer.OrdinalIgnoreCase);
        public static bool Prefilter = true;
        public static int PrefilterMinRules = 8;
        public static int PrefilteredRules { get { int n = 0; foreach (Rule r in rules) if (r.LitIds != null) n++; return n; } }
        public static int RegexTimeoutMs = 200;
        public static int MaxValueChars = 131072;
        static long timeouts;
        static readonly object sync = new object();
        public static long Timeouts { get { return System.Threading.Interlocked.Read(ref timeouts); } }
        public static int Count { get { return rules.Count; } }

        public static void Clear() { lock (sync) { rules = new List<Rule>(); getRules = new List<Rule>(); byField = new Dictionary<string, List<Rule>>(StringComparer.OrdinalIgnoreCase); nameInfo = new Dictionary<string, OutDef>(StringComparer.OrdinalIgnoreCase); fieldAc = new Dictionary<string, AhoCorasick>(StringComparer.OrdinalIgnoreCase); } }

        public static RulePack ReadPack(string json)
        {
            DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(RulePack));
            using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(json))) return (RulePack)ser.ReadObject(ms);
        }

        public static string WritePack(RulePack p)
        {
            DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(RulePack));
            using (MemoryStream ms = new MemoryStream()) { ser.WriteObject(ms, p); return Encoding.UTF8.GetString(ms.ToArray()); }
        }

        public static RegexOptions Opts(string o)
        {
            // default: ^/$ match at line breaks (Ruby/Recog semantics). 'a' = absolute anchors (JavaScript/Wappalyzer semantics).
            RegexOptions ro = RegexOptions.CultureInvariant;
            if (string.IsNullOrEmpty(o) || o.IndexOf('a') < 0) ro |= RegexOptions.Multiline;
            if (!string.IsNullOrEmpty(o))
            {
                if (o.IndexOf('i') >= 0) ro |= RegexOptions.IgnoreCase;
                if (o.IndexOf('s') >= 0) ro |= RegexOptions.Singleline;
            }
            return ro;
        }

        // Returns number of rules loaded; compile failures are appended to errors (rule skipped, never fatal).
        public static int Load(RulePack pack, List<string> errors)
        {
            int n = 0;
            if (pack == null || pack.Rules == null) return 0;
            List<Rule> add = new List<Rule>();
            int idx = 0;
            foreach (RuleDef d in pack.Rules)
            {
                idx++;
                if (d == null || string.IsNullOrEmpty(d.F) || d.R == null) { errors.Add(pack.Name + "#" + idx + ": missing field or pattern"); continue; }
                Rule r = new Rule();
                r.Id = string.IsNullOrEmpty(d.Id) ? pack.Name + "#" + idx : d.Id;
                r.Field = d.F.Trim();
                r.Src = string.IsNullOrEmpty(d.Src) ? pack.Name : d.Src;
                r.Ports = d.Ports;
                r.Ex = d.Ex; r.Exv = d.Exv;
                try { r.Re = new Regex(d.R, Opts(d.O), TimeSpan.FromMilliseconds(RegexTimeoutMs)); }
                catch (Exception ex) { errors.Add(r.Id + ": regex compile failed: " + ex.Message); continue; }
                r.B64 = !string.IsNullOrEmpty(d.O) && d.O.IndexOf('b') >= 0;
                // literals of a base64 rule are in the decoded text, not in the value the prefilter scans
                if (r.B64) r.Lits = null; else { try { r.Lits = Lit.Requirement(d.R); } catch { r.Lits = null; } }
                if (d.And != null)
                {
                    List<Cond> cs = new List<Cond>(); bool bad = false;
                    foreach (CondDef cd in d.And)
                    {
                        try
                        {
                            Cond c = new Cond(); c.Field = cd.F; c.Not = cd.Not;
                            c.Re = new Regex(cd.R ?? "", Opts(cd.O), TimeSpan.FromMilliseconds(RegexTimeoutMs));
                            cs.Add(c);
                        }
                        catch (Exception ex) { errors.Add(r.Id + ": condition regex failed: " + ex.Message); bad = true; }
                    }
                    if (bad) continue;
                    r.And = cs.ToArray();
                }
                if (d.Out != null && d.Out.Length > 0) r.Out = d.Out;
                else
                {
                    OutDef o = new OutDef();
                    o.T = d.T; o.N = d.N; o.C = d.C; o.V = d.V; o.P = d.P; o.K = d.K; o.Im = d.Im; o.Xs = d.Xs; o.Rq = d.Rq; o.Rc = d.Rc; o.Flag = d.Flag; o.Vo = d.Vo;
                    r.Out = new OutDef[] { o };
                }
                bool any = false;
                foreach (OutDef o in r.Out) if (!string.IsNullOrEmpty(o.N) || !string.IsNullOrEmpty(o.Flag)) any = true;
                if (!any) { errors.Add(r.Id + ": no output name/flag"); continue; }
                if (!string.IsNullOrEmpty(d.Get))
                {
                    string why = GetProblem(d.Get, r.Field);
                    foreach (OutDef o in r.Out) if (!o.Vo || string.IsNullOrEmpty(o.N)) why = why ?? "only version-only outputs may name a path";
                    if (why != null) { errors.Add(r.Id + ": get '" + d.Get + "': " + why); continue; }
                    r.Get = d.Get;
                }
                add.Add(r); n++;
            }
            lock (sync)
            {
                List<Rule> nr = new List<Rule>(rules); nr.AddRange(add);
                Dictionary<string, OutDef> ni = new Dictionary<string, OutDef>(nameInfo, StringComparer.OrdinalIgnoreCase);
                foreach (Rule r in add)
                    foreach (OutDef o in r.Out)
                        if (!o.Vo && !string.IsNullOrEmpty(o.N) && o.N.IndexOf('{') < 0 && !ni.ContainsKey(o.N) && (!string.IsNullOrEmpty(o.C) || !string.IsNullOrEmpty(o.T))) ni[o.N] = o;
                nameInfo = ni;
                List<Rule> ng = new List<Rule>(getRules);
                foreach (Rule r in add) if (r.Get != null) ng.Add(r);
                getRules = ng;
                Dictionary<string, List<Rule>> nb = new Dictionary<string, List<Rule>>(StringComparer.OrdinalIgnoreCase);
                foreach (Rule r in nr)
                {
                    List<Rule> l;
                    if (!nb.TryGetValue(r.Field, out l)) { l = new List<Rule>(); nb[r.Field] = l; }
                    l.Add(r);
                }
                // literal prefilter automata, one per field (literal ids are per field)
                Dictionary<string, AhoCorasick> na = new Dictionary<string, AhoCorasick>(StringComparer.OrdinalIgnoreCase);
                foreach (KeyValuePair<string, List<Rule>> kv in nb)
                {
                    int withLit = 0;
                    foreach (Rule r in kv.Value) { r.LitIds = null; if (r.Lits != null) withLit++; }
                    if (withLit < PrefilterMinRules) continue;
                    AhoCorasick ac = new AhoCorasick();
                    Dictionary<string, int> ids = new Dictionary<string, int>(StringComparer.Ordinal);
                    foreach (Rule r in kv.Value)
                    {
                        if (r.Lits == null) continue;
                        int[][] li = new int[r.Lits.Length][];
                        for (int t = 0; t < r.Lits.Length; t++)
                        {
                            li[t] = new int[r.Lits[t].Length];
                            for (int q = 0; q < r.Lits[t].Length; q++)
                            {
                                string l = r.Lits[t][q]; int id;
                                if (!ids.TryGetValue(l, out id)) { id = ids.Count; ids[l] = id; ac.Add(l, id); }
                                li[t][q] = id;
                            }
                        }
                        r.LitIds = li;
                    }
                    ac.Build();
                    na[kv.Key] = ac;
                }
                rules = nr; byField = nb; fieldAc = na;
            }
            return n;
        }

        static Match SafeMatch(Regex re, string v)
        {
            try
            {
                if (v.Length > MaxValueChars) v = v.Substring(0, MaxValueChars);
                return re.Match(v);
            }
            catch (RegexMatchTimeoutException) { System.Threading.Interlocked.Increment(ref timeouts); return null; }
        }

        static bool CondsOk(Rule r, Observation obs)
        {
            if (r.And == null) return true;
            foreach (Cond c in r.And)
            {
                bool hit = false;
                List<string> vals;
                if (obs.F.TryGetValue(c.Field, out vals))
                    foreach (string v in vals) { Match m = SafeMatch(c.Re, v); if (m != null && m.Success) { hit = true; break; } }
                if (hit == c.Not) return false;
            }
            return true;
        }

        static readonly Regex Tpl = new Regex(@"\{(\w+)\}", RegexOptions.CultureInvariant);

        // UTF-8 text of a base64 value (standard or URL alphabet, padding optional); null when it is not base64
        public static string FromBase64(string v)
        {
            if (string.IsNullOrEmpty(v)) return null;
            string t = v.Trim().Replace('-', '+').Replace('_', '/');
            if (t.Length == 0 || t.Length > 65536) return null;
            if (t.Length % 4 == 2) t += "=="; else if (t.Length % 4 == 3) t += "=";
            try { return new UTF8Encoding(false, true).GetString(Convert.FromBase64String(t)); }
            catch { return null; }
        }

        public static string Expand(string tpl, Match m)
        {
            if (string.IsNullOrEmpty(tpl)) return "";
            string s = Tpl.Replace(tpl, delegate(Match t)
            {
                string k = t.Groups[1].Value;
                int gi;
                if (int.TryParse(k, out gi)) return gi < m.Groups.Count && m.Groups[gi].Success ? m.Groups[gi].Value : "";
                if (k == "v") return t.Value;  // CPE placeholder, resolved later
                Group g = m.Groups[k];
                return (g != null && g.Success) ? g.Value : "";
            });
            return s.Trim();
        }

        // cpe:/a:vendor:product:ver  or  cpe:2.3:a:vendor:product:ver:...  -> CPE 2.3 formatted string
        public static string NormalizeCpe(string cpe, string version)
        {
            if (string.IsNullOrEmpty(cpe)) return "";
            string ver = string.IsNullOrEmpty(version) ? "*" : version.Replace(" ", "_").Replace(":", "\\:");
            cpe = cpe.Replace("{v}", ver);
            string[] parts;
            if (cpe.StartsWith("cpe:/")) parts = ("2.3:" + cpe.Substring(5)).Split(':');
            else if (cpe.StartsWith("cpe:2.3:")) parts = cpe.Substring(4).Split(':');
            else return cpe;
            string[] o = new string[12];
            for (int i = 0; i < 12; i++) o[i] = (i < parts.Length && parts[i].Length > 0) ? parts[i] : "*";
            if ((o[4] == "*" || o[4] == "-") && ver != "*") o[4] = ver;
            if (o[4] == "-" ) o[4] = "*";
            return "cpe:" + string.Join(":", o);
        }

        // "part:vendor:product" (lower case, escapes removed) of a CPE 2.3 formatted string or a cpe:/ URI; "" otherwise
        public static string CpeKey(string cpe)
        {
            if (string.IsNullOrEmpty(cpe)) return "";
            List<string> f = new List<string>();
            if (cpe.StartsWith("cpe:2.3:", StringComparison.OrdinalIgnoreCase))
            {
                StringBuilder cur = new StringBuilder();
                for (int i = 8; i < cpe.Length && f.Count < 3; i++)
                {
                    char c = cpe[i];
                    if (c == '\\' && i + 1 < cpe.Length) { cur.Append(cpe[++i]); continue; }
                    if (c == ':') { f.Add(cur.ToString()); cur.Length = 0; continue; }
                    cur.Append(c);
                }
                if (f.Count < 3) f.Add(cur.ToString());
            }
            else if (cpe.StartsWith("cpe:/", StringComparison.OrdinalIgnoreCase)) f.AddRange(Uri.UnescapeDataString(cpe.Substring(5)).Split(':'));
            if (f.Count < 3) return "";
            return (f[0] + ":" + f[1] + ":" + f[2]).ToLowerInvariant();
        }

        // Completes rule CPEs from the reviewed supplement (src/cpe-supplement.json, embedded in the script) when a pack is
        // imported: "fill" gives products whose rules carry no CPE their NVD name; "replace" corrects a known-wrong upstream
        // CPE, and only while the rule still carries exactly that one. Returns { filled, replaced }.
        public static int[] ApplyCpeSupplement(RulePack pack, string supplementJson)
        {
            int filled = 0, replaced = 0;
            Dictionary<string, object> root = Json.Parse(supplementJson) as Dictionary<string, object>;
            Dictionary<string, string> fill = new Dictionary<string, string>(StringComparer.Ordinal);
            Dictionary<string, string[]> repl = new Dictionary<string, string[]>(StringComparer.Ordinal);
            object o;
            if (root != null && root.TryGetValue("fill", out o) && o is List<object>)
                foreach (object e in (List<object>)o)
                {
                    Dictionary<string, object> d = e as Dictionary<string, object>;
                    if (d != null) fill[Convert.ToString(d["t"]) + "|" + Convert.ToString(d["n"])] = Convert.ToString(d["p"]);
                }
            if (root != null && root.TryGetValue("replace", out o) && o is List<object>)
                foreach (object e in (List<object>)o)
                {
                    Dictionary<string, object> d = e as Dictionary<string, object>;
                    if (d != null) repl[Convert.ToString(d["n"])] = new[] { Convert.ToString(d["was"]), Convert.ToString(d["p"]) };
                }
            if (pack == null || pack.Rules == null) return new[] { 0, 0 };
            foreach (RuleDef r in pack.Rules)
            {
                if (r == null) continue;
                if (r.Out != null && r.Out.Length > 0)
                {
                    foreach (OutDef od in r.Out)
                    {
                        if (od == null) continue;
                        string p = od.P;
                        int how = Supplement(od.T, od.N, od.V, ref p, fill, repl);
                        if (how != 0) { od.P = p; if (how == 1) filled++; else replaced++; }
                    }
                }
                else
                {
                    string p = r.P;
                    int how = Supplement(r.T, r.N, r.V, ref p, fill, repl);
                    if (how != 0) { r.P = p; if (how == 1) filled++; else replaced++; }
                }
            }
            return new[] { filled, replaced };
        }

        static int Supplement(string kind, string name, string version, ref string cpe, Dictionary<string, string> fill, Dictionary<string, string[]> repl)
        {
            if (string.IsNullOrEmpty(name) || name.IndexOf('{') >= 0) return 0;
            // a version written into the rule ("11" for an IOS login realm) is a guess, not an observation: no CPE is added,
            // because the CPE would carry it into the vulnerability join
            if (string.IsNullOrEmpty(cpe) && !string.IsNullOrEmpty(version) && version.IndexOf('{') < 0) return 0;
            string[] rp;
            if (!string.IsNullOrEmpty(cpe))
            {
                if (repl.TryGetValue(name, out rp) && CpeKey(cpe) == rp[0]) { cpe = rp[1].Length > 0 ? rp[1] : null; return 2; }
                return 0;
            }
            string fp;
            if (fill.TryGetValue((string.IsNullOrEmpty(kind) ? "service" : kind) + "|" + name, out fp)) { cpe = fp; return 1; }
            return 0;
        }

        // a fixed absolute path (no query, no dot segments, no doubled slash, conservative characters) that the rule's field reads
        static readonly Regex GetPath = new Regex(@"^(?:/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+/?$", RegexOptions.CultureInvariant);
        static string GetProblem(string get, string field)
        {
            if (get.Length > 200) return "longer than 200 characters";
            if (!GetPath.IsMatch(get) || get.Contains("/.") || get.Contains("//")) return "not a plain absolute path";
            if (!field.StartsWith("path:" + get + ".", StringComparison.Ordinal)) return "the rule's field must be path:" + get + ".<part>";
            return null;
        }

        // -VersionPaths: the paths of version-only rules whose product was detected (same kind, and the same CPE product or
        // name, at the reporting confidence) without a version a detection rule captured; at most max, in rule order
        public static string[] VersionPaths(List<Detection> dets, int minConfidence, int max)
        {
            List<string> res = new List<string>();
            List<Rule> gr = getRules;
            if (dets == null || gr.Count == 0 || max <= 0) return res.ToArray();
            foreach (Rule r in gr)
            {
                if (res.Contains(r.Get)) continue;
                bool need = false;
                foreach (OutDef o in r.Out)
                {
                    string kind = string.IsNullOrEmpty(o.T) ? "service" : o.T;
                    string ok = CpeKey(o.P);
                    foreach (Detection d in dets)
                    {
                        if (d.VersionOnly || d.Kind != kind || d.Confidence < minConfidence) continue;
                        if (d.Version.Length > 0 && !d.FixedVersion) continue;
                        if ((ok.Length > 0 && CpeKey(d.Cpe) == ok) || string.Equals(d.Name, o.N, StringComparison.OrdinalIgnoreCase)) { need = true; break; }
                    }
                    if (need) break;
                }
                if (need) { res.Add(r.Get); if (res.Count >= max) break; }
            }
            return res.ToArray();
        }

        static string MergeKey(Detection d)
        {
            if (!string.IsNullOrEmpty(d.Cpe))
            {
                string[] p = d.Cpe.Split(':');
                if (p.Length > 5) return d.Kind + "|" + p[2] + ":" + p[3] + ":" + p[4];
            }
            return d.Kind + "|" + (d.Name ?? d.Flag ?? "").ToLowerInvariant();
        }

        public static List<Detection> Evaluate(Observation obs)
        {
            List<Detection> raw = new List<Detection>();
            Dictionary<string, List<Rule>> bf = byField;
            Dictionary<string, AhoCorasick> fa = fieldAc;
            bool pre = Prefilter;
            foreach (KeyValuePair<string, List<string>> kv in obs.F)
            {
                List<Rule> list;
                if (!bf.TryGetValue(kv.Key, out list)) continue;
                AhoCorasick ac = null;
                if (pre) fa.TryGetValue(kv.Key, out ac);
                bool[][] present = ac != null ? new bool[kv.Value.Count][] : null;
                foreach (Rule r in list)
                {
                    if (r.Ports != null && r.Ports.Length > 0 && Array.IndexOf(r.Ports, obs.Port) < 0) continue;
                    for (int vi = 0; vi < kv.Value.Count; vi++)
                    {
                        string v = kv.Value[vi];
                        if (v == null) continue;
                        if (ac != null && r.LitIds != null)
                        {
                            // a value that does not satisfy the rule's literal requirement cannot match: skip the regex (identical outcome)
                            bool[] h = present[vi];
                            if (h == null) { h = ac.Scan(v, Math.Min(v.Length, MaxValueChars)); present[vi] = h; }
                            bool ok = false;
                            foreach (int[] t in r.LitIds)
                            {
                                bool all = true;
                                foreach (int id in t) if (!h[id]) { all = false; break; }
                                if (all) { ok = true; break; }
                            }
                            if (!ok) continue;
                        }
                        if (r.B64) { v = FromBase64(v); if (v == null) continue; }
                        Match m = SafeMatch(r.Re, v);
                        if (m == null || !m.Success) continue;
                        if (!CondsOk(r, obs)) break;
                        foreach (OutDef o in r.Out)
                        {
                            Detection d = new Detection();
                            d.Kind = string.IsNullOrEmpty(o.T) ? (string.IsNullOrEmpty(o.N) ? "flag" : "service") : o.T;
                            d.Name = Expand(o.N, m);
                            d.Flag = o.Flag ?? "";
                            if (string.IsNullOrEmpty(d.Name) && d.Kind != "flag") continue;
                            d.Version = Expand(o.V, m);
                            d.FixedVersion = d.Version.Length > 0 && o.V.IndexOf('{') < 0;
                            d.Category = o.C ?? "";
                            d.Confidence = o.K > 0 ? Math.Min(100, o.K) : 85;
                            d.Cpe = NormalizeCpe(Expand(o.P, m), d.Version);
                            d.Source = r.Src;
                            d.Field = kv.Key;
                            string ev = m.Value; if (ev.Length > 120) ev = ev.Substring(0, 120);
                            d.Evidence = kv.Key + "=" + ev;
                            d.HostName = Expand(o.H, m);
                            d.Implies = o.Im; d.Excludes = o.Xs; d.Requires = o.Rq; d.RequiresCategory = o.Rc;
                            if (o.Vo)
                            {
                                if (string.IsNullOrEmpty(d.Version)) continue;
                                d.VersionOnly = true; d.VoVersion = true; d.Confidence = 0;
                                d.Implies = null; d.Excludes = null; d.Requires = null; d.RequiresCategory = null; d.Flag = "";
                            }
                            raw.Add(d);
                        }
                        break;
                    }
                }
            }
            return Aggregate(raw);
        }

        public static List<Detection> Aggregate(List<Detection> raw)
        {
            Dictionary<string, Detection> m0 = new Dictionary<string, Detection>(StringComparer.OrdinalIgnoreCase);
            List<string> order0 = new List<string>();
            foreach (Detection d in raw) MergeInto(m0, order0, d);
            // second pass: same kind+name reached via different CPE spellings (e.g. microsoft:iis vs microsoft:internet_information_services)
            Dictionary<string, Detection> m = new Dictionary<string, Detection>(StringComparer.OrdinalIgnoreCase);
            List<string> order = new List<string>();
            foreach (string k0 in order0)
            {
                Detection d = m0[k0];
                string nk = d.Kind + "|" + (d.Name ?? d.Flag ?? "").ToLowerInvariant();
                Detection e;
                if (m.TryGetValue(nk, out e)) Merge(e, d); else { m[nk] = d; order.Add(nk); }
            }
            // third pass: same CPE product + same version from different vendor spellings (mortbay:jetty vs eclipse:jetty)
            Dictionary<string, Detection> m3 = new Dictionary<string, Detection>(StringComparer.OrdinalIgnoreCase);
            List<string> order3 = new List<string>();
            foreach (string k in order)
            {
                Detection d = m[k];
                string key = k;
                if (!string.IsNullOrEmpty(d.Cpe) && !string.IsNullOrEmpty(d.Version))
                {
                    string[] cp = d.Cpe.Split(':');
                    if (cp.Length > 5) key = d.Kind + "|cpeprod|" + cp[4] + "|" + d.Version;
                }
                Detection e;
                if (m3.TryGetValue(key, out e)) Merge(e, d); else { m3[key] = d; order3.Add(key); }
            }
            m = m3; order = order3;
            // implies (bounded fan-out)
            for (int pass = 0; pass < 4; pass++)
            {
                bool added = false;
                foreach (string key in new List<string>(order))
                {
                    Detection d = m[key];
                    if (d.Implies == null) continue;
                    foreach (string im in d.Implies)
                    {
                        if (string.IsNullOrEmpty(im)) continue;
                        Detection x = new Detection(); x.Name = im; x.Confidence = d.Confidence; x.Source = "implied:" + d.Name; x.Field = "implies";
                        OutDef info;
                        if (nameInfo.TryGetValue(im, out info))
                        {
                            if (!string.IsNullOrEmpty(info.T)) x.Kind = info.T;
                            x.Category = info.C ?? "";
                            if (!string.IsNullOrEmpty(info.P) && info.P.IndexOf('{') < 0) x.Cpe = NormalizeCpe(info.P, "");
                            else if (!string.IsNullOrEmpty(info.P)) x.Cpe = NormalizeCpe(Tpl.Replace(info.P, "*"), "");
                        }
                        string k2 = MergeKey(x);
                        Detection vo = VersionOnlyFor(m, k2, im);
                        if (vo != null) { Merge(vo, x); added = true; }
                        else if (!m.ContainsKey(k2) && !NameExists(m, im)) { MergeInto(m, order, x); added = true; }
                    }
                }
                if (!added) break;
            }
            // version-only outputs that no detection rule joined are discarded
            order.RemoveAll(delegate(string k) { return m[k].VersionOnly; });
            // excludes / requires
            HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string k in order) names.Add(m[k].Name ?? "");
            HashSet<string> cats = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string k in order) { Detection d = m[k]; if (!string.IsNullOrEmpty(d.Category) && d.RequiresCategory == null) cats.Add(d.Category); }
            HashSet<string> drop = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string k in order)
            {
                Detection d = m[k];
                if (d.Excludes != null) foreach (string x in d.Excludes) if (!string.IsNullOrEmpty(x)) drop.Add(x);
                if (d.Requires != null) foreach (string q in d.Requires) if (!string.IsNullOrEmpty(q) && !names.Contains(q)) drop.Add(d.Name);
                if (d.RequiresCategory != null && d.RequiresCategory.Length > 0)
                {
                    bool ok = false;
                    foreach (string c in d.RequiresCategory) if (!string.IsNullOrEmpty(c) && cats.Contains(c)) { ok = true; break; }
                    if (!ok) drop.Add(d.Name);
                }
            }
            List<Detection> outl = new List<Detection>();
            foreach (string k in order) { Detection d = m[k]; if (!drop.Contains(d.Name ?? "")) outl.Add(d); }
            outl.Sort(delegate(Detection a, Detection b)
            {
                int c = b.Confidence.CompareTo(a.Confidence);
                return c != 0 ? c : string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
            });
            return outl;
        }

        static bool NameExists(Dictionary<string, Detection> m, string name)
        {
            foreach (Detection d in m.Values) if (!d.VersionOnly && string.Equals(d.Name, name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        // a still version-only detection that an implied product with this key or name would join
        static Detection VersionOnlyFor(Dictionary<string, Detection> m, string key, string name)
        {
            Detection d;
            if (m.TryGetValue(key, out d)) return d.VersionOnly ? d : null;
            if (NameExists(m, name)) return null;
            foreach (Detection x in m.Values) if (x.VersionOnly && string.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase)) return x;
            return null;
        }

        static void MergeInto(Dictionary<string, Detection> m, List<string> order, Detection d)
        {
            string k = MergeKey(d);
            Detection e;
            if (!m.TryGetValue(k, out e)) { m[k] = d; order.Add(k); return; }
            Merge(e, d);
        }

        static void Merge(Detection e, Detection d)
        {
            if (e.VersionOnly && !d.VersionOnly)
            {
                // a detection rule joins what so far only version-only outputs contributed: it takes over the identity,
                // and the version-only contribution is then merged into it like any other
                Detection v = new Detection();
                v.Kind = e.Kind; v.Name = e.Name; v.Version = e.Version; v.Cpe = e.Cpe; v.Source = e.Source; v.Field = e.Field;
                v.Evidence = e.Evidence; v.VersionOnly = true; v.VoVersion = e.VoVersion; v.Confidence = 0;
                e.Kind = d.Kind; e.Name = d.Name; e.Category = d.Category; e.Confidence = d.Confidence; e.Cpe = d.Cpe; e.Flag = d.Flag;
                e.Source = d.Source; e.Field = d.Field; e.Evidence = d.Evidence; e.HostName = d.HostName;
                e.Implies = d.Implies; e.Excludes = d.Excludes; e.Requires = d.Requires; e.RequiresCategory = d.RequiresCategory;
                e.Version = d.Version; e.VoVersion = d.VoVersion; e.FixedVersion = d.FixedVersion; e.VersionOnly = false;
                d = v;
            }
            if (d.Confidence > e.Confidence)
            {
                e.Confidence = d.Confidence;
                if (!string.IsNullOrEmpty(d.Name)) e.Name = d.Name;
                if (!string.IsNullOrEmpty(d.Cpe)) e.Cpe = d.Cpe;
                if (!string.IsNullOrEmpty(d.Category)) e.Category = d.Category;
            }
            // the longer version wins; when a version-only rule takes part, a version captured by a detection rule beats it,
            // and it beats one written into a rule (a favicon's "1.5.0+")
            if (!string.IsNullOrEmpty(d.Version) && (string.IsNullOrEmpty(e.Version)
                || ((e.VoVersion || d.VoVersion) && VersionRank(e) != VersionRank(d) ? VersionRank(d) > VersionRank(e) : d.Version.Length > e.Version.Length)))
            {
                e.Version = d.Version; e.VoVersion = d.VoVersion; e.FixedVersion = d.FixedVersion;
                if (!string.IsNullOrEmpty(d.Cpe)) e.Cpe = d.Cpe;
            }
            e.VersionOnly = e.VersionOnly && d.VersionOnly;
            if (string.IsNullOrEmpty(e.Cpe)) e.Cpe = d.Cpe;
            if (string.IsNullOrEmpty(e.Category)) e.Category = d.Category;
            if (!string.IsNullOrEmpty(d.Flag))
            {
                if (string.IsNullOrEmpty(e.Flag)) e.Flag = d.Flag;
                else if ((";" + e.Flag + ";").IndexOf(";" + d.Flag + ";", StringComparison.OrdinalIgnoreCase) < 0) e.Flag += ";" + d.Flag;
            }
            if (string.IsNullOrEmpty(e.HostName)) e.HostName = d.HostName;
            if (!string.IsNullOrEmpty(d.Source) && e.Source.IndexOf(d.Source, StringComparison.OrdinalIgnoreCase) < 0) e.Source += "+" + d.Source;
            if (!string.IsNullOrEmpty(d.Evidence) && e.Evidence.Length < 400 && e.Evidence.IndexOf(d.Evidence, StringComparison.Ordinal) < 0) e.Evidence += " | " + d.Evidence;
            e.Implies = Union(e.Implies, d.Implies); e.Excludes = Union(e.Excludes, d.Excludes); e.Requires = Union(e.Requires, d.Requires);
            // the gate only survives a merge if every contributing rule was gated
            if (!d.VersionOnly && e.RequiresCategory != null && d.RequiresCategory == null) e.RequiresCategory = null;
            // a version-bearing CPE is never overwritten by a version-less one
            if (!string.IsNullOrEmpty(e.Cpe) && !string.IsNullOrEmpty(e.Version)) e.Cpe = NormalizeCpe(e.Cpe, e.Version);
        }

        static int VersionRank(Detection x) { return x.VoVersion ? 2 : (x.FixedVersion ? 1 : 3); }

        static string[] Union(string[] a, string[] b)
        {
            if (a == null) return b; if (b == null) return a;
            List<string> l = new List<string>(a); foreach (string x in b) if (!l.Contains(x)) l.Add(x); return l.ToArray();
        }

        // Self-test of the loaded rule packs: every rule that carries an example must match it (and yield the expected version).
        public static List<string> TestExamples(out int tested)
        {
            List<string> fails = new List<string>();
            tested = 0;
            foreach (Rule r in rules)
            {
                if (r.Ex == null) continue;
                tested++;
                Match mm = SafeMatch(r.Re, r.B64 ? (FromBase64(r.Ex) ?? "") : r.Ex);
                if (mm == null || !mm.Success) { fails.Add(r.Id + ": example did not match: " + r.Ex); continue; }
                // the prefilter must never hide a match: the required literal has to occur in every matching example
                if (r.Lits != null && !Lit.Satisfies(r.Lits, Lit.Fold(r.Ex))) fails.Add(r.Id + ": prefilter requirement not met by its matching example");
                if (!string.IsNullOrEmpty(r.Exv))
                {
                    string v = "";
                    foreach (OutDef o in r.Out) { string vv = Expand(o.V, mm); if (!string.IsNullOrEmpty(vv)) { v = vv; break; } }
                    if (v != r.Exv) fails.Add(r.Id + ": version '" + v + "' != expected '" + r.Exv + "'");
                }
            }
            return fails;
        }

        // JavaScript (Wappalyzer) regex dialect -> .NET: JS treats \<letter> it does not know as that letter; [^] is "any char"
        // escapes JavaScript itself understands (all of which mean the same in .NET); any other \<letter> is a literal letter in JS
        const string NetEscapes = "bBcdDfknpPrsStuvwWx0123456789";
        public static string FromJs(string p)
        {
            if (p == null) return null;
            StringBuilder sb = new StringBuilder(p.Length + 8);
            for (int i = 0; i < p.Length; i++)
            {
                char c = p[i];
                if (c == '[' && i + 2 < p.Length && p[i + 1] == '^' && p[i + 2] == ']') { sb.Append(@"[\s\S]"); i += 2; continue; }
                if (c != '\\' || i + 1 >= p.Length) { sb.Append(c); continue; }
                char n = p[++i];
                if ((char.IsLetter(n) || n == '_') && NetEscapes.IndexOf(n) < 0) sb.Append(n);
                else sb.Append('\\').Append(n);
            }
            return sb.ToString();
        }

        // Ruby (Recog) regex dialect -> .NET
        static readonly Regex InlineFlags = new Regex(@"\(\?([imx]*)(?:-([imx]*))?(:|\))", RegexOptions.CultureInvariant);
        public static string FromRuby(string p)
        {
            if (p == null) return null;
            // escape scanner: Ruby accepts escapes of word characters that .NET rejects (\_ etc.)
            StringBuilder sb = new StringBuilder(p.Length + 16);
            bool inClass = false;
            for (int i = 0; i < p.Length; i++)
            {
                char c = p[i];
                if (c != '\\' || i + 1 >= p.Length)
                {
                    if (c == '[' && !inClass) inClass = true;
                    else if (c == ']' && inClass && i > 0 && p[i - 1] != '[' && p[i - 1] != '^') inClass = false;
                    sb.Append(c);
                    continue;
                }
                char n = p[++i];
                switch (n)
                {
                    case 'h': sb.Append(inClass ? "0-9A-Fa-f" : "[0-9A-Fa-f]"); break;
                    case 'H': sb.Append(inClass ? @"\H" : "[^0-9A-Fa-f]"); break;
                    case 'R': sb.Append(@"(?:\r\n|[\n\v\f\r\x85" + "\\" + "u2028" + "\\" + "u2029])"); break;
                    case '_': sb.Append('_'); break;
                    default: sb.Append('\\').Append(n); break;
                }
            }
            string s = sb.ToString();
            s = s.Replace("[:alpha:]", "a-zA-Z").Replace("[:digit:]", "0-9").Replace("[:alnum:]", "a-zA-Z0-9").Replace("[:space:]", @"\s")
                 .Replace("[:upper:]", "A-Z").Replace("[:lower:]", "a-z").Replace("[:xdigit:]", "0-9A-Fa-f").Replace("[:print:]", @"\x20-\x7E")
                 .Replace("[:punct:]", @"!-/:-@\[-`{-~").Replace("[:word:]", @"\w").Replace("[:blank:]", @" \t").Replace("[:cntrl:]", @"\x00-\x1F");
            // Ruby (?m) == .NET (?s); Ruby ^/$ are always line-anchored (we always set Multiline)
            s = InlineFlags.Replace(s, delegate(Match m)
            {
                string on = m.Groups[1].Value.Replace('m', 's');
                string off = m.Groups[2].Success ? m.Groups[2].Value.Replace('m', 's') : null;
                return "(?" + on + (off != null ? "-" + off : "") + m.Groups[3].Value;
            });
            return s;
        }
    }

    // ------------------------------------------------------------------ Minimal JSON reader (case-sensitive keys; for rule import)
    public static class Json
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
            return double.Parse(s.Substring(st, i - st), System.Globalization.CultureInfo.InvariantCulture);
        }
        static string Str(string s, ref int i)
        {
            if (s[i] != '"') throw new FormatException("expected string at " + i);
            i++;
            StringBuilder sb = new StringBuilder();
            while (i < s.Length)
            {
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                char e = s[i++];
                switch (e)
                {
                    case 'n': sb.Append('\n'); break;
                    case 't': sb.Append('\t'); break;
                    case 'r': sb.Append('\r'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'u': sb.Append((char)Convert.ToInt32(s.Substring(i, 4), 16)); i += 4; break;
                    default: sb.Append(e); break;
                }
            }
            throw new FormatException("unterminated string");
        }
    }

    // ------------------------------------------------------------------ Version advisories (passive, version-based)
    public static class Advisory
    {
        // "8.3.10" -> [8,3,10]; null if not numeric
        public static int[] Parse(string v)
        {
            if (string.IsNullOrEmpty(v)) return null;
            string[] p = v.Split('.');
            int[] o = new int[Math.Max(3, p.Length)];
            for (int i = 0; i < p.Length; i++) { int x; if (!int.TryParse(p[i], out x) || x < 0) return null; o[i] = x; }
            return o;
        }

        public static int Compare(int[] a, int[] b)
        {
            int n = Math.Max(a.Length, b.Length);
            for (int i = 0; i < n; i++)
            {
                int x = i < a.Length ? a[i] : 0, y = i < b.Length ? b[i] : 0;
                if (x != y) return x < y ? -1 : 1;
            }
            return 0;
        }

        // fixed: first fixed release per maintained branch (e.g. 8.5.12, 8.4.27, 8.3.36, 8.2.35); minBranch: oldest branch that got a fix.
        // Returns: vulnerable | eol | fixed | newer | unknown
        public static string Status(string version, string[] fixedVersions, string minBranch)
        {
            int[] v = Parse(version);
            if (v == null) return "unknown";
            int[] mb = Parse(minBranch);
            if (mb != null && (v[0] < mb[0] || (v[0] == mb[0] && v[1] < mb[1]))) return "eol";
            int[] newest = null;
            foreach (string f in fixedVersions)
            {
                int[] fv = Parse(f);
                if (fv == null) continue;
                if (newest == null || Compare(fv, newest) > 0) newest = fv;
                if (fv[0] == v[0] && fv[1] == v[1]) return Compare(v, fv) < 0 ? "vulnerable" : "fixed";
            }
            // a branch between fixed branches with no listed fix (e.g. unreleased) is treated as unknown; above all fixed branches = newer
            if (newest != null && (v[0] > newest[0] || (v[0] == newest[0] && v[1] > newest[1]))) return "newer";
            return "unknown";
        }
    }

    // ------------------------------------------------------------------ Scope / exclusion sets
    // ------------------------------------------------------------------ HTTP response parsing / HTML extraction
    // Ports of the worker's PowerShell parsing with the same regexes and options (PowerShell's -match is IgnoreCase in the
    // current culture; [regex]::Match uses the pattern's inline options only), so results are identical, just faster.
    public class HttpResp
    {
        public bool IsHttp;
        public int Code;
        public System.Collections.Hashtable Headers = new System.Collections.Hashtable(StringComparer.OrdinalIgnoreCase);
        public List<string[]> List = new List<string[]>();
        public byte[] Body = new byte[0];
        public string Text = "";
        public string Banner = "";
        string title; List<string[]> metas; List<string> scripts;
        public string Title { get { if (title == null) title = Html.Title(Text); return title; } }
        public List<string[]> Metas { get { if (metas == null) metas = Html.Metas(Text); return metas; } }
        public List<string> Scripts { get { if (scripts == null) scripts = Html.ScriptSrcs(Text); return scripts; } }
    }

    public static class Html
    {
        static readonly Regex StatusRe = new Regex(@"^HTTP/\d(?:\.\d)?\s+(\d{3})", RegexOptions.IgnoreCase);
        static readonly Regex CtCharset = new Regex("charset\\s*=\\s*\"?([\\w\\-]+)", RegexOptions.IgnoreCase);
        static readonly Regex MetaCharset = new Regex("<meta[^>]+charset\\s*=\\s*[\"']?([\\w\\-]+)", RegexOptions.IgnoreCase);
        static readonly Regex TitleRe = new Regex(@"(?is)<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase);
        static readonly Regex Ws = new Regex(@"\s+", RegexOptions.IgnoreCase);
        static readonly Regex MetaTag = new Regex(@"(?is)<meta\s[^>]*>");
        static readonly Regex MetaName = new Regex("(?is)\\b(?:name|property|http-equiv)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))");
        static readonly Regex MetaContent = new Regex("(?is)\\bcontent\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))");
        static readonly Regex ScriptSrc = new Regex("(?is)<script[^>]+\\bsrc\\s*=\\s*[\"']?([^\"'\\s>]+)");

        public static HttpResp Parse(byte[] raw)
        {
            HttpResp o = new HttpResp();
            if (raw != null && raw.Length >= 5 && raw[0] == 72 && raw[1] == 84 && raw[2] == 84 && raw[3] == 80 && raw[4] == 47)
            {
                string head;
                o.Body = Net.Body(raw, out head);
                string[] lines = Regex.Split(head, "\r?\n");
                o.IsHttp = true;
                Match m = StatusRe.Match(lines[0]);
                if (m.Success) o.Code = int.Parse(m.Groups[1].Value);
                for (int i = 1; i < lines.Length; i++)
                {
                    string l = lines[i]; int ix = l.IndexOf(':');
                    if (ix <= 0) continue;
                    string k = l.Substring(0, ix).Trim().ToLowerInvariant(), v = l.Substring(ix + 1).Trim();
                    o.List.Add(new string[] { k, v });
                    if (o.Headers.ContainsKey(k)) o.Headers[k] = (string)o.Headers[k] + "\n" + v; else o.Headers[k] = v;
                }
                o.Text = BodyText(o.Body, (string)o.Headers["content-type"] ?? "");
            }
            else if (raw != null && raw.Length > 0) o.Banner = Util.BannerText(raw, 512);
            return o;
        }

        public static string BodyText(byte[] body, string contentType)
        {
            if (body == null || body.Length == 0) return "";
            Encoding enc = null;
            Match m = CtCharset.Match(contentType ?? "");
            if (m.Success) { try { enc = Encoding.GetEncoding(m.Groups[1].Value); } catch { enc = null; } }
            if (enc == null)
            {
                string sniff = Encoding.ASCII.GetString(body, 0, Math.Min(2048, body.Length));
                Match mm = MetaCharset.Match(sniff);
                if (mm.Success) { try { enc = Encoding.GetEncoding(mm.Groups[1].Value); } catch { enc = null; } }
            }
            if (enc == null) enc = Encoding.UTF8;
            return enc.GetString(body);
        }

        public static string Title(string html)
        {
            if (string.IsNullOrEmpty(html)) return "";
            Match m = TitleRe.Match(html);
            if (!m.Success) return "";
            string t = WebUtility.HtmlDecode(Ws.Replace(m.Groups[1].Value, " ").Trim());
            if (t.Length > 200) t = t.Substring(0, 200);
            return t;
        }

        public static List<string[]> Metas(string html)
        {
            List<string[]> o = new List<string[]>();
            if (string.IsNullOrEmpty(html)) return o;
            int n = 0;
            foreach (Match m in MetaTag.Matches(html))
            {
                if (++n > 64) break;
                string tag = m.Value;
                Match nm = MetaName.Match(tag), ct = MetaContent.Match(tag);
                if (!nm.Success || !ct.Success) continue;
                o.Add(new string[] { (nm.Groups[1].Value + nm.Groups[2].Value + nm.Groups[3].Value).ToLowerInvariant(),
                                     WebUtility.HtmlDecode(ct.Groups[1].Value + ct.Groups[2].Value + ct.Groups[3].Value) });
            }
            return o;
        }

        public static List<string> ScriptSrcs(string html)
        {
            List<string> o = new List<string>();
            if (string.IsNullOrEmpty(html)) return o;
            foreach (Match m in ScriptSrc.Matches(html)) { if (o.Count >= 64) break; o.Add(m.Groups[1].Value); }
            return o;
        }

        // Add-HeaderObs
        public static void AddHeader(Observation obs, string prefix, string name, string value)
        {
            obs.Add(prefix + "header:" + name, value);
            if (string.Equals(name, "set-cookie", StringComparison.OrdinalIgnoreCase))
            {
                obs.Add(prefix + "setcookie", value);
                string nv = (value ?? "").Split(';')[0]; int eq = nv.IndexOf('=');
                if (eq > 0)
                {
                    string cn = nv.Substring(0, eq).Trim();
                    obs.Add(prefix + "cookiename", cn);
                    obs.Add(prefix + "cookie:" + cn.ToLowerInvariant(), nv.Substring(eq + 1));
                }
            }
            else if (string.Equals(name, "www-authenticate", StringComparison.OrdinalIgnoreCase)) obs.Add(prefix + "auth", value);
        }

        // Add-BodyObs (identification paths)
        public static void AddBody(Observation obs, string prefix, HttpResp r)
        {
            obs.Add(prefix + "status", r.Code.ToString());
            foreach (string[] h in r.List) AddHeader(obs, prefix, h[0], h[1]);
            if (!string.IsNullOrEmpty(r.Text))
            {
                obs.Add(prefix + "body", r.Text);
                string t = r.Title; if (!string.IsNullOrEmpty(t)) obs.Add(prefix + "title", t);
            }
        }

        // Add-WebObs: headers of every hop, redirect locations, final status/url/body/title/meta/script sources
        public static void AddWeb(Observation obs, HttpResp[] hops, IEnumerable<string> locations, string finalUrl)
        {
            foreach (HttpResp h in hops) foreach (string[] p in h.List) AddHeader(obs, "", p[0], p[1]);
            foreach (string l in locations) obs.Add("location", l);
            HttpResp fin = hops[hops.Length - 1];
            obs.Add("status", fin.Code.ToString());
            obs.Add("url", finalUrl);
            if (!string.IsNullOrEmpty(fin.Text))
            {
                obs.Add("body", fin.Text);
                string t = fin.Title; if (!string.IsNullOrEmpty(t)) obs.Add("title", t);
                foreach (string[] mp in fin.Metas) obs.Add("meta:" + mp[0], mp[1]);
                foreach (string s in fin.Scripts) obs.Add("scriptsrc", s);
            }
        }
    }

    // ------------------------------------------------------------------ Result rows -> CSV / JSONL
    public static class Out
    {
        static readonly Regex Nl = new Regex("[\r\n]+");
        public static string CsvLine(object[] values, bool sanitize)
        {
            StringBuilder sb = new StringBuilder(1024);
            for (int i = 0; i < values.Length; i++)
            {
                if (i > 0) sb.Append(',');
                object v = Unwrap(values[i]);
                if (v == null) { sb.Append("\"\""); continue; }
                string s = Nl.Replace(Str(v), " ");
                if (sanitize) s = Util.CsvSafe(s);
                sb.Append('"').Append(s.Replace("\"", "\"\"")).Append('"');
            }
            return sb.ToString();
        }

        // PowerShell's [string] conversion of the scalar types rows hold (bool -> True/False, numbers invariant)
        static string Str(object v)
        {
            if (v is string) return (string)v;
            if (v is bool) return (bool)v ? "True" : "False";
            IFormattable f = v as IFormattable;
            if (f != null) return f.ToString(null, System.Globalization.CultureInfo.InvariantCulture);
            return v.ToString();
        }

        // PSObject wrappers (no compile-time reference to System.Management.Automation)
        public static object Unwrap(object v)
        {
            for (int i = 0; i < 4 && v != null; i++)
            {
                Type t = v.GetType();
                if (t.FullName != "System.Management.Automation.PSObject") break;
                System.Reflection.PropertyInfo p = t.GetProperty("BaseObject");
                if (p == null) break;
                object b = p.GetValue(v, null);
                if (b == null || ReferenceEquals(b, v) || b.GetType().FullName == "System.Management.Automation.PSCustomObject") break;
                v = b;
            }
            return v;
        }

        public static string JsonLine(string[] names, object[] values)
        {
            StringBuilder sb = new StringBuilder(4096);
            sb.Append('{');
            for (int i = 0; i < names.Length; i++)
            {
                if (i > 0) sb.Append(',');
                Str(sb, names[i]); sb.Append(':'); Value(sb, values[i], 0);
            }
            sb.Append('}');
            return sb.ToString();
        }

        static void Value(StringBuilder sb, object v, int depth)
        {
            v = Unwrap(v);
            if (v == null) { sb.Append("null"); return; }
            if (v is string) { Str(sb, (string)v); return; }
            if (v is bool) { sb.Append((bool)v ? "true" : "false"); return; }
            if (v is int || v is long || v is short || v is byte || v is sbyte || v is uint || v is ulong || v is ushort)
            { sb.Append(((IFormattable)v).ToString(null, System.Globalization.CultureInfo.InvariantCulture)); return; }
            if (v is double || v is float || v is decimal)
            { sb.Append(((IFormattable)v).ToString("R", System.Globalization.CultureInfo.InvariantCulture)); return; }
            if (v is Enum) { sb.Append(Convert.ToInt64(v).ToString(System.Globalization.CultureInfo.InvariantCulture)); return; }
            if (depth >= 5) { Str(sb, v.ToString()); return; }
            System.Collections.IDictionary d = v as System.Collections.IDictionary;
            if (d != null)
            {
                sb.Append('{'); bool first = true;
                foreach (System.Collections.DictionaryEntry e in d)
                {
                    if (!first) sb.Append(','); first = false;
                    Str(sb, Convert.ToString(e.Key, System.Globalization.CultureInfo.InvariantCulture)); sb.Append(':'); Value(sb, e.Value, depth + 1);
                }
                sb.Append('}'); return;
            }
            System.Collections.IEnumerable en = v as System.Collections.IEnumerable;
            if (en != null)
            {
                sb.Append('['); bool first = true;
                foreach (object x in en) { if (!first) sb.Append(','); first = false; Value(sb, x, depth + 1); }
                sb.Append(']'); return;
            }
            Str(sb, v.ToString());
        }

        // JSON string; HTML-sensitive characters escaped as \u00XX (as Windows PowerShell's ConvertTo-Json does)
        static void Str(StringBuilder sb, string s)
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
                            sb.Append('\\').Append('u').Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }
    }

    // ------------------------------------------------------------------ Target expansion -> job lines
    // Same semantics as the PowerShell loop it replaces: ranges then names per entry, exclusions and scope applied per
    // host, port-major job order, de-duplicated on host|ip|port (case-insensitive).
    public class JobBuilder
    {
        readonly RangeSet ex, scope;
        readonly System.Collections.IDictionary resolved;
        readonly bool allAddresses;
        readonly HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public readonly List<string> Jobs = new List<string>();
        public readonly HashSet<string> Hosts = new HashSet<string>();
        public readonly List<string> OutOfScope = new List<string>();
        public int Excluded;

        public JobBuilder(RangeSet exclude, RangeSet scope, System.Collections.IDictionary resolved, bool allAddresses)
        { ex = exclude; this.scope = scope; this.resolved = resolved; this.allAddresses = allAddresses; }

        public void Add(System.Collections.IEnumerable ranges, System.Collections.IEnumerable names, int[] ports, string scheme, string src)
        {
            List<string[]> pairs = new List<string[]>();
            if (ranges != null)
                foreach (object o in ranges)
                {
                    long[] rg = (long[])Out.Unwrap(o);
                    for (long n = rg[0]; n <= rg[1]; n++) { string ip = Util.Ip4ToString(n); pairs.Add(new string[] { ip, ip }); }
                }
            if (names != null)
                foreach (object o in names)
                {
                    string nm = (string)Out.Unwrap(o);
                    IPAddress tmp;
                    if (IPAddress.TryParse(nm, out tmp)) { pairs.Add(new string[] { nm, tmp.ToString() }); continue; }
                    if (ex.ContainsName(nm)) { Excluded++; continue; }
                    if (resolved == null || !resolved.Contains(nm)) continue;
                    List<string> addrs = new List<string>();
                    object rv = Out.Unwrap(resolved[nm]);
                    if (rv is string) addrs.Add((string)rv);
                    else foreach (object a in (System.Collections.IEnumerable)rv) addrs.Add(Convert.ToString(Out.Unwrap(a)));
                    if (addrs.Count == 0) continue;
                    if (allAddresses) { foreach (string a in addrs) pairs.Add(new string[] { nm, a }); continue; }
                    string pick = null;
                    foreach (string a in addrs) if (a.IndexOf(':') < 0) { pick = a; break; }
                    pairs.Add(new string[] { nm, pick ?? addrs[0] });
                }
            List<string[]> keep = new List<string[]>();
            foreach (string[] pr in pairs)
            {
                if (ex.Contains(pr[1], pr[0])) { Excluded++; continue; }
                if (!scope.IsEmpty && !scope.Contains(pr[1], pr[0])) { OutOfScope.Add(pr[0] + " (" + pr[1] + ") from " + src); continue; }
                keep.Add(pr);
            }
            string sch = scheme ?? "";
            foreach (int port in ports)
            {
                string ps = port.ToString(System.Globalization.CultureInfo.InvariantCulture);
                foreach (string[] pr in keep)
                    if (seen.Add(pr[0] + "|" + pr[1] + "|" + ps)) { Jobs.Add(pr[0] + "\t" + pr[1] + "\t" + ps + "\t" + sch); Hosts.Add(pr[1]); }
            }
        }

        // -ListTargets lines: "ip:port" or "name (ip):port"
        public static string[] Format(List<string> jobs)
        {
            string[] o = new string[jobs.Count];
            for (int i = 0; i < o.Length; i++)
            {
                string[] p = jobs[i].Split('\t');
                o[i] = p[0] == p[1] ? p[1] + ":" + p[2] : p[0] + " (" + p[1] + "):" + p[2];
                if (p.Length > 3 && (p[3] == "smb" || p[3] == "rdp" || p[3] == "snmp")) o[i] += p[3] == "snmp" ? " (snmp, udp)" : " (" + p[3] + ")";
            }
            return o;
        }
    }

    // ------------------------------------------------------------------ Job scheduler (long-lived workers)
    // Workers block in Take() until a check is available whose host is below the per-host cap; results go to a
    // concurrent queue the dispatcher waits on (no polling). Per-host queues are served round-robin, preserving each
    // host's job order. A watchdog can Abandon() a worker slot; a late Done() for an abandoned slot is discarded.
    public class Sched
    {
        readonly object gate = new object();
        readonly Dictionary<string, Queue<string>> byHost = new Dictionary<string, Queue<string>>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, int> active = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        readonly LinkedList<string> ready = new LinkedList<string>();
        readonly HashSet<string> inReady = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly int maxPerHost;
        readonly string[] slotJob;
        readonly long[] slotStart;
        readonly Stopwatch clock = Stopwatch.StartNew();
        readonly System.Threading.AutoResetEvent signal = new System.Threading.AutoResetEvent(false);
        int queued, running;
        bool stopped;
        public readonly System.Collections.Concurrent.ConcurrentQueue<object[]> Results = new System.Collections.Concurrent.ConcurrentQueue<object[]>();

        public Sched(string[] jobs, int maxPerHost, int slots)
        {
            this.maxPerHost = Math.Max(1, maxPerHost);
            slotJob = new string[Math.Max(1, slots)];
            slotStart = new long[slotJob.Length];
            foreach (string j in jobs)
            {
                string h = HostOf(j);
                Queue<string> q;
                if (!byHost.TryGetValue(h, out q)) { q = new Queue<string>(); byHost[h] = q; active[h] = 0; ready.AddLast(h); inReady.Add(h); }
                q.Enqueue(j); queued++;
            }
        }

        // job line = host \t ip \t port \t scheme; the per-host cap is keyed on the IP
        public static string HostOf(string job)
        {
            int a = job.IndexOf('\t'); if (a < 0) return job;
            int b = job.IndexOf('\t', a + 1); if (b < 0) b = job.Length;
            return job.Substring(a + 1, b - a - 1);
        }

        public string Take(int slot)
        {
            lock (gate)
            {
                while (true)
                {
                    if (stopped) return null;
                    if (ready.Count > 0)
                    {
                        string h = ready.First.Value; ready.RemoveFirst(); inReady.Remove(h);
                        Queue<string> q = byHost[h];
                        string j = q.Dequeue(); queued--; running++;
                        int a = active[h] + 1; active[h] = a;
                        if (q.Count > 0 && a < maxPerHost) { ready.AddLast(h); inReady.Add(h); }
                        slotJob[slot] = j; slotStart[slot] = clock.ElapsedMilliseconds;
                        return j;
                    }
                    if (queued == 0) return null;
                    System.Threading.Monitor.Wait(gate);
                }
            }
        }

        void Release(int slot)
        {
            string j = slotJob[slot];
            slotJob[slot] = null; running--;
            string h = HostOf(j);
            int a = active[h] - 1; active[h] = a;
            if (byHost[h].Count > 0 && a < maxPerHost && !inReady.Contains(h)) { ready.AddLast(h); inReady.Add(h); }
            System.Threading.Monitor.PulseAll(gate);
        }

        // false when the slot was abandoned meanwhile (watchdog): the late result is discarded
        public bool Done(int slot, string job, object result)
        {
            lock (gate)
            {
                if (!string.Equals(slotJob[slot], job, StringComparison.Ordinal)) return false;
                Release(slot);
            }
            Results.Enqueue(new object[] { job, result });
            signal.Set();
            return true;
        }

        public string Abandon(int slot)
        {
            lock (gate)
            {
                string j = slotJob[slot];
                if (j != null) Release(slot);
                return j;
            }
        }

        // stop dispatching; returns how many queued checks will not run
        public int Stop()
        {
            int n;
            lock (gate) { n = stopped ? 0 : queued; stopped = true; System.Threading.Monitor.PulseAll(gate); }
            signal.Set();
            return n;
        }

        public bool Wait(int ms) { return signal.WaitOne(ms); }
        // next finished check as { jobLine, result }, or null when none is waiting (avoids [ref] on generic out params in PowerShell)
        public object[] NextResult() { object[] r; return Results.TryDequeue(out r) ? r : null; }
        public int Queued { get { lock (gate) return queued; } }
        public int Running { get { lock (gate) return running; } }
        public bool Stopped { get { lock (gate) return stopped; } }
        public string Current(int slot) { lock (gate) return slotJob[slot]; }

        public int[] Overdue(long budgetMs)
        {
            List<int> o = new List<int>();
            lock (gate)
            {
                long now = clock.ElapsedMilliseconds;
                for (int i = 0; i < slotJob.Length; i++) if (slotJob[i] != null && now - slotStart[i] > budgetMs) o.Add(i);
            }
            return o.ToArray();
        }
    }

    public class RangeSet
    {
        readonly List<long[]> ranges = new List<long[]>();
        readonly HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public int RangeCount { get { return ranges.Count; } }
        public int NameCount { get { return names.Count; } }
        public bool IsEmpty { get { return ranges.Count == 0 && names.Count == 0; } }
        public void AddRange(long a, long b) { ranges.Add(new long[] { Math.Min(a, b), Math.Max(a, b) }); }
        public void AddName(string n)
        {
            if (string.IsNullOrEmpty(n)) return;
            IPAddress ip;
            if (IPAddress.TryParse(n, out ip)) names.Add(ip.ToString()); else names.Add(n.TrimEnd('.'));
        }
        public bool ContainsName(string n) { return !string.IsNullOrEmpty(n) && names.Contains(n.TrimEnd('.')); }
        public bool ContainsIp(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;
            if (names.Contains(ip)) return true;
            long v = Util.Ip4(ip);
            if (v < 0) return false;
            foreach (long[] r in ranges) if (v >= r[0] && v <= r[1]) return true;
            return false;
        }
        public bool Contains(string ip, string name) { return ContainsName(name) || ContainsIp(ip); }
    }

    // ------------------------------------------------------------------ Misc helpers
    public static class Util
    {
        public const string EngineVersion = "2.4.0";

        // strict dotted-quad IPv4 -> 0..2^32-1, or -1
        public static long Ip4(string s)
        {
            if (string.IsNullOrEmpty(s)) return -1;
            string[] p = s.Split('.');
            if (p.Length != 4) return -1;
            long v = 0;
            foreach (string x in p)
            {
                int o;
                if (x.Length == 0 || x.Length > 3 || !int.TryParse(x, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out o) || o > 255) return -1;
                v = (v << 8) | (uint)o;
            }
            return v;
        }

        public static string Ip4ToString(long v)
        {
            return ((v >> 24) & 255) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255);
        }

        // CSV/Excel formula-injection guard: scanned hosts control titles/headers
        public static string CsvSafe(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            char c = s[0];
            if (c == '=' || c == '+' || c == '-' || c == '@' || c == '\t' || c == '\r') return "'" + s;
            return s;
        }

        // Strip control characters (incl. ANSI escapes) before printing attacker-controlled text to a console
        public static string Printable(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return s ?? "";
            StringBuilder sb = new StringBuilder(Math.Min(s.Length, max));
            foreach (char c in s)
            {
                if (sb.Length >= max) break;
                if (c == '\t') sb.Append(' ');
                else if (c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0)) sb.Append('.');
                else sb.Append(c);
            }
            return sb.ToString();
        }

        public static string Html(string s) { return string.IsNullOrEmpty(s) ? "" : WebUtility.HtmlEncode(s); }

        public static int KeySize(X509Certificate2 c)
        {
            try { using (RSA r = c.GetRSAPublicKey()) { if (r != null) return r.KeySize; } } catch { }
            try { using (ECDsa e = c.GetECDsaPublicKey()) { if (e != null) return e.KeySize; } } catch { }
            try { using (DSA d = c.GetDSAPublicKey()) { if (d != null) return d.KeySize; } } catch { }
            return 0;
        }

        public static string BannerText(byte[] raw, int max)
        {
            if (raw == null || raw.Length == 0) return "";
            int n = Math.Min(raw.Length, max);
            StringBuilder sb = new StringBuilder(n);
            for (int i = 0; i < n; i++) { byte b = raw[i]; sb.Append(b >= 0x20 && b < 0x7f ? (char)b : (b == 10 || b == 13 ? '\n' : '.')); }
            return sb.ToString();
        }

        // MySQL/MariaDB initial handshake: [3-byte len][seq][0x0a protocol][version NUL]...
        public static string MySqlVersion(byte[] raw)
        {
            if (raw == null || raw.Length < 6 || raw[4] != 0x0a) return null;
            int e = Array.IndexOf(raw, (byte)0, 5);
            if (e < 6 || e - 5 > 64) return null;
            string v = Encoding.ASCII.GetString(raw, 5, e - 5);
            foreach (char c in v) if (c < 0x20 || c > 0x7e) return null;
            return v;
        }
    }
}
