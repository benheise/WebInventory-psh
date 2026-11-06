#!/usr/bin/env python3
"""Test PKI for the Tideline shipping tests (never for production): a root and intermediate like step-ca's, the
ingest server's certificate, and sensor certificates, good and bad.

  python3 tests/v26/mkcerts.py OUTDIR
Writes PEM files, PFX files (no password, and one with the password in pfx-password.txt) and a summary."""
import datetime, ipaddress, pathlib, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

out = pathlib.Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
now = datetime.datetime.now(datetime.timezone.utc)

def name(cn, org="Tideline Test"):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org), x509.NameAttribute(NameOID.COMMON_NAME, cn)])

def key(kind="ec"):
    return ec.generate_private_key(ec.SECP256R1()) if kind == "ec" else rsa.generate_private_key(public_exponent=65537, key_size=2048)

def ca(cn, issuer=None, ikey=None, path=None):
    k = key()
    b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(issuer.subject if issuer else name(cn))
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=True, path_length=path), critical=True)
         .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False))
    if issuer:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ikey.public_key()), critical=False)
    return b.sign(ikey or k, hashes.SHA256()), k

def leaf(cn, issuer, ikey, sans, eku, kind="ec", nb=None, na=None):
    k = key(kind)
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])).issuer_name(issuer.subject)
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(nb or now - datetime.timedelta(minutes=5)).not_valid_after(na or now + datetime.timedelta(days=30))
         .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
         .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ikey.public_key()), critical=False))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return b.sign(ikey, hashes.SHA256()), k

def pem(c): return c.public_bytes(serialization.Encoding.PEM)
def kpem(k): return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

def write(stem, cert, k, chain=(), pfx_password=None):
    (out / (stem + ".crt")).write_bytes(pem(cert) + b"".join(pem(c) for c in chain))
    (out / (stem + ".key")).write_bytes(kpem(k))
    enc = serialization.BestAvailableEncryption(pfx_password) if pfx_password else serialization.NoEncryption()
    (out / (stem + ".pfx")).write_bytes(pkcs12.serialize_key_and_certificates(stem.encode(), k, cert, list(chain), enc))

URN = "urn:tideline:sensor:"
root, rk = ca("Tideline Test Root CA", path=1)
inter, ik = ca("Tideline Test Intermediate CA", root, rk, path=0)
(out / "root.crt").write_bytes(pem(root))
(out / "intermediate.crt").write_bytes(pem(inter))
(out / "client-ca.pem").write_bytes(pem(root) + pem(inter))     # what ingest trusts for client certificates
rogue, rok = ca("Rogue Root CA", path=0)
(out / "rogue-root.crt").write_bytes(pem(rogue))

srv_sans = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.IPAddress(ipaddress.ip_address("::1"))]
c, k = leaf("localhost", inter, ik, srv_sans, [ExtendedKeyUsageOID.SERVER_AUTH]); write("server", c, k, [inter])
c, k = leaf("other.example", inter, ik, [x509.DNSName("other.example")], [ExtendedKeyUsageOID.SERVER_AUTH]); write("server-wrongname", c, k, [inter])
c, k = leaf("localhost", rogue, rok, srv_sans, [ExtendedKeyUsageOID.SERVER_AUTH]); write("server-rogue", c, k, [])

cli = [ExtendedKeyUsageOID.CLIENT_AUTH]
c, k = leaf("wi-test01", inter, ik, [x509.UniformResourceIdentifier(URN + "wi-test01")], cli); write("sensor", c, k, [inter])
write("sensor-pw", c, k, [inter], b"pfx-pass")
(out / "pfx-password.txt").write_text("pfx-pass\n")
c, k = leaf("wi-other", inter, ik, [x509.UniformResourceIdentifier(URN + "wi-other")], cli); write("sensor-other", c, k, [inter])
c, k = leaf("wi-test01", rogue, rok, [x509.UniformResourceIdentifier(URN + "wi-test01")], cli); write("sensor-rogue", c, k, [])
c, k = leaf("wi-test01", inter, ik, [x509.UniformResourceIdentifier(URN + "wi-test01")], cli,
            nb=now - datetime.timedelta(days=40), na=now - datetime.timedelta(days=10)); write("sensor-expired", c, k, [inter])
c, k = leaf("wi-test01", inter, ik, [x509.DNSName("wi-test01")], cli); write("sensor-nourn", c, k, [inter])
c, k = leaf("wi-test01", inter, ik, [x509.UniformResourceIdentifier(URN + "wi-test01")], cli, kind="rsa"); write("sensor-rsa", c, k, [inter])
print("test PKI in", out)
