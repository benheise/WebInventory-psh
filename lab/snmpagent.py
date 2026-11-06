#!/usr/bin/env python3
"""SNMP agent for lab tests of -Snmp (127.0.0.1 only; pysnmp 7). v1/v2c community 'labcommunity'; v3 users:
   authpriv  SHA / AES-128   authpass123 / privpass123
   authonly  SHA256 / -      authpass456
   md5des    MD5 / DES       authpass789 / privpass789
   noauth    (noAuthNoPriv)
   snmpagent.py <port> [sysDescr]
"""
import asyncio, sys
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp

port = int(sys.argv[1])
descr = sys.argv[2] if len(sys.argv) > 2 else "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E8, RELEASE SOFTWARE (fc1)\r\nTechnical Support: http://www.cisco.com/techsupport"

snmpEngine = engine.SnmpEngine()
config.add_transport(snmpEngine, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode(("127.0.0.1", port)))
config.add_v1_system(snmpEngine, "lab-area", "labcommunity")
config.add_v3_user(snmpEngine, "authpriv", config.USM_AUTH_HMAC96_SHA, "authpass123", config.USM_PRIV_CFB128_AES, "privpass123")
config.add_v3_user(snmpEngine, "authonly", config.USM_AUTH_HMAC192_SHA256, "authpass456")
config.add_v3_user(snmpEngine, "md5des", config.USM_AUTH_HMAC96_MD5, "authpass789", config.USM_PRIV_CBC56_DES, "privpass789")
config.add_v3_user(snmpEngine, "noauth")
for name, level in (("lab-area", "noAuthNoPriv"), ("authpriv", "authPriv"), ("authonly", "authNoPriv"), ("md5des", "authPriv"), ("noauth", "noAuthNoPriv")):
    model = 2 if name == "lab-area" else 3
    config.add_vacm_user(snmpEngine, model, name, level, (1, 3, 6, 1, 2, 1, 1))
    if model == 2:
        config.add_vacm_user(snmpEngine, 1, name, level, (1, 3, 6, 1, 2, 1, 1))

snmpContext = context.SnmpContext(snmpEngine)
mb = snmpContext.get_mib_instrum().get_mib_builder()
sd, so, sn, sl = mb.import_symbols("__SNMPv2-MIB", "sysDescr", "sysObjectID", "sysName", "sysLocation")
sd.syntax = sd.syntax.clone(descr)
so.syntax = so.syntax.clone((1, 3, 6, 1, 4, 1, 9, 1, 1208))
sn.syntax = sn.syntax.clone("lab-switch-01.lab.test")
sl.syntax = sl.syntax.clone("Server room A, rack 3")

cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
snmpEngine.transport_dispatcher.job_started(1)
print("snmp agent up on udp", port, flush=True)
try:
    snmpEngine.open_dispatcher()
except KeyboardInterrupt:
    pass
