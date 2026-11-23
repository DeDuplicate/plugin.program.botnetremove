"""Self-check: scan() against a fake infected box. Run: python test_scan.py"""
import socket
import struct

from xcpe_remover import scan


def proc_addr(ip, port):
    return '%08X:%04X' % (struct.unpack('<I', socket.inet_aton(ip))[0], port)


BOX = {
    'getprop': '[ro.product.model]: [HY300]\n[ro.txcz.model]: [rk3326-V12]\n[service.adb.tcp.port]: [22337]\n',
    'pm list packages -f': 'package:/system/priv-app/Auth/Auth.apk=com.android.auth.handler\n'
                           'package:/data/app/tiger/base.apk=com.android.tigertv\n'
                           'package:/system/app/TxBox/TxBox.apk=com.shzhtxcz.txbox\n'
                           'package:/system/priv-app/Vending/Vending.apk=com.android.vending\n',
    'pm list packages -3': 'package:com.android.tigertv\n',
    '/proc/net/tcp': f'  sl local rem st\n   0: {proc_addr("10.0.0.5", 40000)} {proc_addr("47.113.90.237", 8081)} 01\n',
    '/proc/net/unix': '0000: 00000002 0 10000 0001 01 1234 @niggaboxv7\n',
    'logcat -d': 'I/Ads: GET https://api.shzhtxcz.com/videoadmin/api/advertisement/getByModel\n',
    'settings get': 'null',
}


def sh(cmd):
    return next((out for key, out in BOX.items() if key in cmd), '')


found = {f.title: f for f in scan(sh, {})}
for title in found:
    print(found[title].sev, title)
assert found['Malicious package com.android.auth.handler'].sev == 'HIGH'
assert found['Suspicious package com.android.tigertv'].sev == 'MEDIUM'  # review list, not the com.android.* heuristic
assert not any('tigertv impersonates' in t for t in found)
assert found['TXCZ (BADBOX 3.0) firmware detected (com.shzhtxcz.txbox)'].fix is None  # launcher: never removed
assert 'TXCZ (BADBOX 3.0) firmware detected (ro.txcz.model)' in found
assert 'Live connection to BADBOX 3.0 C2 47.113.90.237:8081' in found
assert 'Malicious process running: Kimwolf/Aisuru bot (control socket open)' in found
assert found['ADB opened on port 22337, the JackSkid botnet signature'].sev == 'HIGH'
assert 'Device contacted BADBOX 3.0 infrastructure: api.shzhtxcz.com' in found
assert not any('com.android.vending' in t for t in found)
assert found['Malicious package com.android.auth.handler'].fix[1] == 'pm disable-user --user 0 com.android.auth.handler'

# MECOOL KM2 Plus (props from an owner's dump): before and after MECOOL's Nov 2026 cleaned firmware
km2 = '[ro.product.manufacturer]: [SkyworthDigital]\n[ro.product.name]: [HP4414-MECOOL]\n[ro.product.model]: [KM2 Plus]\n'
for fw, title in [('C1.3.3_20260611', 'Videostrong/Mecool device (the XCPE vendor)'),
                  ('C1.3.5_20261111', "MECOOL's cleaned firmware C1.3.5_20261111 (Nov 2026, no XCPE)")]:
    BOX = {'getprop': km2 + f'[ro.build.fingerprint]: [MECOOL/HP4414/x:14/UKG3/{fw}:user/release-keys]\n'
                            '[sys.boot.reason]: [reboot,ota]\n', 'settings get': 'null'}
    titles = [f.title for f in scan(sh, {})]
    assert title in titles and 'Last restart was a firmware update (sys.boot.reason=reboot,ota)' in titles, titles
    assert not any(t.startswith('Model ') for t in titles)
print('OK')
