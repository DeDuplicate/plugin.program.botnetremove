#!/usr/bin/env python3
"""XCPE remover: scan Android TV boxes over ADB for the XCPE botnet and related threats, and remove them.

Usage:
  python xcpe_remover.py                     # scan every USB/already-connected ADB device
  python xcpe_remover.py --connect 192.168.1.50   # connect to a TV box over the network first
  python xcpe_remover.py --yes               # remove confirmed (HIGH) threats without asking

IOCs (iocs.json): Google Threat Intelligence, "Shutting the Door on the XCPE Botnet" (2026-11-03)
https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet/
and Synthient, "Videostrong" https://github.com/synthient/public-research/blob/main/2026/11/Videostrong/README.md
"""
from __future__ import annotations  # Kodi 19-21 embed Python 3.8; keeps `list[str] | None` lazy

import argparse
import datetime
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------- IOCs

IOC = json.loads(Path(__file__).with_name('iocs.json').read_text(encoding='utf-8'))
IOC_PORTS = set(IOC['ports'])  # XCPE MQTT broker
DOMAINS = IOC['domains']  # domain or github.com/owner/ -> family
HASHES = IOC['hashes']  # sha256 -> description
DOMAIN_RE = re.compile(r'(?<![\w-])(?:' + '|'.join(map(re.escape, sorted(DOMAINS, key=len, reverse=True)))
                       + r')(?:(?<=/)|(?![\w-]))', re.I)  # github.com/owner/ prefixes need no right boundary

# ContentProviders exported by x.cpe; any package owning them is XCPE, whatever its name.
PROVIDER_RE = re.compile(r'\[[^\]\n]*\b(?:com\.release\.debug\.provider|com\.oem\.share\.provider)\b[^\]\n]*\]:'
                         r'\s*\n\s*Provider\{\S+ ([\w.]+)/')
# XCPE/ABCNexus classes and the affiliate module services they host.
COMPONENT_RE = re.compile(r'([A-Za-z][\w.]*)/((?:x\.cpe|com\.abc\.nexus|com\.gaganode|io\.popanet|com\.bird\.cc|'
                          r'com\.android\.init\.android|com\.data\.trans\.android|com\.qdp\.s\.b)\.[\w.$]+|'
                          r'[\w.$]*(?:Linkfog|Bwm|SN4|Adtime|PProxy|lb102|Devour|ADMOYU|Amh|Titan)Service)\b')
# Heuristic: bandwidth-sharing / residential-proxy apps.
PROXYWARE_RE = re.compile(r'honeygain|traffmonetizer|earnapp|pawns|peer2profit|packetstream|repocket|getgrass|'
                          r'titannet|gaganode|popanet|ipcola|earnfm|linkfog|bestipip|ipweb|proxyrack|appsalt', re.I)

# ---------------------------------------------------------------- scanning

SEVS = ('HIGH', 'MEDIUM', 'LOW', 'INFO')


@dataclass
class Finding:
    sev: str
    title: str
    detail: str = ''
    fix: list[str] | None = None  # shell commands that remediate it


def remove_cmds(pkg):
    # Full uninstall removes /data/app copies and system-app updates; --user 0 hides the
    # firmware copy so its BootReceiver can't reinstall it; disable-user is the last resort.
    return [f'am force-stop {pkg}', f'pm uninstall {pkg}', f'pm uninstall --user 0 {pkg}',
            f'pm list packages | grep -qx package:{pkg} && pm disable-user --user 0 {pkg}']


def ipv4_from_proc(hexaddr):
    """Decode a /proc/net/tcp{,6} address; None for real IPv6."""
    if len(hexaddr) == 32 and hexaddr[:24].upper() == '0000000000000000FFFF0000':
        hexaddr = hexaddr[24:]
    if len(hexaddr) != 8:
        return None
    return '.'.join(str(b) for b in reversed(bytes.fromhex(hexaddr)))


def sha256_files(sh, paths, cache):
    todo = [p for p in paths if p not in cache]
    for i in range(0, len(todo), 40):
        chunk = todo[i:i + 40]
        out = sh('sha256sum ' + ' '.join(f"'{p}'" for p in chunk) + ' 2>/dev/null')
        for h, p in re.findall(r'^([0-9a-f]{64})\s+\*?(.+?)\s*$', out, re.M):
            cache[p] = h
        for p in chunk:
            cache.setdefault(p, None)  # unreadable or no sha256sum (Android < 6)


def scan(sh, cache):
    """sh(cmd) -> device shell output. cache: path -> sha256, reused across scans."""
    out = []

    def add(*a, **k):
        out.append(Finding(*a, **k))

    prop = dict(re.findall(r'^\[([^\]]+)\]: \[([^\]]*)\]', sh('getprop'), re.M))

    # --- packages: by name, exported provider, component class, and APK hash
    pkgs = {}
    for line in sh('pm list packages -f').splitlines():
        if line.startswith('package:') and '=' in line:
            path, name = line[8:].strip().rsplit('=', 1)
            pkgs[name] = path
    third = set(re.findall(r'^package:(\S+)', sh('pm list packages -3'), re.M))
    bad = {}

    def flag(pkg, why):
        if pkg in pkgs and why not in bad.setdefault(pkg, []):
            bad[pkg].append(why)

    for p, why in IOC['packages'].items():
        flag(p, why)
    dump = sh('dumpsys package providers; dumpsys package r')
    for m in PROVIDER_RE.finditer(dump):
        flag(m[1], 'exports the XCPE config ContentProvider')
    for m in COMPONENT_RE.finditer(dump):
        flag(m[1], f'contains XCPE/affiliate component {m[2]}')

    names = IOC['files'] + list(IOC['packages']) + [f'privapp-permissions-{p}.xml' for p in IOC['packages']]
    expr = ' -o '.join(f"-name '{n}*'" for n in names)
    found = [l.strip() for l in sh(f'find /system /vendor /product /odm /oem /data/local/tmp {expr} 2>/dev/null')
             .splitlines() if l.startswith('/')]
    oem_apks = [l.strip() for l in sh("find /oem -name '*.apk' 2>/dev/null").splitlines() if l.startswith('/')]

    owner = {v: k for k, v in pkgs.items()}
    files = list(pkgs.values()) + found + oem_apks
    print(f'  hashing {len(files)} files...')
    sha256_files(sh, files, cache)
    for f in files:
        fam = HASHES.get(cache.get(f))
        if fam and f in owner:
            flag(owner[f], f'APK hash matches {fam}')
        elif fam and f not in found:
            add('HIGH', f'Known malicious file {f}', fam)

    for p, why in bad.items():
        where = ('user-installed' if p in third else
                 'SYSTEM app: the firmware itself is backdoored; it returns after a factory reset')
        add('HIGH', f'Malicious package {p}', f"{'; '.join(why)} [{pkgs[p]}, {where}]", remove_cmds(p))
    for p in sorted(third - bad.keys()):
        if p.startswith('com.android.'):
            add('MEDIUM', f'{p} impersonates a system package', 'user-installed app with a com.android.* name',
                remove_cmds(p))
        elif PROXYWARE_RE.search(p):
            add('MEDIUM', f'{p} looks like proxyware', 'sells your bandwidth / turns the box into a proxy exit node',
                remove_cmds(p))
    for f in found:
        add('HIGH', f'XCPE artifact {f}', 'on a read-only partition: needs root or a clean firmware flash to delete')
    for f in oem_apks:
        if not HASHES.get(cache.get(f)):
            add('INFO', f'APK on /oem partition: {f}', 'XCPE reinstalls itself from /oem at boot; review')

    # --- running native malware daemons
    ps = sh('ps -A 2>/dev/null; ps 2>/dev/null')
    for n in IOC['files']:
        if (n[:-3] if n.endswith('.so') else n) in ps:  # no str.removesuffix on 3.8
            add('HIGH', f'Malicious process running: {n}', 'stops once its parent package is removed and the box rebooted')

    # --- network: live C2 connections, and C2 domains seen in logs
    hits = set()
    for line in sh('cat /proc/net/tcp /proc/net/tcp6 2>/dev/null').splitlines():
        parts = line.split()
        # ESTABLISHED/SYN_SENT only: TIME_WAIT leftovers would flag a just-removed C2 link as live
        if len(parts) > 3 and parts[3] in ('01', '02') and parts[2].count(':') == 1:
            addr, port = parts[2].split(':')
            ip, port = ipv4_from_proc(addr), int(port, 16)
            if ip in IOC['ips'] or port in IOC_PORTS:
                hits.add(f'{ip}:{port}')
    for h in sorted(hits):
        add('HIGH', f'Live connection to XCPE C2 {h}')
    for d in sorted({m.lower() for m in DOMAIN_RE.findall(sh('logcat -d 2>/dev/null'))}):
        add('HIGH', f'Device contacted {DOMAINS[d]} infrastructure: {d}', 'seen in the system log')

    # --- XCPE fingerprints in properties and settings
    for k in IOC['props']:
        if k in prop:
            add('HIGH', f'XCPE dropper control property {k}={prop[k]}', 'set by XCPE operator scripts')

    def setting(ns, key):
        return sh(f'settings get {ns} {key}').strip()

    if setting('global', 'package_verifier_user_consent') == '-1':
        add('HIGH', 'Google Play Protect disabled (package_verifier_user_consent=-1, an XCPE trait)', '',
            ['settings put global package_verifier_user_consent 1'])
    if setting('global', 'package_verifier_enable') == '0':
        add('MEDIUM', 'App verification (Play Protect) is off', '', ['settings put global package_verifier_enable 1'])

    # --- general security risks
    proxy = setting('global', 'http_proxy')
    if proxy not in ('', 'null', ':0'):
        add('MEDIUM', f'Global HTTP proxy set: {proxy}', 'web traffic is routed through a third party',
            ['settings put global http_proxy :0'])
    vendor = ' '.join(prop.get(k, '') for k in ('ro.product.brand', 'ro.product.manufacturer', 'ro.product.model'))
    if prop.get('ro.mecool.device') in ('true', '1') or re.search('videostrong|mecool', vendor, re.I):
        add('MEDIUM', 'Videostrong/Mecool device (the XCPE vendor)', 'treat the firmware as untrusted; consider replacing')
    elif prop.get('ro.product.model') in IOC['models']:
        add('MEDIUM', f"Model {prop['ro.product.model']} was observed shipping XCPE firmware",
            'not proof by itself; treat the firmware as untrusted')
    if prop.get('ro.debuggable') == '1' or prop.get('ro.secure') == '0':
        add('MEDIUM', 'Insecure debug firmware (ro.debuggable=1 / ro.secure=0)', 'ADB access grants root')
    if 'test-keys' in prop.get('ro.build.tags', ''):
        add('MEDIUM', 'Firmware signed with public test-keys', 'anyone can sign "system" apps for this device')
    port = prop.get('service.adb.tcp.port') or prop.get('persist.adb.tcp.port')
    if port and port not in ('0', '-1'):
        add('MEDIUM', f'ADB exposed on network port {port}', 'open ADB is a common botnet entry point; disable when done')
    if sh('ls /system/xbin/su /system/bin/su /sbin/su /su/bin/su 2>/dev/null').strip():
        add('MEDIUM', 'Root (su) binary present', 'any app granted root can take over the device')
    patch = prop.get('ro.build.version.security_patch', '')
    try:
        if (datetime.date.today() - datetime.date.fromisoformat(patch)).days > 730:
            add('LOW', f'Security patch level {patch} is over 2 years old')
    except ValueError:
        pass
    if setting('secure', 'install_non_market_apps') == '1':
        add('LOW', 'Installing apps from unknown sources is allowed')
    acc = setting('secure', 'enabled_accessibility_services')
    if acc not in ('', 'null'):
        add('LOW', 'Accessibility services enabled (can read the screen and inject input)', acc)

    return sorted(out, key=lambda f: SEVS.index(f.sev))


# ---------------------------------------------------------------- ADB / CLI

ADB = 'adb'
ADB_URL = 'https://dl.google.com/android/repository/platform-tools-latest-{}.zip'
HERE = Path(__file__).resolve().parent

ENABLE_HELP = """
No authorized ADB device found. Enable ADB on the Android TV box:
  1. Settings > Device Preferences > About: click "Build" 7 times to unlock Developer options
     (older boxes: Settings > About > Build number).
  2. Settings > Device Preferences > Developer options: turn on "USB debugging"
     (plus "Network debugging" / "ADB over network" to connect over Wi-Fi).
  3. Connect by USB (USB-A to USB-A cable), or by network: find the box IP under Settings > Network, then
       python xcpe_remover.py --connect <TV-IP>
  4. Accept the "Allow debugging?" prompt on the TV (tick "Always allow").
"""
AFTER_HELP = """
Next steps:
  - Reboot cleaned devices and run this tool again: XCPE tries to reinstall itself at boot.
  - Turn USB/Network debugging off again in Developer options.
  - Block szbboys.com and anyevonline.com (XCPE C2) on your router/DNS.
  - Firmware-level (SYSTEM) infections return after a factory reset: replace the box or flash clean firmware.
"""


def find_adb():
    exe = 'adb.exe' if os.name == 'nt' else 'adb'
    candidates = [shutil.which('adb'), HERE / 'platform-tools' / exe]
    candidates += [Path(os.environ[v]) / 'platform-tools' / exe
                   for v in ('ANDROID_HOME', 'ANDROID_SDK_ROOT', 'LOCALAPPDATA') if os.environ.get(v)]
    candidates.append(Path(os.environ.get('LOCALAPPDATA', '.')) / 'Android' / 'Sdk' / 'platform-tools' / exe)
    for c in candidates:
        if c and Path(c).is_file():
            return str(c)
    plat = {'win32': 'windows', 'darwin': 'darwin'}.get(sys.platform, 'linux')
    print('adb not found; downloading Android platform-tools from Google...')
    with urllib.request.urlopen(ADB_URL.format(plat)) as r:
        zipfile.ZipFile(io.BytesIO(r.read())).extractall(HERE)
    adb = HERE / 'platform-tools' / exe
    adb.chmod(0o755)
    return str(adb)


def run(*args, timeout=600):
    r = subprocess.run([ADB, *args], capture_output=True, text=True, encoding='utf-8', errors='replace',
                       timeout=timeout)
    return r.stdout + r.stderr


def devices():
    return dict(l.split('\t', 1) for l in run('devices').splitlines()[1:] if '\t' in l)


def ask(question):
    try:
        return input(question).strip().lower() in ('y', 'yes')
    except EOFError:
        return False


def report(findings):
    if not findings:
        print('  No threats found.')
    for f in findings:
        print(f'  [{f.sev}] {f.title}' + (' (fixable)' if f.fix else '') + (f'\n          {f.detail}' if f.detail else ''))


def check_device(serial, yes):
    def sh(cmd):
        return run('-s', serial, 'shell', cmd)

    info = ' '.join(sh(f'getprop {k}').strip() for k in ('ro.product.manufacturer', 'ro.product.model'))
    print(f"\n=== {serial}: {info}, Android {sh('getprop ro.build.version.release').strip()} ===")
    cache = {}
    findings = scan(sh, cache)
    report(findings)
    fixed = False
    for f in findings:
        # --yes only auto-applies HIGH (IOC-confirmed) fixes; heuristics always ask.
        if f.fix and ((yes and f.sev == 'HIGH') or ask(f'Fix [{f.sev}] {f.title}? [y/N] ')):
            for c in f.fix:
                sh(c)
            fixed = True
    if fixed:
        print('\nRe-scanning to verify...')
        findings = scan(sh, cache)
        report(findings)
    return int(any(f.sev == 'HIGH' for f in findings))


def main():
    ap = argparse.ArgumentParser(description='Scan Android TV boxes over ADB for the XCPE botnet and remove it.')
    ap.add_argument('--connect', nargs='+', default=[], metavar='IP[:PORT]',
                    help='connect to devices over the network first (port defaults to 5555)')
    ap.add_argument('-y', '--yes', action='store_true', help='remove confirmed (HIGH) threats without asking')
    args = ap.parse_args()

    global ADB
    ADB = find_adb()
    run('start-server')
    for host in args.connect:
        print(run('connect', host).strip())
    devs = devices()
    for i in range(30):
        if 'unauthorized' not in devs.values():
            break
        if i == 0:
            print('Waiting for you to accept the "Allow debugging?" prompt on the TV...')
        time.sleep(2)
        devs = devices()
    ready = [s for s, state in devs.items() if state == 'device']
    if not ready:
        print(ENABLE_HELP)
        return 2
    infected = max(check_device(s, args.yes) for s in ready)
    print(AFTER_HELP)
    return infected


if __name__ == '__main__':
    sys.exit(main())
