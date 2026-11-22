"""Botnet Remover: finds the XCPE botnet on this Android TV box and removes it, antivirus-style.

Shell access comes from the box's own adbd (127.0.0.1:5555) via adb.py; detection and the removal
commands are xcpe_remover.scan() + iocs.json (copied from the XCPE remover PC tool).
"""
import re

import xbmc
import xbmcaddon
import xbmcgui

from adb import Adb
from xcpe_remover import AFTER_HELP, scan

NAME = 'Botnet Remover'
COLORS = {'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow', 'INFO': 'grey'}
ACTIVE = ('Malicious package', 'Live connection', 'Malicious process')  # anything else left is inert residue
ENABLE_HELP = """[B]Turn on ADB so the add-on can clean this box:[/B]
1. Settings > Device Preferences > About: click "Build" 7 times (older boxes: Settings > About > Build number).
2. Developer options: turn on "USB debugging" and "ADB over network" / "Network debugging" (port 5555).
   No network option? Run once from a PC over USB:  adb tcpip 5555
   ("Wireless debugging" with pairing codes is not supported.)
3. Run the add-on again and press "Allow" on the "Allow USB debugging?" prompt.

To clean another box on your network, enter its IP address on the next screen."""
dlg = xbmcgui.Dialog()


class Cancelled(Exception):
    pass


def report(findings):
    return '\n'.join(f'[COLOR {COLORS[f.sev]}][B]{f.sev}[/B][/COLOR]  {f.title}'
                     + (f'\n        {f.detail}' if f.detail else '') for f in findings) or 'No threats found.'


def log(title, findings):
    xbmc.log(f'[{NAME}] {title}: ' + ' | '.join(f'[{f.sev}] {f.title} {f.detail}' for f in findings), xbmc.LOGINFO)


def connect(pd):
    addr = '127.0.0.1:5555'
    while True:
        pd.create(NAME, f'Connecting to ADB at {addr}...')
        try:
            host, _, port = addr.partition(':')
            return Adb(host, int(port or 5555),
                       lambda: pd.update(0, 'Press [B]Allow[/B] on the "Allow USB debugging?" prompt'))
        except (OSError, ValueError) as e:
            pd.close()
            dlg.textviewer(NAME, f'Could not connect to ADB at {addr}: {e}\n\n{ENABLE_HELP}')
            addr = dlg.input('ADB address of the box (this box: 127.0.0.1:5555)', addr)
            if not addr:
                return None


def main():
    pd = xbmcgui.DialogProgress()
    adb = connect(pd)
    if not adb:
        return
    step = [0]

    def sh(cmd):
        if pd.iscanceled():
            raise Cancelled
        step[0] += 1
        pd.update(min(99, step[0] * 3), cmd[:80])
        return adb.shell(cmd)

    try:
        cache = {}
        found = scan(sh, cache)
        log('scan', found)
        bad = [f for f in found if f.sev == 'HIGH']
        if bad:  # antivirus mode: remove every IOC-confirmed threat; heuristics (MEDIUM/LOW) are only reported
            dlg.notification(NAME, f'INFECTED: XCPE botnet found, removing {len(bad)} threat(s)...',
                             xbmcaddon.Addon().getAddonInfo('icon'), 8000)
            for f in bad:
                for c in f.fix or ():
                    sh(c)
            sh('logcat -c')  # old C2 lookups in the log would re-flag the cleaned box
            found = scan(sh, cache)
            log('after removal', found)
        pd.close()

        disabled = set(re.findall(r'^package:(\S+)', adb.shell('pm list packages -d'), re.M))
        left = [f for f in found if f.sev == 'HIGH' and f.title.startswith(ACTIVE)
                and f.title.split()[-1] not in disabled]  # disable-user fallback = neutralised
        residue = [f for f in found if f.sev == 'HIGH' and f not in left]
        infected = f'[COLOR red][B]Scan result: INFECTED[/B][/COLOR] - {len(bad)} XCPE threat(s) found.\n'
        if left:
            dlg.ok(NAME, infected + '[COLOR red][B]XCPE could not be fully removed:[/B][/COLOR]\n'
                   + '\n'.join(f.title for f in left))
        elif bad:
            dlg.ok(NAME, infected + '[COLOR lime][B]Device is cleared from XCPE botnet.[/B][/COLOR]\n'
                   + (f'{len(residue)} inactive leftover(s) in the read-only firmware come back after a factory '
                      'reset. ' if residue else '')
                   + 'Reboot and run again to make sure it stays gone.')
        else:
            dlg.ok(NAME, '[COLOR lime][B]Scan result: CLEAN[/B][/COLOR]\nNo XCPE botnet found on this device.')
        if found:
            dlg.textviewer(NAME, report(found) + (AFTER_HELP if bad else ''))

        if dlg.yesno(NAME, 'Turn ADB debugging off now? (recommended)\n'
                           'Open ADB is how botnets like Kimwolf get in. Turn it back on to scan again.'):
            try:
                adb.shell('settings put global adb_enabled 0')
            except OSError:
                pass  # adbd went down mid-reply: that's the point
    except Cancelled:
        pass
    except OSError as e:
        dlg.ok(NAME, f'Lost the ADB connection: {e}')
    finally:
        pd.close()
        adb.close()


main()
