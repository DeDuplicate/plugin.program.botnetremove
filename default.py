"""Botnet Remover: finds TV-box botnets (XCPE, BADBOX, Vo1d, Kimwolf...) on this Android box and removes it, antivirus-style.

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
ACTIVE = ('Malicious package', 'Live connection', 'Malicious process', 'ADB opened')  # anything else left is inert residue
# Android lets only the user turn debugging on (an app that could would be malware's dream), so we walk them
# through it, opening each Settings page straight from Kodi: (label, how-to, settings intent).
STEPS = [
    ('1. Unlock developer mode',
     'Click "Build" 7 times until it says "You are now a developer". Then press Back.',
     'android.settings.DEVICE_INFO_SETTINGS'),
    ('2. Turn on debugging',
     'Turn on "USB debugging" and "Network debugging" (or "ADB over network"). Then press Back.',
     'android.settings.APPLICATION_DEVELOPMENT_SETTINGS'),
]
RETRY = ('3. Scan now', 'If the box asks "Allow USB debugging?": tick "Always allow" and press OK.')
OTHER = ('Clean another box on my network', 'Enter the IP address of a box that has network debugging on.')
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
    android = xbmc.getCondVisibility('System.Platform.Android')
    steps = STEPS if android else []  # off-box (e.g. Windows Kodi) the only option is another box's IP
    menu = [xbmcgui.ListItem(label, how) for label, how, *_ in steps + [RETRY] + ([] if android else [OTHER])]
    while True:
        pd.create(NAME, f'Connecting to ADB at {addr}...')
        try:
            host, _, port = addr.partition(':')
            return Adb(host, int(port or 5555),
                       lambda: pd.update(0, 'Press [B]Allow[/B] on the "Allow USB debugging?" prompt'))
        except (OSError, ValueError) as e:
            pd.close()
            xbmc.log(f'[{NAME}] ADB at {addr} unreachable: {e}', xbmc.LOGINFO)
            while True:  # guide menu: steps open Settings and come back here; Scan now / another box retry
                i = dlg.select('Turn on debugging so Botnet Remover can scan this box', menu, useDetails=True)
                if i < 0:
                    return None
                if i < len(steps):
                    # FLAG_ACTIVITY_NEW_TASK, like `am start`: without it About opened and closed at once (MuMu)
                    xbmc.executebuiltin(f'StartAndroidActivity("",{steps[i][2]},"","",268435456)')
                    xbmc.sleep(2000)  # let Settings take the screen before the menu reopens behind it
                    continue
                if i == len(steps) + 1:
                    addr = dlg.input('IP address of the box', addr) or addr
                break


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
            dlg.notification(NAME, f'INFECTED: botnet found, removing {len(bad)} threat(s)...',
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
        infected = f'[COLOR red][B]Scan result: INFECTED[/B][/COLOR] - {len(bad)} botnet threat(s) found.\n'
        if left:
            dlg.ok(NAME, infected + '[COLOR red][B]The botnet could not be fully removed:[/B][/COLOR]\n'
                   + '\n'.join(f.title for f in left))
        elif bad:
            dlg.ok(NAME, infected + '[COLOR lime][B]Device is cleared from the botnet.[/B][/COLOR]\n'
                   + (f'{len(residue)} inactive leftover(s) in the read-only firmware come back after a factory '
                      'reset. ' if residue else '')
                   + 'Reboot and run again to make sure it stays gone.')
        else:
            dlg.ok(NAME, '[COLOR lime][B]Scan result: CLEAN[/B][/COLOR]\nNo botnet found on this device.')
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
