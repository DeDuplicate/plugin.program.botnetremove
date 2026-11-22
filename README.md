# Botnet Remover (Kodi add-on)

Antivirus-style Kodi add-on that finds and removes the **XCPE botnet** (preinstalled on Videostrong / MECOOL
Android TV boxes) and the proxyware it loads, from the box Kodi runs on.

It connects to the box's own ADB (`127.0.0.1:5555`) with a built-in pure-Python ADB client. It checks the
installed packages, APK hashes, running processes, C2 connections and settings against the published
indicators of compromise (IOCs), removes the confirmed threats, scans again to check, and then shows
**"Device is cleared from XCPE botnet"**.

## Install
1. Download `plugin.program.botnetremove-x.y.z.zip` from [Releases](../../releases).
2. Kodi: Settings > System > Add-ons > turn on **Unknown sources**.
3. Add-ons > **Install from zip file** > pick the zip.

## Run
Open Add-ons > Program add-ons > **Botnet Remover**. Android only lets *you* turn debugging on, not an
app, so if it's off the add-on shows three steps and opens the right Settings screen for each one:
1. **Unlock developer mode**: click **Build** 7 times, then press Back.
2. **Turn on debugging**: turn on **USB debugging** and **Network debugging** / **ADB over network**, then
   press Back. No network option? Run `adb tcpip 5555` once from a PC over USB.
3. **Scan now**: if the box asks "Allow USB debugging?", tick **Always allow** and press OK.

Many boxes ship with debugging already on, and on those the scan starts right away. When it's done, let it
turn ADB off again. Open ADB is how botnets like Kimwolf get in.

You can also scan another box on your network: if the local connection fails, enter that box's IP.

## Limits
- If XCPE is part of the firmware (a system app), it gets uninstalled and stops running, but its files stay in
  the read-only firmware and **come back after a factory reset**. Replace the box or flash clean firmware.
- Android 11+ "Wireless debugging" (pairing codes) is not supported. Use ADB over network on port 5555.
- MEDIUM/LOW findings (heuristics) are only reported, never removed automatically.

## IOC sources
- Google Threat Intelligence, [Shutting the door on the XCPE botnet](https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet/) (Nov 2026)
- Synthient, [Videostrong research](https://github.com/synthient/public-research/blob/main/2026/11/Videostrong/README.md)
