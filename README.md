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
1. On the box: Settings > Device Preferences > About, click **Build** 7 times to unlock Developer options.
2. In Developer options, turn on **USB debugging** and **ADB over network / Network debugging** (port 5555).
   No network option? Run `adb tcpip 5555` once from a PC over USB.
3. Open Add-ons > Program add-ons > **Botnet Remover** and press **Allow** on the "Allow USB debugging?" prompt.
4. When it's done, let it turn ADB off again. Open ADB is how botnets like Kimwolf get in.

You can also scan another box on your network: if the local connection fails, enter that box's IP.

## Limits
- If XCPE is part of the firmware (a system app), it gets uninstalled and stops running, but its files stay in
  the read-only firmware and **come back after a factory reset**. Replace the box or flash clean firmware.
- Android 11+ "Wireless debugging" (pairing codes) is not supported. Use ADB over network on port 5555.
- MEDIUM/LOW findings (heuristics) are only reported, never removed automatically.

## IOC sources
- Google Threat Intelligence, [Shutting the door on the XCPE botnet](https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet/) (Nov 2026)
- Synthient, [Videostrong research](https://github.com/synthient/public-research/blob/main/2026/11/Videostrong/README.md)
