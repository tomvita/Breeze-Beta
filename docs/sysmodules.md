# Sysmodule Manager

Open **Settings → Sysmodule Manager** to inspect optional Atmosphere sysmodules.

## On and Off

- **On** means Breeze detected that the sysmodule is currently loaded and running.
- **Off** means no running process was detected.
- A sysmodule can load, finish its task, exit normally, and therefore show Off.

There are two kinds of sysmodule:

1. Immediate sysmodules can be launched and terminated without restarting.
2. Boot-time sysmodules require a console restart. Breeze displays a popup when a selected module requires restart.

For boot-time modules, the button describes the current session, not the pending next-boot setting. A newly enabled module remains Off until restart. A running module scheduled for disable can remain On until restart.

The Gen2 fork (`010000000000D609`) is managed by Breeze's dedicated Gen2 controls and is intentionally excluded from Sysmodule Manager.

## sys-ftp-breeze

`sys-ftp-breeze` is a special FTP-server fork with Breeze-aware, game-specific mount points. These mounts make the active game's files and Breeze workflow locations easier to access from an FTP client.

Configure it through `/breeze:/config.ini`. The installation supplies a template such as `config.ini.template`; rename the supplied template to `config.ini` by removing its template/default suffix.

Configure either a username and password or anonymous access. Anonymous FTP can expose files to other devices on the network and is a security risk on untrusted networks. Writing to game save data is disabled by default and must be explicitly enabled in `config.ini` when required.
