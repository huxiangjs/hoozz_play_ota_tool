# Hoozz Play OTA Tool

A command-line / interactive tool for OTA firmware upgrades of Hoozz Play
devices (ESP8266 smart IR remotes), over the control channel (TCP 54542,
the AES128-CBC-encrypted HOOZZ protocol).

[简体中文](README_zh.md)

## The upgrade process

1. discover the device over UDP (`HOOZZ?` query / `HOOZZ:...` reply)
2. send `INFO/FW_UPGRADE` over the control channel with
   `hoozz://<16-char visible key>/<port>`
3. the device opens an OTA tunnel on that port (tcp_crypto,
   authenticated by the "HoozzPlay" handshake)
4. the client sends the total firmware size as 4 little-endian bytes, then
   streams the firmware in chunks of at most 1024 bytes
5. the control channel polls `INFO/FW_PROGRESS` for the progress display;
   at 100% the device reboots ~3 s later
6. after the reboot, reconnect and read `INFO/FW_VERSION` to verify the
   upgrade

Key points of the discovery mechanism (established empirically, and the
reason the scanner works at all):

- the device's reply is **unicast back to the query's source address**
  (its `recvfrom` rewrites the reply destination to the sender), so the
  query has to be sent FROM port 54543 and received on the same socket;
  a query sent from an ephemeral port is answered to that ephemeral port
  and is lost
- the query is sent on two legs: a unicast probe of every /24 of every
  local network interface (one round every 2 s) plus a broadcast to
  255.255.255.255:54542 (every second; on many home APs
  client-to-client broadcasts are blocked, in which case only the
  unicast leg works)
- for ~4 s after boot the device also self-announces by broadcasting
  `HOOZZ:...` to 255.255.255.255:54543, which a scanner listening on
  54543 picks up while it happens

## Requirements

- Python 3.7+
- `pip install cryptography`
- the scanner must be on the same LAN as the device

## Quick start (interactive mode)

```
python ota_tool.py
```

1. scans the LAN for 5 s and lists the online devices
   (number / name / class / ID / IP)
2. enter the device number (s = rescan, q = quit)
3. enter the access key (16 bytes, see the format section below; empty
   = the all-zero key, which is what factory devices use; the key saved
   for this device is pre-filled if you used it before)
4. the tool immediately fetches the firmware version - this also
   verifies the key; if it is right, enter the local firmware path (the
   saved path is pre-filled if present)
5. confirm to start the upgrade; sent/total, device-side progress and
   speed are shown live
6. once the upgrade finishes, the device reboots, the version is
   verified, and the key + path are recorded in `config.json` keyed by
   device ID - no re-entry needed next time

## Command line (non-interactive)

```
python ota_tool.py scan [-t SECONDS]        list the online devices (default 5 s)
python ota_tool.py devices                  show the saved device records
python ota_tool.py version -d <DEVICE>      print the device's firmware version
python ota_tool.py ota -d <DEVICE> -f <FW>  run an OTA upgrade
```

`-d <DEVICE>` accepts three forms: the device ID (14 hex chars, a unique
prefix works), the device name, or the IP address.

The device list shows each device's class (type) as `class=NN(NAME)`
(e.g. `03(SMART_IR)`, `04(SENSOR)`, `06(SWITCH)`; the names follow the
firmware's `class_id.h`), so you can confirm what kind of device you are
about to upgrade straight from the printed list.

Both `version` and `ota` accept `--key`; `-f` and `-p` are `ota`-only:

| option | command | meaning |
|---|---|---|
| `--key` | version / ota | access key (default: the one saved for this device, else the zero key) |
| `-f, --firmware` | ota | firmware path (default: the one saved for this device) |
| `-p, --port` | ota | OTA tunnel port (default 54550) |

Examples:

```
python ota_tool.py scan -t 8
python ota_tool.py version -d a848fad630e4
python ota_tool.py ota -d a848fad630e4 -f E:\fw\smart_ir.bin
python ota_tool.py ota -d "SMART IR" --key 00000000000000000000000000000000 -f smart_ir.bin -p 54551
```

## Access key format

The device's access key is a 16-byte AES-128 key (= the access password
set on the device, zero-padded to 16 bytes; a factory device without a
password has the all-zero key). Three input forms are supported:

| input | interpretation |
|---|---|
| empty (just Enter) | the all-zero key (factory devices) |
| 16 ASCII characters | used verbatim as the 16-byte key |
| 32 hex digits | parsed into the 16-byte key |

In interactive mode a saved key is pre-filled in its readable form
(visible characters as-is; the zero key shows as `(zero key)`);
`config.json` itself still stores the key as hex (unambiguous even for
binary keys).

## Device records (config.json)

Next to the script. Keyed by device ID (14 hex chars): name, IP, access
key (hex), firmware path, last-seen time. Written automatically after a
successful upgrade; view them any time with
`python ota_tool.py devices`. This is a local file - **do not commit it
to git** (it is in .gitignore).

## FAQ

- **Wrong key**: if the device cannot decrypt the correct magic it
  closes the TCP connection right away; the tool reports
  `device closed the connection`. Try another key (factory devices: try
  the empty key first).
- **No devices found by the scan**: make sure the scanner is on the same
  LAN; on multi-NIC machines the tool probes the /24 of every local
  network, so no intervention is usually needed. For a few seconds
  after a reboot the device self-announces `HOOZZ:...` broadcasts,
  which a scan also picks up.
- **FW_UPGRADE rejected (busy)**: after an interrupted upgrade (e.g. the
  client crashed) the device is still in its 30 s tunnel-accept window
  and refuses new upgrade requests; it recovers on its own when the
  window ends. The tool retries automatically (up to ~45 s), so no
  intervention is usually needed.
- **Cannot connect to the OTA port**: 54550 doubles as the IR remote
  tunnel port; if another app has an IR tunnel open on it at the time,
  use a different port (`-p 54551`).
- **Network drops mid-upgrade**: the device-side watchdog timeouts (15 s
  per chunk, 30 s accept) abandon the upgrade and keep running the old
  firmware - the device cannot be bricked this way.
- **Validation and rollback**: a new image is marked valid if it runs
  stably for 10 s after boot; after 3 consecutive failed boots the
  device rolls back to the previous partition automatically.

## Files

| file | purpose |
|---|---|
| `ota_tool.py` | entry point: interactive mode + CLI + device records |
| `hoozz_proto.py` | protocol layer: discovery / control channel / OTA tunnel / AES frames |
| `config.json` | per-device key + firmware path records (generated at runtime, not committed) |
