# -*- coding: utf-8 -*-
"""
ota_tool.py — Hoozz Play OTA upgrade tool (interactive + command line).

Interactive (no arguments):
    python ota_tool.py
    1. scans the LAN for 5 s and lists the online devices
    2. you pick a device, then enter its access key
       (empty = the all-zero key of a factory device)
    3. the current firmware version is fetched - this also proves the
       key is right
    4. you enter the local firmware path and the upgrade runs with progress

Command line (non-interactive):
    python ota_tool.py scan [-t SECONDS]      list online devices
    python ota_tool.py devices                show the saved device records
    python ota_tool.py version -d DEV         print the device's version
    python ota_tool.py ota -d DEV -f FW       run an OTA upgrade

    DEV matches the device id (full 14 hex chars, or any unique prefix),
    the device name, or its IP address.
    Options: --key KEY (16 ASCII chars or 32 hex digits; default: the key
    saved for this device, or the zero key), --port PORT (OTA port,
    default 54550).

Per-device records (config.json next to this script): the access key and
the firmware path are remembered per device (keyed by device id), so the
next run pre-fills them.
"""
import argparse
import json
import os
import sys
import time

import hoozz_proto as proto

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

ALPHABET_NOTE = "16 ASCII chars, or 32 hex digits, or empty for the zero key"


# --- console helpers -------------------------------------------------------

def safe_print(text):
    """Print without crashing on odd characters (device names are UTF-8,
    the Windows console is often GBK)."""
    enc = sys.stdout.encoding or "utf-8"
    sys.stdout.write(text.encode(enc, "replace").decode(enc, "replace") + "\n")
    sys.stdout.flush()


def display_width(text):
    """Console cells occupied by [text] (East Asian wide/fullwidth chars
    take two cells on a CJK console)."""
    import unicodedata
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1
               for ch in text)


def pad(text, width):
    """Left-align [text] to [width] console cells (CJK-aware)."""
    return text + " " * max(0, width - display_width(text))


def prompt(text, default=""):
    """input() with a [default] hint; an empty answer takes the default."""
    suffix = (" [%s]" % default) if default else ""
    return input(text + suffix + ": ").strip() or default


# --- config ----------------------------------------------------------------

def load_config():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if isinstance(cfg, dict) and isinstance(cfg.get("devices"), dict):
            return cfg
    except (IOError, ValueError):
        pass
    return {"devices": {}}


def save_config(cfg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")


def record_device(cfg, dev, key=None, fw_path=None):
    """Upsert the record for a device (keyed by its 14-hex id)."""
    rec = cfg["devices"].setdefault(dev.dev_id, {
        "name": dev.name,
        "ip": dev.ip,
    })
    rec["name"] = dev.name
    rec["ip"] = dev.ip
    rec["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S")
    if key is not None:
        rec["key"] = key.hex()
    if fw_path is not None:
        rec["fw_path"] = os.path.abspath(fw_path)
    return rec


# --- device resolution -----------------------------------------------------

def resolve_device(devices, cfg, spec):
    """Match [spec] (id / id-prefix / name / ip) against the scanned
    devices; falls back to the saved records (by id/name) for the ip."""
    spec_l = spec.strip().lower()

    def match(dev_id, name, ip):
        return (dev_id == spec_l or dev_id.startswith(spec_l)
                or (name or "").lower() == spec_l or ip == spec_l)

    for dev in devices:
        if match(dev.dev_id, dev.name, dev.ip):
            return dev
    hits = [d for d in devices if d.dev_id.startswith(spec_l)]
    if len(hits) > 1:
        raise SystemExit("device prefix %r is ambiguous: %s"
                         % (spec, ", ".join(d.dev_id for d in hits)))

    for dev_id, rec in cfg["devices"].items():
        if match(dev_id, rec.get("name"), rec.get("ip")):
            dev = proto.DeviceInfo(dev_id, rec.get("name", "?"),
                                   0, 0, "-", rec.get("ip"))
            return dev
    raise SystemExit("device %r not found (scan the LAN or check the id)"
                     % spec)


def get_key(cfg, dev, key_text=None):
    """The access key: explicit > saved > zero."""
    if key_text is not None:
        try:
            return proto.parse_key(key_text)
        except ValueError as e:
            raise SystemExit("bad --key: %s" % e)
    rec = cfg["devices"].get(dev.dev_id, {})
    if rec.get("key"):
        return bytes.fromhex(rec["key"])
    return proto.ZERO_KEY


def get_fw_path(cfg, dev, fw_text=None):
    """The firmware path: explicit > saved > error."""
    if fw_text:
        return os.path.abspath(fw_text)
    rec = cfg["devices"].get(dev.dev_id, {})
    if rec.get("fw_path"):
        return rec["fw_path"]
    raise SystemExit("no firmware path given and none saved for this device")


# --- progress display ------------------------------------------------------

class Progress(object):
    def __init__(self, title):
        self.title = title

    def __call__(self, sent, total, device_pct, speed):
        sys.stdout.write("\r%s  %6.1f/%6.1f KB (%3d%%) | device %3d%%"
                         " | %5.1f KB/s   "
                         % (self.title, sent / 1024.0, total / 1024.0,
                            sent * 100 // total, device_pct, speed))
        sys.stdout.flush()


# --- OTA run (shared by both modes) ----------------------------------------

def run_ota(dev, key, fw_path, ota_port, progress_title=""):
    safe_print("Upgrading %s (%s) with %s" % (dev.name, dev.ip, fw_path))
    safe_print("  access key : %s" % proto.describe_key(key))
    safe_print("  ota port   : %d" % ota_port)
    safe_print("")

    old_v, new_v = proto.ota_transfer(dev.ip, key, fw_path,
                                      ota_port=ota_port,
                                      progress=Progress(progress_title))
    safe_print("")
    safe_print("OTA complete.")
    safe_print("  version before : %s" % old_v)
    safe_print("  version after  : %s" % new_v)
    if old_v != new_v:
        safe_print("  (the version changed, as expected for a new firmware)")
    return old_v, new_v


# --- interactive mode ------------------------------------------------------

def print_device_list(devices):
    for i, dev in enumerate(devices, 1):
        safe_print("  [%d] %s  id=%s  ip=%s"
                   % (i, pad(dev.name, 20), dev.dev_id, dev.ip))


def interactive():
    safe_print("== Hoozz Play OTA tool (interactive) ==")
    while True:
        safe_print("")
        safe_print("Scanning for devices (5 s)...")
        devices = proto.discover_devices(5.0)
        if not devices:
            safe_print("  no devices found (is the device on this LAN?)")
        else:
            safe_print("  %d device(s) found:" % len(devices))
            print_device_list(devices)

        choice = prompt("select a device [1-%d], s=rescan, q=quit"
                        % max(len(devices), 1)).lower()
        if choice == "q":
            return
        if choice == "s":
            continue
        if not choice.isdigit() or not (1 <= int(choice) <= len(devices)):
            safe_print("  bad choice, try again")
            continue
        dev = devices[int(choice) - 1]

        cfg = load_config()
        rec = cfg["devices"].get(dev.dev_id, {})

        # the access key (saved key pre-filled)
        saved_key_hex = rec.get("key")
        saved_key = bytes.fromhex(saved_key_hex) if saved_key_hex else None
        while True:
            default = (saved_key_hex
                       if saved_key else "(empty = zero key)")
            raw = input("access key of %s (%s)"
                        % (dev.name, ALPHABET_NOTE) + " [" + default + "]: ")
            try:
                key = proto.parse_key(raw)
            except ValueError as e:
                safe_print("  %s" % e)
                continue
            break
        if key != (saved_key or proto.ZERO_KEY):
            saved_key_hex = key.hex()  # a new key will be saved

        # fetch the version: this also verifies the key
        safe_print("  fetching the current firmware version (verifies the "
                   "key)...")
        try:
            ctrl = proto.CtrlClient(dev.ip, key=key)
            version = ctrl.fw_version()
            ctrl.close()
        except (OSError, proto.ControlError) as e:
            safe_print("  failed: %s" % e)
            safe_print("  the key is probably wrong, try again")
            continue
        safe_print("  current version: %s" % version)

        # the firmware path (saved path pre-filled)
        saved_fw = rec.get("fw_path", "")
        while True:
            path = prompt("local firmware path", saved_fw)
            path = os.path.abspath(path)
            if os.path.isfile(path):
                break
            safe_print("  no such file: %s" % path)
        size = os.path.getsize(path)
        safe_print("  firmware: %d bytes" % size)

        answer = prompt("upgrade this device now? [y/N]").lower()
        if answer not in ("y", "yes"):
            safe_print("  cancelled (the key/path are NOT saved)")
            continue

        try:
            run_ota(dev, key, path, proto.OTA_DEFAULT_PORT,
                    progress_title="  ")
        except (OSError, proto.ControlError) as e:
            safe_print("")
            safe_print("OTA FAILED: %s" % e)
            safe_print("the device keeps running its old firmware.")
            continue

        # remember this device
        record_device(cfg, dev, key=key, fw_path=path)
        save_config(cfg)
        safe_print("  device record saved to %s" % CONFIG_FILE)

        answer = prompt("continue? [y=N]").lower()
        if answer in ("n", "no", "q"):
            return


# --- command line mode -----------------------------------------------------

def cmd_scan(args):
    safe_print("Scanning for devices (%.0f s)..." % args.seconds)
    devices = proto.discover_devices(args.seconds)
    if not devices:
        safe_print("no devices found")
        return 1
    safe_print("%d device(s):" % len(devices))
    print_device_list(devices)
    return 0


def cmd_devices(args):
    cfg = load_config()
    if not cfg["devices"]:
        safe_print("no saved device records yet (%s)" % CONFIG_FILE)
        return 0
    for dev_id, rec in sorted(cfg["devices"].items()):
        key = rec.get("key")
        safe_print("%s  name=%s ip=%s key=%s"
                   % (dev_id, pad(rec.get("name", "?"), 20),
                      pad(rec.get("ip", "?"), 15),
                      proto.describe_key(bytes.fromhex(key)) if key
                      else "(zero)"))
        if rec.get("fw_path"):
            safe_print("    fw: %s" % rec["fw_path"])
        if rec.get("last_seen"):
            safe_print("    last seen: %s" % rec["last_seen"])
    return 0


def with_device(args, quick_scan=3.0):
    """Scan (briefly) + resolve the device + key + return (dev, key)."""
    cfg = load_config()
    devices = proto.discover_devices(quick_scan)
    dev = resolve_device(devices, cfg, args.device)
    key = get_key(cfg, dev, getattr(args, "key", None))
    return dev, key


def cmd_version(args):
    dev, key = with_device(args)
    ctrl = proto.CtrlClient(dev.ip, key=key)
    try:
        version = ctrl.fw_version()
    finally:
        ctrl.close()
    safe_print("%s (%s): %s" % (dev.name, dev.ip, version))
    return 0


def cmd_ota(args):
    dev, key = with_device(args)
    fw_path = get_fw_path(load_config(), dev, args.firmware)
    if not os.path.isfile(fw_path):
        raise SystemExit("no such firmware file: %s" % fw_path)
    run_ota(dev, key, fw_path, args.port, progress_title="")
    cfg = load_config()
    record_device(cfg, dev, key=key, fw_path=fw_path)
    save_config(cfg)
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        description="Hoozz Play OTA upgrade tool",
        epilog="with no subcommand the interactive mode starts")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("scan", help="list the online devices")
    sp.add_argument("-t", "--seconds", type=float, default=5.0,
                    help="scan duration in seconds (default 5)")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("devices", help="show the saved device records")
    sp.set_defaults(func=cmd_devices)

    sp = sub.add_parser("version", help="print a device's firmware version")
    sp.add_argument("-d", "--device", required=True,
                    help="device id (or prefix), name, or ip")
    sp.add_argument("--key", help=ALPHABET_NOTE)
    sp.set_defaults(func=cmd_version)

    sp = sub.add_parser("ota", help="run an OTA upgrade")
    sp.add_argument("-d", "--device", required=True,
                    help="device id (or prefix), name, or ip")
    sp.add_argument("-f", "--firmware",
                    help="local firmware path (default: the saved one)")
    sp.add_argument("--key", help=ALPHABET_NOTE)
    sp.add_argument("-p", "--port", type=int, default=proto.OTA_DEFAULT_PORT,
                    help="the OTA tunnel port (default %d)"
                         % proto.OTA_DEFAULT_PORT)
    sp.set_defaults(func=cmd_ota)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if getattr(args, "func", None) is None:
        interactive()
        return 0
    try:
        return args.func(args)
    except (OSError, proto.ControlError, SystemExit) as e:
        if isinstance(e, SystemExit):
            raise
        safe_print("ERROR: %s" % e)
        return 1
    except KeyboardInterrupt:
        safe_print("\ninterrupted")
        return 130
    except EOFError:
        # stdin exhausted (piped input ran out): a clean exit, not a
        # traceback
        safe_print("\ninput ended, exiting")
        return 0


if __name__ == "__main__":
    sys.exit(main())
