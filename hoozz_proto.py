# -*- coding: utf-8 -*-
"""
hoozz_proto.py — Hoozz Play device protocol layer.

Three pieces, all as used by the phone app:

1. Discovery (UDP)
   The device answers each "HOOZZ?" query (sent to its port 54542) with
       HOOZZ:<class 2hex><crypto 2hex><has-pw 1 char><id 14hex><name>
   The reply goes back to the query's SOURCE address - the device's
   recvfrom() overwrites the reply destination with the sender's - so a
   query sent from port 54543 is answered to 54543, and a query from an
   ephemeral port is answered to that ephemeral port (lost). The scanner
   must therefore send its queries FROM port 54543. The query is sent
   two ways: broadcast to 255.255.255.255:54542 (dead on networks that
   block client-to-client broadcasts) and as a unicast probe over every
   local /24 of the scanner's own interfaces (works everywhere; the
   device may sit on any of the scanner's LANs). The device also broadcasts its own
   "HOOZZ:..." self-announce for a few seconds after boot, which the
   54543 listener picks up while it happens.

2. Control channel (TCP 54542)
   packet = [ptype 1B][len 4B LE] + IV(16) + AES128-CBC(header16 + data)
   header16 = "HOOZZ" + 7 zero bytes + data_len(4B LE)   (zero-padded to 16)
   ptype: 0x00 PING / 0x01 INFO / 0x02 REQUEST / 0x03 NOTIFY
   INFO subcommands used here:
       0x04 FW_VERSION  -> [cmd, ret, version...]
       0x05 FW_UPGRADE  -> request [cmd, url...], response [cmd, ret]
       0x06 FW_PROGRESS -> [cmd, ret, progress 0-100]
   The 16-byte AES key is the device's access password bytes, zero-padded
   to 16 (a factory device without a password uses the all-zero key).
   A wrong key decrypts to garbage and the device closes the connection
   (no explicit error message comes back).

3. OTA tunnel (TCP, device-side listener on the port carried in the url)
   frame = [len 2B LE] + IV(16) + AES128-CBC(plaintext zero-padded to 16)
   handshake: the first message each way is the 9-byte "HoozzPlay"; the
   device verifies the plaintext, which authenticates the key.
   After the handshake the client sends:
       msg 1 : 4-byte little-endian firmware total size
       msg 2..N: the firmware in messages of at most 1024 bytes
   The url format is "hoozz://<key16>/<port>"; the key is 16 visible
   characters (no hex) used directly as the AES-128 key.
"""
import os
import socket
import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CTRL_PORT = 54542
DISCOVER_QUERY_PORT = 54542   # device listens for "HOOZZ?" here
DISCOVER_RESPOND_PORT = 54543 # device broadcasts its reply here
DISCOVER_SAY = b"HOOZZ?"
DISCOVER_PREFIX = b"HOOZZ:"

# INFO subcommands (outer ptype 0x01)
INFO_FW_VERSION = 0x04
INFO_FW_UPGRADE = 0x05
INFO_FW_PROGRESS = 0x06

RETURN_OK = 0x00
RETURN_FAIL = 0x01

ZERO_KEY = b"\x00" * 16
KEY_LENGTH = 16
OTA_CHUNK = 1024
OTA_DEFAULT_PORT = 54550


# --- AES helpers -----------------------------------------------------------

def aes_cbc_encrypt(key, plaintext):
    """IV(16) + AES128-CBC ciphertext, zero-padded to the 16-byte boundary."""
    pad = (16 - len(plaintext) % 16) % 16
    data = plaintext + b"\x00" * pad
    iv = os.urandom(16)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv),
                 backend=default_backend()).encryptor()
    return iv + enc.update(data) + enc.finalize()


def aes_cbc_decrypt(key, blob):
    """blob = IV(16) + ciphertext; returns the full (padded) plaintext."""
    iv, data = blob[:16], blob[16:]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv),
                 backend=default_backend()).decryptor()
    return dec.update(data) + dec.finalize()


# --- key handling ----------------------------------------------------------

def parse_key(text):
    """Turn user input into a 16-byte AES key.

    empty string        -> the all-zero key (factory devices)
    32 hex digits       -> raw bytes
    exactly 16 chars    -> the raw ASCII bytes (visible-char key)
    anything else       -> ValueError
    """
    s = (text or "").strip()
    if not s:
        return ZERO_KEY
    if len(s) == 32 and all(c in "0123456789abcdefABCDEF" for c in s):
        return bytes.fromhex(s)
    if len(s) == 16:
        try:
            return s.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("a 16-char key must be plain ASCII")
    raise ValueError(
        "key must be empty (zero key), 16 ASCII chars, or 32 hex digits")


def describe_key(key):
    """A printable form of a 16-byte key."""
    if key == ZERO_KEY:
        return "(zero key)"
    if all(0x21 <= b <= 0x7e for b in key):
        return bytes(key).decode("ascii")
    return key.hex()


# --- discovery -------------------------------------------------------------

class DeviceInfo(object):
    def __init__(self, dev_id, name, class_id, crypto_type, has_pwd, ip):
        self.dev_id = dev_id          # 14 hex chars (6 fixed id bytes + "00")
        self.name = name              # device name (UTF-8)
        self.class_id = class_id      # e.g. 0x03 smart IR
        self.crypto_type = crypto_type
        self.has_pwd = has_pwd        # '*' has a password, '-' does not
        self.ip = ip

    def __repr__(self):
        return "DeviceInfo(%s, %r, %s)" % (self.dev_id, self.name, self.ip)


def parse_discover(data):
    """Parse a "HOOZZ:..." discovery reply. Returns DeviceInfo or None
    (ip is filled in by the caller)."""
    if not data.startswith(DISCOVER_PREFIX):
        return None
    body = data[len(DISCOVER_PREFIX):]
    if len(body) < 2 + 2 + 1 + 14:
        return None
    try:
        class_id = int(body[0:2], 16)
        crypto_type = int(body[2:4], 16)
        has_pwd = body[4:5]
        dev_id = body[5:19].decode("ascii").lower()
    except (ValueError, UnicodeDecodeError):
        return None
    name = body[19:].decode("utf-8", "replace")
    return DeviceInfo(dev_id, name, class_id, crypto_type, has_pwd, None)


def local_network_prefixes():
    """The /24 prefix of every local IPv4 address, e.g. ['192.168.1'].
    Every interface is probed: the device may be on ANY of this host's
    LANs, and the default-route interface is NOT necessarily the right
    one (e.g. a VPN/virtual adapter may take the default route while the
    device sits on the plain home LAN)."""
    prefixes = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None,
                                       socket.AF_INET):
            ip = info[4][0]
            if ip.startswith("127."):
                continue
            prefixes.add(".".join(ip.split(".")[:3]))
    except OSError:
        pass
    if not prefixes:
        # fallback: the default-route interface (connect() sends no
        # packet; it only selects the outgoing interface)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            prefixes.add(".".join(s.getsockname()[0].split(".")[:3]))
        except OSError:
            pass
        finally:
            s.close()
    return sorted(prefixes)


def discover_devices(seconds=5.0, interval=1.0):
    """Find Hoozz Play devices for [seconds].

    The device answers each "HOOZZ?" query with "HOOZZ:<class><crypto>
    <has-pw><id14><name>" sent back to the query's SOURCE address
    (its recvfrom() overwrites the reply destination with the sender's),
    so the query must be sent FROM port 54543 and the scanner listens
    on the same socket: a query from an ephemeral port is answered to
    that ephemeral port, where nobody listens.

    Two complementary query legs (one socket, bound to 54543):
      1. a unicast "HOOZZ?" to every address of every local /24
         (all of this host's LANs), repeated every 2*[interval] s
         (works everywhere; also re-probes devices that were busy when
         the first burst went out)
      2. a broadcast "HOOZZ?" to 255.255.255.255:54542 every [interval] s
         (dead on networks that block client-to-client broadcasts)
    In addition the device broadcasts its own "HOOZZ:..." self-announce
    to 255.255.255.255:54543 for ~4 s after boot, which this listener
    picks up while it happens.

    Windows quirk handled: an ICMP "port unreachable" from a dead host
    makes the next sendto()/recvfrom() to THAT host fail once with
    WSAECONNRESET (10054); the error state clears by itself, so the
    failing call is simply retried/skipped and the socket is never
    closed (closing it would drop the replies already in its queue).

    Returns a list of DeviceInfo (one per unique device id).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # The device answers to the query's source address, so sending from
    # and receiving on this (54543) port is what delivers the replies.
    s.bind(("0.0.0.0", DISCOVER_RESPOND_PORT))
    s.settimeout(0.25)

    devices = {}
    prefixes = local_network_prefixes()

    def probe_unicast():
        for prefix in prefixes:
            for host in range(1, 255):
                try:
                    s.sendto(DISCOVER_SAY, ("%s.%d" % (prefix, host),
                                            DISCOVER_QUERY_PORT))
                except OSError:
                    pass  # transient 10054: no device there, error clears

    def probe_broadcast():
        try:
            s.sendto(DISCOVER_SAY, ("255.255.255.255", DISCOVER_QUERY_PORT))
        except OSError:
            pass

    probe_unicast()
    probe_broadcast()

    deadline = time.time() + seconds
    last_unicast = time.time()
    last_bcast = time.time()
    while time.time() < deadline:
        now = time.time()
        if now - last_bcast >= interval:
            probe_broadcast()
            last_bcast = now
        if now - last_unicast >= 2.0 * interval:
            probe_unicast()
            last_unicast = now
        try:
            data, addr = s.recvfrom(512)
        except socket.timeout:
            continue
        except OSError:
            continue  # transient 10054 from a dead host, clears by itself
        dev = parse_discover(data)
        if dev is not None:
            dev.ip = addr[0]
            devices[dev.dev_id] = dev
    s.close()
    # Stable order (by device id) so the numbered list is predictable
    # between runs.
    return sorted(devices.values(), key=lambda d: d.dev_id)


# --- control channel -------------------------------------------------------

def build_packet(key, ptype, data):
    """[ptype 1B][len 4B LE] + IV(16) + AES128-CBC(header16 + data)."""
    header = b"HOOZZ" + b"\x00" * 7 + struct.pack("<I", len(data))
    blob = aes_cbc_encrypt(key, header + data)
    return struct.pack("<BI", ptype, len(blob)) + blob


class ControlError(Exception):
    """A control-channel problem (bad key, device closed, bad response...)."""


class CtrlClient(object):
    """The encrypted control channel (TCP 54542)."""

    def __init__(self, ip, port=CTRL_PORT, key=ZERO_KEY, timeout=5):
        self.ip = ip
        self.key = key
        self.sock = socket.create_connection((ip, port), timeout=timeout)
        self.sock.settimeout(timeout)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ControlError(
                    "device closed the connection "
                    "(with a wrong key the device closes here: the "
                    "decrypted magic does not match)")
            buf += chunk
        return buf

    def _read_packet(self):
        head = self._read_exact(5)
        ptype, length = struct.unpack("<BI", head)
        blob = self._read_exact(length)
        plain = aes_cbc_decrypt(self.key, blob)
        if plain[:6] != b"HOOZZ\x00":
            raise ControlError("bad magic in the device response: %r"
                               % plain[:6])
        data_len = struct.unpack("<I", plain[12:16])[0]
        return ptype, plain[16:16 + data_len]

    def info(self, sub, payload=b""):
        """Send INFO (0x01) subcommand [sub] and wait for the response,
        skipping NOTIFY (0x03) messages the device may interleave."""
        self.sock.sendall(build_packet(self.key, 0x01, bytes([sub]) + payload))
        while True:
            ptype, rdata = self._read_packet()
            if ptype == 0x03:
                continue
            return rdata

    def fw_version(self):
        r = self.info(INFO_FW_VERSION)
        if not r or r[0] != INFO_FW_VERSION:
            raise ControlError("unexpected FW_VERSION response: %r" % r[:4])
        if r[1] != RETURN_OK:
            raise ControlError("FW_VERSION rejected: %r" % r[:4])
        return r[2:].decode("utf-8", "replace")

    def fw_upgrade(self, url):
        r = self.info(INFO_FW_UPGRADE, url.encode("ascii"))
        if not r or r[0] != INFO_FW_UPGRADE:
            raise ControlError("unexpected FW_UPGRADE response: %r" % r[:4])
        if r[1] != RETURN_OK:
            raise ControlError("FW_UPGRADE rejected: %r" % r[:4])

    def fw_progress(self):
        r = self.info(INFO_FW_PROGRESS)
        if not r or r[0] != INFO_FW_PROGRESS:
            raise ControlError("unexpected FW_PROGRESS response: %r" % r[:4])
        if r[1] != RETURN_OK:
            raise ControlError("FW_PROGRESS rejected: %r" % r[:4])
        return r[2]


# --- OTA tunnel ------------------------------------------------------------

class TunnelClient(object):
    """The OTA tunnel: the device's listener on [port], keyed by [key]
    (16 visible chars used as the raw AES key)."""

    def __init__(self, ip, port, key, timeout=5):
        self.sock = socket.create_connection((ip, port), timeout=timeout)
        self.sock.settimeout(timeout)
        if isinstance(key, str):
            key = key.encode("ascii")
        self.key = bytes(key)
        # handshake: the first message each way is "HoozzPlay"; the device
        # verifies the decrypted content, which authenticates the key
        self.send_msg(b"HoozzPlay")
        if self.recv_msg(9) != b"HoozzPlay":
            raise ControlError("tunnel handshake failed (wrong key?)")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ControlError("tunnel closed by the device")
            buf += chunk
        return buf

    def send_msg(self, data):
        self.sock.sendall(struct.pack("<H", len(data)) +
                          aes_cbc_encrypt(self.key, data))

    def recv_msg(self, size):
        """Receive one message whose plaintext is exactly [size] bytes."""
        (length,) = struct.unpack("<H", self._read_exact(2))
        if length != size:
            raise ControlError("tunnel size mismatch: %d != %d"
                               % (length, size))
        blob = self._read_exact(16 + ((length + 15) & ~15))
        return aes_cbc_decrypt(self.key, blob)[:length]

    def recv_msg_auto(self):
        """Receive one message of unknown size; return its plaintext."""
        (length,) = struct.unpack("<H", self._read_exact(2))
        blob = self._read_exact(16 + ((length + 15) & ~15))
        return aes_cbc_decrypt(self.key, blob)[:length]


# --- the OTA transfer ------------------------------------------------------

def random_ota_key(n=16):
    """A random key from the device's visible alphabet (the same set the
    device uses, no ambiguous chars)."""
    import random
    alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
    return "".join(random.choice(alphabet) for _ in range(n))


def ota_transfer(ip, access_key, fw_path, ota_port=OTA_DEFAULT_PORT,
                 connect_timeout_s=30.0, reboot_wait_s=90.0,
                 progress=None):
    """Run a full OTA against the device at [ip].

    access_key : the device's control-channel key (16 bytes)
    fw_path    : local path of the firmware image
    progress   : optional callback(sent_bytes, total_bytes, device_pct)

    Returns (old_version, new_version).
    """
    with open(fw_path, "rb") as f:
        fw = f.read()
    total = len(fw)
    if total == 0:
        raise ControlError("the firmware file is empty")

    ctrl = CtrlClient(ip, key=access_key)
    try:
        old_version = ctrl.fw_version()

        ota_key = random_ota_key()
        url = "hoozz://%s/%d" % (ota_key, ota_port)
        # The device refuses the request while it is busy - typically the
        # 30 s accept window of a previously interrupted OTA (e.g. the
        # client crashed before connecting to the tunnel). It clears
        # itself, so retry until the request is accepted (~45 s max).
        deadline = time.time() + 45.0
        while True:
            try:
                ctrl.fw_upgrade(url)
                break
            except ControlError:
                if time.time() >= deadline:
                    raise ControlError(
                        "device refused FW_UPGRADE (it is busy; after an "
                        "interrupted OTA it recovers ~30 s, then retry)")
                time.sleep(2)

        # the device opens its listener right after accepting; retry for a
        # while (its accept window is 30 s)
        t = None
        deadline = time.time() + connect_timeout_s
        last_err = None
        while t is None and time.time() < deadline:
            try:
                t = TunnelClient(ip, ota_port, ota_key)
            except (OSError, ControlError) as e:
                last_err = e
                time.sleep(0.5)
        if t is None:
            raise ControlError("could not connect to the OTA port %d: %s"
                               % (ota_port, last_err))

        t.send_msg(struct.pack("<I", total))
        sent = 0
        t0 = time.time()
        try:
            while sent < total:
                t.send_msg(fw[sent:sent + OTA_CHUNK])
                sent += OTA_CHUNK
                try:
                    dev = ctrl.fw_progress()
                except (OSError, ControlError):
                    dev = -1  # control hiccup; the tunnel will fail hard
                if progress:
                    elapsed = max(time.time() - t0, 0.001)
                    progress(min(sent, total), total, dev,
                             sent / 1024.0 / elapsed)
        finally:
            t.close()

        # wait for the device to reach 100 (it reboots ~3 s later)
        p = 0
        for _ in range(30):
            try:
                p = ctrl.fw_progress()
            except (OSError, ControlError):
                p = 100  # connection gone: already rebooting
                break
            if p >= 100:
                break
            time.sleep(0.5)
        if p < 100:
            raise ControlError("OTA progress stuck at %d" % p)
    finally:
        ctrl.close()

    # wait for the reboot, then confirm the device is back
    time.sleep(8)
    deadline = time.time() + reboot_wait_s
    while True:
        if time.time() > deadline:
            raise ControlError("the device did not come back in %ds"
                               % int(reboot_wait_s))
        try:
            ctrl2 = CtrlClient(ip, key=access_key)
            new_version = ctrl2.fw_version()
            ctrl2.close()
            break
        except (OSError, ControlError):
            time.sleep(1)

    return old_version, new_version
