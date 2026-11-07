"""Bounded TLS ClientHello and QUIC Initial inspection from observed bytes.

This module handles only the public Initial keys (RFC 9001 / RFC 9369). It
does not decrypt TLS application traffic, Handshake packets, or ECH inner
ClientHellos. Raw SNI is internal data; use analyze.py for redacted output.
"""
import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAX_HELLO = 262144
INITIAL_SALTS = {
    0x00000001: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    0x6B3343CF: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}


class DecodeError(ValueError):
    pass


class NeedMore(DecodeError):
    pass


class Reader:
    def __init__(self, data):
        self.data = data
        self.at = 0

    @property
    def remaining(self):
        return len(self.data) - self.at

    def take(self, n):
        if n < 0 or n > self.remaining:
            raise NeedMore("truncated field")
        out = self.data[self.at:self.at + n]
        self.at += n
        return out

    def integer(self, n):
        return int.from_bytes(self.take(n), "big")

    def vector(self, n):
        return self.take(self.integer(n))

    def varint(self):
        first = self.integer(1)
        length = 1 << (first >> 6)
        return ((first & 0x3F) << (8 * (length - 1))) | self.integer(length - 1)


def numbers(data, width=2):
    if len(data) % width:
        raise DecodeError("misaligned numeric vector")
    return [int.from_bytes(data[i:i + width], "big") for i in range(0, len(data), width)]


def grease(value):
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF


def transport_parameters(data):
    r, out = Reader(data), []
    numeric = {1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 0x20}
    seen = set()
    while r.remaining:
        tag, size = r.varint(), r.varint()
        value = r.take(size)
        if tag in seen:
            raise DecodeError("duplicate QUIC transport parameter")
        seen.add(tag)
        entry = {"id": tag, "length": size}
        if tag in numeric:
            item = Reader(value)
            entry["numeric_value"] = item.varint()
            if item.remaining:
                raise DecodeError("invalid numeric QUIC transport parameter")
        elif tag == 12:
            entry["disable_active_migration"] = size == 0
        else:
            # CID, address and token fields must not escape into public reports.
            entry["value_redacted"] = True
        out.append(entry)
    return out


def client_hello(handshake):
    r = Reader(handshake)
    if r.integer(1) != 1:
        raise DecodeError("first TLS handshake is not ClientHello")
    size = r.integer(3)
    if size > MAX_HELLO:
        raise DecodeError("ClientHello exceeds inspection bound")
    body = Reader(r.take(size))
    out = {"handshake_bytes": size + 4, "legacy_version": body.integer(2)}
    body.take(32)  # Per-connection random is not a useful public report field.
    out["legacy_session_id_bytes"] = len(body.vector(1))
    out["cipher_suites"] = numbers(body.vector(2))
    out["compression_methods"] = numbers(body.vector(1), 1)
    exts = Reader(body.vector(2)) if body.remaining else Reader(b"")
    if body.remaining:
        raise DecodeError("trailing bytes after ClientHello extensions")
    out.update(extension_ids=[], extension_lengths=[], server_names=[], alpn=[],
               supported_versions=[], supported_groups=[], signature_algorithms=[], key_shares=[])
    seen = set()
    while exts.remaining:
        tag, payload = exts.integer(2), exts.vector(2)
        if tag in seen:
            raise DecodeError("duplicate TLS extension")
        seen.add(tag)
        out["extension_ids"].append(tag)
        out["extension_lengths"].append({"id": tag, "bytes": len(payload)})
        p = Reader(payload)
        if tag == 0:
            names = Reader(p.vector(2))
            while names.remaining:
                kind, value = names.integer(1), names.vector(2)
                out["server_names"].append({"type": kind, "value": value.decode("ascii", errors="replace")})
        elif tag == 16:
            protocols = Reader(p.vector(2))
            while protocols.remaining:
                out["alpn"].append(protocols.vector(1).decode("ascii", errors="replace"))
        elif tag == 43:
            out["supported_versions"] = numbers(p.vector(1))
        elif tag == 10:
            out["supported_groups"] = numbers(p.vector(2))
        elif tag == 13:
            out["signature_algorithms"] = numbers(p.vector(2))
        elif tag == 51:
            shares = Reader(p.vector(2))
            while shares.remaining:
                group, key = shares.integer(2), shares.vector(2)
                out["key_shares"].append({"group": group, "key_bytes": len(key)})
        elif tag == 57:
            out["quic_transport_parameters"] = transport_parameters(payload)
    out["ech_extension_present"] = 0xFE0D in seen
    out["grease_extension_ids"] = [x for x in out["extension_ids"] if grease(x)]
    out["sni_scope"] = "visible outer ClientHello only; ECH inner name is not decrypted"
    return out


def tls_record_hello(stream):
    """Reassemble handshake records from ordered TCP bytes, not IP packets."""
    r, handshake, record_lengths = Reader(stream), bytearray(), []
    while r.remaining:
        content_type = r.integer(1)
        version, length = r.integer(2), r.integer(2)
        if version >> 8 != 3 or length > 18432:
            raise DecodeError("invalid TLS record header")
        payload = r.take(length)
        record_lengths.append(length)
        if content_type == 20 and not handshake:  # Compatibility CCS is not a ClientHello.
            continue
        if content_type != 22:
            raise DecodeError("non-handshake record before complete ClientHello")
        handshake += payload
        if len(handshake) > MAX_HELLO + 4:
            raise DecodeError("handshake inspection bound exceeded")
        if len(handshake) >= 4:
            want = 4 + int.from_bytes(handshake[1:4], "big")
            if want > MAX_HELLO + 4:
                raise DecodeError("ClientHello exceeds inspection bound")
            if len(handshake) >= want:
                hello = client_hello(bytes(handshake[:want]))
                hello["tls_record_payload_lengths_until_hello"] = record_lengths
                return hello
    raise NeedMore("ClientHello not complete in captured TCP prefix")


def hkdf_expand(secret, info, length):
    output, last = b"", b""
    for counter in range(1, (length + 31) // 32 + 1):
        last = hmac.new(secret, last + info + bytes([counter]), hashlib.sha256).digest()
        output += last
    return output[:length]


def expand_label(secret, label, length):
    full = b"tls13 " + label
    return hkdf_expand(secret, length.to_bytes(2, "big") + bytes([len(full)]) + full + b"\x00", length)


def initial_keys(version, dcid, side="client"):
    if version not in INITIAL_SALTS:
        raise DecodeError("unsupported QUIC Initial version")
    if side not in ("client", "server"):
        raise DecodeError("invalid Initial key side")
    initial = hmac.new(INITIAL_SALTS[version], dcid, hashlib.sha256).digest()
    secret = expand_label(initial, (side + " in").encode(), 32)
    prefix = b"quicv2 " if version == 0x6B3343CF else b"quic "
    return tuple(expand_label(secret, prefix + name, size)
                 for name, size in ((b"key", 16), (b"iv", 12), (b"hp", 16)))


def packet_number(truncated, bits, expected):
    window, half = 1 << bits, 1 << (bits - 1)
    candidate = (expected & ~(window - 1)) | truncated
    if candidate + half <= expected and candidate + window < 1 << 62:
        return candidate + window
    if candidate > expected + half and candidate >= window:
        return candidate - window
    return candidate


@dataclass
class Initial:
    version: int
    dcid: bytes
    packet_number: int
    plaintext: bytes
    packet_bytes: int


def decrypt_initial(packet, expected_packet_number=0, original_dcid=None, side="client"):
    """Decrypt the first Initial; return its length for coalesced datagrams.

    For server packets the client-chosen original DCID must be supplied.
    The original DCID must also be supplied for subsequent client Initials
    whose header DCID has changed to a server-selected connection ID. After
    Retry, the first new client Initial's DCID establishes a new key namespace.
    """
    r = Reader(packet)
    first, version = r.integer(1), r.integer(4)
    if first & 0xC0 != 0xC0:
        raise DecodeError("not a fixed-bit QUIC long header")
    if version not in INITIAL_SALTS:
        raise DecodeError("unsupported QUIC Initial version")
    initial_type = 1 if version == 0x6B3343CF else 0
    if first >> 4 & 3 != initial_type:
        raise DecodeError("not a QUIC Initial packet")
    dcid, scid = r.vector(1), r.vector(1)
    if len(dcid) > 20 or len(scid) > 20:
        raise DecodeError("invalid QUIC connection ID length")
    r.take(r.varint())  # Retry token, if any; not logged.
    protected_length = r.varint()
    pn_offset, end = r.at, r.at + protected_length
    if end > len(packet):
        raise NeedMore("truncated QUIC Initial packet")
    if protected_length < 20 or pn_offset + 20 > end:
        raise DecodeError("QUIC packet too short for header-protection sample")
    if side == "server" and original_dcid is None:
        raise DecodeError("server Initial needs original client DCID")
    key, iv, hp = initial_keys(version, original_dcid if original_dcid is not None else dcid, side)
    encryptor = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = encryptor.update(packet[pn_offset + 4:pn_offset + 20]) + encryptor.finalize()
    header = bytearray(packet[:pn_offset + 4])
    header[0] ^= mask[0] & 0x0F
    pn_len = (header[0] & 3) + 1
    for i in range(pn_len):
        header[pn_offset + i] ^= mask[i + 1]
    header = bytes(header[:pn_offset + pn_len])
    pn = packet_number(int.from_bytes(header[pn_offset:], "big"), pn_len * 8, expected_packet_number)
    nonce = bytes(x ^ y for x, y in zip(iv, pn.to_bytes(12, "big")))
    try:
        plaintext = AESGCM(key).decrypt(nonce, packet[pn_offset + pn_len:end], header)
    except Exception as exc:
        # Authenticated decryption failure must not become a parsed success.
        raise DecodeError("QUIC Initial AEAD authentication failed") from exc
    if header[0] & 0x0C:
        raise DecodeError("nonzero QUIC reserved bits")
    return Initial(version, dcid, pn, plaintext, end)


def crypto_frames(plaintext):
    r, fragments = Reader(plaintext), []
    while r.remaining:
        kind = r.varint()
        if kind in (0, 1):  # PADDING / PING
            continue
        if kind in (2, 3):
            r.varint()  # largest acknowledged
            r.varint()  # ACK delay
            ranges = r.varint()
            r.varint()  # first ACK range
            if ranges > 4096:
                raise DecodeError("ACK range inspection bound exceeded")
            for _ in range(ranges):
                r.varint()
                r.varint()
            if kind == 3:
                for _ in range(3):
                    r.varint()
        elif kind == 6:
            offset, length = r.varint(), r.varint()
            if offset + length > MAX_HELLO + 4:
                raise DecodeError("CRYPTO inspection bound exceeded")
            fragments.append((offset, r.take(length)))
        elif kind in (0x1C, 0x1D):
            r.varint()  # error code
            if kind == 0x1C:
                r.varint()  # triggering frame type
            r.take(r.varint())  # reason phrase is not exported
        else:
            raise DecodeError("unhandled frame in QUIC Initial: " + str(kind))
    return fragments


class CryptoStream:
    def __init__(self):
        self.values = bytearray(MAX_HELLO + 4)
        self.present = bytearray(MAX_HELLO + 4)
        self.contiguous = 0

    def add(self, offset, data):
        if offset < 0 or offset + len(data) > len(self.values):
            raise DecodeError("CRYPTO reassembly bound exceeded")
        for i, value in enumerate(data, offset):
            if self.present[i] and self.values[i] != value:
                raise DecodeError("conflicting CRYPTO overlap")
            self.values[i], self.present[i] = value, 1
        while self.contiguous < len(self.present) and self.present[self.contiguous]:
            self.contiguous += 1

    def hello(self):
        if self.contiguous < 4:
            raise NeedMore("no complete handshake header")
        want = 4 + int.from_bytes(self.values[1:4], "big")
        if want > len(self.values):
            raise DecodeError("ClientHello exceeds inspection bound")
        if self.contiguous < want:
            raise NeedMore("ClientHello CRYPTO ranges incomplete")
        return client_hello(bytes(self.values[:want]))
