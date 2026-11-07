"""Inspector correctness checks; these are not traffic-classifier tests."""
from pathlib import Path
import unittest

from wire import CryptoStream, DecodeError, NeedMore, client_hello, crypto_frames, decrypt_initial, initial_keys, tls_record_hello


class WireChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet = bytes.fromhex((Path(__file__).parent / "testdata/rfc9001-client-initial.hex").read_text())
        cls.initial = decrypt_initial(cls.packet)
        cls.fragments = crypto_frames(cls.initial.plaintext)
        cls.handshake = cls.fragments[0][1]

    def test_rfc9001_keys_and_authenticated_packet(self):
        key, iv, hp = initial_keys(1, bytes.fromhex("8394c8f03e515708"))
        self.assertEqual(key.hex(), "1f369613dd76d5467730efcbe3b1a22d")
        self.assertEqual(iv.hex(), "fa044b2f42a3fd3b46fb255c")
        self.assertEqual(hp.hex(), "9f50449e04a0e810283a1e9933adedd2")
        self.assertEqual(self.initial.packet_number, 2)
        self.assertEqual(self.initial.packet_bytes, 1200)
        hello = client_hello(self.handshake)
        self.assertEqual(hello["server_names"], [{"type": 0, "value": "example.com"}])
        self.assertEqual(hello["alpn"], ["alpn"])
        self.assertEqual(hello["supported_versions"], [0x0304])

    def test_corrupted_tag_and_truncated_packet_are_not_success(self):
        bad = self.packet[:-1] + bytes([self.packet[-1] ^ 1])
        with self.assertRaisesRegex(DecodeError, "authentication failed"):
            decrypt_initial(bad)
        with self.assertRaises(NeedMore):
            decrypt_initial(self.packet[:-1])

    def test_rfc9369_v2_keys_and_authenticated_packet(self):
        key, iv, hp = initial_keys(0x6B3343CF, bytes.fromhex("8394c8f03e515708"))
        self.assertEqual(key.hex(), "8b1a0bc121284290a29e0971b5cd045d")
        self.assertEqual(iv.hex(), "91f73e2351d8fa91660e909f")
        self.assertEqual(hp.hex(), "45b95e15235d6f45a6b19cbcb0294ba9")
        packet = bytes.fromhex((Path(__file__).parent / "testdata/rfc9369-client-initial.hex").read_text())
        initial = decrypt_initial(packet)
        self.assertEqual(initial.version, 0x6B3343CF)
        self.assertEqual(initial.packet_number, 2)
        self.assertEqual(initial.packet_bytes, 1200)
        self.assertEqual(client_hello(crypto_frames(initial.plaintext)[0][1])["alpn"], ["alpn"])

    def test_out_of_order_and_duplicate_crypto_ranges(self):
        stream = CryptoStream()
        stream.add(80, self.handshake[80:])
        with self.assertRaises(NeedMore):
            stream.hello()
        stream.add(0, self.handshake[:100])
        stream.add(0, self.handshake[:100])
        self.assertEqual(stream.hello()["alpn"], ["alpn"])
        with self.assertRaisesRegex(DecodeError, "conflicting"):
            stream.add(0, b"\xff")

    def test_tcp_tls_record_fragmentation(self):
        def record(value):
            return b"\x16\x03\x01" + len(value).to_bytes(2, "big") + value
        stream = record(self.handshake[:70]) + record(self.handshake[70:])
        self.assertEqual(tls_record_hello(stream)["alpn"], ["alpn"])
        with self.assertRaises(NeedMore):
            tls_record_hello(stream[:-1])

    def test_oversized_crypto_range_is_rejected(self):
        with self.assertRaises(DecodeError):
            CryptoStream().add(1 << 40, b"x")


if __name__ == "__main__":
    unittest.main()
