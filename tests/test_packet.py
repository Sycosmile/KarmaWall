import unittest
from types import SimpleNamespace

from packet import PacketMetadata, extract_metadata


class TestExtractMetadata(unittest.TestCase):
    def test_tcp_packet(self):
        packet = SimpleNamespace(
            src_addr="192.0.2.10",
            dst_addr="93.184.216.34",
            dst_port=443,
            tcp=object(),
            udp=None,
        )

        metadata = extract_metadata(packet)

        self.assertEqual(
            metadata,
            PacketMetadata(
                source_ip="192.0.2.10",
                destination_ip="93.184.216.34",
                destination_port=443,
                protocol="tcp",
            ),
        )

    def test_udp_packet(self):
        packet = SimpleNamespace(
            src_addr="192.0.2.10",
            dst_addr="8.8.8.8",
            dst_port=53,
            tcp=None,
            udp=object(),
        )

        metadata = extract_metadata(packet)

        self.assertEqual(metadata.protocol, "udp")
        self.assertEqual(metadata.destination_port, 53)

    def test_non_tcp_udp_packet_has_no_port(self):
        packet = SimpleNamespace(
            src_addr="192.0.2.10",
            dst_addr="198.51.100.20",
            dst_port=0,
            tcp=None,
            udp=None,
        )

        metadata = extract_metadata(packet)

        self.assertEqual(metadata.protocol, "other")
        self.assertIsNone(metadata.destination_port)


if __name__ == "__main__":
    unittest.main()
