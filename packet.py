"""Packet metadata extraction for KarmaWall.

This module keeps WinDivert packet-object handling separate from the firewall
loop so the decision path can be tested without a live WinDivert handle.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class PacketMetadata:
    """Normalized metadata used by the rule engine and audit logger."""

    source_ip: str
    destination_ip: str
    destination_port: int | None
    protocol: str


def extract_metadata(packet) -> PacketMetadata:
    """Extract the fields KarmaWall needs from a pydivert packet."""
    protocol = (
        "tcp" if packet.tcp
        else "udp" if packet.udp
        else "other"
    )

    return PacketMetadata(
        source_ip=packet.src_addr,
        destination_ip=packet.dst_addr,
        destination_port=(
            packet.dst_port if (packet.tcp or packet.udp) else None
        ),
        protocol=protocol,
    )
