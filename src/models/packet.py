"""Data models for parsed packet data."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class ProtocolLayer:
    """
    Represents a single protocol layer in the packet.

    Attributes:
        protocol_name: Protocol name (e.g., 'rrc', 'nas-5gs', 's1ap')
        protocol_display: Human-readable protocol name
        fields: Dictionary of protocol-specific fields
    """

    protocol_name: str
    protocol_display: str
    fields: Dict[str, str] = field(default_factory=dict)

    def get_field(self, field_name: str, default: Optional[str] = None) -> Optional[str]:
        """Get a field value with optional default."""
        return self.fields.get(field_name, default)


@dataclass
class ParsedPacket:
    """
    Represents a parsed packet with protocol layers.

    Attributes:
        packet_number: Sequential packet number from PCAP
        timestamp: Packet timestamp (epoch seconds)
        timestamp_dt: Packet timestamp as datetime object
        length: Frame length in bytes
        protocol_stack: List of protocol names in order (e.g., ['eth', 'ip', 'udp', 'gtp', 'rrc'])
        protocol_layers: List of protocol layer details
        source_ip: Source IP address (if available)
        destination_ip: Destination IP address (if available)
        source_port: Source port (if available)
        destination_port: Destination port (if available)
    """

    packet_number: int
    timestamp: float
    timestamp_dt: datetime
    length: int
    protocol_stack: List[str]
    protocol_layers: List[ProtocolLayer]
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "packet_number": self.packet_number,
            "timestamp": self.timestamp,
            "timestamp_iso": self.timestamp_dt.isoformat(),
            "length": self.length,
            "protocol_stack": self.protocol_stack,
            "protocol_layers": [
                {
                    "protocol_name": layer.protocol_name,
                    "protocol_display": layer.protocol_display,
                    "fields": layer.fields,
                }
                for layer in self.protocol_layers
            ],
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
        }

    def get_protocol_layer(self, protocol_name: str) -> Optional[ProtocolLayer]:
        """Get a specific protocol layer by name."""
        for layer in self.protocol_layers:
            if layer.protocol_name.lower() == protocol_name.lower():
                return layer
        return None

    def has_protocol(self, protocol_name: str) -> bool:
        """Check if packet contains a specific protocol."""
        return protocol_name.lower() in [p.lower() for p in self.protocol_stack]
