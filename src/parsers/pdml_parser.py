"""PDML XML streaming parser for efficient packet processing."""

import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, Generator, List, Optional

from src.models.packet import ParsedPacket, ProtocolLayer
from src.utils.logger import get_logger

logger = get_logger(__name__)


def parse_pdml_stream(pdml_stream) -> Generator[ParsedPacket, None, None]:
    """
    Stream parse a PDML XML stream and yield ParsedPacket objects.

    Uses iterparse() to minimize memory usage. The input is a file-like
    object (e.g., stdout from a subprocess).

    Args:
        pdml_stream: A file-like object yielding PDML XML content.

    Yields:
        ParsedPacket objects.

    Raises:
        ET.ParseError: If XML is malformed.
    """
    logger.info("Parsing PDML stream...")
    packet_count = 0

    try:
        # Use iterparse to stream-parse the XML from the input stream
        for event, elem in ET.iterparse(pdml_stream, events=("end",)):
            if elem.tag == "packet":
                packet = _parse_packet_element(elem)
                if packet:
                    packet_count += 1
                    yield packet

                    if packet_count % 1000 == 0:
                        logger.debug(f"Parsed {packet_count:,} packets from stream...")

                # Clear the element to free memory
                elem.clear()

        if packet_count > 0:
            logger.info(f"✓ Parsed {packet_count:,} total packets from stream")

    except ET.ParseError as e:
        # This can happen if tshark closes the stream unexpectedly
        logger.error(f"XML parsing error in stream: {e}. The stream may have been incomplete.")
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred during stream parsing: {e}")
        raise


def _parse_packet_element(packet_elem: ET.Element) -> Optional[ParsedPacket]:
    """
    Parse a <packet> XML element into ParsedPacket object.

    Args:
        packet_elem: <packet> XML element

    Returns:
        ParsedPacket object or None if parsing fails
    """
    try:
        # Extract protocol layers
        protocol_stack = []
        protocol_layers = []

        for proto_elem in packet_elem.findall("proto"):
            proto_name = proto_elem.get("name", "")
            proto_display = proto_elem.get("showname", proto_name)

            # Build protocol stack
            protocol_stack.append(proto_name)

            # Extract fields for this protocol
            fields = _extract_protocol_fields(proto_elem)

            protocol_layers.append(
                ProtocolLayer(
                    protocol_name=proto_name,
                    protocol_display=proto_display,
                    fields=fields,
                )
            )

        # Extract frame-level metadata
        frame_proto = packet_elem.find("proto[@name='frame']")
        if frame_proto is None:
            return None

        packet_number = int(_get_field_value(frame_proto, "frame.number", "0"))
        timestamp_str = _get_field_value(frame_proto, "frame.time_epoch", "0")
        timestamp = float(timestamp_str)
        timestamp_dt = datetime.fromtimestamp(timestamp)
        length = int(_get_field_value(frame_proto, "frame.len", "0"))

        # Extract IP addresses if present
        ip_proto = packet_elem.find("proto[@name='ip']")
        source_ip = None
        destination_ip = None
        if ip_proto is not None:
            source_ip = _get_field_value(ip_proto, "ip.src")
            destination_ip = _get_field_value(ip_proto, "ip.dst")

        # Extract port numbers if present
        source_port = None
        destination_port = None
        for proto_name in ["tcp", "udp", "sctp"]:
            transport_proto = packet_elem.find(f"proto[@name='{proto_name}']")
            if transport_proto is not None:
                port_src = _get_field_value(transport_proto, f"{proto_name}.srcport")
                port_dst = _get_field_value(transport_proto, f"{proto_name}.dstport")
                if port_src:
                    source_port = int(port_src)
                if port_dst:
                    destination_port = int(port_dst)
                break

        return ParsedPacket(
            packet_number=packet_number,
            timestamp=timestamp,
            timestamp_dt=timestamp_dt,
            length=length,
            protocol_stack=protocol_stack,
            protocol_layers=protocol_layers,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
        )

    except Exception as e:
        logger.warning(f"Failed to parse packet: {e}")
        return None


def _extract_protocol_fields(proto_elem: ET.Element) -> Dict[str, str]:
    """
    Extract all fields from a <proto> element.

    Args:
        proto_elem: <proto> XML element

    Returns:
        Dictionary of field_name -> field_value
    """
    fields = {}

    # Measurement context enrichment:
    # Some PDML structures (LTE RRC measurementReport) repeat lte-rrc.rsrpResult / lte-rrc.rsrqResult
    # for PCell and for each neighbor cell list item. We now:
    #   1. Preserve first occurrence for backward compatibility (plain keys).
    #   2. ALSO capture contextual variants:
    #        lte-rrc.rsrpResult__context=pcell
    #        lte-rrc.rsrqResult__context=pcell
    #        lte-rrc.rsrpResult__context=neigh[index]
    #        lte-rrc.rsrqResult__context=neigh[index]
    #      where index is 0-based order encountered among neighbor entries.
    # This lets downstream extraction explicitly choose PCell values while preserving neighbors.

    # Build context maps by subtree collection (xml.etree does not retain parent refs).
    pcell_ids = set()
    for pcell in proto_elem.findall(".//field[@name='lte-rrc.measResultPCell_element']"):
        for desc in pcell.findall('.//field'):
            pcell_ids.add(id(desc))

    neighbor_root_exprs = [
        ".//field[@name='lte-rrc.MeasResultEUTRA_element']",
        ".//field[@name='lte-rrc.measResultListEUTRA']",
    ]
    neighbor_ids = set()
    for expr in neighbor_root_exprs:
        for neigh_root in proto_elem.findall(expr):
            for desc in neigh_root.findall('.//field'):
                neighbor_ids.add(id(desc))

    neighbor_index_counter = 0
    for field_elem in proto_elem.findall('.//field'):
        field_name = field_elem.get('name', '')
        if not field_name:
            continue
        chosen_value = field_elem.get('show') or field_elem.get('value', '')

        is_pcell_context = id(field_elem) in pcell_ids
        is_neighbor_context = (not is_pcell_context) and id(field_elem) in neighbor_ids

        if field_name in {"lte-rrc.rsrpResult", "lte-rrc.rsrqResult"}:
            # Preserve first occurrence as legacy key
            if field_name not in fields:
                fields[field_name] = chosen_value
            # Contextual key
            if is_pcell_context:
                ctx_key = f"{field_name}__context=pcell"
                if ctx_key not in fields:
                    fields[ctx_key] = chosen_value
            elif is_neighbor_context:
                ctx_key = f"{field_name}__context=neigh[{neighbor_index_counter}]"
                fields[ctx_key] = chosen_value
            if is_neighbor_context and field_name == 'lte-rrc.rsrqResult':
                neighbor_index_counter += 1
        else:
            fields[field_name] = chosen_value

    return fields

    return fields


def _get_field_value(proto_elem: ET.Element, field_name: str, default: str = "") -> str:
    """
    Get a specific field value from a protocol element.

    Args:
        proto_elem: <proto> XML element
        field_name: Field name to search for
        default: Default value if not found

    Returns:
        Field value or default
    """
    field_elem = proto_elem.find(f".//field[@name='{field_name}']")
    if field_elem is not None:
        # Prefer 'show' (human-readable) over 'value' (hex)
        return field_elem.get("show") or field_elem.get("value", default)
    return default
