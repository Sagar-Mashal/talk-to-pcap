"""Transform PDML XML to JSON format."""

import json
from pathlib import Path
from typing import Optional

from src.parsers import field_extractors, pdml_parser
from src.utils.logger import get_logger

logger = get_logger(__name__)


def pdml_to_json(
    pdml_stream,
    json_output_path: str,
    chunk_size: int = 10000,
) -> int:
    """
    Convert a stream of PDML XML to newline-delimited JSON (JSONL).

    Processes packets in chunks to minimize memory usage.

    Args:
        pdml_stream: A file-like object streaming PDML content.
        json_output_path: Path to output JSONL file.
        chunk_size: Number of packets to process before writing.

    Returns:
        The total number of packets processed.

    Raises:
        FileNotFoundError: If PDML file doesn't exist
    """
    json_file = Path(json_output_path)
    json_file.parent.mkdir(parents=True, exist_ok=True)

    logger.info(f"Converting PDML Stream → JSON: {json_file.name}")

    packet_count = 0
    chunk_buffer = []

    with open(json_file, "w", encoding="utf-8") as f:
        # The parser now directly consumes the tshark stdout stream
        for packet in pdml_parser.parse_pdml_stream(pdml_stream):
            # Convert packet to dict
            packet_dict = packet.to_dict()

            # Extract 3GPP-specific fields
            packet_dict["ue_id"] = field_extractors.extract_ue_id(packet.protocol_layers)
            packet_dict["message_type"] = field_extractors.extract_message_type(
                packet.protocol_layers
            )
            packet_dict["protocol"] = field_extractors.extract_protocol(packet.protocol_layers)
            packet_dict["interface"] = field_extractors.extract_interface(
                packet.protocol_stack, (packet.source_port, packet.destination_port)
            )
            packet_dict["direction"] = field_extractors.extract_direction(packet.protocol_layers)

            # Flatten protocol layers for easier querying
            packet_dict["protocol_fields"] = _flatten_protocol_fields(packet.protocol_layers)

            chunk_buffer.append(packet_dict)
            packet_count += 1

            # Write chunk to file
            if len(chunk_buffer) >= chunk_size:
                _write_json_chunk(f, chunk_buffer)
                chunk_buffer = []
                logger.debug(f"Wrote {packet_count:,} packets...")

        # Write remaining packets
        if chunk_buffer:
            _write_json_chunk(f, chunk_buffer)

    if packet_count > 0:
        logger.info(
            f"✓ JSON created: {json_file.name} ({json_file.stat().st_size:,} bytes, "
            f"{packet_count:,} packets)"
        )
    else:
        logger.warning("No packets were processed. The JSON file is empty.")

    return packet_count


def _flatten_protocol_fields(protocol_layers) -> dict:
    """
    Flatten protocol layer fields into a single dictionary.

    Prefixes field names with protocol name to avoid conflicts.

    Args:
        protocol_layers: List of ProtocolLayer objects

    Returns:
        Flattened field dictionary
    """
    flattened = {}

    for layer in protocol_layers:
        proto_prefix = layer.protocol_name.replace("-", "_")
        for field_name, field_value in layer.fields.items():
            # Use protocol-prefixed name to avoid conflicts
            key = f"{proto_prefix}.{field_name}"
            flattened[key] = field_value

    return flattened


def _write_json_chunk(file_handle, chunk: list) -> None:
    """
    Write a chunk of JSON records to file.

    Args:
        file_handle: Open file handle
        chunk: List of dictionaries to write
    """
    for record in chunk:
        file_handle.write(json.dumps(record, ensure_ascii=False) + "\n")
