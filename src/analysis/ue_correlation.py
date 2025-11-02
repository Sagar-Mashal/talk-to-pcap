"""
UE Correlation Engine for LTE/5G Packet Analysis

This module implements intelligent User Equipment (UE) correlation across multiple
3GPP protocol layers. In LTE/5G networks, the same physical UE is identified by
different IDs at different protocol layers:
- RLC layer: rlc-lte.ueid (e.g., 61)
- S1AP layer: ENB_UE_S1AP_ID, MME_UE_S1AP_ID (e.g., 1, 1)
- NAS layer: M-TMSI, GUTI, IMSI (e.g., 424504)

The correlation engine builds a mapping table to track these relationships,
enabling queries like "show all messages for ENB_UE_S1AP_ID=1" to return
packets from all protocol layers for that physical UE.

Correlation Strategy:
1. **M-TMSI as Anchor**: M-TMSI appears in both RRC and S1AP messages (embedded NAS)
2. **Temporal Proximity**: Messages within same call flow occur close in time
3. **Transitive Closure**: If A↔B and B↔C, then A↔C
4. **Protocol-Specific Rules**:
   - RRCConnectionSetupComplete links RLC UEId → M-TMSI
   - InitialUEMessage links ENB_UE_S1AP_ID → M-TMSI
   - SubsequentInitialUEMessage may contain GUTI → M-TMSI
"""

import json
import logging
from typing import Dict, Set, List, Optional, Any
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger("talk-to-pcap.analysis")


@dataclass(frozen=True)
class UeIdentifier:
    """Represents a UE identifier with its type and value."""
    id_type: str  # 'rlc_ueid', 'enb_ue_s1ap_id', 'mme_ue_s1ap_id', 'm_tmsi', 'guti', 'imsi'
    value: str
    packet_number: int
    timestamp: Optional[str] = None


class UeCorrelationTable:
    """
    Maintains correlation mappings between different UE identifiers.
    
    Uses a union-find-like structure where each unique UE ID points to
    a set of all correlated IDs for that physical UE.
    """
    
    def __init__(self):
        # Maps normalized_id -> set of all UeIdentifiers for that physical UE
        self._ue_groups: Dict[str, Set[UeIdentifier]] = defaultdict(set)
        # Maps (id_type, value) -> normalized_id for quick lookup
        self._id_to_group: Dict[tuple, str] = {}
    
    def add_correlation(self, id1: UeIdentifier, id2: UeIdentifier):
        """
        Correlate two UE identifiers as belonging to the same physical UE.
        
        Args:
            id1: First UE identifier
            id2: Second UE identifier (must be from same physical UE)
        """
        key1 = (id1.id_type, id1.value)
        key2 = (id2.id_type, id2.value)
        
        # Find existing groups
        group1 = self._id_to_group.get(key1)
        group2 = self._id_to_group.get(key2)
        
        if group1 and group2:
            # Both exist - merge groups
            if group1 != group2:
                self._merge_groups(group1, group2)
        elif group1:
            # Only first exists - add second to its group
            self._add_to_group(group1, id2)
        elif group2:
            # Only second exists - add first to its group
            self._add_to_group(group2, id1)
        else:
            # Neither exists - create new group
            group_id = f"ue_group_{len(self._ue_groups)}"
            self._ue_groups[group_id] = {id1, id2}
            self._id_to_group[key1] = group_id
            self._id_to_group[key2] = group_id
    
    def _add_to_group(self, group_id: str, ue_id: UeIdentifier):
        """Add a UE identifier to an existing group."""
        self._ue_groups[group_id].add(ue_id)
        self._id_to_group[(ue_id.id_type, ue_id.value)] = group_id
    
    def _merge_groups(self, group1: str, group2: str):
        """Merge two groups (transitive closure)."""
        # Move all from group2 to group1
        for ue_id in self._ue_groups[group2]:
            self._ue_groups[group1].add(ue_id)
            self._id_to_group[(ue_id.id_type, ue_id.value)] = group1
        del self._ue_groups[group2]
    
    def get_correlated_ids(self, id_type: str, value: str) -> Set[UeIdentifier]:
        """
        Get all UE identifiers correlated with the given ID.
        
        Args:
            id_type: Type of identifier (e.g., 'enb_ue_s1ap_id')
            value: Value of identifier (e.g., '1')
            
        Returns:
            Set of all correlated UeIdentifiers, or empty set if not found
        """
        key = (id_type, value)
        group_id = self._id_to_group.get(key)
        if group_id:
            return self._ue_groups[group_id].copy()
        return set()
    
    def get_all_groups(self) -> List[Set[UeIdentifier]]:
        """Get all UE groups for debugging/visualization."""
        return [group.copy() for group in self._ue_groups.values()]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get correlation statistics."""
        return {
            "total_groups": len(self._ue_groups),
            "total_identifiers": len(self._id_to_group),
            "avg_ids_per_group": len(self._id_to_group) / max(1, len(self._ue_groups))
        }


def extract_all_ue_ids(packet_fields: Dict[str, Any], packet_number: int) -> List[UeIdentifier]:
    """
    Extract ALL UE identifiers from a single packet's protocol fields.
    
    Unlike the simple extract_ue_id() which returns one ID, this extracts
    every UE-related identifier present in the packet for correlation purposes.
    
    Args:
        packet_fields: Dictionary of protocol field name -> value
        packet_number: Packet number for reference
        
    Returns:
        List of all UeIdentifiers found in the packet
    """
    identifiers = []
    timestamp = packet_fields.get("frame.frame.time")
    
    # RLC Layer UE ID
    rlc_ueid = packet_fields.get("rlc_lte.rlc-lte.ueid") or packet_fields.get("rlc_lte.pdcp-lte.ueid")
    if rlc_ueid:
        identifiers.append(UeIdentifier(
            id_type="rlc_ueid",
            value=str(rlc_ueid),
            packet_number=packet_number,
            timestamp=timestamp
        ))
    
    # S1AP Layer - ENB UE S1AP ID
    enb_s1ap_id = packet_fields.get("s1ap.s1ap.ENB_UE_S1AP_ID")
    if enb_s1ap_id:
        identifiers.append(UeIdentifier(
            id_type="enb_ue_s1ap_id",
            value=str(enb_s1ap_id),
            packet_number=packet_number,
            timestamp=timestamp
        ))
    
    # S1AP Layer - MME UE S1AP ID
    mme_s1ap_id = packet_fields.get("s1ap.s1ap.MME_UE_S1AP_ID")
    if mme_s1ap_id:
        identifiers.append(UeIdentifier(
            id_type="mme_ue_s1ap_id",
            value=str(mme_s1ap_id),
            packet_number=packet_number,
            timestamp=timestamp
        ))
    
    # NAS Layer - M-TMSI (most important for correlation!)
    # Can appear in multiple fields depending on message embedding
    m_tmsi_fields = [
        "nas_eps.nas-eps.emm.m_tmsi",  # Direct NAS message
        "s1ap.nas-eps.emm.m_tmsi",     # NAS embedded in S1AP
        "rlc_lte.nas-eps.emm.m_tmsi",  # NAS embedded in RRC (via RLC)
        "nas_eps.3gpp.tmsi"            # Alternative field name
    ]
    for field in m_tmsi_fields:
        m_tmsi = packet_fields.get(field)
        if m_tmsi:
            identifiers.append(UeIdentifier(
                id_type="m_tmsi",
                value=str(m_tmsi),
                packet_number=packet_number,
                timestamp=timestamp
            ))
            break  # Only need one M-TMSI
    
    # NAS Layer - GUTI
    guti_fields = [
        "nas_eps.nas-eps.emm.guti",
        "s1ap.nas-eps.emm.guti"
    ]
    for field in guti_fields:
        guti = packet_fields.get(field)
        if guti:
            identifiers.append(UeIdentifier(
                id_type="guti",
                value=str(guti),
                packet_number=packet_number,
                timestamp=timestamp
            ))
            break
    
    # NAS Layer - IMSI (most unique, but rare)
    imsi_fields = [
        "e212.imsi",
        "nas_eps.e212.imsi",
        "s1ap.e212.imsi"
    ]
    for field in imsi_fields:
        imsi = packet_fields.get(field)
        if imsi:
            identifiers.append(UeIdentifier(
                id_type="imsi",
                value=str(imsi),
                packet_number=packet_number,
                timestamp=timestamp
            ))
            break
    
    return identifiers


def build_correlation_table(packets_data: List[Dict[str, Any]]) -> UeCorrelationTable:
    """
    Build UE correlation table by analyzing all packets.
    
    Strategy:
    1. Extract all UE IDs from each packet
    2. If packet has multiple UE IDs, correlate them (same physical UE)
    3. Use M-TMSI as primary correlation anchor across protocols
    4. Return completed correlation table
    
    Args:
        packets_data: List of packet records from parquet/DuckDB
                      Each record must have: packet_number, protocol_fields_json
        
    Returns:
        UeCorrelationTable with all discovered correlations
    """
    correlation_table = UeCorrelationTable()
    packets_processed = 0
    correlations_found = 0
    
    logger.info(f"Building UE correlation table from {len(packets_data)} packets...")
    
    for packet in packets_data:
        packet_number = packet.get("packet_number")
        protocol_fields_json = packet.get("protocol_fields_json")
        
        if not protocol_fields_json or packet_number is None:
            continue
        
        # Parse protocol fields
        try:
            fields = json.loads(protocol_fields_json) if isinstance(protocol_fields_json, str) else protocol_fields_json
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse packet {packet_number} fields")
            continue
        
        # Extract all UE IDs from this packet
        ue_ids = extract_all_ue_ids(fields, int(packet_number))
        
        if len(ue_ids) >= 2:
            # Multiple UE IDs in same packet = they belong to same physical UE!
            # Create correlation between each pair
            for i, id1 in enumerate(ue_ids):
                for id2 in ue_ids[i+1:]:
                    correlation_table.add_correlation(id1, id2)
                    correlations_found += 1
        
        if ue_ids:
            packets_processed += 1
    
    stats = correlation_table.get_stats()
    logger.info(
        f"✓ UE correlation table built: {stats['total_groups']} UE groups, "
        f"{stats['total_identifiers']} unique IDs, "
        f"{correlations_found} correlations found from {packets_processed} packets"
    )
    
    return correlation_table


def expand_ue_query(
    original_query: str,
    ue_id_field: str,
    ue_id_value: str,
    correlation_table: UeCorrelationTable
) -> str:
    """
    Expand a UE-specific query to include all correlated UE identifiers.
    
    Example:
        Input:  "WHERE s1ap.ENB_UE_S1AP_ID = '1'"
        Output: "WHERE (s1ap.ENB_UE_S1AP_ID = '1' OR rlc-lte.ueid = '61' OR m_tmsi = '424504')"
    
    Args:
        original_query: Original SQL query
        ue_id_field: Field name being queried (e.g., "s1ap.ENB_UE_S1AP_ID")
        ue_id_value: Value being queried (e.g., "1")
        correlation_table: Built correlation table
        
    Returns:
        Expanded SQL query with all correlated IDs
    """
    # Map field names to correlation ID types
    field_to_type = {
        "rlc-lte.ueid": "rlc_ueid",
        "rlc_lte.rlc-lte.ueid": "rlc_ueid",
        "s1ap.s1ap.ENB_UE_S1AP_ID": "enb_ue_s1ap_id",
        "s1ap.ENB_UE_S1AP_ID": "enb_ue_s1ap_id",
        "s1ap.s1ap.MME_UE_S1AP_ID": "mme_ue_s1ap_id",
        "s1ap.MME_UE_S1AP_ID": "mme_ue_s1ap_id",
        "nas-eps.emm.m_tmsi": "m_tmsi",
        "m_tmsi": "m_tmsi",
        "guti": "guti",
        "imsi": "imsi"
    }
    
    id_type = field_to_type.get(ue_id_field)
    if not id_type:
        logger.warning(f"Unknown UE ID field: {ue_id_field}, returning original query")
        return original_query
    
    # Get all correlated IDs
    correlated_ids = correlation_table.get_correlated_ids(id_type, ue_id_value)
    
    if not correlated_ids:
        logger.info(f"No correlations found for {ue_id_field}={ue_id_value}")
        return original_query
    
    # Build OR clauses for all correlated IDs
    # Map correlation ID types back to JSON field names for SQL LIKE queries
    type_to_field = {
        "rlc_ueid": "rlc_lte.rlc-lte.ueid",
        "enb_ue_s1ap_id": "s1ap.s1ap.ENB_UE_S1AP_ID",
        "mme_ue_s1ap_id": "s1ap.s1ap.MME_UE_S1AP_ID",
        "m_tmsi": "nas-eps.emm.m_tmsi",
        "guti": "nas-eps.emm.guti",
        "imsi": "e212.imsi"
    }
    
    conditions = []
    for ue_id in correlated_ids:
        field_name = type_to_field.get(ue_id.id_type)
        if field_name:
            # Use JSON LIKE queries since fields are in JSON column
            conditions.append(f"protocol_fields_json LIKE '%\"{field_name}\": \"{ue_id.value}\"%'")
    
    if not conditions:
        return original_query
    
    # Join with OR
    expanded_condition = " OR ".join(conditions)
    
    logger.info(
        f"Expanded UE query: Found {len(correlated_ids)} correlated IDs for "
        f"{ue_id_field}={ue_id_value}"
    )
    
    # Replace original condition with expanded one
    # This is a simple implementation - a more robust version would parse SQL AST
    # For now, we'll add the expansion as an additional OR clause
    if "WHERE" in original_query.upper():
        # Add to existing WHERE clause
        expanded_query = original_query.replace(
            "WHERE",
            f"WHERE (({expanded_condition}) AND "
        ) + ")"
    else:
        # Add new WHERE clause
        expanded_query = original_query + f" WHERE ({expanded_condition})"
    
    return expanded_query
