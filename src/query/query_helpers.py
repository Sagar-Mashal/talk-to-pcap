"""Query helpers for UE correlation and result enhancement."""

import re
import json
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("talk-to-pcap.query_helpers")


def _generate_field_name_variations_internal(field_name: str) -> List[str]:
    """
    Generate all common variations of a field name to support fuzzy matching.
    
    Examples:
        "hnb-name" → ["hnb_name", "hnb_Name", "hnbName", "hnb-name", "HNB_NAME", "hnbname"]
        "q-RxLevMin" → ["q_RxLevMin", "qRxLevMin", "q-RxLevMin", "Q_RXLEVMIN", "qrxlevmin"]
    """
    variations = set()
    
    # Original
    variations.add(field_name)
    
    # Lowercase
    variations.add(field_name.lower())
    
    # Uppercase
    variations.add(field_name.upper())
    
    # Replace hyphens with underscores
    variations.add(field_name.replace('-', '_'))
    
    # Replace underscores with hyphens
    variations.add(field_name.replace('_', '-'))
    
    # Replace spaces with underscores
    variations.add(field_name.replace(' ', '_'))
    
    # Replace spaces with hyphens
    variations.add(field_name.replace(' ', '-'))
    
    # camelCase: remove separators and capitalize after them
    camel = field_name
    for sep in ['-', '_', '.', ' ']:
        parts = camel.split(sep)
        camel = parts[0] + ''.join(p.capitalize() for p in parts[1:])
    variations.add(camel)
    
    # PascalCase: capitalize first letter too
    if camel:
        variations.add(camel[0].upper() + camel[1:])
    
    # All lowercase no separators
    variations.add(re.sub(r'[-_.\s]', '', field_name.lower()))
    
    # All uppercase with underscores
    variations.add(re.sub(r'[-.\s]', '_', field_name.upper()))
    
    # Mixed case variations (common in 3GPP: q_RxLevMin, hnb_Name)
    # Handle patterns with hyphens, underscores, or spaces
    for sep in ['-', '_', ' ']:
        if sep in field_name:
            # Convert to underscore-separated
            mixed = field_name.replace('-', '_').replace(' ', '_')
            # Capitalize letters after underscores
            parts = mixed.split('_')
            if len(parts) > 1:
                # Style 1: lowercase_Capitalized (e.g., hnb_Name)
                variations.add('_'.join([parts[0].lower()] + [p.capitalize() for p in parts[1:]]))
                # Style 2: with hyphens instead (e.g., hnb-Name)
                variations.add('-'.join([parts[0].lower()] + [p.capitalize() for p in parts[1:]]))
            break  # Only need to process once

    # If there are no explicit separators but CamelCase boundaries exist, synthesize underscore/hyphen versions.
    # Example: qRxLevMin -> q_RxLevMin, q-RxLevMin
    if all(sep not in field_name for sep in ['-', '_', ' ', '.']) and re.search(r'[a-z][A-Z]', field_name):
        # Split at transitions from lowercase to uppercase or uppercase followed by lowercase (word boundaries)
        parts = []
        buf = field_name[0]
        for c_prev, c in zip(field_name, field_name[1:]):
            if c.isupper() and (not c_prev.isupper()):
                parts.append(buf)
                buf = c
            else:
                buf += c
        parts.append(buf)
        if len(parts) > 1:
            underscore_variant = '_'.join(parts)
            hyphen_variant = '-'.join(parts)
            variations.add(underscore_variant)
            variations.add(hyphen_variant)
            # lower_first + capitalized rest style (q_RxLevMin already covers)
            variations.add(parts[0].lower() + '_' + '_'.join(p.capitalize() for p in parts[1:]))
            variations.add(parts[0].lower() + '-' + '-'.join(p.capitalize() for p in parts[1:]))
            # Single underscore after first segment then CamelCase concatenation of remaining (canonical seen in dataset)
            single_us = parts[0] + '_' + ''.join(parts[1:])
            variations.add(single_us)
            single_hyphen = parts[0] + '-' + ''.join(parts[1:])
            variations.add(single_hyphen)
    
    # Common 3GPP spelling variations (phyCellId vs physCellId, etc.)
    # Add 's' after 'phy' if missing
    if 'phycell' in field_name.lower() and 'physcell' not in field_name.lower():
        variations.add(field_name.lower().replace('phycell', 'physcell'))
        variations.add(field_name.lower().replace('phycell', 'physCell'))
        variations.add(field_name.lower().replace('phycell', 'physcell').replace('_', ''))  # physcellid
    # Remove 's' after 'phys' if present (reverse mapping)
    if 'physcell' in field_name.lower():
        variations.add(field_name.lower().replace('physcell', 'phycell'))
        variations.add(field_name.lower().replace('physcell', 'phyCell'))
    
    return list(variations)


def detect_ue_id_in_sql(sql: str) -> Optional[tuple[str, str]]:
    """
    Detect if SQL query is filtering by a UE ID field.
    
    Returns:
        Tuple of (field_name, value) if UE ID detected, None otherwise
        
    Examples:
        "WHERE s1ap.ENB_UE_S1AP_ID = '1'" -> ("s1ap.ENB_UE_S1AP_ID", "1")
        "WHERE rlc-lte.ueid = '61'" -> ("rlc-lte.ueid", "61")
    """
    # Common UE ID field patterns
    ue_id_patterns = [
        # LIKE patterns for JSON fields (most common in our queries)
        (r"ENB_UE_S1AP_ID[\"']?:\s*[\"']?(\d+)", "s1ap.s1ap.ENB_UE_S1AP_ID"),
        (r"MME_UE_S1AP_ID[\"']?:\s*[\"']?(\d+)", "s1ap.s1ap.MME_UE_S1AP_ID"),
        (r"rlc-lte\.ueid[\"']?:\s*[\"']?(\d+)", "rlc_lte.rlc-lte.ueid"),
        (r"m_tmsi[\"']?:\s*[\"']?(\d+)", "nas-eps.emm.m_tmsi"),
        (r"RAN_UE_NGAP_ID[\"']?:\s*[\"']?(\d+)", "ngap.RAN_UE_NGAP_ID"),
        # Direct field comparisons
        (r"s1ap\.(?:s1ap\.)?ENB_UE_S1AP_ID['\"]?\s*=\s*['\"]?(\d+)", "s1ap.s1ap.ENB_UE_S1AP_ID"),
        (r"s1ap\.(?:s1ap\.)?MME_UE_S1AP_ID['\"]?\s*=\s*['\"]?(\d+)", "s1ap.s1ap.MME_UE_S1AP_ID"),
        (r"rlc-lte\.ueid['\"]?\s*=\s*['\"]?(\d+)", "rlc_lte.rlc-lte.ueid"),
        (r"rlc_lte\.rlc-lte\.ueid['\"]?\s*=\s*['\"]?(\d+)", "rlc_lte.rlc-lte.ueid"),
        (r"m_tmsi['\"]?\s*=\s*['\"]?(\d+)", "nas-eps.emm.m_tmsi"),
        (r"ngap\.(?:ngap\.)?RAN_UE_NGAP_ID['\"]?\s*=\s*['\"]?(\d+)", "ngap.RAN_UE_NGAP_ID"),
    ]
    
    for pattern, field_name in ue_id_patterns:
        match = re.search(pattern, sql, re.IGNORECASE)
        if match:
            value = match.group(1)
            logger.info(f"Detected UE ID filter: {field_name} = {value}")
            return (field_name, value)
    
    return None


def expand_query_results_with_correlation(
    original_results: List[Dict[str, Any]],
    correlation_table,
    conn,
    ue_id_field: str,
    ue_id_value: str,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Expand query results by adding all packets for correlated UE IDs.
    
    Args:
        original_results: Original query results
        correlation_table: UeCorrelationTable instance
        conn: DuckDB connection
        ue_id_field: Field name that was queried
        ue_id_value: Value that was queried
        limit: Maximum total rows to return
        
    Returns:
        Expanded results with all correlated UE packets
    """
    # Map field names to correlation ID types
    field_to_type = {
        "rlc_lte.rlc-lte.ueid": "rlc_ueid",
        "s1ap.s1ap.ENB_UE_S1AP_ID": "enb_ue_s1ap_id",
        "s1ap.s1ap.MME_UE_S1AP_ID": "mme_ue_s1ap_id",
        "nas-eps.emm.m_tmsi": "m_tmsi",
    }
    
    id_type = field_to_type.get(ue_id_field)
    if not id_type:
        logger.warning(f"Unknown UE ID field for correlation: {ue_id_field}")
        return original_results
    
    # Get all correlated IDs
    correlated_ids = correlation_table.get_correlated_ids(id_type, ue_id_value)
    
    if not correlated_ids:
        logger.info(f"No correlations found for {ue_id_field}={ue_id_value}")
        return original_results
    
    logger.info(f"Found {len(correlated_ids)} correlated IDs - fetching all related packets...")
    
    # Build SQL to fetch all packets with any of the correlated IDs
    type_to_field = {
        "rlc_ueid": "rlc_lte.rlc-lte.ueid",
        "enb_ue_s1ap_id": "s1ap.s1ap.ENB_UE_S1AP_ID",
        "mme_ue_s1ap_id": "s1ap.s1ap.MME_UE_S1AP_ID",
        "m_tmsi": "nas-eps.emm.m_tmsi",
    }
    
    conditions = []
    for ue_id in correlated_ids:
        field_name = type_to_field.get(ue_id.id_type)
        if field_name:
            conditions.append(f"protocol_fields_json LIKE '%\"{field_name}\": \"{ue_id.value}\"%'")
    
    if not conditions:
        return original_results
    
    # Build and execute expanded query
    expanded_condition = " OR ".join(conditions)
    expanded_sql = f"""
        SELECT * FROM packets 
        WHERE ({expanded_condition})
        ORDER BY packet_number
        LIMIT {limit}
    """
    
    logger.debug(f"Executing expanded query for UE correlation")
    
    try:
        expanded_results = conn.execute(expanded_sql).fetchdf().to_dict('records')
        logger.info(f"✓ UE correlation: Expanded from {len(original_results)} to {len(expanded_results)} packets")
        return expanded_results
    except Exception as e:
        logger.error(f"Failed to execute expanded query: {e}")
        return original_results


def extract_specific_field_value(
    results: List[Dict[str, Any]],
    query_text: str,
    return_all: bool = True,
    schema_catalog=None
) -> Optional[tuple[str, str] | List[Dict[str, Any]]]:
    """Extract field value(s) the user asked for.

    Extended behavior: when multiple packets contain matches and `return_all` is True,
    return a list of rows: [{packet_number, field, value}]. If single match, return
    legacy tuple (field, value) for backwards compatibility.

    Args:
        results: Query results with protocol_fields_json
        query_text: Original natural language query
        return_all: Whether to return all matches instead of a single best match
        schema_catalog: Optional SchemaCatalog for intelligent field name resolution

    Returns:
        (field, value) tuple OR list of dict rows OR None
    """
    if not results:
        logger.debug("No results to extract field value from")
        return None
    
    # Try to identify what the user is asking for
    query_lower = query_text.lower()
    
    # Common query patterns - extract field names
    search_terms = []
    
    # Pattern 1: "what is X" or "what is the X timer/value/etc" - capture field name
    # Handles: "what is q-RxLevMin", "what is the t300 timer", "what is the t310 timer value in sib2", etc.
    # Also handles: "what is hnb name", "what is RxLevMin" (spaces and partial names)
    # Also handles: "what is lte-rrc.carrierFreq" (dot-separated field names)
    # Also handles contractions: "whats", "what's"
    # The field name can contain letters, numbers, spaces, hyphens, underscores, DOTS
    # NOTE: Using case-insensitive flag (re.IGNORECASE) to match keywords, but PRESERVE original field name case
    patterns = [
        # "... value of FIELD" - MUST BE FIRST to match "what is the value of X" queries
        r"value\s+of\s+(?:the\s+)?([a-zA-Z0-9_\-\s\.]+?)(?:\s+(?:in|from|for|of)|[?\s,;.!]*$)",
        # "what is the FIELD timer/parameter/field..." (multi-word with spaces/dots) - but NOT "value"
        r"what(?:'?s|'s|\s+is)\s+(?:the\s+)?([a-zA-Z0-9_\-\s\.]+?)\s+(?:timer|parameter|field)\s",
        # "what is the FIELD in/from..." (multi-word with spaces/dots)
        r"what(?:'?s|'s|\s+is)\s+(?:the\s+)?([a-zA-Z0-9_\-\s\.]+?)\s+(?:in|from|for|of)\s+",
        # "what is the FIELD?" (end of query with optional punctuation)
        r"what(?:'?s|'s|\s+is)\s+(?:the\s+)?([a-zA-Z0-9_\-\s\.]+?)[?\s,;.!]*$",
        # "show me the FIELD..."
        r"show\s+(?:me\s+)?(?:the\s+)?([a-zA-Z0-9_\-\s\.]+?)\s+(?:timer|parameter|field|in|from|for|of)",
        r"find\s+(?:the\s+)?([a-zA-Z0-9_\-\s\.]+?)\s+(?:timer|parameter|field|in|from|for|of)",
        r"get\s+(?:the\s+)?([a-zA-Z0-9_\-\s\.]+?)\s+(?:timer|parameter|field|in|from|for|of)",
    ]
    
    for pattern in patterns:
        # Use case-insensitive matching on original query to preserve field name case
        match = re.search(pattern, query_text, re.IGNORECASE)
        if match:
            field_term = match.group(1).strip()  # Strip whitespace and punctuation
            # Clean up: remove common words like "value", "timer", "parameter" (case-insensitive)
            field_term = re.sub(r'\s+(value|timer|parameter|field)$', '', field_term, flags=re.IGNORECASE)
            # Skip if the extracted term is just a common word (value, timer, etc.)
            if field_term.strip().lower() in ['value', 'timer', 'parameter', 'field', 'the']:
                continue
            search_terms.append(field_term)

    
    if not search_terms:
        logger.debug(f"No search terms extracted from query: {query_text}")
        return None
    
    # Generate all variations of each search term for fuzzy matching
    # hnb-name → [hnb_name, hnbName, hnb_Name, HNB_NAME, etc.]
    search_variations = []
    for term in search_terms:
        variations = _generate_field_name_variations_internal(term)
        search_variations.extend(variations)
        logger.debug(f"Generated {len(variations)} variations for '{term}': {variations[:5]}")
    
    logger.debug(f"Search terms: {search_terms} (with {len(search_variations)} total variations)")
    
    # Aggregate matches across all packets when return_all=True
    all_matches: List[Dict[str, Any]] = []
    best_match: Optional[tuple[str, str]] = None
    best_score = 0
    
    # Try to use schema catalog for intelligent field resolution first
    exact_field_names = []
    if schema_catalog:
        # Get message type from first result if available
        message_type = None
        if results and "message_type" in results[0]:
            message_type = results[0]["message_type"]
        
        # Try to resolve each search term to exact field names
        for term in search_terms:
            if message_type:
                exact_name = schema_catalog.get_exact_field_name(term, message_type)
                # If we only got a *_flag field, look globally for a better non-flag identity field
                if exact_name and ('flag' in exact_name.lower()):
                    global_matches = schema_catalog.find_matching_fields(term)
                    better = [gm for (_mt, gm) in global_matches if 'flag' not in gm.lower()]
                    if better:
                        # Prefer one containing the query token exactly (e.g., m_tmsi)
                        preferred = None
                        for cand in better:
                            if term.lower().replace('-', '').replace('_', '') in cand.lower().replace('-', '').replace('_', ''):
                                preferred = cand
                                break
                        exact_name = preferred or better[0]
                if exact_name and exact_name != term:
                    exact_field_names.append(exact_name)
                    logger.info(f"✓ Schema catalog resolved '{term}' → '{exact_name}' for {message_type}")
            else:
                # Try without message type constraint
                matches = schema_catalog.find_matching_fields(term)
                if matches:
                    # De-prioritize flag fields if value field exists
                    value_first = sorted(matches, key=lambda m: (('flag' in m[1].lower()), m[1]))
                    field_name = value_first[0][1]
                    exact_field_names.append(field_name)
                    logger.info(f"✓ Schema catalog resolved '{term}' → '{field_name}'")

    for result in results:
        protocol_fields_json = result.get("protocol_fields_json")
        # Accept possible key variants; fallback to geninfo.num embedded in JSON
        pkt_num = result.get("packet_number") or result.get("packet_num") or result.get("packet")
        if not protocol_fields_json:
            continue

        try:
            fields = json.loads(protocol_fields_json) if isinstance(protocol_fields_json, str) else protocol_fields_json
        except json.JSONDecodeError:
            continue
        
        # Fallback: extract packet_number from geninfo.num in JSON if missing
        if pkt_num is None:
            pkt_num = fields.get("geninfo.num") or "unknown"
        
        # Extract UE ID from multiple possible field names (best effort)
        ue_id = None
        ue_id_candidates = [
            fields.get("s1ap.s1ap.ENB_UE_S1AP_ID"),
            fields.get("rlc_lte.rlc-lte.ueid"),
            fields.get("s1ap.s1ap.MME_UE_S1AP_ID"),
            fields.get("ngap.RAN_UE_NGAP_ID"),
        ]
        for candidate in ue_id_candidates:
            if candidate is not None and candidate != "" and candidate is not False:
                ue_id = str(candidate)
                break
        
        # Default to empty string if no UE ID found
        if ue_id is None:
            ue_id = ""
        
        # PRIORITY 1: Try exact field names from schema catalog first
        if exact_field_names:
            for exact_field in exact_field_names:
                if exact_field in fields:
                    field_value = fields[exact_field]
                    if field_value not in (None, ''):
                        if return_all:
                            all_matches.append({
                                "packet_number": pkt_num,
                                "ue_id": ue_id,
                                "field": exact_field,
                                "value": str(field_value)
                            })
                        else:
                            best_match = (exact_field, str(field_value))
                            best_score = 1000  # Highest priority
                        logger.debug(f"✓ Exact match from schema catalog: {exact_field} = {field_value}")

        # PRIORITY 2: Fallback to fuzzy matching if no exact matches found
        if not all_matches and best_score < 1000:
            for field_name, field_value in fields.items():
                field_name_lower = field_name.lower()
                matched = False
                for search_variation in search_variations:
                    search_normalized = search_variation.replace('-', '').replace('_', '').replace(' ', '').lower()
                    field_normalized = field_name_lower.replace('-', '').replace('_', '').replace('.', '')
                    if search_normalized in field_normalized:
                        matched = True
                        score = len(search_normalized)
                        if field_normalized.endswith(search_normalized):
                            score += 10
                        if len(field_name) < 50:
                            score += 5
                        if field_name_lower.endswith(search_variation.lower()):
                            score += 15
                        if score > best_score:
                            best_score = score
                            best_match = (field_name, str(field_value))
                        # Break after first variation match to prevent duplicates
                        break
                if matched and return_all and field_value not in (None, ''):
                    all_matches.append({
                        "packet_number": pkt_num,
                        "ue_id": ue_id,  # Add UE ID column
                        "field": field_name,
                        "value": str(field_value)
                    })

    if return_all and all_matches:
        query_lower = query_text.lower()
        # Deduplicate exact packet/field/value triples
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for row in all_matches:
            key = (row.get("packet_number"), row.get("field"), row.get("value"))
            if key not in seen:
                seen.add(key)
                deduped.append(row)

        # Optionally hide flag fields unless user explicitly asked for a flag
        if 'flag' not in query_lower:
            before = len(deduped)
            deduped = [r for r in deduped if 'flag' not in (r.get('field','').lower())]
            if len(deduped) != before:
                logger.debug(f"Filtered flag helper fields: {before} -> {len(deduped)}")

        # Collapse duplicates when query intent is singular (e.g. 'what is', 'value of')
        singular_intent = (('what is' in query_lower or "what's" in query_lower or 'value of' in query_lower)
                           and 'all ' not in query_lower and 'list' not in query_lower and 'each' not in query_lower)
        if singular_intent and deduped:
            # Group by value string
            from collections import defaultdict
            by_value: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for r in deduped:
                by_value[str(r.get('value'))].append(r)
            if len(by_value) == 1:
                # Only one unique value -> keep earliest packet only
                only_value = next(iter(by_value.keys()))
                earliest = min(by_value[only_value], key=lambda r: int(r.get('packet_number') or 1))
                deduped = [earliest]
                logger.debug("Collapsed identical values across multiple packets/UEs to single representative row")
            else:
                # Multiple distinct values -> keep earliest per distinct value
                collapsed = []
                for val, rows in by_value.items():
                    earliest = min(rows, key=lambda r: int(r.get('packet_number') or 1))
                    collapsed.append(earliest)
                deduped = sorted(collapsed, key=lambda r: int(r.get('packet_number') or 1))
                logger.debug(f"Collapsed to earliest row per distinct value ({len(deduped)} distinct values)")

        # Sort so that non-flag primary identity/value fields appear first (after collapsing)
        def _row_score(r: Dict[str, Any]) -> int:
            fname = (r.get('field') or '').lower()
            score = 0
            if 'flag' in fname:
                score -= 100
            for ident in ['m_tmsi', 'pdn_ipv4', 'guti', 'imsi', 'ran_ue_ngap_id']:
                if ident in fname:
                    score += 50
            return -score
        deduped.sort(key=_row_score)
        logger.info(f"Collected {len(deduped)} unique matches for requested field")
        return deduped
    if best_match:
        logger.info(f"Found best match: {best_match[0]} = {best_match[1]}")
        return best_match
    
    logger.debug("No matching field found in results")
    return None


def extract_rsrp_rsrq_values(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extract RSRP and RSRQ values from RRC measurement report results.
    
    Converts the JSON protocol_fields_json into a clean table with:
    - packet_number
    - timestamp_iso
    - rsrp_result (integer value)
    - rsrp_dbm (human-readable dBm range)
    - rsrq_result (integer value)  
    - rsrq_db (human-readable dB range)
    
    Args:
        results: Query results containing measurement reports with protocol_fields_json
        
    Returns:
        List of dictionaries with extracted RSRP/RSRQ values
    """
    extracted_rows = []
    
    for result in results:
        protocol_fields_json = result.get("protocol_fields_json")
        if not protocol_fields_json:
            continue
        
        # Parse JSON
        try:
            if isinstance(protocol_fields_json, str):
                fields = json.loads(protocol_fields_json)
            else:
                fields = protocol_fields_json
        except (json.JSONDecodeError, TypeError):
            continue
        
        # Prefer newly added contextual PCell keys when present.
        rsrp_result = None
        rsrq_result = None

        # Contextual keys may be prefixed by protocol name (e.g. rlc_lte.lte-rrc.rsrpResult__context=pcell)
        # Build dynamic search for any key ending with suffix.
        pcell_rsrp_suffix = 'lte-rrc.rsrpResult__context=pcell'
        pcell_rsrq_suffix = 'lte-rrc.rsrqResult__context=pcell'
        # Find matching full keys
        pcell_rsrp_key = next((k for k in fields.keys() if k.endswith(pcell_rsrp_suffix)), None)
        pcell_rsrq_key = next((k for k in fields.keys() if k.endswith(pcell_rsrq_suffix)), None)
        if pcell_rsrp_key and pcell_rsrq_key:
            # Direct contextual extraction
            try:
                rsrp_result = int(fields[pcell_rsrp_key])
            except (ValueError, TypeError):
                rsrp_result = None
            try:
                rsrq_result = int(fields[pcell_rsrq_key])
            except (ValueError, TypeError):
                rsrq_result = None
        else:
            # Fallback to legacy heuristic (first occurrence filtering)
            pcell_keys = [k for k in fields.keys() if k.endswith('measResultPCell_element') or k.endswith('.measResultPCell_element')]
            has_meas_result_pcell = len(pcell_keys) > 0
            if not has_meas_result_pcell:
                continue
            neighbor_markers = [
                'measResultNeighCells',
                'measResultListEUTRA',
                'cellsTriggeredList',
                'measResultBestNeighCell'
            ]
            neighbor_presence = any(any(marker in k for marker in neighbor_markers) for k in fields.keys())
            for field_name, field_value in fields.items():
                if field_value is None:
                    continue
                if any(marker in field_name for marker in neighbor_markers):
                    continue
                if 'rsrpResult' in field_name and rsrp_result is None:
                    try:
                        rsrp_result = int(field_value)
                    except (ValueError, TypeError):
                        rsrp_result = None
                elif 'rsrqResult' in field_name and rsrq_result is None:
                    try:
                        rsrq_result = int(field_value)
                    except (ValueError, TypeError):
                        rsrq_result = None
            if neighbor_presence and (rsrp_result is None or rsrq_result is None):
                continue

        # If neighbor list present and serving cell values look suspicious (e.g., zero or unrealistic range), could add validation later.
        
        # Require both values; if either missing, skip to avoid partial rows
        if rsrp_result is None or rsrq_result is None:
            continue
        
        # Convert to human-readable values
        rsrp_dbm = rsrp_to_dbm(rsrp_result) if rsrp_result is not None else None
        rsrq_db = rsrq_to_db(rsrq_result) if rsrq_result is not None else None
        
        # Create extracted row - handle all potential None values
        row = {
            "packet_number": result.get("packet_number") or "N/A",
            "timestamp_iso": result.get("timestamp_iso") or result.get("timestamp") or "N/A",  # Fallback chain
            "rsrp_result": rsrp_result if rsrp_result is not None else "N/A",  # Prevent None
            "rsrp_dbm": rsrp_dbm or "N/A",  # Prevent None values
            "rsrq_result": rsrq_result if rsrq_result is not None else "N/A",  # Prevent None
            "rsrq_db": rsrq_db or "N/A",  # Prevent None values
        }
        
        extracted_rows.append(row)
    
    return extracted_rows


def build_measurement_report_sql_for_ue(ue_id: str, conn) -> Optional[str]:
    """Construct a deterministic SQL statement to fetch measurement reports for a given UE id.

    Logic:
    1. Treat provided ue_id first as direct RLC UE ID (rlc_lte.rlc-lte.ueid).
    2. If no packets exist for that id containing rsrpResult, attempt correlation mapping:
       - Look for packets where protocol_fields_json contains rsrpResult and any of correlated identifiers
         (s1ap ENB/MME IDs) equal to the given ue_id, then read corresponding rlc UE id from those packets.
    3. Return None if no measurement reports found.
    """
    import duckdb, json

    # Ensure ue_id is numeric string
    ue_id_str = str(ue_id).strip()

    # Check for direct RLC match
    direct_sql = f"""
    SELECT packet_number, timestamp_iso, protocol_fields_json
    FROM packets
    WHERE protocol_fields_json LIKE '%"rlc_lte.rlc-lte.ueid": "{ue_id_str}"%' AND protocol_fields_json LIKE '%rsrpResult%'
    ORDER BY packet_number
    """
    try:
        direct_rows = conn.execute(direct_sql).fetchall()
    except Exception:
        direct_rows = []

    if direct_rows:
        # We found packets directly; include rsrqResult filter tightening
        return f"""
        SELECT packet_number, timestamp_iso, protocol_fields_json
        FROM packets
        WHERE protocol_fields_json LIKE '%"rlc_lte.rlc-lte.ueid": "{ue_id_str}"%' 
          AND protocol_fields_json LIKE '%rsrpResult%'
          AND protocol_fields_json LIKE '%rsrqResult%'
        ORDER BY packet_number
        """

    # Attempt correlation: find any packet with rsrpResult that has ENB/MME matching given id
    correlation_scan_sql = """
    SELECT packet_number, protocol_fields_json
    FROM packets
    WHERE protocol_fields_json LIKE '%rsrpResult%'
    """
    try:
        corr_rows = conn.execute(correlation_scan_sql).fetchall()
    except Exception:
        corr_rows = []

    correlated_rlc_ids = set()
    for pkt, pf_json in corr_rows:
        try:
            fields = json.loads(pf_json)
        except Exception:
            continue
        enb = fields.get('s1ap.s1ap.ENB_UE_S1AP_ID')
        mme = fields.get('s1ap.s1ap.MME_UE_S1AP_ID')
        rlc = fields.get('rlc_lte.rlc-lte.ueid')
        if (enb and enb == ue_id_str) or (mme and mme == ue_id_str):
            if rlc:
                correlated_rlc_ids.add(rlc)

    if correlated_rlc_ids:
        # Build IN clause for all correlated RLC ids
        or_clauses = []
        for rid in sorted(correlated_rlc_ids):
            or_clauses.append(f"protocol_fields_json LIKE '%\"rlc_lte.rlc-lte.ueid\": \"{rid}\",%'")
            # Escape literal closing brace with doubling
            or_clauses.append(f"protocol_fields_json LIKE '%\"rlc_lte.rlc-lte.ueid\": \"{rid}\"}}%'")
        or_clause = " OR ".join(or_clauses)
        return (
            "SELECT packet_number, timestamp_iso, protocol_fields_json "
            "FROM packets WHERE protocol_fields_json LIKE '%rsrpResult%' "
            "AND protocol_fields_json LIKE '%rsrqResult%' "
            "AND (" + or_clause + ") ORDER BY packet_number"
        )

    return None


def resolve_rlc_ids_for_logical_ue(ue_value: str, correlation_table, conn) -> set[str]:
    """Resolve one or more RLC UE IDs (rlc_lte.rlc-lte.ueid) for a user-provided UE identifier.

    The provided ``ue_value`` might be:
    - A direct RLC UE ID (e.g. "64")
    - An ENB_UE_S1AP_ID / MME_UE_S1AP_ID (e.g. "1")
    - An m_tmsi value

    Resolution strategy (ordered):
    1. Direct check: If treating ue_value as RLC UE ID yields measurement packets (rsrpResult present), accept it.
    2. Correlation table lookup: Attempt correlated IDs for id types enb_ue_s1ap_id, mme_ue_s1ap_id, m_tmsi.
       Collect any correlated rlc_ueid values.
    3. Passive scan: As last resort, scan packets containing rsrpResult and look for ENB/MME IDs equal to ue_value,
       then collect their associated rlc UE IDs.

    Args:
        ue_value: User provided UE identifier
        correlation_table: UeCorrelationTable instance (may be None)
        conn: DuckDB connection for lightweight existence checks

    Returns:
        Set of resolved RLC UE ID strings (may be empty if unresolved)
    """
    resolved: set[str] = set()
    val = str(ue_value).strip()

    # 1. Direct check
    direct_sql = (
        "SELECT 1 FROM packets WHERE protocol_fields_json LIKE '%\"rlc_lte.rlc-lte.ueid\": \""
        + val + "\"%' AND protocol_fields_json LIKE '%rsrpResult%' LIMIT 1"
    )
    try:
        direct_rows = conn.execute(direct_sql).fetchall()
        if direct_rows:
            resolved.add(val)
            logger.debug(f"Resolved UE '{val}' directly as RLC UE ID")
    except Exception:
        pass

    # 2. Correlation table lookup (if available)
    if correlation_table:
        for id_type in ["enb_ue_s1ap_id", "mme_ue_s1ap_id", "m_tmsi"]:
            correlated = correlation_table.get_correlated_ids(id_type, val)
            if correlated:
                for cid in correlated:
                    if cid.id_type == "rlc_ueid":
                        resolved.add(cid.value)
                if resolved:
                    logger.debug(
                        f"Correlation table mapping for {id_type}={val} produced RLC IDs: {sorted(resolved)}"
                    )
                    # Do not break; collect all potential mappings from other layers too

    # 3. Passive scan if still empty
    if not resolved:
        scan_sql = "SELECT packet_number, protocol_fields_json FROM packets WHERE protocol_fields_json LIKE '%rsrpResult%'"
        try:
            rows = conn.execute(scan_sql).fetchall()
        except Exception:
            rows = []
        import json as _json
        for pkt_num, pf_json in rows:
            try:
                fields = _json.loads(pf_json)
            except Exception:
                continue
            enb = fields.get('s1ap.s1ap.ENB_UE_S1AP_ID')
            mme = fields.get('s1ap.s1ap.MME_UE_S1AP_ID')
            rlc = fields.get('rlc_lte.rlc-lte.ueid')
            if rlc and (enb == val or mme == val):
                resolved.add(str(rlc))
        if resolved:
            logger.debug(f"Passive scan resolved UE '{val}' to RLC IDs: {sorted(resolved)}")

    if not resolved:
        logger.info(f"Could not resolve UE identifier '{val}' to any RLC UE IDs")
    return resolved


def rsrp_to_dbm(rsrp_value: int) -> str:
    """
    Convert RSRP integer value (0-97) to dBm range string.
    
    3GPP TS 36.133: RSRP measurement range is -140 dBm to -44 dBm
    Each step is 1 dBm.
    
    Args:
        rsrp_value: Integer 0-97
        
    Returns:
        String like "-93dBm to -92dBm" or "Unknown" if out of range
    """
    if rsrp_value is None or not (0 <= rsrp_value <= 97):
        return "Unknown"
    
    lower_dbm = -140 + rsrp_value
    upper_dbm = lower_dbm + 1
    
    return f"{lower_dbm}dBm to {upper_dbm}dBm"


def rsrq_to_db(rsrq_value: int) -> str:
    """
    Convert RSRQ integer value (0-34) to dB range string.
    
    3GPP TS 36.133: RSRQ measurement range is -19.5 dB to -3 dB
    Each step is 0.5 dB.
    
    Args:
        rsrq_value: Integer 0-34
        
    Returns:
        String like "-6.0dB to -5.5dB" or "Unknown" if out of range
    """
    if rsrq_value is None or not (0 <= rsrq_value <= 34):
        return "Unknown"
    
    lower_db = -19.5 + (rsrq_value * 0.5)
    upper_db = lower_db + 0.5
    
    return f"{lower_db:.1f}dB to {upper_db:.1f}dB"


def format_handover_call_flow(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Format handover call flow with enhanced readability and flow analysis.
    
    Detects handover type (X2 or S1), identifies phases, and adds flow indicators.
    
    Args:
        results: Query results with handover messages
        
    Returns:
        Formatted list with handover flow annotations
    """
    if not results:
        return results
    
    formatted_rows = []
    handover_type = None
    phase = "UNKNOWN"
    
    # Handover message patterns for X2 and S1
    x2_patterns = {
        "preparation": ["handoverrequest", "handoverpreparation"],
        "execution": ["snstatustransfer", "pathswitch"],
        "completion": ["uecontextrelease", "handoverrequestacknowledge"],
        "failure": ["handoverpreparationfailure", "handoverfailure"]
    }
    
    s1_patterns = {
        "preparation": ["handoverrequired", "handoverrequest"],
        "execution": ["handovercommand", "mobilityfromeut"],
        "completion": ["handovernotify", "uecontextrelease"],
        "failure": ["handoverfailure", "handoverpreparationfailure"]
    }
    
    for idx, result in enumerate(results):
        protocol = result.get("protocol", "")
        message_type = result.get("message_type", "").lower()
        direction = result.get("direction", "")
        interface = result.get("interface", "")
        
        # Extract UE IDs and specific message name from protocol_fields_json if available
        enb_ue_id = None
        mme_ue_id = None
        specific_message = None
        protocol_fields_json = result.get("protocol_fields_json", "")
        
        if protocol_fields_json:
            try:
                import json
                fields = json.loads(protocol_fields_json) if isinstance(protocol_fields_json, str) else protocol_fields_json
                
                # Extract S1AP UE IDs
                enb_ue_id = fields.get("s1ap.s1ap.ENB_UE_S1AP_ID")
                mme_ue_id = fields.get("s1ap.s1ap.MME_UE_S1AP_ID")
                
                # Extract X2AP UE IDs if S1AP not found
                if not enb_ue_id:
                    enb_ue_id = fields.get("x2ap.x2ap.Old_ENB_UE_X2AP_ID") or fields.get("x2ap.x2ap.New_ENB_UE_X2AP_ID")
                
                # Extract RRC UE ID if others not found
                if not enb_ue_id:
                    enb_ue_id = fields.get("rlc_lte.rlc-lte.ueid")
                
                # Extract specific S1AP/X2AP message name (for disambiguating generic names)
                for key in fields.keys():
                    if protocol == "S1AP" and "s1ap.s1ap." in key and "_element" in key:
                        # Extract message name like "HandoverRequired" from "s1ap.s1ap.HandoverRequired_element"
                        msg_name = key.replace("s1ap.s1ap.", "").replace("_element", "")
                        if msg_name and "handover" in msg_name.lower():
                            specific_message = msg_name
                            break
                    elif protocol == "X2AP" and "x2ap.x2ap." in key and "_element" in key:
                        # Extract message name from X2AP
                        msg_name = key.replace("x2ap.x2ap.", "").replace("_element", "")
                        if msg_name and "handover" in msg_name.lower():
                            specific_message = msg_name
                            break
            except (json.JSONDecodeError, AttributeError, TypeError):
                pass
        
        # Use specific message name if found, otherwise use generic
        display_message = specific_message if specific_message else result.get("message_type")
        
        # Detect handover type from protocol
        if protocol == "X2AP":
            handover_type = "X2"
        elif protocol == "S1AP" and "handover" in message_type:
            handover_type = "S1"
        
        # Determine phase based on message
        if handover_type == "X2":
            if any(pat in message_type for pat in x2_patterns["preparation"]):
                phase = "PREPARATION"
            elif any(pat in message_type for pat in x2_patterns["execution"]):
                phase = "EXECUTION"
            elif any(pat in message_type for pat in x2_patterns["completion"]):
                phase = "COMPLETION"
            elif any(pat in message_type for pat in x2_patterns["failure"]):
                phase = "FAILURE"
        elif handover_type == "S1":
            if any(pat in message_type for pat in s1_patterns["preparation"]):
                phase = "PREPARATION"
            elif any(pat in message_type for pat in s1_patterns["execution"]):
                phase = "EXECUTION"
            elif any(pat in message_type for pat in s1_patterns["completion"]):
                phase = "COMPLETION"
            elif any(pat in message_type for pat in s1_patterns["failure"]):
                phase = "FAILURE"
        
        # Detect RRC mobility messages
        if protocol == "RRC":
            if "mobility" in message_type or "reconfiguration" in message_type:
                phase = "EXECUTION"
        
        # Add flow indicator
        flow_indicator = ""
        if idx == 0:
            flow_indicator = "▶ START"
        elif "failure" in message_type.lower():
            flow_indicator = "✗ FAIL"
        elif "acknowledge" in message_type.lower() or "complete" in message_type.lower():
            flow_indicator = "✓ ACK"
        elif "notify" in message_type.lower():
            flow_indicator = "✓ NOTIFY"
        elif "release" in message_type.lower():
            if idx == len(results) - 1:
                flow_indicator = "▶ END"
            else:
                flow_indicator = "⚡ RELEASE"
        else:
            flow_indicator = "→"
        
        # Create formatted row with UE IDs and specific message name
        formatted_row = {
            "step": idx + 1,
            "flow": flow_indicator,
            "packet_number": result.get("packet_number"),
            "timestamp_iso": result.get("timestamp_iso"),
            "protocol": protocol,
            "message_type": display_message,
            "enb_ue_id": enb_ue_id if enb_ue_id else "-",
            "mme_ue_id": mme_ue_id if mme_ue_id else "-",
            "direction": direction if direction else "-",
            "interface": interface if interface else "-",
            "phase": phase,
            "ho_type": handover_type if handover_type else "UNKNOWN"
        }
        
        formatted_rows.append(formatted_row)
    
    return formatted_rows


def detect_handover_in_query(query_text: str, generated_sql: str) -> bool:
    """
    Detect if query is about handover call flow tracing.
    
    Args:
        query_text: User's natural language query
        generated_sql: Generated SQL query
        
    Returns:
        True if this is a handover tracing query
    """
    query_lower = query_text.lower()
    sql_lower = generated_sql.lower()
    
    # Handover keywords
    handover_keywords = [
        "handover", "ho ", "h.o", "mobility",
        "call flow", "trace", "flow"
    ]
    
    # Check if query mentions handover
    has_handover_keyword = any(kw in query_lower for kw in handover_keywords)
    
    # Check if SQL searches for handover messages
    sql_has_handover = (
        "handover" in sql_lower or 
        "x2ap" in sql_lower or
        ("s1ap" in sql_lower and ("enb_ue_s1ap_id" in sql_lower or "mme_ue_s1ap_id" in sql_lower))
    )
    
    return has_handover_keyword and sql_has_handover
