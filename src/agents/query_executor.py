"""Natural language query executor."""

import time
import re
import json
from typing import Optional, Any, List

import click
import duckdb

from src.agents import message_type_mapper, prompts, reasoning_engine
from src.agents.llm_client import initialize_llm_client
from datetime import datetime
from src.models.query import QueryRequest, QueryResult, QueryStatus, ResultType
from src.query import sql_executor
from src.utils.logger import get_logger
from src.config import config

logger = get_logger(__name__)


def _detect_sib_query(query_text: str) -> bool:
    """
    Detect if query is asking about SIB (System Information Block) broadcast messages.
    
    SIB queries should NOT have UE ID filters since SIBs are broadcast to all UEs.
    """
    query_lower = query_text.lower()
    sib_patterns = [
        r'\bsib\s*\d+\b',  # sib1, sib2, sib3, etc.
        r'\bsib\b',  # just "sib"
        r'system\s+information',  # "system information"
        r'broadcast',  # "broadcast"
    ]
    return any(re.search(pattern, query_lower) for pattern in sib_patterns)


def _generate_field_name_variations(field_name: str) -> List[str]:
    """
    Generate all common variations of a field name to support fuzzy matching.
    
    Examples:
        "hnb-name" → ["hnb_name", "hnb_Name", "hnbName", "hnb-name", "HNB_NAME", "hnbname"]
        "q-RxLevMin" → ["q_RxLevMin", "qRxLevMin", "q-RxLevMin", "Q_RXLEVMIN", "qrxlevmin"]
    
    This allows users to type field names naturally without worrying about exact casing/separators.
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
    # Handle patterns like "q-RxLevMin" → "q_RxLevMin" or "hnb name" → "hnb_Name"
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


def execute_natural_language_query(
    model: Any,
    conn: duckdb.DuckDBPyConnection,
    query_text: str,
    dataset_path: str,
    limit: int = 100,
    correlation_table=None,
    network_mode: Optional[str] = None,
) -> tuple[QueryRequest, QueryResult]:
    """
    Execute natural language query using Gemini + DuckDB.

    Args:
        model: Gemini model instance
        conn: DuckDB connection
        query_text: Natural language query
        dataset_path: Path to dataset being queried
        limit: Maximum rows to return
        correlation_table: Optional UE correlation table
        network_mode: Network mode - "4g" (LTE), "5g" (NR), or None (auto-detect)

    Returns:
        Tuple of (QueryRequest, QueryResult)

    Raises:
        Exception: If query generation or execution fails
    """
    # Create query request
    query_request = QueryRequest(query_text=query_text, dataset_path=dataset_path)

    query_request.status = QueryStatus.GENERATING
    start_time = time.time()

    try:
        # NGAP Release / Failure analysis trigger (early evaluation before SQL generation)
        # Detect user intent: phrases like "explain how many ues are released" or "reason for failure".
        nl_lower_full = query_text.lower()
        
        # Check for UE message query: "did ue 93 get handover notify", "does ue 82 have InitialContextSetup"
        ue_msg_match = re.search(
            r'\b(?:ue\s+id\s+|ue\s+)(\d+)\b.*?\b(?:for|get|have|has|receive|received|send|sent)\b.*?\b(?:the\s+)?(\w+(?:\s+\w+){0,3})\s+(?:msg|message)',
            nl_lower_full,
            re.IGNORECASE
        )
        if not ue_msg_match:
            # Try alternative patterns: "did ue 93 handover notify"
            ue_msg_match = re.search(
                r'\b(?:did|does|has|is)\s+(?:ue\s+id\s+|ue\s+)(\d+)\b.*?\b(handover\s+\w+|initial\w+|pdu\w+|downlink\w+|uplink\w+)',
                nl_lower_full,
                re.IGNORECASE
            )
        
        if ue_msg_match:
            target_ue_id = ue_msg_match.group(1)
            message_type_raw = ue_msg_match.group(2).strip()
            
            # Clean up message type
            message_type = message_type_raw.replace('_', ' ').title().replace(' ', '')
            
            logger.info(f"Detected UE message query: UE {target_ue_id}, Message: {message_type}")
            
            # Check network mode
            if network_mode == "4g":
                error_msg = f"● UE Message Query - UE ID: {target_ue_id} (4G LTE)\n\n"
                error_msg += "  ⚠ 4G/LTE UE message queries are not yet implemented.\n"
                error_msg += "  The system currently only supports 5G NGAP message queries.\n\n"
                error_msg += f"  Message Type: {message_type}\n\n"
                error_msg += "  4G S1AP message analyzer is planned for future implementation."
                
                result = QueryResult(
                    query_id=query_request.query_id,
                    data=[{"message": error_msg}],
                    columns=["message"],
                    row_count=1,
                    result_type=ResultType.TABLE,
                    summary=f"4G UE message query not yet implemented (UE {target_ue_id})",
                )
                query_request.status = QueryStatus.COMPLETED
                query_request.generated_sql = "N/A - 4G message analyzer not available"
                query_request.execution_time_ms = int((time.time() - start_time) * 1000)
                return query_request, result
            else:
                # 5G NGAP message query
                logger.info(f"Performing 5G NGAP UE message query: UE {target_ue_id}, Message: {message_type}")
                analysis_sql = "SELECT packet_number, message_type, protocol_fields_json, timestamp_iso FROM packets LIMIT 10000"
                from src.query import sql_executor as _se
                analysis_rows = []
                try:
                    ar = _se.execute_sql(conn, analysis_sql, limit=10000)
                    analysis_rows = ar.data or []
                except Exception as ar_ex:
                    logger.warning(f"UE message query SQL failed: {ar_ex}")
                
                if analysis_rows:
                    from src.analysis.ngap_release_analyzer import analyze_ue_message
                    from src.models.query import ResultType as _RT
                    summary_text = analyze_ue_message(analysis_rows, target_ue_id, message_type)
                    
                    result = QueryResult(
                        query_id=query_request.query_id,
                        data=[{"analysis": summary_text}],
                        columns=["analysis"],
                        row_count=1,
                        result_type=_RT.TABLE,
                        summary=f"UE {target_ue_id} message query: {message_type}",
                    )
                    query_request.status = QueryStatus.COMPLETED
                    query_request.generated_sql = analysis_sql
                    query_request.execution_time_ms = int((time.time() - start_time) * 1000)
                    return query_request, result
                else:
                    logger.warning("UE message query returned no data rows")
        
        # Check for PDN/UE IP address query (4G): "what is the PDN IP address for UE ID 1", "UE IP address for UE 1"
        pdn_ip_match = re.search(
            r'\b(?:pdn|ue)\s+ip\s+address\b.*?\b(?:ue\s+id\s+|ue\s+|for\s+ue\s+)(\d+)',
            nl_lower_full,
            re.IGNORECASE
        )
        if not pdn_ip_match:
            # Alternative pattern: "UE 1 PDN IP"
            pdn_ip_match = re.search(
                r'\b(?:ue\s+id\s+|ue\s+)(\d+)\b.*?\b(?:pdn|ue)\s+ip',
                nl_lower_full,
                re.IGNORECASE
            )
        
        if pdn_ip_match and network_mode == "4g":
            target_ue_id = pdn_ip_match.group(1)
            logger.info(f"Detected PDN IP address query for UE ID: {target_ue_id}")
            
            # Direct SQL query for PDN IP address (4G S1AP field: s1ap.nas-eps.esm.pdn_ipv4)
            # Note: protocol_fields_json is stored as string, need to extract using regex
            pdn_ip_sql = f"""
                SELECT 
                    packet_number,
                    message_type,
                    regexp_extract(protocol_fields_json, '"s1ap\\.nas-eps\\.esm\\.pdn_ipv4":\\s*"([^"]+)"', 1) as pdn_ip_address
                FROM packets
                WHERE 
                    message_type LIKE '%InitialContextSetup%'
                    AND protocol_fields_json LIKE '%"s1ap.s1ap.ENB_UE_S1AP_ID": "{target_ue_id}"%'
                    AND protocol_fields_json LIKE '%pdn_ipv4%'
                LIMIT 1
            """
            
            from src.query import sql_executor as _se
            try:
                pdn_result = _se.execute_sql(conn, pdn_ip_sql, limit=1)
                if pdn_result.data and len(pdn_result.data) > 0:
                    pdn_ip = pdn_result.data[0].get('pdn_ip_address', 'Not found')
                    result_msg = f"PDN IP Address for UE ID {target_ue_id}: {pdn_ip}"
                    
                    result = QueryResult(
                        query_id=query_request.query_id,
                        data=[{
                            "ue_id": target_ue_id,
                            "pdn_ip_address": pdn_ip,
                            "packet_number": pdn_result.data[0].get('packet_number'),
                            "message_type": pdn_result.data[0].get('message_type')
                        }],
                        columns=["ue_id", "pdn_ip_address", "packet_number", "message_type"],
                        row_count=1,
                        result_type=ResultType.TABLE,
                        summary=result_msg,
                    )
                    query_request.status = QueryStatus.COMPLETED
                    query_request.generated_sql = pdn_ip_sql
                    query_request.execution_time_ms = int((time.time() - start_time) * 1000)
                    return query_request, result
                else:
                    result_msg = f"PDN IP Address not found for UE ID {target_ue_id}. Check if InitialContextSetup message exists for this UE."
                    result = QueryResult(
                        query_id=query_request.query_id,
                        data=[{"message": result_msg}],
                        columns=["message"],
                        row_count=1,
                        result_type=ResultType.TABLE,
                        summary=result_msg,
                    )
                    query_request.status = QueryStatus.COMPLETED
                    query_request.generated_sql = pdn_ip_sql
                    query_request.execution_time_ms = int((time.time() - start_time) * 1000)
                    return query_request, result
            except Exception as pdn_ex:
                logger.error(f"PDN IP query failed: {pdn_ex}")
        
        # Check for UE call flow analysis: "trace ue 92", "call flow for ue 92", "all messages for ue 92"
        ue_callflow_match = re.search(
            r'\b(?:trace|call\s+flow|all\s+messages?|complete\s+flow)\b.*?\b(?:ue\s+id\s+|ue\s+)(\d+)',
            nl_lower_full,
            re.IGNORECASE
        )
        if not ue_callflow_match:
            # Alternative patterns
            ue_callflow_match = re.search(
                r'\b(?:ue\s+id\s+|ue\s+)(\d+)\b.*?\b(?:trace|call\s+flow|all\s+messages?|complete)',
                nl_lower_full,
                re.IGNORECASE
            )
        
        if ue_callflow_match:
            target_ue_id = ue_callflow_match.group(1)
            logger.info(f"Detected UE call flow analysis request for UE ID: {target_ue_id}")
            
            # Check network mode
            if network_mode == "4g":
                error_msg = f"● UE Call Flow Analysis - UE ID: {target_ue_id} (4G LTE)\n\n"
                error_msg += "  ⚠ 4G/LTE UE call flow analysis is not yet implemented.\n"
                error_msg += "  The system currently only supports 5G NGAP call flow tracing.\n\n"
                error_msg += "  4G S1AP call flow analyzer is planned for future implementation."
                
                result = QueryResult(
                    query_id=query_request.query_id,
                    data=[{"message": error_msg}],
                    columns=["message"],
                    row_count=1,
                    result_type=ResultType.TABLE,
                    summary=f"4G UE call flow not yet implemented (UE {target_ue_id})",
                )
                query_request.status = QueryStatus.COMPLETED
                query_request.generated_sql = "N/A - 4G call flow analyzer not available"
                query_request.execution_time_ms = int((time.time() - start_time) * 1000)
                return query_request, result
            else:
                # 5G NGAP call flow analysis
                logger.info(f"Performing comprehensive 5G call flow analysis for UE {target_ue_id}")
                analysis_sql = "SELECT packet_number, message_type, protocol_fields_json, timestamp_iso FROM packets ORDER BY packet_number LIMIT 50000"
                from src.query import sql_executor as _se
                analysis_rows = []
                try:
                    ar = _se.execute_sql(conn, analysis_sql, limit=50000)
                    analysis_rows = ar.data or []
                except Exception as ar_ex:
                    logger.warning(f"Call flow analysis SQL failed: {ar_ex}")
                
                if analysis_rows:
                    from src.analysis.ue_call_flow_analyzer import analyze_ue_call_flow
                    from src.models.query import ResultType as _RT
                    summary_text = analyze_ue_call_flow(analysis_rows, target_ue_id)
                    
                    result = QueryResult(
                        query_id=query_request.query_id,
                        data=[{"analysis": summary_text}],
                        columns=["analysis"],
                        row_count=1,
                        result_type=_RT.TABLE,
                        summary=f"Complete call flow analysis for UE {target_ue_id}",
                    )
                    query_request.status = QueryStatus.COMPLETED
                    query_request.generated_sql = analysis_sql
                    query_request.execution_time_ms = int((time.time() - start_time) * 1000)
                    return query_request, result
                else:
                    logger.warning("Call flow analysis returned no data rows")
        
        # Check for UE-specific release/failure analysis (higher priority)
        ue_specific_match = re.search(r'\b(?:ue\s+id|ran\s+ue\s+id|ngap\s+id|enb\s+id|mme\s+id|ue)\s+(\d+)\b', nl_lower_full)
        if ue_specific_match and ("failure" in nl_lower_full or "release" in nl_lower_full or "call" in nl_lower_full or "explain" in nl_lower_full):
            target_ue_id = ue_specific_match.group(1)
            
            # Check network mode for 4G
            if network_mode == "4g":
                logger.info(f"Detected UE-specific analysis request for UE ID: {target_ue_id} (4G mode)")
                error_msg = f"● Detailed UE Analysis - UE ID: {target_ue_id} (4G LTE)\n\n"
                error_msg += "  ⚠ 4G/LTE UE-specific analysis is not yet implemented.\n"
                error_msg += "  The system currently only supports 5G NGAP UE analysis.\n\n"
                error_msg += "  For 4G LTE PCAPs, please use SQL queries to examine specific UE packets:\n"
                error_msg += f"  Example: SELECT * FROM packets WHERE protocol_fields_json LIKE '%ENB_UE_S1AP_ID\": \"{target_ue_id}\"%'\n\n"
                error_msg += "  4G S1AP UE analyzer is planned for future implementation."
                
                result = QueryResult(
                    query_id=query_request.query_id,
                    data=[{"message": error_msg}],
                    columns=["message"],
                    row_count=1,
                    result_type=ResultType.TABLE,
                    summary=f"4G UE analysis not yet implemented (UE {target_ue_id})",
                )
                query_request.status = QueryStatus.COMPLETED
                query_request.generated_sql = f"N/A - 4G UE analyzer not available"
                query_request.execution_time_ms = int((time.time() - start_time) * 1000)
                return query_request, result
            
            logger.info(f"Detected UE-specific analysis request for UE ID: {target_ue_id} (5G mode)")
            
            # Fetch all packets for detailed UE analysis
            analysis_sql = "SELECT packet_number, message_type, protocol_fields_json FROM packets LIMIT 5000"
            from src.query import sql_executor as _se
            analysis_rows = []
            try:
                ar = _se.execute_sql(conn, analysis_sql, limit=5000)
                analysis_rows = ar.data or []
            except Exception as ar_ex:
                logger.warning(f"Analysis SQL failed: {ar_ex}")
            
            if analysis_rows:
                from src.analysis.ngap_release_analyzer import analyze_ue_detailed
                from src.models.query import ResultType as _RT
                summary_text = analyze_ue_detailed(analysis_rows, target_ue_id)
                
                result = QueryResult(
                    query_id=query_request.query_id,
                    data=[{"analysis": summary_text}],
                    columns=["analysis"],
                    row_count=1,
                    result_type=_RT.TABLE,
                    summary=f"Detailed UE analysis for RAN-UE-NGAP-ID {target_ue_id}",
                )
                query_request.status = QueryStatus.COMPLETED
                query_request.generated_sql = f"N/A - UE-specific analyzer (UE ID: {target_ue_id})"
                query_request.execution_time_ms = int((time.time() - start_time) * 1000)
                return query_request, result
            else:
                logger.warning("No rows available for UE-specific analysis")
        
        # General release/failure analysis (applies to all UEs)
        elif re.search(r"\b(explain|show|summarize)\b.*\bues?\b.*\breleased", nl_lower_full) or ("reason for failure" in nl_lower_full):
            # Check network mode to determine which analyzer to use
            if network_mode == "4g":
                logger.info("Detected release analysis intent for 4G LTE; 4G S1AP analyzer not yet implemented")
                # For now, inform user that 4G release analysis is not yet available
                error_msg = "● 4G LTE Release Analysis\n\n"
                error_msg += "  ⚠ 4G/LTE release analysis is not yet implemented.\n"
                error_msg += "  The system currently only supports 5G NGAP release analysis.\n\n"
                error_msg += "  For 4G LTE PCAPs, please use SQL queries to examine S1AP UE Context Release messages:\n"
                error_msg += "  Example: SELECT * FROM packets WHERE message_type LIKE '%UEContextRelease%'\n\n"
                error_msg += "  4G S1AP release analyzer is planned for future implementation."
                
                result = QueryResult(
                    query_id=query_request.query_id,
                    data=[{"message": error_msg}],
                    columns=["message"],
                    row_count=1,
                    result_type=ResultType.TABLE,
                    summary="4G release analysis not yet implemented",
                )
                query_request.status = QueryStatus.COMPLETED
                query_request.generated_sql = "N/A - 4G analyzer not available"
                query_request.execution_time_ms = int((time.time() - start_time) * 1000)
                return query_request, result
            else:
                logger.info("Detected release analysis intent; performing 5G NGAP release/failure analysis")
                # Fetch all packets that contain NGAP UE anchor identifiers or release indications generically.
                # We do not hard-code RAN IDs; we scan all rows.
                analysis_sql = "SELECT packet_number, message_type, protocol_fields_json FROM packets LIMIT 5000"
                from src.query import sql_executor as _se
                analysis_rows = []
                try:
                    ar = _se.execute_sql(conn, analysis_sql, limit=5000)
                    analysis_rows = ar.data or []
                except Exception as ar_ex:
                    logger.warning(f"Analysis SQL failed: {ar_ex}")
                
                if analysis_rows:
                    from src.analysis.ngap_release_analyzer import analyze_packets
                    from src.analysis.llm_release_analyzer import generate_llm_analysis
                    from src.models.query import ResultType as _RT
                    
                    # Extract release data using deterministic parser
                    analysis_result = analyze_packets(analysis_rows)
                    
                    # Convert to structured format for LLM
                    summary_dict = analysis_result.to_summary_dict()
                    release_data = {
                        'total_releases': summary_dict['release_stats']['total_releases'],
                        'release_events': [
                            {
                                'cause_raw': ev.cause_raw,
                                'cause_category': ev.cause_category,
                                'normal': ev.normal,
                            }
                            for ev in analysis_result.release_events
                        ],
                        'normal_count': summary_dict['release_stats']['normal_count'],
                        'abnormal_count': summary_dict['release_stats']['abnormal_count'],
                    }
                    
                    ue_data = {
                        'initial_ue_messages': summary_dict['initial_ue_messages'],
                        'ran_ids': summary_dict['ue_counts']['ran_ids'],
                        'amf_ids': sorted(list(analysis_result.unique_amf_ids)),  # Get from raw object
                        'ran_total': summary_dict['ue_counts']['ran_total'],
                        'amf_total': summary_dict['ue_counts']['amf_total'],
                    }
                    
                    # Generate LLM-powered analysis
                    logger.info("Generating LLM-powered release cause analysis...")
                    summary_text = generate_llm_analysis(release_data, ue_data)
                    
                    # Return result immediately
                    result = QueryResult(
                        query_id=query_request.query_id,
                        data=[{"summary": summary_text}],
                        columns=["summary"],
                        row_count=1,
                        result_type=_RT.TABLE,
                        summary="LLM-powered NGAP release/failure analysis",
                    )
                    query_request.status = QueryStatus.COMPLETED
                    query_request.generated_sql = "N/A - LLM-powered NGAP release analyzer"
                    query_request.execution_time_ms = int((time.time() - start_time) * 1000)
                    return query_request, result
                else:
                    logger.warning("No rows available for NGAP release analysis")
        
        # Handover failure analysis (applies to all UEs)
        elif re.search(r"\b(which|what|show|list|identify)\b.*\bues?\b.*(handover|ho)\s+(failure|fail)", nl_lower_full, re.IGNORECASE) or \
             re.search(r"\b(handover|ho)\s+(failure|fail).*\bues?\b", nl_lower_full, re.IGNORECASE):
            # Check network mode
            if network_mode == "4g":
                logger.info("Detected handover failure analysis for 4G LTE; 4G S1AP analyzer not yet implemented")
                error_msg = "● 4G LTE Handover Failure Analysis\n\n"
                error_msg += "  ⚠ 4G/LTE handover analysis is not yet implemented.\n"
                error_msg += "  The system currently only supports 5G NGAP handover analysis.\n\n"
                error_msg += "  4G S1AP handover analyzer is planned for future implementation."
                
                result = QueryResult(
                    query_id=query_request.query_id,
                    data=[{"message": error_msg}],
                    columns=["message"],
                    row_count=1,
                    result_type=ResultType.TABLE,
                    summary="4G handover analysis not yet implemented",
                )
                query_request.status = QueryStatus.COMPLETED
                query_request.generated_sql = "N/A - 4G HO analyzer not available"
                query_request.execution_time_ms = int((time.time() - start_time) * 1000)
                return query_request, result
            else:
                logger.info("Detected handover failure analysis intent; performing 5G NGAP handover analysis")
                analysis_sql = "SELECT packet_number, message_type, protocol_fields_json FROM packets LIMIT 5000"
                from src.query import sql_executor as _se
                analysis_rows = []
                try:
                    ar = _se.execute_sql(conn, analysis_sql, limit=5000)
                    analysis_rows = ar.data or []
                except Exception as ar_ex:
                    logger.warning(f"Handover analysis SQL failed: {ar_ex}")
                
                if analysis_rows:
                    from src.analysis.ngap_release_analyzer import analyze_handover_failures
                    from src.models.query import ResultType as _RT
                    summary_text = analyze_handover_failures(analysis_rows)
                    
                    result = QueryResult(
                        query_id=query_request.query_id,
                        data=[{"summary": summary_text}],
                        columns=["summary"],
                        row_count=1,
                        result_type=_RT.TABLE,
                        summary="NGAP handover failure analysis generated",
                    )
                    query_request.status = QueryStatus.COMPLETED
                    query_request.generated_sql = "N/A - NGAP handover analyzer"
                    query_request.execution_time_ms = int((time.time() - start_time) * 1000)
                    return query_request, result
                else:
                    logger.warning("No rows available for handover analysis")
        
        # Build schema catalog by analyzing the dataset
        from src.query.schema_catalog import SchemaCatalog
        schema_catalog = SchemaCatalog()
        schema_catalog.analyze_dataset(conn, limit=50)
        
        # --- UE ID anchor detection (enb vs mme) ---
        def _parse_ue_anchor(q: str):
            """Return (anchor_field, id_value, origin) based on user wording (LTE + 5G).

            Order of evaluation (most specific first):
              1. 5G explicit: 'ran ue id <n>' / 'ngap ue id <n>' / 'ran id <n>' / 'ngap id <n>' -> ngap.RAN_UE_NGAP_ID
              2. LTE explicit: 'mme ue id <n>' -> s1ap.s1ap.MME_UE_S1AP_ID
              3. LTE explicit: 'enb ue id <n>' or 'enb id <n>' -> s1ap.s1ap.ENB_UE_S1AP_ID
              4. Generic 'ue id <n>':
                   - If network_mode="5g" or dataset appears 5G (heuristic: ngap present in schema) choose ngap.RAN_UE_NGAP_ID
                   - Else default to ENB (existing behavior)
            """
            ql = q.lower()
            import re as _re

            # Determine if we're in 5G mode
            has_5g = False
            if network_mode == "5g":
                has_5g = True
                logger.info("5G mode explicitly set via CLI flag")
            elif network_mode == "4g":
                has_5g = False
                logger.info("4G mode explicitly set via CLI flag")
            else:
                # Auto-detect: check schema_catalog for ngap presence
                try:
                    if any('ngap' in f.lower() for fields in schema_catalog.message_field_map.values() for f in fields):
                        has_5g = True
                        logger.info("Auto-detected 5G protocols in dataset")
                except Exception:
                    pass

            # 5G explicit patterns
            ran_match = _re.search(r"(?:ran|ngap)\s*(?:ue\s*)?id\s*(\d+)", ql)
            if ran_match:
                return ("ngap.RAN_UE_NGAP_ID", ran_match.group(1), "ran")

            # LTE explicit patterns
            mme_match = _re.search(r"mme\s*(?:ue\s*)?id\s*(\d+)", ql)
            if mme_match:
                return ("s1ap.s1ap.MME_UE_S1AP_ID", mme_match.group(1), "mme")
            enb_match = _re.search(r"enb\s*(?:ue\s*)?id\s*(\d+)", ql)
            if enb_match:
                return ("s1ap.s1ap.ENB_UE_S1AP_ID", enb_match.group(1), "enb")

            # Generic ambiguous pattern
            generic = _re.search(r"(?<!mme\s)(?<!enb\s)(?<!ran\s)(?<!ngap\s)ue\s*id\s*(\d+)", ql)
            if generic:
                if has_5g:
                    return ("ngap.RAN_UE_NGAP_ID", generic.group(1), "default_ran")
                return ("s1ap.s1ap.ENB_UE_S1AP_ID", generic.group(1), "default_enb")
            return (None, None, None)

        anchor_field, anchor_value, anchor_origin = _parse_ue_anchor(query_text)
        if anchor_field and anchor_value:
            logger.info(f"UE anchor selected: {anchor_field}={anchor_value} (origin={anchor_origin})")

        # Pre-process query to add hints for message types (after anchor parsing)
        # Use LLM to resolve message type mentions to actual values in the dataset
        processed_query = query_text
        if anchor_field and anchor_value and f"{anchor_value}" not in processed_query:
            # Append an explicit clarifying hint for LLM while keeping original text
            processed_query = f"{processed_query} [Anchor: {anchor_field}={anchor_value}]"
        message_type_hint = ""
        matched_msg_type = None  # Will store the resolved message type
        
        # Check if query mentions a potential message type
        if any(word in query_text.lower() for word in ["message", "msg", "request", "response", "setup", "release", "attach", "detach", "handover"]):
            # Get actual message types from dataset
            try:
                actual_msg_types = conn.execute("SELECT DISTINCT message_type FROM packets WHERE message_type IS NOT NULL LIMIT 50").fetchall()
                msg_types_list = [row[0] for row in actual_msg_types if row[0]]
                
                if msg_types_list:
                    # Ask LLM to match user's message type mention to actual dataset values
                    llm_msg_prompt = f"""You are a 3GPP protocol expert. The user query mentions a message type.
User query: "{query_text}"

Available message_type values in the dataset:
{', '.join(msg_types_list)}

Task: Identify which message_type the user is referring to. Consider:
- User may abbreviate (e.g., "initialcontextsetupresponse" could match "InitialContextSetup")
- User may add "Request" or "Response" suffix that might not be in the actual value
- Case variations (user: lowercase, data: PascalCase)
- 3GPP standard names vs dataset encoding

Respond with ONLY the exact message_type value from the list above that matches, or "NONE" if no match.
Example responses: "InitialContextSetup" or "NONE"
"""
                    llm_response = model.generate_content(llm_msg_prompt)
                    matched_msg_type = llm_response.text.strip().strip('"\'')
                    
                    if matched_msg_type and matched_msg_type != "NONE" and matched_msg_type in msg_types_list:
                        message_type_hint = f"\n**MESSAGE TYPE MATCH**: User query refers to message_type = '{matched_msg_type}'\n**CRITICAL**: You MUST use `message_type = '{matched_msg_type}'` (exact case) in your WHERE clause!"
                        # Also modify the query itself for clarity
                        processed_query = query_text + f" [Message type resolved to: {matched_msg_type}]"
                        logger.info(f"LLM matched message type: '{matched_msg_type}'")
            except Exception as e:
                logger.warning(f"Message type LLM resolution failed: {e}")
        
        # Fallback to old mapper if LLM didn't match
        if not message_type_hint:
            processed_query = message_type_mapper.preprocess_query_for_message_types(query_text)
            if processed_query != query_text:
                logger.info(f"Query pre-processed with message type hint: {processed_query}")

        # Detect if this is a SIB query (affects LLM prompt)
        is_sib_query = _detect_sib_query(processed_query)
        if is_sib_query:
            logger.info("Detected SIB query - will instruct LLM to avoid UE ID filters")

        # Extract potential field names from query using LLM as 3GPP expert
        # This handles cases where user types "hnbname" and we need to know it means "hnb-name" or "hnb_Name"
        field_patterns = []
        field_variations_hint = ""
        
        # First try simple pattern extraction for obvious field names
        explicit_fields = re.findall(
            r'\b([a-zA-Z0-9]+(?:[-_.]+[a-zA-Z0-9]+)+)\b', 
            processed_query
        )
        
        # Also check for single words that might be field names (like "hnbname", "phycellid")
        potential_fields = re.findall(
            r'what\s+is\s+(?:the\s+)?([a-zA-Z][a-zA-Z0-9]+)(?:\s+(?:value|timer|parameter|field|in|from))?', 
            processed_query,
            re.IGNORECASE
        )
        
        # Combine and filter
        candidate_fields = list(set(explicit_fields + potential_fields))
        # Remove generic words
        candidate_fields = [f for f in candidate_fields if f.lower() not in 
                           {"what", "value", "timer", "parameter", "field", "from", "show", "find", "get", "the"}]
        
        if candidate_fields:
            # Use LLM to interpret field names as 3GPP expert
            llm_field_prompt = f"""You are a 3GPP LTE/NAS protocol expert. The user mentioned these potential field/parameter names in their query:
{', '.join(candidate_fields)}

Context: Query is "{processed_query}"

For each field name above, provide the CANONICAL 3GPP specification name and common variations found in PCAP data.
Consider:
- User may concatenate words without separators (e.g., "hnbname" → "hnb-name" or "hnb_Name")
- Common separators: hyphen, underscore, camelCase, PascalCase
- 3GPP standard names from specifications (e.g., q-RxLevMin, physCellId, hnb-Name)

Format your response as a simple list:
<field>: <canonical_name>, <variation1>, <variation2>, ...

Example:
hnbname: hnb-name, hnb_Name, hnbName, HNB_NAME, hnb_name
phycellid: physCellId, phyCellId, physcellid, PHYSCELLID, phys_cell_id
"""
            
            try:
                llm_response = model.generate_content(llm_field_prompt)
                llm_text = llm_response.text.strip()
                logger.info(f"LLM field interpretation:\n{llm_text}")
                
                # Parse LLM response
                all_variations = []
                all_sql_conditions = []
                for line in llm_text.split('\n'):
                    line = line.strip()
                    if ':' in line and not line.startswith('#'):
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            original = parts[0].strip()
                            variations_str = parts[1].strip()
                            variations = [v.strip() for v in variations_str.split(',') if v.strip()]
                            if variations:
                                field_patterns.append(original)
                                all_variations.append(f"{original} → {', '.join(variations[:8])}")
                                like_conditions = [f"LIKE '%{v}%'" for v in variations[:8]]
                                all_sql_conditions.append(f"({' OR '.join(like_conditions)})")

                if all_variations:
                    field_variations_hint = (
                        f"\n**FIELD NAME VARIATIONS TO SEARCH**: Based on 3GPP specifications and common PCAP encodings:\n" +
                        '\n'.join(f"  - {v}" for v in all_variations) +
                        f"\n\n**CRITICAL**: When searching for these fields, you MUST use OR with ALL variations:\n"
                        f"Example for '{field_patterns[0]}':\n"
                        f"  protocol_fields_json {all_sql_conditions[0]}"
                    )
                    if message_type_hint:
                        field_variations_hint += message_type_hint
                    if matched_msg_type and matched_msg_type != "NONE":
                        catalog_hint = schema_catalog.generate_llm_hint(matched_msg_type)
                        if catalog_hint:
                            field_variations_hint += catalog_hint
            except Exception as e:
                logger.warning(f"LLM field interpretation failed: {e}")

        # Prepare dynamic schema info for LLM reasoning
        try:
            schema_info = _get_schema_info(conn)
        except Exception as e:
            logger.warning(f"Could not build schema_info summary: {e}")
            schema_info = ""

        # (Temporarily disabled) correlation-based UE ID enrichment variables
        correlation_hint = None
        correlated_ids = None
        ue_id = None

        # Use reasoning engine for better SQL generation
        logger.info(f"🧠 Initializing LLM client ({config.LLM_PROVIDER})...")
        llm_client = initialize_llm_client()
        
        generated_sql, reasoning_metadata = reasoning_engine.generate_sql_with_reasoning(
            llm_client=llm_client,
            natural_language_query=processed_query,
            schema_info=schema_info,
            conn=conn,
            max_retries=2,
            correlation_hint=correlation_hint,
            field_variations_hint=field_variations_hint,
            network_mode=network_mode
        )
        
        # Log reasoning metadata
        if reasoning_metadata.get("attempts"):
            logger.info(f"SQL generation attempts: {len(reasoning_metadata['attempts'])}")
            for i, attempt in enumerate(reasoning_metadata['attempts'], 1):
                logger.debug(f"  Attempt {i}: {attempt.get('row_count', 'N/A')} rows, "
                           f"success={attempt.get('success', 'N/A')}")

        # POST-PROCESS: Ensure anchor UE ID constraint present if user specified (or defaulted) and missing
        if anchor_field and anchor_value:
            # Build anchor variants based on the detected anchor field
            # For 5G NGAP: multiple JSON key namespace variants
            # For 4G S1AP: standard s1ap.s1ap.* fields only (NO PROPRIETARY .pw. FIELDS)
            if anchor_field == "ngap.RAN_UE_NGAP_ID":
                anchor_variants = [
                    f'"ngap.RAN_UE_NGAP_ID": "{anchor_value}"',
                    f'"ngap.ngap.RAN_UE_NGAP_ID": "{anchor_value}"',
                    f'"RAN_UE_NGAP_ID": "{anchor_value}"'
                ]
                logger.info(f"Using 5G NGAP anchor variants for UE ID {anchor_value}")
            elif anchor_field == "s1ap.s1ap.ENB_UE_S1AP_ID":
                anchor_variants = [f'"s1ap.s1ap.ENB_UE_S1AP_ID": "{anchor_value}"']
                logger.info(f"Using 4G S1AP ENB anchor for UE ID {anchor_value}")
            elif anchor_field == "s1ap.s1ap.MME_UE_S1AP_ID":
                anchor_variants = [f'"s1ap.s1ap.MME_UE_S1AP_ID": "{anchor_value}"']
                logger.info(f"Using 4G S1AP MME anchor for UE ID {anchor_value}")
            else:
                anchor_variants = [f'"{anchor_field}": "{anchor_value}"']

            # Skip injection if any variant already present (case-insensitive)
            lower_sql = generated_sql.lower()
            if not any(v.lower() in lower_sql for v in anchor_variants):
                import re as _re
                limit_match = _re.search(r"LIMIT\s+\d+", generated_sql, flags=_re.IGNORECASE)
                # Build OR group of all variants
                or_group = ' OR '.join([f"LOWER(protocol_fields_json) LIKE LOWER('%{v}%')" for v in anchor_variants])
                anchor_condition = f"({or_group})"
                if limit_match:
                    prefix = generated_sql[:limit_match.start()].rstrip().rstrip(';')
                    suffix = generated_sql[limit_match.start():]
                    if re.search(r"WHERE", prefix, flags=re.IGNORECASE):
                        prefix += f" AND {anchor_condition}"
                    else:
                        prefix += f" WHERE {anchor_condition}"
                    generated_sql = prefix + " " + suffix
                else:
                    if re.search(r"WHERE", generated_sql, flags=_re.IGNORECASE):
                        generated_sql = generated_sql.rstrip().rstrip(';') + f" AND {anchor_condition}"
                    else:
                        generated_sql = generated_sql.rstrip().rstrip(';') + f" WHERE {anchor_condition}"
                logger.info(f"Injected anchor UE ID filter (variants): {anchor_field}={anchor_value}")
            else:
                logger.debug("Anchor filter already present in generated SQL (one of the variants detected)")

        # (Correlation-based UE ID post-processing removed for now; will be reintroduced after refactor)

        # POST-PROCESS: Fix common field name character patterns (hyphens vs underscores)
        # 3GPP fields often have hyphens in user queries but underscores in PDML
        # Instead of hard-coding specific fields, detect candidate field tokens from the original
        # natural language query that look like 3GPP RRC/NAS parameter names and expand any single
        # LIKE '%token%' pattern into an OR group of all common variations (underscore, hyphen,
        # camelCase, PascalCase, space-separated etc). This allows q-RxLevMin, qRxLevMin, q RxLevMin
        # to all map to the canonical stored form q_RxLevMin without hard-coding.
        try:
            from src.query.query_helpers import _generate_field_name_variations_internal as _gen_var
        except Exception:
            _gen_var = None

        # Extract tokens: sequences containing letters/numbers plus optional internal separators
        # We focus on tokens that contain at least one uppercase letter after a separator or a hyphen/underscore.
        candidate_tokens = set()
        # --- Multi-word token handling (e.g. "PDU address info", "UE Aggregate Maximum Bit Rate") ---
        # We proactively capture short phrases (2-4 words) that look like parameter names so that if the LLM
        # includes only ONE stylistic variant in SQL we can still expand it (similar to single-token logic).
        # Examples:
        #   "PDU address info" -> pduaddressinfo, pdu_address_info, pdu-address-info, PduAddressInfo
        #   "UE Aggregate Maximum Bit Rate" -> ueaggregatemaximumbitrate, ue_Aggregate_Maximum_Bit_Rate, etc.
        # These variants are only added to candidate_tokens (and later expanded) if at least one collapsed
        # form already appears in the generated SQL OR the phrase contains a high-signal keyword; this avoids
        # excessive LIKE explosion on generic narrative text.
        multiword_keywords = {"pdu", "address", "bit", "rate", "aggregate", "maximum", "amf", "ue", "identity", "name", "plmn"}
        stop_words = {"the", "for", "of", "in", "to", "a", "an", "is", "what", "value", "find", "show", "get"}
        phrase_pattern = re.compile(r"\b([A-Za-z][A-Za-z0-9]+(?:\s+[A-Za-z][A-Za-z0-9]+){1,3})\b")
        raw_phrases = phrase_pattern.findall(processed_query)
        for phrase in raw_phrases:
            words = phrase.split()
            # Require at least one keyword and at least one non-stop word besides keywords
            lowered_words = [w.lower() for w in words]
            if all(w in stop_words for w in lowered_words):
                continue
            if not any(w in multiword_keywords for w in lowered_words):
                continue
            # Build collapsed variants
            collapsed = ''.join(lowered_words)
            underscored = '_'.join(lowered_words)
            hyphened = '-'.join(lowered_words)
            pascal = ''.join(w.capitalize() for w in lowered_words)
            camel = lowered_words[0] + ''.join(w.capitalize() for w in lowered_words[1:])
            variants = {collapsed, underscored, hyphened, pascal, camel}
            # Only keep if ANY variant appears (case-insensitive) in generated_sql OR phrase has a strong keyword combo
            strong = any(k in {"pdu", "aggregate", "bit", "rate"} for k in lowered_words)
            if strong or any(v.lower() in generated_sql.lower() for v in variants):
                candidate_tokens.update(variants)
                logger.debug(f"Multi-word phrase detected -> variants added: {phrase} -> {sorted(list(variants))[:6]}...")
        # Join space-separated alphanumeric fragments that look like they form a single 3GPP parameter
        # Example: "q RxLevMin" -> "qRxLevMin" so that variation expansion can unify them
        space_joined = re.sub(r"\b([A-Za-z])\s+([A-Z][A-Za-z0-9]+)\b", lambda m: m.group(1) + m.group(2), processed_query)
        for raw_token in re.findall(r"[A-Za-z][A-Za-z0-9_\-]{2,}", space_joined):
            # Heuristics: skip very generic words
            lower = raw_token.lower()
            if lower in {"what", "value", "timer", "in", "sib", "show", "find", "get", "the", "rx", "ue"}:
                continue
            # Must have at least one of: hyphen, underscore, internal capital after first char, space (handled earlier)
            if ("-" in raw_token or "_" in raw_token or any(c.isupper() for c in raw_token[1:])):
                candidate_tokens.add(raw_token)

        # For SIB queries we also want to ensure sibX_element pattern gets added; detect sib<digit>
        sib_match = re.search(r"sib\s*(\d+)", processed_query, re.IGNORECASE)
        sib_element_clause = None
        if sib_match:
            sib_num = sib_match.group(1)
            # canonical container field ends with sib<num>_element (observed in dataset as sib3_element etc.)
            sib_element_clause = f"protocol_fields_json LIKE '%sib{sib_num}_element%'"

        # Build variation replacement map for single LIKE patterns.
        # IMPORTANT:
        # We intentionally replace the entire literal pattern "protocol_fields_json LIKE '%token%'" with an OR group
        # of all stylistic variants WITHOUT keeping the original leading "protocol_fields_json LIKE" because the OR
        # group itself is a boolean expression composed of fully qualified LIKE clauses. Keeping the original prefix
        # leads to invalid SQL: protocol_fields_json LIKE (<boolean expression>). This was the source of the earlier
        # syntax error seen as: "protocol_fields_json LIKE LOWER(protocol_fields_json) LIKE ...".
        # Heuristic for candidate tokens:
        #   - token length >= 3
        #   - presence of hyphen/underscore OR internal uppercase (camelCase/PascalCase)
        # This avoids exploding common short words while still capturing structured parameter names (e.g. qRxLevMin).
        # Variations are generated via _generate_field_name_variations_internal (non-hardcoded + reusable) and then
        # deduplicated + length-capped for safety. Case-insensitivity is applied later by a separate pass so we do
        # not lowercase tokens prematurely here.
        if _gen_var and candidate_tokens:
            def _expand_like(match: re.Match) -> str:
                like_inner = match.group(1)
                token = like_inner.strip('%')
                cmp_token = token.replace(' ', '').lower()
                matched = None
                for cand in candidate_tokens:
                    if cmp_token == cand.replace(' ', '').lower():
                        matched = cand
                        break
                if not matched:
                    return match.group(0)  # unchanged (leave original pattern intact)
                if _gen_var:
                    variations = _gen_var(matched)
                else:
                    return match.group(0)
                variations = sorted({v for v in variations if len(v) <= 40})
                if not variations:
                    return match.group(0)
                like_clauses = [f"LOWER(protocol_fields_json) LIKE LOWER('%{v}%')" for v in variations]
                or_group = "(" + " OR ".join(like_clauses) + ")"
                logger.info(f"Expanded field token '{matched}' into {len(variations)} LIKE variations")
                return or_group

            # Pattern to catch LIKE '%token%' where token is alphanum with separators.
            # Replace only patterns on protocol_fields_json to avoid touching other columns inadvertently.
            generated_sql = re.sub(
                r"protocol_fields_json\s+LIKE\s+'%(.*?)%'",
                lambda m: _expand_like(m),
                generated_sql,
                flags=re.IGNORECASE,
            )

            # If SIB element clause detected and not already present, append it safely.
            if sib_element_clause and sib_element_clause not in generated_sql:
                # Insert before LIMIT if present, else append.
                limit_match = re.search(r"\bLIMIT\b", generated_sql, re.IGNORECASE)
                if limit_match:
                    # Split at LIMIT and inject additional AND
                    parts = re.split(r"\bLIMIT\b", generated_sql, flags=re.IGNORECASE)
                    generated_sql = parts[0].rstrip().rstrip(';') + f" AND {sib_element_clause} LIMIT" + parts[1]
                else:
                    # Append as additional AND condition
                    generated_sql = generated_sql.rstrip().rstrip(';') + f" AND {sib_element_clause}"
                logger.info(f"Added SIB element clause: {sib_element_clause}")

        # No hard-coded replacements performed above; legacy normalization list removed.
        
        # Track SQL changes for logging
        original_sql = generated_sql
        
        # POST-PROCESS: Fix common RSRP/RSRQ field name mistakes
        if 'rsrp' in processed_query.lower() or 'rsrq' in processed_query.lower():
            logger.info("Post-processing SQL to fix RSRP/RSRQ field names...")
            
            # Use regex for case-insensitive replacement of wrong field patterns
            # Replace any field path containing "rsrp" or "rsrq" with just "rsrpResult" or "rsrqResult"
            
            # Match patterns like: rlc_lte.lte-rrc.RSRP, rlc_lte.rlc-lte.rsrp, measResults.measQuality.rsrp, etc.
            # Replace with just: rsrpResult or rsrqResult
            rsrp_pattern = r'[a-zA-Z0-9_\-\.]+\.rsrp[a-zA-Z0-9_\-\.]*'
            rsrq_pattern = r'[a-zA-Z0-9_\-\.]+\.rsrq[a-zA-Z0-9_\-\.]*'
            generated_sql = re.sub(rsrp_pattern, 'rsrpResult', generated_sql, flags=re.IGNORECASE)
            generated_sql = re.sub(rsrq_pattern, 'rsrqResult', generated_sql, flags=re.IGNORECASE)
            
            # Fix common message_type mistakes for measurement reports
            # LLM generates various formats:
            # - 'Measurement Report' (title case with space)
            # - 'MeasurementReport' (PascalCase without space)
            # Actual value is: 'measurementReport' (camelCase)
            generated_sql = generated_sql.replace("'Measurement Report'", "'measurementReport'")
            generated_sql = generated_sql.replace('"Measurement Report"', "'measurementReport'")
            generated_sql = generated_sql.replace("'MeasurementReport'", "'measurementReport'")
            generated_sql = generated_sql.replace('"MeasurementReport"', "'measurementReport'")
            
            # Also fix LIKE patterns with wrong case
            generated_sql = generated_sql.replace("'%MeasurementReport%'", "'%measurementReport%'")
            generated_sql = generated_sql.replace('"%MeasurementReport%"', "'%measurementReport%'")
            
            if "'measurementReport'" in generated_sql or "'%measurementReport%'" in generated_sql:
                logger.info("Fixed message_type value to 'measurementReport'")
            
            # Fix overly specific JSON search patterns that won't match nested fields
            # LLM sometimes generates: LIKE '%"rsrpResult":%' expecting direct value
            # But actual JSON has: "rlc_lte.lte-rrc.rsrpResult": "36"
            # Should be: LIKE '%rsrpResult%' to match any field containing rsrpResult
            generated_sql = re.sub(r"LIKE\s+'%\"rsrpResult\":\s*[^']*%'", "LIKE '%rsrpResult%'", generated_sql, flags=re.IGNORECASE)
            generated_sql = re.sub(r"LIKE\s+'%\"rsrqResult\":\s*[^']*%'", "LIKE '%rsrqResult%'", generated_sql, flags=re.IGNORECASE)
        
        # POST-PROCESS: Fix overly specific JSON key patterns for any field
        # LLM generates: LIKE '%"field_name":%' or LIKE '%"prefix.field_name": %'
        # Should be: LIKE '%field_name%' to match any prefixed key
        # Pattern: Replace '%"anything.field_name": %' or '%"field_name":%' with '%field_name%'
        specific_pattern = re.compile(r"LIKE\s+'%\"[^\"]*\.([^\"]+)\":\s*[^']*%'")
        matches = specific_pattern.findall(generated_sql)
        for field_name in set(matches):
            # Replace overly specific pattern with broader one
            generated_sql = specific_pattern.sub(f"LIKE '%{field_name}%'", generated_sql, count=1)
            logger.info(f"Broadened LIKE pattern to match any prefix: %{field_name}%")
        
        # Also handle patterns without prefixes: '%"field_name":%'
        specific_no_prefix = re.compile(r"LIKE\s+'%\"([^\"\.]+)\":\s*[^']*%'")
        matches_no_prefix = specific_no_prefix.findall(generated_sql)
        for field_name in set(matches_no_prefix):
            if field_name not in ['packet_number', 'timestamp', 'protocol']:  # Skip metadata fields
                generated_sql = specific_no_prefix.sub(f"LIKE '%{field_name}%'", generated_sql, count=1)
                logger.info(f"Broadened LIKE pattern (no prefix): %{field_name}%")
        
        # Handle unquoted nested paths: LIKE '%prefix.prefix.field%'
        # Extract rightmost component after last dot
        unquoted_nested = re.compile(r"LIKE\s+'%([a-zA-Z0-9_\-]+\.){2,}([a-zA-Z0-9_\-]+)%'")
        matches_nested = unquoted_nested.findall(generated_sql)
        for match_tuple in matches_nested:
            # match_tuple is (prefix_with_dot, final_field_name)
            final_field = match_tuple[-1]  # Get last element (field name)
            if final_field not in ['packet_number', 'timestamp', 'protocol', 'ueid']:
                generated_sql = unquoted_nested.sub(f"LIKE '%{final_field}%'", generated_sql, count=1)
                logger.info(f"Broadened unquoted nested pattern: %{final_field}%")
        
        if generated_sql != original_sql:
            logger.info(f"Applied post-processing field pattern fixes")

        # POST-PROCESS: Make all field name searches case-insensitive
        # Convert: protocol_fields_json LIKE '%fieldname%'
        # To: LOWER(protocol_fields_json) LIKE LOWER('%fieldname%')
        # This handles cases where user says "cellindex" but data has "cellIndex"
        # Support optional table alias before protocol_fields_json (e.g., T1.protocol_fields_json)
        case_insensitive_pattern = re.compile(r"((?:[A-Za-z_][A-Za-z0-9_]*\.)?)protocol_fields_json\s+(LIKE|NOT LIKE)\s+('\%[^']+\%')", re.IGNORECASE)
        def _ci_sub(match: re.Match) -> str:
            alias = match.group(1)  # includes trailing dot if present
            op = match.group(2)
            like_pattern = match.group(3)
            if alias:  # Preserve alias inside LOWER()
                return f"LOWER({alias}protocol_fields_json) {op} LOWER({like_pattern})"
            return f"LOWER(protocol_fields_json) {op} LOWER({like_pattern})"
        if case_insensitive_pattern.search(generated_sql):
            generated_sql = case_insensitive_pattern.sub(_ci_sub, generated_sql)
            # Clean any accidental alias.function pattern like T1.LOWER( that could remain from previous runs
            generated_sql = re.sub(r"[A-Za-z_][A-Za-z0-9_]*\.LOWER\(", "LOWER(", generated_sql)
            # Clean malformed alias.(LOWER(...) patterns from LLM mistakes
            generated_sql = re.sub(r"[A-Za-z_][A-Za-z0-9_]*\.\(LOWER\(", "(LOWER(", generated_sql)
            logger.info("Made field searches case-insensitive using LOWER() (alias-aware)")

        # SECOND PASS: Field variation expansion for case-insensitive patterns that were not expanded earlier.
        # If the initial pass missed a token (e.g. space-separated user input produced only lowercase pattern),
        # expand single occurrences of LOWER(protocol_fields_json) LIKE LOWER('%token%') into an OR group.
        if _gen_var and candidate_tokens:
            def _expand_ci_like(match: re.Match) -> str:
                token = match.group(1)
                cmp_token = token.replace(' ', '').lower()
                # Avoid re-expanding if OR group for this token already present
                if re.search(rf"LOWER\(protocol_fields_json\)\s+LIKE\s+LOWER\('%{re.escape(cmp_token)}%'\).+OR", generated_sql, re.IGNORECASE):
                    return match.group(0)
                matched = None
                for cand in candidate_tokens:
                    if cmp_token == cand.replace(' ', '').lower():
                        matched = cand
                        break
                if not matched:
                    return match.group(0)
                if _gen_var:
                    variations = _gen_var(matched)
                else:
                    return match.group(0)
                variations = sorted({v for v in variations if len(v) <= 40})
                if not variations:
                    return match.group(0)
                clauses = [f"LOWER(protocol_fields_json) LIKE LOWER('%{v}%')" for v in variations]
                or_group = "(" + " OR ".join(clauses) + ")"
                logger.info(f"Second-pass expanded token '{matched}' into {len(variations)} LIKE variations")
                return or_group
            generated_sql = re.sub(r"LOWER\(protocol_fields_json\)\s+LIKE\s+LOWER\('%(.*?)%'\)", _expand_ci_like, generated_sql, flags=re.IGNORECASE)
            # Enforcement: if we expanded a CamelCase token group but underscore/hyphen single-segment variants
            # (e.g., q_RxLevMin / q-RxLevMin) are missing, inject them to guarantee matching canonical stored key.
            for cand in candidate_tokens:
                if re.search(r"[a-z][A-Z]", cand) and cand.lower() in generated_sql.lower():
                    single_us = re.sub(r"([a-z])([A-Z])", r"\1_\2", cand, count=1)
                    single_hy = single_us.replace('_', '-')
                    # Only inject if not already present
                    def _inject_variant(sql: str, variant: str) -> str:
                        if variant.lower() in sql.lower():
                            return sql
                        # Find OR group containing original token
                        pattern = re.compile(r"\(([^()]*%" + re.escape(cand) + r"%[^()]*)\)")
                        m = pattern.search(sql)
                        if not m:
                            return sql
                        group = m.group(1)
                        insertion = f" OR LOWER(protocol_fields_json) LIKE LOWER('%{variant}%')"
                        new_group = group + insertion
                        return sql[:m.start(1)] + new_group + sql[m.end(1):]
                    generated_sql = _inject_variant(generated_sql, single_us)
                    generated_sql = _inject_variant(generated_sql, single_hy)

            # Fallback: expand solitary lowercase pattern not already part of an OR group.
            def _expand_lonely_lower(match: re.Match) -> str:
                token = match.group(1)
                cmp_token = token.lower()
                # skip if already part of an OR group
                if ' OR ' in match.group(0):
                    return match.group(0)
                matched = None
                for cand in candidate_tokens:
                    if cmp_token == cand.replace(' ', '').lower():
                        matched = cand
                        break
                if not matched:
                    return match.group(0)
                if _gen_var:
                    variations = _gen_var(matched)
                else:
                    return match.group(0)
                variations = sorted({v for v in variations if len(v) <= 40})
                like_clauses = [f"LOWER(protocol_fields_json) LIKE LOWER('%{v}%')" for v in variations]
                or_group = '(' + ' OR '.join(like_clauses) + ')'
                logger.info(f"Fallback-expanded solitary token '{matched}' into {len(variations)} variations")
                return or_group
            generated_sql = re.sub(r"LOWER\(protocol_fields_json\)\s+LIKE\s+'%(.*?)%'", _expand_lonely_lower, generated_sql, flags=re.IGNORECASE)

        # POST-PROCESS: Normalize S1/X2 handover message type variants.
        # The dataset uses 'HandoverPreparation' and 'HandoverResourceAllocation'.
        # LLM may output various case/spelling variants.
        handover_variants = [
            "'handoverRequired'", '"handoverRequired"',
            "'HandoverRequired'", '"HandoverRequired"',
            "'handoverrequired'", '"handoverrequired"',
            "'handoverpreparation'", '"handoverpreparation"',  # lowercase variant
            "'handoverPreparation'", '"handoverPreparation"',  # camelCase variant
        ]
        for variant in handover_variants:
            if variant in generated_sql:
                generated_sql = generated_sql.replace(variant, "'HandoverPreparation'")
                logger.info(f"Normalized message_type variant {variant} → 'HandoverPreparation'")

        # Direct equality pattern (case-insensitive catch-all for any handover* variant)
        generated_sql = re.sub(r"message_type\s*=\s*'handover(?:Required|Preparation|preparation|required)'", "message_type = 'HandoverPreparation'", generated_sql, flags=re.IGNORECASE)
        # IN (...) list pattern
        generated_sql = re.sub(r"message_type\s*IN\s*\(([^)]*?)\)", lambda m: m.group(0).replace('handoverRequired', 'HandoverPreparation').replace('HandoverRequired', 'HandoverPreparation').replace('handoverpreparation', 'HandoverPreparation').replace('handoverPreparation', 'HandoverPreparation'), generated_sql, flags=re.IGNORECASE)
        # LIKE pattern referencing variant
        generated_sql = re.sub(r"LIKE\s+'%handover(?:Required|Preparation|preparation|required)%'", "LIKE '%HandoverPreparation%'", generated_sql, flags=re.IGNORECASE)


        query_request.generated_sql = generated_sql
        query_request.status = QueryStatus.EXECUTING

        # Validate SQL
        sql_executor.validate_sql(generated_sql)

        # Execute SQL with graceful degradation (allow downstream deterministic fallbacks)
        try:
            result = sql_executor.execute_sql(conn, generated_sql, limit=limit)
        except Exception as primary_exc:
            logger.error(f"Primary SQL execution failed (will proceed with empty result for fallback): {primary_exc}")
            result = QueryResult(
                query_id=query_request.query_id,
                result_type=ResultType.EMPTY,
                row_count=0,
                columns=["protocol_fields_json"],
                data=[],
                summary=f"Primary SQL failed: {primary_exc}"
            )

        # Enhanced deterministic call flow extraction (always executed for call flow queries regardless of primary SQL outcome)
        try:
            call_flow_match = re.search(r"trace\s+the\s+call\s+flow\s+for\s+ue\s+id\s+(\d+)", query_text, re.IGNORECASE)
            if call_flow_match:
                ue_flow_id = call_flow_match.group(1)
                logger.info(f"Building enriched call flow for UE id {ue_flow_id}")
                anchor_like = f'"ngap.RAN_UE_NGAP_ID": "{ue_flow_id}"'
                # Broaden slightly: also include packets carrying NAS PDU with same AMF_UE_NGAP_ID if present later (optional heuristic)
                # Match multiple possible JSON key encodings (single vs double ngap prefix, bare field)
                flow_like_patterns = [
                    '%"ngap.RAN_UE_NGAP_ID": "' + ue_flow_id + '"%',
                    '%"ngap.ngap.RAN_UE_NGAP_ID": "' + ue_flow_id + '"%',
                    '%"RAN_UE_NGAP_ID": "' + ue_flow_id + '"%'
                ]
                like_clause = ' OR '.join([f"LOWER(protocol_fields_json) LIKE LOWER('{p}')" for p in flow_like_patterns])
                flow_sql = (
                    "SELECT packet_number, timestamp, protocol_fields_json "
                    f"FROM packets WHERE ({like_clause}) ORDER BY packet_number LIMIT 1200"
                )
                try:
                    flow_result = sql_executor.execute_sql(conn, flow_sql, limit=1200)
                    raw_rows = flow_result.data or []
                    if raw_rows:
                        # Parse and enrich - import NGAP procedure codes from field_extractors
                        from src.parsers.field_extractors import NGAP_PROCEDURE_CODES
                        proc_map = NGAP_PROCEDURE_CODES
                        enriched = []
                        step = 1
                        prev_ts = None
                        for r in raw_rows:
                            pfj = r.get('protocol_fields_json') if isinstance(r, dict) else None
                            if not pfj:
                                continue
                            try:
                                jf = json.loads(pfj) if isinstance(pfj, str) else pfj
                            except Exception:
                                continue
                            proc_code = jf.get('ngap.ngap.procedureCode')
                            proc_name = proc_map.get(proc_code, f'PROC_{proc_code}' if proc_code else 'UNKNOWN')
                            amf = jf.get('ngap.ngap.AMF_UE_NGAP_ID')
                            ran = jf.get('ngap.ngap.RAN_UE_NGAP_ID')
                            pdu_id = jf.get('ngap.ngap.pDUSessionID') or jf.get('ngap.nas-5gs.pdu_session_id')
                            ue_ip = jf.get('ngap.nas-5gs.sm.pdu_addr_inf_ipv4') or jf.get('ngap.nas-5gs.sm.pdu_addr_inf_ipv6')
                            # Timestamp normalization & delta
                            raw_ts = r.get('timestamp') or r.get('timestamp_iso')
                            iso_time = None
                            delta_ms = None
                            if isinstance(raw_ts, (int, float)):
                                try:
                                    iso_time = datetime.utcfromtimestamp(float(raw_ts)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                                    if prev_ts is not None:
                                        delta_ms = int((float(raw_ts) - prev_ts) * 1000)
                                    prev_ts = float(raw_ts)
                                except Exception:
                                    pass
                            # Flow direction heuristics
                            flow_dir = None
                            if 'ngap.ngap.DownlinkNASTransport_element' in jf or proc_code == '4':
                                flow_dir = 'DOWNLINK'
                            elif 'ngap.ngap.UplinkNASTransport_element' in jf or proc_code == '46':
                                flow_dir = 'UPLINK'
                            else:
                                # SCTP port heuristic
                                srcp = jf.get('sctp.sctp.srcport') or jf.get('sctp.srcport')
                                dstp = jf.get('sctp.sctp.dstport') or jf.get('sctp.dstport')
                                try:
                                    if srcp == '38412':
                                        flow_dir = 'DOWNLINK'
                                    elif dstp == '38412':
                                        flow_dir = 'UPLINK'
                                except Exception:
                                    pass
                            # Determine outcome / direction hints
                            direction = None
                            if 'initiatingMessage_element' in jf:
                                direction = 'initiating'
                            elif 'successfulOutcome_element' in jf:
                                direction = 'successfulOutcome'
                            elif 'unsuccessfulOutcome_element' in jf:
                                direction = 'unsuccessfulOutcome'
                            notes_parts = []
                            
                            # Extract NAS message name for NAS Transport messages
                            if proc_code in ('4', '46'):  # DownlinkNASTransport or UplinkNASTransport
                                from src.parsers.field_extractors import map_nas_5gs_message_type
                                # Try MM message type (note: field uses hyphens in name)
                                nas_mm_type = jf.get('ngap.nas-5gs.mm.message_type') or jf.get('nas-5gs.mm.message_type')
                                if nas_mm_type:
                                    # Convert hex to decimal if needed
                                    if isinstance(nas_mm_type, str) and nas_mm_type.startswith('0x'):
                                        nas_mm_type = str(int(nas_mm_type, 16))
                                    nas_msg_name = map_nas_5gs_message_type(nas_mm_type, is_sm=False)
                                    notes_parts.append(f"NAS: {nas_msg_name}")
                                else:
                                    # Try SM message type
                                    nas_sm_type = jf.get('ngap.nas-5gs.sm.message_type') or jf.get('nas-5gs.sm.message_type')
                                    if nas_sm_type:
                                        # Convert hex to decimal if needed
                                        if isinstance(nas_sm_type, str) and nas_sm_type.startswith('0x'):
                                            nas_sm_type = str(int(nas_sm_type, 16))
                                        nas_msg_name = map_nas_5gs_message_type(nas_sm_type, is_sm=True)
                                        notes_parts.append(f"NAS: {nas_msg_name}")
                            
                            if pdu_id:
                                notes_parts.append(f"PDU={pdu_id}")
                            if ue_ip:
                                notes_parts.append(f"UE_IP={ue_ip}")
                            if direction:
                                notes_parts.append(direction)
                            # Only include rows that have at least a procedure, pdu info, or are NAS transports
                            include = False
                            if proc_code in proc_map or pdu_id or ue_ip:
                                include = True
                            # Keep DownlinkNASTransport even without extras to show progression
                            if proc_code == '4':
                                include = True
                            if include:
                                enriched.append({
                                    'step': step,
                                    'packet_number': r.get('packet_number'),
                                    'iso_time': iso_time,
                                    'delta_ms': delta_ms,
                                    'procedure_code': proc_code,
                                    'procedure_name': proc_name,
                                    'amf_ue_id': amf,
                                    'ran_ue_id': ran,
                                    'pdu_session_id': pdu_id,
                                    'ue_ip': ue_ip,
                                    'flow_dir': flow_dir,
                                    'notes': ', '.join(notes_parts) if notes_parts else None,
                                })
                                step += 1
                        if enriched:
                            logger.info(f"✓ Enriched call flow built with {len(enriched)} steps (raw rows={len(raw_rows)})")
                            # Overwrite result regardless of earlier content so user always gets structured view
                            from src.models.query import ResultType as _RT
                            result.data = enriched
                            result.columns = ['step','packet_number','iso_time','delta_ms','procedure_code','procedure_name','amf_ue_id','ran_ue_id','pdu_session_id','ue_ip','flow_dir','notes']
                            result.row_count = len(enriched)
                            result.result_type = _RT.TABLE
                            result.summary = f"Call flow for UE id {ue_flow_id}: {len(enriched)} steps"
                        else:
                            logger.warning(f"Call flow query found anchor rows but none qualified for enrichment (rows={len(raw_rows)})")
                    else:
                        logger.warning(f"No packets located for call flow UE id {ue_flow_id} using anchor filter")
                except Exception as cf_ex:
                    logger.warning(f"Enhanced call flow extraction failed: {cf_ex}")
        except Exception as cf_outer:
            logger.warning(f"Call flow enrichment orchestration error: {cf_outer}")

        # Fallback for measurement reports per UE id if LLM failed to include correct filters
        # Detect pattern "UE id <number>" in natural language
        import re as _re
        nl_lower = processed_query.lower()
        ue_id_match = _re.search(r"ue\s+id\s+(\d+)", nl_lower)
        measurement_intent = ('rsrp' in nl_lower or 'rsrq' in nl_lower)
        missing_rsrp_in_sql = measurement_intent and ('rsrp' not in generated_sql.lower())
        zero_rows = (not result.data or len(result.data) == 0)
        if measurement_intent and ue_id_match and (missing_rsrp_in_sql or zero_rows):
            target_ue_id = ue_id_match.group(1)
            logger.info(f"Attempting deterministic measurement report fallback for UE id {target_ue_id}...")
            from src.query.query_helpers import build_measurement_report_sql_for_ue
            fallback_sql = build_measurement_report_sql_for_ue(target_ue_id, conn)

            # If direct builder failed and we have a correlation table, attempt correlation-based resolution
            if not fallback_sql and correlation_table:
                logger.info("Direct fallback produced no SQL; attempting enhanced correlation-based RLC UE ID resolution...")
                from src.query.query_helpers import resolve_rlc_ids_for_logical_ue
                correlated_rlc_ids = resolve_rlc_ids_for_logical_ue(target_ue_id, correlation_table, conn)
                if correlated_rlc_ids:
                    logger.info(f"Enhanced correlation resolved UE id {target_ue_id} to RLC IDs: {sorted(correlated_rlc_ids)}")
                    clauses = []
                    for rid in sorted(correlated_rlc_ids):
                        clauses.append(f"protocol_fields_json LIKE '%\"rlc_lte.rlc-lte.ueid\": \"{rid}\",%'")
                        clauses.append(f"protocol_fields_json LIKE '%\"rlc_lte.rlc-lte.ueid\": \"{rid}\"}}%'")
                    or_clause = " OR ".join(clauses)
                    fallback_sql = (
                        "SELECT packet_number, timestamp_iso, protocol_fields_json FROM packets WHERE "
                        "protocol_fields_json LIKE '%rsrpResult%' AND protocol_fields_json LIKE '%rsrqResult%' "
                        f"AND ({or_clause}) ORDER BY packet_number"
                    )
                else:
                    logger.info(f"Enhanced correlation could not resolve RLC UE ID for {target_ue_id}")

            if fallback_sql:
                logger.debug(f"Fallback SQL: {fallback_sql}")
                try:
                    fallback_result = sql_executor.execute_sql(conn, fallback_sql, limit=limit)
                    if fallback_result.data and len(fallback_result.data) > 0:
                        logger.info(f"✓ Fallback measurement report query succeeded for UE id {target_ue_id} ({len(fallback_result.data)} rows)")
                        result = fallback_result
                    else:
                        logger.warning(f"Fallback measurement report query returned 0 rows for UE id {target_ue_id}")
                except Exception as e:
                    logger.error(f"Fallback measurement report SQL failed: {e}")
            else:
                logger.warning(f"No measurement reports found to build fallback SQL for UE id {target_ue_id}")

        # Deterministic 5G identity fallback (PLMNIdentity / TAC) BEFORE generic value-intent fallback
        # Rationale: Generic fallback currently can mis-target generic words like "value" producing noisy http2.* matches.
        # We short‑circuit for high-value 5G identity parameters to extract precise answers.
        identity_fallback_applied = False
        if (not result.data or len(result.data) == 0):
            q_norm = query_text.lower()
            wants_plmn = any(token in q_norm for token in ["plmnidentity", "plmn identity", "plmn id", "plmnid"])
            wants_tac = re.search(r"\btac\b", q_norm) is not None
            # Only attempt when user explicitly requests and we have (or can infer) UE anchor for scoping (except tac which also needs registration context hint if provided)
            if (wants_plmn or wants_tac):
                try:
                    # Build base WHERE parts
                    where_clauses = []
                    if anchor_field and anchor_value:
                        # Support multiple possible JSON key namespace variants for NGAP anchor
                        if anchor_field == "ngap.RAN_UE_NGAP_ID":
                            anchor_variants = [
                                f'"ngap.RAN_UE_NGAP_ID": "{anchor_value}"',
                                f'"ngap.ngap.RAN_UE_NGAP_ID": "{anchor_value}"',
                                f'"RAN_UE_NGAP_ID": "{anchor_value}"'
                            ]
                            anchor_clause = '(' + ' OR '.join([f"LOWER(protocol_fields_json) LIKE LOWER('%{pat}%')" for pat in anchor_variants]) + ')'
                            where_clauses.append(anchor_clause)
                        else:
                            where_clauses.append(f"LOWER(protocol_fields_json) LIKE LOWER('%\"{anchor_field}\": \"{anchor_value}\"%')")
                    # Narrow by message_type for registration complete if user hints 'reg complete'
                    reg_hint = ("reg complete" in q_norm or "registration complete" in q_norm)
                    reg_clause_added = False
                    if wants_tac and reg_hint:
                        # Prefer explicit message_type if present in table; fallback to JSON search otherwise
                        where_clauses.append("(LOWER(message_type) = 'registrationcomplete' OR LOWER(protocol_fields_json) LIKE LOWER('%registrationcomplete%'))")
                        reg_clause_added = True
                    # Field specific LIKE filters
                    if wants_plmn:
                        # Look for any PLMN related keys (pLMNIdentity OR mcc/mnc pairs)
                        where_clauses.append("(LOWER(protocol_fields_json) LIKE LOWER('%plmnidentity%') OR LOWER(protocol_fields_json) LIKE LOWER('%plmn-id.mcc%') OR LOWER(protocol_fields_json) LIKE LOWER('%plmn-id.mnc%'))")
                    if wants_tac:
                        where_clauses.append("(LOWER(protocol_fields_json) LIKE LOWER('%tac%'))")
                    if where_clauses:
                        identity_sql = (
                            "SELECT packet_number, timestamp_iso, message_type, protocol_fields_json "
                            "FROM packets WHERE " + " AND ".join(where_clauses) + " ORDER BY packet_number LIMIT 300"
                        )
                        logger.debug(f"Identity fallback SQL: {identity_sql}")
                        try:
                            id_result = sql_executor.execute_sql(conn, identity_sql, limit=limit)
                        except Exception as id_ex:
                            logger.warning(f"Identity fallback SQL failed: {id_ex}")
                            id_result = None
                        # If we filtered on registrationComplete and found nothing for TAC, relax that filter and retry once.
                        if id_result and (not id_result.data) and wants_tac and reg_clause_added:
                            relaxed_clauses = [c for c in where_clauses if 'registrationcomplete' not in c]
                            if relaxed_clauses:
                                relaxed_sql = ("SELECT packet_number, timestamp_iso, message_type, protocol_fields_json FROM packets WHERE " + " AND ".join(relaxed_clauses) + " ORDER BY packet_number LIMIT 300")
                                logger.debug("Identity fallback retry without registrationComplete filter for TAC")
                                try:
                                    id_result = sql_executor.execute_sql(conn, relaxed_sql, limit=limit)
                                except Exception as rid_ex:
                                    logger.warning(f"Relaxed identity fallback SQL failed: {rid_ex}")
                        if id_result and id_result.data:
                            # Parse rows to extract desired values
                            plmn_answer = None
                            tac_answer = None
                            for row in id_result.data:
                                pfj = row.get('protocol_fields_json') if isinstance(row, dict) else None
                                if not pfj:
                                    continue
                                try:
                                    jf = json.loads(pfj) if isinstance(pfj, str) else pfj
                                except Exception:
                                    continue
                                if wants_plmn and plmn_answer is None:
                                    # Strategy: prefer explicit pLMNIdentity value; else construct from mcc/mnc
                                    for k, v in jf.items():
                                        kl = k.lower()
                                        if 'plmnidentity' in kl and isinstance(v, str) and v:
                                            plmn_answer = v
                                            break
                                    if plmn_answer is None:
                                        mcc = None
                                        mnc = None
                                        for k, v in jf.items():
                                            kl = k.lower()
                                            if mcc is None and kl.endswith('.mcc') and isinstance(v, str):
                                                mcc = v
                                            elif mnc is None and kl.endswith('.mnc') and isinstance(v, str):
                                                mnc = v
                                        if mcc and mnc:
                                            plmn_answer = f"MCC={mcc}, MNC={mnc}"
                                if wants_tac and tac_answer is None:
                                    for k, v in jf.items():
                                        kl = k.lower()
                                        if 'tac' in kl and isinstance(v, str) and v:
                                            # Avoid capturing unrelated substrings (e.g., 'contact')
                                            if re.search(r"(^|[_.-])tac($|[_.-])", kl):
                                                tac_answer = v
                                                break
                                if (not wants_plmn or plmn_answer) and (not wants_tac or tac_answer):
                                    break
                            extracted_rows = []
                            if wants_plmn and plmn_answer:
                                extracted_rows.append({'field': 'ngap.pLMNIdentity', 'value': plmn_answer})
                            if wants_tac and tac_answer:
                                extracted_rows.append({'field': 'ngap.tAC', 'value': tac_answer})
                            if extracted_rows:
                                from src.models.query import ResultType as _RT
                                result.data = extracted_rows
                                result.columns = ['field', 'value']
                                result.row_count = len(extracted_rows)
                                result.result_type = _RT.TABLE
                                summary_bits = []
                                for r_ex in extracted_rows:
                                    summary_bits.append(f"{r_ex['field']} = {r_ex['value']}")
                                result.summary = (result.summary or "") + (" | " if result.summary else "") + ", ".join(summary_bits)
                                identity_fallback_applied = True
                                logger.info(f"✓ Identity fallback extracted: {', '.join(summary_bits)}")
                except Exception as id_fb_ex:
                    logger.warning(f"Identity fallback orchestration failed: {id_fb_ex}")

        # Generic VALUE-INTENT deterministic fallback (multi-technology) for queries like:
        #   "what is the amfname?", "value of q-RxLevMin", "find the pLMNIdentity"
        # Trigger only if original result is empty OR contains only protocol_fields_json column without extracted value semantics
        if (not result.data or len(result.data) == 0) and not identity_fallback_applied and re.search(r"\bwhat\s+is\b|\bvalue\s+of\b|\bfind\s+the\b", query_text, re.IGNORECASE):
            logger.info("Initiating deterministic value-intent fallback search (zero primary rows)")
            try:
                import re as _re
                m = _re.search(r"(?:what(?:'s|s)?\s+is|value\s+of|find\s+the)\s+(?:the\s+)?([a-zA-Z0-9_\-\. ]{1,80}?)(?:\s+(?:for|in|from|of)\b|\?|$)", query_text, flags=_re.IGNORECASE)
                if m:
                    raw_token = m.group(1).strip().rstrip('?')
                    from src.query.query_helpers import _generate_field_name_variations_internal as _gen_var
                    base_candidates = set()
                    phrase_parts = [p for p in re.split(r"\s+", raw_token) if p]
                    collapsed = ''.join(phrase_parts)
                    if collapsed:
                        base_candidates.add(collapsed)
                        base_candidates.add(collapsed.lower())
                    if len(phrase_parts) > 1:
                        base_candidates.add('_'.join(phrase_parts))
                        base_candidates.add('-'.join(phrase_parts))
                    for part in phrase_parts:
                        base_candidates.add(part)
                        base_candidates.add(part.lower())
                    variations = []
                    for cand in list(base_candidates)[:25]:
                        try:
                            variations.extend(_gen_var(cand))
                        except Exception:
                            variations.append(cand)
                    variations.append(raw_token)
                    variations.append(raw_token.lower())
                    variations = list({v for v in variations if v})[:120]
                    like_clauses = [f"LOWER(protocol_fields_json) LIKE LOWER('%{v}%')" for v in sorted(set(variations))]
                    where_clause = " OR ".join(like_clauses)
                    fallback_sql = (
                        "SELECT packet_number, timestamp_iso, message_type, protocol_fields_json FROM packets WHERE (" + where_clause + ")"
                    )
                    if anchor_field and anchor_value:
                        anchor_like = f"\"{anchor_field}\": \"{anchor_value}\""
                        fallback_sql += f" AND LOWER(protocol_fields_json) LIKE LOWER('%{anchor_like}%')"
                    fallback_sql += " ORDER BY packet_number LIMIT 500"
                    logger.debug(f"Value-intent fallback SQL: {fallback_sql}")
                    try:
                        fb_result = sql_executor.execute_sql(conn, fallback_sql, limit=limit)
                        if fb_result.data and len(fb_result.data) > 0:
                            logger.info(f"✓ Value-intent fallback located {len(fb_result.data)} candidate packets for '{raw_token}'")
                            result = fb_result
                        else:
                            # Retry WITHOUT anchor if anchor present (field may be system/broadcast level)
                            if anchor_field and anchor_value:
                                unanchored_sql = fallback_sql.replace(f" AND LOWER(protocol_fields_json) LIKE LOWER('%\"{anchor_field}\": \"{anchor_value}\"%')", "")
                                logger.info("Value-intent fallback with anchor returned 0 rows; retrying without anchor constraint")
                                try:
                                    fb_result2 = sql_executor.execute_sql(conn, unanchored_sql, limit=limit)
                                    if fb_result2.data and len(fb_result2.data) > 0:
                                        logger.info(f"✓ Unanchored value-intent fallback succeeded with {len(fb_result2.data)} rows")
                                        result = fb_result2
                                        if result.summary:
                                            result.summary += " | (anchor relaxed for broadcast/system field)"
                                        else:
                                            result.summary = "Anchor relaxed for broadcast/system field"
                                except Exception as fe2:
                                    logger.warning(f"Unanchored value-intent retry failed: {fe2}")
                            if not result.data or len(result.data) == 0:
                                # Provide top-close suggestions from schema catalog for user feedback
                                suggestions = []
                                token_norm = raw_token.lower().replace('-', '').replace('_', '')
                                for field_name in schema_catalog.field_samples.keys():
                                    fn_norm = field_name.lower().replace('-', '').replace('_', '')
                                    if token_norm in fn_norm or fn_norm in token_norm:
                                        suggestions.append(field_name)
                                        if len(suggestions) >= 6:
                                            break
                                if suggestions:
                                    if result.summary:
                                        result.summary += f" | Suggestions: {', '.join(suggestions)}"
                                    else:
                                        result.summary = f"Suggestions: {', '.join(suggestions)}"
                    except Exception as fe:
                        logger.warning(f"Value-intent fallback execution failed: {fe}")
                else:
                    logger.debug("No identifiable target token for value fallback")
            except Exception as e_fb:
                logger.warning(f"Value-intent fallback orchestration failed: {e_fb}")

        # Strict anchor filtering (post SQL) to avoid multi-UE mixing when anchor explicitly or implicitly set
        if 'anchor_field' in locals() and anchor_field and anchor_value and result.data:
            filtered = []
            dropped = 0
            for r in result.data:
                pfj = r.get('protocol_fields_json')
                if not pfj:
                    continue
                try:
                    jf = json.loads(pfj) if isinstance(pfj, str) else pfj
                except Exception:
                    jf = {}
                val = jf.get(anchor_field)
                if val is not None and str(val) == str(anchor_value):
                    filtered.append(r)
                else:
                    dropped += 1
            if filtered and dropped:
                logger.info(f"Anchor post-filter removed {dropped} rows; kept {len(filtered)} for {anchor_field}={anchor_value}")
                result.data = filtered
                result.row_count = len(filtered)

        # Apply UE correlation if enabled
        if correlation_table and result.data:
            from src.query.query_helpers import detect_ue_id_in_sql, expand_query_results_with_correlation
            
            ue_id_info = detect_ue_id_in_sql(generated_sql)
            if ue_id_info:
                field_name, value = ue_id_info
                logger.info(f"UE correlation enabled - expanding results for {field_name}={value}")
                
                expanded_data = expand_query_results_with_correlation(
                    original_results=result.data,
                    correlation_table=correlation_table,
                    conn=conn,
                    ue_id_field=field_name,
                    ue_id_value=value,
                    limit=limit
                )
                
                # Update result with expanded data
                if expanded_data and len(expanded_data) > len(result.data):
                    result.data = expanded_data
                    result.row_count = len(expanded_data)
        
        # Check for special query types and apply formatting
        # Check if query is for RSRP/RSRQ values (from measurement reports)
        has_rsrp_rsrq = ("rsrp" in query_text.lower() or "rsrq" in query_text.lower())
        has_measurement_context = (
            "measurement" in generated_sql.lower() or 
            "measurement" in query_text.lower() or
            "%rsrp%" in generated_sql.lower() or  # SQL searches for rsrp in JSON
            "%rsrq%" in generated_sql.lower() or
            "rsrpResult" in generated_sql or      # direct field name
            "rsrqResult" in generated_sql         # direct field name
        )
        is_measurement_query = has_rsrp_rsrq and has_measurement_context
        
        if result.data and len(result.data) > 0:
            
            if is_measurement_query and "protocol_fields_json" in result.data[0]:
                from src.query.query_helpers import extract_rsrp_rsrq_values
                extracted_data = extract_rsrp_rsrq_values(result.data)
                
                if extracted_data:
                    # Replace the result data with extracted RSRP/RSRQ table
                    result.data = extracted_data
                    result.columns = ["packet_number", "timestamp_iso", "rsrp_result", "rsrp_dbm", "rsrq_result", "rsrq_db"]
                    result.row_count = len(extracted_data)
                    logger.info(f"✓ Extracted RSRP/RSRQ values from {len(extracted_data)} measurement reports")
            
            # Check if query is for handover call flow tracing
            from src.query.query_helpers import detect_handover_in_query, format_handover_call_flow
            is_handover_query = detect_handover_in_query(query_text, generated_sql)
            
            if is_handover_query and "protocol" in result.data[0]:
                formatted_data = format_handover_call_flow(result.data)
                
                if formatted_data:
                    # Replace with formatted handover flow (now includes UE IDs)
                    result.data = formatted_data
                    result.columns = ["step", "flow", "packet_number", "timestamp_iso", "protocol", "message_type", "enb_ue_id", "mme_ue_id", "direction", "interface", "phase", "ho_type"]
                    result.row_count = len(formatted_data)
                    
                    # Detect handover type from data
                    ho_types = {row.get("ho_type") for row in formatted_data if row.get("ho_type") and row.get("ho_type") != "UNKNOWN"}
                    if ho_types:
                        ho_type_str = "/".join(sorted(str(t) for t in ho_types))
                        logger.info(f"✓ Formatted {len(formatted_data)} messages as {ho_type_str} handover call flow")
            
                # Check if query is asking for a specific field value (e.g., "what is m-tmsi")
                is_value_query = any(word in query_text.lower() for word in ["what is", "whats", "what's", "show me the", "find the", "get the", "value of"])

                # Fallback path: if value intent but zero rows returned from LLM SQL, perform deterministic variation search
                if is_value_query and (not result.data or len(result.data) == 0):
                    try:
                        logger.info("Value-intent query returned 0 rows; attempting deterministic 5G/LTE field fallback search")
                        # Extract raw token after 'what is' / 'value of'
                        import re as _re
                        # Capture multi-word phrase up to a stop token (for, in, for UE, question mark)
                        m = _re.search(r"(?:what(?:'s|s)?\s+is|value\s+of)\s+(?:the\s+)?([a-zA-Z0-9_\-\. ]{1,80}?)(?:\s+(?:for|in|from|of)\b|\?|$)", query_text, flags=_re.IGNORECASE)
                        if m:
                            raw_token = m.group(1).strip().rstrip('?')
                            from src.query.query_helpers import _generate_field_name_variations_internal as _gen_var
                            variations = []
                            phrase_parts = [p for p in re.split(r"\s+", raw_token) if p]
                            base_candidates = set()
                            # Include whole phrase collapsed variants (remove spaces, underscore, hyphen joins)
                            collapsed = ''.join(phrase_parts)
                            if collapsed:
                                base_candidates.add(collapsed)
                                base_candidates.add(collapsed.lower())
                            if len(phrase_parts) > 1:
                                base_candidates.add('_'.join(phrase_parts))
                                base_candidates.add('-'.join(phrase_parts))
                            # Per-part candidates
                            for part in phrase_parts:
                                base_candidates.add(part)
                                base_candidates.add(part.lower())
                            # Expand each candidate with variation generator
                            for cand in list(base_candidates)[:20]:
                                try:
                                    variations.extend(_gen_var(cand))
                                except Exception:
                                    variations.append(cand)
                            # Always include raw phrase (with spaces) and lowercase
                            variations.append(raw_token)
                            variations.append(raw_token.lower())
                            # De-duplicate and limit
                            variations = list({v for v in variations if v})[:80]
                            like_clauses = [f"LOWER(protocol_fields_json) LIKE LOWER('%{v}%')" for v in sorted(set(variations))]
                            where_clause = " OR ".join(like_clauses)
                            fallback_sql = (
                                "SELECT packet_number, timestamp_iso, message_type, protocol_fields_json FROM packets WHERE (" +
                                where_clause + ")"
                            )
                            # Re-apply anchor if present
                            if anchor_field and anchor_value:
                                anchor_like = f"\"{anchor_field}\": \"{anchor_value}\""
                                fallback_sql += f" AND LOWER(protocol_fields_json) LIKE LOWER('%{anchor_like}%')"
                            fallback_sql += " ORDER BY packet_number LIMIT 500"
                            logger.debug(f"Fallback value SQL: {fallback_sql}")
                            try:
                                fb_result = sql_executor.execute_sql(conn, fallback_sql, limit=limit)
                                if fb_result.data and len(fb_result.data) > 0:
                                    logger.info(f"✓ Fallback located {len(fb_result.data)} candidate packets for '{raw_token}'")
                                    # Replace main result so downstream extraction logic applies
                                    result = fb_result
                                else:
                                    # Offer nearest field suggestions from schema catalog
                                    suggestions = []
                                    token_norm = raw_token.lower().replace('-', '').replace('_', '')
                                    for field_name in schema_catalog.field_samples.keys():
                                        fn_norm = field_name.lower().replace('-', '').replace('_', '')
                                        if token_norm in fn_norm or fn_norm in token_norm:
                                            suggestions.append(field_name)
                                            if len(suggestions) >= 5:
                                                break
                                    if suggestions:
                                        result.summary = (result.summary or "") + f" | Suggestions: {', '.join(suggestions)}"
                            except Exception as fe:
                                logger.warning(f"Fallback value search failed: {fe}")
                    except Exception as e_fallback:
                        logger.warning(f"Value fallback orchestration failed: {e_fallback}")

                if is_value_query and result.data and "protocol_fields_json" in result.data[0]:
                    from src.query.query_helpers import extract_specific_field_value
                    extracted_value = extract_specific_field_value(result.data, query_text, return_all=True, schema_catalog=schema_catalog)
                    if extracted_value:
                        if isinstance(extracted_value, list):
                            # Multi-row table of all matches (now includes ue_id column)
                            result.data = extracted_value
                            result.columns = ["packet_number", "ue_id", "field", "value"]
                            result.row_count = len(extracted_value)
                            result.result_type = ResultType.TABLE  # Force table format even for single row
                            logger.info(f"✓ Extracted {len(extracted_value)} matching values for requested field")
                        else:
                            field_name, field_value = extracted_value
                            logger.info(f"✓ Extracted answer: {field_name} = {field_value}")
                            result.data = [{"field": field_name, "value": field_value}]
                            result.columns = ["field", "value"]
                        result.row_count = 1
                        result.result_type = ResultType.TABLE  # Table with field/value columns

        # Post-processing: direct field/value extraction for value-intent queries when rows contain protocol_fields_json
        try:
            if result and result.data and isinstance(result.data, list):
                # Re-detect value intent (lightweight) to avoid threading earlier flags
                if re.search(r"\bwhat\s+is\b|\bvalue\s+of\b|\bfind\s+the\b", query_text, re.IGNORECASE):
                    # Extract target token again (same pattern used in fallback)
                    m_tok = re.search(r"(?:what(?:'s|s)?\s+is|value\s+of|find\s+the)\s+(?:the\s+)?([a-zA-Z0-9_\-\. ]{1,80}?)(?:\s+(?:for|in|from|of)\b|\?|$)", query_text, re.IGNORECASE)
                    target_token = m_tok.group(1).strip().rstrip('?') if m_tok else None
                    if target_token:
                        norm_token = target_token.lower().replace('-', '').replace('_', '').replace(' ', '')
                        extracted_pairs = []
                        seen = set()
                        for row in result.data:
                            pfj = row.get('protocol_fields_json') if isinstance(row, dict) else None
                            if not pfj:
                                continue
                            try:
                                jf = json.loads(pfj) if isinstance(pfj, str) else pfj
                            except Exception:
                                continue
                            for k, v in jf.items():
                                kn = k.lower().replace('-', '').replace('_', '').replace('.', '').replace(' ', '')
                                if norm_token in kn or kn in norm_token:
                                    if (k, v) not in seen and isinstance(v, str) and v:
                                        extracted_pairs.append({"field": k, "value": v})
                                        seen.add((k, v))
                            if len(extracted_pairs) >= 25:
                                break
                        # Heuristic narrowing: prefer exact token (ignoring case/sep) containment at end or exact word boundaries
                        if extracted_pairs:
                            # Rank: shorter field name, then exact containment position
                            def _rank(item):
                                fn = item['field']
                                fn_norm = fn.lower().replace('-', '').replace('_', '').replace('.', '')
                                pos = fn_norm.find(norm_token)
                                return (0 if fn_norm == norm_token else 1,
                                        0 if pos == 0 else 1,
                                        len(fn_norm))
                            extracted_pairs.sort(key=_rank)
                            # Replace result with concise table (unless already an extraction table)
                            if not (result.columns and set(result.columns) >= {"field", "value"}):
                                result.data = extracted_pairs[:10]
                                result.columns = ["field", "value"]
                                result.row_count = len(result.data)
                                result.result_type = ResultType.TABLE
                                ans_field = extracted_pairs[0]['field']
                                ans_value = extracted_pairs[0]['value']
                                answer_snippet = f"{ans_field} = {ans_value}"
                                if result.summary:
                                    if answer_snippet not in result.summary:
                                        result.summary += f" | Answer: {answer_snippet}"
                                else:
                                    result.summary = f"Answer: {answer_snippet}"
        except Exception as e_extract:
            logger.warning(f"Value extraction post-processing skipped due to error: {e_extract}")

        # Update query request
        execution_time_ms = int((time.time() - start_time) * 1000)
        query_request.execution_time_ms = execution_time_ms
        query_request.status = QueryStatus.COMPLETED

        # Update result with query ID
        result.query_id = query_request.query_id

        # Generate human-readable summary if needed
        if not result.summary:
            result.summary = _generate_summary(query_text, result)

        # Annotate summary with anchor information if present
        if anchor_field and anchor_value and result.summary and anchor_field in ['s1ap.s1ap.ENB_UE_S1AP_ID', 's1ap.s1ap.MME_UE_S1AP_ID', 'ngap.RAN_UE_NGAP_ID']:
            result.summary += f" (anchored on {anchor_field.split('.')[-1]}={anchor_value})"

        logger.info(f"✓ Query completed: {result.summary}")

        return query_request, result

    except Exception as e:
        execution_time_ms = int((time.time() - start_time) * 1000)
        query_request.execution_time_ms = execution_time_ms
        query_request.status = QueryStatus.FAILED
        query_request.error_message = str(e)

        logger.error(f"Query failed: {e}")

        # Return empty result with error
        result = QueryResult(
            query_id=query_request.query_id,
            result_type=ResultType.EMPTY,
            row_count=0,
            summary=f"Query failed: {e}",
        )
        return query_request, result


def execute_direct_sql(
    conn: duckdb.DuckDBPyConnection,
    sql: str,
    dataset_path: str,
    limit: int = 100,
    correlation_table=None,
) -> tuple[QueryRequest, QueryResult]:
    """
    Execute SQL query directly (without LLM).

    Args:
        conn: DuckDB connection
        sql: SQL query
        dataset_path: Path to dataset being queried
        limit: Maximum rows to return

    Returns:
        Tuple of (QueryRequest, QueryResult)

    Raises:
        Exception: If query execution fails
    """
    # Create query request
    query_request = QueryRequest(query_text=f"[Direct SQL] {sql}", dataset_path=dataset_path)

    query_request.generated_sql = sql
    query_request.status = QueryStatus.EXECUTING
    start_time = time.time()

    try:
        # Validate SQL
        sql_executor.validate_sql(sql)

        # Execute SQL
        result = sql_executor.execute_sql(conn, sql, limit=limit)

        # Apply UE correlation if enabled
        if correlation_table and result.data:
            from src.query.query_helpers import detect_ue_id_in_sql, expand_query_results_with_correlation
            
            ue_id_info = detect_ue_id_in_sql(sql)
            if ue_id_info:
                field_name, value = ue_id_info
                logger.info(f"UE correlation enabled - expanding results for {field_name}={value}")
                
                expanded_data = expand_query_results_with_correlation(
                    original_results=result.data,
                    correlation_table=correlation_table,
                    conn=conn,
                    ue_id_field=field_name,
                    ue_id_value=value,
                    limit=limit
                )
                
                # Update result with expanded data
                if expanded_data and len(expanded_data) > len(result.data):
                    result.data = expanded_data
                    result.row_count = len(expanded_data)

        # Measurement extraction (provide same convenience as natural language path)
        if result.data and len(result.data) > 0 and "protocol_fields_json" in result.data[0]:
            lower_sql = sql.lower()
            has_rsrp_rsrq = ("rsrp" in lower_sql or "rsrq" in lower_sql)
            has_measurement_context = (
                "measurement" in lower_sql or
                "%rsrp%" in lower_sql or
                "%rsrq%" in lower_sql or
                "rsrpresult" in lower_sql or
                "rsrqresult" in lower_sql
            )
            if has_rsrp_rsrq and has_measurement_context:
                from src.query.query_helpers import extract_rsrp_rsrq_values
                extracted_data = extract_rsrp_rsrq_values(result.data)
                if extracted_data:
                    result.data = extracted_data
                    result.columns = ["packet_number", "timestamp_iso", "rsrp_result", "rsrp_dbm", "rsrq_result", "rsrq_db"]
                    result.row_count = len(extracted_data)
                    logger.info(f"✓ Direct SQL: Extracted RSRP/RSRQ values from {len(extracted_data)} measurement reports")

        # Update query request
        execution_time_ms = int((time.time() - start_time) * 1000)
        query_request.execution_time_ms = execution_time_ms
        query_request.status = QueryStatus.COMPLETED

        # Update result with query ID
        result.query_id = query_request.query_id

        logger.info(f"✓ Direct SQL query completed: {result.summary}")

        return query_request, result

    except Exception as e:
        execution_time_ms = int((time.time() - start_time) * 1000)
        query_request.execution_time_ms = execution_time_ms
        query_request.status = QueryStatus.FAILED
        query_request.error_message = str(e)

        logger.error(f"Direct SQL query failed: {e}")
        raise


def _get_schema_info(conn: duckdb.DuckDBPyConnection) -> str:
    """Get database schema information as string."""
    columns = conn.execute("DESCRIBE packets").fetchall()
    schema_lines = ["Table: packets", "Columns:"]
    for col in columns:
        schema_lines.append(f"  - {col[0]} ({col[1]})")

    return "\\n".join(schema_lines)


def _generate_summary(query_text: str, result: QueryResult) -> str:
    """Generate human-readable summary of results."""
    if result.is_empty():
        return f"No results found for query: {query_text}"

    if result.row_count == 1 and len(result.columns) == 1:
        # Scalar result
        value = result.data[0][result.columns[0]]
        return f"Result: {value}"

    return f"Found {result.row_count} results for query: {query_text}"
