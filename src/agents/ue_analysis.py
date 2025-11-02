"""
Advanced UE analysis and call flow intelligence.
Provides LTE-specific knowledge for determining UE states and tracing call flows.
"""

# LTE Attachment Success Indicators
ATTACHMENT_SUCCESS_PATTERNS = {
    "rrc_setup_complete": {
        "description": "UE successfully completed RRC connection setup",
        "indicators": [
            "protocol = 'RRC' AND protocol_fields_json LIKE '%rrcConnectionSetupComplete%'",
            "rlc-lte UEId present AND lte-rrc.c1 = rrcConnectionSetupComplete"
        ],
        "significance": "Air interface (Uu) connection established"
    },
    "attach_accept": {
        "description": "Network accepted UE attach request",
        "indicators": [
            "protocol = 'NAS_EPS' AND message_type = '66'",  # Attach Accept
        ],
        "significance": "UE successfully attached to EPS network"
    },
    "initial_context_setup_response": {
        "description": "eNB successfully set up initial context for UE",
        "indicators": [
            "protocol = 'S1AP' AND message_type = '10'",  # Initial Context Setup Response
        ],
        "significance": "E-RAB established, UE can now send/receive data"
    }
}

# LTE Call Flow Sequences
CALL_FLOW_SEQUENCES = {
    "attach_procedure": {
        "name": "UE Attach Procedure",
        "sequence": [
            {"step": 1, "message": "RRC Connection Request", "direction": "UL", "protocol": "RRC", "identifier": "rrcConnectionRequest"},
            {"step": 2, "message": "RRC Connection Setup", "direction": "DL", "protocol": "RRC", "identifier": "rrcConnectionSetup"},
            {"step": 3, "message": "RRC Connection Setup Complete", "direction": "UL", "protocol": "RRC", "identifier": "rrcConnectionSetupComplete"},
            {"step": 4, "message": "Attach Request", "direction": "UL", "protocol": "NAS_EPS", "message_type": "65"},
            {"step": 5, "message": "Authentication Request", "direction": "DL", "protocol": "NAS_EPS", "message_type": "82"},
            {"step": 6, "message": "Authentication Response", "direction": "UL", "protocol": "NAS_EPS", "message_type": "83"},
            {"step": 7, "message": "Security Mode Command", "direction": "DL", "protocol": "NAS_EPS", "message_type": "93"},
            {"step": 8, "message": "Security Mode Complete", "direction": "UL", "protocol": "NAS_EPS", "message_type": "94"},
            {"step": 9, "message": "Initial Context Setup Request", "direction": "DL", "protocol": "S1AP", "message_type": "9"},
            {"step": 10, "message": "Initial Context Setup Response", "direction": "UL", "protocol": "S1AP", "message_type": "10"},
            {"step": 11, "message": "Attach Accept", "direction": "DL", "protocol": "NAS_EPS", "message_type": "66"},
            {"step": 12, "message": "Attach Complete", "direction": "UL", "protocol": "NAS_EPS", "message_type": "68"},
        ]
    },
    "detach_procedure": {
        "name": "UE Detach Procedure",
        "sequence": [
            {"step": 1, "message": "Detach Request", "direction": "UL/DL", "protocol": "NAS_EPS", "message_type": "69"},
            {"step": 2, "message": "Detach Accept", "direction": "DL/UL", "protocol": "NAS_EPS", "message_type": "70"},
            {"step": 3, "message": "UE Context Release Command", "direction": "DL", "protocol": "S1AP", "message_type": "23"},
            {"step": 4, "message": "UE Context Release Complete", "direction": "UL", "protocol": "S1AP", "message_type": "24"},
        ]
    },
    "handover_procedure": {
        "name": "X2 Handover Procedure",
        "sequence": [
            {"step": 1, "message": "Handover Request", "direction": "Source->Target", "protocol": "X2AP", "message_type": "0"},
            {"step": 2, "message": "Handover Request Acknowledge", "direction": "Target->Source", "protocol": "X2AP", "message_type": "1"},
            {"step": 3, "message": "RRC Connection Reconfiguration", "direction": "DL", "protocol": "RRC", "identifier": "rrcConnectionReconfiguration"},
            {"step": 4, "message": "RRC Connection Reconfiguration Complete", "direction": "UL", "protocol": "RRC", "identifier": "rrcConnectionReconfigurationComplete"},
        ]
    },
    "tracking_area_update": {
        "name": "Tracking Area Update Procedure",
        "sequence": [
            {"step": 1, "message": "Tracking Area Update Request", "direction": "UL", "protocol": "NAS_EPS", "message_type": "72"},
            {"step": 2, "message": "Tracking Area Update Accept", "direction": "DL", "protocol": "NAS_EPS", "message_type": "73"},
        ]
    }
}

# UE Identification Methods
UE_IDENTIFICATION_METHODS = """
To trace a specific UE through the capture, use these identification methods:

1. **RLC-LTE UEId**: Found in RLC-LTE layer (rlc-lte.ueid)
   - Direct UE identifier in MAC/RLC layers
   - Query: `protocol_fields_json LIKE '%rlc-lte.ueid": "61%'`

2. **S1AP UE IDs**: MME_UE_S1AP_ID and ENB_UE_S1AP_ID
   - Core network and eNB identifiers
   - Query: `protocol = 'S1AP' AND (protocol_fields_json LIKE '%MME_UE_S1AP_ID%' OR protocol_fields_json LIKE '%ENB_UE_S1AP_ID%')`

3. **IMSI/GUTI/M-TMSI**: In NAS-EPS messages
   - Permanent and temporary identifiers
   - Found in Attach Request, TAU Request, etc.
   - Query: `protocol_fields_json LIKE '%m_tmsi": "424504%'`

4. **Combined approach**: 
   - Start with RRC messages to find RLC UEId
   - Follow through S1AP messages using MME/ENB UE IDs
   - Correlate with NAS-EPS using IMSI/GUTI
"""

def generate_ue_attach_detection_query() -> str:
    """
    Generate SQL to detect successfully attached UEs.
    
    Returns:
        SQL query string to find UEs that completed attachment
    """
    return """
    SELECT DISTINCT 
        packet_number,
        timestamp_iso,
        protocol,
        message_type,
        protocol_fields_json
    FROM packets
    WHERE 
        (protocol = 'RRC' AND protocol_fields_json LIKE '%rrcConnectionSetupComplete%')
        OR (protocol = 'NAS_EPS' AND message_type = '66')
        OR (protocol = 'S1AP' AND message_type = '10')
    ORDER BY timestamp
    LIMIT 100
    """

def generate_ue_call_flow_query(ue_identifier: str, identifier_type: str = "rlc_ueid") -> str:
    """
    Generate SQL to trace a UE's complete call flow.
    
    Args:
        ue_identifier: The UE identifier (e.g., "61", "424504")
        identifier_type: Type of identifier ("rlc_ueid", "m_tmsi", "mme_ue_s1ap_id")
    
    Returns:
        SQL query string to trace the UE
    """
    if identifier_type == "rlc_ueid":
        where_clause = f"protocol_fields_json LIKE '%rlc-lte.ueid\": \"{ue_identifier}%'"
    elif identifier_type == "m_tmsi":
        where_clause = f"protocol_fields_json LIKE '%m_tmsi\": \"{ue_identifier}%'"
    elif identifier_type == "mme_ue_s1ap_id":
        where_clause = f"protocol_fields_json LIKE '%MME_UE_S1AP_ID\": \"{ue_identifier}%'"
    else:
        where_clause = f"protocol_fields_json LIKE '%{ue_identifier}%'"
    
    return f"""
    SELECT 
        packet_number,
        timestamp_iso,
        protocol,
        message_type,
        direction,
        interface,
        LEFT(protocol_fields_json, 200) as summary
    FROM packets
    WHERE {where_clause}
    ORDER BY timestamp
    LIMIT 100
    """

def get_call_flow_explanation(procedure_name: str) -> str:
    """
    Get detailed explanation of a call flow procedure.
    
    Args:
        procedure_name: Name of the procedure
    
    Returns:
        Human-readable explanation
    """
    if procedure_name not in CALL_FLOW_SEQUENCES:
        return f"Unknown procedure: {procedure_name}"
    
    procedure = CALL_FLOW_SEQUENCES[procedure_name]
    explanation = f"\n{procedure['name']} Call Flow:\n"
    explanation += "=" * 60 + "\n"
    
    for step in procedure["sequence"]:
        direction_symbol = "→" if step["direction"] == "UL" else "←" if step["direction"] == "DL" else "↔"
        explanation += f"{step['step']:2}. {direction_symbol} {step['message']:<40} ({step['protocol']})\n"
    
    return explanation

# Prompt enhancement for LTE intelligence
LTE_INTELLIGENCE_PROMPT = """
**Advanced LTE/3GPP Analysis Intelligence**:

1. **Determining UE Attachment Success**:
   - A UE is SUCCESSFULLY ATTACHED when you see:
     a) RRC Connection Setup Complete (protocol_fields_json contains "rrcConnectionSetupComplete")
     b) Attach Accept (NAS_EPS message_type = 66)
     c) Initial Context Setup Response (S1AP message_type = 10)
   - To count attached UEs, look for distinct UE identifiers in these messages

2. **Tracing a Specific UE**:
   - UEs can be identified by multiple IDs across layers:
     * RLC layer: rlc-lte.ueid (e.g., 61)
     * S1AP layer: MME_UE_S1AP_ID, ENB_UE_S1AP_ID
     * NAS layer: IMSI, GUTI, M-TMSI
   - To trace a UE, search protocol_fields_json for these identifiers

3. **Call Flow Analysis**:
   - For attach procedure, query in sequence: RRC messages → NAS-EPS messages → S1AP messages
   - Order by timestamp to see chronological flow
   - Look for direction field: UL (uplink/UE→Network), DL (downlink/Network→UE)

4. **Example Queries**:
   - Find attached UEs: `SELECT * FROM packets WHERE protocol_fields_json LIKE '%rrcConnectionSetupComplete%' ORDER BY timestamp`
   - Trace UE with ID 61: `SELECT * FROM packets WHERE protocol_fields_json LIKE '%rlc-lte.ueid": "61%' ORDER BY timestamp`
   - Get attach flow: `SELECT packet_number, timestamp_iso, protocol, message_type, direction FROM packets WHERE protocol IN ('RRC', 'NAS_EPS', 'S1AP') ORDER BY timestamp LIMIT 100`
"""
