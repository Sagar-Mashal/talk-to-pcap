"""3GPP-specific field extraction utilities."""

from typing import List, Optional

from src.models.packet import ProtocolLayer
from src.utils.logger import get_logger

logger = get_logger(__name__)


# S1AP Procedure Code to Message Name Mapping (3GPP TS 36.413)
S1AP_PROCEDURE_CODES = {
    "0": "HandoverPreparation",
    "1": "HandoverResourceAllocation",
    "2": "HandoverNotification",
    "3": "PathSwitchRequest",
    "4": "HandoverCancel",
    "5": "E-RABSetup",
    "6": "E-RABModify",
    "7": "E-RABRelease",
    "8": "E-RABReleaseIndication",
    "9": "InitialContextSetup",
    "10": "Paging",
    "11": "DownlinkNASTransport",
    "12": "InitialUEMessage",
    "13": "UplinkNASTransport",
    "14": "Reset",
    "15": "ErrorIndication",
    "16": "NASNonDeliveryIndication",
    "17": "S1Setup",
    "18": "UEContextReleaseRequest",
    "19": "DownlinkS1cdma2000tunnelling",
    "20": "UplinkS1cdma2000tunnelling",
    "21": "UEContextModification",
    "22": "UECapabilityInfoIndication",
    "23": "UEContextRelease",
    "24": "eNBStatusTransfer",
    "25": "MMEStatusTransfer",
    "26": "DeactivateTrace",
    "27": "TraceStart",
    "28": "TraceFailureIndication",
    "29": "ENBConfigurationUpdate",
    "30": "MMEConfigurationUpdate",
    "31": "LocationReportingControl",
    "32": "LocationReportingFailureIndication",
    "33": "LocationReport",
    "34": "OverloadStart",
    "35": "OverloadStop",
    "36": "WriteReplaceWarning",
    "37": "eNBDirectInformationTransfer",
    "38": "MMEDirectInformationTransfer",
    "39": "PrivateMessage",
    "40": "eNBConfigurationTransfer",
    "41": "MMEConfigurationTransfer",
    "42": "CellTrafficTrace",
}

# NGAP Procedure Code to Message Name Mapping (3GPP TS 38.413)
NGAP_PROCEDURE_CODES = {
    "0": "AMFConfigurationUpdate",
    "1": "AMFStatusIndication",
    "2": "CellTrafficTrace",
    "3": "DeactivateTrace",
    "4": "DownlinkNASTransport",
    "5": "DownlinkNonUEAssociatedNRPPaTransport",
    "6": "DownlinkRANConfigurationTransfer",
    "7": "DownlinkRANStatusTransfer",
    "8": "DownlinkUEAssociatedNRPPaTransport",
    "9": "ErrorIndication",
    "10": "HandoverCancel",
    "11": "HandoverNotification",
    "12": "HandoverPreparation",
    "13": "HandoverResourceAllocation",
    "14": "InitialContextSetup",
    "15": "InitialUEMessage",
    "16": "LocationReportingControl",
    "17": "LocationReportingFailureIndication",
    "18": "LocationReport",
    "19": "NASNonDeliveryIndication",
    "20": "NGReset",
    "21": "NGSetup",
    "22": "OverloadStart",
    "23": "OverloadStop",
    "24": "Paging",
    "25": "PathSwitchRequest",
    "26": "PDUSessionResourceModify",
    "27": "PDUSessionResourceModifyIndication",
    "28": "PDUSessionResourceRelease",
    "29": "PDUSessionResourceSetup",
    "30": "PDUSessionResourceNotify",
    "31": "PrivateMessage",
    "32": "PWSCancel",
    "33": "PWSFailureIndication",
    "34": "PWSRestartIndication",
    "35": "RANConfigurationUpdate",
    "36": "RerouteNASRequest",
    "37": "RRCInactiveTransitionReport",
    "38": "TraceFailureIndication",
    "39": "TraceStart",
    "40": "UEContextModification",
    "41": "UEContextRelease",
    "42": "UEContextReleaseRequest",
    "43": "UERadioCapabilityCheck",
    "44": "UERadioCapabilityInfoIndication",
    "45": "UETNLABindingRelease",
    "46": "UplinkNASTransport",
    "47": "UplinkNonUEAssociatedNRPPaTransport",
    "48": "UplinkRANConfigurationTransfer",
    "49": "UplinkRANStatusTransfer",
    "50": "UplinkUEAssociatedNRPPaTransport",
    "51": "WriteReplaceWarning",
}


def map_s1ap_procedure_code(code: str) -> str:
    """
    Map S1AP procedure code to readable message name.
    
    Args:
        code: S1AP procedure code (e.g., "9", "12")
    
    Returns:
        Human-readable message name or original code if not found
    """
    return S1AP_PROCEDURE_CODES.get(code, code)


def map_ngap_procedure_code(code: str) -> str:
    """
    Map NGAP procedure code to readable message name.
    
    Args:
        code: NGAP procedure code (e.g., "14", "15", "41")
    
    Returns:
        Human-readable message name or original code if not found
    """
    return NGAP_PROCEDURE_CODES.get(code, code)


# NAS-5GS MM Message Types (3GPP TS 24.501)
NAS_5GS_MM_MESSAGE_TYPES = {
    "65": "Registration request",
    "66": "Registration accept",
    "67": "Registration complete",
    "68": "Registration reject",
    "69": "Deregistration request (UE originating)",
    "70": "Deregistration accept (UE originating)",
    "71": "Deregistration request (UE terminated)",
    "72": "Deregistration accept (UE terminated)",
    "76": "Service request",
    "77": "Service reject",
    "78": "Service accept",
    "79": "Configuration update command",
    "80": "Configuration update complete",
    "81": "Authentication request",
    "82": "Authentication response",
    "83": "Authentication reject",
    "84": "Authentication failure",
    "85": "Authentication result",
    "86": "Identity request",
    "87": "Identity response",
    "93": "Security mode command",
    "94": "Security mode complete",
    "95": "Security mode reject",
    "100": "5GMM status",
    "101": "Notification",
    "102": "Notification response",
    "103": "UL NAS transport",
    "104": "DL NAS transport",
}

# NAS-5GS SM Message Types (3GPP TS 24.501)
NAS_5GS_SM_MESSAGE_TYPES = {
    "193": "PDU session establishment request",
    "194": "PDU session establishment accept",
    "195": "PDU session establishment reject",
    "197": "PDU session authentication command",
    "198": "PDU session authentication complete",
    "199": "PDU session authentication result",
    "201": "PDU session modification request",
    "202": "PDU session modification reject",
    "203": "PDU session modification command",
    "204": "PDU session modification complete",
    "205": "PDU session modification command reject",
    "209": "PDU session release request",
    "210": "PDU session release reject",
    "211": "PDU session release command",
    "212": "PDU session release complete",
    "214": "5GSM status",
}


def map_nas_5gs_message_type(msg_type: str, is_sm: bool = False) -> str:
    """
    Map NAS-5GS message type to readable name.
    
    Args:
        msg_type: NAS-5GS message type code
        is_sm: True if Session Management message, False if Mobility Management
    
    Returns:
        Human-readable message name or original code if not found
    """
    if is_sm:
        return NAS_5GS_SM_MESSAGE_TYPES.get(msg_type, msg_type)
    return NAS_5GS_MM_MESSAGE_TYPES.get(msg_type, msg_type)


def extract_ue_id(protocol_layers: List[ProtocolLayer]) -> Optional[str]:
    """
    Extract UE identifier from protocol layers.

    Priority order: 
    1. Control plane IDs (NGAP/S1AP UE IDs) - most stable for signaling analysis
    2. IMSI (global unique identifier)
    3. GUTI (global temporary ID)
    4. TMSI (temporary ID)
    5. RNTI (least stable, cell-specific)

    Args:
        protocol_layers: List of protocol layers from packet

    Returns:
        UE identifier or None
    """
    # PRIORITY 1: Try to extract NGAP UE IDs (5G control plane)
    # Only use RAN_UE_NGAP_ID (gNB-side identifier, stable throughout UE session)
    for layer in protocol_layers:
        if layer.protocol_name == "ngap":
            # Check for RAN_UE_NGAP_ID (most common in NGAP messages)
            ran_ue_id = layer.get_field("ngap.RAN_UE_NGAP_ID")
            if ran_ue_id:
                return str(ran_ue_id)
            
            # Fallback to nested field format
            ran_ue_id = layer.get_field("ngap.ngap.RAN_UE_NGAP_ID")
            if ran_ue_id:
                return str(ran_ue_id)

    # PRIORITY 2: Try to extract S1AP UE IDs (4G control plane)
    for layer in protocol_layers:
        if layer.protocol_name == "s1ap":
            # Check for ENB_UE_S1AP_ID (most common in S1AP messages)
            enb_ue_id = layer.get_field("s1ap.ENB_UE_S1AP_ID")
            if enb_ue_id:
                return str(enb_ue_id)
            
            # Fallback to nested field format
            enb_ue_id = layer.get_field("s1ap.s1ap.ENB_UE_S1AP_ID")
            if enb_ue_id:
                return str(enb_ue_id)
            
            # Try MME_UE_S1AP_ID as fallback
            mme_ue_id = layer.get_field("s1ap.MME_UE_S1AP_ID")
            if mme_ue_id:
                return str(mme_ue_id)
            
            mme_ue_id = layer.get_field("s1ap.s1ap.MME_UE_S1AP_ID")
            if mme_ue_id:
                return str(mme_ue_id)

    # PRIORITY 3: Try to extract IMSI (most stable identifier)
    for layer in protocol_layers:
        if layer.protocol_name in ["nas-eps", "nas-5gs", "gsm_a.gm"]:
            # Check for IMSI in NAS layer
            for field_name in ["nas_eps.emm.imsi", "nas_5gs.mm.imsi", "e212.imsi"]:
                imsi = layer.get_field(field_name)
                if imsi:
                    return f"IMSI:{imsi}"

    # PRIORITY 4: Try to extract GUTI
    for layer in protocol_layers:
        if layer.protocol_name in ["nas-eps", "nas-5gs"]:
            for field_name in ["nas_eps.emm.guti", "nas_5gs.mm.5g_guti"]:
                guti = layer.get_field(field_name)
                if guti:
                    return f"GUTI:{guti}"

    # PRIORITY 5: Try to extract TMSI
    for layer in protocol_layers:
        if layer.protocol_name in ["nas-eps", "gsm_a.gm"]:
            for field_name in ["nas_eps.emm.m_tmsi", "gsm_a.tmsi"]:
                tmsi = layer.get_field(field_name)
                if tmsi:
                    return f"TMSI:{tmsi}"

    # PRIORITY 6: Try to extract RNTI (least stable, cell-specific)
    for layer in protocol_layers:
        if layer.protocol_name == "rrc":
            for field_name in ["rrc.c_rnti", "lte-rrc.c_rnti", "nr-rrc.c_rnti"]:
                rnti = layer.get_field(field_name)
                if rnti:
                    return f"RNTI:{rnti}"

    return None


def extract_nas_message_name(protocol_layers: List[ProtocolLayer]) -> Optional[str]:
    """
    Extract NAS message name from NAS-5GS or NAS-EPS layers.
    
    Args:
        protocol_layers: List of protocol layers from packet
    
    Returns:
        NAS message name or None
    """
    for layer in protocol_layers:
        if layer.protocol_name == "nas-5gs":
            # Try MM message type first
            mm_msg_type = layer.get_field("nas_5gs.mm.message_type")
            if mm_msg_type:
                return map_nas_5gs_message_type(mm_msg_type, is_sm=False)
            
            # Try SM message type
            sm_msg_type = layer.get_field("nas_5gs.sm.message_type")
            if sm_msg_type:
                return map_nas_5gs_message_type(sm_msg_type, is_sm=True)
    
    return None


def extract_message_type(protocol_layers: List[ProtocolLayer]) -> Optional[str]:
    """
    Extract message type from protocol layers.

    Args:
        protocol_layers: List of protocol layers from packet

    Returns:
        Message type string or None
    """
    # Map protocol to message type field
    protocol_message_fields = {
        "rrc": ["rrc.messageType", "lte-rrc.messageType", "nr-rrc.messageType"],
        "nas-eps": ["nas-eps.nas_msg_emm_type", "nas-eps.nas_msg_esm_type"],
        "nas-5gs": ["nas_5gs.mm.message_type", "nas_5gs.sm.message_type"],
        "s1ap": ["s1ap.procedureCode"],
        "x2ap": ["x2ap.procedureCode"],
        "ngap": ["ngap.procedureCode"],
        "gtpv2": ["gtpv2.message_type"],
    }

    for layer in protocol_layers:
        proto_name = layer.protocol_name.lower()
        
        # Standard field extraction
        for key, field_names in protocol_message_fields.items():
            if key in proto_name:
                for field_name in field_names:
                    msg_type = layer.get_field(field_name)
                    if msg_type:
                        # Map S1AP/NGAP procedure codes to readable names
                        if key == "s1ap":
                            return map_s1ap_procedure_code(msg_type)
                        elif key == "ngap":
                            return map_ngap_procedure_code(msg_type)
                        return msg_type
        
        # Special handling for RRC: extract from *_element fields
        # RRC messages are identified by fields like "lte-rrc.rrcConnectionSetup_element"
        if proto_name == "rlc-lte":
            for field_name in layer.fields.keys():
                # Look for pattern: lte-rrc.<MessageName>_element or nr-rrc.<MessageName>_element
                if (field_name.startswith("lte-rrc.") or field_name.startswith("nr-rrc.")) and field_name.endswith("_element"):
                    # Extract message name (e.g., "lte-rrc.rrcConnectionSetup_element" -> "rrcConnectionSetup")
                    parts = field_name.split(".")
                    if len(parts) == 2:
                        message_name = parts[1].replace("_element", "")
                        # Skip generic/container fields
                        if message_name not in ["DL_CCCH_Message", "UL_CCCH_Message", "DL_DCCH_Message", "UL_DCCH_Message", 
                                                 "BCCH_BCH_Message", "BCCH_DL_SCH_Message", "PCCH_Message", "criticalExtensions"]:
                            return message_name

    return None


def extract_protocol(protocol_layers: List[ProtocolLayer]) -> Optional[str]:
    """
    Extract primary 3GPP protocol from packet.

    Classifies packet based on highest-level 3GPP protocol present.

    Args:
        protocol_layers: List of protocol layers from packet

    Returns:
        Protocol name (RRC/NAS/S1AP/X2AP/NGAP/GTP) or None
    """
    # Priority order for classification
    protocol_priority = [
        "rrc",
        "nas-5gs",
        "nas-eps",
        "s1ap",
        "x2ap",
        "ngap",
        "gtpv2",
        "diameter",
    ]

    for priority_proto in protocol_priority:
        for layer in protocol_layers:
            # Check protocol name
            if priority_proto in layer.protocol_name.lower():
                return priority_proto.upper().replace("-", "_")
            
            # Special case: RRC fields are often nested in rlc-lte layer
            if priority_proto == "rrc" and layer.protocol_name == "rlc-lte":
                # Check if this layer contains RRC fields (lte-rrc.* or nr-rrc.*)
                for field_name in layer.fields.keys():
                    if field_name.startswith("lte-rrc.") or field_name.startswith("nr-rrc."):
                        return "RRC"

    return None


def extract_interface(protocol_stack: List[str], ports: tuple) -> Optional[str]:
    """
    Infer 3GPP interface from protocol stack and ports.

    Common interfaces:
    - Uu: UE-eNB/gNB (RRC over RLC/MAC/PHY)
    - S1: eNB-MME (S1AP) or eNB-SGW (GTP-U)
    - X2: eNB-eNB (X2AP)
    - N1: UE-AMF (NAS over N1)
    - N2: gNB-AMF (NGAP)
    - N3: gNB-UPF (GTP-U)

    Args:
        protocol_stack: List of protocol names
        ports: Tuple of (source_port, destination_port)

    Returns:
        Interface name or None
    """
    protocol_stack_lower = [p.lower() for p in protocol_stack]

    # Check for Uu interface (air interface)
    if "rrc" in protocol_stack_lower or "rlc" in protocol_stack_lower:
        return "Uu"

    # Check for S1 interface (S1AP or GTP-U)
    if "s1ap" in protocol_stack_lower:
        return "S1-MME"
    if "gtpv2" in protocol_stack_lower or "gtp" in protocol_stack_lower:
        # Check ports to distinguish S1-U from other GTP interfaces
        if ports and (2152 in ports):  # GTP-U port
            return "S1-U"
        if ports and (2123 in ports):  # GTP-C port
            return "S11"

    # Check for X2 interface
    if "x2ap" in protocol_stack_lower:
        return "X2"

    # Check for NG interfaces (5G)
    if "ngap" in protocol_stack_lower:
        return "N2"
    if "nas-5gs" in protocol_stack_lower:
        return "N1"

    # Check for SBI (HTTP/2 based)
    if "http2" in protocol_stack_lower:
        return "SBI"

    return None


def extract_direction(protocol_layers: List[ProtocolLayer]) -> Optional[str]:
    """
    Extract message direction (uplink/downlink).

    Args:
        protocol_layers: List of protocol layers from packet

    Returns:
        'UL' (uplink), 'DL' (downlink), or None
    """
    # Check RRC direction
    for layer in protocol_layers:
        if "rrc" in layer.protocol_name.lower():
            direction_field = layer.get_field("rrc.direction")
            if direction_field:
                if "uplink" in direction_field.lower() or "ul" in direction_field.lower():
                    return "UL"
                elif "downlink" in direction_field.lower() or "dl" in direction_field.lower():
                    return "DL"

    # Check NAS direction
    for layer in protocol_layers:
        if "nas" in layer.protocol_name.lower():
            # NAS messages have implicit direction based on message type
            msg_type = extract_message_type([layer])
            if msg_type:
                # Common uplink messages
                uplink_msgs = [
                    "attach request",
                    "registration request",
                    "service request",
                    "authentication response",
                ]
                # Common downlink messages
                downlink_msgs = [
                    "attach accept",
                    "attach reject",
                    "registration accept",
                    "authentication request",
                ]

                msg_lower = msg_type.lower()
                if any(ul_msg in msg_lower for ul_msg in uplink_msgs):
                    return "UL"
                if any(dl_msg in msg_lower for dl_msg in downlink_msgs):
                    return "DL"

    return None
