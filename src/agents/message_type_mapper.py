"""
Central mapping for 3GPP message types to their numeric codes.
This helps in pre-processing natural language queries to guide the LLM.
"""

# Maps various spellings/names to a canonical name and its code
MESSAGE_TYPE_MAP = {
    # S1AP Messages (with multiple spelling variations)
    "s1 setup request": ("S1 Setup Request", "18"),
    "s1setuprequest": ("S1 Setup Request", "18"),
    "s1 setup response": ("S1 Setup Response", "17"),
    "s1setupresponse": ("S1 Setup Response", "17"),
    "initial context setup request": ("Initial Context Setup Request", "9"),
    "initialcontextsetuprequest": ("Initial Context Setup Request", "9"),
    "initial context setup response": ("Initial Context Setup Response", "10"),
    "initialcontextsetupresponse": ("Initial Context Setup Response", "10"),
    "ue context release command": ("UE Context Release Command", "23"),
    "uecontextreleasecommand": ("UE Context Release Command", "23"),
    "ue context release complete": ("UE Context Release Complete", "24"),
    "uecontextreleasecomplete": ("UE Context Release Complete", "24"),
    "mme configuration update": ("MME Configuration Update", "30"),
    "mmeconfigurationupdate": ("MME Configuration Update", "30"),
    "handover request": ("Handover Request", "0"),
    "handoverrequest": ("Handover Request", "0"),
    "handover command": ("Handover Command", "1"),
    "handovercommand": ("Handover Command", "1"),
    "handover failure": ("Handover Failure", "4"),
    "handoverfailure": ("Handover Failure", "4"),
    "handover required": ("Handover Required", "HandoverPreparation"),
    "handoverrequired": ("Handover Required", "HandoverPreparation"),
    # CamelCase variant sometimes produced by LLM
    "handoverRequired": ("Handover Required", "HandoverPreparation"),
    "handover preparation": ("Handover Preparation", "HandoverPreparation"),
    "handoverpreparation": ("Handover Preparation", "HandoverPreparation"),
    "HandoverPreparation": ("Handover Preparation", "HandoverPreparation"),
    "handover resource allocation": ("Handover Resource Allocation", "HandoverResourceAllocation"),
    "handoverresourceallocation": ("Handover Resource Allocation", "HandoverResourceAllocation"),
    "HandoverResourceAllocation": ("Handover Resource Allocation", "HandoverResourceAllocation"),

    # NAS-EPS Messages (with multiple spelling variations)
    "attach request": ("Attach Request", "65"),
    "attachrequest": ("Attach Request", "65"),
    "attach accept": ("Attach Accept", "66"),
    "attachaccept": ("Attach Accept", "66"),
    "attach reject": ("Attach Reject", "67"),
    "attachreject": ("Attach Reject", "67"),
    "detach request": ("Detach Request", "69"),
    "detachrequest": ("Detach Request", "69"),
    "detach accept": ("Detach Accept", "70"),
    "detachaccept": ("Detach Accept", "70"),
    "tracking area update request": ("Tracking Area Update Request", "72"),
    "trackingareaupdaterequest": ("Tracking Area Update Request", "72"),
    "tracking area update accept": ("Tracking Area Update Accept", "73"),
    "trackingareaupdateaccept": ("Tracking Area Update Accept", "73"),
    "tracking area update reject": ("Tracking Area Update Reject", "74"),
    "trackingareaupdatereject": ("Tracking Area Update Reject", "74"),
    "authentication request": ("Authentication Request", "82"),
    "authenticationrequest": ("Authentication Request", "82"),
    "authentication response": ("Authentication Response", "83"),
    "authenticationresponse": ("Authentication Response", "83"),
    "authentication failure": ("Authentication Failure", "92"),
    "authenticationfailure": ("Authentication Failure", "92"),
    "security mode command": ("Security Mode Command", "93"),
    "securitymodecommand": ("Security Mode Command", "93"),
    "security mode complete": ("Security Mode Complete", "94"),
    "securitymodecomplete": ("Security Mode Complete", "94"),
    "security mode reject": ("Security Mode Reject", "95"),
    "securitymodereject": ("Security Mode Reject", "95"),

    # LTE RRC Messages (Note: RRC uses camelCase in message_type column)
    "rrc connection request": ("RRC Connection Request", "rrcConnectionRequest"),
    "rrcconnectionrequest": ("RRC Connection Request", "rrcConnectionRequest"),
    "rrc connection setup": ("RRC Connection Setup", "rrcConnectionSetup"),
    "rrcconnectionsetup": ("RRC Connection Setup", "rrcConnectionSetup"),
    "rrc connection setup complete": ("RRC Connection Setup Complete", "rrcConnectionSetupComplete"),
    "rrcconnectionsetupcomplete": ("RRC Connection Setup Complete", "rrcConnectionSetupComplete"),
    "rrc connection release": ("RRC Connection Release", "rrcConnectionRelease"),
    "rrcconnectionrelease": ("RRC Connection Release", "rrcConnectionRelease"),
    "rrc connection reconfiguration": ("RRC Connection Reconfiguration", "rrcConnectionReconfiguration"),
    "rrcconnectionreconfiguration": ("RRC Connection Reconfiguration", "rrcConnectionReconfiguration"),
    "rrc connection reconfiguration complete": ("RRC Connection Reconfiguration Complete", "rrcConnectionReconfigurationComplete"),
    "rrcconnectionreconfigurationcomplete": ("RRC Connection Reconfiguration Complete", "rrcConnectionReconfigurationComplete"),
    "measurement report": ("Measurement Report", "measurementReport"),
    "measurementreport": ("Measurement Report", "measurementReport"),
    "security mode command": ("Security Mode Command", "securityModeCommand"),
    "securitymodecommand": ("Security Mode Command", "securityModeCommand"),
    "security mode complete": ("Security Mode Complete", "securityModeComplete"),
    "securitymodecomplete": ("Security Mode Complete", "securityModeComplete"),
    "system information": ("System Information", "systemInformation"),
    "systeminformation": ("System Information", "systemInformation"),
    "paging": ("Paging", "paging"),
}

def preprocess_query_for_message_types(query: str) -> str:
    """
    Scans a query for known message type names and injects a hint for the LLM.

    Args:
        query: The user's natural language query.

    Returns:
        The query with an appended hint if a match is found.
    """
    query_lower = query.lower()
    for keyword, (canonical_name, code) in MESSAGE_TYPE_MAP.items():
        if keyword in query_lower:
            # This hint is very explicit to force the LLM's behavior
            hint = f" (Hint: The user mentioned '{keyword}', which refers to the '{canonical_name}' message. You MUST use `message_type = '{code}'` in the WHERE clause of your SQL query.)"
            return query + hint
    return query

