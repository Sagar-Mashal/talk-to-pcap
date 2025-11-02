"""NGAP UE release and failure analysis (generic, heuristic-based).

This module inspects packets table rows (protocol_fields_json) to derive:
- Unique UE counts (RAN_UE_NGAP_ID / AMF_UE_NGAP_ID)
- Release related events (UE Context Release Request / Command, etc.)
- Cause codes / textual causes where present
- Classification of causes into normal vs abnormal categories (heuristics)

Design Principles:
- Generic: no hard-coded numeric IDs beyond recognized NGAP procedure codes published in 3GPP (but kept as a mapping dictionary)
- Extensible: adding new cause categories only requires adjusting heuristics sets
- Resilient: tolerant of partial captures (mid-session start) and multiple releases per UE
- Works on any parquet produced by pipeline (expects packets table with protocol_fields_json)

Procedure Code Reference (subset used):
4  DownlinkNASTransport
29 PDUSessionResourceSetup
14 InitialContextSetup
21 UEContextRelease           (successfulOutcome / initiatingMessage variants)

We derive release events from:
- presence of UEContextRelease* procedure
- JSON keys containing release cause fields (e.g., ngap.ngap.Cause.*)
- textual indicators ("release" in message_type)

Failure vs Normal Heuristics:
Normal keywords: inactivity, mobility, handover, deregister, normal
Abnormal keywords: redirect, redirection, unsuccessful, failure, triggered (without success), timeout

Outputs a structured dict suitable for formatting.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Set, Optional, Tuple

NORMAL_KEYWORDS = {"inactivity","mobility","handover","deregister","normal"}
ABNORMAL_KEYWORDS = {"redirect","redirection","unsuccessful","failure","triggered","timeout"}

# Map NGAP procedure codes to names (minimal, generic)
PROCEDURE_MAP = {
    "4": "DownlinkNASTransport",
    "14": "InitialContextSetup",
    "15": "InitialUEMessage",
    "21": "UEContextRelease",
    "29": "PDUSessionResourceSetup",
    # Additional codes can be added here generically.
}

# NGAP Cause values according to 3GPP TS 38.413
# Cause group: 0=radioNetwork, 1=transport, 2=nas, 3=protocol, 4=misc
NGAP_RADIO_NETWORK_CAUSES = {
    "0": "unspecified",
    "1": "txnrelocoverall-expiry",
    "2": "successful-handover",
    "3": "release-due-to-ngran-generated-reason",
    "4": "release-due-to-5gc-generated-reason",
    "5": "handover-cancelled",
    "6": "partial-handover",
    "7": "ho-failure-in-target-5GC-ngran-node-or-target-system",
    "8": "ho-target-not-allowed",
    "9": "tngrelocoverall-expiry",
    "10": "tngrelocprep-expiry",
    "11": "cell-not-available",
    "12": "unknown-targetID",
    "13": "no-radio-resources-available-in-target-cell",
    "14": "unknown-local-UE-NGAP-ID",
    "15": "inconsistent-remote-UE-NGAP-ID",
    "16": "handover-desirable-for-radio-reason",
    "17": "time-critical-handover",
    "18": "resource-optimisation-handover",
    "19": "reduce-load-in-serving-cell",
    "20": "user-inactivity",
    "21": "radio-connection-with-ue-lost",
    "22": "radio-resources-not-available",
    "23": "invalid-qos-combination",
    "24": "failure-in-radio-interface-procedure",
    "25": "interaction-with-other-procedure",
    "26": "unknown-PDU-session-ID",
    "27": "unkown-qos-flow-ID",
    "28": "multiple-PDU-session-ID-instances",
    "29": "multiple-qos-flow-ID-instances",
    "30": "encryption-and-or-integrity-protection-algorithms-not-supported",
    "31": "ng-intra-system-handover-triggered",
    "32": "ng-inter-system-handover-triggered",
    "33": "xn-handover-triggered",
    "34": "not-supported-5QI-value",
    "35": "ue-context-transfer",
    "36": "ims-voice-eps-fallback-or-rat-fallback-triggered",
    "37": "up-integrity-protection-not-possible",
    "38": "up-confidentiality-protection-not-possible",
    "39": "slice-not-supported",
    "40": "ue-in-rrc-inactive-state-not-reachable",
    "41": "redirection",
    "42": "resources-not-available-for-the-slice",
    "43": "ue-max-integrity-protected-data-rate-reason",
    "44": "release-due-to-cn-detected-mobility",
    "45": "n26-interface-not-available",
    "46": "release-due-to-pre-emption",
}

NGAP_TRANSPORT_CAUSES = {
    "0": "transport-resource-unavailable",
    "1": "unspecified",
}

NGAP_NAS_CAUSES = {
    "0": "normal-release",
    "1": "authentication-failure",
    "2": "deregister",
    "3": "unspecified",
}

NGAP_PROTOCOL_CAUSES = {
    "0": "transfer-syntax-error",
    "1": "abstract-syntax-error-reject",
    "2": "abstract-syntax-error-ignore-and-notify",
    "3": "message-not-compatible-with-receiver-state",
    "4": "semantic-error",
    "5": "abstract-syntax-error-falsely-constructed-message",
    "6": "unspecified",
}

NGAP_MISC_CAUSES = {
    "0": "control-processing-overload",
    "1": "not-enough-user-plane-processing-resources",
    "2": "hardware-failure",
    "3": "om-intervention",
    "4": "unknown-PLMN",
    "5": "unspecified",
}

@dataclass
class ReleaseEvent:
    ran_ue_id: Optional[str]
    amf_ue_id: Optional[str]
    packet_number: Optional[int]
    procedure_name: Optional[str]
    cause_raw: Optional[str]
    cause_category: Optional[str]
    normal: bool

@dataclass
class AnalysisResult:
    unique_ran_ids: Set[str] = field(default_factory=set)
    unique_amf_ids: Set[str] = field(default_factory=set)
    initial_ue_msgs: int = 0
    release_events: List[ReleaseEvent] = field(default_factory=list)

    def to_summary_dict(self) -> Dict[str, Any]:
        total_releases = len(self.release_events)
        normal_events = [e for e in self.release_events if e.normal]
        abnormal_events = [e for e in self.release_events if not e.normal]
        # Count categories and track UE IDs
        category_counts: Dict[str,int] = {}
        category_ues: Dict[str,List[str]] = {}
        for e in self.release_events:
            if e.cause_category:
                category_counts[e.cause_category] = category_counts.get(e.cause_category,0)+1
                if e.cause_category not in category_ues:
                    category_ues[e.cause_category] = []
                if e.ran_ue_id:
                    category_ues[e.cause_category].append(e.ran_ue_id)
        return {
            "ue_counts": {
                "ran_total": len(self.unique_ran_ids),
                "ran_ids": sorted(self.unique_ran_ids),
                "amf_total": len(self.unique_amf_ids),
            },
            "initial_ue_messages": self.initial_ue_msgs,
            "release_stats": {
                "total_releases": total_releases,
                "normal_count": len(normal_events),
                "abnormal_count": len(abnormal_events),
                "normal_pct": (len(normal_events)/total_releases*100.0) if total_releases else 0.0,
                "abnormal_pct": (len(abnormal_events)/total_releases*100.0) if total_releases else 0.0,
            },
            "categories": category_counts,
            "category_ues": category_ues,
            "release_events": [e.__dict__ for e in self.release_events],
            "effective_failure_rate_pct": (len(abnormal_events)/max(1,len(self.unique_ran_ids))*100.0) if self.unique_ran_ids else 0.0,
        }

def classify_cause(text: str) -> Tuple[str,bool]:
    tl = text.lower()
    # Determine category name for grouping (first matching keyword or fallback generic)
    for kw in ABNORMAL_KEYWORDS:
        if kw in tl:
            return kw, False
    for kw in NORMAL_KEYWORDS:
        if kw in tl:
            return kw, True
    # Fallback heuristic: treat unknown cause containing 'release' but no normal keyword as abnormal if it also has 'triggered'
    if 'triggered' in tl and 'success' not in tl:
        return 'triggered', False
    return 'other', True  # Default to normal to avoid false alarms

def analyze_packets(rows: List[Dict[str,Any]]) -> AnalysisResult:
    result = AnalysisResult()
    for r in rows:
        pfj = r.get('protocol_fields_json')
        if not pfj:
            continue
        try:
            jf = json.loads(pfj) if isinstance(pfj,str) else pfj
        except Exception:
            continue
        ran_id = jf.get('ngap.ngap.RAN_UE_NGAP_ID') or jf.get('RAN_UE_NGAP_ID') or jf.get('ngap.RAN_UE_NGAP_ID')
        amf_id = jf.get('ngap.ngap.AMF_UE_NGAP_ID') or jf.get('AMF_UE_NGAP_ID') or jf.get('ngap.AMF_UE_NGAP_ID')
        if ran_id:
            result.unique_ran_ids.add(str(ran_id))
        if amf_id:
            result.unique_amf_ids.add(str(amf_id))
        
        # Count InitialUEMessage occurrences using procedureCode or message_type
        mt = r.get('message_type')
        proc_code = jf.get('ngap.ngap.procedureCode') or jf.get('procedureCode') or jf.get('ngap.procedureCode')
        
        # Check if this is InitialUEMessage (procedure code 15 or text match or JSON key)
        is_initial_ue = False
        if str(mt) == '15' or str(proc_code) == '15':
            is_initial_ue = True
        elif mt and 'initialuemessage' in str(mt).lower():
            is_initial_ue = True
        else:
            # Check JSON keys for InitialUEMessage_element or similar
            for k in jf.keys():
                if 'initialuemessage' in k.lower():
                    is_initial_ue = True
                    break
        
        if is_initial_ue:
            result.initial_ue_msgs += 1
        
        proc_name = PROCEDURE_MAP.get(str(proc_code), None)
        # Release detection heuristics
        # Consider UEContextRelease procedure or JSON keys containing 'release' and a cause element
        has_release = False
        if proc_name == 'UEContextRelease':
            has_release = True
        else:
            # Fallback textual detection
            for k in jf.keys():
                if 'release' in k.lower() and ('uecontext' in k.lower() or 'ue_context' in k.lower()):
                    has_release = True
                    break
        if not has_release:
            continue
        # Extract NGAP Cause per 3GPP TS 38.413
        # NGAP Cause structure: ngap.ngap.Cause (category) + ngap.ngap.{categoryName} (value)
        cause_text = None
        cause_category = jf.get("ngap.ngap.Cause")
        
        if cause_category is not None:
            # Map category to specific cause field and mapping table
            if cause_category == 0 or cause_category == "0":
                # radioNetwork cause
                cause_value = jf.get("ngap.ngap.radioNetwork")
                if cause_value is not None:
                    cause_text = NGAP_RADIO_NETWORK_CAUSES.get(str(cause_value), f"radioNetwork-{cause_value}")
            elif cause_category == 1 or cause_category == "1":
                # transport cause
                cause_value = jf.get("ngap.ngap.transport")
                if cause_value is not None:
                    cause_text = NGAP_TRANSPORT_CAUSES.get(str(cause_value), f"transport-{cause_value}")
            elif cause_category == 2 or cause_category == "2":
                # nas cause
                cause_value = jf.get("ngap.ngap.nas")
                if cause_value is not None:
                    cause_text = NGAP_NAS_CAUSES.get(str(cause_value), f"nas-{cause_value}")
            elif cause_category == 3 or cause_category == "3":
                # protocol cause
                cause_value = jf.get("ngap.ngap.protocol")
                if cause_value is not None:
                    cause_text = NGAP_PROTOCOL_CAUSES.get(str(cause_value), f"protocol-{cause_value}")
            elif cause_category == 4 or cause_category == "4":
                # misc cause
                cause_value = jf.get("ngap.ngap.misc")
                if cause_value is not None:
                    cause_text = NGAP_MISC_CAUSES.get(str(cause_value), f"misc-{cause_value}")
        
        # Fallback: search for string cause fields (legacy support)
        if not cause_text:
            for k,v in jf.items():
                if 'cause' in k.lower() and isinstance(v,str):
                    cause_text = v
                    break
        
        # Try nested textual hints as last resort
        if not cause_text:
            for k,v in jf.items():
                if isinstance(v,str) and any(w in v.lower() for w in ['inactivity','mobility','handover','redirect','failure','triggered','timeout','deregister']):
                    cause_text = v
                    break
        
        if not cause_text:
            cause_text = 'unspecified'
        category, normal = classify_cause(cause_text)
        result.release_events.append(ReleaseEvent(
            ran_ue_id=str(ran_id) if ran_id else None,
            amf_ue_id=str(amf_id) if amf_id else None,
            packet_number=r.get('packet_number'),
            procedure_name=proc_name,
            cause_raw=cause_text,
            cause_category=category,
            normal=normal,
        ))
    return result

def format_summary(result: AnalysisResult) -> str:
    d = result.to_summary_dict()
    lines = []
    lines.append('● 5G NGAP Log Analysis - Summary')
    lines.append('')
    lines.append('  UE Connection Summary')
    lines.append(f"  Total UEs Connected: {d['ue_counts']['ran_total']} unique UEs (by RAN-UE-NGAP-ID)")
    lines.append(f"  - RAN-UE-NGAP-IDs: {', '.join(d['ue_counts']['ran_ids']) if d['ue_counts']['ran_ids'] else 'None'}")
    lines.append(f"  - AMF-UE-NGAP-IDs: {d['ue_counts']['amf_total']} unique identifiers")
    lines.append(f"  - Initial UE Messages detected: {d['initial_ue_messages']} (capture may start mid-session)")
    lines.append('')
    total_rel = d['release_stats']['total_releases']
    lines.append('  UE Release Statistics')
    lines.append(f"  Total Release Events: {total_rel}")
    lines.append(f"  Normal Releases: {d['release_stats']['normal_count']} ({d['release_stats']['normal_pct']:.1f}% of releases)")
    lines.append(f"  Abnormal Releases: {d['release_stats']['abnormal_count']} ({d['release_stats']['abnormal_pct']:.1f}% of releases)")
    lines.append('')
    lines.append('  Release Causes Breakdown')
    # Aggregate categories with normal/abnormal classification
    cat_bucket: Dict[str, Dict[str,int]] = {}
    cat_ues: Dict[str, List[str]] = {}
    for ev in result.release_events:
        cat = ev.cause_category or 'other'
        bucket = cat_bucket.setdefault(cat,{"normal":0,"abnormal":0})
        if ev.normal:
            bucket['normal'] += 1
        else:
            bucket['abnormal'] += 1
        # Track UE IDs per category
        if cat not in cat_ues:
            cat_ues[cat] = []
        if ev.ran_ue_id:
            cat_ues[cat].append(ev.ran_ue_id)
    
    for cat, counts in sorted(cat_bucket.items(), key=lambda x: (-(x[1]['normal']+x[1]['abnormal']))):
        total_cat = counts['normal'] + counts['abnormal']
        pct = (total_cat/total_rel*100.0) if total_rel else 0
        ue_list = ', '.join(cat_ues.get(cat, []))
        lines.append(f"  - {cat}: {total_cat} releases ({pct:.1f}%)")
        lines.append(f"    UE IDs: [{ue_list}]")
    lines.append('')
    fail_rate = d['effective_failure_rate_pct']
    status = 'OK' if fail_rate < 50 else ('ELEVATED' if fail_rate < 100 else 'HIGH')
    lines.append('  Call Failure Analysis')
    lines.append(f"  - Effective Call Failure Rate: {fail_rate:.1f}% ({d['release_stats']['abnormal_count']} abnormal releases / {d['ue_counts']['ran_total']} UEs)")
    lines.append(f"  - Status: {status}")
    lines.append('  - Note: Values are heuristic; multiple abnormal events per UE will push rate >100%.')
    return '\n'.join(lines)


def analyze_ue_detailed(rows: List[Dict[str,Any]], target_ue_id: str) -> str:
    """
    Perform detailed analysis for a specific UE by RAN-UE-NGAP-ID.
    
    Args:
        rows: List of packet rows from parquet table
        target_ue_id: The RAN-UE-NGAP-ID to analyze
        
    Returns:
        Formatted detailed analysis string for the specific UE
    """
    # Track all packets for this UE
    ue_packets = []
    ue_procedures = []
    ue_releases = []
    
    for r in rows:
        jf = r.get('protocol_fields_json')
        if not jf:
            continue
        
        if isinstance(jf, str):
            try:
                jf = json.loads(jf)
            except:
                continue
        
        # Check if this packet belongs to our target UE
        ran_id = jf.get('ngap.ngap.RAN_UE_NGAP_ID')
        if str(ran_id) != str(target_ue_id):
            continue
        
        # This packet belongs to our UE
        packet_info = {
            'packet_number': r.get('packet_number'),
            'message_type': r.get('message_type'),
            'proc_code': jf.get('ngap.ngap.procedureCode'),
            'json_fields': jf
        }
        ue_packets.append(packet_info)
        
        # Track procedures
        proc_code = jf.get('ngap.ngap.procedureCode')
        proc_name = PROCEDURE_MAP.get(str(proc_code), f"Procedure-{proc_code}")
        if proc_code:
            ue_procedures.append({
                'packet': r.get('packet_number'),
                'procedure': proc_name,
                'code': proc_code
            })
        
        # Check for release events
        has_release = False
        for k in jf.keys():
            if 'release' in k.lower() and ('uecontext' in k.lower() or 'ue_context' in k.lower()):
                has_release = True
                break
        
        if has_release:
            # Extract cause
            cause_text = None
            cause_category_val = jf.get("ngap.ngap.Cause")
            
            if cause_category_val is not None:
                if cause_category_val == 0 or cause_category_val == "0":
                    cause_value = jf.get("ngap.ngap.radioNetwork")
                    if cause_value is not None:
                        cause_text = NGAP_RADIO_NETWORK_CAUSES.get(str(cause_value), f"radioNetwork-{cause_value}")
                elif cause_category_val == 1 or cause_category_val == "1":
                    cause_value = jf.get("ngap.ngap.transport")
                    if cause_value is not None:
                        cause_text = NGAP_TRANSPORT_CAUSES.get(str(cause_value), f"transport-{cause_value}")
                elif cause_category_val == 2 or cause_category_val == "2":
                    cause_value = jf.get("ngap.ngap.nas")
                    if cause_value is not None:
                        cause_text = NGAP_NAS_CAUSES.get(str(cause_value), f"nas-{cause_value}")
                elif cause_category_val == 3 or cause_category_val == "3":
                    cause_value = jf.get("ngap.ngap.protocol")
                    if cause_value is not None:
                        cause_text = NGAP_PROTOCOL_CAUSES.get(str(cause_value), f"protocol-{cause_value}")
                elif cause_category_val == 4 or cause_category_val == "4":
                    cause_value = jf.get("ngap.ngap.misc")
                    if cause_value is not None:
                        cause_text = NGAP_MISC_CAUSES.get(str(cause_value), f"misc-{cause_value}")
            
            if not cause_text:
                cause_text = "unspecified"
            
            category, is_normal = classify_cause(cause_text)
            
            ue_releases.append({
                'packet': r.get('packet_number'),
                'cause': cause_text,
                'category': category,
                'normal': is_normal,
                'release_type': 'Request' if 'request' in str(jf.keys()).lower() else ('Command' if 'command' in str(jf.keys()).lower() else 'Complete')
            })
    
    # Format the detailed report
    lines = []
    lines.append(f'● Detailed UE Analysis - RAN-UE-NGAP-ID: {target_ue_id}')
    lines.append('')
    
    if not ue_packets:
        lines.append('  No packets found for this UE ID.')
        return '\n'.join(lines)
    
    lines.append(f'  Total Packets: {len(ue_packets)}')
    lines.append(f'  Procedures Detected: {len(ue_procedures)}')
    lines.append(f'  Release Events: {len(ue_releases)}')
    lines.append('')
    
    # Show procedures
    if ue_procedures:
        lines.append('  NGAP Procedures Timeline:')
        for proc in ue_procedures:
            lines.append(f"    Packet {proc['packet']:5d}: {proc['procedure']}")
        lines.append('')
    
    # Show releases in detail
    if ue_releases:
        lines.append('  Release Events Analysis:')
        for rel in ue_releases:
            status_str = 'NORMAL' if rel['normal'] else 'ABNORMAL'
            lines.append(f"    Packet {rel['packet']:5d}: {rel['release_type']}")
            lines.append(f"      Cause: {rel['cause']}")
            lines.append(f"      Category: {rel['category']}")
            lines.append(f"      Status: {status_str}")
            lines.append('')
        
        # Failure analysis
        abnormal_releases = [r for r in ue_releases if not r['normal']]
        normal_releases = [r for r in ue_releases if r['normal']]
        
        lines.append('  Call Failure Analysis:')
        if abnormal_releases:
            lines.append(f"    ⚠ FAILURES DETECTED: {len(abnormal_releases)} abnormal release(s)")
            lines.append('    Failure Reasons:')
            for rel in abnormal_releases:
                lines.append(f"      - {rel['cause']} (Packet {rel['packet']})")
            lines.append('')
            lines.append('    Recommendation: Investigate network conditions, radio link quality,')
            lines.append('    and core network connectivity at the time of failure.')
        else:
            lines.append(f"    ✓ No failures detected. {len(normal_releases)} normal release(s).")
            if normal_releases:
                lines.append('    Normal Release Reasons:')
                for rel in normal_releases:
                    lines.append(f"      - {rel['cause']} (Packet {rel['packet']})")
        lines.append('')
        
        # Provide 3GPP context for causes
        if ue_releases:
            lines.append('  3GPP Cause Interpretation:')
            for rel in ue_releases:
                cause = rel['cause']
                if 'user-inactivity' in cause:
                    lines.append('    • user-inactivity: UE became idle after inactivity timer expiry (normal behavior)')
                elif 'deregister' in cause:
                    lines.append('    • deregister: UE initiated detach/deregistration (user or device action)')
                elif 'normal-release' in cause:
                    lines.append('    • normal-release: Standard call/session termination procedure')
                elif 'handover' in cause or 'ng-inter-system-handover-triggered' in cause or 'ng-intra-system-handover-triggered' in cause:
                    lines.append('    • handover: UE moved to different cell/system (mobility procedure)')
                elif 'radio-connection-with-ue-lost' in cause:
                    lines.append('    • radio-connection-with-ue-lost: Radio link failure - possible coverage issue')
                elif 'authentication-failure' in cause:
                    lines.append('    • authentication-failure: Security authentication failed - check SIM/credentials')
                elif 'failure' in cause:
                    lines.append(f"    • {cause}: Indicates a failure condition requiring investigation")
    else:
        lines.append('  No release events found for this UE.')
    
    return '\n'.join(lines)


def analyze_handover_failures(rows: List[Dict[str,Any]]) -> str:
    """
    Analyze handover failures across all UEs.
    
    Identifies UEs with handover-related issues including:
    - handover-cancelled
    - partial-handover
    - ho-failure-in-target-5GC-ngran-node-or-target-system
    - ho-target-not-allowed
    
    Args:
        rows: List of packet rows from parquet table
        
    Returns:
        Formatted analysis string with handover failure details per UE
    """
    # Handover failure cause codes (radioNetwork category)
    HO_FAILURE_CAUSES = {
        "5": "handover-cancelled",
        "6": "partial-handover", 
        "7": "ho-failure-in-target-5GC-ngran-node-or-target-system",
        "8": "ho-target-not-allowed",
    }
    
    # Handover success/normal mobility causes
    HO_SUCCESS_CAUSES = {
        "2": "successful-handover",
        "16": "handover-desirable-for-radio-reason",
        "17": "time-critical-handover",
        "18": "resource-optimisation-handover",
        "31": "ng-intra-system-handover-triggered",
        "32": "ng-inter-system-handover-triggered",
        "33": "xn-handover-triggered",
    }
    
    # Track UE handover events
    ue_handovers = {}  # {ran_ue_id: {'failures': [], 'successes': [], 'packets': []}}
    
    for r in rows:
        jf = r.get('protocol_fields_json')
        if not jf:
            continue
        
        if isinstance(jf, str):
            try:
                jf = json.loads(jf)
            except:
                continue
        
        # Get UE ID
        ran_id = jf.get('ngap.ngap.RAN_UE_NGAP_ID')
        if not ran_id:
            continue
        
        # Check for release events (handover-related or not)
        has_release = False
        for k in jf.keys():
            if 'release' in k.lower() and ('uecontext' in k.lower() or 'ue_context' in k.lower()):
                has_release = True
                break
        
        if not has_release:
            continue
        
        # Extract cause
        cause_cat = jf.get('ngap.ngap.Cause')
        if cause_cat != 0 and cause_cat != "0":
            continue  # Only interested in radioNetwork causes
        
        cause_value = jf.get('ngap.ngap.radioNetwork')
        if cause_value is None:
            continue
        
        cause_str = str(cause_value)
        
        # Initialize UE tracking
        if str(ran_id) not in ue_handovers:
            ue_handovers[str(ran_id)] = {'failures': [], 'successes': [], 'packets': []}
        
        # Classify the handover event
        if cause_str in HO_FAILURE_CAUSES:
            ue_handovers[str(ran_id)]['failures'].append({
                'packet': r.get('packet_number'),
                'cause': NGAP_RADIO_NETWORK_CAUSES.get(cause_str, f"radioNetwork-{cause_str}"),
                'cause_code': cause_str
            })
            ue_handovers[str(ran_id)]['packets'].append(r.get('packet_number'))
        elif cause_str in HO_SUCCESS_CAUSES:
            ue_handovers[str(ran_id)]['successes'].append({
                'packet': r.get('packet_number'),
                'cause': NGAP_RADIO_NETWORK_CAUSES.get(cause_str, f"radioNetwork-{cause_str}"),
                'cause_code': cause_str
            })
            ue_handovers[str(ran_id)]['packets'].append(r.get('packet_number'))
    
    # Format output
    lines = []
    lines.append('● Handover Failure Analysis')
    lines.append('')
    
    # Count UEs with failures
    ues_with_failures = {ue_id: data for ue_id, data in ue_handovers.items() if data['failures']}
    ues_with_ho_only = {ue_id: data for ue_id, data in ue_handovers.items() if data['successes'] and not data['failures']}
    
    if not ue_handovers:
        lines.append('  No handover events detected in this capture.')
        lines.append('')
        lines.append('  Note: This analysis looks for NGAP radioNetwork causes related to handover procedures.')
        lines.append('  If the capture does not contain handover attempts, no results will be shown.')
        return '\n'.join(lines)
    
    lines.append(f'  Total UEs with Handover Events: {len(ue_handovers)}')
    lines.append(f'  UEs with Handover Failures: {len(ues_with_failures)}')
    lines.append(f'  UEs with Successful Handovers: {len(ues_with_ho_only)}')
    lines.append('')
    
    if ues_with_failures:
        lines.append('  Handover Failures by UE:')
        lines.append('')
        for ue_id in sorted(ues_with_failures.keys(), key=lambda x: int(x) if x.isdigit() else 0):
            data = ues_with_failures[ue_id]
            lines.append(f'  RAN-UE-NGAP-ID: {ue_id}')
            lines.append(f'    Failure Count: {len(data["failures"])}')
            lines.append(f'    Success Count: {len(data["successes"])}')
            lines.append('')
            
            lines.append('    Failure Details:')
            for failure in data['failures']:
                lines.append(f'      Packet {failure["packet"]:5d}: {failure["cause"]}')
            
            if data['successes']:
                lines.append('')
                lines.append('    Successful Handovers:')
                for success in data['successes']:
                    lines.append(f'      Packet {success["packet"]:5d}: {success["cause"]}')
            
            lines.append('')
            
            # Provide cause-specific interpretation
            for failure in data['failures']:
                cause = failure['cause']
                if 'cancelled' in cause:
                    lines.append('    ⚠ handover-cancelled: Handover procedure was cancelled before completion.')
                    lines.append('      Possible reasons: Network congestion, target cell unavailable, UE moved out of range.')
                elif 'partial' in cause:
                    lines.append('    ⚠ partial-handover: Only some bearers/PDU sessions were handed over.')
                    lines.append('      Possible reasons: Target cell lacks resources for all sessions, QoS constraints.')
                elif 'ho-failure' in cause:
                    lines.append('    ⚠ ho-failure-in-target: Handover failed at the target gNB or core network.')
                    lines.append('      Possible reasons: Target cell overload, configuration mismatch, X2/Xn interface issues.')
                elif 'ho-target-not-allowed' in cause:
                    lines.append('    ⚠ ho-target-not-allowed: Handover to target cell is not permitted.')
                    lines.append('      Possible reasons: Access restrictions, roaming policies, cell barring.')
            
            lines.append('')
        
        lines.append('  Recommendations:')
        lines.append('    1. Check target cell availability and resource allocation')
        lines.append('    2. Verify X2/Xn interface connectivity between gNBs')
        lines.append('    3. Review handover parameters (thresholds, timers, hysteresis)')
        lines.append('    4. Analyze radio conditions at handover decision point')
        lines.append('    5. Check for cell access restrictions or barring')
        lines.append('')
    else:
        lines.append('  ✓ No Handover Failures Detected')
        lines.append('')
        if ues_with_ho_only:
            lines.append(f'  All {len(ues_with_ho_only)} UE(s) with handover events completed successfully:')
            for ue_id in sorted(ues_with_ho_only.keys(), key=lambda x: int(x) if x.isdigit() else 0):
                data = ues_with_ho_only[ue_id]
                lines.append(f'    UE {ue_id}: {len(data["successes"])} successful handover(s)')
                for success in data['successes']:
                    lines.append(f'      Packet {success["packet"]}: {success["cause"]}')
            lines.append('')
    
    return '\n'.join(lines)


def analyze_ue_message(rows: List[Dict[str,Any]], ue_id: str, message_type: str) -> str:
    """
    Check if a specific UE has a specific message type.
    
    Args:
        rows: List of packet rows from parquet table
        ue_id: Target UE identifier (RAN-UE-NGAP-ID)
        message_type: Message type to search for (e.g., 'HandoverNotification', 'InitialContextSetup')
        
    Returns:
        Formatted analysis string indicating if UE has the message
    """
    import json
    
    # Normalize message type for flexible matching
    # Remove spaces, hyphens, underscores and convert to lowercase
    msg_search = message_type.lower().replace(' ', '').replace('-', '').replace('_', '')
    
    # Track all packets for this UE
    ue_packets = []
    matching_packets = []
    
    for r in rows:
        jf = r.get('protocol_fields_json')
        if not jf:
            continue
        
        if isinstance(jf, str):
            try:
                jf = json.loads(jf)
            except:
                continue
        
        # Get UE ID
        ran_id = jf.get('ngap.ngap.RAN_UE_NGAP_ID')
        if not ran_id or str(ran_id) != str(ue_id):
            continue
        
        # This packet belongs to the UE
        pkt_num = r.get('packet_number')
        pkt_msg_type = r.get('message_type')
        ue_packets.append({
            'packet': pkt_num,
            'message': pkt_msg_type,
            'timestamp': r.get('timestamp_iso')
        })
        
        # Check if message type matches (flexible matching)
        # Two levels: 1) Top-level message type, 2) Submessage elements (e.g., HandoverCommand inside HandoverPreparation)
        match = False
        matched_submessage = None
        
        if pkt_msg_type:
            pkt_msg_normalized = pkt_msg_type.lower().replace(' ', '').replace('-', '').replace('_', '')
            
            # Match if:
            # 1. Exact substring match (either direction)
            if msg_search in pkt_msg_normalized or pkt_msg_normalized in msg_search:
                match = True
            # 2. Significant prefix overlap (at least 80% of shorter string matches)
            elif len(msg_search) > 5 or len(pkt_msg_normalized) > 5:
                shorter_len = min(len(msg_search), len(pkt_msg_normalized))
                # Check if first N chars match (allowing minor differences at end)
                match_threshold = int(shorter_len * 0.8)
                match = (msg_search[:match_threshold] == pkt_msg_normalized[:match_threshold] or
                        pkt_msg_normalized[:match_threshold] == msg_search[:match_threshold])
        
        # Also check for submessages in JSON fields (e.g., HandoverCommand_element, HandoverRequired_element)
        if not match and jf:
            # Look for fields like "ngap.ngap.HandoverCommand_element", "ngap.ngap.HandoverRequired_element"
            for field_key in jf.keys():
                if '_element' in field_key or 'Transfer' in field_key:
                    # Extract the message name from field like "ngap.ngap.HandoverCommand_element"
                    field_normalized = field_key.lower().replace('.', '').replace('ngap', '').replace('_element', '').replace('_', '').replace('-', '')
                    
                    # Check if search term matches this field
                    if msg_search in field_normalized or field_normalized in msg_search:
                        match = True
                        # Extract readable name: "ngap.ngap.HandoverCommand_element" -> "HandoverCommand"
                        if '.' in field_key:
                            matched_submessage = field_key.split('.')[-1].replace('_element', '')
                        break
                    
                    # Also check with prefix matching
                    if len(msg_search) > 5 or len(field_normalized) > 5:
                        shorter_len = min(len(msg_search), len(field_normalized))
                        match_threshold = int(shorter_len * 0.8)
                        if (msg_search[:match_threshold] == field_normalized[:match_threshold] or
                            field_normalized[:match_threshold] == msg_search[:match_threshold]):
                            match = True
                            if '.' in field_key:
                                matched_submessage = field_key.split('.')[-1].replace('_element', '')
                            break
        
        if match:
            display_msg = f"{pkt_msg_type} ({matched_submessage})" if matched_submessage else pkt_msg_type
            matching_packets.append({
                'packet': pkt_num,
                'message': display_msg,
                'timestamp': r.get('timestamp_iso')
            })
    
    # Format output
    lines = []
    lines.append(f'● UE Message Query')
    lines.append('')
    lines.append(f'  UE ID: {ue_id}')
    lines.append(f'  Message Type: {message_type}')
    lines.append('')
    
    if not ue_packets:
        lines.append(f'  ✗ UE {ue_id} not found in this capture.')
        lines.append('')
        lines.append('  Note: This UE may not exist or may not have any NGAP messages.')
        return '\n'.join(lines)
    
    if matching_packets:
        lines.append(f'  ✓ YES - UE {ue_id} has {len(matching_packets)} "{message_type}" message(s)')
        lines.append('')
        lines.append('  Matching Packets:')
        for match in matching_packets:
            timestamp_str = match['timestamp'][:23] if match['timestamp'] else 'N/A'
            lines.append(f'    Packet {match["packet"]:5d}  {timestamp_str}  {match["message"]}')
    else:
        lines.append(f'  ✗ NO - UE {ue_id} does NOT have "{message_type}" message')
    
    lines.append('')
    lines.append(f'  Total packets for UE {ue_id}: {len(ue_packets)}')
    
    # Show all message types for this UE
    if ue_packets:
        lines.append('')
        lines.append(f'  All messages for UE {ue_id}:')
        for pkt in sorted(ue_packets, key=lambda x: x['packet']):
            lines.append(f'    Packet {pkt["packet"]:5d}: {pkt["message"]}')
    
    return '\n'.join(lines)


__all__ = ["analyze_packets", "format_summary", "analyze_ue_detailed", "analyze_handover_failures", "analyze_ue_message"]
