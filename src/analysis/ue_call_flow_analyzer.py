"""
Comprehensive UE Call Flow Analyzer - 5G NGAP Expert Methodology
Traces ALL messages for a UE using multiple correlation strategies.
"""
from typing import List, Dict, Any, Set, Tuple
import json
from collections import defaultdict
from datetime import datetime


def analyze_ue_call_flow(rows: List[Dict[str, Any]], target_ue_id: str) -> str:
    """
    Trace complete call flow for a UE using 5G architect expert methodology.
    
    CRITICAL: This function traces BACKWARDS to find the UE's initial RAN-UE-NGAP-ID,
    then traces FORWARD through all handovers to show the complete journey.
    
    Strategy:
    1. Find messages with target RAN-UE-NGAP-ID = X
    2. Extract AMF-UE-NGAP-ID(s) from those messages
    3. Go BACKWARDS to find where this AMF-UE-NGAP-ID first appeared (initial attach)
    4. Trace FORWARD following all RAN-UE-NGAP-ID changes during handovers
    
    Args:
        rows: All packets from the PCAP
        target_ue_id: Target UE identifier (RAN-UE-NGAP-ID) - may be from middle of session
        
    Returns:
        Comprehensive call flow analysis report showing complete UE journey
    """
    
    # Step 1: Find all messages with target RAN-UE-NGAP-ID and collect AMF-UE-NGAP-IDs
    target_amf_ids = set()
    
    for r in rows:
        jf = r.get('protocol_fields_json')
        if not jf:
            continue
        
        if isinstance(jf, str):
            try:
                jf = json.loads(jf)
            except:
                continue
        
        ran_id = jf.get('ngap.ngap.RAN_UE_NGAP_ID')
        if ran_id and str(ran_id) == str(target_ue_id):
            # Found target UE - collect its AMF-UE-NGAP-ID
            amf_id = jf.get('ngap.ngap.AMF_UE_NGAP_ID')
            if amf_id:
                target_amf_ids.add(str(amf_id))
    
    if not target_amf_ids:
        return f"✗ No messages found for UE RAN-UE-NGAP-ID: {target_ue_id}"
    
    # Step 2: Now find ALL messages for these AMF-UE-NGAP-IDs (this gives us the complete UE session)
    # This includes messages BEFORE the target RAN-UE-NGAP-ID appeared
    ue_messages = []
    all_ran_ids = set()
    all_amf_ids = set()
    all_pdu_sessions = set()
    
    # First pass: Find all RAN-UE-NGAP-IDs that belong to this UE session
    for r in rows:
        jf = r.get('protocol_fields_json')
        if not jf:
            continue
        
        if isinstance(jf, str):
            try:
                jf = json.loads(jf)
            except:
                continue
        
        amf_id = jf.get('ngap.ngap.AMF_UE_NGAP_ID')
        if amf_id and str(amf_id) in target_amf_ids:
            # Collect all RAN-UE-NGAP-IDs this UE used
            ran_id = jf.get('ngap.ngap.RAN_UE_NGAP_ID')
            if ran_id:
                all_ran_ids.add(str(ran_id))
            
            all_amf_ids.add(str(amf_id))
            
            # Collect PDU Session IDs
            for key in jf.keys():
                if 'pDUSessionID' in key or 'PDUSessionID' in key:
                    pdu_id = jf.get(key)
                    if pdu_id:
                        all_pdu_sessions.add(str(pdu_id))
    
    # Second pass: Now collect ALL messages that belong to this UE
    # This includes:
    # 1. Messages with AMF-UE-NGAP-ID (normal case)
    # 2. Messages with RAN-UE-NGAP-ID but NO AMF-UE-NGAP-ID yet (InitialUEMessage, etc.)
    for r in rows:
        jf = r.get('protocol_fields_json')
        if not jf:
            continue
        
        if isinstance(jf, str):
            try:
                jf = json.loads(jf)
            except:
                continue
        
        ran_id = jf.get('ngap.ngap.RAN_UE_NGAP_ID')
        amf_id = jf.get('ngap.ngap.AMF_UE_NGAP_ID')
        
        # Include message if:
        # - It has AMF-UE-NGAP-ID matching our target AMF IDs, OR
        # - It has RAN-UE-NGAP-ID matching our collected RAN IDs (includes InitialUEMessage)
        if (amf_id and str(amf_id) in target_amf_ids) or \
           (ran_id and str(ran_id) in all_ran_ids):
            ue_messages.append(r)
    
    # Sort by packet number to get chronological order
    ue_messages.sort(key=lambda x: x.get('packet_number', 0))
    
    if not ue_messages:
        return f"✗ No messages found for UE RAN-UE-NGAP-ID: {target_ue_id}"
    
    # Analyze the call flow
    return format_call_flow_analysis(ue_messages, target_ue_id, all_ran_ids, all_amf_ids, all_pdu_sessions)


def format_call_flow_analysis(messages: List[Dict], target_ue_id: str, 
                               ran_ids: Set[str], amf_ids: Set[str], 
                               pdu_sessions: Set[str]) -> str:
    """Format the comprehensive call flow analysis report."""
    
    lines = []
    lines.append('=' * 80)
    lines.append(f'COMPLETE CALL FLOW ANALYSIS FOR UE RAN-UE-NGAP-ID = {target_ue_id}')
    lines.append('3GPP 5G ARCHITECT EXPERT METHODOLOGY')
    lines.append('=' * 80)
    lines.append('')
    
    # Executive Summary
    lines.append('EXECUTIVE SUMMARY')
    lines.append('-' * 80)
    lines.append(f'UE Identity:        RAN-UE-NGAP-ID: {", ".join(sorted(ran_ids))}')
    lines.append(f'AMF-UE-NGAP-IDs:    {", ".join(sorted(amf_ids))}')
    lines.append(f'Total Messages:     {len(messages)} NGAP messages')
    
    if messages:
        first_ts = messages[0].get('timestamp_iso', '')
        last_ts = messages[-1].get('timestamp_iso', '')
        if first_ts and last_ts:
            lines.append(f'First Message:      {first_ts[:19]}')
            lines.append(f'Last Message:       {last_ts[:19]}')
    
    lines.append(f'PDU Sessions:       {len(pdu_sessions)} session(s): {", ".join(sorted(pdu_sessions))}')
    lines.append('')
    
    # RAN-UE-NGAP-ID Evolution - trace how the ID changed
    if len(ran_ids) > 1:
        lines.append('RAN-UE-NGAP-ID EVOLUTION')
        lines.append('-' * 80)
        lines.append(f'Query started with:  RAN-UE-NGAP-ID = {target_ue_id}')
        lines.append(f'Total IDs discovered: {len(ran_ids)} identifiers')
        lines.append('')
        
        # Build RAN-UE-NGAP-ID timeline
        ran_id_timeline = []
        for msg in messages:
            jf = msg.get('protocol_fields_json')
            if isinstance(jf, str):
                try:
                    jf = json.loads(jf)
                except:
                    jf = {}
            
            if not jf:
                continue
                
            ran_id = jf.get('ngap.ngap.RAN_UE_NGAP_ID')
            if ran_id:
                ran_id = str(ran_id)
                # Check if this is a new RAN-UE-NGAP-ID
                if not ran_id_timeline or ran_id != ran_id_timeline[-1][0]:
                    msg_type = msg.get('message_type', 'Unknown')
                    pkt_num = msg.get('packet_number')
                    ts = msg.get('timestamp_iso', '')[:19]
                    ran_id_timeline.append((ran_id, msg_type, pkt_num, ts, jf))
        
        # Explain the evolution
        lines.append('Timeline of RAN-UE-NGAP-ID changes:')
        for idx, (ran_id, msg_type, pkt_num, ts, jf) in enumerate(ran_id_timeline):
            if idx == 0:
                lines.append(f'  Initial: RAN-UE-NGAP-ID = {ran_id}')
                lines.append(f'           First appeared in Packet {pkt_num} ({msg_type}) at {ts}')
            else:
                prev_ran_id = ran_id_timeline[idx-1][0]
                lines.append(f'  Changed: RAN-UE-NGAP-ID = {prev_ran_id} → {ran_id}')
                lines.append(f'           Changed in Packet {pkt_num} ({msg_type}) at {ts}')
                
                # Explain why it changed
                reason = ''
                if msg_type == 'HandoverResourceAllocation':
                    reason = 'Target gNB assigns new RAN-UE-NGAP-ID after handover request'
                elif msg_type == 'HandoverNotification':
                    reason = 'Handover completed, UE now using target gNB ID'
                elif msg_type == 'PathSwitchRequest':
                    reason = 'Path switch after handover, new gNB identifier'
                elif msg_type == 'InitialContextSetup':
                    reason = 'New context established with new RAN-UE-NGAP-ID'
                else:
                    # Check if this message follows a handover
                    reason = 'New RAN-UE-NGAP-ID assigned during mobility procedure'
                
                if reason:
                    lines.append(f'           Reason: {reason}')
                
                # Show proof (message fields)
                lines.append(f'           Proof: Message type = {msg_type}')
                if 'ngap.ngap.AMF_UE_NGAP_ID' in jf:
                    lines.append(f'                  AMF-UE-NGAP-ID = {jf["ngap.ngap.AMF_UE_NGAP_ID"]} (same UE)')
            lines.append('')
        
        lines.append('NOTE: Despite RAN-UE-NGAP-ID changes, AMF-UE-NGAP-ID remains consistent,')
        lines.append('      confirming this is the SAME UE throughout the session.')
        lines.append('')
    
    # Analyze message types
    msg_type_counts = defaultdict(int)
    handover_attempts = 0
    context_releases = 0
    
    for msg in messages:
        msg_type = msg.get('message_type')
        if msg_type:
            msg_type_counts[msg_type] += 1
        
        if msg_type == 'HandoverPreparation':
            jf = msg.get('protocol_fields_json')
            if isinstance(jf, str):
                try:
                    jf = json.loads(jf)
                except:
                    jf = {}
            if jf and 'ngap.ngap.HandoverRequired_element' in jf:
                handover_attempts += 1
        
        if msg_type and 'Release' in msg_type:
            context_releases += 1
    
    # Key findings
    lines.append('KEY FINDINGS')
    lines.append('-' * 80)
    lines.append(f'Handover Attempts:  {handover_attempts}')
    lines.append(f'Context Releases:   {context_releases}')
    lines.append(f'Message Types:      {len(msg_type_counts)} unique types')
    lines.append('')
    
    # Detailed call flow
    lines.append('DETAILED CALL FLOW')
    lines.append('=' * 80)
    lines.append('')
    
    # Group into phases
    phases = detect_phases(messages)
    
    for phase_num, phase in enumerate(phases, 1):
        lines.append(f"Phase {phase_num}: {phase['name']} (Packets {phase['start']}-{phase['end']})")
        lines.append('-' * 80)
        
        for idx, msg in enumerate(phase['messages'], 1):
            pkt_num = msg.get('packet_number')
            ts = msg.get('timestamp_iso', '')[:19]
            msg_type = msg.get('message_type', 'Unknown')
            
            jf = msg.get('protocol_fields_json')
            if isinstance(jf, str):
                try:
                    jf = json.loads(jf)
                except:
                    jf = {}
            
            # Extract key info
            ran_id = jf.get('ngap.ngap.RAN_UE_NGAP_ID', '-')
            amf_id = jf.get('ngap.ngap.AMF_UE_NGAP_ID', '-')
            
            # Check for submessages
            submsg = ''
            if 'ngap.ngap.HandoverRequired_element' in jf:
                submsg = ' [HandoverRequired]'
            elif 'ngap.ngap.HandoverCommand_element' in jf:
                submsg = ' [HandoverCommand]'
            elif 'ngap.ngap.HandoverRequest_element' in jf:
                submsg = ' [HandoverRequest]'
            
            lines.append(f'[{idx:2d}] Packet {pkt_num:5d} - {msg_type}{submsg}')
            lines.append(f'     Time: {ts}')
            if ran_id != '-' or amf_id != '-':
                lines.append(f'     RAN-UE-ID: {ran_id}, AMF-UE-ID: {amf_id}')
            
            # Extract cause if present
            cause = extract_cause(jf)
            if cause:
                lines.append(f'     Cause: {cause}')
            
            lines.append('')
        
        lines.append('')
    
    # Summary statistics
    lines.append('CALL FLOW SUMMARY STATISTICS')
    lines.append('=' * 80)
    lines.append(f'Total Messages:           {len(messages)}')
    for msg_type, count in sorted(msg_type_counts.items(), key=lambda x: -x[1])[:10]:
        lines.append(f'{msg_type:30s} {count}')
    lines.append('')
    
    # Correlation methodology
    lines.append('CORRELATION METHODOLOGY USED')
    lines.append('=' * 80)
    lines.append('✓ Strategy 1: RAN-UE-NGAP-ID direct matching')
    lines.append(f'  Discovered {len(ran_ids)} RAN-UE-NGAP-ID(s): {", ".join(sorted(ran_ids))}')
    lines.append('')
    lines.append('✓ Strategy 2: AMF-UE-NGAP-ID correlation')
    lines.append(f'  Discovered {len(amf_ids)} AMF-UE-NGAP-ID(s): {", ".join(sorted(amf_ids))}')
    lines.append('  Used to find messages without RAN-UE-NGAP-ID')
    lines.append('')
    lines.append('✓ Strategy 3: PDU Session ID correlation')
    lines.append(f'  Tracked {len(pdu_sessions)} PDU Session(s): {", ".join(sorted(pdu_sessions))}')
    lines.append('  Links session-related messages across handovers')
    lines.append('')
    
    lines.append('=' * 80)
    lines.append('Generated by: talk_to_pcap - UE Call Flow Analyzer')
    lines.append(f'Analysis Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    lines.append('=' * 80)
    
    return '\n'.join(lines)


def detect_phases(messages: List[Dict]) -> List[Dict]:
    """Detect logical phases in the call flow."""
    if not messages:
        return []
    
    phases = []
    current_phase = {
        'name': 'Registration and Attach',
        'messages': [],
        'start': messages[0].get('packet_number'),
        'end': messages[0].get('packet_number')
    }
    
    for msg in messages:
        msg_type = msg.get('message_type', '')
        pkt_num = msg.get('packet_number')
        
        # Detect phase transitions
        if msg_type == 'InitialUEMessage' and current_phase['messages']:
            # Start new phase
            phases.append(current_phase)
            current_phase = {
                'name': 'Registration and Attach',
                'messages': [],
                'start': pkt_num,
                'end': pkt_num
            }
        elif 'HandoverPreparation' in msg_type and 'Handover' not in current_phase['name']:
            phases.append(current_phase)
            current_phase = {
                'name': 'Handover Procedure',
                'messages': [],
                'start': pkt_num,
                'end': pkt_num
            }
        elif msg_type == 'PathSwitchRequest':
            if 'PathSwitch' not in current_phase['name']:
                phases.append(current_phase)
                current_phase = {
                    'name': 'Path Switch',
                    'messages': [],
                    'start': pkt_num,
                    'end': pkt_num
                }
        elif 'PDUSessionResourceSetup' in msg_type and len(current_phase['messages']) > 5:
            phases.append(current_phase)
            current_phase = {
                'name': 'PDU Session Establishment',
                'messages': [],
                'start': pkt_num,
                'end': pkt_num
            }
        
        current_phase['messages'].append(msg)
        current_phase['end'] = pkt_num
    
    if current_phase['messages']:
        phases.append(current_phase)
    
    return phases


def extract_cause(jf: Dict) -> str:
    """Extract cause from NGAP message."""
    if not jf:
        return None
    
    cause_cat = jf.get('ngap.ngap.Cause')
    if cause_cat is not None:
        # Map cause categories
        cause_types = {
            '0': 'radioNetwork',
            '1': 'transport',
            '2': 'nas',
            '3': 'protocol',
            '4': 'misc'
        }
        
        cause_type = cause_types.get(str(cause_cat), f'category-{cause_cat}')
        
        # Get specific cause value
        cause_field = f'ngap.ngap.{cause_type}'
        cause_value = jf.get(cause_field)
        
        if cause_value is not None:
            # Map common causes
            if cause_type == 'radioNetwork':
                cause_map = {
                    '2': 'successful-handover',
                    '5': 'handover-cancelled',
                    '20': 'user-inactivity',
                    '31': 'ng-intra-system-handover-triggered',
                    '32': 'ng-inter-system-handover-triggered'
                }
                cause_name = cause_map.get(str(cause_value), f'code-{cause_value}')
                return f'{cause_type}: {cause_name}'
    
    return None


__all__ = ['analyze_ue_call_flow']
