"""LLM-powered 5G NGAP release cause analysis generator.

This module uses Gemini LLM to generate detailed expert-level analysis
of UE release causes, matching Claude's analysis format. Unlike the deterministic
ngap_release_analyzer, this module passes structured release data to the LLM
and prompts it to generate insights based on 3GPP specifications.

The LLM generates:
- Release cause breakdown with percentages
- Normal/Abnormal classification with expert insights
- Connection behavior statistics
- Call failure rate assessment
- Recommendations for abnormal releases

Design Principles:
- Domain knowledge embedded in prompts (3GPP TS 38.413 NGAP cause codes)
- LLM generates narrative analysis, not hardcoded logic
- Structured data passed to LLM for context
- Few-shot examples guide output format
"""
from __future__ import annotations
import json
import logging
from typing import Dict, List, Any
import google.generativeai as genai
from src.config import config

logger = logging.getLogger(__name__)

# 3GPP TS 38.413 NGAP Cause Values Knowledge Base
NGAP_CAUSE_KNOWLEDGE = """
=== 3GPP TS 38.413 NGAP Cause Values ===

Radio Network Causes (Cause group 0):
- user-inactivity (20): NORMAL - UE entered RRC_IDLE after inactivity timer expiry
- successful-handover (2): NORMAL - UE successfully handed over to another cell
- release-due-to-cn-detected-mobility (44): NORMAL - Core Network initiated release for mobility management
- ng-intra-system-handover-triggered (31): NORMAL - 5G intra-system handover initiated
- ng-inter-system-handover-triggered (32): NORMAL - Inter-system handover (5G to 4G/3G)
- xn-handover-triggered (33): NORMAL - Xn interface handover
- release-due-to-ngran-generated-reason (3): NORMAL - RAN-initiated release (various reasons)
- release-due-to-5gc-generated-reason (4): NORMAL - Core network-initiated release

- redirection (41): ABNORMAL - Target cell admission control failure or redirection issue
- radio-connection-with-ue-lost (21): ABNORMAL - Radio link failure, coverage issue
- handover-cancelled (5): ABNORMAL - Handover procedure cancelled
- partial-handover (6): ABNORMAL - Handover partially completed
- ho-failure-in-target-5GC-ngran-node-or-target-system (7): ABNORMAL - Handover failed at target
- ho-target-not-allowed (8): ABNORMAL - Handover target not permitted
- no-radio-resources-available-in-target-cell (13): ABNORMAL - Resource shortage at target
- cell-not-available (11): ABNORMAL - Target cell unavailable
- failure-in-radio-interface-procedure (24): ABNORMAL - Radio procedure failed

NAS Causes (Cause group 2):
- normal-release (0): NORMAL - Standard NAS release
- deregister (3): NORMAL - UE deregistration (user or network initiated)
- authentication-failure (1): ABNORMAL - Security authentication failed
- detach (2): NORMAL - Standard detach procedure

Transport Causes (Cause group 1):
- transport-resource-unavailable (0): ABNORMAL - NG interface transport issue
- unspecified (1): ABNORMAL - Transport layer problem

Protocol Causes (Cause group 3):
- transfer-syntax-error (0): ABNORMAL - Protocol encoding issue
- abstract-syntax-error-reject (1): ABNORMAL - Protocol message rejected
- message-not-compatible-with-receiver-state (2): ABNORMAL - Protocol state mismatch

Misc Causes (Cause group 4):
- control-processing-overload (0): ABNORMAL - Network overload
- not-enough-user-plane-processing-resources (1): ABNORMAL - Resource exhaustion
- hardware-failure (2): ABNORMAL - Hardware fault
"""

ANALYSIS_PROMPT_TEMPLATE = """You are an expert 5G network architect analyzing NGAP (5G core network) logs for UE release causes and call failures.

{cause_knowledge}

## STRUCTURED DATA FROM PCAP:

{structured_data}

## YOUR TASK:

Generate a detailed expert analysis report matching this EXACT format:

================================================================================
5G NGAP LOG ANALYSIS - 5G ARCHITECT VIEW
================================================================================

SUMMARY:
- Total UEs Connected (InitialUEMessage): {initial_ue_count}
- Unique UEs by RAN-UE-NGAP-ID: {ran_ue_count}
- Unique UEs by AMF-UE-NGAP-ID: {amf_ue_count}
- Total Release Events: {total_releases}

RELEASE CAUSE ANALYSIS:
- List each cause with count and percentage
- Format: "Radio Network: user-inactivity: 8 occurrences (22.2%)"

5G ARCHITECT ANALYSIS:

1. UE CONNECTION BEHAVIOR:
   - Summarize connection attempts and unique UE identifiers
   - Note any discrepancies or interesting patterns

2. UE RELEASE PATTERN:
   - Breakdown of Release Requests vs Commands
   - Release procedure ratio

3. DETAILED CAUSE ANALYSIS:
   - Total Normal Releases: X (XX.X%)
   - Total Abnormal Releases: Y (YY.Y%)
   
   For EACH cause, provide:
   [NORMAL/ABNORMAL] Cause Name: Count
            Classification reason
            Insight: Expert explanation of what this means

   Classification Rules:
   - NORMAL: user-inactivity, successful-handover, deregister, normal-release, cn-detected-mobility, handover-triggered (all variants), release-due-to-ngran/5gc-generated-reason
   - ABNORMAL: redirection, radio-connection-lost, handover-cancelled, handover-failure, authentication-failure, transport/protocol/misc causes

4. CALL FAILURE ASSESSMENT:
   - Calculate: (abnormal releases / unique UEs) × 100%
   - Status: OK (<50%), ELEVATED (50-99%), HIGH (≥100%)
   - Provide assessment based on failure rate

5. RECOMMENDATIONS:
   - Highlight positive findings (normal releases)
   - Provide ACTION ITEMS for abnormal releases with specific troubleshooting steps

CRITICAL REQUIREMENTS:
1. Use EXACT cause names from structured data (do not invent causes)
2. Calculate percentages correctly: (cause_count / total_releases) × 100
3. Classify causes strictly according to 3GPP knowledge base above
4. Provide actionable insights for each cause type
5. Be concise but technically precise
6. Use expert telecom terminology

Generate the analysis report now:
"""

def generate_llm_analysis(release_data: Dict[str, Any], ue_data: Dict[str, Any]) -> str:
    """
    Generate detailed 5G release cause analysis using Gemini LLM.
    
    Args:
        release_data: Dictionary containing release event details:
            - total_releases: int
            - release_events: List[Dict] with cause, category, normal flag
            - normal_count: int
            - abnormal_count: int
        ue_data: Dictionary containing UE connection statistics:
            - initial_ue_messages: int
            - ran_ue_ids: List[str]
            - amf_ue_ids: List[str]
            - ran_total: int
            - amf_total: int
    
    Returns:
        Formatted analysis string generated by LLM
    """
    try:
        # Aggregate release causes for structured data
        cause_breakdown = {}
        for event in release_data.get('release_events', []):
            cause = event.get('cause_raw', 'unspecified')
            category = event.get('cause_category', 'unknown')
            normal = event.get('normal', False)
            
            key = f"{category}: {cause}"
            if key not in cause_breakdown:
                cause_breakdown[key] = {
                    'count': 0,
                    'normal': normal,
                    'category': category,
                    'cause': cause
                }
            cause_breakdown[key]['count'] += 1
        
        # Sort by count descending
        sorted_causes = sorted(
            cause_breakdown.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )
        
        # Format structured data for LLM
        structured_data = {
            'ue_statistics': {
                'initial_ue_messages': ue_data.get('initial_ue_messages', 0),
                'unique_ran_ue_ids': ue_data.get('ran_total', 0),
                'unique_amf_ue_ids': ue_data.get('amf_total', 0),
                'ran_id_list': ', '.join(ue_data.get('ran_ids', [])) if ue_data.get('ran_ids') else 'None',
                'amf_id_list': ', '.join(str(x) for x in ue_data.get('amf_ids', [])) if ue_data.get('amf_ids') else 'None',
            },
            'release_statistics': {
                'total_releases': release_data.get('total_releases', 0),
                'normal_releases': release_data.get('normal_count', 0),
                'abnormal_releases': release_data.get('abnormal_count', 0),
                'normal_percentage': (release_data.get('normal_count', 0) / release_data.get('total_releases', 1) * 100) if release_data.get('total_releases', 0) > 0 else 0,
                'abnormal_percentage': (release_data.get('abnormal_count', 0) / release_data.get('total_releases', 1) * 100) if release_data.get('total_releases', 0) > 0 else 0,
            },
            'cause_breakdown': [
                {
                    'cause_name': item[1]['cause'],
                    'cause_category': item[1]['category'],
                    'count': item[1]['count'],
                    'percentage': (item[1]['count'] / release_data.get('total_releases', 1) * 100) if release_data.get('total_releases', 0) > 0 else 0,
                    'classification': 'NORMAL' if item[1]['normal'] else 'ABNORMAL'
                }
                for item in sorted_causes
            ]
        }
        
        # Construct prompt
        prompt = ANALYSIS_PROMPT_TEMPLATE.format(
            cause_knowledge=NGAP_CAUSE_KNOWLEDGE,
            structured_data=json.dumps(structured_data, indent=2),
            initial_ue_count=ue_data.get('initial_ue_messages', 0),
            ran_ue_count=ue_data.get('ran_total', 0),
            amf_ue_count=ue_data.get('amf_total', 0),
            total_releases=release_data.get('total_releases', 0)
        )
        
        # Call Gemini API
        logger.info("Calling Gemini API for 5G release cause analysis...")
        
        # Initialize Gemini model
        genai.configure(api_key=config.GEMINI_API_KEY)
        model = genai.GenerativeModel(
            model_name=config.GEMINI_MODEL,
            generation_config={
                "temperature": config.GEMINI_TEMPERATURE,
                "max_output_tokens": config.GEMINI_MAX_OUTPUT_TOKENS,
            },
        )
        
        response = model.generate_content(prompt)
        
        if not response or not response.text:
            logger.error("Empty response from Gemini API")
            return _fallback_analysis(release_data, ue_data)
        
        analysis_text = response.text.strip()
        
        # Validate response contains expected sections
        required_sections = ['SUMMARY', 'RELEASE CAUSE ANALYSIS', '5G ARCHITECT ANALYSIS']
        missing_sections = [s for s in required_sections if s not in analysis_text]
        
        if missing_sections:
            logger.warning(f"LLM response missing sections: {missing_sections}")
            # Still return the response, as it may have partial content
        
        logger.info("Successfully generated LLM-powered release cause analysis")
        return analysis_text
        
    except Exception as e:
        logger.error(f"LLM analysis generation failed: {e}")
        return _fallback_analysis(release_data, ue_data)


def _fallback_analysis(release_data: Dict[str, Any], ue_data: Dict[str, Any]) -> str:
    """
    Generate simple fallback analysis when LLM fails.
    
    This is a minimal hardcoded fallback, not the primary analysis path.
    """
    lines = []
    lines.append("=" * 80)
    lines.append("5G NGAP RELEASE ANALYSIS - FALLBACK MODE")
    lines.append("=" * 80)
    lines.append("")
    lines.append("⚠ LLM-powered analysis unavailable. Showing basic statistics:")
    lines.append("")
    lines.append(f"Total UEs: {ue_data.get('ran_total', 0)}")
    lines.append(f"Total Releases: {release_data.get('total_releases', 0)}")
    lines.append(f"Normal Releases: {release_data.get('normal_count', 0)}")
    lines.append(f"Abnormal Releases: {release_data.get('abnormal_count', 0)}")
    lines.append("")
    lines.append("For detailed expert analysis, please ensure Gemini API is configured correctly.")
    lines.append("=" * 80)
    
    return '\n'.join(lines)
