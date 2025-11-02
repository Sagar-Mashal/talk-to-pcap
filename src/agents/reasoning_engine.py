"""Enhanced LLM client with reasoning and self-correction capabilities."""

from typing import Optional, Dict, Any, List, Tuple
import json

from src.config import config
from src.utils.logger import get_logger
from src.query.sql_fixer import validate_and_fix_sql
from src.agents.llm_client import LLMClient

logger = get_logger(__name__)



def analyze_field_structure(conn, sample_size: int = 10) -> Dict[str, Any]:
    """
    Analyze protocol_fields_json structure to discover common field patterns.
    
    This helps the LLM understand what fields are available dynamically.
    """
    try:
        # Get sample of JSON fields
        result = conn.execute(f"""
            SELECT protocol, message_type, protocol_fields_json 
            FROM packets 
            WHERE protocol_fields_json IS NOT NULL 
            LIMIT {sample_size}
        """).fetchall()
        
        field_patterns = {
            "s1ap_fields": set(),
            "x2ap_fields": set(),
            "rrc_fields": set(),
            "nas_fields": set(),
            "ue_id_fields": set()
        }
        
        for protocol, msg_type, json_str in result:
            if not json_str:
                continue
                
            try:
                fields = json.loads(json_str)
                
                for key in fields.keys():
                    # Categorize fields
                    if "s1ap.s1ap." in key:
                        field_patterns["s1ap_fields"].add(key)
                        if "UE" in key and "ID" in key:
                            field_patterns["ue_id_fields"].add(key)
                    elif "x2ap.x2ap." in key:
                        field_patterns["x2ap_fields"].add(key)
                        if "UE" in key and "ID" in key:
                            field_patterns["ue_id_fields"].add(key)
                    elif "rlc_lte.lte-rrc." in key or "rlc_lte.rlc-lte." in key:
                        field_patterns["rrc_fields"].add(key)
                        if "ueid" in key.lower():
                            field_patterns["ue_id_fields"].add(key)
                    elif "nas" in key.lower():
                        field_patterns["nas_fields"].add(key)
                        if "tmsi" in key.lower() or "imsi" in key.lower():
                            field_patterns["ue_id_fields"].add(key)
            except:
                continue
        
        # Convert sets to lists for JSON serialization
        return {k: list(v) for k, v in field_patterns.items()}
        
    except Exception as e:
        logger.warning(f"Could not analyze field structure: {e}")
        return {}


def generate_reasoning_prompt(
    natural_language_query: str,
    schema_info: str,
    field_patterns: Dict[str, Any],
    previous_attempt: Optional[Dict[str, Any]] = None,
    correlation_hint: Optional[str] = None,
    field_variations_hint: Optional[str] = None,
    network_mode: Optional[str] = None
) -> str:
    """
    Generate a reasoning-based prompt that teaches the LLM to think, not memorize.
    
    Args:
        network_mode: "4g" for LTE (S1AP, X2AP), "5g" for NR (NGAP, F1AP), None for auto-detect
    """
    
    field_examples = ""
    if field_patterns:
        field_examples = f"""
**DISCOVERED FIELD PATTERNS IN THIS PCAP**:
The protocol_fields_json column contains these field types:
- S1AP UE ID fields: {', '.join(field_patterns.get('ue_id_fields', [])[:5]) or 'Not yet discovered'}
- Common S1AP fields: {', '.join(list(field_patterns.get('s1ap_fields', []))[:8]) or 'Check JSON'}
- Common RRC fields: {', '.join(list(field_patterns.get('rrc_fields', []))[:8]) or 'Check JSON'}
- NAS identifier fields: {', '.join(list(field_patterns.get('nas_fields', []))[:5]) or 'Check JSON'}

**IMPORTANT**: These are just EXAMPLES from this PCAP. The actual field names may vary slightly.
When searching, use PARTIAL MATCHING with LIKE operator.
"""
    
    retry_guidance = ""
    if previous_attempt:
        retry_guidance = f"""
**PREVIOUS ATTEMPT FAILED**:
- SQL: {previous_attempt.get('sql', 'N/A')}
- Result: {previous_attempt.get('result', 'N/A')}
- Rows returned: {previous_attempt.get('row_count', 0)}

**WHY IT FAILED**:
{previous_attempt.get('failure_reason', 'Unknown')}

**CORRECTION STRATEGY**:
{previous_attempt.get('correction_hint', 'Try broader search patterns')}

Now generate a CORRECTED SQL query that addresses these issues.
"""
    
    # Add correlation hint if available
    correlation_guidance = ""
    if correlation_hint:
        correlation_guidance = f"""
**🔗 CRITICAL: UE CORRELATION INFO**:
{correlation_hint}

**⚠️ YOU MUST USE THE CORRELATED IDs IN YOUR SQL!**
When the user asks for "UE ID 1", they mean ALL correlated identifiers for that UE.

EXAMPLE: If the correlation shows `rlc_ueid=61`, your WHERE clause MUST include:
```sql
protocol_fields_json LIKE '%"rlc_lte.rlc-lte.ueid": "61",%' OR 
protocol_fields_json LIKE '%"rlc_lte.rlc-lte.ueid": "61"}}%'
```

DO NOT just search for literal "1" - use the ACTUAL correlated values shown above!
This is MANDATORY for finding data across different protocol layers.
"""
    
    # Network mode guidance
    network_mode_guidance = ""
    if network_mode == "5g":
        network_mode_guidance = """
**🔵 NETWORK MODE: 5G NR (New Radio) 🔵**

**CRITICAL: Use ONLY 5G protocols and fields!**

**5G Core Protocols**:
- NGAP (NG Application Protocol) - Control plane between gNB and AMF
- F1AP - Interface between gNB-CU and gNB-DU  
- NR-RRC - Radio Resource Control for 5G

**5G UE Identifier Fields (USE THESE)**:
- ✅ **Primary**: `ngap.RAN_UE_NGAP_ID` (or `ngap.ngap.RAN_UE_NGAP_ID` or `RAN_UE_NGAP_ID`)
- ✅ **Secondary**: `ngap.AMF_UE_NGAP_ID` (or `ngap.ngap.AMF_UE_NGAP_ID`)

**❌ DO NOT USE 4G/LTE FIELDS IN 5G MODE:**
- ❌ NO `s1ap.s1ap.ENB_UE_S1AP_ID` (this is 4G LTE)
- ❌ NO `s1ap.s1ap.MME_UE_S1AP_ID` (this is 4G LTE)
- ❌ NO `x2ap.x2ap.*` (this is 4G LTE)
- ❌ NO proprietary or custom wrapper fields

**Example 5G Call Flow Query**:
```sql
SELECT packet_number, timestamp_iso, protocol, message_type, direction, protocol_fields_json
FROM packets
WHERE (protocol_fields_json LIKE '%"ngap.RAN_UE_NGAP_ID": "77",%' 
       OR protocol_fields_json LIKE '%"ngap.RAN_UE_NGAP_ID": "77"}%'
       OR protocol_fields_json LIKE '%"ngap.ngap.RAN_UE_NGAP_ID": "77",%'
       OR protocol_fields_json LIKE '%"ngap.ngap.RAN_UE_NGAP_ID": "77"}%')
ORDER BY timestamp
LIMIT 100;
```
"""
    elif network_mode == "4g":
        network_mode_guidance = """
**🔴 NETWORK MODE: 4G LTE (Long Term Evolution) 🔴**

**CRITICAL: Use ONLY 4G protocols and fields!**

**4G Core Protocols**:
- S1AP (S1 Application Protocol) - Control plane between eNB and MME
- X2AP - Interface between eNBs for handover
- RRC - Radio Resource Control for LTE

**4G UE Identifier Fields (USE THESE)**:
- ✅ **Primary**: `s1ap.s1ap.ENB_UE_S1AP_ID`
- ✅ **Secondary**: `s1ap.s1ap.MME_UE_S1AP_ID`
- ✅ **Handover**: `x2ap.x2ap.Old_ENB_UE_X2AP_ID`, `x2ap.x2ap.New_ENB_UE_X2AP_ID`

**❌ DO NOT USE 5G/NR FIELDS IN 4G MODE:**
- ❌ NO `ngap.RAN_UE_NGAP_ID` (this is 5G NR)
- ❌ NO `ngap.AMF_UE_NGAP_ID` (this is 5G NR)
- ❌ NO `f1ap.*` (this is 5G NR)
- ❌ NO proprietary or custom wrapper fields

**Example 4G Call Flow Query**:
```sql
SELECT packet_number, timestamp_iso, protocol, message_type, direction, protocol_fields_json
FROM packets
WHERE (protocol_fields_json LIKE '%"s1ap.s1ap.ENB_UE_S1AP_ID": "2",%'
       OR protocol_fields_json LIKE '%"s1ap.s1ap.ENB_UE_S1AP_ID": "2"}%'
       OR protocol_fields_json LIKE '%"s1ap.s1ap.MME_UE_S1AP_ID": "2",%'
       OR protocol_fields_json LIKE '%"s1ap.s1ap.MME_UE_S1AP_ID": "2"}%')
ORDER BY timestamp
LIMIT 100;
```
"""
    
    prompt = f"""You are an EXPERT telecommunications protocol analyzer with deep knowledge of 3GPP standards.

**YOUR TASK**: Analyze the user's question and generate the BEST POSSIBLE SQL query.

**USER QUESTION**: "{natural_language_query}"

{network_mode_guidance}

{correlation_guidance}
```
"""
    
    # Detect if this is a SIB (System Information Block) query
    is_sib_query = any(keyword in natural_language_query.lower() 
                       for keyword in ['sib1', 'sib2', 'sib3', 'sib4', 'sib5', 'sib6', 'sib7', 'sib8', 'sib9', 
                                      'sib10', 'sib11', 'sib12', 'sib13', 'system information'])
    
    sib_guidance = ""
    if is_sib_query:
        sib_guidance = """
**🚨 CRITICAL: THIS IS A SIB (System Information Block) QUERY! 🚨**

**SIB RULES - YOU MUST FOLLOW THESE**:
1. **NO UE ID FILTERS**: SIBs are BROADCAST messages sent to ALL UEs
   - ❌ DO NOT add: `LIKE '%ENB_UE_S1AP_ID%'`
   - ❌ DO NOT add: `LIKE '%MME_UE_S1AP_ID%'`
   - ❌ DO NOT add: `LIKE '%ueid%'`
   - ❌ DO NOT filter by any UE identifier!

2. **PROTOCOL MUST BE RRC**: SIBs are RRC broadcast messages
   - ✅ DO add: `protocol = 'RRC'` OR `message_type LIKE '%SystemInformation%'`
   - ✅ Search only in: `rlc_lte.lte-rrc.*` fields in protocol_fields_json

3. **SEARCH FOR SIB TYPE**: Look for the specific SIB number
   - Example: For "sib3", search: `LIKE '%sib3%'` **OR** `LIKE '%SystemInformationBlockType3%'`
   - **CRITICAL**: Use **OR**, not AND! Different packets use different naming conventions.
   - The `sib3_element` field and `SystemInformationBlockType3` are alternative representations!

4. **BROADCAST CHARACTERISTICS**:
   - SIBs have NO specific UE context
   - They appear in RLC-LTE BCCH (Broadcast Control Channel) messages
   - One SIB applies to ALL UEs in the cell

**CORRECT SIB QUERY EXAMPLE**:
```sql
SELECT packet_number, protocol_fields_json
FROM packets
WHERE protocol = 'RRC'
  AND protocol_fields_json LIKE '%sib3%'
LIMIT 100;
```

**WRONG SIB QUERY (DO NOT DO THIS)**:
```sql
-- ❌ WRONG: Adding UE ID filters to broadcast message!
SELECT * FROM packets
WHERE protocol_fields_json LIKE '%ENB_UE_S1AP_ID%'  -- NO! SIBs have no UE ID!
  AND protocol_fields_json LIKE '%sib3%'
```
"""
    
    prompt = f"""You are an EXPERT telecommunications protocol analyzer with deep knowledge of 3GPP standards.

**YOUR TASK**: Analyze the user's question and generate the BEST POSSIBLE SQL query.

**USER QUESTION**: "{natural_language_query}"

{sib_guidance}

{correlation_guidance}

**DATABASE SCHEMA**:
{schema_info}

**⚠️ CRITICAL RULE #1: protocol_fields_json is VARCHAR (STRING), NOT JSON type!**
- ❌ NEVER use: JSON_EXTRACT(), JSON_VALUE(), json_extract_path()
- ✅ ALWAYS use: LIKE operator for pattern matching

**⚠️ CRITICAL RULE #2: TWO TYPES OF LIKE PATTERNS - PAY ATTENTION!!!**

🔴 **TYPE A: Searching for SPECIFIC field = value** (e.g., "find UE ID 1"):
   - Pattern: `LIKE '%"full.field.path": "value"%'` ← WITH QUOTES
   - Example: `LIKE '%"s1ap.s1ap.ENB_UE_S1AP_ID": "1"%'`
   - Use when: You know BOTH field name AND the value you're looking for

🔴 **TYPE B: Searching for ANY field containing a word** (e.g., "find m-tmsi field"):
   - Pattern: `LIKE '%word%'` ← NO QUOTES, just the word!
   - Example: `LIKE '%m_tmsi%'` NOT `LIKE '%"m_tmsi"%'`
   - Use when: You're looking for a field NAME, not a specific value
   - Common cases: m_tmsi, imsi, guti, rsrp, rsrq (when you want to find the field, not match a value)

**WRONG vs RIGHT examples**:
- ❌ `LIKE '%"m_tmsi"%'` ← WRONG! Returns 0 results!
- ✅ `LIKE '%m_tmsi%'` ← CORRECT! Finds any field with "m_tmsi" in name
- ✅ `LIKE '%"ENB_UE_S1AP_ID": "1"%'` ← CORRECT! Finds specific UE ID = 1

{field_examples}

{retry_guidance}

**REASONING FRAMEWORK - THINK STEP BY STEP**:

1. **UNDERSTAND THE QUESTION**:
   - What is the user asking for? (specific value, list, count, trace, etc.)
   - What entities are involved? (UE, cell, message type, field value)
   - What time scope? (all time, specific UE session, etc.)

2. **IDENTIFY REQUIRED FIELDS**:
   - Is this about a specific UE? → Need to search UE ID fields in protocol_fields_json
   - Is this about message content? → Need to search specific field names in protocol_fields_json
   - Is this about call flow? → Need timestamp ordering and multiple protocols

3. **CRITICAL DECISION: UE ID Searching**:
   - **NEVER use ue_id column alone** - it's often NULL!
   - **ALWAYS search protocol_fields_json for UE identifiers**:
     * S1AP: `s1ap.s1ap.ENB_UE_S1AP_ID`, `s1ap.s1ap.MME_UE_S1AP_ID`
     * X2AP: `x2ap.x2ap.Old_ENB_UE_X2AP_ID`, `x2ap.x2ap.New_ENB_UE_X2AP_ID`
     * NAS: Fields containing "m_tmsi", "imsi", "guti"
   
   - **⚠️ CRITICAL: ALWAYS include FULL field path with protocol prefix!**
     * ✅ CORRECT: `LIKE '%"s1ap.s1ap.ENB_UE_S1AP_ID": "1"%'`
     * ❌ WRONG: `LIKE '%"ENB_UE_S1AP_ID": "1"%'` (missing s1ap.s1ap. prefix!)
     * ✅ CORRECT: `LIKE '%"rlc_lte.rlc-lte.ueid": "61"%'`
     * ❌ WRONG: `LIKE '%"ueid": "61"%'` (too generic, matches many fields!)
   
   - **PATTERN RULE**: Pattern must end with either comma or closing brace to match JSON value boundaries

4. **CRITICAL: TWO TYPES OF LIKE SEARCHES**:
   
   **A. Searching for SPECIFIC FIELD:VALUE pairs** (e.g., UE ID = 1):
      - Use: `LIKE '%"field_name": "value"%'` (WITH quotes around field and value)
      - Example: `LIKE '%"s1ap.s1ap.ENB_UE_S1AP_ID": "1"%'`
      - This searches for an EXACT field:value match in the JSON
   
   **B. Searching for ANY field containing a NAME** (e.g., "find m-tmsi field"):
      - Use: `LIKE '%field_name%'` (NO quotes, just the name)
      - Example: `LIKE '%m_tmsi%'` NOT `LIKE '%"m_tmsi"%'`
      - This finds ANY field whose name contains "m_tmsi"
      - ⚠️ DO NOT wrap field name in quotes when searching for field presence!

5. **FIELD NAME VARIATIONS & CASE SENSITIVITY**:
   - User might say: "m-tmsi", "mtmsi", "M-TMSI", "TMSI", "cellindex", "cellIndex"
   - Data might have: "m_tmsi", "m-tmsi", "M_TMSI", "mTmsi", "cellIndex" (with capital I)
   - **CRITICAL - CASE INSENSITIVE SEARCH**: Field names in JSON can have different casing!
     ```sql
     -- WRONG (case-sensitive, will miss "cellIndex"):
     LIKE '%cellindex%'
     
     -- CORRECT (case-insensitive, will match "cellIndex", "cellindex", "CellIndex"):
     LOWER(protocol_fields_json) LIKE '%cellindex%'
     ```
   - **ALWAYS use LOWER() for field name searches** to handle case variations
   - Search ALL variations with OR: 
     ```sql
     LOWER(protocol_fields_json) LIKE '%m_tmsi%' OR 
     LOWER(protocol_fields_json) LIKE '%mtmsi%' OR 
     LOWER(protocol_fields_json) LIKE '%m-tmsi%' OR 
     LOWER(protocol_fields_json) LIKE '%mtmsi%'
     ```
   - Be flexible with underscores, hyphens, camelCase, PascalCase

{field_variations_hint if field_variations_hint else ""}

6. **MESSAGE TYPE CASING**:
   - RRC message types use **camelCase** in the `message_type` column
   - Examples: `rrcConnectionReconfiguration`, `rrcConnectionSetup`, `measurementReport`, `paging`
   - ❌ WRONG: `WHERE message_type = 'RRCConnectionReconfiguration'` (PascalCase)
   - ✅ CORRECT: `WHERE message_type = 'rrcConnectionReconfiguration'` (camelCase)
   - **CRITICAL**: First letter is lowercase, rest use camelCase convention
   - If unsure, query available message types or use LIKE with case-insensitive search

7. **CONSTRUCT THE QUERY**:
   - SELECT what the user needs (not everything!)
   - FROM packets
   - WHERE conditions (combine with OR for flexibility, AND for specificity)
   - ORDER BY timestamp if showing flow/sequence
   - LIMIT 100 (or more if user asks)

8. **VALIDATION CHECK**:
   - Does this query search the RIGHT place for UE IDs? (protocol_fields_json, not just ue_id)
   - Does this query handle field name variations? (underscores, hyphens, case)
   - Does this query use correct message_type casing? (camelCase for RRC)
   - Will this query return 0 rows if the field doesn't exist? (that's OK, we'll retry)

**OUTPUT FORMAT**:
Return ONLY the SQL query. No explanations, no markdown, just the query.

**EXAMPLE REASONING** (for "what is m-tmsi of UE id 1"):
- User wants: specific field value (m-tmsi)
- For which UE: UE id 1
- Where to search: 
  1. First find packets containing UE ID 1 in S1AP/NAS fields
  2. Then extract m_tmsi field value from those packets
- SQL approach: Search protocol_fields_json with LIKE for both UE ID and m_tmsi field

SQL Query:
"""
    
    return prompt


def generate_sql_with_reasoning(
    llm_client: LLMClient,
    natural_language_query: str,
    schema_info: str,
    conn: Any,
    max_retries: int = 2,
    correlation_hint: Optional[str] = None,
    field_variations_hint: Optional[str] = None,
    network_mode: Optional[str] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Generate SQL with reasoning and self-correction.
    
    Args:
        llm_client: LLMClient instance (supports Gemini, OpenAI, Anthropic)
        network_mode: "4g" for LTE, "5g" for NR, None for auto-detect
    
    Returns:
        Tuple of (sql_query, metadata)
    """
    # Analyze field structure from actual data
    field_patterns = analyze_field_structure(conn, sample_size=20)
    
    metadata = {
        "attempts": [],
        "field_patterns": field_patterns,
        "reasoning_used": True
    }
    
    previous_attempt = None
    
    for attempt in range(max_retries + 1):
        try:
            # Generate prompt with reasoning
            prompt = generate_reasoning_prompt(
                natural_language_query=natural_language_query,
                schema_info=schema_info,
                field_patterns=field_patterns,
                previous_attempt=previous_attempt,
                network_mode=network_mode,
                correlation_hint=correlation_hint,
                field_variations_hint=field_variations_hint
            )
            
            logger.debug(f"Attempt {attempt + 1}: Generating SQL with reasoning...")
            
            response_text = llm_client.generate_content(prompt, temperature=0.0)
            
            if not response_text:
                raise Exception("LLM returned empty response")
            
            sql = response_text.strip()
            
            # Clean up response
            if sql.startswith("```sql"):
                sql = sql[6:]
            if sql.startswith("```"):
                sql = sql[3:]
            if sql.endswith("```"):
                sql = sql[:-3]
            
            sql = sql.strip()
            
            # Apply automatic fixes
            sql, fix_metadata = validate_and_fix_sql(sql)
            if fix_metadata.get("fixes_applied"):
                logger.info(f"Auto-fixed SQL: {', '.join(fix_metadata['fixes_applied'])}")
            for warning in fix_metadata.get("warnings", []):
                logger.warning(warning)
            
            # Quick validation
            if attempt < max_retries:
                # Test query
                try:
                    test_result = conn.execute(sql).fetchall()
                    row_count = len(test_result)
                    
                    metadata["attempts"].append({
                        "attempt": attempt + 1,
                        "sql": sql,
                        "row_count": row_count,
                        "success": row_count > 0
                    })
                    
                    # Debug: Write full SQL to file
                    with open(f"debug_sql_attempt_{attempt + 1}.txt", "w", encoding="utf-8") as f:
                        f.write(f"ATTEMPT {attempt + 1} SQL (returned {row_count} rows):\n{sql}\n")
                    
                    if row_count > 0:
                        logger.info(f"✓ Generated SQL (attempt {attempt + 1}): {sql[:100]}...")
                        return sql, metadata
                    else:
                        # Prepare retry with hints
                        previous_attempt = {
                            "sql": sql,
                            "result": "0 rows",
                            "row_count": 0,
                            "failure_reason": "Query returned no results. Possible issues:\n"
                                            "1. Field name might be slightly different (try partial matching)\n"
                                            "2. UE ID field might use different format\n"
                                            "3. Need to search more field variations",
                            "correction_hint": "Try:\n"
                                             "- Use '%m_tmsi%' instead of exact field name\n"
                                             "- Search multiple UE ID field patterns with OR\n"
                                             "- Remove strict filters, make query broader\n"
                                             "- Check if protocol_fields_json LIKE patterns need adjustment"
                        }
                        logger.warning(f"Attempt {attempt + 1} returned 0 rows, retrying with corrections...")
                        continue
                        
                except Exception as e:
                    logger.error(f"Test query failed: {e}")
                    previous_attempt = {
                        "sql": sql,
                        "result": f"Error: {e}",
                        "row_count": 0,
                        "failure_reason": f"Query syntax or execution error: {e}",
                        "correction_hint": "Fix SQL syntax errors and try again"
                    }
                    continue
            else:
                # Last attempt, return as-is
                logger.info(f"✓ Generated SQL (final attempt): {sql[:100]}...")
                # Debug: Write full SQL to file for inspection
                with open("debug_sql.txt", "w", encoding="utf-8") as f:
                    f.write(f"FINAL ATTEMPT SQL:\n{sql}\n")
                metadata["attempts"].append({
                    "attempt": attempt + 1,
                    "sql": sql,
                    "row_count": "not tested",
                    "success": "unknown"
                })
                return sql, metadata
                
        except Exception as e:
            logger.error(f"SQL generation attempt {attempt + 1} failed: {e}")
            if attempt == max_retries:
                raise Exception(f"Failed to generate SQL after {max_retries + 1} attempts: {e}") from e
            continue
    
    raise Exception("Failed to generate valid SQL")
