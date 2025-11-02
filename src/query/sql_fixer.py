"""SQL post-processor to fix common field path issues."""

import re
from typing import Dict, List
from src.utils.logger import get_logger

logger = get_logger(__name__)


# Field name mappings: bare name → full path
FIELD_PATH_MAPPINGS = {
    # S1AP fields
    "ENB_UE_S1AP_ID": "s1ap.s1ap.ENB_UE_S1AP_ID",
    "MME_UE_S1AP_ID": "s1ap.s1ap.MME_UE_S1AP_ID",
    "m_TMSI": "s1ap.s1ap.m_TMSI",
    "M_TMSI": "s1ap.s1ap.m_TMSI",
    
    # X2AP fields  
    "Old_ENB_UE_X2AP_ID": "x2ap.x2ap.Old_ENB_UE_X2AP_ID",
    "New_ENB_UE_X2AP_ID": "x2ap.x2ap.New_ENB_UE_X2AP_ID",
    
    # RRC/RLC fields (be careful - these can cause false positives!)
    "rlc-lte.ueid": "rlc_lte.rlc-lte.ueid",
    
    # NAS fields
    "m_tmsi": ["s1ap.nas-eps.emm.m_tmsi", "nas_eps.nas-eps.emm.m_tmsi", "rlc_lte.nas-eps.emm.m_tmsi"],
    "imsi": ["s1ap.nas-eps.emm.imsi", "nas_eps.nas-eps.emm.imsi"],
}


def fix_field_paths_in_sql(sql: str) -> tuple[str, List[str]]:
    """
    Fix missing field path prefixes and add boundary markers in SQL LIKE patterns.
    
    Args:
        sql: Generated SQL query
        
    Returns:
        Tuple of (fixed_sql, list_of_fixes_made)
    """
    fixes = []
    fixed_sql = sql
    
    # Pattern 1: Find LIKE clauses that need boundaries added
    # Matches: protocol_fields_json LIKE '%"field": "value"%'
    # We need to match the FULL context including the column name
    # Use [^"\n]+ to avoid matching across lines and breaking multi-line SQL
    boundary_pattern = r"(protocol_fields_json)\s+(LIKE\s+'%\"([^\"]+?)\":\s*\"([^\"]+?)\"%')"
    
    for match in re.finditer(boundary_pattern, sql, re.IGNORECASE):
        column_name = match.group(1)  # "protocol_fields_json"
        like_clause = match.group(2)   # Full LIKE clause
        field_name = match.group(3)
        field_value = match.group(4)
        original_pattern = match.group(0)  # Full match
        
        # Add boundaries: create two patterns (one with comma, one with closing brace)
        # Keep the column name, wrap in parentheses for OR condition
        new_pattern = f'({column_name} LIKE \'%"{field_name}": "{field_value}",%\' OR {column_name} LIKE \'%"{field_name}": "{field_value}"}}%\')'
        
        fixed_sql = fixed_sql.replace(original_pattern, new_pattern)
        fixes.append(f'Added boundaries to "{field_name}": "{field_value}"')
        logger.info(f"Added boundary markers to: {field_name}")
    
    # Pattern 2: Fix missing field path prefixes
    prefix_pattern = r"\"(ENB_UE_S1AP_ID|MME_UE_S1AP_ID|m_TMSI|M_TMSI|Old_ENB_UE_X2AP_ID|New_ENB_UE_X2AP_ID)\""
    
    for match in re.finditer(prefix_pattern, fixed_sql):
        field_name = match.group(1)
        
        # Check if field name needs prefix
        if field_name in FIELD_PATH_MAPPINGS:
            full_paths = FIELD_PATH_MAPPINGS[field_name]
            
            # Handle single mapping
            if isinstance(full_paths, str):
                full_path = full_paths
            else:
                full_path = full_paths[0]
            
            # Replace bare field name with full path
            fixed_sql = fixed_sql.replace(f'"{field_name}"', f'"{full_path}"')
            fixes.append(f'"{field_name}" → "{full_path}"')
            logger.info(f"Fixed field path: {field_name} → {full_path}")
    
    # Special handling for generic patterns that are too broad
    # Replace bare field names that appear without protocol prefix
    generic_fixes = {
        r'"ueid":\s*"(\d+)"': r'"rlc_lte.rlc-lte.ueid": "\1"',  # But don't use for handovers!
        r'"tmsi":\s*': r'"m_tmsi": ',  # Generic tmsi → m_tmsi
    }
    
    # Pattern 3: Fix field name searches that have unnecessary quotes
    # LLM often generates: LIKE '%"m_tmsi"%' when it should be: LIKE '%m_tmsi%'
    # Rule: If pattern is LIKE '%"something"%' WITHOUT a colon (no :), it's a field name search
    field_name_search_pattern = r"LIKE\s+'%\"([^\":]+)\"%'"
    
    for match in re.finditer(field_name_search_pattern, fixed_sql, re.IGNORECASE):
        field_word = match.group(1)
        original_pattern = match.group(0)
        
        # Remove quotes - searching for field name, not field:value
        new_pattern = f"LIKE '%{field_word}%'"
        fixed_sql = fixed_sql.replace(original_pattern, new_pattern)
        fixes.append(f'Removed quotes from field name search: "{field_word}" → {field_word}')
        logger.info(f"Fixed field name search: removed quotes from {field_word}")
    
    for pattern, replacement in generic_fixes.items():
        if re.search(pattern, fixed_sql):
            fixed_sql = re.sub(pattern, replacement, fixed_sql)
            fixes.append(f"Generic pattern fix: {pattern} → {replacement}")
    
    return fixed_sql, fixes


def validate_and_fix_sql(sql: str) -> tuple[str, Dict[str, str]]:
    """
    Validate SQL and apply automatic fixes for common issues.
    
    Args:
        sql: Generated SQL query
        
    Returns:
        Tuple of (fixed_sql, metadata_dict)
    """
    metadata = {
        "original_sql": sql,
        "fixes_applied": [],
        "warnings": []
    }
    
    fixed_sql = sql
    
    # Fix 1: Add missing field path prefixes
    fixed_sql, path_fixes = fix_field_paths_in_sql(fixed_sql)
    if path_fixes:
        metadata["fixes_applied"].extend(path_fixes)
        logger.info(f"Applied {len(path_fixes)} field path fixes")
    
    # Fix 2: Check for JSON functions on VARCHAR column
    if any(func in fixed_sql.upper() for func in ['JSON_EXTRACT', 'JSON_VALUE', 'JSON_QUERY']):
        metadata["warnings"].append(
            "⚠️  SQL uses JSON functions on VARCHAR column - these will fail! "
            "Use LIKE patterns instead."
        )
        logger.warning("SQL contains JSON functions on VARCHAR column")
    
    # Fix 3: Check for missing boundary markers in LIKE patterns
    # Pattern should end with `,` or `}` to avoid substring matches
    like_patterns = re.findall(r"LIKE\s+'([^']+)'", fixed_sql, re.IGNORECASE)
    for pattern in like_patterns:
        if '": "' in pattern and not (pattern.endswith(',%') or pattern.endswith('}%')):
            metadata["warnings"].append(
                f"⚠️  Pattern '{pattern}' might cause substring false positives. "
                f"Should end with ',%' or '}}%'"
            )
    
    return fixed_sql, metadata
