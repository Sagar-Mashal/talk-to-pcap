"""
Smart schema catalog that learns available fields per message type from the actual PCAP data.
This enables LLM to understand what fields actually exist in each message.
"""

import json
import logging
import re
from typing import Dict, List, Set
import duckdb

logger = logging.getLogger("talk-to-pcap.schema_catalog")


class SchemaCatalog:
    """
    Analyzes PCAP data to build a catalog of:
    - Which message types exist
    - What fields are available in each message type
    - Sample values for each field
    """
    
    def __init__(self):
        self.message_field_map: Dict[str, Set[str]] = {}
        self.field_samples: Dict[str, List[str]] = {}
        
    def analyze_dataset(self, conn: duckdb.DuckDBPyConnection, limit: int = 100) -> None:
        """
        Analyze the loaded dataset to learn the schema.
        
        Args:
            conn: DuckDB connection with packets table loaded
            limit: Max packets per message type to analyze
        """
        logger.info("Analyzing dataset to build schema catalog...")
        
        try:
            # Get all message types
            msg_types_result = conn.execute(
                "SELECT DISTINCT message_type FROM packets WHERE message_type IS NOT NULL"
            ).fetchall()
            
            for (msg_type,) in msg_types_result:
                if not msg_type:
                    continue
                    
                # Get sample packets for this message type
                packets = conn.execute(
                    f"""
                    SELECT protocol_fields_json 
                    FROM packets 
                    WHERE message_type = ? 
                    LIMIT ?
                    """,
                    [msg_type, limit]
                ).fetchall()
                
                fields_in_msg = set()
                
                for (json_str,) in packets:
                    if not json_str:
                        continue
                    
                    try:
                        fields_dict = json.loads(json_str)
                        
                        # Extract all field names from JSON
                        for field_name, field_value in fields_dict.items():
                            fields_in_msg.add(field_name)
                            
                            # Store sample value
                            if field_name not in self.field_samples:
                                self.field_samples[field_name] = []
                            
                            if len(self.field_samples[field_name]) < 3:
                                value_str = str(field_value)[:50]  # Truncate long values
                                if value_str not in self.field_samples[field_name]:
                                    self.field_samples[field_name].append(value_str)
                    
                    except json.JSONDecodeError:
                        continue
                
                self.message_field_map[msg_type] = fields_in_msg
                logger.info(f"  {msg_type}: {len(fields_in_msg)} unique fields")
            
            logger.info(f"✓ Schema catalog built: {len(self.message_field_map)} message types analyzed")
            
        except Exception as e:
            logger.error(f"Schema catalog analysis failed: {e}")
    
    def get_fields_for_message(self, message_type: str) -> List[str]:
        """Get list of available fields for a message type."""
        return sorted(self.message_field_map.get(message_type, set()))
    
    def find_matching_fields(self, query_field: str, message_type: str | None = None) -> List[tuple[str, str]]:
        """
        Find fields that match the user's query field name.
        
        Args:
            query_field: Field name from user query (e.g., "pdn_ipv4", "nas-eps.esm.pdn_ipv4")
            message_type: Optional message type to filter by
            
        Returns:
            List of (message_type, field_name) tuples that match
        """
        matches = []
        query_lower = query_field.lower().replace('-', '').replace('_', '').replace('.', '')
        
        search_msgs = [message_type] if message_type else self.message_field_map.keys()
        
        for msg_type in search_msgs:
            fields = self.message_field_map.get(msg_type, set())
            
            for field_name in fields:
                field_normalized = field_name.lower().replace('-', '').replace('_', '').replace('.', '')
                
                # Match if query is substring of field or vice versa
                if query_lower in field_normalized or field_normalized in query_lower:
                    matches.append((msg_type, field_name))
        
        return matches
    
    def generate_llm_hint(self, message_type: str | None = None) -> str:
        """
        Generate a hint for LLM about available fields.
        
        Args:
            message_type: Optional specific message type
            
        Returns:
            Formatted string describing available fields
        """
        if message_type and message_type in self.message_field_map:
            fields = sorted(self.message_field_map[message_type])
            
            # Group by protocol prefix
            field_groups = {}
            for field in fields:
                prefix = field.split('.')[0] if '.' in field else 'other'
                if prefix not in field_groups:
                    field_groups[prefix] = []
                field_groups[prefix].append(field)
            
            hint = f"\n**AVAILABLE FIELDS IN {message_type} MESSAGE**:\n"
            for prefix, field_list in sorted(field_groups.items()):
                hint += f"  {prefix}: {', '.join(field_list[:10])}"
                if len(field_list) > 10:
                    hint += f" ... ({len(field_list) - 10} more)"
                hint += "\n"
            
            hint += "\n**CRITICAL**: Only search for fields that actually exist in the JSON!"
            return hint
        
        return ""
    
    def get_exact_field_name(self, query_field: str, message_type: str) -> str:
        """
        Get the exact field name from the dataset that matches user's query.
        
        Args:
            query_field: User's field name (may be partial or different case)
            message_type: The message type context
            
        Returns:
            Exact field name from dataset, or original if no match
        """
        matches = self.find_matching_fields(query_field, message_type)
        if not matches:
            return query_field

        # Deterministic scoring to avoid non-deterministic set iteration order.
        # Goals:
        #  1. Prefer fields whose normalized form exactly equals the normalized query (ignoring separators/case)
        #  2. Prefer fields containing the query as a full token vs merely as substring
        #  3. Penalize helper/flag fields (e.g. tmsi_flag) when a value field (m_tmsi) exists
        #  4. Keep ordering stable by also considering lexical order as final tiebreaker
        norm_query = query_field.lower().replace('-', '').replace('_', '').replace('.', '')

        def _score(field_name: str) -> int:
            fl = field_name.lower()
            norm_field = fl.replace('-', '').replace('_', '').replace('.', '')
            score = 0
            if norm_field == norm_query:
                score += 1000
            if norm_query in norm_field:
                score += 100
            # Token boundary preference (exact component match)
            parts = re.split(r'[._-]', fl)
            if norm_query in {p.replace('-', '').replace('_', '').replace('.', '') for p in parts}:
                score += 200
            # Penalize flags / booleans when searching for an identity value
            if 'flag' in fl:
                score -= 250
            if fl.endswith('flag'):
                score -= 50
            # Light boost for common identity fields
            for ident_token in ['m_tmsi', 'mme_ue_s1ap_id', 'enb_ue_s1ap_id', 'ran_ue_ngap_id', 'ueid']:
                if ident_token in fl:
                    score += 25
            return score

        # Rank and select best
        ranked = sorted(matches, key=lambda mf: (-_score(mf[1]), mf[1]))
        best_field = ranked[0][1]
        return best_field
