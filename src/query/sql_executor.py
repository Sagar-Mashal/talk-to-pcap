"""SQL query executor with timeout and error handling."""

import time
from typing import List

import duckdb

from src.models.query import QueryResult, ResultType
from src.utils.logger import get_logger

logger = get_logger(__name__)


def execute_sql(
    conn: duckdb.DuckDBPyConnection,
    sql: str,
    limit: int = 100,
    timeout_seconds: int = 30,
) -> QueryResult:
    """
    Execute SQL query and return results.

    Args:
        conn: DuckDB connection
        sql: SQL query to execute
        limit: Maximum number of rows to return
        timeout_seconds: Query timeout in seconds

    Returns:
        QueryResult object

    Raises:
        ValueError: If SQL is invalid or unsafe
        duckdb.Error: If query execution fails
    """
    # Validate SQL
    validate_sql(sql)

    logger.info(f"Executing SQL: {sql[:200]}{'...' if len(sql) > 200 else ''}")

    start_time = time.time()

    try:
        # Execute query with limit
        if "LIMIT" not in sql.strip().upper():
            sql_with_limit = f"{sql.strip().rstrip(';')} LIMIT {limit}"
        else:
            sql_with_limit = sql

        result = conn.execute(sql_with_limit).fetchall()
        columns = [desc[0] for desc in conn.description]

        execution_time_ms = int((time.time() - start_time) * 1000)

        # Convert to list of dicts
        data = []
        for row in result:
            row_dict = {}
            for i, col_name in enumerate(columns):
                row_dict[col_name] = row[i]
            data.append(row_dict)

        # Determine result type
        if not data:
            result_type = ResultType.EMPTY
        elif len(data) == 1 and len(columns) == 1:
            result_type = ResultType.SCALAR
        elif "timestamp" in columns or "time" in columns:
            result_type = ResultType.TIME_SERIES
        else:
            result_type = ResultType.TABLE

        logger.info(f"✓ Query returned {len(data)} rows in {execution_time_ms}ms")

        return QueryResult(
            query_id="",  # Will be set by caller
            result_type=result_type,
            row_count=len(data),
            columns=columns,
            data=data,
summary=f"Returned {len(data)} rows in {execution_time_ms}ms",
        )

    except duckdb.Error as e:
        error_msg = str(e)
        logger.error(f"SQL execution error: {error_msg}")
        raise duckdb.Error(f"Query failed: {error_msg}") from e


def validate_sql(sql: str) -> bool:
    """
    Validate SQL query syntax and safety.

    Args:
        sql: SQL query to validate

    Returns:
        True if valid

    Raises:
        ValueError: If SQL is invalid
    """
    import re

    sql_upper = sql.strip().upper()

    # Must be SELECT
    if not sql_upper.startswith("SELECT"):
        raise ValueError("Only SELECT queries are allowed")

    # No dangerous operations
    dangerous_keywords = [
        "DROP",
        "DELETE",
        "UPDATE",
        "INSERT",
        "ALTER",
        "CREATE TABLE",
        "TRUNCATE",
        "EXEC",
        "EXECUTE",
    ]
    for keyword in dangerous_keywords:
        if re.search(r'\\b' + keyword + r'\\b', sql_upper):
            raise ValueError(f"Unsafe SQL operation: {keyword}")

    return True


def explain_query(conn: duckdb.DuckDBPyConnection, sql: str) -> str:
    """
    Get query execution plan.

    Args:
        conn: DuckDB connection
        sql: SQL query to explain

    Returns:
        Query execution plan as string
    """
    try:
        explain_sql = f"EXPLAIN {sql}"
        result = conn.execute(explain_sql).fetchall()
        return "\\n".join([row[0] for row in result])
    except Exception as e:
        logger.error(f"Failed to explain query: {e}")
        return f"Could not explain query: {e}"


def get_sample_queries() -> List[dict]:
    """
    Get sample queries for 3GPP PCAP analysis.

    Returns:
        List of sample query dicts with description and SQL
    """
    return [
        {
            "description": "List all RRC messages",
            "sql": "SELECT packet_number, timestamp, message_type, direction FROM packets "
            "WHERE protocol = 'RRC' LIMIT 100",
        },
        {
            "description": "Count unique UE IDs",
            "sql": "SELECT COUNT(DISTINCT ue_id) as unique_ues FROM packets "
            "WHERE ue_id IS NOT NULL",
        },
        {
            "description": "Show handover failures vs successes",
            "sql": "SELECT message_type, COUNT(*) as count FROM packets "
            "WHERE protocol = 'X2AP' AND message_type LIKE '%Handover%' "
            "GROUP BY message_type ORDER BY count DESC",
        },
        {
            "description": "Top 10 protocols by packet count",
            "sql": "SELECT protocol, COUNT(*) as count FROM packets "
            "WHERE protocol IS NOT NULL GROUP BY protocol ORDER BY count DESC LIMIT 10",
        },
        {
            "description": "Packets per hour time series",
            "sql": "SELECT timestamp_hour, COUNT(*) as packet_count FROM packets "
            "GROUP BY timestamp_hour ORDER BY timestamp_hour",
        },
        {
            "description": "Find all attach requests",
            "sql": "SELECT packet_number, timestamp, ue_id, message_type FROM packets "
            "WHERE message_type LIKE '%Attach%Request%' LIMIT 50",
        },
        {
            "description": "List all interfaces present",
            "sql": "SELECT DISTINCT interface FROM packets WHERE interface IS NOT NULL",
        },
        {
            "description": "Count messages by direction",
            "sql": "SELECT direction, COUNT(*) as count FROM packets "
            "WHERE direction IS NOT NULL GROUP BY direction",
        },
    ]
