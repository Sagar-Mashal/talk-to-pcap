"""DuckDB loader for Parquet files."""

from pathlib import Path
from typing import List, Union

import duckdb

from src.utils.logger import get_logger

logger = get_logger(__name__)


def load_parquet_to_duckdb(
    parquet_path: Union[str, List[str]],
    in_memory: bool = True,
    db_path: str = ":memory:",
) -> duckdb.DuckDBPyConnection:
    """
    Load Parquet file(s) into DuckDB.

    Args:
        parquet_path: Path to Parquet file or list of paths
        in_memory: Use in-memory database (faster but requires RAM)
        db_path: Database file path (if not in_memory)

    Returns:
        DuckDB connection

    Raises:
        FileNotFoundError: If Parquet file(s) don't exist
    """
    # Handle single path or list
    if isinstance(parquet_path, str):
        parquet_paths = [parquet_path]
    else:
        parquet_paths = parquet_path

    # Validate all paths exist
    for path in parquet_paths:
        if not Path(path).exists():
            raise FileNotFoundError(f"Parquet file not found: {path}")

    # Create connection
    if in_memory:
        conn = duckdb.connect(database=":memory:")
        logger.info("Created in-memory DuckDB connection")
    else:
        conn = duckdb.connect(database=db_path)
        logger.info(f"Connected to DuckDB: {db_path}")

    try:
        # Load single file
        if len(parquet_paths) == 1:
            parquet_file = Path(parquet_paths[0])
            logger.info(f"Loading Parquet: {parquet_file.name}")

            conn.execute(
                f"""
                CREATE TABLE packets AS 
                SELECT * FROM read_parquet('{parquet_paths[0]}')
                """
            )

            row_count = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
            logger.info(f"✓ Loaded {row_count:,} packets into DuckDB")

        # Load multiple files with UNION ALL
        else:
            logger.info(f"Loading {len(parquet_paths)} Parquet files...")

            # Build UNION ALL query
            union_parts = [f"SELECT * FROM read_parquet('{path}')" for path in parquet_paths]
            union_query = " UNION ALL ".join(union_parts)

            conn.execute(f"CREATE TABLE packets AS {union_query}")

            row_count = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
            logger.info(f"✓ Loaded {row_count:,} packets from {len(parquet_paths)} files")

        # Create helpful indexes
        logger.debug("Creating indexes...")
        conn.execute("CREATE INDEX idx_packet_number ON packets(packet_number)")
        conn.execute("CREATE INDEX idx_timestamp ON packets(timestamp)")
        conn.execute("CREATE INDEX idx_protocol ON packets(protocol)")
        logger.debug("✓ Indexes created")

        return conn

    except Exception as e:
        logger.error(f"Failed to load Parquet into DuckDB: {e}")
        conn.close()
        raise


def get_table_info(conn: duckdb.DuckDBPyConnection) -> dict:
    """
    Get information about the packets table.

    Args:
        conn: DuckDB connection

    Returns:
        Dictionary with table information
    """
    # Get row count
    row_count = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]

    # Get column info
    columns = conn.execute("DESCRIBE packets").fetchall()
    column_info = [{"name": col[0], "type": col[1]} for col in columns]

    # Get sample protocols
    protocols = conn.execute(
        "SELECT protocol, COUNT(*) as count FROM packets " "WHERE protocol IS NOT NULL "
        "GROUP BY protocol ORDER BY count DESC LIMIT 10"
    ).fetchall()

    # Get time range
    time_range = conn.execute(
        "SELECT MIN(timestamp) as min_time, MAX(timestamp) as max_time FROM packets"
    ).fetchone()

    return {
        "row_count": row_count,
        "columns": column_info,
        "top_protocols": [{"protocol": p[0], "count": p[1]} for p in protocols],
        "time_range": {"min": time_range[0], "max": time_range[1]},
    }
