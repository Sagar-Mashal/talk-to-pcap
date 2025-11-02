"""Transform JSON to Parquet columnar format."""

import json
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from src.config import config
from src.utils.logger import get_logger

logger = get_logger(__name__)


def json_to_parquet(
    json_path: str,
    parquet_output_path: str,
    chunk_size: int = 10000,
) -> None:
    """
    Convert newline-delimited JSON to Parquet format.
    Processes in chunks and handles malformed JSON lines gracefully.

    Args:
        json_path: Path to JSONL file
        parquet_output_path: Path to output Parquet file
        chunk_size: Number of records to process per chunk

    Raises:
        FileNotFoundError: If JSON file doesn't exist
    """
    json_file = Path(json_path)
    if not json_file.exists():
        raise FileNotFoundError(f"JSON file not found: {json_path}")

    parquet_file = Path(parquet_output_path)
    parquet_file.parent.mkdir(parents=True, exist_ok=True)

    logger.info(f"Converting JSON → Parquet: {json_file.absolute()} → {parquet_file.absolute()}")

    total_rows = 0
    malformed_lines = 0
    first_chunk = True
    parquet_writer = None
    schema = None
    buffer = []

    try:
        with open(json_file, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                try:
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    buffer.append(record)
                except json.JSONDecodeError as e:
                    malformed_lines += 1
                    logger.warning(f"Skipping malformed JSON line {i}: {str(e)[:100]}")
                    if i <= 3:  # Show first few malformed lines for debugging
                        logger.debug(f"Malformed line content: {line[:200]}")
                    continue

                if len(buffer) >= chunk_size:
                    schema, parquet_writer, first_chunk = _write_chunk(
                        buffer, schema, parquet_writer, parquet_file, first_chunk
                    )
                    total_rows += len(buffer)
                    logger.debug(f"Wrote {total_rows:,} rows...")
                    buffer = []

            if buffer:
                schema, parquet_writer, first_chunk = _write_chunk(
                    buffer, schema, parquet_writer, parquet_file, first_chunk
                )
                total_rows += len(buffer)

        if malformed_lines > 0:
            logger.warning(f"Skipped {malformed_lines:,} malformed JSON lines in total.")

        if total_rows == 0:
            raise ValueError(f"No valid data rows found in JSON file. All {malformed_lines} lines were malformed.")

        logger.info(
            f"✓ Parquet created: {parquet_file.absolute()} ({parquet_file.stat().st_size:,} bytes, "
            f"{total_rows:,} rows)"
        )

    except Exception as e:
        logger.error(f"Error converting JSON to Parquet: {e}", exc_info=True)
        if parquet_file.exists():
            parquet_file.unlink()
        raise
    finally:
        if parquet_writer:
            parquet_writer.close()


def _write_chunk(buffer, schema, writer, path, is_first):
    """Write a chunk of records to the Parquet file."""
    df = pd.DataFrame(buffer)

    # Data Sanitization
    df["timestamp"] = pd.to_numeric(df["timestamp"], errors='coerce')
    df["timestamp_hour"] = pd.to_datetime(df["timestamp"], unit="s").dt.floor("H")

    for col in ["protocol_fields", "protocol_layers", "protocol_stack"]:
        if col in df.columns:
            new_col_name = f"{col}_json"
            df[new_col_name] = df[col].apply(
                lambda x: json.dumps(x) if isinstance(x, (dict, list)) else None
            )
            df = df.drop(columns=[col])

    for col in df.columns:
        if df[col].dtype == 'object':
            df[col] = df[col].astype(str)

    table = pa.Table.from_pandas(df, schema=schema)

    if is_first:
        schema = table.schema
        writer = pq.ParquetWriter(
            path,
            schema,
            compression=config.PARQUET_COMPRESSION,
            use_dictionary=True,
            write_statistics=True,
        )
        is_first = False

    if not table.schema.equals(writer.schema):
        table = table.cast(writer.schema)

    writer.write_table(table)
    return schema, writer, is_first


def get_parquet_schema(parquet_path: str) -> pa.Schema:
    """
    Get the schema of a Parquet file.

    Args:
        parquet_path: Path to Parquet file

    Returns:
        PyArrow schema

    Raises:
        FileNotFoundError: If Parquet file doesn't exist
    """
    parquet_file = Path(parquet_path)
    if not parquet_file.exists():
        raise FileNotFoundError(f"Parquet file not found: {parquet_path}")

    parquet_file_obj = pq.ParquetFile(parquet_file)
    return parquet_file_obj.schema


def get_parquet_stats(parquet_path: str) -> dict:
    """
    Get statistics about a Parquet file.

    Args:
        parquet_path: Path to Parquet file

    Returns:
        Dictionary with file statistics

    Raises:
        FileNotFoundError: If Parquet file doesn't exist
    """
    parquet_file = Path(parquet_path)
    if not parquet_file.exists():
        raise FileNotFoundError(f"Parquet file not found: {parquet_path}")

    parquet_file_obj = pq.ParquetFile(parquet_file)
    metadata = parquet_file_obj.metadata

    return {
        "num_rows": metadata.num_rows,
        "num_row_groups": metadata.num_row_groups,
        "num_columns": metadata.num_columns,
        "file_size_bytes": parquet_file.stat().st_size,
        "file_size_mb": parquet_file.stat().st_size / (1024 * 1024),
        "created_by": metadata.created_by,
        "schema": str(parquet_file_obj.schema),
    }
