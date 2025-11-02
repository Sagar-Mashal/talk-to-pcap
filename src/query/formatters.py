"""Result formatters for different output formats."""

import json
from typing import List

from tabulate import tabulate

from src.models.query import QueryRequest, QueryResult, ResultType


def format_as_table(result: QueryResult) -> str:
    """
    Format query result as ASCII table.

    Args:
        result: Query result

    Returns:
        Formatted table string
    """
    if result.is_empty():
        return "No results found."

    # Scalar result
    if result.result_type == ResultType.SCALAR and result.row_count == 1:
        col_name = result.columns[0]
        value = result.data[0][col_name]
        return f"{col_name}: {value}"

    # Table result
    headers = result.columns
    import logging
    logger = logging.getLogger(__name__)
    logger.debug(f"Formatter - headers: {headers}")
    logger.debug(f"Formatter - result.data type: {type(result.data)}, length: {len(result.data) if hasattr(result.data, '__len__') else 'N/A'}")
    if result.data:
        logger.debug(f"Formatter - sample row (0): {result.data[0]}")

    # Build rows ensuring every cell is a string *before* calling tabulate
    rows: List[List[str]] = []
    for row_idx, row in enumerate(result.data):
        current: List[str] = []
        for col in headers:
            raw = row.get(col) if isinstance(row, dict) else getattr(row, col, '')
            if raw is None:
                safe = ''
            else:
                try:
                    # Fast path for common primitives; avoid calling str twice
                    if isinstance(raw, (str, int, float)):
                        safe = str(raw)
                    else:
                        # Booleans & all other types coerced explicitly
                        safe = str(raw)
                except Exception as coercion_err:
                    logger.warning(f"Formatter - failed to coerce value at row {row_idx} col '{col}': {coercion_err}; using repr")
                    safe = repr(raw)
            current.append(safe)
        rows.append(current)

    if rows:
        logger.debug(f"Formatter - coerced first row types: {[type(v) for v in rows[0]]}")
        logger.debug(f"Formatter - coerced first row values: {rows[0]}")

    # Defensive: final pass guarantee – convert any lingering non-str (should not happen)
    for r_i, r in enumerate(rows):
        for c_i, cell in enumerate(r):
            if not isinstance(cell, str):  # pragma: no cover (safety net)
                logger.debug(f"Formatter - late coercion row {r_i} col {c_i} type {type(cell)}")
                r[c_i] = str(cell)

    try:
        # Some tabulate versions exhibit a bug coercing already-stringified booleans when maxcolwidths is set.
        # Use a conservative call without maxcolwidths first; if desired this can be reintroduced conditionally.
        table = tabulate(rows, headers=headers, tablefmt="grid")
    except Exception as e:
        # Capture per-cell types to aid debug then fallback to simple formatter
        logger.error(f"Tabulate failed ({e}); falling back to plain table rendering", exc_info=True)
        diagnostics = []
        for r in rows[:5]:  # limit
            diagnostics.append(', '.join(f"{headers[i]}={repr(v)}({type(v).__name__})" for i, v in enumerate(r)))
        logger.error("Formatter diagnostics (first rows):\n" + "\n".join(diagnostics))
        # Plain fallback
        col_widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)] if rows else [len(h) for h in headers]
        def _fmt_row(vals):
            return " | ".join(v.ljust(col_widths[i]) for i, v in enumerate(vals))
        sep = "-+-".join('-' * w for w in col_widths)
        out_lines = [_fmt_row(headers), sep]
        out_lines.extend(_fmt_row(r) for r in rows)
        return "\n".join(out_lines) + f"\n({result.row_count} rows)"

    footer = f"\n({result.row_count} rows)"
    return table + footer


def format_as_json(result: QueryResult, pretty: bool = True) -> str:
    """
    Format query result as JSON.

    Args:
        result: Query result
        pretty: Use pretty printing (indented)

    Returns:
        JSON string
    """
    output = {"query_id": result.query_id, "row_count": result.row_count, "data": result.data}

    if pretty:
        return json.dumps(output, indent=2, ensure_ascii=False)
    else:
        return json.dumps(output, ensure_ascii=False)


def format_as_csv(result: QueryResult) -> str:
    """
    Format query result as CSV.

    Args:
        result: Query result

    Returns:
        CSV string
    """
    if result.is_empty():
        return "No results found."

    # Header row
    csv_lines = [",".join(result.columns)]

    # Data rows
    for row in result.data:
        values = [str(row[col]) if row[col] is not None else "" for col in result.columns]
        # Escape values with commas
        escaped_values = [f'"{v}"' if "," in v else v for v in values]
        csv_lines.append(",".join(escaped_values))

    return "\\n".join(csv_lines)


def format_as_sql(query_request: QueryRequest) -> str:
    """
    Format generated SQL with comments.

    Args:
        query_request: Query request

    Returns:
        Formatted SQL string
    """
    lines = [
        "-- Generated SQL Query",
        f"-- Natural Language: {query_request.query_text}",
        f"-- Query ID: {query_request.query_id}",
        f"-- Status: {query_request.status.value}",
    ]

    if query_request.execution_time_ms:
        lines.append(f"-- Execution Time: {query_request.execution_time_ms}ms")

    lines.append("")
    lines.append(query_request.generated_sql or "-- No SQL generated")

    return "\\n".join(lines)


def format_query_summary(query_request: QueryRequest, result: QueryResult) -> str:
    """
    Format complete query summary.

    Args:
        query_request: Query request
        result: Query result

    Returns:
        Summary string
    """
    lines = [
        "=" * 80,
        f"Query: {query_request.query_text}",
        f"Status: {query_request.status.value}",
    ]

    if query_request.generated_sql:
        lines.append(f"Generated SQL: {query_request.generated_sql}")

    if query_request.execution_time_ms:
        lines.append(f"Execution Time: {query_request.execution_time_ms}ms")

    lines.append(f"Result: {result.row_count} rows")

    if result.summary:
        lines.append(f"Summary: {result.summary}")

    if query_request.error_message:
        lines.append(f"Error: {query_request.error_message}")

    lines.append("=" * 80)

    return "\\n".join(lines)


def format_list(items: List[str], title: str = "") -> str:
    """
    Format a simple list.

    Args:
        items: List of strings
        title: Optional title

    Returns:
        Formatted list
    """
    lines = []
    if title:
        lines.append(title)
        lines.append("-" * len(title))

    for item in items:
        lines.append(f"  - {item}")

    return "\\n".join(lines)
