"""Data models for query requests and results."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class QueryStatus(Enum):
    """Query execution status."""

    PENDING = "pending"
    GENERATING = "generating"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


class ResultType(Enum):
    """Type of query result."""

    SCALAR = "scalar"  # Single value
    TABLE = "table"  # Rows and columns
    TIME_SERIES = "time_series"  # Time-based data
    EMPTY = "empty"  # No results


@dataclass
class QueryRequest:
    """
    Represents a natural language query request.

    Attributes:
        query_id: Unique query identifier
        query_text: Natural language query
        dataset_path: Path to Parquet file being queried
        timestamp: Query submission time
        generated_sql: SQL generated from NL query (if applicable)
        execution_time_ms: Query execution time in milliseconds
        status: Current query status
        error_message: Error message if query failed
    """

    query_text: str
    dataset_path: str
    query_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    generated_sql: Optional[str] = None
    execution_time_ms: Optional[int] = None
    status: QueryStatus = QueryStatus.PENDING
    error_message: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "query_id": self.query_id,
            "query_text": self.query_text,
            "dataset_path": self.dataset_path,
            "timestamp": self.timestamp.isoformat(),
            "generated_sql": self.generated_sql,
            "execution_time_ms": self.execution_time_ms,
            "status": self.status.value,
            "error_message": self.error_message,
        }


@dataclass
class QueryResult:
    """
    Represents the result of a query execution.

    Attributes:
        query_id: Associated query ID
        result_type: Type of result
        row_count: Number of rows returned
        columns: List of column names
        data: Result data (list of dicts for table, single value for scalar)
        summary: Human-readable summary
        charts: Optional chart data for visualization
    """

    query_id: str
    result_type: ResultType
    row_count: int
    columns: List[str] = field(default_factory=list)
    data: Any = None
    summary: Optional[str] = None
    charts: Optional[Dict] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "query_id": self.query_id,
            "result_type": self.result_type.value,
            "row_count": self.row_count,
            "columns": self.columns,
            "data": self.data,
            "summary": self.summary,
            "charts": self.charts,
        }

    def is_empty(self) -> bool:
        """Check if result is empty."""
        return self.result_type == ResultType.EMPTY or self.row_count == 0
