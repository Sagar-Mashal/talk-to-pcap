import duckdb
import json
import sys
import pytest
from pathlib import Path

# Ensure project root is on path so 'src' package resolves when running tests in environments
# that do not automatically add it (e.g., direct invocation without editable install).
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.query.query_helpers import extract_rsrp_rsrq_values, resolve_rlc_ids_for_logical_ue
from src.analysis.ue_correlation import build_correlation_table

# NOTE: This is a lightweight unit-style test relying on the existing parquet file.
# It validates that measurement reports can be extracted for several UE identifiers
# including a logical UE id that requires correlation ("1" -> RLC UE ID 61).

def setup_duckdb():
    parquet_path = Path('data/parquet/pcapLog.parquet')
    if not parquet_path.exists():
        pytest.skip(f"Test data file not found: {parquet_path}")
    conn = duckdb.connect(':memory:')
    conn.execute("CREATE TABLE packets AS SELECT * FROM read_parquet('data/parquet/pcapLog.parquet')")
    return conn


def fetch_packets_for_rsrp(conn, rlc_ids):
    if not rlc_ids:
        return []
    clauses = []
    for rid in sorted(rlc_ids):
        clauses.append(f"protocol_fields_json LIKE '%\"rlc_lte.rlc-lte.ueid\": \"{rid}\",%'")
        clauses.append(f"protocol_fields_json LIKE '%\"rlc_lte.rlc-lte.ueid\": \"{rid}\"}}%'")
    or_clause = " OR ".join(clauses)
    sql = (
        "SELECT packet_number, timestamp_iso, protocol_fields_json FROM packets WHERE "
        "protocol_fields_json LIKE '%rsrpResult%' AND protocol_fields_json LIKE '%rsrqResult%' "
        f"AND ({or_clause}) ORDER BY packet_number"
    )
    return conn.execute(sql).fetchdf().to_dict('records')


def test_measurement_reports_multi_ue():
    conn = setup_duckdb()
    # Build correlation table using a small subset (optimization: sampling) - here full for correctness
    packets = conn.execute("SELECT packet_number, protocol_fields_json FROM packets LIMIT 5000").fetchdf().to_dict('records')
    correlation_table = build_correlation_table(packets)

    test_inputs = ["64", "65", "66", "1"]  # include logical UE id 1
    results_summary = {}

    for ue in test_inputs:
        rlc_ids = resolve_rlc_ids_for_logical_ue(ue, correlation_table, conn)
        packets_rows = fetch_packets_for_rsrp(conn, rlc_ids)
        extracted = extract_rsrp_rsrq_values(packets_rows)
        results_summary[ue] = {
            'resolved_rlc_ids': sorted(list(rlc_ids)),
            'packet_numbers': [r['packet_number'] for r in extracted],
            'count': len(extracted)
        }

    # Basic assertions: each UE should yield at least one measurement report
    # (Depending on dataset, UE 66 may have 2, etc.)
    for ue, summary in results_summary.items():
        assert summary['count'] >= 1, f"Expected at least one measurement report for UE {ue}; got {summary['count']} (resolved RLC IDs: {summary['resolved_rlc_ids']})"
        assert summary['resolved_rlc_ids'], f"No RLC IDs resolved for UE {ue}" 

    # Ensure logical UE id '1' resolved to a different RLC ID (e.g., 61)
    logical_summary = results_summary['1']
    assert any(rid != '1' for rid in logical_summary['resolved_rlc_ids']), "Logical UE '1' did not resolve to any distinct RLC UE IDs"

    # Optionally print a compact debug summary (would be visible when running pytest -s)
    print("Measurement report extraction summary:")
    for ue, summary in results_summary.items():
        print(f"UE {ue}: RLC IDs {summary['resolved_rlc_ids']} -> packets {summary['packet_numbers']}")
