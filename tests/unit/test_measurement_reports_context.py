import duckdb, json, sys, pytest
from pathlib import Path

# Ensure root on path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.query.query_helpers import extract_rsrp_rsrq_values

def setup_duckdb():
    conn = duckdb.connect(':memory:')
    # Use new parquet if present, else fallback
    parquet_path_new = PROJECT_ROOT / 'data' / 'parquet' / 'pcapLog_new.parquet'
    target = parquet_path_new if parquet_path_new.exists() else (PROJECT_ROOT / 'data' / 'parquet' / 'pcapLog.parquet')
    if not target.exists():
        pytest.skip(f"Test data file not found: {target}")
    conn.execute(f"CREATE TABLE packets AS SELECT * FROM read_parquet('{target.as_posix()}')")
    return conn

def fetch_packet(conn, pkt):
    sql = f"SELECT packet_number, timestamp_iso, protocol_fields_json FROM packets WHERE packet_number={pkt}"
    return conn.execute(sql).fetchdf().to_dict('records')

def test_contextual_pcell_preference_dynamic():
    conn = setup_duckdb()
    # Find any packet with contextual pcell keys
    sql = "SELECT packet_number, timestamp_iso, protocol_fields_json FROM packets WHERE protocol_fields_json LIKE '%rsrpResult__context=pcell%' LIMIT 1"
    rows = conn.execute(sql).fetchdf().to_dict('records')
    assert rows, 'No packet with contextual pcell rsrp key found (parser enhancement missing?)'
    pkt_row = rows[0]
    fields = json.loads(pkt_row['protocol_fields_json'])
    rsrp_pcell_key = next((k for k in fields.keys() if k.endswith('lte-rrc.rsrpResult__context=pcell')), None)
    rsrq_pcell_key = next((k for k in fields.keys() if k.endswith('lte-rrc.rsrqResult__context=pcell')), None)
    assert rsrp_pcell_key, 'Missing contextual pcell rsrp key'
    assert rsrq_pcell_key, 'Missing contextual pcell rsrq key'
    # Use extractor and ensure it returns the pcell indices (matches contextual values)
    extracted = extract_rsrp_rsrq_values(rows)
    assert extracted, 'Extractor did not return measurement for contextual packet.'
    meas = extracted[0]
    expected_rsrp = int(fields[rsrp_pcell_key])
    expected_rsrq = int(fields[rsrq_pcell_key])
    assert meas['rsrp_result'] == expected_rsrp, f"Extractor rsrp_result {meas['rsrp_result']} != contextual {expected_rsrp}"
    assert meas['rsrq_result'] == expected_rsrq, f"Extractor rsrq_result {meas['rsrq_result']} != contextual {expected_rsrq}"
    # Neighbor contextual keys (optional) - do not fail test if absent, but gather diagnostics
    neigh_keys = [k for k in fields.keys() if k.startswith('lte-rrc.rsrpResult__context=neigh')]
    if not neigh_keys:
        print('No neighbor contextual rsrp keys present for packet', pkt_row['packet_number'])
