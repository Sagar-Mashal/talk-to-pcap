# Talk-to-PCAP Quick Reference

## Installation

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure API key
cp .env.example .env
# Edit .env and add GEMINI_API_KEY

# 3. Verify installation
python scripts/verify_tshark.py
```

## Common Commands

### Parse PCAP to Parquet

```bash
# Basic parsing
python -m src.cli parse pcapLog.pcap

# Keep intermediate files
python -m src.cli parse pcapLog.pcap --keep-intermediates

# Custom output directory
python -m src.cli parse pcapLog.pcap --output-dir /path/to/output

# Smaller chunks (for memory constraints)
python -m src.cli parse pcapLog.pcap --chunk-size 5000
```

### Query with Natural Language

```bash
# Basic query (table format)
python -m src.cli query data/parquet/pcapLog.parquet "List all RRC messages"

# JSON output
python -m src.cli query data/parquet/pcapLog.parquet "How many UEs attached?" --format json

# Show generated SQL
python -m src.cli query data/parquet/pcapLog.parquet "Show handover failures" --show-sql

# Limit results
python -m src.cli query data/parquet/pcapLog.parquet "List all packets" --limit 50
```

### Query with Direct SQL

```bash
# Execute SQL directly (no LLM)
python -m src.cli query data/parquet/pcapLog.parquet \\
  "SELECT * FROM packets WHERE protocol = 'RRC' LIMIT 10" --no-llm

# Count packets by protocol
python -m src.cli query data/parquet/pcapLog.parquet \\
  "SELECT protocol, COUNT(*) as count FROM packets GROUP BY protocol" --no-llm

# Find specific UE
python -m src.cli query data/parquet/pcapLog.parquet \\
  "SELECT * FROM packets WHERE ue_id LIKE '%123456789%'" --no-llm
```

### Inspect Data

```bash
# Show schema
python -m src.cli inspect data/parquet/pcapLog.parquet --schema

# Show statistics
python -m src.cli inspect data/parquet/pcapLog.parquet --stats

# Show sample data
python -m src.cli inspect data/parquet/pcapLog.parquet --head 20
```

### Utility Commands

```bash
# Show example queries
python -m src.cli examples

# Show version
python -m src.cli --version

# Show help
python -m src.cli --help
python -m src.cli parse --help
python -m src.cli query --help
```

## Example Queries (Natural Language)

| Question | Description |
|----------|-------------|
| "List all RRC messages" | Show RRC protocol messages |
| "How many unique UEs are in this capture?" | Count distinct UE identifiers |
| "Show me all attach requests" | Find NAS attach requests |
| "Find handover failures" | Show X2AP handover failures |
| "Count packets by protocol" | Protocol distribution |
| "Show all authentication failures" | Find auth failures |
| "What interfaces are present?" | List 3GPP interfaces (Uu, S1, X2, etc.) |
| "List all S1AP messages" | Show S1AP protocol messages |
| "Show packets from UE with IMSI 123456789012345" | Filter by specific UE |
| "Count messages by direction" | Uplink vs downlink distribution |

## SQL Schema

### Main Table: `packets`

| Column | Type | Description |
|--------|------|-------------|
| packet_number | INTEGER | Sequential packet number |
| timestamp | DOUBLE | Unix timestamp |
| timestamp_iso | VARCHAR | ISO 8601 timestamp |
| timestamp_hour | TIMESTAMP | Hour-based timestamp (for grouping) |
| length | INTEGER | Packet size in bytes |
| protocol_stack | VARCHAR[] | List of protocols |
| protocol | VARCHAR | Primary 3GPP protocol (RRC, NAS_EPS, S1AP, etc.) |
| message_type | VARCHAR | Protocol-specific message type |
| interface | VARCHAR | 3GPP interface (Uu, S1-MME, S1-U, X2, etc.) |
| direction | VARCHAR | UL (uplink) or DL (downlink) |
| ue_id | VARCHAR | User equipment identifier |
| source_ip | VARCHAR | Source IP address |
| destination_ip | VARCHAR | Destination IP address |
| source_port | INTEGER | Source port |
| destination_port | INTEGER | Destination port |

## Common SQL Patterns

```sql
-- Count packets by protocol
SELECT protocol, COUNT(*) as count 
FROM packets 
GROUP BY protocol 
ORDER BY count DESC;

-- Find specific message type
SELECT * FROM packets 
WHERE message_type LIKE '%Attach%Request%' 
LIMIT 100;

-- Time-series analysis
SELECT timestamp_hour, COUNT(*) as packet_count 
FROM packets 
GROUP BY timestamp_hour 
ORDER BY timestamp_hour;

-- UE-specific analysis
SELECT protocol, message_type, COUNT(*) as count 
FROM packets 
WHERE ue_id = 'IMSI:123456789012345' 
GROUP BY protocol, message_type;

-- Interface distribution
SELECT interface, COUNT(*) as count 
FROM packets 
WHERE interface IS NOT NULL 
GROUP BY interface;
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "tshark not found" | Install Wireshark, ensure tshark in PATH |
| "GEMINI_API_KEY not set" | Create .env file with API key |
| Out of memory | Use --chunk-size 5000 or smaller PCAP |
| Slow parsing | Normal for large files; use --verbose to monitor |
| Import errors | Activate venv: `source venv/bin/activate` |

## File Locations

- **Input**: `data/pcap/*.pcap`
- **Intermediate**: `data/pdml/*.pdml`, `data/json/*.jsonl`
- **Output**: `data/parquet/*.parquet`
- **Logs**: `talk-to-pcap.log`
- **Config**: `.env`

## Environment Variables

```bash
# Required for NL queries
GEMINI_API_KEY=your_api_key_here

# Optional
TALK_TO_PCAP_DATA_DIR=/path/to/data
TALK_TO_PCAP_LOG_LEVEL=INFO
GEMINI_MODEL=gemini-1.5-flash
```

## Performance Tips

1. **For large PCAPs (>1GB)**:
   - Use smaller chunk size: `--chunk-size 5000`
   - Keep intermediates for debugging: `--keep-intermediates`
   - Monitor memory usage

2. **For faster queries**:
   - Use direct SQL with `--no-llm` when possible
   - Limit results with `--limit N`
   - Use WHERE clauses to filter early

3. **For debugging**:
   - Use `--show-sql` to see generated queries
   - Use `--verbose` for detailed logging
   - Inspect intermediate files with `inspect` command

## Links

- **Installation Guide**: `docs/installation.md`
- **Full README**: `README.md`
- **Specification**: `specs/001-parse-lte-5g/spec.md`
- **Implementation Summary**: `IMPLEMENTATION_SUMMARY.md`
