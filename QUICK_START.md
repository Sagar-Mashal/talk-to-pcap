# Talk-to-PCAP - Quick Command Reference

## Setup (One-Time)
```bash
# Install dependencies
pip install -r requirements.txt

# Set Gemini API key (required for natural language queries)
$env:GEMINI_API_KEY = "your_api_key_here"
```

## Common Commands

### Parse PCAP Files
```bash
# Basic parsing (4G with default filter)
python -m src.cli parse pcapLog.pcap

# Parse and keep intermediate files for debugging
python -m src.cli parse pcapLog.pcap --keep-intermediates

# Parse with custom filter (5G)
python -m src.cli parse 5g_capture.pcap --tshark-filter "ngap || nr_rrc || nas_5gs"

# Parse without filter (all packets)
python -m src.cli parse capture.pcap --tshark-filter ""
```

### Query with Natural Language (Uses Gemini LLM)
```bash
# Simple count
python -m src.cli query data/parquet/pcapLog.parquet "How many NGAP messages?"

# Show top results
python -m src.cli query data/parquet/pcapLog.parquet "Show top 5 protocols"

# Complex query
python -m src.cli query data/parquet/pcapLog.parquet "List all handover messages"

# Show generated SQL
python -m src.cli query data/parquet/pcapLog.parquet "Count packets" --show-sql
```

### Query with Direct SQL (Free, No LLM)
```bash
# Count by protocol
python -m src.cli query data/parquet/pcapLog.parquet \
  "SELECT protocol, COUNT(*) FROM packets GROUP BY protocol" --no-llm

# Filter specific protocol
python -m src.cli query data/parquet/pcapLog.parquet \
  "SELECT * FROM packets WHERE protocol='S1AP' LIMIT 10" --no-llm

# Export to JSON
python -m src.cli query data/parquet/pcapLog.parquet \
  "SELECT * FROM packets LIMIT 100" --no-llm --format json > output.json
```

### Inspect Data
```bash
# Show statistics
python -m src.cli inspect data/parquet/pcapLog.parquet --stats

# Show sample data (first 10 rows)
python -m src.cli inspect data/parquet/pcapLog.parquet --head 10

# Show both
python -m src.cli inspect data/parquet/pcapLog.parquet --stats --head 20
```

### Check Examples
```bash
# Show example queries
python -m src.cli examples
```

## File Locations
```
Input:  pcapLog.pcap
JSON:   data/json/pcapLog.jsonl     (if --keep-intermediates)
Output: data/parquet/pcapLog.parquet
Logs:   talk-to-pcap.log
```

## Common Filters

### 4G LTE (Default)
```
s1ap || x2ap || lte_rrc
```

### 5G NR
```
ngap || nr_rrc || nas_5gs
```

### All Protocols
```
""  (empty string = no filter)
```

## Troubleshooting

### Error: "GEMINI_API_KEY not found"
```bash
$env:GEMINI_API_KEY = "your_key_here"
# Or create .env file with: GEMINI_API_KEY=your_key_here
```

### Error: "tshark not found"
- Install Wireshark
- Add to PATH: `C:\Program Files\Wireshark\`

### Error: "No packets matched filter"
- Try without filter: `--tshark-filter ""`
- Verify PCAP contains the protocols

### Debug JSON/Parquet issues
```bash
# Keep intermediate files to inspect
python -m src.cli parse file.pcap --keep-intermediates

# Check the JSON file
Get-Content data/json/file.jsonl -Head 5

# View logs
Get-Content talk-to-pcap.log -Tail 50
```

## Performance Tips

1. **Use filters** to reduce processing time
2. **Use --no-llm** for free SQL queries
3. **Keep intermediates** only when debugging
4. **Query Parquet files** directly (fast, no re-parsing)

## Output Formats

```bash
--format table   # Default, pretty ASCII table
--format json    # JSON array
--format csv     # CSV format
--format sql     # Show SQL query only
```

## Documentation

- Complete guide: `COMPLETE_SUCCESS_REPORT.md`
- Bug fixes: `FIXES_SUMMARY.md`
- File paths: `FILE_LOCATIONS.md`
- Installation: `docs/installation.md`
