# Talk-to-PCAP

Natural language query interface for 3GPP LTE/5G PCAP files. Ask questions about your packet captures in plain English and get SQL-grounded answers.

## Features

- **Parse PCAP files** to efficient Parquet columnar format
- **Query using natural language** powered by Google Gemini AI
- **Full 3GPP protocol support**: RRC, NAS, S1AP, X2AP, NGAP, and more
- **Fast queries** on multi-GB datasets using DuckDB
- **Preserves protocol fidelity** by leveraging Wireshark's dissectors
- **Runs locally** with file-based storage (no external databases)

## Quick Start

### Installation

1. **Prerequisites**:
   - Python 3.9+
   - Wireshark/tshark 4.0+ (for PCAP parsing)
   - Gemini API key ([get one free](https://makersuite.google.com/app/apikey))

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Configure API key**:
```bash
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

### Usage

#### 1. Parse a PCAP file

Convert PCAP to queryable Parquet format:

```bash
python -m src.cli parse pcapLog.pcap
```

This will create `data/parquet/pcapLog.parquet`.

#### 2. Query using natural language

```bash
python -m src.cli query data/parquet/pcapLog.parquet "List all RRC messages"

python -m src.cli query data/parquet/pcapLog.parquet "How many UEs attached?"

python -m src.cli query data/parquet/pcapLog.parquet "Show handover failures"
```

#### 3. Query using direct SQL

```bash
python -m src.cli query data/parquet/pcapLog.parquet \\
  "SELECT * FROM packets WHERE protocol = 'RRC' LIMIT 10" --no-llm
```

#### 4. Inspect parsed data

```bash
# Show schema
python -m src.cli inspect data/parquet/pcapLog.parquet --schema

# Show statistics
python -m src.cli inspect data/parquet/pcapLog.parquet --stats

# Show sample data
python -m src.cli inspect data/parquet/pcapLog.parquet --head 20
```

## Example Queries

Talk-to-PCAP understands questions about 3GPP protocols:

- "List all RRC messages"
- "How many unique UEs are in this capture?"
- "Show me all attach requests"
- "Find handover failures"
- "Count packets by protocol"
- "Show all authentication failures"
- "What interfaces are present in this capture?"
- "Show packets from UE with IMSI 123456789012345"
- "List all S1AP messages in the last hour"

## Data Pipeline

```
PCAP → tshark (PDML XML) → Python (JSON) → pandas (Parquet) → DuckDB → Gemini → Results
```

1. **PCAP → PDML**: tshark converts PCAP to XML with full protocol dissection
2. **PDML → JSON**: Python extracts fields into newline-delimited JSON
3. **JSON → Parquet**: pandas converts to columnar format with compression
4. **Parquet → DuckDB**: DuckDB loads Parquet for fast SQL queries
5. **Natural Language → SQL**: Gemini translates questions to SQL
6. **SQL → Results**: DuckDB executes query and returns results

## Architecture

```
src/
├── parsers/          # PCAP/PDML parsing (tshark_wrapper, pdml_parser, field_extractors)
├── transformers/     # Data format conversions (xml_to_json, json_to_parquet)
├── query/            # Query execution (duckdb_loader, sql_executor, formatters)
├── agents/           # LLM integration (gemini_client, query_executor, prompts)
├── models/           # Data structures (packet, query)
├── utils/            # Utilities (logger)
├── config.py         # Configuration management
├── pipeline.py       # Parsing pipeline orchestrator
└── cli.py            # Command-line interface
```

## Configuration

Environment variables (set in `.env` file):

- `GEMINI_API_KEY`: Gemini API key (required for NL queries)
- `TALK_TO_PCAP_DATA_DIR`: Data directory (default: `./data`)
- `TALK_TO_PCAP_LOG_LEVEL`: Logging level (default: `INFO`)

## Development

### Running Tests

```bash
pytest
```

### Code Quality

```bash
# Format code
black src tests

# Lint
ruff check src tests

# Type check
mypy src
```

## Performance

- **Parsing**: ~1GB PCAP → Parquet in <5 minutes (4-core CPU, 8GB RAM)
- **Querying**: <10 seconds for 1M packet datasets
- **Memory**: Streaming processing with chunking for large files
- **Storage**: Parquet files ~2x PCAP size (with snappy compression)

## Supported Protocols

### 3GPP Radio Access

- LTE RRC (Radio Resource Control)
- 5G NR RRC
- LTE PDCP/RLC/MAC
- 5G PDCP/RLC/MAC

### 3GPP Core Network

- LTE NAS (Non-Access Stratum)
- 5G NAS
- S1AP (LTE S1 interface)
- X2AP (LTE X2 interface)
- NGAP (5G NG interface)
- GTP-C / GTP-U
- Diameter

## Limitations

- Requires Wireshark 4.0+ for 3GPP protocol dissectors
- Gemini API has rate limits (free tier: 60 requests/minute)
- Memory usage scales with PCAP size (recommend 8GB+ RAM for multi-GB files)
- Parsing is single-threaded (parallelization possible for multi-file processing)

## Troubleshooting

### "tshark not found"

Install Wireshark:
- **Linux**: `sudo apt install tshark`
- **macOS**: `brew install wireshark`
- **Windows**: Download from [wireshark.org](https://www.wireshark.org/download.html)

### "GEMINI_API_KEY not set"

1. Get API key from https://makersuite.google.com/app/apikey
2. Add to `.env` file: `GEMINI_API_KEY=your_key_here`

### Out of memory errors

Try:
- Reduce chunk size: `--chunk-size 5000`
- Process smaller PCAP files
- Increase system RAM

### Incorrect query results

- Check generated SQL with `--show-sql` flag
- Use `--no-llm` to execute direct SQL for validation
- Report issues with sample queries for improvement

## License

MIT

## Contributing

Contributions welcome! Please see the project's specification documents in `specs/` for architecture and design decisions.

## Acknowledgments

- **Wireshark**: Protocol dissectors and tshark CLI
- **Google Gemini**: Natural language understanding
- **DuckDB**: Fast analytical queries
- **LangChain**: LLM orchestration framework
