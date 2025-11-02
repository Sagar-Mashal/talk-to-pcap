# Installation Guide

Complete installation instructions for Talk-to-PCAP on Linux, macOS, and Windows.

## Prerequisites

### 1. Python 3.9+

**Check existing installation:**
```bash
python --version
```

**Install Python:**

- **Linux (Ubuntu/Debian)**:
  ```bash
  sudo apt update
  sudo apt install python3.9 python3.9-venv python3-pip
  ```

- **macOS**:
  ```bash
  brew install python@3.9
  ```

- **Windows**:
  Download from [python.org](https://www.python.org/downloads/) and install.

### 2. Wireshark/tshark 4.0+

Talk-to-PCAP requires tshark (Wireshark's command-line tool) for PCAP parsing.

**Check existing installation:**
```bash
tshark --version
```

**Install Wireshark:**

- **Linux (Ubuntu/Debian)**:
  ```bash
  sudo apt update
  sudo apt install tshark wireshark
  
  # Allow non-root users to capture packets (optional)
  sudo usermod -aG wireshark $USER
  ```

- **macOS**:
  ```bash
  brew install wireshark
  
  # Add tshark to PATH (if not already)
  export PATH="/usr/local/bin:$PATH"
  ```

- **Windows**:
  1. Download installer from [wireshark.org](https://www.wireshark.org/download.html)
  2. Run installer and select "TShark" component
  3. Add Wireshark directory to PATH: `C:\\Program Files\\Wireshark`

**Verify installation:**
```bash
tshark --version
# Should show: TShark (Wireshark) 4.0.x or higher
```

### 3. Gemini API Key

Required for natural language queries.

1. Get a free API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Save the key (you'll add it to `.env` file later)

## Installation Steps

### 1. Clone Repository

```bash
git clone <repository_url>
cd talk_to_pcap
```

### 2. Create Virtual Environment

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows (PowerShell):**
```powershell
python -m venv venv
.\\venv\\Scripts\\Activate.ps1
```

**Windows (Command Prompt):**
```cmd
python -m venv venv
venv\\Scripts\\activate.bat
```

### 3. Install Dependencies

```bash
# Install core dependencies
pip install -r requirements.txt

# Install development dependencies (optional)
pip install -r requirements-dev.txt
```

### 4. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit .env and add your Gemini API key
# On Linux/macOS:
nano .env

# On Windows:
notepad .env
```

Add your API key to `.env`:
```
GEMINI_API_KEY=your_actual_api_key_here
```

### 5. Verify Installation

```bash
# Check tshark
python scripts/verify_tshark.py

# Check 3GPP dissectors
python scripts/verify_3gpp_dissectors.py

# Test CLI
python -m src.cli --version
python -m src.cli --help
```

## Quick Test

Test the installation with a sample PCAP:

```bash
# 1. Download a sample PCAP (or use your own)
# Place it in data/pcap/ directory

# 2. Parse PCAP
python -m src.cli parse data/pcap/sample.pcap

# 3. Query using natural language
python -m src.cli query data/parquet/sample.parquet "List all RRC messages"

# 4. Query using direct SQL (no API key needed)
python -m src.cli query data/parquet/sample.parquet \\
  "SELECT * FROM packets LIMIT 10" --no-llm
```

## Troubleshooting

### "tshark not found"

**Solution:**
- Verify tshark is installed: `which tshark` (Linux/macOS) or `where tshark` (Windows)
- Add Wireshark to PATH if needed
- On Windows, ensure `C:\\Program Files\\Wireshark` is in system PATH

### "GEMINI_API_KEY not set"

**Solution:**
- Create `.env` file from `.env.example`
- Add valid API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
- Verify file is named exactly `.env` (not `.env.txt`)

### "Import errors" or "Module not found"

**Solution:**
- Activate virtual environment: `source venv/bin/activate` (Linux/macOS) or `venv\\Scripts\\activate` (Windows)
- Reinstall dependencies: `pip install -r requirements.txt`
- Verify Python version: `python --version` (must be 3.9+)

### "Permission denied" errors on Linux

**Solution:**
```bash
# For tshark
sudo usermod -aG wireshark $USER
# Log out and log back in

# For file permissions
chmod +x scripts/*.py
```

### Out of memory errors

**Solution:**
- Process smaller PCAP files first
- Reduce chunk size: `--chunk-size 5000`
- Increase system RAM (recommend 8GB+ for multi-GB PCAPs)

### Slow parsing performance

**Solution:**
- Parsing is CPU-bound; use faster CPU or smaller PCAP files
- Monitor with `--verbose` flag to see progress
- Consider splitting large PCAP into smaller files

## System Requirements

### Minimum

- Python 3.9+
- 4GB RAM
- 2-core CPU
- 10GB disk space (for intermediate files)

### Recommended

- Python 3.10+
- 8GB+ RAM
- 4-core CPU
- 50GB disk space (for large PCAP datasets)

## Platform-Specific Notes

### Linux

- Preferred platform (best performance)
- tshark runs fastest on Linux
- Use `apt`, `yum`, or `dnf` for package management

### macOS

- Works well on Intel and Apple Silicon
- Use Homebrew for dependencies
- May need to adjust PATH for tshark

### Windows

- Fully supported via PowerShell or Command Prompt
- Ensure Python and Wireshark are in system PATH
- WSL2 (Windows Subsystem for Linux) recommended for best performance

## Next Steps

After installation:

1. Read the [README](../README.md) for usage examples
2. Try example queries: `python -m src.cli examples`
3. Review the [specification](../specs/001-parse-lte-5g/spec.md) for use cases
4. Check [quickstart guide](../specs/002-baseline-pcap-agent/quickstart.md) for detailed scenarios

## Support

For installation issues:

1. Check this guide's troubleshooting section
2. Verify all prerequisites are installed correctly
3. Review error messages and logs in `talk-to-pcap.log`
4. Open an issue with system details and error logs
