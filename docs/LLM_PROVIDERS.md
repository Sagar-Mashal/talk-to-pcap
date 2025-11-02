# Multi-Provider LLM Support

Talk-to-PCAP now supports multiple LLM providers! Choose the one that fits your needs.

## Supported Providers

### 1. **Google Gemini** (Default)
- **Model**: `gemini-2.5-flash-lite`
- **Get API Key**: https://makersuite.google.com/app/apikey
- **Install**: `pip install google-generativeai`

### 2. **OpenAI**
- **Model**: `gpt-4o` (or `gpt-4`, `gpt-3.5-turbo`)
- **Get API Key**: https://platform.openai.com/api-keys
- **Install**: `pip install openai`

### 3. **Anthropic Claude**
- **Model**: `claude-3-5-sonnet-20241022`
- **Get API Key**: https://console.anthropic.com/
- **Install**: `pip install anthropic`

## Configuration

### Option 1: Environment Variables

```bash
# Choose your provider
export LLM_PROVIDER=gemini  # or openai, anthropic

# Set the corresponding API key
export GEMINI_API_KEY=your_key_here
# or
export OPENAI_API_KEY=your_key_here
# or
export ANTHROPIC_API_KEY=your_key_here
```

### Option 2: .env File

Copy `.env.example` to `.env` and configure:

```bash
# Choose provider
LLM_PROVIDER=gemini

# Gemini setup
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash-lite

# OpenAI setup (if using OpenAI)
# OPENAI_API_KEY=your_openai_api_key_here
# OPENAI_MODEL=gpt-4o

# Anthropic setup (if using Anthropic)
# ANTHROPIC_API_KEY=your_anthropic_api_key_here
# ANTHROPIC_MODEL=claude-3-5-sonnet-20241022
```

## Advanced Options

### Custom OpenAI Endpoint

For Azure OpenAI or other compatible endpoints:

```bash
OPENAI_BASE_URL=https://your-azure-endpoint.openai.azure.com/
```

### Model-Specific Settings

```bash
# Gemini
GEMINI_TEMPERATURE=0.1
GEMINI_MAX_OUTPUT_TOKENS=2048

# OpenAI
OPENAI_TEMPERATURE=0.0
OPENAI_MAX_TOKENS=4096

# Anthropic
ANTHROPIC_TEMPERATURE=0.0
ANTHROPIC_MAX_TOKENS=4096
```

## Usage

Once configured, use the CLI normally:

```bash
# The LLM provider is automatically loaded from config
python -m src.cli query data/parquet/capture.parquet "Show all handover failures"
```

## Provider Comparison

| Feature | Gemini | OpenAI | Anthropic |
|---------|--------|--------|-----------|
| **Free Tier** | ✅ Yes | ❌ No | ❌ No |
| **Speed** | ⚡ Fast | ⚡ Fast | ⚡ Fast |
| **Context Window** | 1M tokens | 128K tokens | 200K tokens |
| **Best For** | Free usage, long context | Production apps | Complex reasoning |
| **Cost (per 1M tokens)** | Free → $0.30 | $2.50-$10 | $3.00-$15 |

## Troubleshooting

### "API key not found"
Make sure you've set the correct environment variable for your chosen provider:
- Gemini: `GEMINI_API_KEY`
- OpenAI: `OPENAI_API_KEY`
- Anthropic: `ANTHROPIC_API_KEY`

### "Module not found: openai"
Install the provider's package:
```bash
pip install openai  # or anthropic
```

### Switch providers mid-session
Just update the environment variable and restart:
```bash
export LLM_PROVIDER=openai
python -m src.cli query ...
```
