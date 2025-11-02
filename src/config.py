"""Configuration management for Talk-to-PCAP."""

import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Application configuration."""

    # LLM Provider Settings
    # Supported providers: "gemini", "openai", "anthropic"
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "gemini").lower()
    
    # Gemini API settings
    GEMINI_API_KEY: Optional[str] = os.getenv("GEMINI_API_KEY")
    
    # OpenAI API settings
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o")
    OPENAI_BASE_URL: Optional[str] = os.getenv("OPENAI_BASE_URL")  # For custom endpoints
    
    # Anthropic API settings
    ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
    ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")

    # Data directories
    PROJECT_ROOT = Path(__file__).parent.parent.absolute()
    DATA_DIR = Path(os.getenv("TALK_TO_PCAP_DATA_DIR", PROJECT_ROOT / "data"))
    PCAP_DIR = DATA_DIR / "pcap"
    PDML_DIR = DATA_DIR / "pdml"
    JSON_DIR = DATA_DIR / "json"
    PARQUET_DIR = DATA_DIR / "parquet"
    DUCKDB_DIR = DATA_DIR / "duckdb"

    # Logging
    LOG_LEVEL = os.getenv("TALK_TO_PCAP_LOG_LEVEL", "INFO").upper()
    LOG_FILE = PROJECT_ROOT / "talk-to-pcap.log"

    # Processing settings
    CHUNK_SIZE = int(os.getenv("TALK_TO_PCAP_CHUNK_SIZE", "10000"))  # Packets per chunk
    MAX_WORKERS = int(os.getenv("TALK_TO_PCAP_MAX_WORKERS", "4"))  # Parallel processing

    # Parquet settings
    PARQUET_COMPRESSION = os.getenv("TALK_TO_PCAP_PARQUET_COMPRESSION", "snappy")
    PARQUET_ROW_GROUP_SIZE = int(os.getenv("TALK_TO_PCAP_PARQUET_ROW_GROUP_SIZE", "100000"))

    # Gemini model settings
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite")
    GEMINI_TEMPERATURE = float(os.getenv("GEMINI_TEMPERATURE", "0.1"))
    GEMINI_MAX_OUTPUT_TOKENS = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "2048"))
    
    # OpenAI model settings
    OPENAI_TEMPERATURE = float(os.getenv("OPENAI_TEMPERATURE", "0.0"))
    OPENAI_MAX_TOKENS = int(os.getenv("OPENAI_MAX_TOKENS", "4096"))
    
    # Anthropic model settings
    ANTHROPIC_TEMPERATURE = float(os.getenv("ANTHROPIC_TEMPERATURE", "0.0"))
    ANTHROPIC_MAX_TOKENS = int(os.getenv("ANTHROPIC_MAX_TOKENS", "4096"))

    # TShark settings - supports both 4G and 5G protocols
    TSHARK_DISPLAY_FILTER = os.getenv("TSHARK_DISPLAY_FILTER", "s1ap || x2ap || lte_rrc || ngap || f1ap || nr-rrc")

    @classmethod
    def validate(cls) -> None:
        """Validate required configuration."""
        errors = []

        # Check if GEMINI_API_KEY is set (only required for query command)
        if not cls.GEMINI_API_KEY:
            errors.append(
                "GEMINI_API_KEY not set. "
                "Get your key from https://makersuite.google.com/app/apikey "
                "and add it to .env file or set as environment variable."
            )

        if errors:
            raise ValueError("Configuration errors:\\n" + "\\n".join(f"  - {e}" for e in errors))

    @classmethod
    def validate_llm_key(cls) -> None:
        """Validate LLM API key is set based on selected provider."""
        provider = cls.LLM_PROVIDER
        
        if provider == "gemini" and not cls.GEMINI_API_KEY:
            raise ValueError(
                "GEMINI_API_KEY is required when using Gemini provider. "
                "Get your key from https://makersuite.google.com/app/apikey "
                "and add it to .env file or set GEMINI_API_KEY environment variable."
            )
        elif provider == "openai" and not cls.OPENAI_API_KEY:
            raise ValueError(
                "OPENAI_API_KEY is required when using OpenAI provider. "
                "Get your key from https://platform.openai.com/api-keys "
                "and add it to .env file or set OPENAI_API_KEY environment variable."
            )
        elif provider == "anthropic" and not cls.ANTHROPIC_API_KEY:
            raise ValueError(
                "ANTHROPIC_API_KEY is required when using Anthropic provider. "
                "Get your key from https://console.anthropic.com/ "
                "and add it to .env file or set ANTHROPIC_API_KEY environment variable."
            )
        elif provider not in ["gemini", "openai", "anthropic"]:
            raise ValueError(
                f"Unsupported LLM_PROVIDER: {provider}. "
                f"Supported providers: gemini, openai, anthropic"
            )
    
    @classmethod
    def validate_gemini_key(cls) -> None:
        """Validate Gemini API key is set (for query command). DEPRECATED: Use validate_llm_key()."""
        cls.validate_llm_key()

    @classmethod
    def ensure_data_dirs(cls) -> None:
        """Ensure all data directories exist."""
        for dir_path in [
            cls.DATA_DIR,
            cls.PCAP_DIR,
            cls.PDML_DIR,
            cls.JSON_DIR,
            cls.PARQUET_DIR,
            cls.DUCKDB_DIR,
        ]:
            dir_path.mkdir(parents=True, exist_ok=True)


# Global config instance
config = Config()
