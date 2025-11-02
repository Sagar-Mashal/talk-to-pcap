"""Gemini API client for natural language query processing."""

from typing import Optional

import google.generativeai as genai

from src.config import config
from src.utils.logger import get_logger

logger = get_logger(__name__)


def initialize_gemini(api_key: Optional[str] = None) -> genai.GenerativeModel:
    """
    Initialize Gemini API client.

    Args:
        api_key: Gemini API key (if not provided, uses config)

    Returns:
        Gemini GenerativeModel instance

    Raises:
        ValueError: If API key not provided
        Exception: If API initialization fails
    """
    # Get API key
    key = api_key or config.GEMINI_API_KEY
    if not key:
        raise ValueError(
            "GEMINI_API_KEY not set. Get your key from "
            "https://makersuite.google.com/app/apikey"
        )

    try:
        # Configure API
        genai.configure(api_key=key)

        # Create model instance
        model = genai.GenerativeModel(
            model_name=config.GEMINI_MODEL,
            generation_config={
                "temperature": config.GEMINI_TEMPERATURE,
                "max_output_tokens": config.GEMINI_MAX_OUTPUT_TOKENS,
            },
        )

        # Test connection with simple prompt
        logger.info(f"Testing Gemini API connection (model: {config.GEMINI_MODEL})...")
        response = model.generate_content("Say 'OK' if you can read this.")

        if response and response.text:
            logger.info("✓ Gemini API connection successful")
            return model
        else:
            raise Exception("Gemini API test failed: no response")

    except Exception as e:
        logger.error(f"Failed to initialize Gemini: {e}")
        raise Exception(f"Gemini API initialization failed: {e}") from e


def generate_sql_from_nl(
    model: genai.GenerativeModel,
    natural_language_query: str,
    schema_info: str,
    few_shot_examples: str = "",
) -> str:
    """
    Generate SQL query from natural language using Gemini.

    Args:
        model: Gemini model instance
        natural_language_query: Natural language query
        schema_info: Database schema information
        few_shot_examples: Few-shot examples for better results

    Returns:
        Generated SQL query

    Raises:
        Exception: If generation fails
    """
    # Build prompt
    prompt = f"""You are a SQL expert specializing in 3GPP telecommunications data analysis.

Given the following database schema:
{schema_info}

{few_shot_examples}

Generate a SQL query for the following question:
"{natural_language_query}"

Requirements:
- Use only SELECT statements (no DROP, DELETE, UPDATE, INSERT, ALTER)
- Query the 'packets' table
- Include appropriate WHERE clauses and aggregations
- Limit results to 100 rows unless specifically asked for more
- Return ONLY the SQL query, no explanations or markdown formatting

SQL Query:"""

    try:
        logger.debug(f"Generating SQL for: {natural_language_query}")

        response = model.generate_content(prompt)

        if not response or not response.text:
            raise Exception("Gemini returned empty response")

        sql = response.text.strip()

        # Clean up response (remove markdown code blocks if present)
        if sql.startswith("```sql"):
            sql = sql[6:]
        if sql.startswith("```"):
            sql = sql[3:]
        if sql.endswith("```"):
            sql = sql[:-3]

        sql = sql.strip()

        logger.info(f"✓ Generated SQL: {sql[:100]}{'...' if len(sql) > 100 else ''}")

        return sql

    except Exception as e:
        logger.error(f"SQL generation failed: {e}")
        raise Exception(f"Failed to generate SQL: {e}") from e
