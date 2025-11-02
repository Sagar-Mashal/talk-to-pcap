"""Universal LLM client supporting multiple providers (Gemini, OpenAI, Anthropic)."""

from typing import Optional, Dict, Any
import os

from src.config import config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class LLMClient:
    """Universal LLM client that abstracts different providers."""
    
    def __init__(self, provider: Optional[str] = None):
        """
        Initialize LLM client with specified provider.
        
        Args:
            provider: LLM provider ("gemini", "openai", "anthropic"). 
                     If None, uses config.LLM_PROVIDER.
        """
        self.provider = (provider or config.LLM_PROVIDER).lower()
        self.model = None
        self.client = None
        
        if self.provider == "gemini":
            self._init_gemini()
        elif self.provider == "openai":
            self._init_openai()
        elif self.provider == "anthropic":
            self._init_anthropic()
        else:
            raise ValueError(
                f"Unsupported LLM provider: {self.provider}. "
                f"Supported: gemini, openai, anthropic"
            )
    
    def _init_gemini(self):
        """Initialize Google Gemini client."""
        try:
            import google.generativeai as genai
        except ImportError:
            raise ImportError(
                "google-generativeai package required for Gemini. "
                "Install: pip install google-generativeai"
            )
        
        api_key = config.GEMINI_API_KEY
        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY not found. Set it in .env file or environment variable."
            )
        
        genai.configure(api_key=api_key)
        model_name = config.GEMINI_MODEL
        
        logger.info(f"Initializing Gemini client (model: {model_name})...")
        
        # Test connection
        try:
            test_model = genai.GenerativeModel(model_name)
            response = test_model.generate_content("test")
            logger.info("✓ Gemini API connection successful")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to Gemini API: {e}")
        
        self.model = genai.GenerativeModel(model_name)
        self.client = genai
    
    def _init_openai(self):
        """Initialize OpenAI client."""
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError(
                "openai package required for OpenAI. "
                "Install: pip install openai"
            )
        
        api_key = config.OPENAI_API_KEY
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY not found. Set it in .env file or environment variable."
            )
        
        model_name = config.OPENAI_MODEL
        base_url = config.OPENAI_BASE_URL
        
        logger.info(f"Initializing OpenAI client (model: {model_name})...")
        
        # Initialize client
        client_kwargs = {"api_key": api_key}
        if base_url:
            client_kwargs["base_url"] = base_url
            logger.info(f"Using custom OpenAI endpoint: {base_url}")
        
        self.client = OpenAI(**client_kwargs)
        self.model = model_name
        
        # Test connection
        try:
            response = self.client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=5
            )
            logger.info("✓ OpenAI API connection successful")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to OpenAI API: {e}")
    
    def _init_anthropic(self):
        """Initialize Anthropic Claude client."""
        try:
            from anthropic import Anthropic
        except ImportError:
            raise ImportError(
                "anthropic package required for Anthropic. "
                "Install: pip install anthropic"
            )
        
        api_key = config.ANTHROPIC_API_KEY
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY not found. Set it in .env file or environment variable."
            )
        
        model_name = config.ANTHROPIC_MODEL
        
        logger.info(f"Initializing Anthropic client (model: {model_name})...")
        
        self.client = Anthropic(api_key=api_key)
        self.model = model_name
        
        # Test connection
        try:
            response = self.client.messages.create(
                model=model_name,
                max_tokens=5,
                messages=[{"role": "user", "content": "test"}]
            )
            logger.info("✓ Anthropic API connection successful")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to Anthropic API: {e}")
    
    def generate_content(
        self, 
        prompt: str, 
        temperature: float = 0.0,
        max_tokens: Optional[int] = None
    ) -> str:
        """
        Generate content using the configured LLM provider.
        
        Args:
            prompt: Input prompt
            temperature: Sampling temperature (0.0 = deterministic)
            max_tokens: Maximum tokens to generate (provider-specific defaults used if None)
        
        Returns:
            Generated text response
        """
        if self.provider == "gemini":
            return self._generate_gemini(prompt, temperature)
        elif self.provider == "openai":
            return self._generate_openai(prompt, temperature, max_tokens)
        elif self.provider == "anthropic":
            return self._generate_anthropic(prompt, temperature, max_tokens)
    
    def _generate_gemini(self, prompt: str, temperature: float) -> str:
        """Generate content using Gemini."""
        generation_config = {
            "temperature": temperature,
            "top_p": 0.95,
            "top_k": 40,
            "max_output_tokens": 8192,
        }
        
        response = self.model.generate_content(
            prompt,
            generation_config=generation_config
        )
        
        # Handle safety blocks
        if not response.candidates:
            raise ValueError("Gemini API blocked the response (safety filters)")
        
        return response.text
    
    def _generate_openai(
        self, 
        prompt: str, 
        temperature: float,
        max_tokens: Optional[int]
    ) -> str:
        """Generate content using OpenAI."""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
            max_tokens=max_tokens or 4096
        )
        
        return response.choices[0].message.content
    
    def _generate_anthropic(
        self, 
        prompt: str, 
        temperature: float,
        max_tokens: Optional[int]
    ) -> str:
        """Generate content using Anthropic Claude."""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens or 4096,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return response.content[0].text
    
    def get_provider_info(self) -> Dict[str, Any]:
        """Get information about the current provider and model."""
        return {
            "provider": self.provider,
            "model": self.model,
            "api_key_set": bool(
                config.GEMINI_API_KEY if self.provider == "gemini"
                else config.OPENAI_API_KEY if self.provider == "openai"
                else config.ANTHROPIC_API_KEY
            )
        }


def initialize_llm_client(provider: Optional[str] = None) -> LLMClient:
    """
    Initialize and return LLM client.
    
    Args:
        provider: LLM provider ("gemini", "openai", "anthropic").
                 If None, uses config.LLM_PROVIDER.
    
    Returns:
        Initialized LLMClient instance
    """
    return LLMClient(provider=provider)
