"""
Ollama AI Model Client

Wrapper for local Ollama instance running drana-infinity-v1 model.
Optimized for cybersecurity analysis and threat detection.
"""

import requests
import json
from typing import Dict, Any, List, Optional, AsyncIterator, Iterator
import logging
from dataclasses import dataclass
import asyncio
import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class OllamaMessage:
    """Represents a message in Ollama chat format."""
    role: str  # 'system', 'user', or 'assistant'
    content: str


class OllamaClient:
    """
    Client for interacting with local Ollama AI instance.

    Supports both streaming and non-streaming responses.
    Optimized for the custom drana-infinity-v1 security model.
    """

    def __init__(
        self,
        endpoint_url: str = "http://localhost:11434",
        model_name: str = "IHA089/drana-infinity-v1",
        timeout: int = 120
    ):
        """
        Initialize Ollama client.

        Args:
            endpoint_url: Base URL for Ollama API
            model_name: Name of the model to use
            timeout: Request timeout in seconds
        """
        self.endpoint_url = endpoint_url.rstrip('/')
        self.model_name = model_name
        self.timeout = timeout

        # Validate connection
        self._validate_connection()

    def _validate_connection(self) -> None:
        """Validate Ollama server is accessible."""
        try:
            response = requests.get(f"{self.endpoint_url}/api/tags", timeout=5)
            response.raise_for_status()
            logger.info(f"Successfully connected to Ollama at {self.endpoint_url}")
        except requests.RequestException as e:
            logger.error(f"Failed to connect to Ollama: {e}")
            raise ConnectionError(f"Ollama server not accessible at {self.endpoint_url}: {e}")

    def list_models(self) -> List[Dict[str, Any]]:
        """
        List all available models.

        Returns:
            List of model information dictionaries
        """
        try:
            response = requests.get(f"{self.endpoint_url}/api/tags", timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            return data.get("models", [])
        except requests.RequestException as e:
            logger.error(f"Failed to list Ollama models: {e}")
            return []

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = False
    ) -> str:
        """
        Generate response from Ollama (synchronous, non-streaming).

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt for context
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens to generate
            stream: If True, returns streaming response

        Returns:
            Generated text response
        """
        url = f"{self.endpoint_url}/api/generate"

        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "temperature": temperature,
            "num_predict": max_tokens,
            "stream": stream
        }

        if system_prompt:
            payload["system"] = system_prompt

        try:
            response = requests.post(
                url,
                json=payload,
                timeout=self.timeout,
                stream=stream
            )
            response.raise_for_status()

            if stream:
                return response  # Return response object for streaming
            else:
                data = response.json()
                return data.get("response", "")

        except requests.RequestException as e:
            logger.error(f"Ollama generation failed: {e}")
            raise RuntimeError(f"Failed to generate response: {e}")

    def chat(
        self,
        messages: List[OllamaMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096
    ) -> str:
        """
        Chat with Ollama using conversation history (non-streaming).

        Args:
            messages: List of conversation messages
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate

        Returns:
            Assistant's response
        """
        url = f"{self.endpoint_url}/api/chat"

        payload = {
            "model": self.model_name,
            "messages": [{"role": msg.role, "content": msg.content} for msg in messages],
            "temperature": temperature,
            "stream": False,
            "options": {
                "num_predict": max_tokens
            }
        }

        try:
            response = requests.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()

            return data.get("message", {}).get("content", "")

        except requests.RequestException as e:
            logger.error(f"Ollama chat failed: {e}")
            raise RuntimeError(f"Failed to chat: {e}")

    def chat_stream(
        self,
        messages: List[OllamaMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096
    ) -> Iterator[str]:
        """
        Chat with Ollama using streaming responses (synchronous iterator).

        Args:
            messages: List of conversation messages
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate

        Yields:
            Chunks of the assistant's response
        """
        url = f"{self.endpoint_url}/api/chat"

        payload = {
            "model": self.model_name,
            "messages": [{"role": msg.role, "content": msg.content} for msg in messages],
            "temperature": temperature,
            "stream": True,
            "options": {
                "num_predict": max_tokens
            }
        }

        try:
            response = requests.post(url, json=payload, timeout=self.timeout, stream=True)
            response.raise_for_status()

            for line in response.iter_lines():
                if line:
                    try:
                        data = json.loads(line)
                        if "message" in data:
                            content = data["message"].get("content", "")
                            if content:
                                yield content
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse streaming response: {line}")
                        continue

        except requests.RequestException as e:
            logger.error(f"Ollama streaming chat failed: {e}")
            raise RuntimeError(f"Failed to stream chat: {e}")

    async def chat_stream_async(
        self,
        messages: List[OllamaMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096
    ) -> AsyncIterator[str]:
        """
        Chat with Ollama using streaming responses (async).

        Args:
            messages: List of conversation messages
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate

        Yields:
            Chunks of the assistant's response
        """
        url = f"{self.endpoint_url}/api/chat"

        payload = {
            "model": self.model_name,
            "messages": [{"role": msg.role, "content": msg.content} for msg in messages],
            "temperature": temperature,
            "stream": True,
            "options": {
                "num_predict": max_tokens
            }
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    response.raise_for_status()

                    async for line in response.content:
                        if line:
                            try:
                                data = json.loads(line)
                                if "message" in data:
                                    content = data["message"].get("content", "")
                                    if content:
                                        yield content
                            except json.JSONDecodeError:
                                continue

        except Exception as e:
            logger.error(f"Ollama async streaming failed: {e}")
            raise RuntimeError(f"Failed to async stream chat: {e}")

    def analyze_threat(
        self,
        threat_data: str,
        context: Optional[str] = None,
        sector: str = "GENERAL"
    ) -> Dict[str, Any]:
        """
        Specialized method for threat analysis using Ollama.

        Args:
            threat_data: Raw threat information (logs, alerts, etc.)
            context: Additional context about the environment
            sector: Target sector (LOGISTICS, MEDICAL_AI, GENERAL)

        Returns:
            Structured threat analysis
        """
        system_prompt = f"""You are Drana-Infinity, an advanced AI cybersecurity analyst specializing in {sector} sector security.
Analyze the provided threat data and return a comprehensive assessment including:
1. Threat severity (CRITICAL, HIGH, MEDIUM, LOW)
2. Attack vector identification
3. Potential impact assessment
4. Recommended mitigation steps
5. Relevant CVEs or IOCs if applicable

Be precise, actionable, and prioritize business impact."""

        user_prompt = f"""Threat Data:
{threat_data}

{f'Context: {context}' if context else ''}

Provide detailed threat analysis."""

        messages = [
            OllamaMessage(role="system", content=system_prompt),
            OllamaMessage(role="user", content=user_prompt)
        ]

        response_text = self.chat(messages, temperature=0.5)  # Lower temp for factual analysis

        # Parse response (in production, would use structured output)
        return {
            "analysis": response_text,
            "model": self.model_name,
            "sector": sector,
            "raw_threat_data": threat_data
        }

    def check_health(self) -> bool:
        """
        Check if Ollama service is healthy.

        Returns:
            True if healthy, False otherwise
        """
        try:
            response = requests.get(f"{self.endpoint_url}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False

    def __repr__(self) -> str:
        """String representation."""
        return f"<OllamaClient model={self.model_name} endpoint={self.endpoint_url}>"
