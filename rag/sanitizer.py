"""Input sanitization for RAG chatbot to prevent prompt injection."""

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Limits
MAX_QUERY_LENGTH = 2000
MAX_HISTORY_MESSAGE_LENGTH = 4000
MAX_HISTORY_MESSAGES = 20

# Allowed Claude models
ALLOWED_MODELS = {
    "claude-sonnet-4-20250514",
    "claude-3-5-sonnet-20241022",
    "claude-3-5-haiku-20241022",
    "claude-3-opus-20240229",
    "claude-3-sonnet-20240229",
    "claude-3-haiku-20240307",
}

# Prompt injection patterns (case-insensitive)
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?)",
    r"disregard\s+(all\s+)?(previous|above|prior)",
    r"forget\s+(everything|all|your)\s+(instructions?|rules?|training)?",
    r"new\s+(instructions?|rules?|prompt)\s*:",
    r"system\s*prompt\s*:",
    r"you\s+are\s+now\s+(a|an|the)",
    r"override\s+(your\s+)?(instructions?|rules?|safety)",
    r"</?(system|instruction|prompt|rule)>",  # XML injection
    r"\[/?INST\]",  # Llama-style injection
    r"<\|im_start\|>",  # ChatML injection
]


class SanitizationError(Exception):
    """Raised when input fails sanitization."""
    pass


def detect_prompt_injection(text: str) -> tuple[bool, Optional[str]]:
    """
    Check if text contains prompt injection patterns.

    Returns:
        (is_malicious, matched_pattern)
    """
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True, pattern
    return False, None


def sanitize_context_chunk(content: str, source: str = "unknown") -> tuple[str, bool]:
    """
    Sanitize a RAG context chunk before injecting into prompt.

    Checks for prompt injection patterns and redacts them if found.
    This protects against indirect prompt injection via malicious documents.

    Args:
        content: The document chunk content
        source: Source file name for logging

    Returns:
        (sanitized_content, was_modified)
    """
    is_malicious, pattern = detect_prompt_injection(content)

    if not is_malicious:
        return content, False

    logger.warning(
        f"Prompt injection detected in document chunk: "
        f"source='{source}', pattern='{pattern}'"
    )

    # Redact the malicious content by replacing injection patterns
    sanitized = content
    for inj_pattern in INJECTION_PATTERNS:
        sanitized = re.sub(
            inj_pattern,
            "[CONTENT REDACTED - POLICY VIOLATION]",
            sanitized,
            flags=re.IGNORECASE
        )

    return sanitized, True


def validate_query(query: str) -> str:
    """
    Validate and sanitize user query.

    Raises:
        SanitizationError: If query fails validation

    Returns:
        Sanitized query string
    """
    if not query or not isinstance(query, str):
        raise SanitizationError("Query must be a non-empty string")

    query = query.strip()

    if len(query) > MAX_QUERY_LENGTH:
        raise SanitizationError(f"Query exceeds maximum length of {MAX_QUERY_LENGTH} characters")

    is_malicious, pattern = detect_prompt_injection(query)
    if is_malicious:
        logger.warning(f"Prompt injection detected: pattern='{pattern}', query='{query[:100]}...'")
        raise SanitizationError("Query contains disallowed content")

    return query


def validate_model(model: str) -> str:
    """
    Validate model name against whitelist.

    Returns:
        Valid model name or default if invalid
    """
    if model in ALLOWED_MODELS:
        return model
    logger.warning(f"Invalid model requested: {model}, using default")
    return "claude-sonnet-4-20250514"


def validate_conversation_history(history: list) -> list:
    """
    Validate and sanitize conversation history.

    Returns:
        Sanitized history list (may be truncated/filtered)
    """
    if not history or not isinstance(history, list):
        return []

    validated = []
    for msg in history[-MAX_HISTORY_MESSAGES:]:
        if not isinstance(msg, dict):
            continue

        role = msg.get("role")
        content = msg.get("content")

        if role not in ("user", "assistant"):
            continue

        if not content or not isinstance(content, str):
            continue

        # Truncate long messages
        if len(content) > MAX_HISTORY_MESSAGE_LENGTH:
            content = content[:MAX_HISTORY_MESSAGE_LENGTH] + "..."

        # Check for injection in history - sanitize malicious content
        sanitized_content, was_modified = sanitize_context_chunk(content, source="conversation_history")
        if was_modified:
            logger.warning(f"Sanitized suspicious content in conversation history")
            content = sanitized_content

        validated.append({"role": role, "content": content})

    return validated
