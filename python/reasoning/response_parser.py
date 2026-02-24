"""Parser for Claude response analysis."""

import json
import re
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)


class ResponseParseError(Exception):
    """Error parsing Claude response."""
    pass


def extract_json_from_response(response: str) -> Dict[str, Any]:
    """
    Extract JSON from Claude's response, handling markdown code blocks.

    Args:
        response: Raw response text from Claude

    Returns:
        Parsed JSON as dictionary

    Raises:
        ResponseParseError: If JSON cannot be extracted or parsed
    """
    # Try to find JSON in code blocks first
    json_block_pattern = r'```(?:json)?\s*\n?([\s\S]*?)\n?```'
    matches = re.findall(json_block_pattern, response)

    for match in matches:
        try:
            return json.loads(match.strip())
        except json.JSONDecodeError:
            continue

    # Try to find JSON without code blocks (looking for { ... })
    json_pattern = r'\{[\s\S]*\}'
    matches = re.findall(json_pattern, response)

    for match in matches:
        try:
            return json.loads(match)
        except json.JSONDecodeError:
            continue

    # Last resort: try parsing entire response
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        raise ResponseParseError(f"Could not extract JSON from response: {response[:200]}")


def parse_analysis_response(response: str) -> Dict[str, Any]:
    """
    Parse vulnerability analysis response from Claude.

    Args:
        response: Raw response text

    Returns:
        Structured analysis result
    """
    try:
        data = extract_json_from_response(response)
    except ResponseParseError:
        logger.warning("Failed to parse JSON, using fallback")
        return _fallback_parse_analysis(response)

    # Validate and normalize required fields
    result = {
        "decision": _normalize_decision(data.get("decision", "CONTINUE")),
        "confidence": _normalize_confidence(data.get("confidence", 0.0)),
        "reasoning": _ensure_list(data.get("reasoning", [])),
        "indicators": _ensure_list(data.get("indicators", [])),
        "suggested_payloads": _ensure_list(data.get("suggested_payloads", [])),
        "chain_opportunities": _ensure_list(data.get("chain_opportunities", [])),
    }

    return result


def parse_chaining_response(response: str) -> List[Dict[str, Any]]:
    """
    Parse chaining analysis response from Claude.

    Args:
        response: Raw response text

    Returns:
        List of chain recommendations
    """
    try:
        data = extract_json_from_response(response)
    except ResponseParseError:
        logger.warning("Failed to parse chaining JSON")
        return []

    recommendations = data.get("chain_recommendations", [])

    # Normalize recommendations
    normalized = []
    for rec in recommendations:
        normalized.append({
            "target_vuln": str(rec.get("target_vuln", "")),
            "rationale": str(rec.get("rationale", "")),
            "priority": min(max(int(rec.get("priority", 5)), 1), 10),
            "technique": str(rec.get("technique", "")),
        })

    return sorted(normalized, key=lambda x: x["priority"], reverse=True)


def _normalize_decision(decision: Any) -> str:
    """Normalize decision to valid value."""
    valid_decisions = {"CONTINUE", "ESCALATE", "REPORT", "STOP", "CHAIN"}
    decision_str = str(decision).upper().strip()

    if decision_str in valid_decisions:
        return decision_str

    # Try to match partial
    for valid in valid_decisions:
        if decision_str.startswith(valid) or valid.startswith(decision_str):
            return valid

    return "CONTINUE"


def _normalize_confidence(confidence: Any) -> float:
    """Normalize confidence to 0-1 range."""
    try:
        conf = float(confidence)
        return max(0.0, min(1.0, conf))
    except (ValueError, TypeError):
        return 0.0


def _ensure_list(value: Any) -> List:
    """Ensure value is a list."""
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _fallback_parse_analysis(response: str) -> Dict[str, Any]:
    """
    Fallback parsing when JSON extraction fails.
    Attempts to extract key information from free-form text.
    """
    result = {
        "decision": "CONTINUE",
        "confidence": 0.0,
        "reasoning": [],
        "indicators": [],
        "suggested_payloads": [],
        "chain_opportunities": [],
    }

    response_lower = response.lower()

    # Try to detect decision
    if any(word in response_lower for word in ["vulnerable", "confirmed", "found vulnerability"]):
        result["decision"] = "REPORT"
        result["confidence"] = 0.7
    elif any(word in response_lower for word in ["escalate", "try more", "investigate further"]):
        result["decision"] = "ESCALATE"
        result["confidence"] = 0.4
    elif any(word in response_lower for word in ["not vulnerable", "no evidence", "stop"]):
        result["decision"] = "STOP"
        result["confidence"] = 0.1

    # Extract reasoning sentences
    sentences = re.split(r'[.!?]\s+', response)
    result["reasoning"] = [s.strip() for s in sentences[:5] if s.strip()]

    return result


def validate_response_structure(data: Dict[str, Any], required_fields: List[str]) -> bool:
    """
    Validate that response has required structure.

    Args:
        data: Parsed response data
        required_fields: List of required field names

    Returns:
        True if all required fields present
    """
    for field in required_fields:
        if field not in data:
            return False
    return True
