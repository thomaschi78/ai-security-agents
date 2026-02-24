"""Prompt templates for Claude reasoning."""

from typing import Dict, Any, List
from string import Template


# Base analysis prompt template
VULNERABILITY_ANALYSIS_PROMPT = Template("""You are an expert security researcher analyzing HTTP responses for $vulnerability_type vulnerabilities (CWE-$cweid).

## Context
- Target URL: $url
- Parameter: $parameter
- HTTP Method: $method
- Current Stage: $current_stage
- Payloads Tested: $payloads_tested

## Payload Sent
```
$payload
```

## Response Analysis
- Status Code: $status_code
- Content-Type: $content_type
- Response Time: $response_time_ms ms

### Response Body (truncated to 2000 chars)
```
$response_body
```

### Error Indicators Found
$error_indicators

### Pattern Matches
$pattern_matches

## Your Task
Analyze this response and determine:
1. Is there evidence of a $vulnerability_type vulnerability?
2. What is your confidence level (0.0 to 1.0)?
3. What should be the next action?

## Response Format
Respond in JSON format:
```json
{
    "decision": "CONTINUE|ESCALATE|REPORT|STOP|CHAIN",
    "confidence": 0.0-1.0,
    "reasoning": ["step 1", "step 2", ...],
    "indicators": ["indicator 1", "indicator 2", ...],
    "suggested_payloads": ["payload1", "payload2", ...],
    "chain_opportunities": ["vuln_type1", "vuln_type2", ...]
}
```

Decision meanings:
- CONTINUE: Keep testing with current stage payloads
- ESCALATE: Move to next stage (PROBE→CONFIRM→EXPLOIT→BYPASS)
- REPORT: Vulnerability confirmed, create finding
- STOP: No vulnerability likely, stop testing
- CHAIN: Trigger related vulnerability agents
""")


# Vulnerability-specific context additions
SQLI_CONTEXT = """
## SQL Injection Specific Analysis
Look for:
- SQL error messages (syntax errors, type conversion)
- Database-specific errors (MySQL, PostgreSQL, MSSQL, Oracle)
- Boolean-based differences in response
- Time delays for blind injection
- UNION-based data leakage
- Stacked queries indicators
"""

XSS_CONTEXT = """
## XSS Specific Analysis
Look for:
- Payload reflection in response (exact or modified)
- HTML context (inside tags, attributes, scripts)
- JavaScript execution indicators
- DOM manipulation possibilities
- Encoding/filtering applied to payload
- CSP headers that might prevent exploitation
"""

CMDI_CONTEXT = """
## Command Injection Specific Analysis
Look for:
- Shell command output in response
- System file contents (passwd, hosts)
- Command execution timing differences
- Error messages indicating command processing
- Environment variable disclosure
"""

LFI_CONTEXT = """
## Local File Inclusion Specific Analysis
Look for:
- File contents in response (etc/passwd, win.ini)
- Path traversal sequences working
- PHP wrapper success indicators
- Log file inclusion possibilities
- Configuration file disclosure
"""

SSRF_CONTEXT = """
## SSRF Specific Analysis
Look for:
- Response content from internal services
- DNS resolution differences
- Timing differences for internal vs external
- Cloud metadata exposure (169.254.169.254)
- Internal network error messages
"""

XXE_CONTEXT = """
## XXE Specific Analysis
Look for:
- XML parsing errors
- External entity resolution
- File content disclosure via entities
- SSRF via external DTD
- Out-of-band data exfiltration indicators
"""

LOG4SHELL_CONTEXT = """
## Log4Shell Specific Analysis
Look for:
- JNDI lookup processing indicators
- Response differences with JNDI payloads
- Error messages mentioning JNDI/LDAP
- DNS callbacks (use collaborator/webhook)
- Java deserialization errors
"""

CSRF_CONTEXT = """
## CSRF Specific Analysis
Look for:
- Missing CSRF tokens
- Predictable token patterns
- Token validation bypass
- Same-site cookie configuration
- Referer header requirements
"""

SSTI_CONTEXT = """
## SSTI Specific Analysis
Look for:
- Template expression evaluation (7*7=49)
- Template engine error messages
- Code execution indicators
- Template-specific syntax errors
- Object method invocation results
"""

PATH_TRAVERSAL_CONTEXT = """
## Path Traversal Specific Analysis
Look for:
- File contents in response
- Directory listing indicators
- Path normalization bypass
- Null byte injection effects
- Double encoding effectiveness
"""

VULN_CONTEXTS = {
    "sqli": SQLI_CONTEXT,
    "xss": XSS_CONTEXT,
    "cmdi": CMDI_CONTEXT,
    "lfi": LFI_CONTEXT,
    "ssrf": SSRF_CONTEXT,
    "xxe": XXE_CONTEXT,
    "log4shell": LOG4SHELL_CONTEXT,
    "csrf": CSRF_CONTEXT,
    "ssti": SSTI_CONTEXT,
    "path_traversal": PATH_TRAVERSAL_CONTEXT,
}


def build_analysis_prompt(
    vulnerability_type: str,
    cweid: int,
    payload: str,
    response_body: str,
    status_code: int,
    error_indicators: List[str],
    pattern_matches: List[Dict[str, Any]],
    current_stage: str,
    context: Dict[str, Any]
) -> str:
    """
    Build a complete analysis prompt for Claude.

    Args:
        vulnerability_type: Type of vulnerability being tested
        cweid: CWE ID
        payload: The payload that was sent
        response_body: HTTP response body
        status_code: HTTP status code
        error_indicators: List of error indicators found
        pattern_matches: List of pattern matches
        current_stage: Current testing stage
        context: Additional context (url, parameter, etc.)

    Returns:
        Complete prompt string
    """
    # Format error indicators
    error_str = "\n".join(f"- {e}" for e in error_indicators) if error_indicators else "None found"

    # Format pattern matches
    if pattern_matches:
        pattern_str = "\n".join(
            f"- Pattern: `{m.get('pattern', '')}` matched: `{m.get('match', '')}`"
            for m in pattern_matches
        )
    else:
        pattern_str = "None found"

    # Truncate response body
    response_truncated = response_body[:2000] if len(response_body) > 2000 else response_body

    # Build base prompt
    prompt = VULNERABILITY_ANALYSIS_PROMPT.substitute(
        vulnerability_type=vulnerability_type,
        cweid=cweid,
        url=context.get("url", "unknown"),
        parameter=context.get("parameter", "unknown"),
        method=context.get("method", "GET"),
        current_stage=current_stage,
        payloads_tested=context.get("payloads_tested", 0),
        payload=payload,
        status_code=status_code,
        content_type=context.get("content_type", "unknown"),
        response_time_ms=context.get("response_time_ms", 0),
        response_body=response_truncated,
        error_indicators=error_str,
        pattern_matches=pattern_str,
    )

    # Add vulnerability-specific context
    vuln_context = VULN_CONTEXTS.get(vulnerability_type, "")
    if vuln_context:
        prompt = prompt + "\n" + vuln_context

    return prompt


# Chaining analysis prompt
CHAINING_PROMPT = Template("""You are an expert security researcher analyzing potential vulnerability chaining opportunities.

## Confirmed Vulnerability
- Type: $source_vuln
- CWE: $source_cweid
- URL: $url
- Parameter: $parameter
- Confidence: $confidence

## Evidence
$evidence

## Question
Based on this confirmed vulnerability, which other vulnerability types should be tested?

Consider:
1. Can this vulnerability expose data useful for other attacks?
2. Can this vulnerability enable access to other attack surfaces?
3. Common vulnerability chains:
   - SQLi → SSRF (extract internal URLs from database)
   - LFI → SQLi (read database credentials)
   - XXE → SSRF (make requests via XML parser)
   - SSRF → Cloud metadata (access instance credentials)
   - XSS → CSRF (chain with session attacks)

## Response Format
Respond in JSON:
```json
{
    "chain_recommendations": [
        {
            "target_vuln": "vuln_type",
            "rationale": "why this chain makes sense",
            "priority": 1-10,
            "technique": "how to exploit the chain"
        }
    ]
}
```
""")


def build_chaining_prompt(
    source_vuln: str,
    source_cweid: int,
    url: str,
    parameter: str,
    confidence: float,
    evidence: str
) -> str:
    """Build a chaining analysis prompt."""
    return CHAINING_PROMPT.substitute(
        source_vuln=source_vuln,
        source_cweid=source_cweid,
        url=url,
        parameter=parameter,
        confidence=confidence,
        evidence=evidence,
    )
