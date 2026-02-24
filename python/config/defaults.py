"""Default configuration values."""

# Execution defaults
DEFAULT_MAX_CONCURRENT_AGENTS = 5
DEFAULT_MAX_PAYLOADS_PER_AGENT = 100
DEFAULT_TIMEOUT_PER_AGENT = 300.0  # 5 minutes

# HTTP client defaults
DEFAULT_HTTP_TIMEOUT = 30.0
DEFAULT_HTTP_RETRIES = 2
DEFAULT_USER_AGENT = "AI-Security-Agent/1.0"

# Claude API defaults
DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-20250514"
DEFAULT_CLAUDE_MAX_TOKENS = 2048
DEFAULT_CLAUDE_TEMPERATURE = 0.3

# Audit logging
DEFAULT_LOG_DIR = "./logs"
DEFAULT_MAX_PAYLOAD_LOG_LENGTH = 500

# Report defaults
DEFAULT_REPORT_DIR = "./reports"
DEFAULT_REPORT_FORMATS = ["json", "html", "markdown", "sqlite"]

# ZAP integration
DEFAULT_ZAP_URL = "http://localhost:8080"

# Agent priorities (higher = runs first)
AGENT_PRIORITY_CRITICAL = 10
AGENT_PRIORITY_HIGH = 8
AGENT_PRIORITY_MEDIUM = 5
AGENT_PRIORITY_LOW = 3

# Vulnerability type to priority mapping
VULNERABILITY_PRIORITIES = {
    "cmdi": AGENT_PRIORITY_CRITICAL,
    "log4shell": AGENT_PRIORITY_CRITICAL,
    "sqli": AGENT_PRIORITY_CRITICAL - 1,
    "ssti": AGENT_PRIORITY_CRITICAL - 1,
    "xxe": AGENT_PRIORITY_HIGH,
    "lfi": AGENT_PRIORITY_HIGH,
    "ssrf": AGENT_PRIORITY_HIGH,
    "path_traversal": AGENT_PRIORITY_HIGH - 1,
    "xss": AGENT_PRIORITY_HIGH - 1,
    "csrf": AGENT_PRIORITY_MEDIUM,
}

# CWE IDs for each vulnerability type
VULNERABILITY_CWEIDS = {
    "sqli": 89,
    "xss": 79,
    "cmdi": 78,
    "lfi": 98,
    "ssrf": 918,
    "xxe": 611,
    "log4shell": 917,
    "csrf": 352,
    "ssti": 1336,
    "path_traversal": 22,
}

# Default enabled agents
DEFAULT_ENABLED_AGENTS = [
    "sqli",
    "xss",
    "cmdi",
    "lfi",
    "ssrf",
    "xxe",
    "log4shell",
    "csrf",
    "ssti",
    "path_traversal",
]
