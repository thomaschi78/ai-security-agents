# AI Security Testing Multi-Agent Framework

A multi-agent AI security testing framework with Claude-powered vulnerability analysis and optional OWASP ZAP integration.

## Overview

This framework uses specialized AI agents to detect web application vulnerabilities through intelligent, staged payload testing. Each agent focuses on a specific vulnerability class and uses Claude for reasoning about responses and attack strategies.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ORCHESTRATOR                             │
│  Modes: PARALLEL | SEQUENTIAL | ADAPTIVE                        │
│  Handles: Agent coordination, priority, vulnerability chaining  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────┼──────────────────────────────────────┐
│                     MESSAGE BUS (Pub/Sub)                       │
│  Topics: vulnerability_found, chain_opportunity, scan_progress  │
└───┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬───────┘
    │     │     │     │     │     │     │     │     │     │
  SQLi  XSS  CMDi  LFI  SSRF  XXE  Log4  CSRF SSTI  Path
  Agent Agent Agent Agent Agent Agent Shell Agent Agent Trav
    │     │     │     │     │     │     │     │     │     │
    └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘
                           │
┌──────────────────────────┴──────────────────────────────────────┐
│                    RESULT AGGREGATOR                            │
│  Deduplication, severity ranking, chain tracking                │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────────────┐
│                    REPORT GENERATOR                             │
│  Outputs: JSON, HTML, SQLite, Markdown                          │
└─────────────────────────────────────────────────────────────────┘
```

## Features

### Vulnerability Agents

| Agent | CWE | Description |
|-------|-----|-------------|
| SQLi | 89 | SQL Injection detection with error-based, blind, and time-based techniques |
| XSS | 79 | Cross-Site Scripting including reflected, stored, and DOM-based |
| CMDi | 78 | Command Injection with Unix/Windows payload variants |
| LFI | 98 | Local File Inclusion with path traversal sequences |
| SSRF | 918 | Server-Side Request Forgery targeting cloud metadata endpoints |
| XXE | 611 | XML External Entity injection |
| Log4Shell | 917 | Log4j JNDI injection (CVE-2021-44228) |
| CSRF | 352 | Cross-Site Request Forgery token analysis |
| SSTI | 1336 | Server-Side Template Injection for multiple engines |
| Path Traversal | 22 | Directory traversal attacks |

### Key Capabilities

- **Staged Payload Testing**: PROBE → CONFIRM → EXPLOIT → BYPASS progression
- **Claude-Powered Reasoning**: AI analysis of responses for intelligent decision making
- **Vulnerability Chaining**: Automatic detection of attack chains (e.g., SQLi → SSRF)
- **Multiple Execution Modes**: Parallel, sequential, or adaptive scheduling
- **Comprehensive Audit Logging**: JSONL format with full decision tracking
- **Multi-Format Reports**: JSON, HTML, Markdown, and SQLite outputs

## Installation

```bash
# Clone the repository
git clone https://github.com/thomaschi78/ai-security-agents.git
cd ai-security-agents

# Install dependencies
pip install -r requirements.txt

# Set up configuration
cp config.example.yaml config.yaml
# Edit config.yaml with your Anthropic API key
```

## Usage

### Basic Scan

```python
import asyncio
from python.orchestrator import Orchestrator, ExecutionMode
from python.results import ScanTarget
from python.config import ScanConfig

async def main():
    # Configure scan
    config = ScanConfig(
        mode=ExecutionMode.ADAPTIVE,
        max_concurrent_agents=5,
        enable_chaining=True,
        anthropic_api_key="your-api-key"
    )

    # Define target
    target = ScanTarget(
        url="https://example.com/search",
        parameters=[{"name": "q", "value": "test"}],
        method="GET"
    )

    # Run scan
    orchestrator = Orchestrator(config)
    results = await orchestrator.scan(target)

    # Generate reports
    from python.reports import ReportGenerator
    generator = ReportGenerator(results)
    generator.generate_all("./reports")

asyncio.run(main())
```

### Command Line

```bash
python -m python.main \
    --target "https://example.com/search?q=test" \
    --agents sqli,xss,cmdi \
    --mode adaptive \
    --output ./reports
```

## Project Structure

```
ai-security-agents/
├── python/
│   ├── agents/
│   │   ├── base/           # Base agent classes and mixins
│   │   └── payload/        # Vulnerability-specific agents
│   ├── orchestrator/       # Coordination and scheduling
│   ├── communication/      # Inter-agent message bus
│   ├── reasoning/          # Claude API integration
│   ├── audit/              # Logging and decision tracking
│   ├── reports/            # Multi-format report generation
│   ├── results/            # Finding aggregation
│   ├── bridge/             # HTTP and ZAP clients
│   ├── payloads/           # Payload loading and encoding
│   └── config/             # Configuration management
├── java/
│   └── zap-ai-bridge/      # Optional ZAP extension
├── tests/                  # Test suite
└── reports/
    └── templates/          # Report templates
```

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_agents.py -v

# Run with coverage
python -m pytest tests/ --cov=python --cov-report=html
```

## Configuration

See `config.example.yaml` for all available options:

```yaml
anthropic:
  api_key: "your-api-key"
  model: "claude-sonnet-4-20250514"

scan:
  mode: adaptive
  max_concurrent: 5
  timeout_per_agent: 300
  enable_chaining: true

agents:
  enabled:
    - sqli
    - xss
    - cmdi
    - ssrf

logging:
  level: INFO
  audit_file: "./logs/audit.jsonl"
```

## Vulnerability Chaining

The framework automatically detects opportunities to chain vulnerabilities:

| Source | Target | Description |
|--------|--------|-------------|
| SQLi | SSRF | Extract internal URLs from database |
| LFI | SQLi | Read database credentials from config files |
| XXE | SSRF/LFI | Leverage XXE for server-side requests or file reads |
| SSTI | CMDi | Template injection often leads to command execution |
| XSS | CSRF | Use XSS to bypass CSRF protections |

## ZAP Integration (Optional)

The Java bridge extension allows integration with OWASP ZAP:

```bash
# Build the extension
cd java/zap-ai-bridge
mvn package

# Install in ZAP
cp target/aibridge-*.zap ~/Library/Application\ Support/ZAP/plugin/
```

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before testing any systems you do not own.
