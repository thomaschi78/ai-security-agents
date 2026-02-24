"""Configuration management."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

import yaml

from .defaults import (
    DEFAULT_MAX_CONCURRENT_AGENTS,
    DEFAULT_MAX_PAYLOADS_PER_AGENT,
    DEFAULT_TIMEOUT_PER_AGENT,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_CLAUDE_MODEL,
    DEFAULT_LOG_DIR,
    DEFAULT_REPORT_DIR,
    DEFAULT_ZAP_URL,
    DEFAULT_ENABLED_AGENTS,
)


@dataclass
class HTTPConfig:
    """HTTP client configuration."""
    timeout: float = DEFAULT_HTTP_TIMEOUT
    max_retries: int = 2
    verify_ssl: bool = False
    follow_redirects: bool = False
    user_agent: str = "AI-Security-Agent/1.0"


@dataclass
class ClaudeConfig:
    """Claude API configuration."""
    api_key: Optional[str] = None
    model: str = DEFAULT_CLAUDE_MODEL
    max_tokens: int = 2048
    temperature: float = 0.3
    timeout: float = 60.0
    max_retries: int = 3
    use_mock: bool = False


@dataclass
class ZAPConfig:
    """ZAP integration configuration."""
    enabled: bool = False
    url: str = DEFAULT_ZAP_URL
    api_key: Optional[str] = None
    report_findings: bool = True


@dataclass
class AuditConfig:
    """Audit logging configuration."""
    enabled: bool = True
    log_dir: str = DEFAULT_LOG_DIR
    console_output: bool = True
    max_payload_length: int = 500


@dataclass
class ReportConfig:
    """Report generation configuration."""
    output_dir: str = DEFAULT_REPORT_DIR
    formats: List[str] = field(default_factory=lambda: ["json", "html", "markdown"])
    include_evidence: bool = True
    template_dir: Optional[str] = None


@dataclass
class ScanConfig:
    """Main scan configuration."""
    # Execution
    mode: str = "adaptive"  # parallel, sequential, adaptive
    max_concurrent_agents: int = DEFAULT_MAX_CONCURRENT_AGENTS
    max_payloads_per_agent: int = DEFAULT_MAX_PAYLOADS_PER_AGENT
    timeout_per_agent: float = DEFAULT_TIMEOUT_PER_AGENT
    enable_chaining: bool = True

    # Agents
    enabled_agents: List[str] = field(default_factory=lambda: DEFAULT_ENABLED_AGENTS.copy())
    disabled_agents: List[str] = field(default_factory=list)

    # Sub-configs
    http: HTTPConfig = field(default_factory=HTTPConfig)
    claude: ClaudeConfig = field(default_factory=ClaudeConfig)
    zap: ZAPConfig = field(default_factory=ZAPConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    report: ReportConfig = field(default_factory=ReportConfig)


class Settings:
    """
    Application settings manager.

    Handles configuration from:
    - Environment variables
    - YAML config files
    - Programmatic overrides
    """

    def __init__(self):
        self._config: Optional[ScanConfig] = None

    @property
    def config(self) -> ScanConfig:
        """Get current configuration."""
        if self._config is None:
            self._config = self._load_defaults()
        return self._config

    def _load_defaults(self) -> ScanConfig:
        """Load default configuration."""
        config = ScanConfig()

        # Override from environment
        self._apply_env_overrides(config)

        return config

    def _apply_env_overrides(self, config: ScanConfig) -> None:
        """Apply environment variable overrides."""
        # Claude API key
        if os.environ.get("ANTHROPIC_API_KEY"):
            config.claude.api_key = os.environ["ANTHROPIC_API_KEY"]

        # ZAP settings
        if os.environ.get("ZAP_API_KEY"):
            config.zap.api_key = os.environ["ZAP_API_KEY"]
            config.zap.enabled = True

        if os.environ.get("ZAP_URL"):
            config.zap.url = os.environ["ZAP_URL"]

        # Concurrency
        if os.environ.get("AI_AGENT_MAX_CONCURRENT"):
            config.max_concurrent_agents = int(os.environ["AI_AGENT_MAX_CONCURRENT"])

        # Mode
        if os.environ.get("AI_AGENT_MODE"):
            config.mode = os.environ["AI_AGENT_MODE"]

    def load_from_file(self, filepath: str) -> ScanConfig:
        """
        Load configuration from YAML file.

        Args:
            filepath: Path to YAML config file

        Returns:
            Loaded configuration
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {filepath}")

        with open(path) as f:
            data = yaml.safe_load(f)

        config = self._parse_config(data)
        self._apply_env_overrides(config)
        self._config = config

        return config

    def _parse_config(self, data: Dict[str, Any]) -> ScanConfig:
        """Parse config dictionary into ScanConfig."""
        config = ScanConfig()

        # Main settings
        if "mode" in data:
            config.mode = data["mode"]
        if "max_concurrent_agents" in data:
            config.max_concurrent_agents = data["max_concurrent_agents"]
        if "max_payloads_per_agent" in data:
            config.max_payloads_per_agent = data["max_payloads_per_agent"]
        if "enable_chaining" in data:
            config.enable_chaining = data["enable_chaining"]

        # Agents
        if "enabled_agents" in data:
            config.enabled_agents = data["enabled_agents"]
        if "disabled_agents" in data:
            config.disabled_agents = data["disabled_agents"]

        # HTTP config
        if "http" in data:
            http_data = data["http"]
            config.http = HTTPConfig(
                timeout=http_data.get("timeout", DEFAULT_HTTP_TIMEOUT),
                max_retries=http_data.get("max_retries", 2),
                verify_ssl=http_data.get("verify_ssl", False),
            )

        # Claude config
        if "claude" in data:
            claude_data = data["claude"]
            config.claude = ClaudeConfig(
                api_key=claude_data.get("api_key"),
                model=claude_data.get("model", DEFAULT_CLAUDE_MODEL),
                use_mock=claude_data.get("use_mock", False),
            )

        # ZAP config
        if "zap" in data:
            zap_data = data["zap"]
            config.zap = ZAPConfig(
                enabled=zap_data.get("enabled", False),
                url=zap_data.get("url", DEFAULT_ZAP_URL),
                api_key=zap_data.get("api_key"),
            )

        # Audit config
        if "audit" in data:
            audit_data = data["audit"]
            config.audit = AuditConfig(
                enabled=audit_data.get("enabled", True),
                log_dir=audit_data.get("log_dir", DEFAULT_LOG_DIR),
                console_output=audit_data.get("console_output", True),
            )

        # Report config
        if "report" in data:
            report_data = data["report"]
            config.report = ReportConfig(
                output_dir=report_data.get("output_dir", DEFAULT_REPORT_DIR),
                formats=report_data.get("formats", ["json", "html", "markdown"]),
            )

        return config

    def save_to_file(self, filepath: str) -> None:
        """Save current configuration to YAML file."""
        data = self._config_to_dict(self.config)

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False)

    def _config_to_dict(self, config: ScanConfig) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "mode": config.mode,
            "max_concurrent_agents": config.max_concurrent_agents,
            "max_payloads_per_agent": config.max_payloads_per_agent,
            "enable_chaining": config.enable_chaining,
            "enabled_agents": config.enabled_agents,
            "http": {
                "timeout": config.http.timeout,
                "max_retries": config.http.max_retries,
                "verify_ssl": config.http.verify_ssl,
            },
            "claude": {
                "model": config.claude.model,
                "use_mock": config.claude.use_mock,
            },
            "zap": {
                "enabled": config.zap.enabled,
                "url": config.zap.url,
            },
            "audit": {
                "enabled": config.audit.enabled,
                "log_dir": config.audit.log_dir,
                "console_output": config.audit.console_output,
            },
            "report": {
                "output_dir": config.report.output_dir,
                "formats": config.report.formats,
            },
        }


# Global settings instance
settings = Settings()
