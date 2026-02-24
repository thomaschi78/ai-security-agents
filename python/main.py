#!/usr/bin/env python3
"""
AI Security Agents Framework

Multi-agent security testing framework with Claude-powered analysis.
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

from orchestrator import Orchestrator, OrchestratorConfig, ExecutionMode
from results import ScanTarget
from reports import ReportGenerator
from config import settings, ScanConfig


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("ai-security-agents")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="AI Security Agents - Multi-agent vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python main.py --url "https://example.com/search?q=test"

  # Scan with specific agents
  python main.py --url "https://example.com/api" --agents sqli,xss,cmdi

  # Parallel mode with more concurrency
  python main.py --url "https://example.com" --mode parallel --concurrent 10

  # Output reports in multiple formats
  python main.py --url "https://example.com" --output ./reports --formats json,html,md

  # Use config file
  python main.py --config config.yaml
        """
    )

    # Target specification
    parser.add_argument(
        "--url", "-u",
        required=True,
        help="Target URL to scan"
    )
    parser.add_argument(
        "--parameter", "-p",
        action="append",
        default=[],
        help="Parameter to test (can specify multiple)"
    )
    parser.add_argument(
        "--method", "-m",
        default="GET",
        choices=["GET", "POST", "PUT", "DELETE"],
        help="HTTP method (default: GET)"
    )

    # Agent configuration
    parser.add_argument(
        "--agents", "-a",
        help="Comma-separated list of agents to run (default: all)"
    )
    parser.add_argument(
        "--exclude-agents",
        help="Comma-separated list of agents to exclude"
    )

    # Execution configuration
    parser.add_argument(
        "--mode",
        default="adaptive",
        choices=["parallel", "sequential", "adaptive"],
        help="Execution mode (default: adaptive)"
    )
    parser.add_argument(
        "--concurrent", "-c",
        type=int,
        default=5,
        help="Max concurrent agents (default: 5)"
    )
    parser.add_argument(
        "--max-payloads",
        type=int,
        default=100,
        help="Max payloads per agent (default: 100)"
    )
    parser.add_argument(
        "--no-chaining",
        action="store_true",
        help="Disable vulnerability chaining"
    )

    # Claude configuration
    parser.add_argument(
        "--api-key",
        help="Anthropic API key (or set ANTHROPIC_API_KEY env)"
    )
    parser.add_argument(
        "--mock-claude",
        action="store_true",
        help="Use mock Claude client (for testing)"
    )

    # Output configuration
    parser.add_argument(
        "--output", "-o",
        default="./reports",
        help="Output directory for reports (default: ./reports)"
    )
    parser.add_argument(
        "--formats", "-f",
        default="json,html,md",
        help="Report formats: json,html,md,sqlite (default: json,html,md)"
    )

    # Logging
    parser.add_argument(
        "--log-dir",
        help="Directory for audit logs"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress console output"
    )

    # Config file
    parser.add_argument(
        "--config",
        help="Path to YAML config file"
    )

    return parser.parse_args()


def build_config(args: argparse.Namespace) -> OrchestratorConfig:
    """Build orchestrator config from arguments."""
    # Start with defaults or load from file
    if args.config:
        config = settings.load_from_file(args.config)
    else:
        config = settings.config

    # Map mode string to enum
    mode_map = {
        "parallel": ExecutionMode.PARALLEL,
        "sequential": ExecutionMode.SEQUENTIAL,
        "adaptive": ExecutionMode.ADAPTIVE,
    }

    # Build orchestrator config
    orch_config = OrchestratorConfig(
        mode=mode_map.get(args.mode, ExecutionMode.ADAPTIVE),
        max_concurrent_agents=args.concurrent,
        max_payloads_per_agent=args.max_payloads,
        enable_chaining=not args.no_chaining,
        claude_api_key=args.api_key,
        use_mock_claude=args.mock_claude,
        log_dir=args.log_dir,
    )

    # Determine agent types
    if args.agents:
        orch_config.agent_types = [a.strip() for a in args.agents.split(",")]

    if args.exclude_agents:
        excluded = [a.strip() for a in args.exclude_agents.split(",")]
        orch_config.agent_types = [
            a for a in orch_config.agent_types if a not in excluded
        ]

    return orch_config


def build_target(args: argparse.Namespace) -> ScanTarget:
    """Build scan target from arguments."""
    # Parse parameters from URL if not specified
    parameters = []
    if args.parameter:
        for p in args.parameter:
            parameters.append({"name": p, "value": ""})
    else:
        # Try to extract from URL query string
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(args.url)
        query_params = parse_qs(parsed.query)
        for name, values in query_params.items():
            parameters.append({"name": name, "value": values[0] if values else ""})

    if not parameters:
        logger.warning("No parameters detected. Consider specifying with --parameter")

    return ScanTarget(
        url=args.url,
        parameters=parameters,
        method=args.method,
    )


async def run_scan(args: argparse.Namespace) -> int:
    """Run the security scan."""
    # Build configuration
    config = build_config(args)
    target = build_target(args)

    logger.info(f"Starting scan of {target.url}")
    logger.info(f"Parameters: {[p['name'] for p in target.parameters]}")
    logger.info(f"Agents: {config.agent_types}")
    logger.info(f"Mode: {config.mode.name}")

    # Create orchestrator and run scan
    orchestrator = Orchestrator(config)

    try:
        result = await orchestrator.scan(target)

        # Log summary
        summary = result.get_summary()
        logger.info("=" * 50)
        logger.info("SCAN COMPLETE")
        logger.info(f"Duration: {summary['duration']}")
        logger.info(f"Findings: {summary['total_findings']}")
        logger.info(f"  Critical: {summary['critical']}")
        logger.info(f"  High: {summary['high']}")
        logger.info(f"  Medium: {summary['medium']}")
        logger.info(f"  Low: {summary['low']}")
        logger.info("=" * 50)

        # Generate reports
        report_gen = ReportGenerator(output_dir=args.output)
        formats = [f.strip() for f in args.formats.split(",")]
        paths = report_gen.generate(result, formats=formats)

        for fmt, path in paths.items():
            logger.info(f"Report generated: {path}")

        # Return exit code based on findings
        if result.critical_count > 0 or result.high_count > 0:
            return 2  # Critical/high findings
        elif result.vulnerability_count > 0:
            return 1  # Some findings
        return 0  # No findings

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        orchestrator.stop()
        return 130

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 3


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    # Run scan
    return asyncio.run(run_scan(args))


if __name__ == "__main__":
    sys.exit(main())
