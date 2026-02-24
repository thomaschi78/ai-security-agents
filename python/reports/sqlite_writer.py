"""SQLite report writer for queryable results."""

import sqlite3
from pathlib import Path
from typing import Optional
from datetime import datetime

from ..results import ScanResult


class SQLiteWriter:
    """Writes scan results to SQLite database."""

    def __init__(self):
        self._connection: Optional[sqlite3.Connection] = None

    def write(self, result: ScanResult, output_path: str) -> str:
        """
        Write scan result to SQLite database.

        Args:
            result: Scan result to write
            output_path: Output file path

        Returns:
            Path to written file
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Create connection
        self._connection = sqlite3.connect(str(path))

        try:
            self._create_tables()
            self._insert_scan(result)
            self._insert_vulnerabilities(result)
            self._connection.commit()
        finally:
            self._connection.close()
            self._connection = None

        return str(path)

    def _create_tables(self) -> None:
        """Create database schema."""
        cursor = self._connection.cursor()

        # Scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target_url TEXT,
                start_time TEXT,
                end_time TEXT,
                duration_seconds REAL,
                total_findings INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER,
                payloads_tested INTEGER,
                agents_used TEXT
            )
        ''')

        # Vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                scan_id TEXT,
                vulnerability_type TEXT,
                cweid INTEGER,
                severity TEXT,
                confidence_score REAL,
                confidence_level TEXT,
                url TEXT,
                parameter TEXT,
                method TEXT,
                payload TEXT,
                evidence TEXT,
                indicators TEXT,
                discovered_at TEXT,
                agent_id TEXT,
                stage TEXT,
                reasoning TEXT,
                owasp_category TEXT,
                remediation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')

        # Audit log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                timestamp TEXT,
                log_type TEXT,
                agent_id TEXT,
                action TEXT,
                details TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')

        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_scan ON vulnerabilities(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_type ON vulnerabilities(vulnerability_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_url ON vulnerabilities(url)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_scan ON audit_log(scan_id)')

    def _insert_scan(self, result: ScanResult) -> None:
        """Insert scan record."""
        cursor = self._connection.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO scans
            (id, target_url, start_time, end_time, duration_seconds,
             total_findings, critical_count, high_count, medium_count, low_count,
             payloads_tested, agents_used)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            result.id,
            result.target.url if result.target else None,
            result.start_time.isoformat(),
            result.end_time.isoformat() if result.end_time else None,
            result.duration_seconds,
            result.vulnerability_count,
            result.critical_count,
            result.high_count,
            result.medium_count,
            result.low_count,
            result.payloads_tested,
            ",".join(result.agents_used),
        ))

    def _insert_vulnerabilities(self, result: ScanResult) -> None:
        """Insert vulnerability records."""
        cursor = self._connection.cursor()

        for vuln in result.vulnerabilities:
            cursor.execute('''
                INSERT OR REPLACE INTO vulnerabilities
                (id, scan_id, vulnerability_type, cweid, severity, confidence_score,
                 confidence_level, url, parameter, method, payload, evidence,
                 indicators, discovered_at, agent_id, stage, reasoning,
                 owasp_category, remediation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vuln.id,
                result.id,
                vuln.vulnerability_type,
                vuln.cweid,
                vuln.severity.value,
                vuln.confidence_score,
                vuln.confidence_level.value,
                vuln.url,
                vuln.parameter,
                vuln.method,
                vuln.payload,
                vuln.evidence[:1000] if vuln.evidence else None,
                ",".join(vuln.indicators),
                vuln.discovered_at.isoformat(),
                vuln.agent_id,
                vuln.stage,
                "\n".join(vuln.reasoning),
                vuln.owasp_category,
                vuln.get_remediation(),
            ))

    def add_audit_entries(self, db_path: str, scan_id: str, entries: list) -> None:
        """Add audit log entries to existing database."""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        for entry in entries:
            cursor.execute('''
                INSERT INTO audit_log
                (scan_id, timestamp, log_type, agent_id, action, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                entry.get("timestamp", datetime.utcnow().isoformat()),
                entry.get("type", "unknown"),
                entry.get("agent_id", ""),
                entry.get("action_type", entry.get("event", "")),
                str(entry),
            ))

        conn.commit()
        conn.close()


def query_database(db_path: str, query: str) -> list:
    """
    Execute a query on the results database.

    Args:
        db_path: Path to SQLite database
        query: SQL query to execute

    Returns:
        List of result rows as dictionaries
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(query)
    rows = cursor.fetchall()

    result = [dict(row) for row in rows]
    conn.close()

    return result
