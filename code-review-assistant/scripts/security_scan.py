#!/usr/bin/env python3
"""
Security Pattern Scanner

Scans code for common security vulnerability patterns.

Usage:
    python security_scan.py <file_or_directory> [--severity all|high|medium|low]
    python security_scan.py <path> --output json

Examples:
    python security_scan.py src/
    python security_scan.py app.py --severity high
    python security_scan.py src/ --exclude '*_test.py'
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Set

from utils import get_source_files, SOURCE_EXTENSIONS, WEB_EXTENSIONS


@dataclass
class SecurityFinding:
    file: str
    line: int
    severity: str
    category: str
    pattern: str
    code: str
    description: str
    recommendation: str


# Severity levels for filtering
SEVERITY_LEVELS = {'high': 3, 'medium': 2, 'low': 1}

# Security patterns to detect
# Note: Pattern strings use 'noqa' comment style to prevent self-detection
SECURITY_PATTERNS = [
    {
        'category': 'Code Injection',
        'severity': 'high',
        'patterns': [
            (r'\beval\s*\([^)]*\)', 'eval() usage'),  # noqa: security
            (r'\bexec\s*\([^)]*\)', 'exec() usage'),  # noqa: security
            (r'subprocess\..*shell\s*=\s*True', 'Shell execution with shell=True'),
            (r'os\.system\s*\([^)]*\)', 'os.system() usage'),  # noqa: security
            (r'os\.popen\s*\([^)]*\)', 'os.popen() usage'),  # noqa: security
        ],
        'description': 'Code execution functions can lead to command injection',
        'recommendation': 'Use safer alternatives or validate/sanitize all input'
    },
    {
        'category': 'SQL Injection',
        'severity': 'high',
        'patterns': [
            (r'execute\s*\(\s*[f"\'].*%[sd]', 'String formatting in SQL query'),
            (r'execute\s*\(\s*[f"\'].*\{', 'F-string in SQL query'),
            (r'execute\s*\(\s*.*\+\s*', 'String concatenation in SQL query'),
        ],
        'description': 'SQL queries built with user input can allow injection attacks',
        'recommendation': 'Use parameterized queries with placeholders'
    },
    {
        'category': 'Hardcoded Credentials',
        'severity': 'high',
        'patterns': [
            (r'password\s*=\s*["\'][^"\']{4,}["\']', 'Hardcoded password'),
            (r'api_key\s*=\s*["\'][^"\']{8,}["\']', 'Hardcoded API key'),
            (r'secret\s*=\s*["\'][^"\']{8,}["\']', 'Hardcoded secret'),
            (r'AWS_SECRET_ACCESS_KEY\s*=\s*["\']', 'Hardcoded AWS secret'),
        ],
        'description': 'Credentials in code can be exposed in version control',
        'recommendation': 'Use environment variables or secure secret management'
    },
    {
        'category': 'Cross-Site Scripting (XSS)',
        'severity': 'medium',
        'patterns': [
            (r'\.innerHTML\s*=\s*[^;]+;', 'Direct innerHTML assignment'),
            (r'dangerouslySetInnerHTML\s*=', 'React dangerouslySetInnerHTML'),
            (r'document\.write\s*\([^)]+\)', 'document.write usage'),
            (r'\bv-html\s*=', 'Vue v-html directive'),
        ],
        'description': 'Rendering unsanitized HTML can lead to XSS attacks',
        'recommendation': 'Sanitize HTML content or use text content instead'
    },
    {
        'category': 'Path Traversal',
        'severity': 'medium',
        'patterns': [
            (r'open\s*\([^)]*\+[^)]*\)', 'Dynamic file path with concatenation'),
            (r'open\s*\([^)]*\.format\([^)]*\)', 'Dynamic file path with format'),
        ],
        'description': 'User input in file paths can access unintended files',
        'recommendation': 'Validate paths against allowed directories'
    },
    {
        'category': 'Insecure Randomness',
        'severity': 'medium',
        'patterns': [
            (r'random\.random\s*\(\)', 'random.random() for security'),
            (r'random\.randint\s*\([^)]+\)', 'random.randint() for security'),
            (r'Math\.random\s*\(\)', 'Math.random() for security'),
        ],
        'description': 'Weak random functions should not be used for security',
        'recommendation': 'Use secrets module (Python) or crypto (Node.js)'
    },
    {
        'category': 'Debug Code',
        'severity': 'low',
        'patterns': [
            (r'\bprint\s*\([^)]*password[^)]*\)', 'Debug print with password'),
            (r'\bconsole\.log\s*\([^)]*token[^)]*\)', 'Console log with token'),
            (r'^\s*DEBUG\s*=\s*True\s*$', 'Debug mode enabled'),
        ],
        'description': 'Debug code may expose sensitive information',
        'recommendation': 'Remove debug code before production deployment'
    },
    {
        'category': 'Error Handling',
        'severity': 'low',
        'patterns': [
            (r'except\s*:\s*$', 'Bare except clause'),
            (r'catch\s*\(\s*\)\s*\{', 'Empty catch block'),
        ],
        'description': 'Poor error handling can hide security issues',
        'recommendation': 'Handle specific exceptions appropriately'
    },
]


def is_pattern_definition_line(line: str) -> bool:
    """Check if line is defining a pattern (to avoid self-detection)."""
    # Skip lines that are regex pattern definitions or comments
    pattern_indicators = [
        "r'\\b",       # Raw string regex start
        'r"\\b',       # Raw string regex start
        "r'\\.",       # Raw string with escaped dot
        'r"\\.',       # Raw string with escaped dot
        "r'random",    # Random pattern definition
        'r"random',    # Random pattern definition
        "r'Math",      # Math pattern definition
        'r"Math',      # Math pattern definition
        "re.compile",  # Compiled regex
        "# noqa",      # Explicit ignore
        "'patterns':", # Pattern dict key
        '"patterns":', # Pattern dict key
    ]
    return any(indicator in line for indicator in pattern_indicators)


def scan_file(
    file_path: Path,
    severity_filter: str = 'all',
    skip_self: bool = True
) -> List[SecurityFinding]:
    """
    Scan a single file for security patterns.

    Args:
        file_path: Path to file to scan
        severity_filter: Minimum severity level to report
        skip_self: Skip pattern definition lines (avoid false positives)
    """
    findings = []

    try:
        content = file_path.read_text(encoding='utf-8')
        lines = content.split('\n')
    except Exception as e:
        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)
        return findings

    min_severity = SEVERITY_LEVELS.get(severity_filter, 0)

    for pattern_group in SECURITY_PATTERNS:
        group_severity = SEVERITY_LEVELS.get(pattern_group['severity'], 0)

        if severity_filter != 'all' and group_severity < min_severity:
            continue

        for pattern_regex, pattern_name in pattern_group['patterns']:
            regex = re.compile(pattern_regex, re.IGNORECASE)

            for line_num, line in enumerate(lines, 1):
                # Skip pattern definition lines to avoid false positives
                if skip_self and is_pattern_definition_line(line):
                    continue

                if regex.search(line):
                    findings.append(SecurityFinding(
                        file=str(file_path),
                        line=line_num,
                        severity=pattern_group['severity'],
                        category=pattern_group['category'],
                        pattern=pattern_name,
                        code=line.strip()[:80],
                        description=pattern_group['description'],
                        recommendation=pattern_group['recommendation']
                    ))

    return findings


def format_severity_section(findings: List[SecurityFinding], severity: str) -> List[str]:
    """Format findings for a single severity level."""
    severity_findings = [f for f in findings if f.severity == severity]
    if not severity_findings:
        return []

    output = [
        f"\n{'=' * 60}",
        f"{severity.upper()} SEVERITY ({len(severity_findings)})",
        "=" * 60,
    ]

    for f in severity_findings:
        output.extend([
            f"\n[{f.category}] {f.pattern}",
            f"  File: {f.file}:{f.line}",
            f"  Code: {f.code}",
            f"  Fix: {f.recommendation}",
        ])

    return output


def format_text_output(findings: List[SecurityFinding]) -> str:
    """Format findings as human-readable text."""
    if not findings:
        return "No security issues found."

    high = sum(1 for f in findings if f.severity == 'high')
    medium = sum(1 for f in findings if f.severity == 'medium')
    low = sum(1 for f in findings if f.severity == 'low')

    output = [
        "=" * 60,
        "SECURITY SCAN RESULTS",
        "=" * 60,
        f"\nSUMMARY",
        f"  Total findings: {len(findings)}",
        f"  High: {high} | Medium: {medium} | Low: {low}",
    ]

    for severity in ['high', 'medium', 'low']:
        output.extend(format_severity_section(findings, severity))

    return '\n'.join(output)


def main():
    parser = argparse.ArgumentParser(
        description='Scan code for security vulnerability patterns'
    )
    parser.add_argument('path', help='File or directory to scan')
    parser.add_argument('--severity', choices=['all', 'high', 'medium', 'low'],
                       default='all', help='Minimum severity to report')
    parser.add_argument('--output', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--exclude', '-e', action='append', default=[],
                       help='Glob patterns to exclude (can be used multiple times)')
    parser.add_argument('--no-skip-self', action='store_true',
                       help='Do not skip pattern definition lines')

    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        print(f"Error: Path does not exist: {path}", file=sys.stderr)
        sys.exit(1)

    # Combine source and web extensions for security scanning
    all_extensions: Set[str] = SOURCE_EXTENSIONS | WEB_EXTENSIONS

    files = get_source_files(
        path,
        extensions=all_extensions,
        recursive=True,
        exclude_patterns=args.exclude
    )

    if not files:
        print(f"No source files found in: {path}", file=sys.stderr)
        sys.exit(1)

    all_findings = []
    for file_path in files:
        findings = scan_file(
            file_path,
            args.severity,
            skip_self=not args.no_skip_self
        )
        all_findings.extend(findings)

    # Sort by severity (high first) then by file
    severity_order = {'high': 0, 'medium': 1, 'low': 2}
    all_findings.sort(key=lambda f: (severity_order[f.severity], f.file, f.line))

    if args.output == 'json':
        data = [asdict(f) for f in all_findings]
        print(json.dumps(data, indent=2))
    else:
        print(format_text_output(all_findings))

    # Exit with error code if high severity issues found
    high_count = sum(1 for f in all_findings if f.severity == 'high')
    if high_count > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
