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
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List


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


SECURITY_PATTERNS = [
    {
        'category': 'Code Injection',
        'severity': 'high',
        'patterns': [
            (r'\beval\s*\(', 'eval() usage'),
            (r'\bexec\s*\(', 'exec() usage'),
            (r'subprocess\..*shell\s*=\s*True', 'Shell execution with shell=True'),
            (r'os\.system\s*\(', 'os.system() usage'),
            (r'os\.popen\s*\(', 'os.popen() usage'),
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
            (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password'),
            (r'api_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key'),
            (r'secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret'),
            (r'AWS_SECRET_ACCESS_KEY\s*=\s*["\']', 'Hardcoded AWS secret'),
        ],
        'description': 'Credentials in code can be exposed in version control',
        'recommendation': 'Use environment variables or secure secret management'
    },
    {
        'category': 'Cross-Site Scripting (XSS)',
        'severity': 'medium',
        'patterns': [
            (r'\.innerHTML\s*=', 'Direct innerHTML assignment'),
            (r'dangerouslySetInnerHTML', 'React dangerouslySetInnerHTML'),
            (r'document\.write\s*\(', 'document.write usage'),
            (r'\bv-html\b', 'Vue v-html directive'),
        ],
        'description': 'Rendering unsanitized HTML can lead to XSS attacks',
        'recommendation': 'Sanitize HTML content or use text content instead'
    },
    {
        'category': 'Path Traversal',
        'severity': 'medium',
        'patterns': [
            (r'open\s*\(.*\+', 'Dynamic file path with concatenation'),
            (r'open\s*\(.*\.format\(', 'Dynamic file path with format'),
            (r'open\s*\(.*[fF]["\']', 'Dynamic file path with f-string'),
        ],
        'description': 'User input in file paths can access unintended files',
        'recommendation': 'Validate paths against allowed directories'
    },
    {
        'category': 'Insecure Randomness',
        'severity': 'medium',
        'patterns': [
            (r'\brandom\s*\.\s*random\s*\(', 'random.random() for security'),
            (r'Math\.random\s*\(', 'Math.random() for security'),
        ],
        'description': 'Weak random functions should not be used for security',
        'recommendation': 'Use secrets module (Python) or crypto (Node.js)'
    },
    {
        'category': 'Debug Code',
        'severity': 'low',
        'patterns': [
            (r'\bprint\s*\(.*password', 'Debug print with password'),
            (r'\bconsole\.log\s*\(.*token', 'Console log with token'),
            (r'DEBUG\s*=\s*True', 'Debug mode enabled'),
        ],
        'description': 'Debug code may expose sensitive information',
        'recommendation': 'Remove debug code before production deployment'
    },
    {
        'category': 'Error Handling',
        'severity': 'low',
        'patterns': [
            (r'except\s*:', 'Bare except clause'),
            (r'catch\s*\(\s*\)', 'Empty catch block'),
        ],
        'description': 'Poor error handling can hide security issues',
        'recommendation': 'Handle specific exceptions appropriately'
    },
]


def scan_file(file_path: Path, severity_filter: str = 'all') -> List[SecurityFinding]:
    """Scan a single file for security patterns."""
    findings = []

    try:
        content = file_path.read_text(encoding='utf-8')
        lines = content.split('\n')
    except Exception as e:
        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)
        return findings

    severity_levels = {'high': 3, 'medium': 2, 'low': 1}
    min_severity = severity_levels.get(severity_filter, 0)

    for pattern_group in SECURITY_PATTERNS:
        group_severity = severity_levels.get(pattern_group['severity'], 0)

        if severity_filter != 'all' and group_severity < min_severity:
            continue

        for pattern_regex, pattern_name in pattern_group['patterns']:
            regex = re.compile(pattern_regex, re.IGNORECASE)

            for line_num, line in enumerate(lines, 1):
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


def get_source_files(path: Path) -> List[Path]:
    """Get all source files from path."""
    extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.vue', '.html'}

    if path.is_file():
        return [path] if path.suffix in extensions else []

    files = []
    for ext in extensions:
        files.extend(path.rglob(f'*{ext}'))

    exclude_dirs = {'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build'}
    files = [f for f in files if not any(d in f.parts for d in exclude_dirs)]

    return sorted(files)


def format_text_output(findings: List[SecurityFinding]) -> str:
    """Format findings as human-readable text."""
    if not findings:
        return "No security issues found."

    output = []
    output.append("=" * 60)
    output.append("SECURITY SCAN RESULTS")
    output.append("=" * 60)

    high = sum(1 for f in findings if f.severity == 'high')
    medium = sum(1 for f in findings if f.severity == 'medium')
    low = sum(1 for f in findings if f.severity == 'low')

    output.append(f"\nSUMMARY")
    output.append(f"  Total findings: {len(findings)}")
    output.append(f"  High: {high} | Medium: {medium} | Low: {low}")

    for severity in ['high', 'medium', 'low']:
        severity_findings = [f for f in findings if f.severity == severity]
        if not severity_findings:
            continue

        output.append(f"\n{'=' * 60}")
        output.append(f"{severity.upper()} SEVERITY")
        output.append("=" * 60)

        for f in severity_findings:
            output.append(f"\n[{f.category}] {f.pattern}")
            output.append(f"  File: {f.file}:{f.line}")
            output.append(f"  Code: {f.code}")
            output.append(f"  Fix: {f.recommendation}")

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

    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        print(f"Error: Path does not exist: {path}", file=sys.stderr)
        sys.exit(1)

    files = get_source_files(path)
    if not files:
        print(f"No source files found in: {path}", file=sys.stderr)
        sys.exit(1)

    all_findings = []
    for file_path in files:
        findings = scan_file(file_path, args.severity)
        all_findings.extend(findings)

    severity_order = {'high': 0, 'medium': 1, 'low': 2}
    all_findings.sort(key=lambda f: (severity_order[f.severity], f.file, f.line))

    if args.output == 'json':
        data = [asdict(f) for f in all_findings]
        print(json.dumps(data, indent=2))
    else:
        print(format_text_output(all_findings))

    high_count = sum(1 for f in all_findings if f.severity == 'high')
    if high_count > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
