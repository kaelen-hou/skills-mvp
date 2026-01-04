#!/usr/bin/env python3
"""
Code Metrics Analyzer

Analyzes code files for complexity, line counts, and function metrics.
Supports Python and JavaScript/TypeScript files.

Usage:
    python analyze.py <file_or_directory> [--output json|text] [--recursive]

Examples:
    python analyze.py src/main.py
    python analyze.py ./src --recursive --output json
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional

from utils import get_source_files, count_lines, SOURCE_EXTENSIONS


@dataclass
class FunctionMetrics:
    name: str
    start_line: int
    end_line: int
    line_count: int
    complexity: int


@dataclass
class FileMetrics:
    path: str
    total_lines: int
    code_lines: int
    comment_lines: int
    blank_lines: int
    functions: List[FunctionMetrics]
    avg_function_length: float
    max_function_length: int
    total_complexity: int


# Complexity estimation patterns
COMPLEXITY_PATTERNS = [
    re.compile(r'\bif\b'),
    re.compile(r'\belif\b'),
    re.compile(r'\belse\b'),
    re.compile(r'\bfor\b'),
    re.compile(r'\bwhile\b'),
    re.compile(r'\bcase\b'),
    re.compile(r'\bcatch\b'),
    re.compile(r'\band\b'),
    re.compile(r'\bor\b'),
    re.compile(r'\?\?'),
    re.compile(r'\|\|'),
    re.compile(r'&&'),
]


def estimate_complexity(code: str) -> int:
    """Estimate cyclomatic complexity by counting decision points."""
    complexity = 1
    for pattern in COMPLEXITY_PATTERNS:
        complexity += len(pattern.findall(code))
    return complexity


def find_python_function_end(lines: List[str], start_idx: int, indent: int) -> int:
    """Find where a Python function ends based on indentation."""
    end_line = start_idx + 1
    for j in range(start_idx + 1, len(lines)):
        line = lines[j]
        if line.strip() and not line.strip().startswith('#'):
            current_indent = len(line) - len(line.lstrip())
            if current_indent <= indent:
                break
        end_line = j + 1
    return end_line


def extract_functions_python(content: str) -> List[FunctionMetrics]:
    """Extract function metrics from Python code."""
    functions = []
    lines = content.split('\n')
    func_pattern = re.compile(r'^(\s*)def\s+(\w+)\s*\(')

    i = 0
    while i < len(lines):
        match = func_pattern.match(lines[i])
        if match:
            indent = len(match.group(1))
            name = match.group(2)
            start_line = i + 1
            end_line = find_python_function_end(lines, i, indent)

            func_content = '\n'.join(lines[i:end_line])
            functions.append(FunctionMetrics(
                name=name,
                start_line=start_line,
                end_line=end_line,
                line_count=end_line - start_line + 1,
                complexity=estimate_complexity(func_content)
            ))
            i = end_line
        else:
            i += 1

    return functions


def find_js_function_end(lines: List[str], start_idx: int) -> int:
    """Find where a JS/TS function ends by counting braces."""
    brace_count = lines[start_idx].count('{') - lines[start_idx].count('}')
    end_line = start_idx + 1

    for j in range(start_idx + 1, len(lines)):
        brace_count += lines[j].count('{') - lines[j].count('}')
        end_line = j + 1
        if brace_count <= 0:
            break

    return end_line


# JS/TS function patterns
JS_FUNCTION_PATTERNS = [
    re.compile(r'^\s*(?:async\s+)?function\s+(\w+)'),
    re.compile(r'^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\('),
    re.compile(r'^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?function'),
    re.compile(r'^\s*(\w+)\s*\([^)]*\)\s*(?::\s*\w+)?\s*\{'),
]


def extract_functions_js(content: str) -> List[FunctionMetrics]:
    """Extract function metrics from JavaScript/TypeScript code."""
    functions = []
    lines = content.split('\n')

    i = 0
    while i < len(lines):
        name = None
        for pattern in JS_FUNCTION_PATTERNS:
            match = pattern.match(lines[i])
            if match:
                name = match.group(1)
                break

        if name:
            start_line = i + 1
            end_line = find_js_function_end(lines, i)

            func_content = '\n'.join(lines[i:end_line])
            functions.append(FunctionMetrics(
                name=name,
                start_line=start_line,
                end_line=end_line,
                line_count=end_line - start_line + 1,
                complexity=estimate_complexity(func_content)
            ))
            i = end_line
        else:
            i += 1

    return functions


def analyze_file(file_path: Path) -> Optional[FileMetrics]:
    """Analyze a single source file."""
    try:
        content = file_path.read_text(encoding='utf-8')
    except Exception as e:
        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)
        return None

    line_counts = count_lines(content)

    suffix = file_path.suffix.lower()
    if suffix == '.py':
        functions = extract_functions_python(content)
    elif suffix in ['.js', '.ts', '.jsx', '.tsx']:
        functions = extract_functions_js(content)
    else:
        functions = []

    if functions:
        avg_length = sum(f.line_count for f in functions) / len(functions)
        max_length = max(f.line_count for f in functions)
        total_complexity = sum(f.complexity for f in functions)
    else:
        avg_length = 0
        max_length = 0
        total_complexity = 0

    return FileMetrics(
        path=str(file_path),
        total_lines=line_counts['total'],
        code_lines=line_counts['code'],
        comment_lines=line_counts['comment'],
        blank_lines=line_counts['blank'],
        functions=functions,
        avg_function_length=round(avg_length, 1),
        max_function_length=max_length,
        total_complexity=total_complexity
    )


def format_summary(metrics: List[FileMetrics]) -> List[str]:
    """Format the summary section."""
    total_files = len(metrics)
    total_lines = sum(m.total_lines for m in metrics)
    total_code = sum(m.code_lines for m in metrics)
    total_functions = sum(len(m.functions) for m in metrics)

    return [
        "=" * 60,
        "CODE METRICS ANALYSIS",
        "=" * 60,
        f"\nSUMMARY",
        f"  Files analyzed: {total_files}",
        f"  Total lines: {total_lines}",
        f"  Code lines: {total_code}",
        f"  Functions found: {total_functions}",
    ]


def format_file_metrics(m: FileMetrics) -> List[str]:
    """Format metrics for a single file."""
    output = [
        f"\n{'-' * 60}",
        f"File: {m.path}",
        f"  Lines: {m.total_lines} (code: {m.code_lines}, "
        f"comments: {m.comment_lines}, blank: {m.blank_lines})",
        f"  Functions: {len(m.functions)}",
        f"  Avg function length: {m.avg_function_length} lines",
        f"  Max function length: {m.max_function_length} lines",
        f"  Total complexity: {m.total_complexity}",
    ]

    if m.functions:
        output.append(f"\n  Functions:")
        for f in m.functions:
            output.append(
                f"    - {f.name} (lines {f.start_line}-{f.end_line}, "
                f"len: {f.line_count}, complexity: {f.complexity})"
            )

    return output


def format_text_output(metrics: List[FileMetrics]) -> str:
    """Format metrics as human-readable text."""
    output = format_summary(metrics)

    for m in metrics:
        output.extend(format_file_metrics(m))

    output.append("\n" + "=" * 60)
    return '\n'.join(output)


def main():
    parser = argparse.ArgumentParser(
        description='Analyze code metrics for source files'
    )
    parser.add_argument('path', help='File or directory to analyze')
    parser.add_argument('--output', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--recursive', '-r', action='store_true',
                       help='Recursively analyze directories')
    parser.add_argument('--exclude', '-e', action='append', default=[],
                       help='Glob patterns to exclude (can be used multiple times)')

    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        print(f"Error: Path does not exist: {path}", file=sys.stderr)
        sys.exit(1)

    files = get_source_files(
        path,
        extensions=SOURCE_EXTENSIONS,
        recursive=args.recursive,
        exclude_patterns=args.exclude
    )

    if not files:
        print(f"No source files found in: {path}", file=sys.stderr)
        sys.exit(1)

    metrics = []
    for file_path in files:
        result = analyze_file(file_path)
        if result:
            metrics.append(result)

    if args.output == 'json':
        data = [asdict(m) for m in metrics]
        print(json.dumps(data, indent=2))
    else:
        print(format_text_output(metrics))


if __name__ == '__main__':
    main()
