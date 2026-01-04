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


def count_lines(content: str) -> dict:
    """Count different types of lines in source code."""
    lines = content.split('\n')
    total = len(lines)
    blank = sum(1 for line in lines if not line.strip())

    comment_patterns = [
        r'^\s*#',
        r'^\s*//',
        r'^\s*/\*',
        r'^\s*\*',
        r'^\s*\*/',
        r'^\s*"""',
        r"^\s*'''",
    ]
    comment = sum(1 for line in lines
                  if any(re.match(p, line) for p in comment_patterns))

    code = total - blank - comment

    return {
        'total': total,
        'code': max(0, code),
        'comment': comment,
        'blank': blank
    }


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

            end_line = start_line
            for j in range(i + 1, len(lines)):
                line = lines[j]
                if line.strip() and not line.startswith(' ' * (indent + 1)) and \
                   not line.strip().startswith('#'):
                    if len(line) - len(line.lstrip()) <= indent:
                        break
                end_line = j + 1

            func_content = '\n'.join(lines[i:end_line])
            complexity = estimate_complexity(func_content)

            functions.append(FunctionMetrics(
                name=name,
                start_line=start_line,
                end_line=end_line,
                line_count=end_line - start_line + 1,
                complexity=complexity
            ))
            i = end_line
        else:
            i += 1

    return functions


def extract_functions_js(content: str) -> List[FunctionMetrics]:
    """Extract function metrics from JavaScript/TypeScript code."""
    functions = []
    lines = content.split('\n')

    patterns = [
        re.compile(r'^\s*(?:async\s+)?function\s+(\w+)'),
        re.compile(r'^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\('),
        re.compile(r'^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?function'),
        re.compile(r'^\s*(\w+)\s*\([^)]*\)\s*(?::\s*\w+)?\s*{'),
    ]

    i = 0
    while i < len(lines):
        name = None
        for pattern in patterns:
            match = pattern.match(lines[i])
            if match:
                name = match.group(1)
                break

        if name:
            start_line = i + 1
            brace_count = lines[i].count('{') - lines[i].count('}')
            end_line = start_line

            for j in range(i + 1, len(lines)):
                brace_count += lines[j].count('{') - lines[j].count('}')
                end_line = j + 1
                if brace_count <= 0:
                    break

            func_content = '\n'.join(lines[i:end_line])
            complexity = estimate_complexity(func_content)

            functions.append(FunctionMetrics(
                name=name,
                start_line=start_line,
                end_line=end_line,
                line_count=end_line - start_line + 1,
                complexity=complexity
            ))
            i = end_line
        else:
            i += 1

    return functions


def estimate_complexity(code: str) -> int:
    """Estimate cyclomatic complexity by counting decision points."""
    decision_keywords = [
        r'\bif\b', r'\belif\b', r'\belse\b',
        r'\bfor\b', r'\bwhile\b',
        r'\bcase\b', r'\bcatch\b',
        r'\band\b', r'\bor\b',
        r'\?\?', r'\|\|', r'&&',
    ]

    complexity = 1
    for pattern in decision_keywords:
        complexity += len(re.findall(pattern, code))

    return complexity


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


def get_source_files(path: Path, recursive: bool = False) -> List[Path]:
    """Get all source files from path."""
    extensions = {'.py', '.js', '.ts', '.jsx', '.tsx'}

    if path.is_file():
        return [path] if path.suffix in extensions else []

    if recursive:
        files = []
        for ext in extensions:
            files.extend(path.rglob(f'*{ext}'))
        return sorted(files)
    else:
        return sorted(f for f in path.iterdir()
                     if f.is_file() and f.suffix in extensions)


def format_text_output(metrics: List[FileMetrics]) -> str:
    """Format metrics as human-readable text."""
    output = []
    output.append("=" * 60)
    output.append("CODE METRICS ANALYSIS")
    output.append("=" * 60)

    total_files = len(metrics)
    total_lines = sum(m.total_lines for m in metrics)
    total_code = sum(m.code_lines for m in metrics)
    total_functions = sum(len(m.functions) for m in metrics)

    output.append(f"\nSUMMARY")
    output.append(f"  Files analyzed: {total_files}")
    output.append(f"  Total lines: {total_lines}")
    output.append(f"  Code lines: {total_code}")
    output.append(f"  Functions found: {total_functions}")

    for m in metrics:
        output.append(f"\n{'-' * 60}")
        output.append(f"File: {m.path}")
        output.append(f"  Lines: {m.total_lines} (code: {m.code_lines}, "
                     f"comments: {m.comment_lines}, blank: {m.blank_lines})")
        output.append(f"  Functions: {len(m.functions)}")
        output.append(f"  Avg function length: {m.avg_function_length} lines")
        output.append(f"  Max function length: {m.max_function_length} lines")
        output.append(f"  Total complexity: {m.total_complexity}")

        if m.functions:
            output.append(f"\n  Functions:")
            for f in m.functions:
                output.append(f"    - {f.name} (lines {f.start_line}-{f.end_line}, "
                             f"len: {f.line_count}, complexity: {f.complexity})")

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

    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        print(f"Error: Path does not exist: {path}", file=sys.stderr)
        sys.exit(1)

    files = get_source_files(path, args.recursive)
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
