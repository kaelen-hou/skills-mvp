#!/usr/bin/env python3
"""
Shared utilities for code analysis scripts.
"""

import re
from pathlib import Path
from typing import List, Set

# Supported source file extensions
SOURCE_EXTENSIONS: Set[str] = {'.py', '.js', '.ts', '.jsx', '.tsx'}
WEB_EXTENSIONS: Set[str] = {'.vue', '.html'}

# Directories to exclude from scanning
EXCLUDE_DIRS: Set[str] = {'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build', '.git'}

# Comment patterns for line counting
COMMENT_PATTERNS = [
    re.compile(r'^\s*#'),           # Python
    re.compile(r'^\s*//'),          # JS/TS
    re.compile(r'^\s*/\*'),         # Multi-line start
    re.compile(r'^\s*\*'),          # Multi-line body
    re.compile(r'^\s*\*/'),         # Multi-line end
    re.compile(r'^\s*"""'),         # Python docstring
    re.compile(r"^\s*'''"),         # Python docstring
]


def get_source_files(
    path: Path,
    extensions: Set[str] = SOURCE_EXTENSIONS,
    recursive: bool = True,
    exclude_dirs: Set[str] = EXCLUDE_DIRS,
    exclude_patterns: List[str] = None
) -> List[Path]:
    """
    Get all source files from path.

    Args:
        path: File or directory to search
        extensions: File extensions to include
        recursive: Whether to search subdirectories
        exclude_dirs: Directory names to skip
        exclude_patterns: Glob patterns to exclude (e.g., ['*_test.py'])

    Returns:
        Sorted list of matching file paths
    """
    exclude_patterns = exclude_patterns or []

    if path.is_file():
        return [path] if path.suffix.lower() in extensions else []

    if recursive:
        files = []
        for ext in extensions:
            files.extend(path.rglob(f'*{ext}'))
    else:
        files = [f for f in path.iterdir()
                 if f.is_file() and f.suffix.lower() in extensions]

    # Filter out excluded directories
    files = [f for f in files if not any(d in f.parts for d in exclude_dirs)]

    # Filter out excluded patterns
    for pattern in exclude_patterns:
        excluded = set(path.rglob(pattern)) if recursive else set(path.glob(pattern))
        files = [f for f in files if f not in excluded]

    return sorted(files)


def is_comment_line(line: str) -> bool:
    """Check if a line is a comment."""
    return any(p.match(line) for p in COMMENT_PATTERNS)


def count_lines(content: str) -> dict:
    """
    Count different types of lines in source code.

    Returns:
        Dict with 'total', 'code', 'comment', 'blank' counts
    """
    lines = content.split('\n')
    total = len(lines)
    blank = sum(1 for line in lines if not line.strip())
    comment = sum(1 for line in lines if is_comment_line(line))
    code = total - blank - comment

    return {
        'total': total,
        'code': max(0, code),
        'comment': comment,
        'blank': blank
    }
