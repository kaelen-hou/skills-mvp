# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Claude Code Skill for code review assistance. It provides structured checklists and automated analysis scripts for reviewing code quality, security, and performance.

## Commands

```bash
# Analyze code metrics (lines, complexity, functions)
python scripts/analyze.py <file_or_directory>
python scripts/analyze.py scripts/ -r --output json
python scripts/analyze.py src/ --exclude '*_test.py'

# Scan for security vulnerabilities
python scripts/security_scan.py <file_or_directory>
python scripts/security_scan.py scripts/ --severity high
python scripts/security_scan.py src/ --exclude 'test_*'
```

## Architecture

```
code-review-assistant/
├── SKILL.md              # Skill entry point (YAML metadata + workflow)
├── references/           # Review checklists (loaded on-demand)
│   ├── SECURITY.md       # SQL injection, XSS, auth, credentials
│   ├── PERFORMANCE.md    # N+1 queries, memory, caching
│   └── QUALITY.md        # Naming, complexity, DRY, error handling
└── scripts/              # Analysis tools
    ├── utils.py          # Shared utilities (get_source_files, count_lines)
    ├── analyze.py        # Code metrics: lines, functions, complexity
    └── security_scan.py  # Pattern-based vulnerability detection
```

## Skill Structure

This follows the Claude Code Skills three-layer loading pattern:
- **Layer 1**: YAML frontmatter (`name`, `description`, `allowed-tools`) - always loaded
- **Layer 2**: SKILL.md body - loaded when skill is triggered
- **Layer 3**: references/*.md and scripts/* - loaded on-demand

The `description` field in SKILL.md determines when Claude activates this skill (triggers on "code review", "security audit", etc.).
