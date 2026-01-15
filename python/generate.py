#!/usr/bin/env python3
"""Generate patterns_gen.py from YAML pattern definitions.

Reads patterns/patterns.yaml, patterns/env.yaml, and patterns/entropy.yaml,
generates python/patterns_gen.py with compiled pattern definitions for kahl.

Uses yq CLI for YAML parsing (no Python YAML dependency needed).

Usage:
    python generate.py              # Generate patterns_gen.py
    python generate.py --check      # Check if patterns_gen.py is up to date
"""
import hashlib
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Paths relative to this script
SCRIPT_DIR = Path(__file__).parent.resolve()
REPO_ROOT = SCRIPT_DIR.parent
PATTERNS_DIR = REPO_ROOT / "patterns"
PATTERNS_YAML = PATTERNS_DIR / "patterns.yaml"
ENV_YAML = PATTERNS_DIR / "env.yaml"
ENTROPY_YAML = PATTERNS_DIR / "entropy.yaml"
OUTPUT_FILE = SCRIPT_DIR / "patterns_gen.py"
MAIN_SCRIPT = SCRIPT_DIR / "main.py"
STANDALONE_OUTPUT = SCRIPT_DIR / "kahl-standalone"


def run_yq(query: str, file: Path, strip: bool = True) -> str:
    """Run yq query on a YAML file and return output.

    Args:
        query: yq query string
        file: Path to YAML file
        strip: Whether to strip whitespace from output (default True).
               Set to False when fetching pattern strings that may have
               significant trailing whitespace.
    """
    result = subprocess.run(
        ["yq", "-r", query, str(file)],
        capture_output=True,
        text=True,
        check=True,
    )
    output = result.stdout
    if strip:
        return output.strip()
    # Remove only trailing newline, preserve other whitespace
    return output.rstrip("\n")


def get_yq_list(query: str, file: Path) -> list[str]:
    """Get a list of strings from yq query."""
    output = run_yq(query, file)
    if not output or output == "null":
        return []
    return [line for line in output.split("\n") if line]


def compute_source_hash() -> str:
    """Compute combined hash of source YAML files."""
    hasher = hashlib.sha256()
    for path in sorted([PATTERNS_YAML, ENV_YAML, ENTROPY_YAML]):
        if path.exists():
            hasher.update(path.read_bytes())
    return hasher.hexdigest()[:12]


def extract_hash_from_generated(path: Path) -> str | None:
    """Extract source hash from generated file header."""
    if not path.exists():
        return None
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("# Source hash:"):
                    return line.split(":")[-1].strip()
                if not line.startswith("#"):
                    break
    except Exception:
        pass
    return None


def format_pattern_string(pattern: str) -> str:
    """Format a regex pattern as a Python raw string literal."""
    if "'" not in pattern:
        return f"r'{pattern}'"
    elif '"' not in pattern:
        return f'r"{pattern}"'
    else:
        # Both quote types present - escape single quotes by ending/restarting raw string
        # r'foo' + "'" + r'bar' -> foo'bar
        # Actually simpler: use regular string with escaped backslashes
        escaped = pattern.replace("\\", "\\\\").replace("'", "\\'")
        return f"'{escaped}'"


def generate_patterns() -> str:
    """Generate the PATTERNS list."""
    lines = ["PATTERNS = ["]

    # Get direct patterns
    count = int(run_yq(".patterns | length", PATTERNS_YAML))
    for i in range(count):
        pattern = run_yq(f".patterns[{i}].pattern", PATTERNS_YAML)
        label = run_yq(f".patterns[{i}].label", PATTERNS_YAML)
        multiline = run_yq(f".patterns[{i}].multiline // false", PATTERNS_YAML)

        # Skip multiline patterns (handled separately by state machine)
        if multiline == "true":
            continue

        lines.append(f"    ({format_pattern_string(pattern)}, '{label}'),")

    lines.append("]")
    return "\n".join(lines)


def generate_context_patterns() -> str:
    """Generate the CONTEXT_PATTERNS list using lookbehind."""
    lines = ["CONTEXT_PATTERNS = ["]

    count = int(run_yq(".context_patterns | length", PATTERNS_YAML))
    for i in range(count):
        # Use strip=False to preserve significant trailing whitespace in prefix
        prefix = run_yq(f".context_patterns[{i}].prefix", PATTERNS_YAML, strip=False)
        value = run_yq(f".context_patterns[{i}].value", PATTERNS_YAML, strip=False)
        label = run_yq(f".context_patterns[{i}].label", PATTERNS_YAML)

        # Python uses lookbehind: (?<=prefix)value
        pattern = f"(?<={prefix}){value}"
        lines.append(f"    ({format_pattern_string(pattern)}, '{label}'),")

    lines.append("]")
    return "\n".join(lines)


def generate_special_patterns() -> str:
    """Generate the SPECIAL_PATTERNS dict."""
    lines = ["SPECIAL_PATTERNS = {"]

    # Get special pattern keys
    keys = get_yq_list(".special_patterns | keys | .[]", PATTERNS_YAML)
    for key in keys:
        pattern = run_yq(f'.special_patterns.{key}.pattern', PATTERNS_YAML)
        label = run_yq(f'.special_patterns.{key}.label', PATTERNS_YAML)
        secret_group = run_yq(f'.special_patterns.{key}.secret_group', PATTERNS_YAML)

        lines.append(f"    '{key}': {{")
        lines.append(f"        'pattern': {format_pattern_string(pattern)},")
        lines.append(f"        'label': '{label}',")
        lines.append(f"        'secret_group': {secret_group},")
        lines.append("    },")

    lines.append("}")
    return "\n".join(lines)


def generate_private_key_patterns() -> str:
    """Generate private key begin/end regex strings."""
    begin = run_yq(".private_key.begin", PATTERNS_YAML)
    end = run_yq(".private_key.end", PATTERNS_YAML)

    lines = [
        f"PRIVATE_KEY_BEGIN = {format_pattern_string(begin)}",
        f"PRIVATE_KEY_END = {format_pattern_string(end)}",
    ]
    return "\n".join(lines)


def generate_env_vars() -> str:
    """Generate environment variable detection rules."""
    lines = []

    # Explicit variable names
    explicit = get_yq_list(".explicit[]", ENV_YAML)
    lines.append("EXPLICIT_ENV_VARS = {")
    for var in sorted(explicit):
        lines.append(f"    '{var}',")
    lines.append("}")
    lines.append("")

    # Suffixes
    suffixes = get_yq_list(".suffixes[]", ENV_YAML)
    lines.append("ENV_SUFFIXES = (")
    for suffix in suffixes:
        lines.append(f"    '{suffix}',")
    lines.append(")")

    return "\n".join(lines)


def generate_entropy_config() -> str:
    """Generate entropy detection configuration."""
    if not ENTROPY_YAML.exists():
        # Entropy config is optional - return minimal defaults
        return """\
# Entropy detection (disabled - entropy.yaml not found)
ENTROPY_ENABLED_DEFAULT = False
ENTROPY_THRESHOLDS = {'hex': 3.0, 'base64': 4.5, 'alphanumeric': 4.5}
ENTROPY_MIN_LENGTH = 16
ENTROPY_MAX_LENGTH = 256
ENTROPY_EXCLUSIONS = []
ENTROPY_CONTEXT_KEYWORDS = set()"""

    lines = []

    # Enabled by default
    enabled = run_yq(".enabled_by_default // false", ENTROPY_YAML)
    lines.append(f"ENTROPY_ENABLED_DEFAULT = {enabled.capitalize()}")
    lines.append("")

    # Thresholds
    hex_t = run_yq(".thresholds.hex // 3.0", ENTROPY_YAML)
    base64_t = run_yq(".thresholds.base64 // 4.5", ENTROPY_YAML)
    alnum_t = run_yq(".thresholds.alphanumeric // 4.5", ENTROPY_YAML)
    lines.append("ENTROPY_THRESHOLDS = {")
    lines.append(f"    'hex': {hex_t},")
    lines.append(f"    'base64': {base64_t},")
    lines.append(f"    'alphanumeric': {alnum_t},")
    lines.append("}")
    lines.append("")

    # Token length constraints
    min_len = run_yq(".token_length.min // 16", ENTROPY_YAML)
    max_len = run_yq(".token_length.max // 256", ENTROPY_YAML)
    lines.append(f"ENTROPY_MIN_LENGTH = {min_len}")
    lines.append(f"ENTROPY_MAX_LENGTH = {max_len}")
    lines.append("")

    # Exclusion patterns
    lines.append("ENTROPY_EXCLUSIONS = [")
    count = int(run_yq(".exclusions | length", ENTROPY_YAML))
    for i in range(count):
        pattern = run_yq(f".exclusions[{i}].pattern", ENTROPY_YAML)
        label = run_yq(f".exclusions[{i}].label", ENTROPY_YAML)
        case_insensitive = run_yq(f".exclusions[{i}].case_insensitive // false", ENTROPY_YAML)

        # Check for context keywords
        keywords_raw = run_yq(f".exclusions[{i}].context_keywords // null", ENTROPY_YAML)
        if keywords_raw and keywords_raw != "null":
            keywords = get_yq_list(f".exclusions[{i}].context_keywords[]", ENTROPY_YAML)
            keywords_str = repr(keywords)
        else:
            keywords_str = "None"

        lines.append("    {")
        lines.append(f"        'pattern': {format_pattern_string(pattern)},")
        lines.append(f"        'label': '{label}',")
        lines.append(f"        'case_insensitive': {case_insensitive.capitalize()},")
        lines.append(f"        'context_keywords': {keywords_str},")
        lines.append("    },")
    lines.append("]")
    lines.append("")

    # Context keywords (global list for quick lookup)
    keywords = get_yq_list(".context_keywords[]", ENTROPY_YAML)
    lines.append("ENTROPY_CONTEXT_KEYWORDS = {")
    for kw in sorted(keywords):
        lines.append(f"    '{kw}',")
    lines.append("}")

    return "\n".join(lines)


def generate_constants() -> str:
    """Generate constants from YAML."""
    long_threshold = run_yq(".constants.long_threshold", PATTERNS_YAML)
    max_buffer = run_yq(".constants.max_private_key_buffer", PATTERNS_YAML)

    lines = [
        f"LONG_THRESHOLD = {long_threshold}",
        f"MAX_PRIVATE_KEY_BUFFER = {max_buffer}",
    ]
    return "\n".join(lines)


def generate_file() -> str:
    """Generate the complete patterns_gen.py content."""
    source_hash = compute_source_hash()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    header = f'''\
# Generated by generate.py - DO NOT EDIT
# Source hash: {source_hash}
# Generated: {timestamp}
#
# This file is auto-generated from:
#   - patterns/patterns.yaml
#   - patterns/env.yaml
#   - patterns/entropy.yaml
#
# To regenerate: python python/generate.py
"""Auto-generated pattern definitions for kahl.

This module exports:
- PATTERNS: Direct regex patterns (regex_string, label)
- CONTEXT_PATTERNS: Patterns with lookbehind (regex_string, label)
- SPECIAL_PATTERNS: Complex patterns with capture groups
- PRIVATE_KEY_BEGIN, PRIVATE_KEY_END: Regex strings for state machine
- EXPLICIT_ENV_VARS: Set of known secret variable names
- ENV_SUFFIXES: Tuple of variable name suffixes indicating secrets
- LONG_THRESHOLD, MAX_PRIVATE_KEY_BUFFER: Integer constants
- ENTROPY_*: Entropy detection configuration
"""
'''

    sections = [
        header,
        "# Constants",
        generate_constants(),
        "",
        "# Direct patterns: (regex_string, label)",
        generate_patterns(),
        "",
        "# Context patterns using lookbehind: (regex_string, label)",
        generate_context_patterns(),
        "",
        "# Special patterns with capture groups",
        generate_special_patterns(),
        "",
        "# Private key markers for streaming state machine",
        generate_private_key_patterns(),
        "",
        "# Environment variable detection",
        generate_env_vars(),
        "",
        "# Entropy detection configuration",
        generate_entropy_config(),
        "",
    ]

    return "\n".join(sections)


def extract_filter_logic() -> str:
    """Extract filter logic from kahl, removing import/auto-gen block.

    Reads the kahl script and extracts everything after the
    patterns_gen import block (lines 81+), which is the actual filter logic.
    Also adjusts imports to remove subprocess and Path (not needed standalone).
    """
    if not MAIN_SCRIPT.exists():
        raise FileNotFoundError(f"kahl not found: {MAIN_SCRIPT}")

    lines = MAIN_SCRIPT.read_text().splitlines()

    # Find the line where filter logic starts (after 'from patterns_gen import')
    # Look for VALID_FILTERS definition as the start of real logic
    start_idx = None
    for i, line in enumerate(lines):
        if line.startswith("VALID_FILTERS"):
            start_idx = i
            break

    if start_idx is None:
        raise ValueError("Could not find VALID_FILTERS in kahl")

    # Extract filter logic
    filter_lines = lines[start_idx:]
    return "\n".join(filter_lines)


def generate_standalone() -> str:
    """Generate standalone kahl with patterns baked in."""
    source_hash = compute_source_hash()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Read version from VERSION file
    version_file = REPO_ROOT / "VERSION"
    version = version_file.read_text().strip() if version_file.exists() else "unknown"

    # Generate pattern data (same as patterns_gen.py but without module docstring)
    pattern_sections = [
        "# Constants",
        generate_constants(),
        "",
        "# Direct patterns: (regex_string, label)",
        generate_patterns(),
        "",
        "# Context patterns using lookbehind: (regex_string, label)",
        generate_context_patterns(),
        "",
        "# Special patterns with capture groups",
        generate_special_patterns(),
        "",
        "# Private key markers for streaming state machine",
        generate_private_key_patterns(),
        "",
        "# Environment variable detection",
        generate_env_vars(),
        "",
        "# Entropy detection configuration",
        generate_entropy_config(),
    ]
    pattern_data = "\n".join(pattern_sections)

    # Extract filter logic
    filter_logic = extract_filter_logic()

    # Combine into standalone script
    header = f'''\
#!/usr/bin/env python3
"""Standalone kahl with patterns baked in.

Generated by generate.py - DO NOT EDIT
Source hash: {source_hash}
Generated: {timestamp}

This is a standalone version of kahl with all pattern definitions
embedded as a single executable file.

To regenerate: python python/generate.py
"""
import math
import os
import re
import sys
from collections import Counter

# Version
__version__ = "{version}"

'''

    sections = [
        header,
        "# " + "=" * 76,
        "# Pattern Data (generated from YAML)",
        "# " + "=" * 76,
        "",
        pattern_data,
        "",
        "# " + "=" * 76,
        "# Filter Logic",
        "# " + "=" * 76,
        "",
        filter_logic,
    ]

    return "\n".join(sections)


def main() -> int:
    """Main entry point."""
    check_mode = "--check" in sys.argv

    # Verify source files exist
    for path in [PATTERNS_YAML, ENV_YAML]:
        if not path.exists():
            print(f"Error: Source file not found: {path}", file=sys.stderr)
            return 1

    # Verify yq is available
    try:
        subprocess.run(["yq", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: yq CLI not found. Install with: brew install yq", file=sys.stderr)
        return 1

    # Check mode: verify generated file is up to date
    if check_mode:
        current_hash = compute_source_hash()
        generated_hash = extract_hash_from_generated(OUTPUT_FILE)

        if generated_hash is None:
            print(f"Error: {OUTPUT_FILE.name} does not exist", file=sys.stderr)
            return 1

        if current_hash != generated_hash:
            print(
                f"Error: {OUTPUT_FILE.name} is stale "
                f"(source: {current_hash}, generated: {generated_hash})",
                file=sys.stderr,
            )
            print("Run: python python/generate.py", file=sys.stderr)
            return 1

        print(f"{OUTPUT_FILE.name} is up to date")
        return 0

    # Generate mode
    try:
        content = generate_file()
    except subprocess.CalledProcessError as e:
        print(f"Error running yq: {e.stderr}", file=sys.stderr)
        return 1

    OUTPUT_FILE.write_text(content)
    print(f"Generated {OUTPUT_FILE}")

    # Also generate standalone version
    standalone_content = generate_standalone()
    STANDALONE_OUTPUT.write_text(standalone_content)
    STANDALONE_OUTPUT.chmod(0o755)  # Make executable
    print(f"Generated {STANDALONE_OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
