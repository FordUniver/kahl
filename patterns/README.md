# Pattern Definitions

This directory contains the single source of truth for all secrets-filter patterns.

## Files

- **patterns.yaml** - Token patterns for detecting secrets in text
- **env.yaml** - Rules for identifying secret environment variables

## Usage

Each language implementation has a codegen script that reads these YAML files and generates native pattern definitions:

```bash
# Generate patterns for a specific language
cd python && ./generate.py
cd perl && ./generate.pl
cd go && go run generate.go
# etc.
```

The generated files (`patterns_gen.*`) are imported by the main implementation.

## Pattern Types

### Direct Patterns (`patterns`)

Regex patterns that match secrets directly without context:

```yaml
- pattern: 'ghp_[A-Za-z0-9]{36}'
  label: GITHUB_PAT
```

### Context Patterns (`context_patterns`)

Patterns that require a prefix for context. Languages with lookbehind support use `(?<=prefix)value`, others use capture groups:

```yaml
- prefix: 'password='
  value: '[^\s,;"''\}\[\]]+'
  label: PASSWORD_VALUE
```

### Special Patterns (`special_patterns`)

Complex patterns with multiple capture groups where the secret is in a specific group:

```yaml
git_credential:
  pattern: '(://[^:]+:)([^@]+)(@)'
  label: GIT_CREDENTIAL
  secret_group: 2
```

## Adding New Patterns

1. Add the pattern to the appropriate section in `patterns.yaml`
2. Run codegen for all languages
3. Run tests to verify: `cd tests && ./test.sh -q`

## Pattern Order

Order matters for direct patterns - more specific patterns should come first to avoid partial matches.
