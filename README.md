# kahl

Streaming filter that redacts secrets from stdin before they appear in conversation history.

## How It Works

Two-layer detection:
1. **Env-based**: Known secret env vars (explicit names + suffix patterns like `*_TOKEN`, `*_SECRET`)
2. **Pattern-based**: Known token formats (GitHub, Slack, AWS, OpenAI, etc.)

## Streaming Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    STATE_NORMAL                          │
│  - Redact line immediately, flush to stdout             │
└────────────────────────┬────────────────────────────────┘
                         │ See "-----BEGIN.*PRIVATE KEY-----"
                         ▼
┌─────────────────────────────────────────────────────────┐
│                STATE_IN_PRIVATE_KEY                      │
│  - Buffer lines (max 100)                               │
│  - On END marker → emit [REDACTED:PRIVATE_KEY:multiline]│
│  - On buffer overflow → flush each line redacted        │
└─────────────────────────────────────────────────────────┘
```

## Binary Handling

Null byte (`\x00`) in input triggers passthrough mode—binary data passes through unchanged to avoid corruption.

## Redaction Format

Structure-preserving labels:
```
[REDACTED:SLACK_BOT:xoxb-9N-9N-12X]       # structured: prefix + segments
[REDACTED:GITHUB_PAT:ghp_36X]             # simple: prefix + length
[REDACTED:ANTHROPIC_KEY:sk-...:105chars]  # long: prefix hint + length
[REDACTED:PRIVATE_KEY:multiline]          # private key blocks
```

## Known Limitations

- **Backgrounded commands**: Wrapped as `( cmd | filter ) &` to maintain filtering
- **Stdout redirections**: `cmd > file` writes to file, filter sees nothing (by design—secret not in conversation)
- **stderr**: Filtered via wrapper (same process substitution as stdout)

## Testing

```bash
cd tests && ./test.sh -q           # Run all tests (7 implementations × 78 tests)
cd tests && ./test.sh -q python    # Run tests for specific implementation
```
