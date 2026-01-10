#!/usr/bin/env bun
// secrets-filter: Filter stdin for secrets, redact with labels
// Streaming mode with state machine for private keys
// Binary detection triggers passthrough
//
// Filter modes:
//   --filter=values    - redact known secret values from environment
//   --filter=patterns  - redact regex patterns (token formats)
//   --filter=all       - all filters (values + patterns + entropy)
//
// Environment variables (override with --filter):
//   SECRETS_FILTER_VALUES=0|false|no    - disable values filter
//   SECRETS_FILTER_PATTERNS=0|false|no  - disable patterns filter

import { dirname, join } from 'path';

// Auto-regenerate patterns if missing or outdated (must complete before dynamic import)
const scriptDir = dirname(Bun.main);
const repoRoot = join(scriptDir, '..');
const patternsGenPath = join(scriptDir, 'patterns_gen.ts');
const yamlSources = [
  join(repoRoot, 'patterns/patterns.yaml'),
  join(repoRoot, 'patterns/env.yaml'),
  join(repoRoot, 'patterns/entropy.yaml'),
];

// Check if regeneration is needed: missing or older than any source YAML
async function needsRegeneration(): Promise<boolean> {
  const genFile = Bun.file(patternsGenPath);
  if (!(await genFile.exists())) return true;

  const genMtime = genFile.lastModified;
  for (const yamlPath of yamlSources) {
    const yamlFile = Bun.file(yamlPath);
    if (await yamlFile.exists()) {
      if (yamlFile.lastModified > genMtime) return true;
    }
  }
  return false;
}

if (await needsRegeneration()) {
  const proc = Bun.spawn(['bun', join(scriptDir, 'generate.ts')], {
    stdout: 'inherit',
    stderr: 'inherit',
  });
  await proc.exited;
}

// Dynamic import to allow regeneration to complete first
const {
  PATTERNS,
  CONTEXT_PATTERNS,
  SPECIAL_PATTERNS,
  PRIVATE_KEY_BEGIN,
  PRIVATE_KEY_END,
  EXPLICIT_ENV_VARS,
  ENV_SUFFIXES,
  LONG_THRESHOLD,
  MAX_PRIVATE_KEY_BUFFER,
  ENTROPY_ENABLED_DEFAULT,
  ENTROPY_THRESHOLDS,
  ENTROPY_MIN_LENGTH,
  ENTROPY_MAX_LENGTH,
  ENTROPY_EXCLUSIONS,
  ENTROPY_CONTEXT_KEYWORDS,
} = await import('./patterns_gen');

import type { EntropyExclusion } from './patterns_gen';

const STATE_NORMAL = 0;
const STATE_IN_PRIVATE_KEY = 1;
const STATE_IN_PRIVATE_KEY_OVERFLOW = 2;

// Valid filter names
const VALID_FILTERS = new Set(['values', 'patterns', 'entropy', 'all']);
const FALSY_VALUES = ['0', 'false', 'no'];
const TRUTHY_VALUES = ['1', 'true', 'yes'];

// Check if environment variable is enabled (truthy value)
function isEnvEnabled(name: string): boolean {
  const val = Bun.env[name];
  return val !== undefined && TRUTHY_VALUES.includes(val.toLowerCase());
}

// Parse filter configuration from CLI args and environment
function parseFilterConfig(): { values: boolean; patterns: boolean; entropy: boolean } {
  // Check CLI args first (--filter=X or -f X)
  const args = Bun.argv.slice(2);
  let cliFilters: string | null = null;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--filter=')) {
      cliFilters = arg.slice('--filter='.length);
      break;
    } else if (arg === '--filter' || arg === '-f') {
      if (i + 1 < args.length) {
        cliFilters = args[i + 1];
        break;
      }
    } else if (arg.startsWith('-f')) {
      // -fvalues style
      cliFilters = arg.slice(2);
      break;
    }
  }

  // If CLI specified, parse and use it (overrides ENV entirely)
  if (cliFilters !== null) {
    const parts = cliFilters.split(',').map(s => s.trim().toLowerCase()).filter(s => s.length > 0);
    const valid: string[] = [];
    const invalid: string[] = [];

    for (const part of parts) {
      if (VALID_FILTERS.has(part)) {
        valid.push(part);
      } else {
        invalid.push(part);
      }
    }

    // Warn about invalid filters
    for (const name of invalid) {
      console.error(`secrets-filter: unknown filter '${name}', ignoring`);
    }

    // Error if no valid filters
    if (valid.length === 0) {
      console.error('secrets-filter: no valid filters specified');
      process.exit(1);
    }

    // Determine enabled filters
    // 'all' means all filters (values + patterns + entropy)
    const hasAll = valid.includes('all');
    return {
      values: hasAll || valid.includes('values'),
      patterns: hasAll || valid.includes('patterns'),
      entropy: hasAll || valid.includes('entropy'),
    };
  }

  // No CLI args: check environment variables
  // values and patterns are enabled by default, entropy is disabled by default
  const valuesEnv = Bun.env.SECRETS_FILTER_VALUES;
  const patternsEnv = Bun.env.SECRETS_FILTER_PATTERNS;

  return {
    values: valuesEnv === undefined || !FALSY_VALUES.includes(valuesEnv.toLowerCase()),
    patterns: patternsEnv === undefined || !FALSY_VALUES.includes(patternsEnv.toLowerCase()),
    entropy: ENTROPY_ENABLED_DEFAULT || isEnvEnabled('SECRETS_FILTER_ENTROPY'),
  };
}

// Parse config at startup
const filterConfig = parseFilterConfig();

// Classify a segment: N=digits, A=letters, X=mixed
function classifySegment(s) {
  if (!s || s.length === 0) return '';
  if (/^\d+$/.test(s)) return `${s.length}N`;
  if (/^[A-Za-z]+$/.test(s)) return `${s.length}A`;
  return `${s.length}X`;
}

// Describe token structure for redaction label
function describeStructure(s) {
  if (!s) return '';

  // Very long tokens: show length (with prefix hint if available)
  if (s.length >= LONG_THRESHOLD) {
    for (const sep of ['-', '_', '.']) {
      if (s.includes(sep)) {
        const parts = s.split(sep);
        const first = parts[0];
        if (/^[a-zA-Z]+$/.test(first) || ['ghp', 'gho', 'ghs', 'ghr', 'npm', 'sk'].includes(first)) {
          return `${first}${sep}...:${s.length}chars`;
        }
      }
    }
    return `${s.length}chars`;
  }

  // Check for structured tokens
  for (const sep of ['-', '.', '_']) {
    if (s.includes(sep)) {
      const parts = s.split(sep);
      if (parts.length >= 2) {
        const first = parts[0];
        if (/^[A-Za-z]+$/.test(first) && first.length <= 12) {
          const segments = parts.slice(1).map(classifySegment);
          return `${first}${sep}${segments.join(sep)}`;
        }
        return parts.map(classifySegment).join(sep);
      }
    }
  }

  return classifySegment(s);
}

// Load secrets from environment variables
function loadSecrets() {
  const secrets = new Map();

  const env = Bun.env;
  for (const [name, value] of Object.entries(env)) {
    if (!value || value.length < 8) continue;

    if (EXPLICIT_ENV_VARS.has(name) || ENV_SUFFIXES.some(s => name.endsWith(s))) {
      secrets.set(name, value);
    }
  }

  return secrets;
}

// Replace known secret values with [REDACTED:VAR_NAME:structure]
function redactEnvValues(text, secrets) {
  if (secrets.size === 0) return text;

  // Sort by value length descending
  const sorted = [...secrets.entries()].sort((a, b) => b[1].length - a[1].length);

  for (const [varName, val] of sorted) {
    if (!val) continue;
    const structure = describeStructure(val);
    const replacement = `[REDACTED:${varName}:${structure}]`;
    text = text.replaceAll(val, replacement);
  }

  return text;
}

// Replace known token patterns
function redactPatterns(text) {
  // Direct patterns (tokens with distinctive prefixes)
  for (const [pattern, label] of PATTERNS) {
    // Reset regex lastIndex for global patterns
    pattern.lastIndex = 0;
    text = text.replace(pattern, (matched) => {
      const structure = describeStructure(matched);
      return `[REDACTED:${label}:${structure}]`;
    });
  }

  // Context patterns (lookbehind patterns for key=value, key: value, etc.)
  for (const [pattern, label] of CONTEXT_PATTERNS) {
    pattern.lastIndex = 0;
    text = text.replace(pattern, (matched) => {
      const structure = describeStructure(matched);
      return `[REDACTED:${label}:${structure}]`;
    });
  }

  // Special patterns (capture group patterns requiring custom replacement)
  for (const sp of Object.values(SPECIAL_PATTERNS)) {
    sp.pattern.lastIndex = 0;
    text = text.replace(sp.pattern, (...args) => {
      // args: [fullMatch, group1, group2, ..., offset, string]
      const secret = args[sp.secretGroup];
      const structure = describeStructure(secret);
      // Reconstruct with all groups, replacing only the secret group
      const groups = args.slice(1, -2); // exclude offset and string
      groups[sp.secretGroup - 1] = `[REDACTED:${sp.label}:${structure}]`;
      return groups.join('');
    });
  }

  return text;
}

// ============================================================================
// Entropy-based detection
// ============================================================================

// Character sets for classification
const CHARSET_HEX = new Set('0123456789abcdef');
const CHARSET_BASE64 = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=');
const CHARSET_ALNUM = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-');

// Token extraction regex: split on delimiters
const TOKEN_DELIM_RE = /[\s"'`()\[\]{},:;<>=@#]+/;

// Precompile exclusion patterns
const EXCLUSION_PATTERNS: { regex: RegExp; label: string; contextKeywords: string[] | null }[] = [];
for (const excl of ENTROPY_EXCLUSIONS) {
  const flags = excl.caseInsensitive ? 'i' : '';
  EXCLUSION_PATTERNS.push({
    regex: new RegExp(`^${excl.pattern}$`, flags),
    label: excl.label,
    contextKeywords: excl.contextKeywords,
  });
}

interface EntropyConfig {
  thresholds: Record<string, number>;
  minLength: number;
  maxLength: number;
}

interface Token {
  text: string;
  start: number;
  end: number;
}

// Check if string is all alphabetic
function isAlpha(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (!((c >= 65 && c <= 90) || (c >= 97 && c <= 122))) {
      return false;
    }
  }
  return true;
}

// Check if string is all numeric
function isDigits(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 57) {
      return false;
    }
  }
  return true;
}

// Calculate Shannon entropy of a string in bits
// H = -Σ p(x) log₂ p(x)
function shannonEntropy(s: string): number {
  if (!s) return 0.0;

  const counts = new Map<string, number>();
  for (const c of s) {
    counts.set(c, (counts.get(c) || 0) + 1);
  }

  const length = s.length;
  let entropy = 0.0;
  for (const count of counts.values()) {
    const p = count / length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Classify a string's character set
// Returns: 'hex', 'base64', 'alphanumeric', or 'mixed'
function classifyCharset(s: string): string {
  const lowerChars = new Set(s.toLowerCase());

  // Check hex first (most restrictive)
  let isHex = true;
  for (const c of lowerChars) {
    if (!CHARSET_HEX.has(c)) {
      isHex = false;
      break;
    }
  }
  if (isHex) return 'hex';

  // Check alphanumeric (common for tokens)
  const upperChars = new Set(s);
  let isAlnum = true;
  for (const c of upperChars) {
    if (!CHARSET_ALNUM.has(c)) {
      isAlnum = false;
      break;
    }
  }
  if (isAlnum) return 'alphanumeric';

  // Check base64
  let isBase64 = true;
  for (const c of upperChars) {
    if (!CHARSET_BASE64.has(c)) {
      isBase64 = false;
      break;
    }
  }
  if (isBase64) return 'base64';

  return 'mixed';
}

// Extract potential secret tokens from text
function extractTokens(text: string, minLen: number, maxLen: number): Token[] {
  const tokens: Token[] = [];
  const parts = text.split(TOKEN_DELIM_RE);

  let pos = 0;
  for (const part of parts) {
    if (part) {
      const start = text.indexOf(part, pos);
      const end = start + part.length;
      pos = end;

      // Filter by length
      if (part.length < minLen || part.length > maxLen) continue;

      // Skip if all alphabetic (variable names)
      if (isAlpha(part)) continue;

      // Skip if all numeric (IDs, line numbers)
      if (isDigits(part)) continue;

      tokens.push({ text: part, start, end });
    }
  }

  return tokens;
}

// Check if a position in text is preceded by a context keyword
// Looks back up to 50 characters for any of the keywords
function hasContextKeyword(text: string, pos: number, keywords: string[] | null): boolean {
  if (!keywords || keywords.length === 0) return false;

  const start = Math.max(0, pos - 50);
  const prefix = text.slice(start, pos).toLowerCase();

  for (const kw of keywords) {
    if (prefix.includes(kw.toLowerCase())) {
      return true;
    }
  }
  return false;
}

// Check if token matches an exclusion pattern
// Returns: label if excluded, null otherwise
function matchesExclusion(token: string, text: string, pos: number): string | null {
  for (const excl of EXCLUSION_PATTERNS) {
    if (excl.regex.test(token)) {
      // Check context keywords if present
      if (excl.contextKeywords) {
        if (hasContextKeyword(text, pos, excl.contextKeywords)) {
          return excl.label;
        }
        // Has context keywords but none found - not excluded
        continue;
      }
      // No context keywords required - excluded
      return excl.label;
    }
  }

  // Check global context keywords
  const globalKeywords = Array.from(ENTROPY_CONTEXT_KEYWORDS);
  if (hasContextKeyword(text, pos, globalKeywords)) {
    return 'CONTEXT';
  }

  return null;
}

// Create structure description for entropy redaction
// Example: hex:40:3.8
function describeEntropyStructure(token: string, entropy: number, charset: string): string {
  const charsetAbbrev: Record<string, string> = {
    'hex': 'hex',
    'base64': 'b64',
    'alphanumeric': 'alnum',
    'mixed': 'mix',
  };
  return `${charsetAbbrev[charset] || charset}:${token.length}:${entropy.toFixed(1)}`;
}

// Get entropy configuration from environment overrides or defaults
function getEntropyConfig(): EntropyConfig {
  const config: EntropyConfig = {
    thresholds: { ...ENTROPY_THRESHOLDS },
    minLength: ENTROPY_MIN_LENGTH,
    maxLength: ENTROPY_MAX_LENGTH,
  };

  // Check for global threshold override
  const globalThreshold = Bun.env.SECRETS_FILTER_ENTROPY_THRESHOLD;
  if (globalThreshold) {
    const t = parseFloat(globalThreshold);
    if (!isNaN(t)) {
      config.thresholds = { hex: t, base64: t, alphanumeric: t };
    }
  }

  // Check for per-charset overrides
  for (const charset of ['hex', 'base64']) {
    const envName = `SECRETS_FILTER_ENTROPY_${charset.toUpperCase()}`;
    const val = Bun.env[envName];
    if (val) {
      const t = parseFloat(val);
      if (!isNaN(t)) {
        config.thresholds[charset] = t;
      }
    }
  }

  // Length overrides
  const minLen = Bun.env.SECRETS_FILTER_ENTROPY_MIN_LEN;
  if (minLen) {
    const n = parseInt(minLen, 10);
    if (!isNaN(n)) config.minLength = n;
  }

  const maxLen = Bun.env.SECRETS_FILTER_ENTROPY_MAX_LEN;
  if (maxLen) {
    const n = parseInt(maxLen, 10);
    if (!isNaN(n)) config.maxLength = n;
  }

  return config;
}

// Detect and redact high-entropy strings
function redactEntropy(text: string, config: EntropyConfig): string {
  const { thresholds, minLength, maxLength } = config;

  const tokens = extractTokens(text, minLength, maxLength);

  // Process in reverse order to preserve positions when replacing
  const replacements: [number, number, string][] = [];
  for (let i = tokens.length - 1; i >= 0; i--) {
    const { text: token, start, end } = tokens[i];

    // Check exclusions
    const excluded = matchesExclusion(token, text, start);
    if (excluded) continue;

    // Classify character set and get threshold
    const charset = classifyCharset(token);
    let threshold: number;
    if (charset === 'mixed') {
      // Mixed character sets are harder to classify - use alphanumeric threshold
      threshold = thresholds['alphanumeric'] ?? 4.5;
    } else {
      threshold = thresholds[charset] ?? 4.5;
    }

    // Calculate entropy
    const entropy = shannonEntropy(token);

    if (entropy >= threshold) {
      const structure = describeEntropyStructure(token, entropy, charset);
      const replacement = `[REDACTED:HIGH_ENTROPY:${structure}]`;
      replacements.push([start, end, replacement]);
    }
  }

  // Apply replacements in reverse order
  for (const [start, end, replacement] of replacements) {
    text = text.slice(0, start) + replacement + text.slice(end);
  }

  return text;
}

// Redact a single line
function redactLine(line: string, secrets: Map<string, string>, entropyEnabled: boolean, entropyConfig: EntropyConfig | null): string {
  if (filterConfig.values) {
    line = redactEnvValues(line, secrets);
  }
  if (filterConfig.patterns) {
    line = redactPatterns(line);
  }
  if (entropyEnabled && entropyConfig) {
    line = redactEntropy(line, entropyConfig);
  }
  return line;
}

// Flush buffer with redaction
function flushBufferRedacted(buffer: string[], secrets: Map<string, string>, writer: ReturnType<typeof Bun.stdout.writer>, entropyEnabled: boolean, entropyConfig: EntropyConfig | null) {
  for (const line of buffer) {
    writer.write(redactLine(line, secrets, entropyEnabled, entropyConfig));
  }
}

// Main processing loop
// Returns true if binary detected (caller should switch to raw passthrough)
async function processChunks(
  stdinStream: ReadableStream<Uint8Array>,
  writer: ReturnType<typeof Bun.stdout.writer>,
  secrets: Map<string, string>,
  entropyEnabled: boolean,
  entropyConfig: EntropyConfig | null
): Promise<{ binary: boolean; reader: ReadableStreamDefaultReader<Uint8Array> | null }> {
  const decoder = new TextDecoder();
  let textBuffer = '';
  let state = STATE_NORMAL;
  let lineBuffer: string[] = [];

  const reader = stdinStream.getReader();

  while (true) {
    const { done, value: chunk } = await reader.read();
    if (done) break;

    // Binary detection: check for null byte in raw chunk
    if (chunk.includes(0)) {
      // Flush any buffered text content first
      if (textBuffer.length > 0) {
        writer.write(redactLine(textBuffer, secrets, entropyEnabled, entropyConfig));
      }
      flushBufferRedacted(lineBuffer, secrets, writer, entropyEnabled, entropyConfig);
      // Write current chunk as-is (contains binary)
      writer.write(chunk);
      // Return reader for raw passthrough of remaining data
      return { binary: true, reader };
    }

    // Decode chunk and process lines
    textBuffer += decoder.decode(chunk, { stream: true });
    const lines = textBuffer.split('\n');
    textBuffer = lines.pop() || '';

    for (const lineContent of lines) {
      const line = lineContent + '\n';

      // Private key state machine only active when patterns filter is enabled
      if (state === STATE_NORMAL) {
        if (filterConfig.patterns && PRIVATE_KEY_BEGIN.test(line)) {
          state = STATE_IN_PRIVATE_KEY;
          lineBuffer = [line];
        } else {
          writer.write(redactLine(line, secrets, entropyEnabled, entropyConfig));
        }
      } else if (state === STATE_IN_PRIVATE_KEY) {
        lineBuffer.push(line);

        if (PRIVATE_KEY_END.test(line)) {
          writer.write('[REDACTED:PRIVATE_KEY:multiline]\n');
          lineBuffer = [];
          state = STATE_NORMAL;
        } else if (lineBuffer.length > MAX_PRIVATE_KEY_BUFFER) {
          // Buffer overflow - redact entirely (fail closed, don't leak)
          writer.write('[REDACTED:PRIVATE_KEY:multiline]\n');
          lineBuffer = [];
          // Transition to overflow state - consume remaining lines silently until END
          state = STATE_IN_PRIVATE_KEY_OVERFLOW;
        }
      } else if (state === STATE_IN_PRIVATE_KEY_OVERFLOW) {
        // Consume lines silently until END marker
        if (PRIVATE_KEY_END.test(line)) {
          state = STATE_NORMAL;
        }
        // No buffering, no output - just wait for END
      }
    }
  }

  // EOF: handle remaining content
  if (textBuffer.length > 0) {
    if (state === STATE_IN_PRIVATE_KEY) {
      lineBuffer.push(textBuffer);
    } else if (state !== STATE_IN_PRIVATE_KEY_OVERFLOW) {
      writer.write(redactLine(textBuffer, secrets, entropyEnabled, entropyConfig));
    }
  }
  // EOF: handle remaining state
  if (state === STATE_IN_PRIVATE_KEY) {
    // Incomplete private key block - redact entirely (fail closed, don't leak)
    writer.write("[REDACTED:PRIVATE_KEY:multiline]\n");
  } else if (state === STATE_IN_PRIVATE_KEY_OVERFLOW) {
    // Already emitted overflow redaction, nothing to do
  } else if (lineBuffer.length > 0) {
    // Flush any remaining buffered content
    flushBufferRedacted(lineBuffer, secrets, writer, entropyEnabled, entropyConfig);
  }

  return { binary: false, reader: null };
}

// Main
async function main() {
  // Only load secrets if values filter is enabled
  const secrets = filterConfig.values ? loadSecrets() : new Map();

  // Load entropy config only if entropy filter is enabled
  const entropyEnabled = filterConfig.entropy;
  const entropyConfig = entropyEnabled ? getEntropyConfig() : null;

  const writer = Bun.stdout.writer();
  const stdinStream = Bun.stdin.stream();

  const result = await processChunks(stdinStream, writer, secrets, entropyEnabled, entropyConfig);

  // If binary detected, passthrough remaining raw bytes
  if (result.binary && result.reader) {
    while (true) {
      const { done, value } = await result.reader.read();
      if (done) break;
      writer.write(value);
    }
  }

  await writer.flush();
}

await main();
