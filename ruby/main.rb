#!/usr/bin/env ruby
# frozen_string_literal: true

# Filter stdin: env lookup (precise labels) + pattern detection (catch-all).
# Streaming mode: processes line-by-line with immediate flush.
# State machine handles multiline private key blocks.
# Binary detection triggers passthrough.
#
# Filter modes:
#   --filter=X or -f X (comma-separated: values, patterns, entropy, all)
#   SECRETS_FILTER_VALUES=0/false/no to disable values filter
#   SECRETS_FILTER_PATTERNS=0/false/no to disable patterns filter
#   SECRETS_FILTER_ENTROPY=1/true/yes to enable entropy filter (off by default)
#   Default: values + patterns enabled, entropy disabled
#
# Entropy filter options:
#   SECRETS_FILTER_ENTROPY_THRESHOLD=N - override all thresholds
#   SECRETS_FILTER_ENTROPY_HEX=N - hex-specific threshold
#   SECRETS_FILTER_ENTROPY_BASE64=N - base64-specific threshold
#   SECRETS_FILTER_ENTROPY_MIN_LEN=N - minimum length
#   SECRETS_FILTER_ENTROPY_MAX_LEN=N - maximum length

# Auto-regenerate patterns if missing
script_dir = File.dirname(File.realpath(__FILE__))
patterns_gen = File.join(script_dir, 'patterns_gen.rb')
unless File.exist?(patterns_gen)
  system('ruby', File.join(script_dir, 'generate.rb')) or raise 'Failed to generate patterns'
end
require_relative 'patterns_gen'

# Auto-flush stdout
$stdout.sync = true

# Check if env value is falsy
def env_falsy?(val)
  return false if val.nil?

  %w[0 false no].include?(val.downcase.strip)
end

# Check if env value is truthy
def env_enabled?(val)
  return false if val.nil?

  %w[1 true yes].include?(val.downcase.strip)
end

# Valid filter names
VALID_FILTERS = %w[values patterns entropy all].freeze

# Parse filter configuration from CLI args and environment
def parse_filters
  values_enabled = true
  patterns_enabled = true
  entropy_enabled = PatternsGen::ENTROPY_ENABLED_DEFAULT

  # Check for CLI --filter= or -f option
  cli_filter = nil
  i = 0
  while i < ARGV.length
    arg = ARGV[i]
    if arg.start_with?('--filter=')
      cli_filter = arg.sub('--filter=', '')
      break
    elsif arg == '-f' && i + 1 < ARGV.length
      cli_filter = ARGV[i + 1]
      break
    elsif arg == '--filter' && i + 1 < ARGV.length
      cli_filter = ARGV[i + 1]
      break
    end
    i += 1
  end

  if cli_filter
    # CLI overrides ENV entirely
    filters = cli_filter.split(',').map { |f| f.strip.downcase }
    valid_filters = []
    invalid_filters = []

    filters.each do |f|
      if VALID_FILTERS.include?(f)
        valid_filters << f
      else
        invalid_filters << f
      end
    end

    # Warn about invalid filters
    invalid_filters.each do |f|
      warn "secrets-filter: unknown filter '#{f}', ignoring"
    end

    if valid_filters.empty?
      warn 'secrets-filter: no valid filters specified'
      exit 1
    end

    # Determine enabled filters
    # 'all' expands to all filters (values + patterns + entropy)
    if valid_filters.include?('all')
      values_enabled = true
      patterns_enabled = true
      entropy_enabled = true
    else
      values_enabled = valid_filters.include?('values')
      patterns_enabled = valid_filters.include?('patterns')
      entropy_enabled = valid_filters.include?('entropy')
    end
  else
    # Use ENV variables
    # values and patterns are enabled by default, entropy is disabled by default
    if ENV.key?('SECRETS_FILTER_VALUES')
      values_enabled = !env_falsy?(ENV['SECRETS_FILTER_VALUES'])
    end
    if ENV.key?('SECRETS_FILTER_PATTERNS')
      patterns_enabled = !env_falsy?(ENV['SECRETS_FILTER_PATTERNS'])
    end
    entropy_enabled = PatternsGen::ENTROPY_ENABLED_DEFAULT || env_enabled?(ENV['SECRETS_FILTER_ENTROPY'])
  end

  { values: values_enabled, patterns: patterns_enabled, entropy: entropy_enabled }
end

# Constants from generated patterns
STATE_NORMAL = 0
STATE_IN_PRIVATE_KEY = 1
STATE_IN_PRIVATE_KEY_OVERFLOW = 2
MAX_PRIVATE_KEY_BUFFER = PatternsGen::MAX_PRIVATE_KEY_BUFFER
LONG_THRESHOLD = PatternsGen::LONG_THRESHOLD

# Private key markers from generated patterns
PRIVATE_KEY_BEGIN = PatternsGen::PRIVATE_KEY_BEGIN
PRIVATE_KEY_END = PatternsGen::PRIVATE_KEY_END

# Combined patterns: direct + context + private key (for batch mode fallback)
PATTERNS = (
  PatternsGen::PATTERNS +
  PatternsGen::CONTEXT_PATTERNS +
  [[PatternsGen::PRIVATE_KEY_PATTERN, 'PRIVATE_KEY']]
).freeze

# Classify a segment: N=digits, A=letters, X=mixed
def classify_segment(s)
  return '' if s.nil? || s.empty?
  return "#{s.length}N" if s.match?(DIGITS_ONLY_RE)
  return "#{s.length}A" if s.match?(LETTERS_ONLY_RE)

  "#{s.length}X"
end

# Known prefix patterns for token detection
KNOWN_PREFIXES = Set.new(%w[ghp gho ghs ghr npm sk]).freeze

# Describe token structure for redaction label
def describe_structure(s)
  return '' if s.nil?

  # Very long tokens: show length (with prefix hint if available)
  if s.length >= LONG_THRESHOLD
    ['-', '_', '.'].each do |sep|
      next unless s.include?(sep)

      parts = s.split(sep)
      first = parts[0]
      if first.match?(LETTERS_ONLY_RE) || KNOWN_PREFIXES.include?(first)
        return "#{first}#{sep}...:#{s.length}chars"
      end
    end
    return "#{s.length}chars"
  end

  # Check for structured tokens
  ['-', '.', '_'].each do |sep|
    next unless s.include?(sep)

    parts = s.split(sep)
    next unless parts.length >= 2

    first = parts[0]
    if first.match?(LETTERS_ONLY_RE) && first.length <= 12
      segments = parts[1..].map { |p| classify_segment(p) }
      return "#{first}#{sep}#{segments.join(sep)}"
    end
    segments = parts.map { |p| classify_segment(p) }
    return segments.join(sep)
  end

  classify_segment(s)
end

# Known secret env var names from generated patterns
EXPLICIT_SECRET_VARS = PatternsGen::EXPLICIT_ENV_VARS

# Suffixes that indicate a secret env var from generated patterns
SECRET_SUFFIXES = PatternsGen::ENV_SUFFIXES

# Load secrets from environment variables
def load_secrets
  secrets = {}

  ENV.each do |name, value|
    next if value.nil? || value.length < 8

    is_explicit = EXPLICIT_SECRET_VARS.include?(name)
    is_pattern = SECRET_SUFFIXES.any? { |suffix| name.end_with?(suffix) }

    secrets[name] = value if is_explicit || is_pattern
  end

  secrets
end

# Build combined regex pattern for env values
# Returns [combined_pattern, value_to_info_hash] or [nil, nil] if no secrets
def build_env_pattern(secrets)
  return [nil, nil] if secrets.empty?

  # Sort by value length descending to match longer values first
  sorted = secrets.sort_by { |_, v| -v.length }

  # Build hash: escaped_value -> [var_name, structure]
  value_info = {}
  patterns = []

  sorted.each do |var, val|
    next if val.nil? || val.empty?

    escaped = Regexp.escape(val)
    patterns << escaped
    value_info[val] = [var, describe_structure(val)]
  end

  return [nil, nil] if patterns.empty?

  # Build combined pattern with alternation
  combined = Regexp.new(patterns.join('|'))
  [combined, value_info]
end

# Replace known secret values with [REDACTED:VAR_NAME:structure]
def redact_env_values(text, secrets, env_pattern = nil, value_info = nil)
  # Use combined pattern if provided
  if env_pattern && value_info
    return text.gsub(env_pattern) do |matched|
      info = value_info[matched]
      if info
        var, structure = info
        "[REDACTED:#{var}:#{structure}]"
      else
        matched  # Shouldn't happen, but be safe
      end
    end
  end

  # Fallback: iterate over secrets (for backward compatibility)
  secrets.sort_by { |_, v| -v.length }.each do |var, val|
    next if val.nil? || val.empty?

    structure = describe_structure(val)
    replacement = "[REDACTED:#{var}:#{structure}]"
    text = text.gsub(val, replacement)
  end

  text
end

# Replace known token patterns
def redact_patterns(text)
  PATTERNS.each do |pattern, label|
    text = text.gsub(pattern) do |matched|
      structure = describe_structure(matched)
      "[REDACTED:#{label}:#{structure}]"
    end
  end

  # Special patterns with capture groups (git credentials, docker auth, etc.)
  PatternsGen::SPECIAL_PATTERNS.each_value do |spec|
    text = text.gsub(spec[:pattern]) do
      secret_group = spec[:secret_group]
      secret_value = ::Regexp.last_match(secret_group)
      structure = describe_structure(secret_value)

      # Reconstruct with redacted secret
      parts = []
      (1..::Regexp.last_match.size - 1).each do |i|
        if i == secret_group
          parts << "[REDACTED:#{spec[:label]}:#{structure}]"
        else
          parts << ::Regexp.last_match(i)
        end
      end
      parts.join
    end
  end

  text
end

# ============================================================================
# Entropy-based detection
# ============================================================================

# Precompiled patterns for classify_segment
DIGITS_ONLY_RE = /\A\d+\z/
LETTERS_ONLY_RE = /\A[A-Za-z]+\z/

# Precompiled patterns for classify_charset
HEX_RE = /\A[0-9a-fA-F]+\z/
ALNUM_EXTENDED_RE = /\A[A-Za-z0-9_-]+\z/
BASE64_RE = /\A[A-Za-z0-9+\/=]+\z/

# Token extraction regex: split on delimiters
TOKEN_DELIM_RE = /[\s"'`()\[\]{},:;<>=@#]+/

# Calculate Shannon entropy of a string in bits
# H = -Σ p(x) log₂ p(x)
def shannon_entropy(s)
  return 0.0 if s.nil? || s.empty?

  counts = Hash.new(0)
  s.each_char { |c| counts[c] += 1 }
  length = s.length.to_f
  entropy = 0.0

  counts.each_value do |count|
    p = count / length
    entropy -= p * Math.log2(p)
  end

  entropy
end

# Classify a string's character set
# Returns: 'hex', 'base64', 'alphanumeric', or 'mixed'
def classify_charset(s)
  # Check hex first (most restrictive)
  return 'hex' if s.match?(HEX_RE)

  # Check alphanumeric (common for tokens)
  return 'alphanumeric' if s.match?(ALNUM_EXTENDED_RE)

  # Check base64
  return 'base64' if s.match?(BASE64_RE)

  'mixed'
end

# Extract potential secret tokens from text
# Returns: array of [token, start_pos, end_pos]
def extract_tokens(text, min_len, max_len)
  tokens = []
  pos = 0

  text.split(TOKEN_DELIM_RE).each do |part|
    next if part.empty?

    start = text.index(part, pos)
    next if start.nil?

    finish = start + part.length
    pos = finish

    # Filter by length
    next unless part.length >= min_len && part.length <= max_len

    # Skip if all alphabetic (variable names)
    next if part.match?(LETTERS_ONLY_RE)

    # Skip if all numeric (IDs, line numbers)
    next if part.match?(DIGITS_ONLY_RE)

    tokens << [part, start, finish]
  end

  tokens
end

# Check if a position in text is preceded by a context keyword
# Looks back up to 50 characters for any of the keywords
def has_context_keyword(text, pos, keywords)
  return false if keywords.nil? || keywords.empty?

  start = [0, pos - 50].max
  prefix = text[start...pos].downcase

  keywords.any? { |kw| prefix.include?(kw.downcase) }
end

# Check if token matches an exclusion pattern
# Returns: label if excluded, nil otherwise
def matches_exclusion(token, text, pos)
  PatternsGen::ENTROPY_EXCLUSIONS.each do |excl|
    regex = excl[:pattern]
    flags = excl[:case_insensitive] ? Regexp::IGNORECASE : 0

    # Build regex with flags if needed
    effective_regex = if excl[:case_insensitive]
                        Regexp.new(regex.source, Regexp::IGNORECASE)
                      else
                        regex
                      end

    next unless token.match?(/\A#{effective_regex.source}\z/)

    # Check context keywords if present
    context_kw = excl[:context_keywords]
    if context_kw
      return excl[:label] if has_context_keyword(text, pos, context_kw)
      # Has context keywords but none found - not excluded
      next
    end

    # No context keywords required - excluded
    return excl[:label]
  end

  # Check global context keywords
  return 'CONTEXT' if has_context_keyword(text, pos, PatternsGen::ENTROPY_CONTEXT_KEYWORDS.to_a)

  nil
end

# Create structure description for entropy redaction
# Example: hex:40:3.8
def describe_entropy_structure(token, entropy, charset)
  charset_abbrev = {
    'hex' => 'hex',
    'base64' => 'b64',
    'alphanumeric' => 'alnum',
    'mixed' => 'mix'
  }.fetch(charset, charset)

  format('%s:%d:%.1f', charset_abbrev, token.length, entropy)
end

# Get entropy configuration from environment overrides or defaults
def get_entropy_config
  config = {
    thresholds: PatternsGen::ENTROPY_THRESHOLDS.dup,
    min_length: PatternsGen::ENTROPY_MIN_LENGTH,
    max_length: PatternsGen::ENTROPY_MAX_LENGTH
  }

  # Check for global threshold override
  global_threshold = ENV['SECRETS_FILTER_ENTROPY_THRESHOLD']
  if global_threshold && !global_threshold.empty?
    begin
      t = Float(global_threshold)
      config[:thresholds] = { 'hex' => t, 'base64' => t, 'alphanumeric' => t }
    rescue ArgumentError
      # Invalid value, ignore
    end
  end

  # Check for per-charset overrides
  %w[hex base64].each do |charset|
    env_name = "SECRETS_FILTER_ENTROPY_#{charset.upcase}"
    val = ENV[env_name]
    if val && !val.empty?
      begin
        config[:thresholds][charset] = Float(val)
      rescue ArgumentError
        # Invalid value, ignore
      end
    end
  end

  # Length overrides
  min_len = ENV['SECRETS_FILTER_ENTROPY_MIN_LEN']
  if min_len && !min_len.empty?
    begin
      config[:min_length] = Integer(min_len)
    rescue ArgumentError
      # Invalid value, ignore
    end
  end

  max_len = ENV['SECRETS_FILTER_ENTROPY_MAX_LEN']
  if max_len && !max_len.empty?
    begin
      config[:max_length] = Integer(max_len)
    rescue ArgumentError
      # Invalid value, ignore
    end
  end

  config
end

# Detect and redact high-entropy strings
def redact_entropy(text, config = nil)
  config ||= get_entropy_config

  min_len = config[:min_length]
  max_len = config[:max_length]
  thresholds = config[:thresholds]

  tokens = extract_tokens(text, min_len, max_len)

  # Process in reverse order to preserve positions when replacing
  replacements = []
  tokens.reverse_each do |token, start, finish|
    # Check exclusions
    excluded = matches_exclusion(token, text, start)
    next if excluded

    # Classify character set and get threshold
    charset = classify_charset(token)
    threshold = if charset == 'mixed'
                  # Mixed character sets - use alphanumeric threshold
                  thresholds['alphanumeric'] || 4.5
                else
                  thresholds[charset] || 4.5
                end

    # Calculate entropy
    entropy = shannon_entropy(token)

    next unless entropy >= threshold

    structure = describe_entropy_structure(token, entropy, charset)
    replacement = "[REDACTED:HIGH_ENTROPY:#{structure}]"
    replacements << [start, finish, replacement]
  end

  # Apply replacements in reverse order
  replacements.each do |start, finish, replacement|
    text = text[0...start] + replacement + text[finish..]
  end

  text
end

# Redact a single line
def redact_line(line, secrets, filters, entropy_config = nil, env_pattern = nil, value_info = nil)
  line = redact_env_values(line, secrets, env_pattern, value_info) if filters[:values]
  line = redact_patterns(line) if filters[:patterns]
  line = redact_entropy(line, entropy_config) if filters[:entropy]
  line
end

# Flush buffer with redaction
def flush_buffer_redacted(buffer, secrets, filters, entropy_config = nil, env_pattern = nil, value_info = nil)
  buffer.each do |line|
    print redact_line(line, secrets, filters, entropy_config, env_pattern, value_info)
  end
end

# Main
def main
  filters = parse_filters
  secrets = filters[:values] ? load_secrets : {}
  entropy_config = filters[:entropy] ? get_entropy_config : nil

  # Build combined env pattern once at startup
  env_pattern, value_info = if filters[:values]
                              build_env_pattern(secrets)
                            else
                              [nil, nil]
                            end

  state = STATE_NORMAL
  buffer = []

  $stdin.each_line do |line|
    # Binary detection: null byte means binary data
    if line.include?("\0")
      flush_buffer_redacted(buffer, secrets, filters, entropy_config, env_pattern, value_info) unless buffer.empty?
      buffer = []
      print line
      # Passthrough rest
      $stdin.each_line { |rest| print rest }
      return
    end

    case state
    when STATE_NORMAL
      # Only use private key state machine if patterns filter is enabled
      if filters[:patterns] && line.match?(PRIVATE_KEY_BEGIN)
        state = STATE_IN_PRIVATE_KEY
        buffer = [line]
      else
        print redact_line(line, secrets, filters, entropy_config, env_pattern, value_info)
      end
    when STATE_IN_PRIVATE_KEY
      buffer << line

      if line.match?(PRIVATE_KEY_END)
        puts '[REDACTED:PRIVATE_KEY:multiline]'
        buffer = []
        state = STATE_NORMAL
      elsif buffer.length > MAX_PRIVATE_KEY_BUFFER
        # Buffer overflow - redact entirely (fail closed, don't leak)
        puts '[REDACTED:PRIVATE_KEY:multiline]'
        buffer = []
        # Transition to overflow state - consume remaining lines silently until END
        state = STATE_IN_PRIVATE_KEY_OVERFLOW
      end
    when STATE_IN_PRIVATE_KEY_OVERFLOW
      # Consume lines silently until END marker
      if line.match?(PRIVATE_KEY_END)
        state = STATE_NORMAL
      end
      # No buffering, no output - just wait for END
    end
  end

  # EOF: handle remaining state
  if state == STATE_IN_PRIVATE_KEY
    # Incomplete private key block - redact entirely (fail closed, don't leak)
    puts "[REDACTED:PRIVATE_KEY:multiline]"
  elsif state == STATE_IN_PRIVATE_KEY_OVERFLOW
    # Already emitted overflow redaction, nothing to do
  elsif !buffer.empty?
    # Flush any remaining buffered content
    flush_buffer_redacted(buffer, secrets, filters, entropy_config, env_pattern, value_info)
  end
end

main
