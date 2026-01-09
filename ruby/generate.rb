#!/usr/bin/env ruby
# frozen_string_literal: true

# Generate patterns_gen.rb from YAML pattern definitions
# Usage: ruby generate.rb
#
# Reads:
#   patterns/patterns.yaml - Token patterns (direct, context, special)
#   patterns/env.yaml      - Environment variable detection rules
#
# Writes:
#   ruby/patterns_gen.rb   - Generated Ruby module with pattern definitions

require 'yaml'
require 'digest'
require 'time'

SCRIPT_DIR = File.dirname(File.expand_path(__FILE__))
REPO_ROOT = File.dirname(SCRIPT_DIR)

PATTERNS_FILE = File.join(REPO_ROOT, 'patterns', 'patterns.yaml')
ENV_FILE = File.join(REPO_ROOT, 'patterns', 'env.yaml')
OUTPUT_FILE = File.join(SCRIPT_DIR, 'patterns_gen.rb')

def compute_file_hash(path)
  Digest::SHA256.file(path).hexdigest[0, 12]
end

# Format a pattern as Ruby regex literal
# Uses %r{} if pattern contains /, otherwise /pattern/
def format_regex(pattern)
  if pattern.include?('/')
    # Use %r{} delimiter to avoid escaping slashes
    "%r{#{pattern}}"
  else
    "/#{pattern}/"
  end
end

def generate_patterns_module
  patterns_yaml = YAML.safe_load(File.read(PATTERNS_FILE), permitted_classes: [Symbol])
  env_yaml = YAML.safe_load(File.read(ENV_FILE), permitted_classes: [Symbol])

  patterns_hash = compute_file_hash(PATTERNS_FILE)
  env_hash = compute_file_hash(ENV_FILE)
  timestamp = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')

  # Extract data from patterns.yaml
  constants = patterns_yaml['constants'] || {}
  long_threshold = constants['long_threshold'] || 50
  max_private_key_buffer = constants['max_private_key_buffer'] || 100

  direct_patterns = patterns_yaml['patterns'] || []
  context_patterns = patterns_yaml['context_patterns'] || []
  special_patterns = patterns_yaml['special_patterns'] || {}
  private_key = patterns_yaml['private_key'] || {}

  # Extract data from env.yaml
  explicit_vars = env_yaml['explicit'] || []
  suffixes = env_yaml['suffixes'] || []

  # Build the output
  lines = []

  lines << '# frozen_string_literal: true'
  lines << ''
  lines << '# AUTO-GENERATED FILE - DO NOT EDIT'
  lines << "# Generated: #{timestamp}"
  lines << "# Source: patterns/patterns.yaml (#{patterns_hash})"
  lines << "#         patterns/env.yaml (#{env_hash})"
  lines << '# Regenerate with: ruby ruby/generate.rb'
  lines << ''
  lines << 'module PatternsGen'
  lines << '  # Constants'
  lines << "  LONG_THRESHOLD = #{long_threshold}"
  lines << "  MAX_PRIVATE_KEY_BUFFER = #{max_private_key_buffer}"
  lines << ''

  # Private key markers
  private_key_begin = private_key['begin'] || '-----BEGIN [A-Z ]*PRIVATE KEY-----'
  private_key_end = private_key['end'] || '-----END [A-Z ]*PRIVATE KEY-----'
  lines << '  # Private key markers (for streaming state machine)'
  lines << "  PRIVATE_KEY_BEGIN = /#{private_key_begin}/"
  lines << "  PRIVATE_KEY_END = /#{private_key_end}/"
  lines << ''

  # Direct patterns array
  lines << '  # Direct patterns: [regex, label]'
  lines << '  # Order: more specific patterns first'
  lines << '  PATTERNS = ['

  direct_patterns.each do |entry|
    pattern = entry['pattern']
    label = entry['label']
    multiline = entry['multiline']

    # Skip multiline patterns in direct array - they're handled separately
    next if multiline

    lines << "    [#{format_regex(pattern)}, '#{label}'],"
  end

  lines << '  ].freeze'
  lines << ''

  # Context patterns array (using lookbehind)
  lines << '  # Context patterns: [regex_with_lookbehind, label]'
  lines << '  # Ruby supports lookbehind: (?<=prefix)value'
  lines << '  CONTEXT_PATTERNS = ['

  context_patterns.each do |entry|
    prefix = entry['prefix']
    value = entry['value']
    label = entry['label']

    # Escape the prefix for use in lookbehind
    escaped_prefix = Regexp.escape(prefix)
    lookbehind_pattern = "(?<=#{escaped_prefix})#{value}"

    lines << "    [#{format_regex(lookbehind_pattern)}, '#{label}'],"
  end

  lines << '  ].freeze'
  lines << ''

  # Special patterns hash
  lines << '  # Special patterns with capture groups'
  lines << '  # Each entry: { pattern: regex, label: string, secret_group: integer }'
  lines << '  SPECIAL_PATTERNS = {'

  special_patterns.each do |name, entry|
    pattern = entry['pattern']
    label = entry['label']
    secret_group = entry['secret_group']

    lines << "    #{name}: {"
    lines << "      pattern: #{format_regex(pattern)},"
    lines << "      label: '#{label}',"
    lines << "      secret_group: #{secret_group}"
    lines << '    },'
  end

  lines << '  }.freeze'
  lines << ''

  # Multiline private key pattern (for batch mode fallback)
  multiline_entry = direct_patterns.find { |e| e['multiline'] }
  if multiline_entry
    lines << '  # Private key pattern (multiline, for batch mode fallback)'
    lines << "  PRIVATE_KEY_PATTERN = #{format_regex(multiline_entry['pattern'])}"
    lines << ''
  end

  # Environment variable detection
  lines << '  # Explicit secret variable names'
  lines << '  EXPLICIT_ENV_VARS = Set.new(%w['

  # Format as multiple lines for readability
  explicit_vars.each_slice(5) do |chunk|
    lines << "    #{chunk.join(' ')}"
  end

  lines << '  ]).freeze'
  lines << ''

  lines << '  # Suffixes indicating secret variables'
  lines << '  ENV_SUFFIXES = %w['
  lines << "    #{suffixes.join(' ')}"
  lines << '  ].freeze'

  lines << 'end'
  lines << ''

  lines.join("\n")
end

def main
  # Check input files exist
  unless File.exist?(PATTERNS_FILE)
    warn "Error: #{PATTERNS_FILE} not found"
    exit 1
  end

  unless File.exist?(ENV_FILE)
    warn "Error: #{ENV_FILE} not found"
    exit 1
  end

  content = generate_patterns_module

  File.write(OUTPUT_FILE, content)
  puts "Generated #{OUTPUT_FILE}"
end

main if __FILE__ == $PROGRAM_NAME
