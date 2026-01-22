// secrets-filter: Filter stdin for secrets, redact with labels
// Build: cargo build --release
//
// Filter modes:
//   --filter=values,patterns,entropy  (CLI, comma-separated, case-insensitive)
//   SECRETS_FILTER_VALUES=0|false|no  (ENV, disables values filter)
//   SECRETS_FILTER_PATTERNS=0|false|no  (ENV, disables patterns filter)
//   SECRETS_FILTER_ENTROPY=1|true|yes  (ENV, enables entropy filter, off by default)
//
// Default: values + patterns enabled, entropy disabled. CLI overrides ENV entirely.

const VERSION: &str = include_str!("../VERSION");

mod patterns_gen;
use patterns_gen::*;

use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::env;
use std::io::{self, BufRead, Write};

#[derive(Debug, Clone, Copy)]
struct FilterConfig {
    values: bool,
    patterns: bool,
    entropy: bool,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            values: true,
            patterns: true,
            entropy: ENTROPY_ENABLED_DEFAULT,
        }
    }
}

/// Check if a string value is falsy (0, false, no)
fn is_falsy(val: &str) -> bool {
    matches!(val.to_lowercase().as_str(), "0" | "false" | "no")
}

/// Check if a string value is truthy (1, true, yes)
fn is_truthy(val: &str) -> bool {
    matches!(val.to_lowercase().as_str(), "1" | "true" | "yes")
}

/// Parse filter configuration from CLI args and environment
fn parse_filter_config() -> Result<FilterConfig, String> {
    let args: Vec<String> = env::args().collect();

    // Check for --version or -v
    for arg in &args[1..] {
        if arg == "--version" || arg == "-v" {
            print!("{}", VERSION);
            std::process::exit(0);
        }
    }

    // Check for --help or -h
    for arg in &args[1..] {
        if arg == "--help" || arg == "-h" {
            // TODO: print help text
            std::process::exit(0);
        }
    }

    // Validate all arguments - reject unknown flags
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with('-') {
            // Check if it's a known flag
            let is_known = arg == "-v"
                || arg == "--version"
                || arg == "-h"
                || arg == "--help"
                || arg == "-f"
                || arg == "--filter"
                || arg.starts_with("--filter=");

            if !is_known {
                eprintln!("Error: Unknown option: {}", arg);
                eprintln!("Try 'kahl --help' for more information.");
                std::process::exit(1);
            }

            // Skip next arg if this is -f or --filter (they take a value)
            if arg == "-f" || arg == "--filter" {
                i += 1;
            }
        }
        i += 1;
    }

    // Check for --filter=X or -f X in args
    let mut cli_filter: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i].starts_with("--filter=") {
            cli_filter = Some(args[i].strip_prefix("--filter=").unwrap().to_string());
            break;
        } else if (args[i] == "-f" || args[i] == "--filter") && i + 1 < args.len() {
            cli_filter = Some(args[i + 1].clone());
            break;
        }
        i += 1;
    }

    if let Some(filter_str) = cli_filter {
        // CLI overrides ENV entirely
        let mut values = false;
        let mut patterns = false;
        let mut entropy = false;
        let mut valid_count = 0;

        for part in filter_str.split(',') {
            let part = part.trim().to_lowercase();
            match part.as_str() {
                "values" => {
                    values = true;
                    valid_count += 1;
                }
                "patterns" => {
                    patterns = true;
                    valid_count += 1;
                }
                "entropy" => {
                    entropy = true;
                    valid_count += 1;
                }
                "all" => {
                    // 'all' means all filters
                    values = true;
                    patterns = true;
                    entropy = true;
                    valid_count += 1;
                }
                "" => {} // ignore empty parts
                unknown => {
                    eprintln!("secrets-filter: unknown filter '{}', ignoring", unknown);
                }
            }
        }

        if valid_count == 0 {
            return Err("secrets-filter: no valid filters specified".to_string());
        }

        Ok(FilterConfig {
            values,
            patterns,
            entropy,
        })
    } else {
        // Use ENV variables
        let values = env::var("SECRETS_FILTER_VALUES")
            .map(|v| !is_falsy(&v))
            .unwrap_or(true);

        let patterns = env::var("SECRETS_FILTER_PATTERNS")
            .map(|v| !is_falsy(&v))
            .unwrap_or(true);

        // Entropy is disabled by default, can be enabled via env var
        let entropy = env::var("SECRETS_FILTER_ENTROPY")
            .map(|v| is_truthy(&v))
            .unwrap_or(ENTROPY_ENABLED_DEFAULT);

        Ok(FilterConfig {
            values,
            patterns,
            entropy,
        })
    }
}

const STATE_NORMAL: u8 = 0;
const STATE_IN_PRIVATE_KEY: u8 = 1;
const STATE_IN_PRIVATE_KEY_OVERFLOW: u8 = 2;
// MAX_PRIVATE_KEY_BUFFER and LONG_THRESHOLD come from patterns_gen

struct Pattern {
    regex: Regex,
    label: &'static str,
}

struct ContextPattern {
    regex: Regex,
    label: &'static str,
    group: usize,
}

fn build_patterns() -> Vec<Pattern> {
    PATTERNS
        .iter()
        .map(|(regex_str, label)| Pattern {
            regex: Regex::new(regex_str).unwrap(),
            label,
        })
        .collect()
}

fn build_context_patterns() -> Vec<ContextPattern> {
    CONTEXT_PATTERNS
        .iter()
        .map(|(regex_str, label, group)| ContextPattern {
            regex: Regex::new(regex_str).unwrap(),
            label,
            group: *group,
        })
        .collect()
}

fn classify_segment(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        return format!("{}N", s.len());
    }
    if s.chars().all(|c| c.is_ascii_alphabetic()) {
        return format!("{}A", s.len());
    }
    format!("{}X", s.len())
}

fn describe_structure(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }

    // Very long tokens
    if s.len() >= LONG_THRESHOLD {
        for sep in ["-", "_", "."] {
            if s.contains(sep) {
                let parts: Vec<&str> = s.split(sep).collect();
                let first = parts[0];
                let is_alpha = first.chars().all(|c| c.is_ascii_alphabetic());
                let known_prefixes = ["ghp", "gho", "ghs", "ghr", "npm", "sk"];
                if is_alpha || known_prefixes.contains(&first) {
                    return format!("{}{}...:{}chars", first, sep, s.len());
                }
            }
        }
        return format!("{}chars", s.len());
    }

    // Check for structured tokens
    for sep in ["-", ".", "_"] {
        if s.contains(sep) {
            let parts: Vec<&str> = s.split(sep).collect();
            if parts.len() >= 2 {
                let first = parts[0];
                let is_alpha = first.chars().all(|c| c.is_ascii_alphabetic());
                if is_alpha && first.len() <= 12 {
                    let segments: Vec<String> =
                        parts[1..].iter().map(|p| classify_segment(p)).collect();
                    return format!("{}{}{}", first, sep, segments.join(sep));
                }
                let segments: Vec<String> = parts.iter().map(|p| classify_segment(p)).collect();
                return segments.join(sep);
            }
        }
    }

    classify_segment(s)
}

fn load_secrets() -> HashMap<String, String> {
    let explicit: HashSet<&str> = EXPLICIT_ENV_VARS.iter().cloned().collect();

    let mut secrets = HashMap::new();

    for (name, value) in env::vars() {
        if value.len() < 8 {
            continue;
        }

        if explicit.contains(name.as_str()) || ENV_SUFFIXES.iter().any(|p| name.ends_with(p)) {
            secrets.insert(name, value);
        }
    }

    secrets
}

fn redact_env_values(text: &str, secrets: &HashMap<String, String>) -> String {
    if secrets.is_empty() {
        return text.to_string();
    }

    // Sort by value length descending
    let mut sorted: Vec<(&String, &String)> = secrets.iter().collect();
    sorted.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    let mut result = text.to_string();
    for (key, val) in sorted {
        if !val.is_empty() {
            let structure = describe_structure(val);
            let replacement = format!("[REDACTED:{}:{}]", key, structure);
            result = result.replace(val, &replacement);
        }
    }

    result
}

/// Precompiled special patterns for hot path
struct SpecialPatterns {
    git_credential: Regex,
    docker_auth: Regex,
}

fn build_special_patterns() -> SpecialPatterns {
    SpecialPatterns {
        git_credential: Regex::new(GIT_CREDENTIAL_PATTERN.pattern).unwrap(),
        docker_auth: Regex::new(DOCKER_AUTH_PATTERN.pattern).unwrap(),
    }
}

fn redact_patterns(
    text: &str,
    patterns: &[Pattern],
    context_patterns: &[ContextPattern],
    special: &SpecialPatterns,
) -> String {
    let mut result = text.to_string();

    // Direct patterns
    for p in patterns {
        result = p
            .regex
            .replace_all(&result, |caps: &regex::Captures| {
                let matched = caps.get(0).unwrap().as_str();
                let structure = describe_structure(matched);
                format!("[REDACTED:{}:{}]", p.label, structure)
            })
            .to_string();
    }

    // Context patterns (simulate lookbehind)
    for cp in context_patterns {
        result = cp
            .regex
            .replace_all(&result, |caps: &regex::Captures| {
                let prefix = caps.get(1).map_or("", |m| m.as_str());
                let secret = caps.get(cp.group).map_or("", |m| m.as_str());
                let structure = describe_structure(secret);
                format!("{}[REDACTED:{}:{}]", prefix, cp.label, structure)
            })
            .to_string();
    }

    // Git credential URLs: ://user:password@ -> ://user:[REDACTED]@
    result = special
        .git_credential
        .replace_all(&result, |caps: &regex::Captures| {
            let prefix = caps.get(1).map_or("", |m| m.as_str());
            let password = caps
                .get(GIT_CREDENTIAL_PATTERN.secret_group)
                .map_or("", |m| m.as_str());
            let suffix = caps.get(3).map_or("", |m| m.as_str());
            let structure = describe_structure(password);
            format!(
                "{}[REDACTED:{}:{}]{}",
                prefix, GIT_CREDENTIAL_PATTERN.label, structure, suffix
            )
        })
        .to_string();

    // Docker config auth: "auth": "base64" -> "auth": "[REDACTED]"
    result = special
        .docker_auth
        .replace_all(&result, |caps: &regex::Captures| {
            let prefix = caps.get(1).map_or("", |m| m.as_str());
            let auth = caps
                .get(DOCKER_AUTH_PATTERN.secret_group)
                .map_or("", |m| m.as_str());
            let suffix = caps.get(3).map_or("", |m| m.as_str());
            let structure = describe_structure(auth);
            format!(
                "{}[REDACTED:{}:{}]{}",
                prefix, DOCKER_AUTH_PATTERN.label, structure, suffix
            )
        })
        .to_string();

    result
}

// ============================================================================
// Entropy-based detection
// ============================================================================

/// Entropy detection configuration (can be overridden via env vars)
#[derive(Debug, Clone)]
struct EntropyConfig {
    threshold_hex: f64,
    threshold_base64: f64,
    threshold_alphanumeric: f64,
    min_length: usize,
    max_length: usize,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            threshold_hex: ENTROPY_THRESHOLD_HEX,
            threshold_base64: ENTROPY_THRESHOLD_BASE64,
            threshold_alphanumeric: ENTROPY_THRESHOLD_ALPHANUMERIC,
            min_length: ENTROPY_MIN_LENGTH,
            max_length: ENTROPY_MAX_LENGTH,
        }
    }
}

/// Get entropy config with environment variable overrides
fn get_entropy_config() -> EntropyConfig {
    let mut config = EntropyConfig::default();

    // Global threshold override
    if let Ok(val) = env::var("SECRETS_FILTER_ENTROPY_THRESHOLD") {
        if let Ok(t) = val.parse::<f64>() {
            config.threshold_hex = t;
            config.threshold_base64 = t;
            config.threshold_alphanumeric = t;
        }
    }

    // Per-charset overrides
    if let Ok(val) = env::var("SECRETS_FILTER_ENTROPY_HEX") {
        if let Ok(t) = val.parse::<f64>() {
            config.threshold_hex = t;
        }
    }
    if let Ok(val) = env::var("SECRETS_FILTER_ENTROPY_BASE64") {
        if let Ok(t) = val.parse::<f64>() {
            config.threshold_base64 = t;
        }
    }

    // Length overrides
    if let Ok(val) = env::var("SECRETS_FILTER_ENTROPY_MIN_LEN") {
        if let Ok(l) = val.parse::<usize>() {
            config.min_length = l;
        }
    }
    if let Ok(val) = env::var("SECRETS_FILTER_ENTROPY_MAX_LEN") {
        if let Ok(l) = val.parse::<usize>() {
            config.max_length = l;
        }
    }

    config
}

/// Calculate Shannon entropy of a string in bits
/// H = -Σ p(x) log₂ p(x)
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }

    let length = s.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.values() {
        let p = count as f64 / length;
        entropy -= p * p.log2();
    }
    entropy
}

/// Character set definitions
const CHARSET_HEX: &str = "0123456789abcdef";
const CHARSET_BASE64: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const CHARSET_ALPHANUMERIC: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

/// Classify a string's character set
/// Returns: "hex", "base64", "alphanumeric", or "mixed"
fn classify_charset(s: &str) -> &'static str {
    let lowercase = s.to_lowercase();
    let chars: HashSet<char> = lowercase.chars().collect();
    let hex_chars: HashSet<char> = CHARSET_HEX.chars().collect();

    // Check hex first (most restrictive)
    if chars.iter().all(|c| hex_chars.contains(c)) {
        return "hex";
    }

    // Check alphanumeric (common for tokens)
    let alnum_chars: HashSet<char> = CHARSET_ALPHANUMERIC.chars().collect();
    let original_chars: HashSet<char> = s.chars().collect();
    if original_chars.iter().all(|c| alnum_chars.contains(c)) {
        return "alphanumeric";
    }

    // Check base64
    let base64_chars: HashSet<char> = CHARSET_BASE64.chars().collect();
    if original_chars.iter().all(|c| base64_chars.contains(c)) {
        return "base64";
    }

    "mixed"
}

/// Token with position information
struct Token {
    text: String,
    start: usize,
    end: usize,
}

/// Extract potential secret tokens from text
fn extract_tokens(text: &str, min_len: usize, max_len: usize, delim_re: &Regex) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut pos = 0;

    for part in delim_re.split(text) {
        if !part.is_empty() {
            // Find the actual position of this part in the original text
            if let Some(idx) = text[pos..].find(part) {
                let start = pos + idx;
                let end = start + part.len();
                pos = end;

                // Filter by length
                if part.len() < min_len || part.len() > max_len {
                    continue;
                }

                // Skip if all alphabetic (variable names)
                if part.chars().all(|c| c.is_ascii_alphabetic()) {
                    continue;
                }

                // Skip if all numeric (IDs, line numbers)
                if part.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }

                // Skip if contains whitespace
                if part.chars().any(|c| c.is_whitespace()) {
                    continue;
                }

                tokens.push(Token {
                    text: part.to_string(),
                    start,
                    end,
                });
            }
        }
    }

    tokens
}

/// Check if a position in text is preceded by a context keyword (within 50 chars)
fn has_context_keyword(text: &str, pos: usize, keywords: &[&str]) -> bool {
    if keywords.is_empty() {
        return false;
    }

    let start = pos.saturating_sub(50);
    let prefix = text[start..pos].to_lowercase();

    for kw in keywords {
        if prefix.contains(&kw.to_lowercase()) {
            return true;
        }
    }

    false
}

/// Check if token matches an exclusion pattern
/// Returns: Some(label) if excluded, None otherwise
fn matches_exclusion(
    token: &str,
    text: &str,
    pos: usize,
    exclusion_regexes: &[(Regex, &EntropyExclusion)],
) -> Option<&'static str> {
    for (regex, excl) in exclusion_regexes {
        if regex.is_match(token) {
            // Check context keywords if present
            if let Some(context_kw) = excl.context_keywords {
                if has_context_keyword(text, pos, context_kw) {
                    return Some(excl.label);
                }
                // Has context keywords but none found - not excluded
                continue;
            }
            // No context keywords required - excluded
            return Some(excl.label);
        }
    }

    // Check global context keywords
    if has_context_keyword(text, pos, ENTROPY_CONTEXT_KEYWORDS) {
        return Some("CONTEXT");
    }

    None
}

/// Create structure description for entropy redaction
/// Example: hex:40:3.8
fn describe_entropy_structure(token: &str, entropy: f64, charset: &str) -> String {
    let charset_abbrev = match charset {
        "hex" => "hex",
        "base64" => "b64",
        "alphanumeric" => "alnum",
        _ => "mix",
    };
    format!("{}:{}:{:.1}", charset_abbrev, token.len(), entropy)
}

/// Build compiled exclusion regexes from patterns
fn build_exclusion_regexes() -> Vec<(Regex, &'static EntropyExclusion)> {
    ENTROPY_EXCLUSIONS
        .iter()
        .filter_map(|excl| {
            let regex = if excl.case_insensitive {
                Regex::new(&format!("(?i)^{}$", excl.pattern)).ok()
            } else {
                Regex::new(&format!("^{}$", excl.pattern)).ok()
            };
            regex.map(|r| (r, excl))
        })
        .collect()
}

/// Detect and redact high-entropy strings
fn redact_entropy(
    text: &str,
    config: &EntropyConfig,
    exclusion_regexes: &[(Regex, &EntropyExclusion)],
    token_delim_re: &Regex,
) -> String {
    let tokens = extract_tokens(text, config.min_length, config.max_length, token_delim_re);

    // Collect replacements (process in reverse order to preserve positions)
    let mut replacements: Vec<(usize, usize, String)> = Vec::new();

    for token in tokens.iter().rev() {
        // Check exclusions
        if matches_exclusion(&token.text, text, token.start, exclusion_regexes).is_some() {
            continue;
        }

        // Classify character set and get threshold
        let charset = classify_charset(&token.text);
        let threshold = match charset {
            "hex" => config.threshold_hex,
            "base64" => config.threshold_base64,
            "alphanumeric" => config.threshold_alphanumeric,
            _ => config.threshold_alphanumeric, // mixed uses alphanumeric threshold
        };

        // Calculate entropy
        let entropy = shannon_entropy(&token.text);

        if entropy >= threshold {
            let structure = describe_entropy_structure(&token.text, entropy, charset);
            let replacement = format!("[REDACTED:HIGH_ENTROPY:{}]", structure);
            replacements.push((token.start, token.end, replacement));
        }
    }

    // Apply replacements in reverse order
    let mut result = text.to_string();
    for (start, end, replacement) in replacements {
        result = format!("{}{}{}", &result[..start], replacement, &result[end..]);
    }

    result
}

#[allow(clippy::too_many_arguments)]
fn redact_line(
    line: &str,
    secrets: &HashMap<String, String>,
    patterns: &[Pattern],
    context_patterns: &[ContextPattern],
    special_patterns: &SpecialPatterns,
    config: &FilterConfig,
    entropy_config: Option<&EntropyConfig>,
    exclusion_regexes: &[(Regex, &EntropyExclusion)],
    token_delim_re: Option<&Regex>,
) -> String {
    let mut result = line.to_string();
    if config.values {
        result = redact_env_values(&result, secrets);
    }
    if config.patterns {
        result = redact_patterns(&result, patterns, context_patterns, special_patterns);
    }
    if config.entropy {
        if let Some(ec) = entropy_config {
            if let Some(delim) = token_delim_re {
                result = redact_entropy(&result, ec, exclusion_regexes, delim);
            }
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn flush_buffer_redacted(
    buffer: &[String],
    secrets: &HashMap<String, String>,
    patterns: &[Pattern],
    context_patterns: &[ContextPattern],
    special_patterns: &SpecialPatterns,
    config: &FilterConfig,
    entropy_config: Option<&EntropyConfig>,
    exclusion_regexes: &[(Regex, &EntropyExclusion)],
    token_delim_re: Option<&Regex>,
) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    for line in buffer {
        let _ = write!(
            handle,
            "{}",
            redact_line(
                line,
                secrets,
                patterns,
                context_patterns,
                special_patterns,
                config,
                entropy_config,
                exclusion_regexes,
                token_delim_re
            )
        );
    }
    let _ = handle.flush();
}

fn main() {
    // Parse filter configuration
    let config = match parse_filter_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    // Conditionally load secrets (skip if values filter disabled)
    let secrets = if config.values {
        load_secrets()
    } else {
        HashMap::new()
    };

    // Conditionally compile patterns (skip if patterns filter disabled)
    let patterns = if config.patterns {
        build_patterns()
    } else {
        Vec::new()
    };

    let context_patterns = if config.patterns {
        build_context_patterns()
    } else {
        Vec::new()
    };

    // Special patterns (git credential, docker auth) - always build, cheap if unused
    let special_patterns = build_special_patterns();

    // Private key detection is part of patterns filter
    let private_key_begin = if config.patterns {
        Some(Regex::new(PRIVATE_KEY_BEGIN).unwrap())
    } else {
        None
    };
    let private_key_end = if config.patterns {
        Some(Regex::new(PRIVATE_KEY_END).unwrap())
    } else {
        None
    };

    // Entropy configuration (only if entropy filter enabled)
    let entropy_config = if config.entropy {
        Some(get_entropy_config())
    } else {
        None
    };

    // Build exclusion regexes for entropy detection
    let exclusion_regexes = if config.entropy {
        build_exclusion_regexes()
    } else {
        Vec::new()
    };

    // Token delimiter regex for entropy detection (precompiled)
    let token_delim_re = if config.entropy {
        Some(Regex::new(r#"[\s"'`()\[\]{},;:<>=@#]+"#).unwrap())
    } else {
        None
    };

    let mut state = STATE_NORMAL;
    let mut buffer: Vec<String> = Vec::new();

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_handle = stdout.lock();
    let mut stdin_handle = stdin.lock();
    let mut line_buf: Vec<u8> = Vec::new();

    loop {
        line_buf.clear();
        match stdin_handle.read_until(b'\n', &mut line_buf) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break,
        }

        // Binary detection: null byte (check raw bytes before UTF-8 conversion)
        if line_buf.contains(&0) {
            flush_buffer_redacted(
                &buffer,
                &secrets,
                &patterns,
                &context_patterns,
                &special_patterns,
                &config,
                entropy_config.as_ref(),
                &exclusion_regexes,
                token_delim_re.as_ref(),
            );
            buffer.clear();
            // Passthrough this line and rest as raw bytes
            let _ = stdout_handle.write_all(&line_buf);
            let _ = stdout_handle.flush();
            let _ = io::copy(&mut stdin_handle, &mut stdout_handle);
            return;
        }

        // Convert to string (lossy for invalid UTF-8 - rare edge case)
        let line = String::from_utf8_lossy(&line_buf).into_owned();

        match state {
            STATE_NORMAL => {
                // Check for private key begin (only if patterns enabled)
                let is_key_begin = private_key_begin
                    .as_ref()
                    .map(|re| re.is_match(&line))
                    .unwrap_or(false);

                if is_key_begin {
                    state = STATE_IN_PRIVATE_KEY;
                    buffer = vec![line];
                } else {
                    let _ = write!(
                        stdout_handle,
                        "{}",
                        redact_line(
                            &line,
                            &secrets,
                            &patterns,
                            &context_patterns,
                            &special_patterns,
                            &config,
                            entropy_config.as_ref(),
                            &exclusion_regexes,
                            token_delim_re.as_ref()
                        )
                    );
                    let _ = stdout_handle.flush();
                }
            }
            STATE_IN_PRIVATE_KEY => {
                buffer.push(line.clone());

                let is_key_end = private_key_end
                    .as_ref()
                    .map(|re| re.is_match(&line))
                    .unwrap_or(false);

                if is_key_end {
                    let _ = writeln!(stdout_handle, "[REDACTED:PRIVATE_KEY:multiline]");
                    let _ = stdout_handle.flush();
                    buffer.clear();
                    state = STATE_NORMAL;
                } else if buffer.len() > MAX_PRIVATE_KEY_BUFFER {
                    // Buffer overflow - redact entirely (fail closed, don't leak)
                    let _ = writeln!(stdout_handle, "[REDACTED:PRIVATE_KEY:multiline]");
                    let _ = stdout_handle.flush();
                    buffer.clear();
                    // Transition to overflow state - consume remaining lines silently until END
                    state = STATE_IN_PRIVATE_KEY_OVERFLOW;
                }
            }
            STATE_IN_PRIVATE_KEY_OVERFLOW => {
                // Consume lines silently until END marker
                let is_key_end = private_key_end
                    .as_ref()
                    .map(|re| re.is_match(&line))
                    .unwrap_or(false);
                if is_key_end {
                    state = STATE_NORMAL;
                }
                // No buffering, no output - just wait for END
            }
            _ => {}
        }
    }

    // EOF: handle remaining state
    if state == STATE_IN_PRIVATE_KEY {
        // Incomplete private key block - redact entirely (fail closed, don't leak)
        let _ = writeln!(stdout_handle, "[REDACTED:PRIVATE_KEY:multiline]");
    } else if state == STATE_IN_PRIVATE_KEY_OVERFLOW {
        // Already emitted overflow redaction, nothing to do
    } else if !buffer.is_empty() {
        // Flush any remaining buffered content
        flush_buffer_redacted(
            &buffer,
            &secrets,
            &patterns,
            &context_patterns,
            &special_patterns,
            &config,
            entropy_config.as_ref(),
            &exclusion_regexes,
            token_delim_re.as_ref(),
        );
    }
}
