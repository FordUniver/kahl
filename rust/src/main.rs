// secrets-filter: Filter stdin for secrets, redact with labels
// Build: cargo build --release
//
// Filter modes:
//   --filter=values,patterns  (CLI, comma-separated, case-insensitive)
//   SECRETS_FILTER_VALUES=0|false|no  (ENV, disables values filter)
//   SECRETS_FILTER_PATTERNS=0|false|no  (ENV, disables patterns filter)
//
// Default: both enabled. CLI overrides ENV entirely.

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
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            values: true,
            patterns: true,
        }
    }
}

/// Check if a string value is falsy (0, false, no)
fn is_falsy(val: &str) -> bool {
    matches!(val.to_lowercase().as_str(), "0" | "false" | "no")
}

/// Parse filter configuration from CLI args and environment
fn parse_filter_config() -> Result<FilterConfig, String> {
    let args: Vec<String> = env::args().collect();

    // Check for --filter=X or -f X in args
    let mut cli_filter: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i].starts_with("--filter=") {
            cli_filter = Some(args[i].strip_prefix("--filter=").unwrap().to_string());
            break;
        } else if args[i] == "-f" || args[i] == "--filter" {
            if i + 1 < args.len() {
                cli_filter = Some(args[i + 1].clone());
                break;
            }
        }
        i += 1;
    }

    if let Some(filter_str) = cli_filter {
        // CLI overrides ENV entirely
        let mut values = false;
        let mut patterns = false;
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
                "all" => {
                    values = true;
                    patterns = true;
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

        Ok(FilterConfig { values, patterns })
    } else {
        // Use ENV variables
        let values = env::var("SECRETS_FILTER_VALUES")
            .map(|v| !is_falsy(&v))
            .unwrap_or(true);

        let patterns = env::var("SECRETS_FILTER_PATTERNS")
            .map(|v| !is_falsy(&v))
            .unwrap_or(true);

        Ok(FilterConfig { values, patterns })
    }
}

const STATE_NORMAL: u8 = 0;
const STATE_IN_PRIVATE_KEY: u8 = 1;
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
                    let segments: Vec<String> = parts[1..].iter().map(|p| classify_segment(p)).collect();
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

fn redact_patterns(text: &str, patterns: &[Pattern], context_patterns: &[ContextPattern]) -> String {
    let mut result = text.to_string();

    // Direct patterns
    for p in patterns {
        result = p.regex.replace_all(&result, |caps: &regex::Captures| {
            let matched = caps.get(0).unwrap().as_str();
            let structure = describe_structure(matched);
            format!("[REDACTED:{}:{}]", p.label, structure)
        }).to_string();
    }

    // Context patterns (simulate lookbehind)
    for cp in context_patterns {
        result = cp.regex.replace_all(&result, |caps: &regex::Captures| {
            let prefix = caps.get(1).map_or("", |m| m.as_str());
            let secret = caps.get(cp.group).map_or("", |m| m.as_str());
            let structure = describe_structure(secret);
            format!("{}[REDACTED:{}:{}]", prefix, cp.label, structure)
        }).to_string();
    }

    // Git credential URLs: ://user:password@ -> ://user:[REDACTED]@
    let git_cred_pattern = Regex::new(GIT_CREDENTIAL_PATTERN.pattern).unwrap();
    result = git_cred_pattern.replace_all(&result, |caps: &regex::Captures| {
        let prefix = caps.get(1).map_or("", |m| m.as_str());
        let password = caps.get(GIT_CREDENTIAL_PATTERN.secret_group).map_or("", |m| m.as_str());
        let suffix = caps.get(3).map_or("", |m| m.as_str());
        let structure = describe_structure(password);
        format!("{}[REDACTED:{}:{}]{}", prefix, GIT_CREDENTIAL_PATTERN.label, structure, suffix)
    }).to_string();

    // Docker config auth: "auth": "base64" -> "auth": "[REDACTED]"
    let docker_auth_pattern = Regex::new(DOCKER_AUTH_PATTERN.pattern).unwrap();
    result = docker_auth_pattern.replace_all(&result, |caps: &regex::Captures| {
        let prefix = caps.get(1).map_or("", |m| m.as_str());
        let auth = caps.get(DOCKER_AUTH_PATTERN.secret_group).map_or("", |m| m.as_str());
        let suffix = caps.get(3).map_or("", |m| m.as_str());
        let structure = describe_structure(auth);
        format!("{}[REDACTED:{}:{}]{}", prefix, DOCKER_AUTH_PATTERN.label, structure, suffix)
    }).to_string();

    result
}

fn redact_line(
    line: &str,
    secrets: &HashMap<String, String>,
    patterns: &[Pattern],
    context_patterns: &[ContextPattern],
    config: &FilterConfig,
) -> String {
    let mut result = line.to_string();
    if config.values {
        result = redact_env_values(&result, secrets);
    }
    if config.patterns {
        result = redact_patterns(&result, patterns, context_patterns);
    }
    result
}

fn flush_buffer_redacted(
    buffer: &[String],
    secrets: &HashMap<String, String>,
    patterns: &[Pattern],
    context_patterns: &[ContextPattern],
    config: &FilterConfig,
) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    for line in buffer {
        let _ = write!(handle, "{}", redact_line(line, secrets, patterns, context_patterns, config));
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

    let mut state = STATE_NORMAL;
    let mut buffer: Vec<String> = Vec::new();

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_handle = stdout.lock();

    for line_result in stdin.lock().lines() {
        let line = match line_result {
            Ok(l) => l + "\n",
            Err(_) => break,
        };

        // Binary detection: null byte
        if line.contains('\0') {
            flush_buffer_redacted(&buffer, &secrets, &patterns, &context_patterns, &config);
            buffer.clear();
            // Passthrough this line and rest
            let _ = write!(stdout_handle, "{}", line);
            let _ = stdout_handle.flush();
            for rest in stdin.lock().lines().flatten() {
                let _ = writeln!(stdout_handle, "{}", rest);
            }
            return;
        }

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
                    let _ = write!(stdout_handle, "{}", redact_line(&line, &secrets, &patterns, &context_patterns, &config));
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
                    flush_buffer_redacted(&buffer, &secrets, &patterns, &context_patterns, &config);
                    buffer.clear();
                    state = STATE_NORMAL;
                }
            }
            _ => {}
        }
    }

    // EOF: flush remaining buffer
    flush_buffer_redacted(&buffer, &secrets, &patterns, &context_patterns, &config);
}
