// secrets-filter: Filter stdin for secrets, redact with labels
// Build: cargo build --release

use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::Command;

const STATE_NORMAL: u8 = 0;
const STATE_IN_PRIVATE_KEY: u8 = 1;
const MAX_PRIVATE_KEY_BUFFER: usize = 100;
const LONG_THRESHOLD: usize = 50;

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
    vec![
        // GitHub
        Pattern { regex: Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap(), label: "GITHUB_PAT" },
        Pattern { regex: Regex::new(r"gho_[A-Za-z0-9]{36}").unwrap(), label: "GITHUB_OAUTH" },
        Pattern { regex: Regex::new(r"ghs_[A-Za-z0-9]{36}").unwrap(), label: "GITHUB_SERVER" },
        Pattern { regex: Regex::new(r"ghr_[A-Za-z0-9]{36}").unwrap(), label: "GITHUB_REFRESH" },
        Pattern { regex: Regex::new(r"github_pat_[A-Za-z0-9_]{22,}").unwrap(), label: "GITHUB_PAT" },

        // GitLab
        Pattern { regex: Regex::new(r"glpat-[A-Za-z0-9_-]{20,}").unwrap(), label: "GITLAB_PAT" },

        // Slack
        Pattern { regex: Regex::new(r"xoxb-[0-9]+-[0-9A-Za-z-]+").unwrap(), label: "SLACK_BOT" },
        Pattern { regex: Regex::new(r"xoxp-[0-9]+-[0-9A-Za-z-]+").unwrap(), label: "SLACK_USER" },
        Pattern { regex: Regex::new(r"xoxa-[0-9]+-[0-9A-Za-z-]+").unwrap(), label: "SLACK_APP" },
        Pattern { regex: Regex::new(r"xoxs-[0-9]+-[0-9A-Za-z-]+").unwrap(), label: "SLACK_SESSION" },

        // OpenAI / Anthropic
        Pattern { regex: Regex::new(r"sk-[A-Za-z0-9]{48}").unwrap(), label: "OPENAI_KEY" },
        Pattern { regex: Regex::new(r"sk-proj-[A-Za-z0-9_-]{20,}").unwrap(), label: "OPENAI_PROJECT_KEY" },
        Pattern { regex: Regex::new(r"sk-ant-[A-Za-z0-9-]{90,}").unwrap(), label: "ANTHROPIC_KEY" },

        // AWS
        Pattern { regex: Regex::new(r"AKIA[A-Z0-9]{16}").unwrap(), label: "AWS_ACCESS_KEY" },

        // Google Cloud
        Pattern { regex: Regex::new(r"AIza[A-Za-z0-9_-]{35}").unwrap(), label: "GOOGLE_API_KEY" },

        // age encryption
        Pattern { regex: Regex::new(r"AGE-SECRET-KEY-[A-Z0-9]{59}").unwrap(), label: "AGE_SECRET_KEY" },

        // Stripe
        Pattern { regex: Regex::new(r"sk_live_[A-Za-z0-9]{24,}").unwrap(), label: "STRIPE_SECRET" },
        Pattern { regex: Regex::new(r"sk_test_[A-Za-z0-9]{24,}").unwrap(), label: "STRIPE_TEST" },
        Pattern { regex: Regex::new(r"pk_live_[A-Za-z0-9]{24,}").unwrap(), label: "STRIPE_PUBLISHABLE" },

        // Twilio
        Pattern { regex: Regex::new(r"SK[a-f0-9]{32}").unwrap(), label: "TWILIO_KEY" },

        // SendGrid
        Pattern { regex: Regex::new(r"SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap(), label: "SENDGRID_KEY" },

        // npm / PyPI
        Pattern { regex: Regex::new(r"npm_[A-Za-z0-9]{36}").unwrap(), label: "NPM_TOKEN" },
        Pattern { regex: Regex::new(r"pypi-[A-Za-z0-9_-]{100,}").unwrap(), label: "PYPI_TOKEN" },

        // JWT tokens
        Pattern { regex: Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap(), label: "JWT_TOKEN" },
    ]
}

fn build_context_patterns() -> Vec<ContextPattern> {
    vec![
        // netrc/authinfo
        ContextPattern { regex: Regex::new(r"(password |passwd )([^\s]+)").unwrap(), label: "NETRC_PASSWORD", group: 2 },

        // Generic key=value patterns
        ContextPattern { regex: Regex::new(r#"(password=)([^\s,;"'\}\[\]]+)"#).unwrap(), label: "PASSWORD_VALUE", group: 2 },
        ContextPattern { regex: Regex::new(r#"(password:)(\s*[^\s,;"'\}\[\]]+)"#).unwrap(), label: "PASSWORD_VALUE", group: 2 },
        ContextPattern { regex: Regex::new(r#"(Password=)([^\s,;"'\}\[\]]+)"#).unwrap(), label: "PASSWORD_VALUE", group: 2 },
        ContextPattern { regex: Regex::new(r#"(Password:)(\s*[^\s,;"'\}\[\]]+)"#).unwrap(), label: "PASSWORD_VALUE", group: 2 },
        ContextPattern { regex: Regex::new(r#"(secret=)([^\s,;"'\}\[\]]+)"#).unwrap(), label: "SECRET_VALUE", group: 2 },
        ContextPattern { regex: Regex::new(r#"(secret:)(\s*[^\s,;"'\}\[\]]+)"#).unwrap(), label: "SECRET_VALUE", group: 2 },
        ContextPattern { regex: Regex::new(r#"(Secret=)([^\s,;"'\}\[\]]+)"#).unwrap(), label: "SECRET_VALUE", group: 2 },
        ContextPattern { regex: Regex::new(r#"(Secret:)(\s*[^\s,;"'\}\[\]]+)"#).unwrap(), label: "SECRET_VALUE", group: 2 },
        ContextPattern { regex: Regex::new(r#"(token=)([^\s,;"'\}\[\]]+)"#).unwrap(), label: "TOKEN_VALUE", group: 2 },
        ContextPattern { regex: Regex::new(r#"(token:)(\s*[^\s,;"'\}\[\]]+)"#).unwrap(), label: "TOKEN_VALUE", group: 2 },
        ContextPattern { regex: Regex::new(r#"(Token=)([^\s,;"'\}\[\]]+)"#).unwrap(), label: "TOKEN_VALUE", group: 2 },
        ContextPattern { regex: Regex::new(r#"(Token:)(\s*[^\s,;"'\}\[\]]+)"#).unwrap(), label: "TOKEN_VALUE", group: 2 },
    ]
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

fn load_secrets_from_dotfiles() -> HashMap<String, String> {
    let dotfiles = env::var("DOTFILES").unwrap_or_else(|_| {
        let home = env::var("HOME").unwrap_or_default();
        format!("{}/.dotfiles", home)
    });
    let secrets_dir = format!("{}/secrets", dotfiles);

    if !Path::new(&secrets_dir).is_dir() {
        return HashMap::new();
    }

    let output = match Command::new("grep")
        .args(["-rh", r"^[A-Z_][A-Z0-9_]*=", &secrets_dir])
        .output()
    {
        Ok(o) => o,
        Err(_) => return HashMap::new(),
    };

    let var_pattern = Regex::new(r"^([A-Z_][A-Z0-9_]*)=").unwrap();
    let mut secrets = HashMap::new();

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some(caps) = var_pattern.captures(line) {
            if let Some(var_match) = caps.get(1) {
                let var_name = var_match.as_str();
                if let Ok(val) = env::var(var_name) {
                    if !val.is_empty() {
                        secrets.insert(var_name.to_string(), val);
                    }
                }
            }
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
            let structure = describe_structure(secret.trim());
            format!("{}[REDACTED:{}:{}]", prefix, cp.label, structure)
        }).to_string();
    }

    // Git credential URLs: ://user:password@ -> ://user:[REDACTED]@
    let git_cred_pattern = Regex::new(r"(://[^:]+:)([^@]+)(@)").unwrap();
    result = git_cred_pattern.replace_all(&result, |caps: &regex::Captures| {
        let prefix = caps.get(1).map_or("", |m| m.as_str());
        let password = caps.get(2).map_or("", |m| m.as_str());
        let suffix = caps.get(3).map_or("", |m| m.as_str());
        let structure = describe_structure(password);
        format!("{}[REDACTED:GIT_CREDENTIAL:{}]{}", prefix, structure, suffix)
    }).to_string();

    // Docker config auth: "auth": "base64" -> "auth": "[REDACTED]"
    let docker_auth_pattern = Regex::new(r#"("auth":\s*")([A-Za-z0-9+/=]{20,})(")"#).unwrap();
    result = docker_auth_pattern.replace_all(&result, |caps: &regex::Captures| {
        let prefix = caps.get(1).map_or("", |m| m.as_str());
        let auth = caps.get(2).map_or("", |m| m.as_str());
        let suffix = caps.get(3).map_or("", |m| m.as_str());
        let structure = describe_structure(auth);
        format!("{}[REDACTED:DOCKER_AUTH:{}]{}", prefix, structure, suffix)
    }).to_string();

    result
}

fn redact_line(line: &str, secrets: &HashMap<String, String>, patterns: &[Pattern], context_patterns: &[ContextPattern]) -> String {
    let line = redact_env_values(line, secrets);
    redact_patterns(&line, patterns, context_patterns)
}

fn flush_buffer_redacted(buffer: &[String], secrets: &HashMap<String, String>, patterns: &[Pattern], context_patterns: &[ContextPattern]) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    for line in buffer {
        let _ = write!(handle, "{}", redact_line(line, secrets, patterns, context_patterns));
    }
    let _ = handle.flush();
}

fn main() {
    let secrets = load_secrets_from_dotfiles();
    let patterns = build_patterns();
    let context_patterns = build_context_patterns();
    let private_key_begin = Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap();
    let private_key_end = Regex::new(r"-----END [A-Z ]*PRIVATE KEY-----").unwrap();

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
            flush_buffer_redacted(&buffer, &secrets, &patterns, &context_patterns);
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
                if private_key_begin.is_match(&line) {
                    state = STATE_IN_PRIVATE_KEY;
                    buffer = vec![line];
                } else {
                    let _ = write!(stdout_handle, "{}", redact_line(&line, &secrets, &patterns, &context_patterns));
                    let _ = stdout_handle.flush();
                }
            }
            STATE_IN_PRIVATE_KEY => {
                buffer.push(line.clone());

                if private_key_end.is_match(&line) {
                    let _ = writeln!(stdout_handle, "[REDACTED:PRIVATE_KEY:multiline]");
                    let _ = stdout_handle.flush();
                    buffer.clear();
                    state = STATE_NORMAL;
                } else if buffer.len() > MAX_PRIVATE_KEY_BUFFER {
                    flush_buffer_redacted(&buffer, &secrets, &patterns, &context_patterns);
                    buffer.clear();
                    state = STATE_NORMAL;
                }
            }
            _ => {}
        }
    }

    // EOF: flush remaining buffer
    flush_buffer_redacted(&buffer, &secrets, &patterns, &context_patterns);
}
