// secrets-filter: Filter stdin for secrets, redact with labels
// Streaming mode with state machine for private keys
// Build: swiftc -O -o secrets-filter main.swift

import Foundation

let STATE_NORMAL = 0
let STATE_IN_PRIVATE_KEY = 1
let MAX_PRIVATE_KEY_BUFFER = 100
let LONG_THRESHOLD = 50

// Private key markers
let privateKeyBegin = #/-----BEGIN [A-Z ]*PRIVATE KEY-----/#
let privateKeyEnd = #/-----END [A-Z ]*PRIVATE KEY-----/#

// Direct patterns (no lookbehind needed): (regex, label)
let directPatterns: [(Regex<Substring>, String)] = [
    // GitHub
    (#/ghp_[A-Za-z0-9]{36}/#, "GITHUB_PAT"),
    (#/gho_[A-Za-z0-9]{36}/#, "GITHUB_OAUTH"),
    (#/ghs_[A-Za-z0-9]{36}/#, "GITHUB_SERVER"),
    (#/ghr_[A-Za-z0-9]{36}/#, "GITHUB_REFRESH"),
    (#/github_pat_[A-Za-z0-9_]{22,}/#, "GITHUB_PAT"),

    // GitLab
    (#/glpat-[A-Za-z0-9_\-]{20,}/#, "GITLAB_PAT"),

    // Slack
    (#/xoxb-[0-9]+-[0-9A-Za-z\-]+/#, "SLACK_BOT"),
    (#/xoxp-[0-9]+-[0-9A-Za-z\-]+/#, "SLACK_USER"),
    (#/xoxa-[0-9]+-[0-9A-Za-z\-]+/#, "SLACK_APP"),
    (#/xoxs-[0-9]+-[0-9A-Za-z\-]+/#, "SLACK_SESSION"),

    // OpenAI / Anthropic
    (#/sk-[A-Za-z0-9]{48}/#, "OPENAI_KEY"),
    (#/sk-proj-[A-Za-z0-9_\-]{20,}/#, "OPENAI_PROJECT_KEY"),
    (#/sk-ant-[A-Za-z0-9\-]{90,}/#, "ANTHROPIC_KEY"),

    // AWS
    (#/AKIA[A-Z0-9]{16}/#, "AWS_ACCESS_KEY"),

    // Google Cloud
    (#/AIza[A-Za-z0-9_\-]{35}/#, "GOOGLE_API_KEY"),

    // age encryption
    (#/AGE-SECRET-KEY-[A-Z0-9]{59}/#, "AGE_SECRET_KEY"),

    // Stripe
    (#/sk_live_[A-Za-z0-9]{24,}/#, "STRIPE_SECRET"),
    (#/sk_test_[A-Za-z0-9]{24,}/#, "STRIPE_TEST"),
    (#/pk_live_[A-Za-z0-9]{24,}/#, "STRIPE_PUBLISHABLE"),

    // Twilio
    (#/SK[a-f0-9]{32}/#, "TWILIO_KEY"),

    // SendGrid
    (#/SG\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/#, "SENDGRID_KEY"),

    // npm / PyPI
    (#/npm_[A-Za-z0-9]{36}/#, "NPM_TOKEN"),
    (#/pypi-[A-Za-z0-9_\-]{100,}/#, "PYPI_TOKEN"),

    // JWT tokens
    (#/eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/#, "JWT_TOKEN"),
]

// Context patterns with capture groups (simulating lookbehind)
// Format: (regex with capture groups, label, group index for secret)
let contextPatterns: [(Regex<(Substring, Substring, Substring)>, String)] = [
    // netrc/authinfo: password <value> or passwd <value>
    (#/(password |passwd )([^\s]+)/#, "NETRC_PASSWORD"),

    // Generic key=value patterns
    (#/(password=)([^\s,;"'\}\[\]]+)/#, "PASSWORD_VALUE"),
    (#/(password:)(\s*[^\s,;"'\}\[\]]+)/#, "PASSWORD_VALUE"),
    (#/(Password=)([^\s,;"'\}\[\]]+)/#, "PASSWORD_VALUE"),
    (#/(Password:)(\s*[^\s,;"'\}\[\]]+)/#, "PASSWORD_VALUE"),
    (#/(secret=)([^\s,;"'\}\[\]]+)/#, "SECRET_VALUE"),
    (#/(secret:)(\s*[^\s,;"'\}\[\]]+)/#, "SECRET_VALUE"),
    (#/(Secret=)([^\s,;"'\}\[\]]+)/#, "SECRET_VALUE"),
    (#/(Secret:)(\s*[^\s,;"'\}\[\]]+)/#, "SECRET_VALUE"),
    (#/(token=)([^\s,;"'\}\[\]]+)/#, "TOKEN_VALUE"),
    (#/(token:)(\s*[^\s,;"'\}\[\]]+)/#, "TOKEN_VALUE"),
    (#/(Token=)([^\s,;"'\}\[\]]+)/#, "TOKEN_VALUE"),
    (#/(Token:)(\s*[^\s,;"'\}\[\]]+)/#, "TOKEN_VALUE"),
]

// Git credential pattern: ://user:password@
let gitCredPattern = #/(:[\/][\/][^:]+:)([^@\[]+)(@)/#

// Docker config auth pattern
let dockerAuthPattern = #/("auth":\s*")([A-Za-z0-9+\/=]{20,})(")/#

// Classify a segment: N=digits, A=letters, X=mixed
func classifySegment(_ s: String) -> String {
    if s.isEmpty { return "" }
    if s.allSatisfy({ $0.isNumber }) { return "\(s.count)N" }
    if s.allSatisfy({ $0.isLetter }) { return "\(s.count)A" }
    return "\(s.count)X"
}

// Describe token structure for redaction label
func describeStructure(_ s: String) -> String {
    if s.isEmpty { return "" }

    // Very long tokens: show length with prefix hint
    if s.count >= LONG_THRESHOLD {
        for sep in ["-", "_", "."] {
            if s.contains(sep) {
                let parts = s.components(separatedBy: sep)
                let first = parts[0]
                if first.allSatisfy({ $0.isLetter }) || ["ghp", "gho", "ghs", "ghr", "npm", "sk"].contains(first) {
                    return "\(first)\(sep)...:\(s.count)chars"
                }
            }
        }
        return "\(s.count)chars"
    }

    // Check for structured tokens
    for sep in ["-", ".", "_"] {
        if s.contains(sep) {
            let parts = s.components(separatedBy: sep)
            if parts.count >= 2 {
                let first = parts[0]
                if first.allSatisfy({ $0.isLetter }) && first.count <= 12 {
                    let segments = parts.dropFirst().map { classifySegment($0) }
                    return "\(first)\(sep)\(segments.joined(separator: sep))"
                }
                return parts.map { classifySegment($0) }.joined(separator: sep)
            }
        }
    }

    return classifySegment(s)
}

// Load secrets from environment variables
func loadSecrets() -> [String: String] {
    var secrets: [String: String] = [:]

    let explicit: Set<String> = [
        "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "GLAB_TOKEN", "BITBUCKET_TOKEN",
        "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET",
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "CLAUDE_API_KEY",
        "SLACK_TOKEN", "SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL",
        "NPM_TOKEN", "PYPI_TOKEN", "DOCKER_PASSWORD",
        "DATABASE_URL", "REDIS_URL", "MONGODB_URI",
        "JWT_SECRET", "SESSION_SECRET", "ENCRYPTION_KEY",
        "SENDGRID_API_KEY", "TWILIO_AUTH_TOKEN", "STRIPE_SECRET_KEY"
    ]

    let patterns = ["_SECRET", "_PASSWORD", "_TOKEN", "_API_KEY", "_PRIVATE_KEY", "_AUTH", "_CREDENTIAL"]

    let env = ProcessInfo.processInfo.environment
    for (name, value) in env {
        guard value.count >= 8 else { continue }

        if explicit.contains(name) || patterns.contains(where: { name.hasSuffix($0) }) {
            secrets[name] = value
        }
    }

    return secrets
}

// Replace known secret values
func redactEnvValues(_ text: String, _ secrets: [String: String]) -> String {
    if secrets.isEmpty { return text }

    var result = text
    // Sort by value length descending
    let sorted = secrets.sorted { $0.value.count > $1.value.count }

    for (varName, val) in sorted {
        if val.isEmpty { continue }
        let structure = describeStructure(val)
        let replacement = "[REDACTED:\(varName):\(structure)]"
        result = result.replacingOccurrences(of: val, with: replacement)
    }

    return result
}

// Replace known token patterns
func redactPatterns(_ text: String) -> String {
    var result = text

    // Direct patterns
    for (pattern, label) in directPatterns {
        result = result.replacing(pattern) { match in
            let matched = String(match.0)
            let structure = describeStructure(matched)
            return "[REDACTED:\(label):\(structure)]"
        }
    }

    // Context patterns (capture group approach)
    for (pattern, label) in contextPatterns {
        result = result.replacing(pattern) { match in
            let prefix = String(match.1)
            let secret = String(match.2).trimmingCharacters(in: .whitespaces)
            let structure = describeStructure(secret)
            return "\(prefix)[REDACTED:\(label):\(structure)]"
        }
    }

    // Git credential URLs: ://user:password@ -> ://user:[REDACTED]@
    result = result.replacing(gitCredPattern) { match in
        let prefix = String(match.1)
        let password = String(match.2)
        let suffix = String(match.3)
        let structure = describeStructure(password)
        return "\(prefix)[REDACTED:GIT_CREDENTIAL:\(structure)]\(suffix)"
    }

    // Docker config auth
    result = result.replacing(dockerAuthPattern) { match in
        let prefix = String(match.1)
        let auth = String(match.2)
        let suffix = String(match.3)
        let structure = describeStructure(auth)
        return "\(prefix)[REDACTED:DOCKER_AUTH:\(structure)]\(suffix)"
    }

    return result
}

// Redact a single line
func redactLine(_ line: String, _ secrets: [String: String]) -> String {
    var result = redactEnvValues(line, secrets)
    result = redactPatterns(result)
    return result
}

// Flush buffer with redaction
func flushBufferRedacted(_ buffer: [String], _ secrets: [String: String]) {
    for line in buffer {
        print(redactLine(line, secrets), terminator: "")
        fflush(stdout)
    }
}

// Main
func main() {
    let secrets = loadSecrets()
    var state = STATE_NORMAL
    var buffer: [String] = []

    while let line = readLine(strippingNewline: false) {
        // Binary detection: null byte
        if line.contains("\0") {
            flushBufferRedacted(buffer, secrets)
            buffer = []
            print(line, terminator: "")
            // Passthrough rest
            while let rest = readLine(strippingNewline: false) {
                print(rest, terminator: "")
            }
            return
        }

        if state == STATE_NORMAL {
            if line.contains(privateKeyBegin) {
                state = STATE_IN_PRIVATE_KEY
                buffer = [line]
            } else {
                print(redactLine(line, secrets), terminator: "")
                fflush(stdout)
            }
        } else {
            buffer.append(line)

            if line.contains(privateKeyEnd) {
                print("[REDACTED:PRIVATE_KEY:multiline]")
                fflush(stdout)
                buffer = []
                state = STATE_NORMAL
            } else if buffer.count > MAX_PRIVATE_KEY_BUFFER {
                flushBufferRedacted(buffer, secrets)
                buffer = []
                state = STATE_NORMAL
            }
        }
    }

    // EOF: flush remaining buffer
    if !buffer.isEmpty {
        flushBufferRedacted(buffer, secrets)
    }
}

main()
