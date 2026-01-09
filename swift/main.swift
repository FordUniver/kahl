// secrets-filter: Filter stdin for secrets, redact with labels
// Streaming mode with state machine for private keys
// Build: swiftc -O -o secrets-filter main.swift patterns_gen.swift
//
// Filter modes:
//   --filter=values    - redact known secret values from environment
//   --filter=patterns  - redact regex patterns (token formats)
//   --filter=all       - shorthand for both (default)
//
// Environment variables (override with --filter):
//   SECRETS_FILTER_VALUES=0|false|no    - disable values filter
//   SECRETS_FILTER_PATTERNS=0|false|no  - disable patterns filter

import Foundation

// Filter configuration
struct FilterConfig {
    var valuesEnabled: Bool = true
    var patternsEnabled: Bool = true
}

// Check if a value is falsy (0, false, no)
func isFalsy(_ value: String) -> Bool {
    let lower = value.lowercased()
    return ["0", "false", "no"].contains(lower)
}

// Parse --filter CLI arguments
// Returns: (config, hadValidFilter) or nil if error (all invalid filters)
func parseFilterArgs() -> (FilterConfig, Bool)? {
    var config = FilterConfig(valuesEnabled: false, patternsEnabled: false)
    var hadFilterArg = false
    var hadValidFilter = false

    let args = CommandLine.arguments
    for arg in args.dropFirst() {  // Skip program name
        var filterValue: String? = nil

        if arg.hasPrefix("--filter=") {
            filterValue = String(arg.dropFirst("--filter=".count))
        } else if arg == "-f" {
            // Find the next argument
            if let idx = args.firstIndex(of: arg), idx + 1 < args.count {
                filterValue = args[idx + 1]
            }
        } else if arg.hasPrefix("-f") && arg.count > 2 {
            // -fvalue format (no space)
            filterValue = String(arg.dropFirst(2))
        }

        guard let value = filterValue else { continue }
        hadFilterArg = true

        // Parse comma-separated filters
        let filters = value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).lowercased() }

        for filter in filters {
            switch filter {
            case "all":
                config.valuesEnabled = true
                config.patternsEnabled = true
                hadValidFilter = true
            case "values":
                config.valuesEnabled = true
                hadValidFilter = true
            case "patterns":
                config.patternsEnabled = true
                hadValidFilter = true
            default:
                fputs("secrets-filter: unknown filter '\(filter)', ignoring\n", stderr)
            }
        }
    }

    if hadFilterArg && !hadValidFilter {
        fputs("secrets-filter: no valid filters specified\n", stderr)
        return nil
    }

    return (config, hadFilterArg)
}

// Parse environment variables for filter config
func parseFilterEnv() -> FilterConfig {
    var config = FilterConfig()

    if let value = ProcessInfo.processInfo.environment["SECRETS_FILTER_VALUES"], isFalsy(value) {
        config.valuesEnabled = false
    }
    if let value = ProcessInfo.processInfo.environment["SECRETS_FILTER_PATTERNS"], isFalsy(value) {
        config.patternsEnabled = false
    }

    return config
}

// Get filter configuration: CLI overrides ENV, ENV overrides defaults
func getFilterConfig() -> FilterConfig? {
    if let (config, hadFilterArg) = parseFilterArgs() {
        if hadFilterArg {
            return config
        }
        // No filter arg, fall through to env
    } else {
        // Error: all invalid filters
        return nil
    }

    return parseFilterEnv()
}

let STATE_NORMAL = 0
let STATE_IN_PRIVATE_KEY = 1

// Compile patterns from patterns_gen.swift at startup
let privateKeyBegin = try! Regex(privateKeyBeginPattern)
let privateKeyEnd = try! Regex(privateKeyEndPattern)

// Direct patterns compiled from generated strings
let directPatterns: [(Regex<AnyRegexOutput>, String)] = patterns.map { (pattern, label) in
    (try! Regex(pattern), label)
}

// Context patterns compiled from generated strings
let compiledContextPatterns: [(Regex<AnyRegexOutput>, String, Int)] = contextPatterns.map { (pattern, label, group) in
    (try! Regex(pattern), label, group)
}

// Special patterns compiled from generated structs
let gitCredPattern = try! Regex(gitCredentialPattern.pattern)
let compiledDockerAuthPattern = try! Regex(dockerAuthPattern.pattern)

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
    if s.count >= longThreshold {
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

    let env = ProcessInfo.processInfo.environment
    for (name, value) in env {
        guard value.count >= 8 else { continue }

        if explicitEnvVars.contains(name) || envSuffixes.contains(where: { name.hasSuffix($0) }) {
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
            let matched = String(match.output[0].substring!)
            let structure = describeStructure(matched)
            return "[REDACTED:\(label):\(structure)]"
        }
    }

    // Context patterns (capture group approach)
    for (pattern, label, _) in compiledContextPatterns {
        result = result.replacing(pattern) { match in
            let prefix = String(match.output[1].substring!)
            let secret = String(match.output[2].substring!)
            let structure = describeStructure(secret)
            return "\(prefix)[REDACTED:\(label):\(structure)]"
        }
    }

    // Git credential URLs: ://user:password@ -> ://user:[REDACTED]@
    result = result.replacing(gitCredPattern) { match in
        let prefix = String(match.output[1].substring!)
        let password = String(match.output[2].substring!)
        let suffix = String(match.output[3].substring!)
        let structure = describeStructure(password)
        return "\(prefix)[REDACTED:\(gitCredentialPattern.label):\(structure)]\(suffix)"
    }

    // Docker config auth
    result = result.replacing(compiledDockerAuthPattern) { match in
        let prefix = String(match.output[1].substring!)
        let auth = String(match.output[2].substring!)
        let suffix = String(match.output[3].substring!)
        let structure = describeStructure(auth)
        return "\(prefix)[REDACTED:\(dockerAuthPattern.label):\(structure)]\(suffix)"
    }

    return result
}

// Redact a single line based on filter config
func redactLine(_ line: String, _ secrets: [String: String], _ config: FilterConfig) -> String {
    var result = line
    if config.valuesEnabled {
        result = redactEnvValues(result, secrets)
    }
    if config.patternsEnabled {
        result = redactPatterns(result)
    }
    return result
}

// Flush buffer with redaction
func flushBufferRedacted(_ buffer: [String], _ secrets: [String: String], _ config: FilterConfig) {
    for line in buffer {
        print(redactLine(line, secrets, config), terminator: "")
        fflush(stdout)
    }
}

// Main
func main() {
    // Get filter configuration (CLI overrides ENV)
    guard let config = getFilterConfig() else {
        exit(1)  // Error already printed by getFilterConfig
    }

    // Load secrets only if values filter is enabled
    let secrets: [String: String] = config.valuesEnabled ? loadSecrets() : [:]

    var state = STATE_NORMAL
    var buffer: [String] = []

    while let line = readLine(strippingNewline: false) {
        // Binary detection: null byte
        if line.contains("\0") {
            flushBufferRedacted(buffer, secrets, config)
            buffer = []
            print(line, terminator: "")
            // Passthrough rest
            while let rest = readLine(strippingNewline: false) {
                print(rest, terminator: "")
            }
            return
        }

        if state == STATE_NORMAL {
            // Only detect private key blocks if patterns filter is enabled
            if config.patternsEnabled && line.contains(privateKeyBegin) {
                state = STATE_IN_PRIVATE_KEY
                buffer = [line]
            } else {
                print(redactLine(line, secrets, config), terminator: "")
                fflush(stdout)
            }
        } else {
            buffer.append(line)

            if line.contains(privateKeyEnd) {
                print("[REDACTED:PRIVATE_KEY:multiline]")
                fflush(stdout)
                buffer = []
                state = STATE_NORMAL
            } else if buffer.count > maxPrivateKeyBuffer {
                flushBufferRedacted(buffer, secrets, config)
                buffer = []
                state = STATE_NORMAL
            }
        }
    }

    // EOF: flush remaining buffer
    if !buffer.isEmpty {
        flushBufferRedacted(buffer, secrets, config)
    }
}

main()
