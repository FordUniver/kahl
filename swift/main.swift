// secrets-filter: Filter stdin for secrets, redact with labels
// Streaming mode with state machine for private keys
// Build: swiftc -O -o secrets-filter main.swift patterns_gen.swift
//
// Filter modes:
//   --filter=values    - redact known secret values from environment
//   --filter=patterns  - redact regex patterns (token formats)
//   --filter=entropy   - redact high-entropy strings (opt-in, off by default)
//   --filter=all       - all filters (values + patterns + entropy)
//
// Environment variables (override with --filter):
//   SECRETS_FILTER_VALUES=0|false|no    - disable values filter
//   SECRETS_FILTER_PATTERNS=0|false|no  - disable patterns filter
//   SECRETS_FILTER_ENTROPY=1|true|yes   - enable entropy filter (off by default)
//
// Entropy filter options (env vars):
//   SECRETS_FILTER_ENTROPY_THRESHOLD=N   - override all thresholds
//   SECRETS_FILTER_ENTROPY_HEX=N         - hex-specific threshold (default: 3.0)
//   SECRETS_FILTER_ENTROPY_BASE64=N      - base64-specific threshold (default: 4.5)
//   SECRETS_FILTER_ENTROPY_MIN_LEN=N     - minimum token length (default: 16)
//   SECRETS_FILTER_ENTROPY_MAX_LEN=N     - maximum token length (default: 256)

import Foundation

// Filter configuration
struct FilterConfig {
    var valuesEnabled: Bool = true
    var patternsEnabled: Bool = true
    var entropyEnabled: Bool = false
}

// Check if a value is falsy (0, false, no)
func isFalsy(_ value: String) -> Bool {
    let lower = value.lowercased()
    return ["0", "false", "no"].contains(lower)
}

// Check if a value is truthy (1, true, yes)
func isTruthy(_ value: String) -> Bool {
    let lower = value.lowercased()
    return ["1", "true", "yes"].contains(lower)
}

// Parse --filter CLI arguments
// Returns: (config, hadValidFilter) or nil if error (all invalid filters)
func parseFilterArgs() -> (FilterConfig, Bool)? {
    var config = FilterConfig(valuesEnabled: false, patternsEnabled: false, entropyEnabled: false)
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
                // 'all' means all filters (values + patterns + entropy)
                config.valuesEnabled = true
                config.patternsEnabled = true
                config.entropyEnabled = true
                hadValidFilter = true
            case "values":
                config.valuesEnabled = true
                hadValidFilter = true
            case "patterns":
                config.patternsEnabled = true
                hadValidFilter = true
            case "entropy":
                config.entropyEnabled = true
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
    // Entropy is disabled by default, enable via env or default from config
    config.entropyEnabled = entropyEnabledDefault
    if let value = ProcessInfo.processInfo.environment["SECRETS_FILTER_ENTROPY"], isTruthy(value) {
        config.entropyEnabled = true
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

// MARK: - Entropy Detection

// Entropy configuration with runtime overrides
struct EntropyConfig {
    var thresholds: [String: Double]
    var minLength: Int
    var maxLength: Int
}

// Character sets for classification
let charsetHex = Set("0123456789abcdef")
let charsetBase64 = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
let charsetAlnum = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")

// Token extraction regex: split on delimiters
let tokenDelimRegex = try! Regex("[\\s\"'`()\\[\\]{},:;<>=@#]+")

// Precompile exclusion patterns
struct CompiledExclusion {
    let regex: Regex<AnyRegexOutput>
    let label: String
    let contextKeywords: [String]?
}

let compiledExclusions: [CompiledExclusion] = entropyExclusions.map { (excl: EntropyExclusion) -> CompiledExclusion in
    let regex: Regex<AnyRegexOutput>
    if excl.caseInsensitive {
        regex = try! Regex(excl.pattern).ignoresCase()
    } else {
        regex = try! Regex(excl.pattern)
    }
    return CompiledExclusion(regex: regex, label: excl.label, contextKeywords: excl.contextKeywords)
}

// Calculate Shannon entropy in bits
func shannonEntropy(_ s: String) -> Double {
    if s.isEmpty { return 0.0 }

    // Count character occurrences
    var counts: [Character: Int] = [:]
    for c in s {
        counts[c, default: 0] += 1
    }

    let length = Double(s.count)
    var entropy = 0.0
    for count in counts.values {
        let p = Double(count) / length
        entropy -= p * log2(p)
    }
    return entropy
}

// Classify a string's character set
func classifyCharset(_ s: String) -> String {
    let chars = Set(s.lowercased())

    // Check hex first (most restrictive)
    if chars.isSubset(of: charsetHex) {
        return "hex"
    }

    // Check alphanumeric (common for tokens)
    let upperChars = Set(s)
    if upperChars.isSubset(of: charsetAlnum) {
        return "alphanumeric"
    }

    // Check base64
    if upperChars.isSubset(of: charsetBase64) {
        return "base64"
    }

    return "mixed"
}

// Extract potential secret tokens from text
func extractTokens(_ text: String, minLen: Int, maxLen: Int) -> [(token: String, start: Int, end: Int)] {
    var tokens: [(String, Int, Int)] = []

    // Split by delimiters while tracking positions
    var pos = text.startIndex
    let parts = text.split(separator: tokenDelimRegex, omittingEmptySubsequences: true)

    for part in parts {
        let partStr = String(part)

        // Find position in original text
        if let range = text.range(of: partStr, range: pos..<text.endIndex) {
            let start = text.distance(from: text.startIndex, to: range.lowerBound)
            let end = text.distance(from: text.startIndex, to: range.upperBound)
            pos = range.upperBound

            // Filter by length
            if partStr.count < minLen || partStr.count > maxLen {
                continue
            }

            // Skip if all alphabetic (variable names)
            if partStr.allSatisfy({ $0.isLetter }) {
                continue
            }

            // Skip if all numeric (IDs, line numbers)
            if partStr.allSatisfy({ $0.isNumber }) {
                continue
            }

            // Skip if contains whitespace
            if partStr.contains(where: { $0.isWhitespace }) {
                continue
            }

            tokens.append((partStr, start, end))
        }
    }

    return tokens
}

// Check if a position in text is preceded by a context keyword
func hasContextKeyword(_ text: String, pos: Int, keywords: [String]) -> Bool {
    if keywords.isEmpty { return false }

    // Look back up to 50 chars
    let startIdx = text.index(text.startIndex, offsetBy: max(0, pos - 50))
    let endIdx = text.index(text.startIndex, offsetBy: pos)
    let prefix = String(text[startIdx..<endIdx]).lowercased()

    for kw in keywords {
        if prefix.contains(kw.lowercased()) {
            return true
        }
    }

    return false
}

// Check if token matches an exclusion pattern
func matchesExclusion(_ token: String, text: String, pos: Int) -> String? {
    for excl in compiledExclusions {
        // Check if token fully matches the exclusion pattern
        if (try? excl.regex.wholeMatch(in: token)) != nil {
            // Check context keywords if present
            if let contextKw = excl.contextKeywords {
                if hasContextKeyword(text, pos: pos, keywords: contextKw) {
                    return excl.label
                }
                // Has context keywords but none found - not excluded
                continue
            }
            // No context keywords required - excluded
            return excl.label
        }
    }

    // Check global context keywords
    if hasContextKeyword(text, pos: pos, keywords: Array(entropyContextKeywords)) {
        return "CONTEXT"
    }

    return nil
}

// Create structure description for entropy redaction
func describeEntropyStructure(_ token: String, entropy: Double, charset: String) -> String {
    let charsetAbbrev: String
    switch charset {
    case "hex": charsetAbbrev = "hex"
    case "base64": charsetAbbrev = "b64"
    case "alphanumeric": charsetAbbrev = "alnum"
    default: charsetAbbrev = "mix"
    }
    return "\(charsetAbbrev):\(token.count):\(String(format: "%.1f", entropy))"
}

// Get entropy configuration from environment overrides or defaults
func getEntropyConfig() -> EntropyConfig {
    var config = EntropyConfig(
        thresholds: entropyThresholds,
        minLength: entropyMinLength,
        maxLength: entropyMaxLength
    )

    let env = ProcessInfo.processInfo.environment

    // Check for global threshold override
    if let globalThreshold = env["SECRETS_FILTER_ENTROPY_THRESHOLD"], let t = Double(globalThreshold) {
        config.thresholds = ["hex": t, "base64": t, "alphanumeric": t]
    }

    // Check for per-charset overrides
    if let hexVal = env["SECRETS_FILTER_ENTROPY_HEX"], let t = Double(hexVal) {
        config.thresholds["hex"] = t
    }
    if let base64Val = env["SECRETS_FILTER_ENTROPY_BASE64"], let t = Double(base64Val) {
        config.thresholds["base64"] = t
    }

    // Length overrides
    if let minLenVal = env["SECRETS_FILTER_ENTROPY_MIN_LEN"], let n = Int(minLenVal) {
        config.minLength = n
    }
    if let maxLenVal = env["SECRETS_FILTER_ENTROPY_MAX_LEN"], let n = Int(maxLenVal) {
        config.maxLength = n
    }

    return config
}

// Detect and redact high-entropy strings
func redactEntropy(_ text: String, config: EntropyConfig) -> String {
    let tokens = extractTokens(text, minLen: config.minLength, maxLen: config.maxLength)

    // Process in reverse order to preserve positions when replacing
    var result = text
    var replacements: [(start: Int, end: Int, replacement: String)] = []

    for (token, start, end) in tokens.reversed() {
        // Check exclusions
        if matchesExclusion(token, text: text, pos: start) != nil {
            continue
        }

        // Classify character set and get threshold
        let charset = classifyCharset(token)
        let threshold: Double
        if charset == "mixed" {
            // Mixed character sets - use alphanumeric threshold
            threshold = config.thresholds["alphanumeric"] ?? 4.5
        } else {
            threshold = config.thresholds[charset] ?? 4.5
        }

        // Calculate entropy
        let entropy = shannonEntropy(token)

        if entropy >= threshold {
            let structure = describeEntropyStructure(token, entropy: entropy, charset: charset)
            let replacement = "[REDACTED:HIGH_ENTROPY:\(structure)]"
            replacements.append((start, end, replacement))
        }
    }

    // Apply replacements in reverse order
    for (start, end, replacement) in replacements {
        let startIdx = result.index(result.startIndex, offsetBy: start)
        let endIdx = result.index(result.startIndex, offsetBy: end)
        result.replaceSubrange(startIdx..<endIdx, with: replacement)
    }

    return result
}

// Redact a single line based on filter config
func redactLine(_ line: String, _ secrets: [String: String], _ config: FilterConfig, _ entropyConfig: EntropyConfig?) -> String {
    var result = line
    if config.valuesEnabled {
        result = redactEnvValues(result, secrets)
    }
    if config.patternsEnabled {
        result = redactPatterns(result)
    }
    if config.entropyEnabled, let ec = entropyConfig {
        result = redactEntropy(result, config: ec)
    }
    return result
}

// Flush buffer with redaction
func flushBufferRedacted(_ buffer: [String], _ secrets: [String: String], _ config: FilterConfig, _ entropyConfig: EntropyConfig?) {
    for line in buffer {
        print(redactLine(line, secrets, config, entropyConfig), terminator: "")
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

    // Load entropy config only if entropy filter is enabled
    let entropyConfig: EntropyConfig? = config.entropyEnabled ? getEntropyConfig() : nil

    var state = STATE_NORMAL
    var buffer: [String] = []

    while let line = readLine(strippingNewline: false) {
        // Binary detection: null byte
        if line.contains("\0") {
            flushBufferRedacted(buffer, secrets, config, entropyConfig)
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
                print(redactLine(line, secrets, config, entropyConfig), terminator: "")
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
                flushBufferRedacted(buffer, secrets, config, entropyConfig)
                buffer = []
                state = STATE_NORMAL
            }
        }
    }

    // EOF: flush remaining buffer
    if !buffer.isEmpty {
        flushBufferRedacted(buffer, secrets, config, entropyConfig)
    }
}

main()
